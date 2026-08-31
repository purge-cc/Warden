//! Sprint 43 T4 (D4): 250 ms debounce window for IPC-triggered reloads.
//!
//! Background: every CLI write (`warden profile blocklists default add …`,
//! `warden rule add …` post-T5, etc.) ends with `IpcCommand::Reload`. A
//! script that fires 100 such commands in quick succession used to
//! schedule 100 actual rebuild passes — 100 `ResolverMap` rebuilds, 100
//! audit-log lines, 100 reload-loop trips. With the per-device overlay
//! shipping in T4 the rebuild cost grows, so D4 introduces a coalescing
//! window: notifications received within 250 ms of the **first** wake
//! collapse into a single rebuild request.
//!
//! Acceptance §8: 100 sequential `IpcCommand::Reload` complete in
//! ≤ 2 × 250 ms (≤ 8 actual rebuilds).
//!
//! ## Wire-shape
//!
//! - The IPC handler (`socket_server::handle_reload`) calls
//!   [`ReloadCoalescer::request`] with the peer uid (from `SO_PEERCRED`).
//!   This bumps an atomic counter, stashes the latest peer uid, and
//!   wakes the worker via `tokio::sync::Notify`.
//! - The worker task spawned by [`ReloadCoalescer::spawn_worker`]:
//!   1. `notify.notified().await` — sleeps until the first request
//!      comes in.
//!   2. `tokio::time::sleep(window).await` — opens the 250 ms window;
//!      every additional request inside it just bumps the atomic
//!      counter without re-arming the sleep.
//!   3. Drains the counter atomically. Sends ONE message on the
//!      shared `reload_tx` mpsc (the same one SIGHUP uses) carrying
//!      the LAST peer uid observed in the window.
//!   4. Emits `RULE_RELOAD_BATCHED` (SN3 frozen) at `tracing::info!`
//!      with the batched count.
//!
//! ## SIGHUP path stays direct
//!
//! Signal-driven reloads bypass the coalescer entirely (the start.rs
//! signal_loop sends straight to `reload_tx`). The coalescer only
//! debounces IPC-triggered reloads — operator-driven external signals
//! preserve their immediate-rebuild semantics, and the coalescer's
//! single-batch-at-a-time worker can't lock out a fresh signal.
//!
//! ## Threading guarantees
//!
//! - `pending_count: AtomicU64` is the only mutable shared state hit
//!   by `request()`. No mutex on the request path.
//! - `last_peer_uid` lives behind a `tokio::sync::Mutex<Option<u32>>`
//!   that's contended only on request submission and worker drain;
//!   single critical section is a `Some` → `take()`, no allocations.
//! - The `Notify` is bounded — multiple notifications before a
//!   `notified()` await coalesce into one. That's the property we
//!   want: 100 in-flight requests all signal the same "wake up"
//!   pattern; the worker sees one wake, sleeps 250 ms, then drains.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{mpsc, Mutex, Notify};

/// Sprint 43 T4 (SN3): operator-facing reload-batch summary, byte-for-
/// byte pinned by `tests/frozen_strings_s43.rs` in T6.
pub const RULE_RELOAD_BATCHED: &str = "{n} rule changes batched in this reload window.";

/// Substitute `{n}` into [`RULE_RELOAD_BATCHED`].
pub fn format_rule_reload_batched(n: u64) -> String {
    RULE_RELOAD_BATCHED.replace("{n}", &n.to_string())
}

/// Default debounce window. Picked per design doc D4 — small enough
/// to feel instant to the operator, big enough to swallow a script
/// firing rapid-fire CLI writes.
pub const DEFAULT_WINDOW: Duration = Duration::from_millis(250);

/// Sprint 43 T4: coalesces IPC-triggered reload requests within a
/// debounce window. See module docs for the wire-shape and acceptance.
pub struct ReloadCoalescer {
    /// Number of `request()` calls observed since the last drain.
    /// Worker resets this to 0 after firing a single reload via
    /// `reload_tx`.
    pending_count: AtomicU64,
    /// Last peer uid passed to `request()`. The drain takes this
    /// value out (`take()`) and forwards it to `reload_tx`. `None`
    /// means SIGHUP-equivalent (no audit-trail uid).
    last_peer_uid: Mutex<Option<u32>>,
    /// Wakes the worker. Multiple `notify_one()` calls before the
    /// first `notified()` await collapse — that's by design.
    notify: Notify,
    /// Underlying mpsc into the start.rs reload loop. The coalescer
    /// is the only writer for IPC-triggered reloads; SIGHUP keeps
    /// its own direct sender.
    reload_tx: mpsc::Sender<Option<u32>>,
    /// Debounce window. Defaults to [`DEFAULT_WINDOW`]; tests inject
    /// shorter values via [`Self::with_window`].
    window: Duration,
    /// Cleared when the worker loop leaves, however it leaves.
    /// [`Self::request`] refuses once this is false: a reload queued
    /// into a worker that will never service it must reach the operator
    /// as an error, not as the success they would otherwise believe.
    ///
    /// Set on exit only — never on "the worker looks slow". `reload_tx`
    /// has capacity 1, so the worker legitimately blocks in `send` for
    /// the length of a rebuild, and a liveness signal that fired on that
    /// would refuse valid reloads on every busy daemon.
    worker_alive: AtomicBool,
}

impl ReloadCoalescer {
    /// Build a coalescer wrapping `reload_tx`. The worker task is
    /// spawned separately via [`Self::spawn_worker`] so callers can
    /// arrange `tokio::spawn` ordering with the rest of daemon boot.
    pub fn new(reload_tx: mpsc::Sender<Option<u32>>) -> Self {
        Self::with_window(reload_tx, DEFAULT_WINDOW)
    }

    /// Test-friendly constructor — accepts a custom debounce window.
    pub fn with_window(reload_tx: mpsc::Sender<Option<u32>>, window: Duration) -> Self {
        Self {
            pending_count: AtomicU64::new(0),
            last_peer_uid: Mutex::new(None),
            notify: Notify::new(),
            reload_tx,
            window,
            worker_alive: AtomicBool::new(true),
        }
    }

    /// Submit a reload request to the coalescer. Returns the count
    /// of pending requests AFTER this submission so the IPC handler
    /// can render an operator-facing message that reflects whether
    /// the request was the first in the window or piggybacked on
    /// an in-flight batch.
    ///
    /// `None` means the worker has exited and nothing will service the
    /// request. The caller must surface that as a failure — queueing
    /// into a dead worker is indistinguishable, from the operator's
    /// side, from a reload that worked.
    pub async fn request(&self, peer_uid: Option<u32>) -> Option<u64> {
        if !self.worker_alive.load(Ordering::Acquire) {
            return None;
        }
        // Order: bump the counter first (so the worker sees a non-zero
        // pending on its drain even if `last_peer_uid` write hasn't
        // landed yet — the `peer_uid: None` fallback is acceptable).
        // Then update last_peer_uid. Finally notify.
        let prev = self.pending_count.fetch_add(1, Ordering::SeqCst);
        {
            let mut slot = self.last_peer_uid.lock().await;
            *slot = peer_uid;
        }
        self.notify.notify_one();
        Some(prev + 1)
    }

    /// Spawn the worker task that drives the debounce window.
    ///
    /// The returned `JoinHandle` is not retained by the daemon: the
    /// worker exits on its own when the underlying mpsc closes at
    /// shutdown, and liveness is reported through [`Self::request`]
    /// rather than by joining the task. Dropping the handle does not
    /// abort the task.
    pub fn spawn_worker(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let _alive = WorkerAliveGuard(self.clone());
            self.run_worker_loop().await;
        })
    }

    /// Worker loop body. Public for tests that drive the window
    /// directly without `tokio::spawn`.
    pub async fn run_worker_loop(&self) {
        loop {
            // Sleep until the first request lands.
            self.notify.notified().await;

            // Open the debounce window. Every additional request
            // arriving inside this sleep just bumps the atomic
            // counter — no re-arm needed.
            tokio::time::sleep(self.window).await;

            // Drain.
            let count = self.pending_count.swap(0, Ordering::SeqCst);
            if count == 0 {
                // Spurious wake (shouldn't happen with notify_one
                // semantics, but defensive). Loop back to wait for a
                // fresh request.
                continue;
            }
            let uid = self.last_peer_uid.lock().await.take();

            tracing::info!(
                target: "audit",
                count,
                "{}",
                format_rule_reload_batched(count)
            );

            // Forward to the shared reload mpsc. If the channel is
            // closed (daemon shutting down) we exit cleanly.
            if self.reload_tx.send(uid).await.is_err() {
                tracing::warn!(
                    "reload coalescer: underlying reload channel closed, worker exiting"
                );
                return;
            }
        }
    }
}

/// Clears the alive flag however the worker loop leaves — a clean
/// `return` or a panic unwind. A flag cleared only on the `return` path
/// would leave a panicked worker advertising itself as live, which is
/// the case nobody observes: the task's `JoinHandle` is dropped, so the
/// panic reaches no one.
struct WorkerAliveGuard(Arc<ReloadCoalescer>);

impl Drop for WorkerAliveGuard {
    fn drop(&mut self) {
        self.0.worker_alive.store(false, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Acceptance §8: 100 sequential requests fired as fast as they
    /// can be issued must complete within `≤ 2 × window`, with the
    /// underlying reload channel receiving ≤ 8 batched messages. We
    /// pick a small window (50 ms here, instead of the 250 ms prod
    /// default) to keep test runtime tight; the coalescing math is
    /// proportional to window size.
    #[tokio::test]
    async fn one_hundred_requests_coalesce_into_at_most_eight_rebuilds() {
        let (tx, mut rx) = mpsc::channel::<Option<u32>>(16);
        let window = Duration::from_millis(50);
        let coalescer = Arc::new(ReloadCoalescer::with_window(tx, window));

        // Spawn the worker.
        let _handle = coalescer.clone().spawn_worker();

        let start = std::time::Instant::now();
        for _ in 0..100 {
            let _ = coalescer.request(Some(1000)).await;
        }
        let submit_elapsed = start.elapsed();
        assert!(
            submit_elapsed < window,
            "request submission must be near-instant (<{window:?}), got {submit_elapsed:?}"
        );

        // Wait long enough that any in-flight batch has flushed.
        tokio::time::sleep(window * 4).await;

        // Drain everything the channel has received so far.
        let mut received = 0usize;
        while let Ok(_msg) = rx.try_recv() {
            received += 1;
        }
        assert!(
            received >= 1,
            "at least one reload must fire after 100 requests"
        );
        assert!(
            received <= 8,
            "100 requests must coalesce into ≤ 8 rebuilds (got {received})"
        );
    }

    #[tokio::test]
    async fn single_request_fires_one_reload_after_window() {
        let (tx, mut rx) = mpsc::channel::<Option<u32>>(4);
        let window = Duration::from_millis(40);
        let coalescer = Arc::new(ReloadCoalescer::with_window(tx, window));
        let _handle = coalescer.clone().spawn_worker();

        let _ = coalescer.request(Some(1234)).await;

        // Within the window: nothing yet.
        tokio::time::sleep(window / 2).await;
        assert!(
            rx.try_recv().is_err(),
            "reload must NOT fire before the window closes"
        );

        // After the window: exactly one reload, with the submitted uid.
        tokio::time::sleep(window).await;
        let received = rx.try_recv().expect("one reload should have landed by now");
        assert_eq!(received, Some(1234));

        assert!(
            rx.try_recv().is_err(),
            "no extra reload should fire from a single request"
        );
    }

    #[tokio::test]
    async fn coalescer_carries_last_peer_uid_across_batch() {
        let (tx, mut rx) = mpsc::channel::<Option<u32>>(4);
        let window = Duration::from_millis(40);
        let coalescer = Arc::new(ReloadCoalescer::with_window(tx, window));
        let _handle = coalescer.clone().spawn_worker();

        let _ = coalescer.request(Some(100)).await;
        let _ = coalescer.request(Some(200)).await;
        let _ = coalescer.request(Some(999)).await;

        tokio::time::sleep(window * 3).await;
        let received = rx.try_recv().unwrap();
        assert_eq!(
            received,
            Some(999),
            "last peer_uid in the batch must be forwarded"
        );
    }

    #[test]
    fn rule_reload_batched_const_is_pinned() {
        // T6 frozen-strings test will subsume this. Pinning here so
        // unintentional rewording surfaces during T4 review.
        assert_eq!(
            RULE_RELOAD_BATCHED,
            "{n} rule changes batched in this reload window."
        );
    }

    #[test]
    fn rule_reload_batched_format_helper_substitutes() {
        assert_eq!(
            format_rule_reload_batched(7),
            "7 rule changes batched in this reload window."
        );
    }

    /// A worker that has exited must refuse further requests. Without
    /// this the operator is told "reload queued" against a daemon that
    /// will never reload again, and has no way to notice.
    #[tokio::test]
    async fn request_refuses_once_the_worker_has_exited() {
        let (tx, rx) = mpsc::channel::<Option<u32>>(1);
        let window = Duration::from_millis(20);
        let coalescer = Arc::new(ReloadCoalescer::with_window(tx, window));
        let _handle = coalescer.clone().spawn_worker();

        // Dropping the receiver is the only thing that makes the
        // worker's send fail, which is the one route out of its loop.
        drop(rx);

        // The flag is still set until the worker wakes, sleeps the
        // window and fails its send — so this first request is `Some` by
        // design. Asserting refusal here instead would pass for the
        // wrong reason, or not at all.
        assert!(
            coalescer.request(Some(1)).await.is_some(),
            "a live worker must still accept the request that kills it"
        );
        tokio::time::sleep(window * 5).await;

        assert!(
            coalescer.request(Some(1)).await.is_none(),
            "a request into an exited worker must be refused, not queued"
        );
    }

    #[tokio::test]
    async fn request_returns_pending_count_progress() {
        // The submitter uses the returned count to render an
        // operator-facing "queued (N pending)" message. Pin the
        // monotonic-progress contract.
        let (tx, _rx) = mpsc::channel::<Option<u32>>(4);
        let coalescer = ReloadCoalescer::with_window(tx, Duration::from_millis(20_000)); // long window
        assert_eq!(coalescer.request(None).await, Some(1));
        assert_eq!(coalescer.request(None).await, Some(2));
        assert_eq!(coalescer.request(None).await, Some(3));
    }
}
