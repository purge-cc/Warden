//! Tokio-spawnable sampler that publishes a [`ResourceBudgetSnapshot`](super::types::ResourceBudgetSnapshot)
//! once per tick into a sampler-owned [`ResourceBudgetStore`].
//!
//! Linux-only implementation; non-Linux builds get the no-op stub at the
//! bottom of the file so the daemon still compiles.

use std::time::Duration;

use super::types::ResourceBudgetStore;

#[cfg(target_os = "linux")]
mod linux {
    use std::path::Path;
    use std::time::{Duration, Instant};

    use super::super::proc_reader;
    use super::super::types::ResourceBudgetSnapshot;

    /// Per-sampler clock-tick cache. Resolved once via `sysconf(_SC_CLK_TCK)`
    /// so the sample-time path doesn't pay for an FFI call every tick.
    pub(super) fn clock_ticks_per_sec() -> u64 {
        // `sysconf` is a plain POSIX call with no aliasing hazards. The
        // result is constant for the life of the process — caching at
        // start time is safe and matches every other crate that reads it.
        let raw = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
        if raw <= 0 {
            100 // sensible Linux default; observed `getconf CLK_TCK` on dev
        } else {
            raw as u64
        }
    }

    /// Pure sample function — collects one snapshot from `/proc/self/*`,
    /// computes the user-mode CPU delta against the caller's `prev_*`
    /// state, and updates that state in place.
    ///
    /// Returns `None` if any of the three reads fail (we'd rather expose
    /// "no sample" than a half-filled snapshot the operator might mistake
    /// for a healthy zero).
    pub(super) fn sample_once(
        clk_tck: u64,
        prev_utime: &mut Option<u64>,
        prev_instant: &mut Option<Instant>,
        rss_warn_mb: u64,
    ) -> Option<ResourceBudgetSnapshot> {
        let status = proc_reader::read_proc_file(Path::new("/proc/self/status")).ok()?;
        let rss_kb = proc_reader::parse_vm_kb(&status, "VmRSS")?;
        let vsz_kb = proc_reader::parse_vm_kb(&status, "VmSize")?;

        let stat = proc_reader::read_proc_file(Path::new("/proc/self/stat")).ok()?;
        let utime_now = proc_reader::parse_utime_ticks(&stat)?;

        let fd_count = proc_reader::count_directory_entries(Path::new("/proc/self/fd")).ok()?;

        let now = Instant::now();
        let cpu_user_pct = match (prev_utime.take(), prev_instant.take()) {
            (Some(prev_u), Some(prev_t)) => {
                let elapsed_ms = now.saturating_duration_since(prev_t).as_millis() as u64;
                compute_cpu_user_pct(utime_now.saturating_sub(prev_u), clk_tck, elapsed_ms)
            }
            _ => 0,
        };
        *prev_utime = Some(utime_now);
        *prev_instant = Some(now);

        Some(ResourceBudgetSnapshot {
            rss_mb: rss_kb / 1024,
            vsz_mb: vsz_kb / 1024,
            fd_count,
            cpu_user_pct,
            rss_warn_mb,
        })
    }

    /// User-mode CPU% over the inter-tick window. Integer math, saturates
    /// at `u8::MAX` (255) — daemon CPU% is expected to stay well below
    /// that on every supported deployment, and saturation is safer than
    /// silent rollover.
    ///
    /// Formula: `(utime_delta_ticks / clk_tck) / elapsed_secs * 100`,
    /// reorganised as `utime_delta * 100_000 / (clk_tck * elapsed_ms)`
    /// so we never hit a float on the sample path.
    pub(super) fn compute_cpu_user_pct(utime_delta: u64, clk_tck: u64, elapsed_ms: u64) -> u8 {
        if clk_tck == 0 || elapsed_ms == 0 {
            return 0;
        }
        let pct = utime_delta.saturating_mul(100_000) / (clk_tck.saturating_mul(elapsed_ms));
        if pct > u8::MAX as u64 {
            u8::MAX
        } else {
            pct as u8
        }
    }

    /// What to publish after one sample attempt, given what is already
    /// published.
    ///
    /// A **transient** `/proc` read failure must not erase a good snapshot.
    /// `sample_once` returns `None` whenever any of its three reads fail, and
    /// the loop below used to store that `None` unconditionally — so one bad
    /// read replaced the last known-good sample and the operator's dashboard
    /// fell back to `RSS —, CPU —, FDs —` until the next successful tick. For
    /// a value sampled every 5 s in production that is a visible, recurring
    /// blank rather than a blip.
    ///
    /// Stale-but-present beats absent here: every field is a footprint
    /// measurement whose previous value stays roughly true across one missed
    /// tick, and the operator reading the dashboard wants "about 180 MB", not
    /// a dash. Note this deliberately does NOT paper over a permanent
    /// failure's first occurrence — a sampler that can never read `/proc`
    /// publishes `None` forever, because there is no prior value to keep.
    ///
    /// Factored out as a pure function for the same reason
    /// [`compute_cpu_user_pct`] is: making `/proc` fail on demand is a
    /// fixture nobody can write cheaply, whereas the *decision* is two lines
    /// and both of its arms are directly assertable.
    pub(super) fn next_stored(
        prev: Option<ResourceBudgetSnapshot>,
        sample: Option<ResourceBudgetSnapshot>,
    ) -> Option<ResourceBudgetSnapshot> {
        sample.or(prev)
    }

    /// Inner async loop. Factored out so tests can poke at the sampler
    /// without spawning a tokio task.
    pub(super) async fn run(store: super::ResourceBudgetStore, tick: Duration, rss_warn_mb: u64) {
        let clk_tck = clock_ticks_per_sec();
        let mut prev_utime: Option<u64> = None;
        let mut prev_instant: Option<Instant> = None;
        let mut ticker = tokio::time::interval(tick);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // First tick fires immediately; skip it so the snapshot stays
        // `None` until the *real* interval has elapsed (CPU delta needs
        // a prior sample to be meaningful anyway).
        ticker.tick().await;
        loop {
            ticker.tick().await;
            let sample = sample_once(clk_tck, &mut prev_utime, &mut prev_instant, rss_warn_mb);
            // Read what is published rather than tracking a local: the
            // invariant worth holding is about the value readers SEE, and
            // it costs one uncontended atomic load per tick.
            // Two derefs, not one: `Guard` derefs to the `Arc`, the `Arc` to
            // the `Option`. `Option<Snapshot>` is `Copy`, so this copies.
            let prev: Option<ResourceBudgetSnapshot> = **store.load();
            store.store(std::sync::Arc::new(next_stored(prev, sample)));
        }
    }
}

/// Spawn the resource-budget sampler. On Linux it reads `/proc/self/*`
/// every `tick` and publishes a snapshot into `store`; on every other
/// target it spawns an immediately-completing future so the daemon's
/// task-handle bookkeeping stays uniform.
#[cfg(target_os = "linux")]
pub fn spawn_sampler(
    store: ResourceBudgetStore,
    tick: Duration,
    rss_warn_mb: u64,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(linux::run(store, tick, rss_warn_mb))
}

#[cfg(not(target_os = "linux"))]
pub fn spawn_sampler(
    _store: ResourceBudgetStore,
    _tick: Duration,
    _rss_warn_mb: u64,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async {})
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::super::types::ResourceBudgetSnapshot;
    use super::*;
    use std::time::Instant;

    #[test]
    fn compute_cpu_user_pct_zero_elapsed_returns_zero() {
        assert_eq!(linux::compute_cpu_user_pct(100, 100, 0), 0);
    }

    #[test]
    fn compute_cpu_user_pct_typical() {
        // 50 ticks of utime over 1000 ms with 100 ticks/sec → 50% CPU.
        assert_eq!(linux::compute_cpu_user_pct(50, 100, 1000), 50);
    }

    #[test]
    fn compute_cpu_user_pct_saturates_at_u8_max() {
        // 1000 ticks of utime over 100 ms with 100 ticks/sec → 10000%
        // theoretical; saturating cast clamps to 255.
        assert_eq!(linux::compute_cpu_user_pct(1000, 100, 100), u8::MAX);
    }

    #[test]
    fn sample_once_first_call_returns_zero_cpu_then_real_delta() {
        let clk_tck = linux::clock_ticks_per_sec();
        let mut prev_utime: Option<u64> = None;
        let mut prev_instant: Option<Instant> = None;
        let first = linux::sample_once(clk_tck, &mut prev_utime, &mut prev_instant, 256)
            .expect("first /proc/self read should succeed in cargo test");
        assert_eq!(first.cpu_user_pct, 0, "no prior sample → CPU% must be 0");
        assert!(
            first.rss_mb > 0,
            "running cargo test always has nonzero RSS"
        );
        assert!(
            first.fd_count > 0,
            "process always has at least stdin/stdout/stderr"
        );
        assert_eq!(first.rss_warn_mb, 256);
        assert!(prev_utime.is_some());
        assert!(prev_instant.is_some());
    }

    /// A snapshot distinguishable from any real one, so an assertion that it
    /// survived cannot be satisfied by a fresh sample of this process.
    fn marker(rss_mb: u64) -> ResourceBudgetSnapshot {
        ResourceBudgetSnapshot {
            rss_mb,
            vsz_mb: 4567,
            fd_count: 42,
            cpu_user_pct: 7,
            rss_warn_mb: 256,
        }
    }

    /// Arm 1 of 2: a good read REPLACES what came before.
    ///
    /// Without this arm the preservation test below is satisfied by a sampler
    /// that never stores anything at all, which is why both are required.
    #[test]
    fn next_stored_good_sample_replaces_the_previous() {
        let prev = marker(100);
        let fresh = marker(200);
        assert_eq!(
            linux::next_stored(Some(prev), Some(fresh)),
            Some(fresh),
            "a successful sample must supersede the previous one"
        );
    }

    /// Arm 2 of 2: a FAILED read preserves the last good snapshot.
    ///
    /// This is the defect. `sample_once` returns `None` when any `/proc` read
    /// fails, and `run` used to store it unconditionally — blanking the
    /// operator's RSS/CPU/FD row on a single transient failure.
    ///
    /// The two arms pin `sample.or(prev)` against its swap, `prev.or(sample)`:
    /// swapping them keeps this test green and reds arm 1. Neither test alone
    /// discriminates.
    #[test]
    fn next_stored_failed_sample_keeps_the_last_good() {
        let good = marker(100);
        assert_eq!(
            linux::next_stored(Some(good), None),
            Some(good),
            "a transient /proc failure must not erase the last good sample"
        );
    }

    /// A failure before any success still publishes `None` — there is nothing
    /// to keep. Pins the boundary the fix must NOT move: the IPC contract
    /// says `None` means "no sample yet", and
    /// `daemon_status_resource_budget_is_none_before_first_tick` in
    /// tests/resource_budget_ipc.rs asserts it end to end.
    #[test]
    fn next_stored_failure_before_any_success_stays_none() {
        assert_eq!(linux::next_stored(None, None), None);
    }

    /// Poll until the sampler publishes, instead of sleeping a fixed 160 ms
    /// against a 40 ms tick.
    ///
    /// The fixed sleep was the same defect S1 removed from
    /// `tests/resource_budget_ipc.rs`: a wall-clock window standing in for a
    /// synchronisation point. This test runs on a `current_thread` runtime, so
    /// the test body and the sampler share **one** OS thread — starve it and
    /// both timers slip together, which is exactly what happens when several
    /// lanes compile on this box at once.
    ///
    /// Widening the bound to 30 s surrenders no coverage: nothing in the
    /// product promises a snapshot inside 160 ms (production `tick_secs`
    /// defaults to 5), so that number asserted a latency property the code
    /// never owned. Every real regression still fails — an unspawned sampler,
    /// a store not shared with the task, or `/proc` reads that never succeed
    /// all leave the store `None` *forever*, so the loop runs out and reports
    /// with the elapsed time attached.
    async fn await_first_sample(
        store: &ResourceBudgetStore,
        budget: Duration,
    ) -> ResourceBudgetSnapshot {
        let start = Instant::now();
        loop {
            if let Some(snap) = **store.load() {
                return snap;
            }
            assert!(
                start.elapsed() < budget,
                "sampler published no snapshot within {budget:?} (elapsed {:?}); \
                 the store is still None",
                start.elapsed()
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn spawn_sampler_updates_store_within_two_ticks() {
        let store = super::super::types::new_store();
        assert!(store.load().as_ref().is_none(), "store starts empty");

        let tick = Duration::from_millis(40);
        let handle = spawn_sampler(store.clone(), tick, 256);

        let snap = await_first_sample(&store, Duration::from_secs(30)).await;
        assert!(
            snap.rss_mb > 0,
            "a running test process always has a nonzero RSS"
        );
        assert_eq!(
            snap.rss_warn_mb, 256,
            "the configured threshold is mirrored"
        );
        handle.abort();
    }
}
