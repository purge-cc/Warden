//! Packed window counter — atomic window-reset for rate-limit primitives.
//!
//! Used by [`super::tunneling::TunnelingDetector`] per base domain and
//! [`super::rrl::Rrl`] per destination prefix. Both previously held a
//! separate `AtomicU32 count` + `AtomicU64 window_start` and reset them
//! with two independent `store` calls — a concurrent caller could see the
//! new `window_start` with the stale (non-zero) `count` and `fetch_add`
//! on it (Hermes review T2.1 + T2.3). The bounded consequence was at most
//! one extra count carried into the new window per tracker per crossing.
//!
//! This helper packs both fields into one `AtomicU64` so the reset is a
//! single CAS — no torn intermediate state.
//!
//! # Layout
//!
//! `[count: u32 | window_start_secs: u32]` — count in the upper 32 bits,
//! window-start in the lower 32. The happy path uses `fetch_add(1 << 32)`
//! which bumps count by 1; if count saturates at `u32::MAX` the carry
//! wraps within the upper 32 bits via `u64` modular arithmetic and never
//! disturbs the window-start bits. The inverse layout (`ws` in upper)
//! would let a count overflow bleed into the window-start and stick the
//! window in a never-expiring state — a hard prefix DoS. Overflow is
//! theoretical at realistic deployment loads (60 s window × 83 kpps
//! single-prefix on the Pi defender ≈ 5 M; far below `u32::MAX` ≈ 4.29 B)
//! but the layout choice removes the failure mode regardless.
//!
//! # Ordering
//!
//! `Relaxed` throughout — same semantics as the pre-fix `AtomicU32` +
//! `AtomicU64` pair. The CAS-reset path retries on contention; the happy
//! path is a single relaxed `fetch_add`.

use std::sync::atomic::{AtomicU64, Ordering};

/// Packed `[count:u32 | window_start_secs:u32]` rate-limit window state.
pub(crate) struct AtomicWindowCounter {
    state: AtomicU64,
}

#[inline]
fn pack(count: u32, ws: u32) -> u64 {
    ((count as u64) << 32) | (ws as u64)
}

#[inline]
fn unpack(packed: u64) -> (u32, u32) {
    ((packed >> 32) as u32, packed as u32)
}

impl AtomicWindowCounter {
    /// Create a counter anchored at `now_secs` with count = 0.
    pub fn new(now_secs: u64) -> Self {
        Self {
            state: AtomicU64::new(pack(0, now_secs as u32)),
        }
    }

    /// Bump the counter, returning the count seen *before* this caller's
    /// increment. If the window has elapsed (`now_secs - ws >= window_secs`)
    /// the state is reset atomically to `(count=1, ws=now_secs)` and the
    /// returned prior count is `0` — the calling thread is the first
    /// responder in the new window.
    ///
    /// Hot-path: 1 relaxed load + 1 relaxed `fetch_add` on the common
    /// (no-crossing) branch. Reset uses `compare_exchange` and retries
    /// on contention; in steady state under any realistic load the
    /// reset branch fires at most once per `window_secs` per counter.
    pub fn check_and_bump(&self, now_secs: u64, window_secs: u64) -> u32 {
        loop {
            let packed = self.state.load(Ordering::Relaxed);
            let (_, ws) = unpack(packed);
            let elapsed = now_secs.saturating_sub(ws as u64);
            if elapsed >= window_secs {
                let desired = pack(1, now_secs as u32);
                match self.state.compare_exchange(
                    packed,
                    desired,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => return 0,
                    Err(_) => continue,
                }
            }
            let prev = self.state.fetch_add(1u64 << 32, Ordering::Relaxed);
            let (prev_count, _) = unpack(prev);
            return prev_count;
        }
    }

    /// Window-start in seconds since the owning detector's creation —
    /// used by [`super::bounded_map::BoundedMap`] for eviction ordering
    /// (smaller = older = evicted first).
    pub fn window_start_secs(&self) -> u64 {
        let (_, ws) = unpack(self.state.load(Ordering::Relaxed));
        ws as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};
    use std::thread;

    #[test]
    fn pack_unpack_roundtrip() {
        let cases = [
            (0u32, 0u32),
            (1, 1),
            (42, 12345),
            (u32::MAX, 0),
            (0, u32::MAX),
        ];
        for (count, ws) in cases {
            assert_eq!(unpack(pack(count, ws)), (count, ws));
        }
    }

    #[test]
    fn pack_unpack_max_values() {
        let packed = pack(u32::MAX, u32::MAX);
        assert_eq!(unpack(packed), (u32::MAX, u32::MAX));
    }

    /// Layout safety: `fetch_add(1 << 32)` at count = `u32::MAX` must
    /// wrap within the upper 32 bits and leave the window_start (lower
    /// 32) untouched. The inverse layout would corrupt ws on overflow
    /// and stick the window in a never-expiring state.
    #[test]
    fn count_overflow_wraps_within_upper_bits() {
        let ws = 0x1234_5678u32;
        let state = AtomicU64::new(pack(u32::MAX, ws));
        let prev = state.fetch_add(1u64 << 32, Ordering::Relaxed);
        let (prev_count, prev_ws) = unpack(prev);
        assert_eq!(prev_count, u32::MAX);
        assert_eq!(prev_ws, ws);

        let after = state.load(Ordering::Relaxed);
        let (count_after, ws_after) = unpack(after);
        assert_eq!(count_after, 0, "count wrapped to 0");
        assert_eq!(ws_after, ws, "ws preserved across count overflow");
    }

    /// Sequential happy path: post-creation first call returns 0; second
    /// returns 1; etc. Pins the L-11 invariant (first responder sees 0
    /// prior count, so the caller compares 0 vs limit and is not over).
    #[test]
    fn first_call_returns_zero() {
        let c = AtomicWindowCounter::new(100);
        assert_eq!(c.check_and_bump(100, 60), 0);
        assert_eq!(c.check_and_bump(100, 60), 1);
        assert_eq!(c.check_and_bump(100, 60), 2);
    }

    /// Sequential reset: after the window elapses, the next call sees
    /// the reset (prior count = 0) and the state moves to (count=1, ws=now).
    #[test]
    fn window_reset_after_elapsed() {
        let c = AtomicWindowCounter::new(100);
        c.check_and_bump(100, 60);
        c.check_and_bump(100, 60);
        c.check_and_bump(100, 60);
        // Jump past the window — next call resets.
        assert_eq!(c.check_and_bump(200, 60), 0);
        assert_eq!(c.check_and_bump(200, 60), 1);
        assert_eq!(c.window_start_secs(), 200);
    }

    /// Window-start exposed for BoundedMap eviction ordering.
    #[test]
    fn window_start_secs_tracks_ws() {
        let c = AtomicWindowCounter::new(12345);
        assert_eq!(c.window_start_secs(), 12345);
        c.check_and_bump(12345, 60);
        assert_eq!(c.window_start_secs(), 12345);
        // Force reset.
        c.check_and_bump(99999, 60);
        assert_eq!(c.window_start_secs(), 99999);
    }

    /// DoD regression: window-crossing under contention. N threads share
    /// one counter; threads in cohort A bump pre-crossing (window valid),
    /// then threads in cohort B bump post-crossing (window elapsed). After
    /// all threads have called, the in-state count must equal exactly the
    /// number of cohort-B calls — no carry-over from cohort A, no torn
    /// intermediate state where cohort B's bumps land on a stale count.
    ///
    /// Determinism via two barriers: cohort A finishes its bumps before
    /// cohort B's bumps begin, so the only race is *within* cohort B
    /// across the reset boundary. With the packed-CAS reset, exactly one
    /// cohort-B thread wins the CAS (returns 0, sets state to (1, t1));
    /// the remaining `B-1` threads see the reset-already-happened state
    /// and take the fetch_add path. Post-state count = B.
    #[test]
    fn window_crossing_under_contention() {
        const A: usize = 4;
        const B: usize = 16;
        const T0: u64 = 1_000;
        const T1: u64 = 2_000; // far past the 60 s window
        const WINDOW: u64 = 60;

        let counter = Arc::new(AtomicWindowCounter::new(T0));

        // Cohort A: 4 threads bump pre-crossing. Sequential semantics
        // via a barrier, then verify post-cohort-A state is (4, T0).
        let barrier_a = Arc::new(Barrier::new(A));
        let handles_a: Vec<_> = (0..A)
            .map(|_| {
                let counter = Arc::clone(&counter);
                let barrier = Arc::clone(&barrier_a);
                thread::spawn(move || {
                    barrier.wait();
                    counter.check_and_bump(T0, WINDOW)
                })
            })
            .collect();
        let priors_a: Vec<u32> = handles_a.into_iter().map(|h| h.join().unwrap()).collect();
        // Each cohort-A thread saw some prior in 0..A.
        let mut sorted_a = priors_a.clone();
        sorted_a.sort_unstable();
        assert_eq!(sorted_a, vec![0, 1, 2, 3], "cohort A priors are 0..A");

        // Cohort B: 16 threads bump post-crossing. The window has long
        // expired; the CAS-reset path applies. Exactly one thread wins
        // the CAS (prior=0); the other 15 see the post-reset state and
        // fetch_add (priors 1..16).
        let barrier_b = Arc::new(Barrier::new(B));
        let handles_b: Vec<_> = (0..B)
            .map(|_| {
                let counter = Arc::clone(&counter);
                let barrier = Arc::clone(&barrier_b);
                thread::spawn(move || {
                    barrier.wait();
                    counter.check_and_bump(T1, WINDOW)
                })
            })
            .collect();
        let priors_b: Vec<u32> = handles_b.into_iter().map(|h| h.join().unwrap()).collect();

        let mut sorted_b = priors_b.clone();
        sorted_b.sort_unstable();
        let expected: Vec<u32> = (0..B as u32).collect();
        assert_eq!(
            sorted_b, expected,
            "cohort B priors are 0..B with no pre-crossing carry-over"
        );

        // Post-state: ws moved to T1, count = B.
        assert_eq!(counter.window_start_secs(), T1);
        let (count_after, ws_after) = unpack(counter.state.load(Ordering::Relaxed));
        assert_eq!(count_after, B as u32, "post-crossing count is exactly B");
        assert_eq!(ws_after as u64, T1);
    }
}
