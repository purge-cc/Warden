//! Per-client query rate limiting via atomic token bucket.
//!
//! Each client IP gets a bucket that refills at `queries_per_second` rate.
//! Burst capacity allows short spikes (e.g. page loads). The bucket state
//! is packed into a single AtomicU64 for lock-free CAS updates.
//!
//! Layout: upper 32 bits = available tokens, lower 32 bits = last refill
//! timestamp (seconds since tracker creation, wraps at ~136 years).

use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use arc_swap::ArcSwap;

use super::bounded_map::BoundedMap;
use crate::config::settings::RateLimitConfig;

/// Hard cap on the number of tracked client IPs (P0-4).
///
/// Prevents memory DoS from a slow-rate flood of unique source IPs. When
/// the cap is reached, new inserts trigger an approximate-LRU eviction of
/// the oldest bucket. IPv6 clients can otherwise pin unbounded memory (the
/// /128 address space makes strict per-IP tracking unsafe without this).
const MAX_TRACKED_CLIENTS: usize = 100_000;

/// Extract the last-refill timestamp (lower 32 bits) from a bucket's state
/// for [`BoundedMap`] eviction ordering. Smaller = older = evicted first.
fn bucket_age(bucket: &Bucket) -> u64 {
    let (_, last_refill) = unpack(bucket.state.load(Ordering::Relaxed));
    last_refill as u64
}

/// Pack tokens (upper 32) and timestamp (lower 32) into a u64.
fn pack(tokens: u32, timestamp: u32) -> u64 {
    ((tokens as u64) << 32) | (timestamp as u64)
}

/// Unpack tokens and timestamp from a u64.
fn unpack(packed: u64) -> (u32, u32) {
    let tokens = (packed >> 32) as u32;
    let timestamp = packed as u32;
    (tokens, timestamp)
}

/// Per-client token bucket state, stored as a single atomic.
struct Bucket {
    /// Packed: [tokens: u32 | last_refill_secs: u32]
    state: AtomicU64,
}

impl Bucket {
    fn new(burst: u32, now_secs: u32) -> Self {
        Self {
            state: AtomicU64::new(pack(burst, now_secs)),
        }
    }

    /// Try to consume one token. Returns true if allowed, false if rate-limited.
    ///
    /// Refills tokens based on elapsed time since last refill, then attempts
    /// to decrement. Uses a CAS loop for lock-free concurrency.
    ///
    /// Correctness invariant: every iteration loads the *current* packed
    /// state and derives the refilled count from that snapshot. The CAS
    /// compares against the same snapshot, so a concurrent mutation causes
    /// a retry that re-reads the updated state — no double-counting of
    /// elapsed refill time.
    fn try_acquire(&self, now_secs: u32, qps: u32, burst: u32) -> bool {
        loop {
            let current = self.state.load(Ordering::Relaxed);
            let (tokens, last_refill) = unpack(current);

            // Refill tokens based on elapsed time since last refill
            let elapsed = now_secs.saturating_sub(last_refill);
            let (available, ts) = if elapsed > 0 {
                let refilled = tokens
                    .saturating_add(elapsed.saturating_mul(qps))
                    .min(burst);
                (refilled, now_secs)
            } else {
                (tokens, last_refill)
            };

            if available == 0 {
                return false;
            }

            let desired = pack(available - 1, ts);

            // CAS: if `current` changed since our load, another thread
            // mutated the bucket — retry with the fresh state.
            match self.state.compare_exchange_weak(
                current,
                desired,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(_) => continue,
            }
        }
    }
}

/// Per-client rate limiter. Lock-free on the hot path.
///
/// Backed by a [`BoundedMap`] with a soft cap of [`MAX_TRACKED_CLIENTS`] —
/// prevents memory DoS from unique-source floods (P0-4). When the cap is
/// reached, new inserts evict the bucket with the oldest last-refill
/// timestamp via sample-8 approximate LRU.
pub struct RateLimiter {
    buckets: BoundedMap<IpAddr, Bucket>,
    /// Live-swappable qps + burst. See [`RateLimiterParams`].
    params: ArcSwap<RateLimiterParams>,
    /// Monotonic epoch every bucket's `last_refill` is measured against.
    /// Deliberately **outside** [`Self::params`]: swapping it on reload
    /// would silently corrupt every live bucket's refill math rather
    /// than retune anything.
    created_at: Instant,
}

/// The reload-swappable half of [`RateLimiter`].
///
/// Split out of [`RateLimiter`] so `warden security set
/// rate_limit.queries_per_second …` takes effect without a daemon
/// restart. `buckets` is *not* in here on purpose: rebuilding the whole
/// limiter on reload would zero every token bucket, handing every
/// client a fresh burst on each config edit.
#[derive(Debug, Clone)]
struct RateLimiterParams {
    qps: u32,
    burst: u32,
}

impl RateLimiterParams {
    fn from_config(config: &RateLimitConfig) -> Self {
        Self {
            qps: config.queries_per_second,
            burst: config.burst,
        }
    }
}

impl RateLimiter {
    pub fn new(config: &RateLimitConfig) -> Self {
        Self {
            buckets: BoundedMap::new(MAX_TRACKED_CLIENTS, bucket_age),
            params: ArcSwap::from_pointee(RateLimiterParams::from_config(config)),
            created_at: Instant::now(),
        }
    }

    /// Swap qps + burst in place, preserving every live bucket. Called
    /// from the daemon's config-reload path.
    pub fn set_params(&self, config: &RateLimitConfig) {
        self.params
            .store(Arc::new(RateLimiterParams::from_config(config)));
    }

    /// Check if a query from this IP is allowed. Returns true if under the limit.
    ///
    /// L-1 (rev-2026-04-ratelimit-toctou): atomic get-or-insert via
    /// `BoundedMap::entry_or_insert_with` closes the prior get-then-insert
    /// race. Two concurrent first queries from the same fresh IP now share
    /// the same bucket — both call `try_acquire` and the budget remains
    /// `burst`, not `2 * burst`.
    ///
    /// **Exactly one `params.load()` per call.** A second load could pair
    /// a pre-reload qps with a post-reload burst (or vice versa),
    /// producing a budget that matches neither configuration.
    pub fn check(&self, ip: &IpAddr) -> bool {
        let now_secs = self.created_at.elapsed().as_secs() as u32;
        let p = self.params.load();

        let bucket = self
            .buckets
            .entry_or_insert_with(*ip, || Bucket::new(p.burst, now_secs));
        bucket.try_acquire(now_secs, p.qps, p.burst)
    }

    /// Remove stale entries (clients not seen for over 5 minutes).
    /// Call periodically from a background task.
    pub fn cleanup(&self) {
        let now_secs = self.created_at.elapsed().as_secs() as u32;
        let stale_threshold = 300; // 5 minutes

        self.buckets.retain(|_, bucket| {
            let (_, last_refill) = unpack(bucket.state.load(Ordering::Relaxed));
            now_secs.saturating_sub(last_refill) < stale_threshold
        });
    }

    /// Current number of tracked client IPs. Exposed so the stats engine
    /// (and the upcoming /metrics endpoint, P1-13) can publish it.
    pub fn entry_count(&self) -> usize {
        self.buckets.len()
    }

    /// Number of tracked clients.
    #[cfg(test)]
    pub fn client_count(&self) -> usize {
        self.buckets.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn test_config(qps: u32, burst: u32) -> RateLimitConfig {
        RateLimitConfig {
            enabled: true,
            queries_per_second: qps,
            burst,
        }
    }

    #[test]
    fn pack_unpack_roundtrip() {
        let (t, ts) = (42u32, 1000u32);
        let packed = pack(t, ts);
        assert_eq!(unpack(packed), (t, ts));
    }

    #[test]
    fn pack_unpack_max_values() {
        let packed = pack(u32::MAX, u32::MAX);
        assert_eq!(unpack(packed), (u32::MAX, u32::MAX));
    }

    #[test]
    fn allows_queries_under_burst() {
        let rl = RateLimiter::new(&test_config(10, 5));
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        // Burst of 5 should be allowed
        for _ in 0..5 {
            assert!(rl.check(&ip));
        }
    }

    #[test]
    fn blocks_after_burst_exhausted() {
        let rl = RateLimiter::new(&test_config(10, 5));
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        // Exhaust burst
        for _ in 0..5 {
            assert!(rl.check(&ip));
        }

        // Next query should be blocked (no time for refill)
        assert!(!rl.check(&ip));
    }

    #[test]
    fn different_ips_independent() {
        let rl = RateLimiter::new(&test_config(10, 2));
        let ip1 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let ip2 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2));

        // Exhaust ip1's burst
        assert!(rl.check(&ip1));
        assert!(rl.check(&ip1));
        assert!(!rl.check(&ip1));

        // ip2 should still have full burst
        assert!(rl.check(&ip2));
        assert!(rl.check(&ip2));
    }

    #[test]
    fn client_count_tracks_unique_ips() {
        let rl = RateLimiter::new(&test_config(10, 5));
        assert_eq!(rl.client_count(), 0);

        rl.check(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(rl.client_count(), 1);

        rl.check(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
        assert_eq!(rl.client_count(), 2);

        // Same IP again — no new entry
        rl.check(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(rl.client_count(), 2);
    }

    #[test]
    fn burst_one_allows_single_query() {
        let rl = RateLimiter::new(&test_config(1, 1));
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

        assert!(rl.check(&ip));
        assert!(!rl.check(&ip));
    }

    #[test]
    fn refill_restores_tokens() {
        // This test exercises the refill path by directly manipulating bucket state
        let bucket = Bucket::new(5, 100);

        // Consume all tokens at time=100
        for _ in 0..5 {
            assert!(bucket.try_acquire(100, 10, 5));
        }
        assert!(!bucket.try_acquire(100, 10, 5));

        // At time=101, 10 tokens should be refilled (but capped at burst=5)
        assert!(bucket.try_acquire(101, 10, 5));
    }

    /// `warden security set rate_limit.*` must apply without a daemon
    /// restart, and the swap must not hand every client bucket a fresh
    /// token count on each config edit.
    #[test]
    fn set_params_applies_without_restart_and_preserves_bucket_state() {
        let rl = RateLimiter::new(&test_config(0, 3)); // qps=0: no refill, ever
        let spent = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

        for _ in 0..3 {
            assert!(rl.check(&spent));
        }
        assert!(
            !rl.check(&spent),
            "burst=3 must be exhausted before the swap"
        );

        rl.set_params(&test_config(0, 50));

        // A bucket created AFTER the swap must see the NEW burst
        // immediately — this is the whole point of the reload path.
        let fresh = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        for _ in 0..50 {
            assert!(
                rl.check(&fresh),
                "a bucket created after set_params must use the new burst"
            );
        }
        assert!(!rl.check(&fresh));

        // The bucket that was ALREADY exhausted must not be handed a
        // fresh budget just because the config changed underneath it —
        // rebuilding `buckets` on reload would be a free reset for
        // every in-flight client.
        assert!(
            !rl.check(&spent),
            "a pre-swap exhausted bucket must still be exhausted after the swap"
        );
    }

    #[test]
    fn concurrent_first_queries_share_one_burst_budget() {
        // L-1 (rev-2026-04-ratelimit-toctou) regression pin: two or more
        // concurrent first queries from the same fresh IP previously each
        // passed the get-None check and each inserted a fresh bucket — the
        // last writer won, but every racing query had already returned true,
        // giving an effective initial budget of (threads × burst). The fix
        // replaces get-then-insert with `BoundedMap::entry_or_insert_with`,
        // which is atomic at the shard level. Pin the new contract: with
        // qps=0 (no refill) and N threads racing on the same fresh IP,
        // exactly `burst` succeed.
        use std::sync::{Arc, Barrier};
        use std::thread;

        let burst = 10u32;
        let threads = 32usize;

        // qps=0 ensures no token ever refills during the test, so the only
        // budget is the initial burst — any leak shows up as extra `true`s.
        let rl = Arc::new(RateLimiter::new(&test_config(0, burst)));
        let ip = IpAddr::V4(Ipv4Addr::new(10, 9, 9, 9));
        let barrier = Arc::new(Barrier::new(threads));

        let handles: Vec<_> = (0..threads)
            .map(|_| {
                let rl = Arc::clone(&rl);
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    rl.check(&ip)
                })
            })
            .collect();

        let allowed = handles
            .into_iter()
            .map(|h| h.join().unwrap_or(false))
            .filter(|allowed| *allowed)
            .count();

        assert_eq!(
            allowed, burst as usize,
            "L-1 regression: exactly burst={burst} concurrent first-queries should be allowed, got {allowed}"
        );
        // Exactly one bucket exists for the IP — no overwrites or leaks.
        assert_eq!(rl.client_count(), 1);
    }
}
