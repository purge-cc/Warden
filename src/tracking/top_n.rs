//! Top-N domain computation — background task that periodically scans
//! domain frequency maps and produces an immutable snapshot via ArcSwap.
//!
//! Sorting is expensive (O(n log n) on the frequency map), so we do it
//! infrequently (every 10s by default) in a background task. Consumers
//! just load() the ArcSwap — cheap atomic pointer read.

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use compact_str::CompactString;
use dashmap::DashMap;

use serde::{Deserialize, Serialize};

/// Immutable snapshot of top-N domains, stored via ArcSwap.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TopNSnapshot {
    pub top_queried: Vec<(CompactString, u64)>,
    pub top_blocked: Vec<(CompactString, u64)>,
    /// Sprint B Dashboard v2 — top-5 Tier 1 blocklists by recent block
    /// count, keyed by `source_bits` bit (0..=63). Bit → label
    /// resolution is daemon-side (`socket_server::handle_tracking_stats`)
    /// using the `list_labels` snapshot on `DaemonState`. Hard-capped
    /// at 5 entries per `spawn_top_n_task`. `#[serde(default)]` so
    /// pre-Sprint-B `data/stats.json` snapshots still deserialise.
    #[serde(default)]
    pub top_blocked_lists: Vec<(u8, u64)>,
    /// 24h-rolling Top-N by per-domain query count. Each tuple is
    /// `(domain, lifetime_count, count_24h)` so the IPC handler can
    /// emit both fields on `DomainCount` (back-compat) without a
    /// second snapshot read. Ranking key is `count_24h`. Drives the
    /// Dashboard narrow-fallback Top Domains (24h) card.
    #[serde(default)]
    pub top_queried_24h: Vec<(CompactString, u64, u64)>,
    /// 24h-rolling Top-N by per-domain block count. Drives the
    /// Dashboard wide-branch Top Blocked Domains (24h) card.
    #[serde(default)]
    pub top_blocked_24h: Vec<(CompactString, u64, u64)>,
    /// 24h-rolling Top-5 Tier 1 blocklists by block count. Tuples are
    /// `(bit, lifetime_count, count_24h)`. Drives the Dashboard Top
    /// Lists (24h) card.
    #[serde(default)]
    pub top_blocked_lists_24h: Vec<(u8, u64, u64)>,
}

/// Extract top-N entries from a DashMap frequency counter.
pub fn extract_top_n(
    map: &DashMap<CompactString, std::sync::atomic::AtomicU64>,
    limit: usize,
) -> Vec<(CompactString, u64)> {
    // top_n_limit comes straight from config with no clamp. `limit == 0`
    // would underflow `limit - 1` in the partial-sort below — guard it.
    if limit == 0 {
        return Vec::new();
    }
    let mut entries: Vec<(CompactString, u64)> = map
        .iter()
        .map(|e| (e.key().clone(), e.value().load(Ordering::Relaxed)))
        .collect();

    // Partial sort: we only need the top `limit` entries
    if entries.len() > limit {
        entries.select_nth_unstable_by(limit - 1, |a, b| b.1.cmp(&a.1));
        entries.truncate(limit);
    }
    entries.sort_unstable_by_key(|b| std::cmp::Reverse(b.1));
    entries
}

/// Sprint B Dashboard v2 — u8-keyed sibling of [`extract_top_n`] for the
/// per-bit blocklist counters on [`super::engine::StatsEngine::list_blocked`].
///
/// Zero-count entries are filtered out so pre-seeded bits with no
/// traffic do not pollute the snapshot. Otherwise mirrors the partial
/// `select_nth_unstable_by` + sort discipline of the parent helper.
///
/// Picked over generifying `extract_top_n<K: Eq + Hash + Clone>`
/// because the existing function relies on `CompactString::clone()`
/// and a generic version would over-engineer one site for one new
/// key type.
pub fn extract_top_n_u8(
    map: &DashMap<u8, std::sync::atomic::AtomicU64>,
    limit: usize,
) -> Vec<(u8, u64)> {
    if limit == 0 {
        return Vec::new();
    }
    let mut entries: Vec<(u8, u64)> = map
        .iter()
        .filter_map(|e| {
            let count = e.value().load(Ordering::Relaxed);
            if count > 0 {
                Some((*e.key(), count))
            } else {
                None
            }
        })
        .collect();

    if entries.len() > limit {
        entries.select_nth_unstable_by(limit - 1, |a, b| b.1.cmp(&a.1));
        entries.truncate(limit);
    }
    entries.sort_unstable_by_key(|b| std::cmp::Reverse(b.1));
    entries
}

/// 24h-rolling Top-N for per-domain `HourlyRing` counters. Reads each
/// entry's `sum_last_24h(now)` (24 atomic loads per entry) and ranks
/// by it. Zero-sum entries are filtered out so cold ring entries don't
/// pollute the snapshot. Joins each survivor with the lifetime
/// counter (`lifetime_lookup`) so the IPC layer can emit both
/// `count` and `count_24h` without a second pass.
///
/// Cost: O(N × 24) atomic loads on the ring map + O(N) lifetime
/// lookups. At MAX_DOMAIN_FREQ_ENTRIES = 10_000, that's ~240k relaxed
/// loads per tick — trivial. Do not refactor into "skip
/// `sum_last_24h` when count is already known" cleverness: §4.39 made
/// the ring slots generation-tagged, so `sum_last_24h` is what
/// excludes stale (out-of-window) slots when entities go idle.
pub fn extract_top_n_hourly(
    map: &DashMap<CompactString, super::engine::HourlyRing>,
    lifetime: &DashMap<CompactString, std::sync::atomic::AtomicU64>,
    now_secs: u64,
    limit: usize,
) -> Vec<(CompactString, u64, u64)> {
    if limit == 0 {
        return Vec::new();
    }
    let mut entries: Vec<(CompactString, u64, u64)> = map
        .iter()
        .filter_map(|e| {
            let count_24h = e.value().sum_last_24h(now_secs);
            if count_24h == 0 {
                return None;
            }
            let lifetime_count = lifetime
                .get(e.key())
                .map(|c| c.value().load(Ordering::Relaxed))
                .unwrap_or(0);
            Some((e.key().clone(), lifetime_count, count_24h))
        })
        .collect();

    if entries.len() > limit {
        entries.select_nth_unstable_by(limit - 1, |a, b| b.2.cmp(&a.2));
        entries.truncate(limit);
    }
    entries.sort_unstable_by_key(|b| std::cmp::Reverse(b.2));
    entries
}

/// 24h-rolling Top-N sibling of [`extract_top_n_u8`] for the per-list
/// `HourlyRing` map. Same shape as [`extract_top_n_hourly`] but
/// u8-keyed and joined against the per-bit lifetime counter.
pub fn extract_top_n_u8_hourly(
    map: &DashMap<u8, super::engine::HourlyRing>,
    lifetime: &DashMap<u8, std::sync::atomic::AtomicU64>,
    now_secs: u64,
    limit: usize,
) -> Vec<(u8, u64, u64)> {
    if limit == 0 {
        return Vec::new();
    }
    let mut entries: Vec<(u8, u64, u64)> = map
        .iter()
        .filter_map(|e| {
            let count_24h = e.value().sum_last_24h(now_secs);
            if count_24h == 0 {
                return None;
            }
            let lifetime_count = lifetime
                .get(e.key())
                .map(|c| c.value().load(Ordering::Relaxed))
                .unwrap_or(0);
            Some((*e.key(), lifetime_count, count_24h))
        })
        .collect();

    if entries.len() > limit {
        entries.select_nth_unstable_by(limit - 1, |a, b| b.2.cmp(&a.2));
        entries.truncate(limit);
    }
    entries.sort_unstable_by_key(|b| std::cmp::Reverse(b.2));
    entries
}

/// Spawn the top-N background computation task.
///
/// Runs every `interval` seconds, scans frequency maps, updates the ArcSwap.
/// Also prunes low-frequency entries to prevent unbounded map growth.
pub fn spawn_top_n_task(
    engine: Arc<super::engine::StatsEngine>,
    limit: usize,
    interval: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        // `tokio::time::interval` panics on a zero period — under the release
        // profile's `panic = "abort"` that kills the daemon. The validator
        // rejects `tracking.top_n_interval_secs = 0`; this floor is the
        // backstop for construction paths that bypass it (settings-02,
        // mirrors prefetch_worker).
        let mut ticker = tokio::time::interval(interval.max(Duration::from_secs(1)));
        ticker.tick().await; // skip first immediate tick
        loop {
            ticker.tick().await;

            let top_queried = extract_top_n(&engine.domain_queries, limit);
            let top_blocked = extract_top_n(&engine.domain_blocked, limit);
            // Sprint B Dashboard v2 — top-5 Tier 1 blocklists by block
            // count. Hard-cap of 5 per design (D8 in
            // `_docs/features/dashboard_v2.md`), independent of the
            // domain-top-N `limit`.
            let top_blocked_lists = extract_top_n_u8(&engine.list_blocked, 5);

            // Snapshot `now_secs` once so prune + extract see a
            // consistent window boundary. `sum_last_24h` is a pure read
            // since §4.39 (generation-tagged slots — no mutation, no
            // advance step); ring hygiene is owned by `prune_hourly_map`.
            let now_secs = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let top_queried_24h = extract_top_n_hourly(
                &engine.domain_queries_hourly,
                &engine.domain_queries,
                now_secs,
                limit,
            );
            let top_blocked_24h = extract_top_n_hourly(
                &engine.domain_blocked_hourly,
                &engine.domain_blocked,
                now_secs,
                limit,
            );
            let top_blocked_lists_24h = extract_top_n_u8_hourly(
                &engine.list_blocked_hourly,
                &engine.list_blocked,
                now_secs,
                5,
            );

            engine.top_n.store(Arc::new(TopNSnapshot {
                top_queried,
                top_blocked,
                top_blocked_lists,
                top_queried_24h,
                top_blocked_24h,
                top_blocked_lists_24h,
            }));

            // Prune maps if over capacity
            engine.prune_domain_freq();
            engine.prune_hourly_domain_freq(now_secs);
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU64;

    #[test]
    fn extract_top_n_correct_order() {
        let map: DashMap<CompactString, AtomicU64> = DashMap::new();
        map.insert(CompactString::from("a.com"), AtomicU64::new(10));
        map.insert(CompactString::from("b.com"), AtomicU64::new(50));
        map.insert(CompactString::from("c.com"), AtomicU64::new(30));
        map.insert(CompactString::from("d.com"), AtomicU64::new(5));

        let top = extract_top_n(&map, 3);
        assert_eq!(top.len(), 3);
        assert_eq!(top[0].0.as_str(), "b.com");
        assert_eq!(top[0].1, 50);
        assert_eq!(top[1].0.as_str(), "c.com");
        assert_eq!(top[1].1, 30);
        assert_eq!(top[2].0.as_str(), "a.com");
        assert_eq!(top[2].1, 10);
    }

    #[test]
    fn extract_top_n_fewer_than_limit() {
        let map: DashMap<CompactString, AtomicU64> = DashMap::new();
        map.insert(CompactString::from("only.com"), AtomicU64::new(42));

        let top = extract_top_n(&map, 10);
        assert_eq!(top.len(), 1);
        assert_eq!(top[0].1, 42);
    }

    #[test]
    fn extract_top_n_empty_map() {
        let map: DashMap<CompactString, AtomicU64> = DashMap::new();
        let top = extract_top_n(&map, 10);
        assert!(top.is_empty());
    }

    /// settings-02 (rev-2606): a zero interval reaching the spawn site must
    /// not panic the task — `tokio::time::interval(0)` panics and the release
    /// profile aborts on panic. The `.max(1 s)` floor is the backstop for
    /// construction paths that bypass the validator gate.
    #[tokio::test]
    async fn zero_interval_does_not_panic_task() {
        let config = crate::config::settings::TrackingConfig::default();
        let engine = Arc::new(super::super::engine::StatsEngine::new(&config));
        let handle = spawn_top_n_task(engine, 5, Duration::ZERO);
        // An interval panic fires at the task's first poll; give it ample
        // time, then confirm the loop is still alive (a panicked task would
        // report finished).
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!handle.is_finished(), "task died on zero interval");
        handle.abort();
    }

    /// trk-top-n-limit-zero-panic regression: `limit == 0` (an
    /// unvalidated `top_n_limit`) over a non-empty map must return empty
    /// rather than underflow `limit - 1` and panic the background task.
    #[test]
    fn extract_top_n_zero_limit_no_panic() {
        let map: DashMap<CompactString, AtomicU64> = DashMap::new();
        map.insert(CompactString::from("a.com"), AtomicU64::new(10));
        map.insert(CompactString::from("b.com"), AtomicU64::new(50));
        assert!(extract_top_n(&map, 0).is_empty());

        let u8_map: DashMap<u8, AtomicU64> = DashMap::new();
        u8_map.insert(0, AtomicU64::new(7));
        assert!(extract_top_n_u8(&u8_map, 0).is_empty());

        use super::super::engine::HourlyRing;
        let ring_map: DashMap<CompactString, HourlyRing> = DashMap::new();
        let r = HourlyRing::new();
        r.record(3600);
        ring_map.insert(CompactString::from("a.com"), r);
        assert!(extract_top_n_hourly(&ring_map, &map, 3600, 0).is_empty());

        let u8_ring: DashMap<u8, HourlyRing> = DashMap::new();
        let r2 = HourlyRing::new();
        r2.record(3600);
        u8_ring.insert(0, r2);
        assert!(extract_top_n_u8_hourly(&u8_ring, &u8_map, 3600, 0).is_empty());
    }

    /// Sprint B Dashboard v2 — `extract_top_n_u8` produces a
    /// descending-by-count list, caps at the requested limit, and
    /// filters out zero-count entries (pre-seeded but cold bits must
    /// not pollute the snapshot).
    #[test]
    fn top_n_extracts_blocked_lists_sorted_capped() {
        let map: DashMap<u8, AtomicU64> = DashMap::new();
        map.insert(0, AtomicU64::new(10));
        map.insert(1, AtomicU64::new(50));
        map.insert(2, AtomicU64::new(30));
        map.insert(3, AtomicU64::new(5));
        map.insert(4, AtomicU64::new(100));
        map.insert(5, AtomicU64::new(70));
        map.insert(6, AtomicU64::new(0)); // pre-seeded, never hit
        map.insert(7, AtomicU64::new(0)); // pre-seeded, never hit

        let top = extract_top_n_u8(&map, 5);

        assert_eq!(top.len(), 5, "hard-cap at 5");
        assert_eq!(top[0], (4, 100));
        assert_eq!(top[1], (5, 70));
        assert_eq!(top[2], (1, 50));
        assert_eq!(top[3], (2, 30));
        assert_eq!(top[4], (0, 10));
        assert!(
            !top.iter().any(|(_, c)| *c == 0),
            "zero-count entries must be filtered out"
        );
    }

    /// 24h-rolling Top-N ranks by `HourlyRing::sum_last_24h`, joins
    /// against the lifetime map for the second tuple slot, and filters
    /// zero-sum entries so cold ring entries don't pollute the
    /// snapshot.
    #[test]
    fn extract_top_n_hourly_ranks_by_24h_sum() {
        use super::super::engine::{HourlyRing, DEVICE_HOURLY_SLOTS};

        let lifetime: DashMap<CompactString, AtomicU64> = DashMap::new();
        let hourly: DashMap<CompactString, HourlyRing> = DashMap::new();

        // a.com: hot in 24h (heavy traffic at hour H) AND cumulatively.
        // b.com: hot lifetime (sole entry in lifetime) but no recent
        //   traffic — must be filtered out by the zero-sum guard.
        // c.com: medium 24h, medium lifetime.
        // d.com: 24h only, no lifetime entry — lifetime count = 0
        //   fallback.
        let now_secs: u64 = 24 * 3600;
        let hour_now = now_secs / 3600;

        // Seed lifetime counters.
        lifetime.insert(CompactString::from("a.com"), AtomicU64::new(1000));
        lifetime.insert(CompactString::from("b.com"), AtomicU64::new(500));
        lifetime.insert(CompactString::from("c.com"), AtomicU64::new(200));
        // d.com intentionally missing from lifetime map.

        // Seed 24h rings.
        let ring_a = HourlyRing::new();
        for _ in 0..50 {
            ring_a.record(now_secs);
        }
        hourly.insert(CompactString::from("a.com"), ring_a);
        // b.com — fresh ring with no records → sum_last_24h = 0.
        hourly.insert(CompactString::from("b.com"), HourlyRing::new());
        let ring_c = HourlyRing::new();
        for _ in 0..20 {
            ring_c.record(now_secs);
        }
        hourly.insert(CompactString::from("c.com"), ring_c);
        let ring_d = HourlyRing::new();
        for _ in 0..30 {
            ring_d.record(now_secs);
        }
        hourly.insert(CompactString::from("d.com"), ring_d);
        let _ = hour_now; // suppress unused

        let top = extract_top_n_hourly(&hourly, &lifetime, now_secs, 10);

        // b.com must be filtered (zero 24h sum), the rest ranked desc.
        assert_eq!(top.len(), 3);
        assert_eq!(top[0].0.as_str(), "a.com");
        assert_eq!(top[0].1, 1000); // lifetime
        assert_eq!(top[0].2, 50); // 24h
        assert_eq!(top[1].0.as_str(), "d.com");
        assert_eq!(top[1].1, 0); // missing lifetime → 0
        assert_eq!(top[1].2, 30);
        assert_eq!(top[2].0.as_str(), "c.com");
        assert_eq!(top[2].1, 200);
        assert_eq!(top[2].2, 20);
        assert!(
            !top.iter().any(|(name, _, _)| name.as_str() == "b.com"),
            "b.com has lifetime=500 but 24h=0 — must be filtered out"
        );
        let _ = DEVICE_HOURLY_SLOTS; // ensure import is used
    }

    /// 24h-rolling Top-N for the u8-keyed `list_blocked_hourly` ring.
    /// Same shape as the per-domain variant; filters zero-sum.
    #[test]
    fn extract_top_n_u8_hourly_ranks_by_24h_sum() {
        use super::super::engine::HourlyRing;

        let lifetime: DashMap<u8, AtomicU64> = DashMap::new();
        let hourly: DashMap<u8, HourlyRing> = DashMap::new();

        let now_secs: u64 = 36_000;

        lifetime.insert(0, AtomicU64::new(1000));
        lifetime.insert(1, AtomicU64::new(800));
        lifetime.insert(2, AtomicU64::new(100));

        let r0 = HourlyRing::new();
        for _ in 0..10 {
            r0.record(now_secs);
        }
        hourly.insert(0, r0);
        // bit 1 — pre-seeded but no traffic in 24h.
        hourly.insert(1, HourlyRing::new());
        let r2 = HourlyRing::new();
        for _ in 0..50 {
            r2.record(now_secs);
        }
        hourly.insert(2, r2);

        let top = extract_top_n_u8_hourly(&hourly, &lifetime, now_secs, 5);

        assert_eq!(top.len(), 2, "bit 1 must be filtered (24h sum = 0)");
        assert_eq!(top[0], (2, 100, 50));
        assert_eq!(top[1], (0, 1000, 10));
    }
}
