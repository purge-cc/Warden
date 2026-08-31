//! Hit-frequency tracker for popular domains (Sprint §4.4 Phase 1/2).
//!
//! Tracks per-domain cache-hit counts in a sliding window with
//! decay-on-write CAS — there is no background task in Phase 1.
//! When a domain crosses `min_hits` within a window, its `is_in_pool`
//! flag flips to `true`; on the next window-boundary crossing with too
//! few accumulated hits, the flag flips back to `false`.
//!
//! # Scope (Phase 1/2)
//!
//! Data plane only. The pool is exported via the existing `TrackingStats`
//! IPC surface but **no DNS-side behaviour reads it yet** — Phase 2/2
//! will add the proactive refresh worker that consumes the pool snapshot
//! and the TUI Pulse row.
//!
//! # Why no parallel `HashSet`
//!
//! An earlier draft kept an `ArcSwap<HashSet<domain>>` mirroring the
//! promoted entries. That set could not observe `BoundedMap`'s
//! approximate-LRU eviction, so an evicted-but-promoted domain would
//! leak into `pool_size` indefinitely. Storing `is_in_pool` inside
//! `HitState` ties the membership lifetime to the entry lifetime — when
//! eviction drops the entry, the in-pool flag goes with it. Reads cost
//! one `BoundedMap::count_where` iteration; for the configured
//! `max_pool_size` (≤16384) that is microseconds at IPC-poll cadence.
//!
//! # Hot-path discipline
//!
//! `record_hit` is the only DNS-side caller. When the tracker is
//! disabled (the default in Phase 1) it short-circuits before any state
//! mutation, costing one branch on a `bool` field. When enabled it
//! performs:
//!
//! - one `BoundedMap::entry_or_insert_with` (atomic shard insert),
//! - two-to-three relaxed atomic ops on `HitState`,
//! - at most one `compare_exchange` on the `is_in_pool` flag.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use compact_str::CompactString;

use crate::security::bounded_map::BoundedMap;

/// Configuration block for the hit-frequency tracker. Mirrors the four
/// `cache.prefetch_tracker_*` keys in `[cache]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrefetchTrackerConfig {
    /// Master enable flag. Default `false` in Phase 1 — operators opt in
    /// per-deploy and Phase 2/2 may flip the default once the refresh
    /// worker has burned in.
    pub enabled: bool,
    /// Sliding-window length in seconds. The counter resets at
    /// `now / window_secs * window_secs` boundaries.
    pub window_secs: u64,
    /// Minimum hit count within a window for a domain to enter the pool.
    pub min_hits: u32,
    /// Soft cap on tracked domains (sample-LRU eviction on overflow).
    /// Sized so the map fits comfortably on a Pi Zero 2 W (512 MB RAM).
    pub max_pool_size: u32,
}

impl Default for PrefetchTrackerConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            window_secs: 300,
            min_hits: 3,
            max_pool_size: 1024,
        }
    }
}

/// Per-domain mutable state held inside the `BoundedMap`. The eviction
/// ordering function inspects `window_start_secs` (smaller = older).
struct HitState {
    /// Hits accumulated within the current window. Initialised to 0 so
    /// the first `fetch_add(1)` lands at 1 cleanly without an off-by-one.
    hit_count: AtomicU64,
    /// Window start, normalised to a `window_secs` boundary.
    window_start_secs: AtomicU64,
    /// Whether this domain is currently considered "popular" — set when
    /// `hit_count` first crosses `min_hits` and cleared on the next
    /// window-boundary record_hit that observes too few hits.
    is_in_pool: AtomicBool,
}

impl HitState {
    fn fresh(window: u64) -> Self {
        Self {
            hit_count: AtomicU64::new(0),
            window_start_secs: AtomicU64::new(window),
            is_in_pool: AtomicBool::new(false),
        }
    }
}

/// `BoundedMap` ordering function — eviction prefers the entry with the
/// oldest `window_start_secs` (i.e. the domain that has gone the longest
/// without a hit).
fn hit_state_age(s: &HitState) -> u64 {
    s.window_start_secs.load(Ordering::Relaxed)
}

/// How many idle windows a promoted domain may go without a client hit
/// before the refresh worker time-demotes it (rev-2606 prefetch-01).
/// Demotion otherwise only fires on a window-boundary client hit, so a
/// domain nobody queries again would stay warm upstream forever. Three
/// windows gives a re-query grace period before the worker lets it cool.
const PROMOTION_IDLE_WINDOWS: u64 = 3;

/// Hit-frequency tracker.
pub struct HitTracker {
    enabled: bool,
    window_secs: u64,
    min_hits: u64,
    map: BoundedMap<CompactString, HitState>,
    promotions_total: AtomicU64,
    demotions_total: AtomicU64,
}

impl HitTracker {
    /// Build a tracker. When `config.enabled = false` the tracker is
    /// inert: `record_hit` short-circuits and counters stay at zero.
    pub fn new(config: &PrefetchTrackerConfig) -> Self {
        // Defensive floors guard against div-by-zero / zero-cap if a
        // downstream caller bypasses the validator. The validator is the
        // primary line of defence; this is belt-and-braces.
        let window_secs = config.window_secs.max(1);
        let cap = (config.max_pool_size as usize).max(1);
        Self {
            enabled: config.enabled,
            window_secs,
            min_hits: u64::from(config.min_hits.max(1)),
            map: BoundedMap::new(cap, hit_state_age),
            promotions_total: AtomicU64::new(0),
            demotions_total: AtomicU64::new(0),
        }
    }

    /// Record a positive cache hit. No-op when the tracker is disabled
    /// or `domain` is empty (the empty-suffix early return mirrors the
    /// L-13 hot-path audit guard in `filter::rules::is_subdomain_of`).
    ///
    /// `now_secs` is the unix-seconds clock the caller already computed
    /// for other purposes — passed in so tests can drive synthetic
    /// timelines without a clock indirection.
    pub fn record_hit(&self, domain: &str, now_secs: u64) {
        if !self.enabled || domain.is_empty() {
            return;
        }

        let current_window = (now_secs / self.window_secs) * self.window_secs;
        let key = normalise(domain);

        let entry = self
            .map
            .entry_or_insert_with(key, || HitState::fresh(current_window));
        let stored = entry.window_start_secs.load(Ordering::Relaxed);
        if stored == current_window {
            // Same window — bump the counter and consider promotion.
            let new_count = entry.hit_count.fetch_add(1, Ordering::Relaxed) + 1;
            if new_count >= self.min_hits {
                self.maybe_promote(entry.value());
            }
        } else {
            // Window boundary crossed — observe the new window with one
            // hit and consider demotion. Because `min_hits >= 1`, a
            // single hit on a freshly-rotated counter never triggers
            // promotion, so we only check the demotion side here.
            entry
                .window_start_secs
                .store(current_window, Ordering::Relaxed);
            entry.hit_count.store(1, Ordering::Relaxed);
            if self.min_hits == 1 {
                // Edge case: when the threshold is 1, a single hit in a
                // fresh window is enough to (re-)promote.
                self.maybe_promote(entry.value());
            } else {
                self.maybe_demote(entry.value());
            }
        }
        // shard guard dropped at end of scope
    }

    /// CAS the `is_in_pool` flag from `false` to `true`. Bumps the
    /// promotions counter only when the CAS wins, so concurrent racers
    /// can't double-count.
    fn maybe_promote(&self, state: &HitState) {
        if state
            .is_in_pool
            .compare_exchange(false, true, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            self.promotions_total.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// CAS the `is_in_pool` flag from `true` to `false`. Mirrors
    /// `maybe_promote` so demotions and promotions never share a single
    /// counter increment under contention.
    fn maybe_demote(&self, state: &HitState) {
        if state
            .is_in_pool
            .compare_exchange(true, false, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            self.demotions_total.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Number of domains currently in the pool. Iterates the bounded
    /// map, so cost is `O(tracked_domains)` — acceptable at IPC-poll
    /// cadence (microseconds for `max_pool_size` ≤ 16k).
    pub fn pool_size(&self) -> usize {
        self.map
            .count_where(|state| state.is_in_pool.load(Ordering::Relaxed))
    }

    /// Cumulative promotion count since startup (or the most recent
    /// snapshot restore).
    pub fn promotions_total(&self) -> u64 {
        self.promotions_total.load(Ordering::Relaxed)
    }

    /// Cumulative demotion count since startup (or the most recent
    /// snapshot restore).
    pub fn demotions_total(&self) -> u64 {
        self.demotions_total.load(Ordering::Relaxed)
    }

    /// Membership query — Phase 2/2 will use this to decide which
    /// domains the proactive refresh worker should exercise. Empty
    /// domain returns `false` (L-13 guard).
    pub fn is_promoted(&self, domain: &str) -> bool {
        if domain.is_empty() {
            return false;
        }
        let key = normalise(domain);
        match self.map.get(&key) {
            Some(state) => state.is_in_pool.load(Ordering::Relaxed),
            None => false,
        }
    }

    /// Bulk snapshot of every domain currently in the pool. Sprint §4.4
    /// P2's background refresh worker calls this once per `tick_secs`
    /// (default 30s) to enumerate the hot set. Cost is one
    /// `BoundedMap::snapshot_keys_where` iteration plus one
    /// `CompactString::clone` per match — measured in microseconds at
    /// the configured `max_pool_size` ceilings (≤16 384).
    ///
    /// Returns an empty `Vec` when the tracker is disabled. Result
    /// ordering is unspecified — DashMap iterates by shard hash order.
    /// The pool's soft-cap semantics mean a briefly-evicted domain may
    /// or may not appear; the worker tolerates this because a
    /// non-existent cache entry simply skips the refresh attempt.
    pub fn snapshot_promoted(&self) -> Vec<CompactString> {
        if !self.enabled {
            return Vec::new();
        }
        self.map
            .snapshot_keys_where(|state| state.is_in_pool.load(Ordering::Relaxed))
    }

    /// Like [`snapshot_promoted`](Self::snapshot_promoted) but also
    /// time-demotes domains that have gone cold: any promoted entry
    /// whose last client hit (`window_start_secs`) predates
    /// `PROMOTION_IDLE_WINDOWS` windows is demoted (`is_in_pool` → false)
    /// and excluded from the returned set.
    ///
    /// prefetch-01 (rev-2606): demotion otherwise only fires on a
    /// window-boundary *client* hit (`record_hit`). A domain nobody
    /// queries again never gets a `record_hit`, so it stayed promoted
    /// indefinitely and the refresh worker kept it warm upstream — a
    /// self-sustaining query loop for a dead domain, bounded only by cap
    /// pressure. Runs at the worker's tick cadence (background, off the
    /// DNS hot path); the demotion is a CAS-guarded atomic flip.
    pub fn snapshot_promoted_pruning_stale(&self, now_secs: u64) -> Vec<CompactString> {
        if !self.enabled {
            return Vec::new();
        }
        let current_window = (now_secs / self.window_secs) * self.window_secs;
        let idle_horizon = PROMOTION_IDLE_WINDOWS.saturating_mul(self.window_secs);
        let stale_before = current_window.saturating_sub(idle_horizon);
        self.map.snapshot_keys_where(|state| {
            if !state.is_in_pool.load(Ordering::Relaxed) {
                return false;
            }
            if state.window_start_secs.load(Ordering::Relaxed) < stale_before {
                // Cold past the idle horizon — demote and drop from the
                // refresh set so the worker stops keeping it warm.
                self.maybe_demote(state);
                false
            } else {
                true
            }
        })
    }

    /// True iff the tracker is configured to record hits.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Seed the cumulative counters from a persisted snapshot. The pool
    /// itself is **not** restored — it rebuilds from live query
    /// traffic, which keeps the on-disk format simple and avoids
    /// resurrecting domains that have gone cold across the daemon
    /// downtime. Sprint §4.4 P1 — only the running totals are stitched
    /// across restarts so the TUI / IPC counters stay monotonic.
    pub fn restore_counters(&self, promotions: u64, demotions: u64) {
        self.promotions_total.store(promotions, Ordering::Relaxed);
        self.demotions_total.store(demotions, Ordering::Relaxed);
    }
}

/// Lowercase-normalise a domain only when uppercase is detected. The
/// blocklist ingestion path already lowercases, so production cache
/// keys are already lowercase — this is defensive belt-and-braces.
fn normalise(domain: &str) -> CompactString {
    if domain.bytes().any(|b| b.is_ascii_uppercase()) {
        CompactString::from(domain.to_ascii_lowercase())
    } else {
        CompactString::from(domain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enabled_cfg() -> PrefetchTrackerConfig {
        PrefetchTrackerConfig {
            enabled: true,
            window_secs: 60,
            min_hits: 3,
            max_pool_size: 128,
        }
    }

    #[test]
    fn disabled_tracker_is_inert() {
        let t = HitTracker::new(&PrefetchTrackerConfig::default());
        for _ in 0..50 {
            t.record_hit("google.com", 1_000);
        }
        assert_eq!(t.pool_size(), 0);
        assert_eq!(t.promotions_total(), 0);
        assert_eq!(t.demotions_total(), 0);
        assert!(!t.is_promoted("google.com"));
    }

    #[test]
    fn empty_domain_early_returns_silently() {
        let t = HitTracker::new(&enabled_cfg());
        for _ in 0..10 {
            t.record_hit("", 1_000);
        }
        assert_eq!(t.pool_size(), 0);
        assert_eq!(t.promotions_total(), 0);
        assert!(!t.is_promoted(""));
    }

    #[test]
    fn hit_below_threshold_does_not_promote() {
        let t = HitTracker::new(&enabled_cfg());
        // Two hits in the same window with min_hits=3 → no promotion.
        t.record_hit("google.com", 0);
        t.record_hit("google.com", 1);
        assert_eq!(t.pool_size(), 0);
        assert_eq!(t.promotions_total(), 0);
        assert!(!t.is_promoted("google.com"));
    }

    #[test]
    fn crosses_min_hits_promotes_to_pool() {
        let t = HitTracker::new(&enabled_cfg());
        // All three calls land in window 0 (60s wide).
        t.record_hit("google.com", 0);
        t.record_hit("google.com", 10);
        t.record_hit("google.com", 20);
        assert_eq!(t.pool_size(), 1);
        assert_eq!(t.promotions_total(), 1);
        assert!(t.is_promoted("google.com"));
    }

    #[test]
    fn additional_hits_after_promotion_do_not_double_count() {
        let t = HitTracker::new(&enabled_cfg());
        for offset in 0..10 {
            // All offsets fit in window 0 (60s wide).
            t.record_hit("google.com", offset * 5);
        }
        assert_eq!(t.pool_size(), 1);
        assert_eq!(
            t.promotions_total(),
            1,
            "promotion counter must be monotonic-by-event, not by-hit"
        );
    }

    #[test]
    fn falls_below_threshold_demotes_on_window_boundary() {
        let t = HitTracker::new(&enabled_cfg());
        // Window 0: three hits → promotion.
        t.record_hit("google.com", 0);
        t.record_hit("google.com", 10);
        t.record_hit("google.com", 20);
        assert!(t.is_promoted("google.com"));
        // Window 60: a single hit → demotion on window crossing.
        t.record_hit("google.com", 60);
        assert!(!t.is_promoted("google.com"));
        assert_eq!(t.demotions_total(), 1);
    }

    #[test]
    fn window_boundary_resets_hit_counter() {
        let t = HitTracker::new(&enabled_cfg());
        // Two hits in window 0 — under threshold, no promotion.
        t.record_hit("noisy.example", 0);
        t.record_hit("noisy.example", 30);
        assert_eq!(t.promotions_total(), 0);
        // First hit in window 60 — must reset, NOT carry forward, even
        // though cumulative hits would have been 3.
        t.record_hit("noisy.example", 60);
        assert!(!t.is_promoted("noisy.example"));
        assert_eq!(t.promotions_total(), 0);
        // Two more hits in window 60 → promotes (3 hits total in window).
        t.record_hit("noisy.example", 70);
        t.record_hit("noisy.example", 80);
        assert!(t.is_promoted("noisy.example"));
    }

    #[test]
    fn case_lowering_normalises_keys() {
        let t = HitTracker::new(&enabled_cfg());
        t.record_hit("Google.COM", 0);
        t.record_hit("gOOgle.com", 1);
        t.record_hit("GOOGLE.COM", 2);
        assert!(t.is_promoted("google.com"));
        // Same logical key — only one promotion event.
        assert_eq!(t.promotions_total(), 1);
        assert_eq!(t.pool_size(), 1);
    }

    #[test]
    fn cap_enforcement_evicts_oldest_and_pool_does_not_leak() {
        // Cap=4, min_hits=1: every first hit promotes its domain.
        // Insert 8 distinct domains and verify pool_size never exceeds
        // the cap — the earlier prefetch_set design leaked here.
        let cfg = PrefetchTrackerConfig {
            enabled: true,
            window_secs: 60,
            min_hits: 1,
            max_pool_size: 4,
        };
        let t = HitTracker::new(&cfg);
        for i in 0..8u64 {
            let now = 60 * (i + 1);
            t.record_hit(&format!("dom{i}.test"), now);
        }
        // Soft cap allows brief overshoot — assert close to cap.
        assert!(
            t.pool_size() <= 6,
            "pool_size {} exceeded acceptable bound of cap+overshoot",
            t.pool_size()
        );
        // Newest entry is unconditionally present.
        assert!(t.is_promoted("dom7.test"));
        // Oldest entry was evicted along with its in-pool flag.
        assert!(!t.is_promoted("dom0.test"));
    }

    #[test]
    fn promotions_demotions_counter_monotonic() {
        let t = HitTracker::new(&enabled_cfg());
        // Window 0 → promote
        t.record_hit("a.example", 0);
        t.record_hit("a.example", 1);
        t.record_hit("a.example", 2);
        // Window 60 → too few → demote
        t.record_hit("a.example", 60);
        // Window 120 → promote again
        t.record_hit("a.example", 120);
        t.record_hit("a.example", 121);
        t.record_hit("a.example", 122);
        assert_eq!(t.promotions_total(), 2);
        assert_eq!(t.demotions_total(), 1);
    }

    #[test]
    fn is_promoted_lookup_lowercases() {
        let t = HitTracker::new(&enabled_cfg());
        t.record_hit("hot.test", 0);
        t.record_hit("hot.test", 1);
        t.record_hit("hot.test", 2);
        assert!(t.is_promoted("HOT.TEST"));
        assert!(t.is_promoted("Hot.Test"));
        assert!(t.is_promoted("hot.test"));
    }

    #[test]
    fn restore_counters_seeds_from_snapshot() {
        let t = HitTracker::new(&enabled_cfg());
        t.restore_counters(42, 17);
        assert_eq!(t.promotions_total(), 42);
        assert_eq!(t.demotions_total(), 17);
        // The pool itself is *not* restored — it stays empty.
        assert_eq!(t.pool_size(), 0);
    }

    #[test]
    fn min_hits_one_keeps_promoted_across_windows_without_churn() {
        let cfg = PrefetchTrackerConfig {
            enabled: true,
            window_secs: 60,
            min_hits: 1,
            max_pool_size: 64,
        };
        let t = HitTracker::new(&cfg);
        t.record_hit("hot.test", 0);
        assert!(t.is_promoted("hot.test"));
        // Cross to window 60. With min_hits=1 the boundary path
        // re-asserts the in-pool flag instead of demote-then-promote
        // churn, so the cumulative promotion event count stays at 1.
        // This keeps the IPC counter readable as "how many distinct
        // promotion events happened" rather than "how many windows
        // saw a popular domain".
        t.record_hit("hot.test", 60);
        assert!(t.is_promoted("hot.test"));
        assert_eq!(t.promotions_total(), 1);
        assert_eq!(t.demotions_total(), 0);
    }

    #[test]
    fn concurrent_record_hit_does_not_panic() {
        // Light stress test — exercises the CAS-promote path under
        // contention. We don't assert exact counts (atomic races may
        // drop a single increment) but no thread should panic and the
        // tracker invariants must hold.
        use std::sync::Arc;
        use std::thread;

        let t = Arc::new(HitTracker::new(&enabled_cfg()));
        let handles: Vec<_> = (0..8)
            .map(|tid| {
                let t = Arc::clone(&t);
                thread::spawn(move || {
                    for offset in 0..50 {
                        let domain = format!("d{}.test", tid % 4);
                        t.record_hit(&domain, (offset / 4) as u64);
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        // Promotions: at least one per distinct domain (4) under
        // perfect serialization, but races may drop a few. Assert
        // a non-zero floor and a reasonable ceiling.
        assert!(t.promotions_total() >= 1);
        assert!(t.pool_size() <= 4);
    }

    // Sprint §4.4 P2 — snapshot_promoted surface for the background worker.

    #[test]
    fn snapshot_promoted_returns_all_in_pool() {
        let t = HitTracker::new(&enabled_cfg());
        // Two distinct domains promoted via the same window.
        for offset in 0..3 {
            t.record_hit("hot1.test", offset);
            t.record_hit("hot2.test", offset);
        }
        let mut snap = t.snapshot_promoted();
        snap.sort();
        assert_eq!(
            snap,
            vec![
                CompactString::from("hot1.test"),
                CompactString::from("hot2.test")
            ]
        );
    }

    #[test]
    fn snapshot_promoted_excludes_demoted() {
        let t = HitTracker::new(&enabled_cfg());
        // Promote in window 0, then demote on boundary crossing.
        t.record_hit("cool.test", 0);
        t.record_hit("cool.test", 10);
        t.record_hit("cool.test", 20);
        assert!(t.is_promoted("cool.test"));
        t.record_hit("cool.test", 60);
        assert!(!t.is_promoted("cool.test"));
        assert!(t.snapshot_promoted().is_empty());
    }

    /// prefetch-01 (rev-2606): a domain that goes cold (no further
    /// client hits) must be time-demoted by the worker's snapshot, not
    /// kept warm forever. Within the idle horizon it stays promoted;
    /// past it, the snapshot demotes it and drops it from the refresh set.
    #[test]
    fn snapshot_promoted_pruning_stale_demotes_cold_domains() {
        let cfg = PrefetchTrackerConfig {
            enabled: true,
            window_secs: 30,
            min_hits: 3,
            max_pool_size: 16,
        };
        let t = HitTracker::new(&cfg);
        // Promote in window 0 (last hit stamps window_start_secs = 0).
        t.record_hit("dead.test", 0);
        t.record_hit("dead.test", 10);
        t.record_hit("dead.test", 20);
        assert!(t.is_promoted("dead.test"));

        // now=60: current window 60, idle horizon 3×30=90, stale_before
        // saturates to 0 → still warm, kept.
        let warm = t.snapshot_promoted_pruning_stale(60);
        assert_eq!(warm, vec![CompactString::from("dead.test")]);
        assert!(t.is_promoted("dead.test"));

        // now=150: current window 150, stale_before 60; the domain's
        // last hit (window 0) predates it → demoted + excluded.
        let cold = t.snapshot_promoted_pruning_stale(150);
        assert!(cold.is_empty(), "cold domain must drop from the set");
        assert!(!t.is_promoted("dead.test"), "cold domain must be demoted");
        assert!(t.demotions_total() >= 1, "time-demotion bumps the counter");
    }

    #[test]
    fn snapshot_promoted_when_disabled_is_empty() {
        let t = HitTracker::new(&PrefetchTrackerConfig::default());
        // Even after recording hits, a disabled tracker reports an empty pool.
        for _ in 0..50 {
            t.record_hit("would.promote", 0);
        }
        assert!(t.snapshot_promoted().is_empty());
    }

    #[test]
    fn snapshot_promoted_does_not_leak_evicted_entries() {
        // Cap=4, min_hits=1: each first hit promotes and the over-cap
        // inserts evict approximate-oldest. The snapshot must track the
        // BoundedMap's eviction — no ghost keys for entries whose
        // HitState has been dropped along with their is_in_pool flag.
        let cfg = PrefetchTrackerConfig {
            enabled: true,
            window_secs: 60,
            min_hits: 1,
            max_pool_size: 4,
        };
        let t = HitTracker::new(&cfg);
        for i in 0..8u64 {
            let now = 60 * (i + 1);
            t.record_hit(&format!("dom{i}.test"), now);
        }
        let snap = t.snapshot_promoted();
        // Soft cap allows brief overshoot; the snapshot length matches
        // pool_size on the same observation, so the two views agree.
        assert_eq!(snap.len(), t.pool_size());
        assert!(
            snap.len() <= 6,
            "snapshot {} exceeded cap+overshoot",
            snap.len()
        );
        // Newest survivor present, oldest evicted entry absent.
        assert!(snap.iter().any(|d| d == "dom7.test"));
        assert!(!snap.iter().any(|d| d == "dom0.test"));
    }
}
