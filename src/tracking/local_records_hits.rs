//! Sprint 44 T3 — per-record hit counter for the Local DNS Scoping v2
//! feature.
//!
//! Lock-free atomic counter keyed per `(scope, apex)` tuple, where `scope`
//! is either the global `[[local_dns.records]]` table or a single profile's
//! `Profile.local_records` array, and `apex` is the **matched record's
//! identity** — its configured apex (exact key, wildcard suffix, or a PTR's
//! owning forward name), surfaced by the lookup. The hot-path probe site is
//! `dns::handler::ForwardHandler::handle_inner`: immediately after a
//! `ProfileLocalRecords::lookup` or global `LocalRecords::lookup` hit, the
//! handler calls [`LocalRecordsHits::record_hit`] before synthesising the
//! local response. Cost: one `DashMap::entry` + one `fetch_add(Relaxed)` —
//! measured in hundreds of nanoseconds, well inside the cache-miss budget.
//!
//! Keying by apex (perfmem T1 / TRK-01) — rather than the raw queried name —
//! makes the table's cardinality **bounded by admin-controlled state**: it
//! equals the operator-configured record count, so a LAN flood of distinct
//! wildcard subdomains can no longer grow it (a `MAX_HIT_KEYS` const backstops
//! any future regression). The product meaning is per-record aggregation —
//! "which records actually fire" — with every wildcard-subdomain hit rolling
//! up under its record's apex (the intended TUI "hits" semantics).
//!
//! The counter is cumulative-since-boot. The §9 "hits (24h)" column
//! header in the TUI is honoured by labelling the column "hits (since
//! boot)" until a future sprint grows the counter to a 24-bucket
//! rolling ring (see `_docs/features/local_dns_scoping.md` §14.3
//! carry-forward). Cumulative is sufficient signal for the operator
//! ("which records actually fire?") and avoids paying for a per-second
//! tick advance on the hot path.

use std::sync::atomic::{AtomicU64, Ordering};

use compact_str::CompactString;
use dashmap::DashMap;

/// Hard upper bound on distinct hit keys. With apex re-keying (perfmem T1),
/// real cardinality equals the operator-configured record count — far under
/// this — so the cap is a belt-and-braces backstop: it only bites if a future
/// callsite regresses to keying by raw QNAMEs. Beyond it, `record_hit` skips
/// inserting NEW keys (existing keys keep counting), so no adversary-driven
/// query stream can grow the table without bound.
const MAX_HIT_KEYS: usize = 4096;

/// Scope key for [`LocalRecordsHits`]. Carried by-value through
/// [`LocalRecordsHits::record_hit`] / [`LocalRecordsHits::snapshot`].
/// Lives in `tracking` (not in the CLI module) so the hot path doesn't
/// pull in the CLI compile graph.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum LocalRecordsScopeKey {
    /// The global `[[local_dns.records]]` table.
    Global,
    /// A single profile's `Profile.local_records` array.
    Profile(CompactString),
}

impl LocalRecordsScopeKey {
    /// Operator-facing tag — `"global"` or `"profile:<id>"`.
    pub fn as_display(&self) -> CompactString {
        match self {
            Self::Global => CompactString::new("global"),
            Self::Profile(id) => {
                let mut s = CompactString::new("profile:");
                s.push_str(id);
                s
            }
        }
    }

    /// Audit / TUI grouping tag — `"global"` or `"profile"`.
    pub fn as_tag(&self) -> &'static str {
        match self {
            Self::Global => "global",
            Self::Profile(_) => "profile",
        }
    }

    /// The profile id when this is a profile-scope key, else `None`.
    pub fn profile_id(&self) -> Option<&str> {
        match self {
            Self::Global => None,
            Self::Profile(id) => Some(id.as_str()),
        }
    }
}

/// Lock-free counter table for local DNS record hits.
///
/// The hot-path increment is `record_hit` — one DashMap entry lookup
/// (shard-locked) + one `fetch_add(Relaxed)`. Read-side `snapshot`
/// iterates the whole map and takes the snapshot's `Relaxed` load of
/// each counter; readers may see counts that drift by O(threads) from
/// concurrent writers, which is acceptable for a TUI-display surface.
#[derive(Debug, Default)]
pub struct LocalRecordsHits {
    counters: DashMap<(LocalRecordsScopeKey, CompactString), AtomicU64>,
}

impl LocalRecordsHits {
    /// Build an empty counter table. Caller wraps in `Arc` and shares
    /// across the handler + IPC read paths.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one hit on `(scope, apex)`, where `apex` is the **matched local
    /// record's identity** (its configured apex / suffix key) — NOT the raw
    /// queried name. Keying by apex is what bounds this table: a wildcard
    /// record's every subdomain rolls up under the one apex, so cardinality
    /// equals the operator-configured record count (perfmem T1 / TRK-01).
    ///
    /// Fires only when a local DNS record actually matched — not on every
    /// query — so it sits off the per-query hot path. The owned `(scope, apex)`
    /// key is built unconditionally on each call; since apexes are short
    /// (host/domain labels), they inline within `CompactString`'s 24-byte
    /// limit and the old per-hit heap allocation for long raw QNAMEs (EXT-01)
    /// is gone in practice — only a pathological >24-byte apex would allocate.
    pub fn record_hit(&self, scope: LocalRecordsScopeKey, apex: &str) {
        let key = (scope, CompactString::new(apex));
        if let Some(entry) = self.counters.get(&key) {
            entry.fetch_add(1, Ordering::Relaxed);
            return;
        }
        // First hit on this key. `get` returned above WITHOUT retaining a shard
        // ref, so the `len()` read + `entry()` insert here never nest a
        // mutation under an outstanding read guard (DashMap shard-deadlock
        // rule). Cap the table: once MAX_HIT_KEYS distinct keys exist, skip NEW
        // inserts — existing keys still increment. The check→insert TOCTOU over
        // the cap is benign (belt-and-braces, not a hard boundary).
        if self.counters.len() >= MAX_HIT_KEYS {
            return;
        }
        self.counters
            .entry(key)
            .or_insert_with(|| AtomicU64::new(0))
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Snapshot of every `(scope, domain, count)` triple. Used by the
    /// TUI Local DNS tab to render the `hits` column. Cost: one shard
    /// lock per row + one `Relaxed` load per atomic; for a typical
    /// home-lab config (≤ 256 records) this is a few microseconds.
    pub fn snapshot(&self) -> Vec<(LocalRecordsScopeKey, CompactString, u64)> {
        let mut out = Vec::with_capacity(self.counters.len());
        for entry in self.counters.iter() {
            let (scope, domain) = entry.key();
            let value = entry.value().load(Ordering::Relaxed);
            out.push((scope.clone(), domain.clone(), value));
        }
        out
    }

    /// Lookup the count for a single `(scope, domain)` key, or 0 when
    /// the key has never been hit. Used by the TUI side-card detail
    /// view; cheap O(1) shard probe.
    pub fn count_for(&self, scope: &LocalRecordsScopeKey, domain: &str) -> u64 {
        let key = (scope.clone(), CompactString::new(domain));
        self.counters
            .get(&key)
            .map(|e| e.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    /// Sum across every key. Surfaced in `Stats` snapshots for the
    /// "local DNS responses served since boot" line.
    pub fn total(&self) -> u64 {
        self.counters
            .iter()
            .map(|entry| entry.value().load(Ordering::Relaxed))
            .sum()
    }

    /// `true` when no hit has been recorded yet (boot-fresh daemon).
    pub fn is_empty(&self) -> bool {
        self.counters.is_empty()
    }

    /// Number of distinct `(scope, domain)` keys observed so far. Test
    /// hook + sanity guard for "is the counter table reasonably sized".
    pub fn key_count(&self) -> usize {
        self.counters.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn t3_local_records_hits_empty_at_boot() {
        let hits = LocalRecordsHits::new();
        assert!(hits.is_empty());
        assert_eq!(hits.total(), 0);
        assert_eq!(hits.snapshot().len(), 0);
        assert_eq!(hits.key_count(), 0);
    }

    #[test]
    fn t3_local_records_hits_record_hit_increments_counter() {
        let hits = LocalRecordsHits::new();
        hits.record_hit(LocalRecordsScopeKey::Global, "nas.home");
        hits.record_hit(LocalRecordsScopeKey::Global, "nas.home");
        hits.record_hit(LocalRecordsScopeKey::Global, "nas.home");
        assert_eq!(hits.count_for(&LocalRecordsScopeKey::Global, "nas.home"), 3);
        assert_eq!(hits.total(), 3);
        assert_eq!(hits.key_count(), 1);
        assert!(!hits.is_empty());
    }

    #[test]
    fn t3_local_records_hits_separate_scopes_kept_apart() {
        let hits = LocalRecordsHits::new();
        hits.record_hit(LocalRecordsScopeKey::Global, "example.test");
        hits.record_hit(
            LocalRecordsScopeKey::Profile(CompactString::new("kids")),
            "example.test",
        );
        hits.record_hit(
            LocalRecordsScopeKey::Profile(CompactString::new("guests")),
            "example.test",
        );
        assert_eq!(
            hits.count_for(&LocalRecordsScopeKey::Global, "example.test"),
            1
        );
        assert_eq!(
            hits.count_for(
                &LocalRecordsScopeKey::Profile(CompactString::new("kids")),
                "example.test"
            ),
            1
        );
        assert_eq!(
            hits.count_for(
                &LocalRecordsScopeKey::Profile(CompactString::new("guests")),
                "example.test"
            ),
            1
        );
        assert_eq!(hits.total(), 3);
        assert_eq!(hits.key_count(), 3);
    }

    #[test]
    fn t3_local_records_hits_count_for_missing_returns_zero() {
        let hits = LocalRecordsHits::new();
        hits.record_hit(LocalRecordsScopeKey::Global, "exists.home");
        assert_eq!(
            hits.count_for(&LocalRecordsScopeKey::Global, "ghost.home"),
            0
        );
        assert_eq!(
            hits.count_for(
                &LocalRecordsScopeKey::Profile(CompactString::new("kids")),
                "exists.home"
            ),
            0
        );
    }

    #[test]
    fn t3_local_records_hits_snapshot_includes_every_key() {
        let hits = LocalRecordsHits::new();
        hits.record_hit(LocalRecordsScopeKey::Global, "a.home");
        hits.record_hit(LocalRecordsScopeKey::Global, "b.home");
        hits.record_hit(
            LocalRecordsScopeKey::Profile(CompactString::new("kids")),
            "c.home",
        );
        let snap = hits.snapshot();
        assert_eq!(snap.len(), 3);
        let mut keys: Vec<String> = snap
            .iter()
            .map(|(s, d, _)| format!("{}|{d}", s.as_display()))
            .collect();
        keys.sort();
        assert_eq!(
            keys,
            vec![
                "global|a.home".to_string(),
                "global|b.home".to_string(),
                "profile:kids|c.home".to_string(),
            ]
        );
    }

    #[test]
    fn t3_local_records_scope_key_display_and_tag() {
        let g = LocalRecordsScopeKey::Global;
        assert_eq!(g.as_display(), CompactString::new("global"));
        assert_eq!(g.as_tag(), "global");
        assert_eq!(g.profile_id(), None);

        let p = LocalRecordsScopeKey::Profile(CompactString::new("kids"));
        assert_eq!(p.as_display(), CompactString::new("profile:kids"));
        assert_eq!(p.as_tag(), "profile");
        assert_eq!(p.profile_id(), Some("kids"));
    }

    #[test]
    fn t3_local_records_hits_concurrent_increments_safe() {
        // Ten threads each record 1000 hits on the same key — the final
        // counter must equal 10_000 exactly. This is the load-bearing
        // property: the `DashMap::entry` + `fetch_add(Relaxed)` chain
        // must compose to a serialisable counter under contention.
        use std::sync::Arc;
        use std::thread;
        let hits = Arc::new(LocalRecordsHits::new());
        let mut handles = Vec::new();
        for _ in 0..10 {
            let h = Arc::clone(&hits);
            handles.push(thread::spawn(move || {
                for _ in 0..1000 {
                    h.record_hit(LocalRecordsScopeKey::Global, "shared.home");
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(
            hits.count_for(&LocalRecordsScopeKey::Global, "shared.home"),
            10_000
        );
    }

    #[test]
    fn t3_record_hit_caps_distinct_keys() {
        // Belt-and-braces backstop (perfmem T1): even if a future caller
        // regressed to unbounded keying, the table stops growing at
        // MAX_HIT_KEYS while already-present keys keep counting.
        let hits = LocalRecordsHits::new();
        for i in 0..(MAX_HIT_KEYS + 500) {
            hits.record_hit(LocalRecordsScopeKey::Global, &format!("k{i}.home"));
        }
        assert_eq!(hits.key_count(), MAX_HIT_KEYS, "table caps at MAX_HIT_KEYS");
        // A key admitted before the cap still increments.
        hits.record_hit(LocalRecordsScopeKey::Global, "k0.home");
        assert_eq!(hits.count_for(&LocalRecordsScopeKey::Global, "k0.home"), 2);
        // A key rejected by the cap never appears.
        assert_eq!(
            hits.count_for(
                &LocalRecordsScopeKey::Global,
                &format!("k{}.home", MAX_HIT_KEYS + 100)
            ),
            0
        );
    }
}
