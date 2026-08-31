//! Memory-bounded concurrent map with approximate-LRU eviction (P0-4).
//!
//! Wraps a `DashMap<K, V>` with a soft cap. When an insert would exceed the
//! cap, the map samples up to `SAMPLE` existing entries and evicts the one
//! with the smallest *ordering key* — typically a `window_start` timestamp
//! packed into the value. The ordering function is supplied at construction
//! time as a plain `fn` pointer, so it must be a pure function of `&V`; all
//! three call sites in this crate meet that contract (each value carries an
//! `AtomicU64` age counter).
//!
//! Why sample-K instead of exact LRU:
//!
//! - Exact LRU needs a shared linked list touched on every read, creating
//!   contention that would be visible on the DNS hot path.
//! - `moka`-style windowed-tiny-LFU is overkill for the access patterns
//!   here — the three consumers care about *insert-rate* attacks, not
//!   read-locality.
//! - Sample-K (Redis `maxmemory-policy allkeys-lru` style) is O(1)
//!   amortized, O(SAMPLE) in the worst case on over-cap insert, and
//!   converges close to true LRU for small `SAMPLE` as long as the
//!   iteration order is not correlated with age. `DashMap`'s shard+bucket
//!   order is keyed by hash, which is effectively uncorrelated with
//!   insertion time, so sampling the first N entries of `.iter()` behaves
//!   close enough to random sampling for this use case.
//!
//! The cap is a *soft* limit. Under contention two threads may both pass
//! the `len() >= cap` check before either has evicted, so the map can
//! temporarily exceed `cap` by a small number of entries. This is
//! intentional — tightening it would require a hot-path mutex.

use std::borrow::Borrow;
use std::hash::Hash;

use dashmap::DashMap;

/// Number of entries sampled per over-cap insert to find an approximate LRU
/// victim. Redis uses 5; 8 gives better LRU fidelity at negligible cost.
const SAMPLE: usize = 8;

/// Extract an ordering key from a value. Smaller values are evicted first.
///
/// For rate_limiter: unpack the last-refill timestamp from the Bucket's
/// `AtomicU64`. For rrl and tunneling: load `window_start`. All three are
/// monotonic (larger = more recent), so the smallest is the oldest.
pub type OrderingFn<V> = fn(&V) -> u64;

/// Memory-bounded concurrent map with approximate-LRU eviction.
///
/// Reads and lookups are O(1) and delegate straight to DashMap. Inserts
/// are O(1) in the common (under-cap) case and O(SAMPLE) when the map is
/// at capacity.
pub struct BoundedMap<K, V>
where
    K: Eq + Hash + Clone,
{
    inner: DashMap<K, V>,
    cap: usize,
    ordering: OrderingFn<V>,
}

impl<K, V> BoundedMap<K, V>
where
    K: Eq + Hash + Clone,
{
    /// Build a new bounded map with the given soft cap and ordering function.
    ///
    /// `cap` is the soft entry limit. `ordering` must return a monotonic age
    /// key where smaller = older.
    pub fn new(cap: usize, ordering: OrderingFn<V>) -> Self {
        // Pre-size for a quarter of cap; DashMap will grow as needed.
        let initial = cap.saturating_sub(1) / 4 + 1;
        Self {
            inner: DashMap::with_capacity(initial),
            cap,
            ordering,
        }
    }

    /// Look up a value by key without touching eviction state.
    pub fn get<Q>(&self, key: &Q) -> Option<dashmap::mapref::one::Ref<'_, K, V>>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.inner.get(key)
    }

    /// Insert or replace a value. If the map is at capacity, evict the
    /// approximately-oldest entry first.
    pub fn insert(&self, key: K, value: V) {
        if self.inner.len() >= self.cap {
            self.evict_approximate_oldest();
        }
        self.inner.insert(key, value);
    }

    /// Atomic get-or-insert. If `key` is already present, returns a write-
    /// guarded ref to the existing value. Otherwise computes a value via `f`
    /// and inserts it (evicting the approximately-oldest entry if the map is
    /// at capacity). The lookup-and-insert is a single atomic shard
    /// operation, closing get-then-insert races — see L-1 in
    /// `_docs/reviews/code_review_2026_04.md` for the rate-limiter call site
    /// that motivated this addition.
    ///
    /// The caller holds a `RefMut` (shard write guard) for the duration of
    /// the returned reference; drop it as soon as practical to release the
    /// shard.
    pub fn entry_or_insert_with<F>(&self, key: K, f: F) -> dashmap::mapref::one::RefMut<'_, K, V>
    where
        F: FnOnce() -> V,
    {
        // Cap check uses the same soft-bound semantics as `insert()` — under
        // contention two threads may both pass the `len() >= cap` check
        // before either has evicted, so the map can briefly exceed `cap`.
        // Probe `contains_key` (one shard) FIRST so the existing-key fast
        // path short-circuits before `len()` (which read-locks every shard
        // — `dashmap::_len` sums per-shard lengths). The boolean is
        // unchanged (AND commutes); only the existing-IP path is now
        // cheaper, never paying the all-shard scan on the DNS hot path.
        if !self.inner.contains_key(&key) && self.inner.len() >= self.cap {
            self.evict_approximate_oldest();
        }
        self.inner.entry(key).or_insert_with(f)
    }

    /// Current entry count. Exposed so call sites can publish it as a stat.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Whether the map is empty.
    #[allow(dead_code)] // API completeness; used by tests
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Retain only entries for which `f` returns `true`. Used by the
    /// existing per-module `cleanup()` calls for stale-window pruning.
    pub fn retain<F: FnMut(&K, &mut V) -> bool>(&self, f: F) {
        self.inner.retain(f);
    }

    /// Count entries whose value satisfies `f`. Iterates under shard
    /// read locks; callers should keep `f` cheap. Sprint §4.4 P1
    /// `HitTracker::pool_size` reads the in-pool flag this way to avoid
    /// maintaining a parallel `HashSet` that could drift out of sync
    /// with `BoundedMap`'s approximate-LRU eviction.
    pub fn count_where<F: FnMut(&V) -> bool>(&self, mut f: F) -> usize {
        self.inner.iter().filter(|entry| f(entry.value())).count()
    }

    /// Snapshot the keys of entries whose value satisfies `f`. Iterates
    /// under shard read locks and clones each matching key into a fresh
    /// `Vec`, so the cost is `O(tracked_entries)` plus one `K::clone`
    /// per match. Intended for low-cadence consumers (Sprint §4.4 P2's
    /// background prefetch worker reads the promoted-domain set every
    /// `tick_secs`); not suitable for the hot path.
    ///
    /// Result ordering is unspecified — DashMap iterates by shard hash
    /// order. Soft-cap semantics (§ module docs) mean a briefly-evicted
    /// entry may or may not appear; callers must tolerate ghost keys.
    pub fn snapshot_keys_where<F: FnMut(&V) -> bool>(&self, mut f: F) -> Vec<K> {
        self.inner
            .iter()
            .filter(|entry| f(entry.value()))
            .map(|entry| entry.key().clone())
            .collect()
    }

    /// Scan up to `SAMPLE` entries and remove the one with the smallest
    /// ordering key. Called only when the map is at capacity.
    ///
    /// DashMap's iter holds shard read locks; we scope the iteration in a
    /// block so the locks are released before we call `remove()`. Cloning
    /// the key here is unavoidable because we cannot hold a reference into
    /// the map across a subsequent mutation.
    fn evict_approximate_oldest(&self) {
        let victim: Option<K> = {
            let mut oldest: Option<(K, u64)> = None;
            let mut scanned = 0;
            for entry in self.inner.iter() {
                let age = (self.ordering)(entry.value());
                oldest = match oldest {
                    None => Some((entry.key().clone(), age)),
                    Some((_, cur_age)) if age < cur_age => Some((entry.key().clone(), age)),
                    other => other,
                };
                scanned += 1;
                if scanned >= SAMPLE {
                    break;
                }
            }
            oldest.map(|(k, _)| k)
        };
        if let Some(k) = victim {
            self.inner.remove(&k);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Test value that wraps an AtomicU64 ordering key.
    struct Aged(AtomicU64);

    fn age_of(v: &Aged) -> u64 {
        v.0.load(Ordering::Relaxed)
    }

    #[test]
    fn insert_and_lookup() {
        let m: BoundedMap<u32, Aged> = BoundedMap::new(100, age_of);
        m.insert(1, Aged(AtomicU64::new(10)));
        m.insert(2, Aged(AtomicU64::new(20)));
        assert_eq!(m.len(), 2);
        assert!(m.get(&1).is_some());
        assert!(m.get(&99).is_none());
    }

    #[test]
    fn under_cap_keeps_all_entries() {
        let m: BoundedMap<u32, Aged> = BoundedMap::new(10, age_of);
        for i in 0..10 {
            m.insert(i, Aged(AtomicU64::new(i as u64)));
        }
        assert_eq!(m.len(), 10);
    }

    #[test]
    fn over_cap_evicts_and_stays_near_limit() {
        // Insert well past the cap; the soft bound should keep len within a
        // small overshoot (sample-8 LRU is approximate, so we allow some slack).
        let m: BoundedMap<u32, Aged> = BoundedMap::new(10, age_of);
        for i in 0..50 {
            m.insert(i, Aged(AtomicU64::new(i as u64)));
        }
        let len = m.len();
        // Each over-cap insert evicts one entry, so len should stay close to cap.
        // Allow a small overshoot for sampling imprecision.
        assert!(
            len <= 12,
            "expected len close to cap=10, got {len} (>12 means eviction is broken)"
        );
    }

    #[test]
    fn over_cap_prefers_evicting_older_entries() {
        // Build a map with 8 entries of ascending age, then insert a 9th.
        // The oldest entry (age=0) should be the most likely victim since
        // sample-8 covers the entire population.
        let m: BoundedMap<u32, Aged> = BoundedMap::new(8, age_of);
        for i in 0..8 {
            m.insert(i, Aged(AtomicU64::new(i as u64)));
        }
        m.insert(100, Aged(AtomicU64::new(999)));
        // The oldest (key 0, age 0) must be gone; the newest must still be there.
        assert!(m.get(&0).is_none(), "oldest entry should have been evicted");
        assert!(m.get(&100).is_some(), "newly inserted entry should remain");
    }

    #[test]
    fn retain_removes_matching() {
        let m: BoundedMap<u32, Aged> = BoundedMap::new(100, age_of);
        for i in 0..10 {
            m.insert(i, Aged(AtomicU64::new(i as u64)));
        }
        m.retain(|_, v| v.0.load(Ordering::Relaxed) >= 5);
        assert_eq!(m.len(), 5);
    }

    #[test]
    fn reinsert_replaces_value() {
        let m: BoundedMap<u32, Aged> = BoundedMap::new(10, age_of);
        m.insert(1, Aged(AtomicU64::new(100)));
        m.insert(1, Aged(AtomicU64::new(200)));
        assert_eq!(m.len(), 1);
        let got = m.get(&1).unwrap();
        assert_eq!(got.0.load(Ordering::Relaxed), 200);
    }

    #[test]
    fn is_empty() {
        let m: BoundedMap<u32, Aged> = BoundedMap::new(10, age_of);
        assert!(m.is_empty());
        m.insert(1, Aged(AtomicU64::new(0)));
        assert!(!m.is_empty());
    }

    #[test]
    fn small_cap_one_works() {
        let m: BoundedMap<u32, Aged> = BoundedMap::new(1, age_of);
        m.insert(1, Aged(AtomicU64::new(1)));
        assert_eq!(m.len(), 1);
        m.insert(2, Aged(AtomicU64::new(2)));
        assert_eq!(m.len(), 1);
        // One of the two keys is present — we don't care which, but not both.
        let has_1 = m.get(&1).is_some();
        let has_2 = m.get(&2).is_some();
        assert!(has_1 ^ has_2, "exactly one entry should remain");
    }

    #[test]
    fn snapshot_keys_where_returns_filtered_keys() {
        let m: BoundedMap<u32, Aged> = BoundedMap::new(100, age_of);
        m.insert(1, Aged(AtomicU64::new(10)));
        m.insert(2, Aged(AtomicU64::new(20)));
        m.insert(3, Aged(AtomicU64::new(30)));
        // Predicate: age >= 20 → keys 2 and 3 match.
        let mut keys = m.snapshot_keys_where(|v| v.0.load(Ordering::Relaxed) >= 20);
        keys.sort();
        assert_eq!(keys, vec![2, 3]);
    }

    #[test]
    fn snapshot_keys_where_empty_predicate_returns_empty() {
        let m: BoundedMap<u32, Aged> = BoundedMap::new(100, age_of);
        m.insert(1, Aged(AtomicU64::new(10)));
        let keys = m.snapshot_keys_where(|_| false);
        assert!(keys.is_empty());
    }
}
