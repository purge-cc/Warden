//! Time-series buckets — hourly and daily aggregation.
//!
//! The current (in-progress) bucket lives behind `ArcSwap` so `record()`
//! is lock-free on the common path: a guard load + atomic `fetch_add`
//! on the per-counter atomics. No `Mutex` is touched on the DNS hot
//! path (project rules §hot path).
//!
//! A `Mutex<VecDeque>` protects the archive of completed buckets and is
//! taken only on rollover — once per hour (or per day), per bucket.
//! The archive lock also serialises rollover so at most one thread
//! performs the `ArcSwap::store` + archive push per boundary.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwap;
use serde::{Deserialize, Serialize};

use super::query_type::TYPE_BUCKET_COUNT;

/// A completed time bucket (immutable — historical data).
///
/// Sprint F extends this from 4 fields → 6 by adding per-`TypeBucket`
/// query and blocked counters. The arrays default to all-zero on
/// pre-Sprint-F snapshots so a daemon upgrading mid-day picks up the
/// existing on-disk hourly ring without an error — the live counters
/// then backfill from incoming traffic.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeBucket {
    /// Unix timestamp (truncated to hour or day boundary).
    pub timestamp: u64,
    pub queries: u64,
    pub blocked: u64,
    pub cache_hits: u64,
    /// Sprint F per-`TypeBucket` query counter in canonical order
    /// (`TypeBucket::ALL`). Sums to `queries` modulo concurrent
    /// updates straddling the snapshot.
    #[serde(default = "zero_per_type")]
    pub per_type: [u64; TYPE_BUCKET_COUNT],
    /// Sprint F per-`TypeBucket` BLOCKED query counter parallel to
    /// `per_type`. Sums to `blocked` modulo concurrent updates.
    #[serde(default = "zero_per_type")]
    pub blocked_per_type: [u64; TYPE_BUCKET_COUNT],
}

/// Atomics for the current (in-progress) bucket. `timestamp` is fixed for
/// the lifetime of each instance — rollover swaps the whole `Arc`.
struct CurrentBucket {
    timestamp: u64,
    queries: AtomicU64,
    blocked: AtomicU64,
    cache_hits: AtomicU64,
    /// Sprint F — parallel to `GlobalStats::per_type`. `Relaxed`
    /// ordering matches the existing counters.
    per_type: [AtomicU64; TYPE_BUCKET_COUNT],
    blocked_per_type: [AtomicU64; TYPE_BUCKET_COUNT],
}

impl CurrentBucket {
    fn new(timestamp: u64) -> Self {
        Self {
            timestamp,
            queries: AtomicU64::new(0),
            blocked: AtomicU64::new(0),
            cache_hits: AtomicU64::new(0),
            per_type: std::array::from_fn(|_| AtomicU64::new(0)),
            blocked_per_type: std::array::from_fn(|_| AtomicU64::new(0)),
        }
    }

    fn snapshot(&self) -> TimeBucket {
        TimeBucket {
            timestamp: self.timestamp,
            queries: self.queries.load(Ordering::Relaxed),
            blocked: self.blocked.load(Ordering::Relaxed),
            cache_hits: self.cache_hits.load(Ordering::Relaxed),
            per_type: std::array::from_fn(|i| self.per_type[i].load(Ordering::Relaxed)),
            blocked_per_type: std::array::from_fn(|i| {
                self.blocked_per_type[i].load(Ordering::Relaxed)
            }),
        }
    }
}

/// `#[serde(default)]` helper for `TimeBucket::per_type` /
/// `blocked_per_type`. Sprint F — pre-Sprint-F snapshots load with
/// all-zero arrays. Mirrors the existing helper in `snapshot.rs`
/// (kept module-local there) but defined here so the derive on
/// `TimeBucket` resolves without touching `snapshot::zero_per_type`.
fn zero_per_type() -> [u64; TYPE_BUCKET_COUNT] {
    [0; TYPE_BUCKET_COUNT]
}

/// Capacity of the hourly ring buffer. Sized at 168 (= 7 days × 24
/// hours). Heatmap retired in Sprint D of `_docs/features/dashboard_v2.md`
/// (2026-05-10), but the buffer stays at 168 to keep serving the
/// remaining hourly consumers: KPI rolling windows, the 24h trend
/// chart slice, and `pulse_row_peak`. They all take the LAST N
/// elements via `len().saturating_sub(n)` and work transparently
/// regardless of buffer size.
const MAX_HOURLY: usize = 168;
/// Capacity of the daily ring buffer. Bumped from 7 to 10 in Sprint
/// D of `_docs/features/dashboard_v2.md` (2026-05-10) to back the new
/// row-3 daily-totals barcharts (`Daily Queries`, `Daily Blocked`),
/// which render a 10-day window anchored on today (UTC). Older
/// 7-bucket snapshots load cleanly: `load()` enforces capacity only
/// on push, so the deque grows organically as new days roll in.
const MAX_DAILY: usize = 10;
const SECS_PER_HOUR: u64 = 3600;
const SECS_PER_DAY: u64 = 86400;

/// Time-series tracker with hourly and daily buckets.
pub struct TimeSeries {
    current_hour: ArcSwap<CurrentBucket>,
    current_day: ArcSwap<CurrentBucket>,
    hourly: Mutex<VecDeque<TimeBucket>>,
    daily: Mutex<VecDeque<TimeBucket>>,
}

impl Default for TimeSeries {
    fn default() -> Self {
        Self::new()
    }
}

impl TimeSeries {
    pub fn new() -> Self {
        let now = now_secs();
        Self {
            current_hour: ArcSwap::from_pointee(CurrentBucket::new(truncate_hour(now))),
            current_day: ArcSwap::from_pointee(CurrentBucket::new(truncate_day(now))),
            hourly: Mutex::new(VecDeque::with_capacity(MAX_HOURLY)),
            daily: Mutex::new(VecDeque::with_capacity(MAX_DAILY)),
        }
    }

    /// Record a query. Lock-free on the common (same-bucket) path.
    ///
    /// Sprint F adds the `bucket: usize` arg — the caller's already-
    /// computed `TypeBucket::classify(record_type) as usize` slot. The
    /// caller must guarantee `bucket < TYPE_BUCKET_COUNT`; the only
    /// production caller (`StatsEngine::record_query`) does so by
    /// construction.
    pub fn record(&self, blocked: bool, cache_hit: bool, bucket: usize) {
        let now = now_secs();
        record_into(
            &self.current_hour,
            &self.hourly,
            truncate_hour(now),
            MAX_HOURLY,
            blocked,
            cache_hit,
            bucket,
        );
        record_into(
            &self.current_day,
            &self.daily,
            truncate_day(now),
            MAX_DAILY,
            blocked,
            cache_hit,
            bucket,
        );
    }

    /// Get hourly buckets (historical + current in-progress).
    pub fn hourly_snapshot(&self) -> Vec<TimeBucket> {
        let current_snap = self.current_hour.load().snapshot();
        // time_series-01 (rev-2606): ignore lock poisoning. Every holder
        // of these archive mutexes does only saturating arithmetic (no
        // panic ops), so a poisoned guard would be spurious — recover the
        // inner value rather than cascade a panic into every later
        // rollover and IPC snapshot read. The mutex still fires ≤1/hour on
        // rollover; the common path stays on ArcSwap (`current_hour`).
        let hourly = self.hourly.lock().unwrap_or_else(|e| e.into_inner());
        let mut result: Vec<TimeBucket> = hourly.iter().cloned().collect();
        if current_snap.queries > 0 {
            merge_current_into_snapshot(&mut result, current_snap);
        }
        result
    }

    /// Sprint F — sum the per-`TypeBucket` query and blocked counters
    /// across the trailing 24 hourly buckets, including the in-flight
    /// current bucket if non-empty (mirrors `hourly_snapshot()`
    /// semantics). Returns `(per_type_24h, blocked_per_type_24h)`.
    ///
    /// No pro-ration of the trailing-edge bucket — the existing
    /// `compute_24h_stats` (`socket_server.rs`) sums raw bucket
    /// values the same way; staying consistent with that is more
    /// important than any precision win.
    pub fn per_type_24h_snapshot(&self) -> ([u64; TYPE_BUCKET_COUNT], [u64; TYPE_BUCKET_COUNT]) {
        let current_snap = self.current_hour.load().snapshot();
        let hourly = self.hourly.lock().unwrap_or_else(|e| e.into_inner());
        let mut q = [0u64; TYPE_BUCKET_COUNT];
        let mut b = [0u64; TYPE_BUCKET_COUNT];
        let mut taken = 0usize;
        if current_snap.queries > 0 {
            for i in 0..TYPE_BUCKET_COUNT {
                q[i] = q[i].saturating_add(current_snap.per_type[i]);
                b[i] = b[i].saturating_add(current_snap.blocked_per_type[i]);
            }
            taken += 1;
        }
        for bucket in hourly.iter().rev() {
            if taken >= 24 {
                break;
            }
            for i in 0..TYPE_BUCKET_COUNT {
                q[i] = q[i].saturating_add(bucket.per_type[i]);
                b[i] = b[i].saturating_add(bucket.blocked_per_type[i]);
            }
            taken += 1;
        }
        (q, b)
    }

    /// Get daily buckets (historical + current in-progress).
    pub fn daily_snapshot(&self) -> Vec<TimeBucket> {
        let current_snap = self.current_day.load().snapshot();
        let daily = self.daily.lock().unwrap_or_else(|e| e.into_inner());
        let mut result: Vec<TimeBucket> = daily.iter().cloned().collect();
        if current_snap.queries > 0 {
            merge_current_into_snapshot(&mut result, current_snap);
        }
        result
    }

    /// Load historical buckets from a snapshot (on startup).
    ///
    /// Sprint G — entries sharing an identical `timestamp` are merged
    /// into a single bucket by summing every numeric field element-wise
    /// (`queries`, `blocked`, `cache_hits`, `per_type[i]`,
    /// `blocked_per_type[i]`) via `saturating_add`. This auto-heals
    /// pre-Sprint-G on-disk snapshots written by daemons that included
    /// the in-flight bucket in `hourly_snapshot()` and then re-loaded
    /// it as a fresh archive entry on restart — over N restarts within
    /// the same hour, N+1 same-timestamp fragments accumulated.
    /// Collapsing on load is forward-only; older daemons can keep
    /// writing fragmented snapshots without breaking anything.
    pub fn load(&self, hourly: Vec<TimeBucket>, daily: Vec<TimeBucket>) {
        let hourly = dedupe_by_timestamp_summing(hourly);
        let daily = dedupe_by_timestamp_summing(daily);

        let mut h = self.hourly.lock().unwrap_or_else(|e| e.into_inner());
        *h = VecDeque::from(hourly);
        while h.len() > MAX_HOURLY {
            h.pop_front();
        }
        let mut d = self.daily.lock().unwrap_or_else(|e| e.into_inner());
        *d = VecDeque::from(daily);
        while d.len() > MAX_DAILY {
            d.pop_front();
        }
    }
}

/// Fold the in-flight current bucket into the snapshot vector,
/// summing into the trailing archive entry when their timestamps
/// match. Pushed as a fresh tail otherwise.
///
/// Closes the §4.26 follow-up mid-hour-restart-dup bug: if the daemon
/// restarts inside the same hour (or day) where a snapshot was already
/// flushed to disk, [`load`](TimeSeries::load) restores the merged
/// archive entry for that hour and a fresh `CurrentBucket` for the
/// same wall-clock hour starts taking new queries. Without this merge
/// the snapshot vector would carry two entries with the same
/// `timestamp` — confusing every downstream consumer that keys on
/// timestamp (TUI dashboard trend chart, `warden stats hourly` /
/// `daily`, CLI table renderer). The fix is local to the read path so
/// the on-disk snapshot format is untouched and older daemon versions
/// keep loading the snapshot without complaint.
fn merge_current_into_snapshot(result: &mut Vec<TimeBucket>, current: TimeBucket) {
    if let Some(last) = result.last_mut() {
        if last.timestamp == current.timestamp {
            last.queries = last.queries.saturating_add(current.queries);
            last.blocked = last.blocked.saturating_add(current.blocked);
            last.cache_hits = last.cache_hits.saturating_add(current.cache_hits);
            for i in 0..TYPE_BUCKET_COUNT {
                last.per_type[i] = last.per_type[i].saturating_add(current.per_type[i]);
                last.blocked_per_type[i] =
                    last.blocked_per_type[i].saturating_add(current.blocked_per_type[i]);
            }
            return;
        }
    }
    result.push(current);
}

/// Sprint G — merge entries sharing the same `timestamp` by summing
/// every numeric field element-wise. `BTreeMap` doubles as a free
/// ascending sort by `timestamp`. `saturating_add` everywhere so
/// pathological pre-Sprint-G snapshots with extreme fragment counts
/// cannot overflow on heal.
fn dedupe_by_timestamp_summing(input: Vec<TimeBucket>) -> Vec<TimeBucket> {
    use std::collections::BTreeMap;
    let mut acc: BTreeMap<u64, TimeBucket> = BTreeMap::new();
    for b in input {
        acc.entry(b.timestamp)
            .and_modify(|e| {
                e.queries = e.queries.saturating_add(b.queries);
                e.blocked = e.blocked.saturating_add(b.blocked);
                e.cache_hits = e.cache_hits.saturating_add(b.cache_hits);
                for i in 0..TYPE_BUCKET_COUNT {
                    e.per_type[i] = e.per_type[i].saturating_add(b.per_type[i]);
                    e.blocked_per_type[i] =
                        e.blocked_per_type[i].saturating_add(b.blocked_per_type[i]);
                }
            })
            .or_insert(b);
    }
    acc.into_values().collect()
}

/// Increment counters on the current bucket, rolling over if the boundary
/// has advanced. Common path is a guard load + atomic `fetch_add`, no lock.
///
/// The guard compares `cur.timestamp >= ts` (not `==`): a backward
/// wall-clock step (NTP step, not slew) or a concurrent over-roll leaves
/// the current bucket NEWER than `ts`, and we fold the event into it
/// rather than installing an older bucket and archiving the newer one —
/// that would seed out-of-order timestamps in the archive deque
/// (trk-time-series-wall-clock-backward). Mirrors the engine `HourlyRing`
/// "ignore behind-clock events" rule (`hour > current_hour → return`).
/// Forward advance (`ts > cur.timestamp`) still rolls over, so the
/// monotonic-clock behavior is unchanged.
///
/// Accepted drift (trk-time-series-rollover-lost-count): a thread that
/// loaded `cur`, passed the `>= ts` check, then runs its `fetch_add`
/// after the rollover owner's `cur.snapshot()` lands the count on the
/// just-archived bucket — that one increment is lost. Bounded by the
/// threads in-flight at the exact boundary, once per hour/day,
/// display-only. Making it exact would require the engine's
/// generation-tagged ring; not worth it for a display stat.
fn record_into(
    current: &ArcSwap<CurrentBucket>,
    archive: &Mutex<VecDeque<TimeBucket>>,
    ts: u64,
    cap: usize,
    blocked: bool,
    cache_hit: bool,
    bucket: usize,
) {
    let cur = current.load();
    if cur.timestamp >= ts {
        // Same bucket, or current is newer than `ts` (backward clock /
        // concurrent over-roll) — fold in, never install an older bucket.
        increment(&cur, blocked, cache_hit, bucket);
        return;
    }
    // Boundary advanced — serialise rollover on the archive mutex.
    let mut arch = archive.lock().unwrap_or_else(|e| e.into_inner());
    let cur = current.load();
    if cur.timestamp >= ts {
        // Another thread already rolled over (to `ts` or beyond), or the
        // clock stepped back; just increment, don't archive a newer bucket.
        drop(arch);
        increment(&cur, blocked, cache_hit, bucket);
        return;
    }
    // We own the rollover. Snapshot the old, install the fresh bucket
    // with our increment pre-applied, push the archive.
    let old_snap = cur.snapshot();
    let fresh = CurrentBucket::new(ts);
    fresh.queries.store(1, Ordering::Relaxed);
    if blocked {
        fresh.blocked.store(1, Ordering::Relaxed);
    }
    if cache_hit {
        fresh.cache_hits.store(1, Ordering::Relaxed);
    }
    if bucket < TYPE_BUCKET_COUNT {
        fresh.per_type[bucket].store(1, Ordering::Relaxed);
        if blocked {
            fresh.blocked_per_type[bucket].store(1, Ordering::Relaxed);
        }
    }
    current.store(Arc::new(fresh));
    arch.push_back(old_snap);
    while arch.len() > cap {
        arch.pop_front();
    }
}

fn increment(b: &CurrentBucket, blocked: bool, cache_hit: bool, bucket: usize) {
    b.queries.fetch_add(1, Ordering::Relaxed);
    if blocked {
        b.blocked.fetch_add(1, Ordering::Relaxed);
    }
    if cache_hit {
        b.cache_hits.fetch_add(1, Ordering::Relaxed);
    }
    if bucket < TYPE_BUCKET_COUNT {
        b.per_type[bucket].fetch_add(1, Ordering::Relaxed);
        if blocked {
            b.blocked_per_type[bucket].fetch_add(1, Ordering::Relaxed);
        }
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn truncate_hour(secs: u64) -> u64 {
    secs - (secs % SECS_PER_HOUR)
}

fn truncate_day(secs: u64) -> u64 {
    secs - (secs % SECS_PER_DAY)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncate_hour_works() {
        // 2024-01-01 12:34:56 UTC = 1704110096
        // Truncated to hour = 1704110096 - (1704110096 % 3600)
        let t = 1_704_110_096u64;
        let truncated = truncate_hour(t);
        assert_eq!(truncated % SECS_PER_HOUR, 0);
        assert!(t - truncated < SECS_PER_HOUR);
    }

    #[test]
    fn truncate_day_works() {
        // 2024-01-01 12:34:56 UTC = 1704110096
        let t = 1_704_110_096;
        let truncated = truncate_day(t);
        assert_eq!(truncated % SECS_PER_DAY, 0);
        assert!(t - truncated < SECS_PER_DAY);
    }

    #[test]
    fn record_increments_current_bucket() {
        let ts = TimeSeries::new();

        // Sprint F — pass distinct buckets so per_type round-trips
        // through the snapshot. Bucket 0 = A, 1 = AAAA, 2 = TXT.
        ts.record(false, false, 0);
        ts.record(true, false, 1);
        ts.record(false, true, 2);

        let hourly = ts.hourly_snapshot();
        assert_eq!(hourly.len(), 1);
        assert_eq!(hourly[0].queries, 3);
        assert_eq!(hourly[0].blocked, 1);
        assert_eq!(hourly[0].cache_hits, 1);
        // Per-type breakdown: 1 A query, 1 AAAA query (blocked), 1 TXT cache-hit.
        assert_eq!(hourly[0].per_type[0], 1);
        assert_eq!(hourly[0].per_type[1], 1);
        assert_eq!(hourly[0].per_type[2], 1);
        assert_eq!(hourly[0].per_type.iter().sum::<u64>(), 3);
        // Only AAAA was blocked → exactly one slot of blocked_per_type set.
        assert_eq!(hourly[0].blocked_per_type[0], 0);
        assert_eq!(hourly[0].blocked_per_type[1], 1);
        assert_eq!(hourly[0].blocked_per_type[2], 0);
        assert_eq!(hourly[0].blocked_per_type.iter().sum::<u64>(), 1);

        let daily = ts.daily_snapshot();
        assert_eq!(daily.len(), 1);
        assert_eq!(daily[0].queries, 3);
        assert_eq!(daily[0].per_type.iter().sum::<u64>(), 3);
        assert_eq!(daily[0].blocked_per_type.iter().sum::<u64>(), 1);
    }

    #[test]
    fn hourly_cap_at_24() {
        let ts = TimeSeries::new();
        // Manually load 30 hourly buckets
        let buckets: Vec<TimeBucket> = (0..30)
            .map(|i| TimeBucket {
                timestamp: i * SECS_PER_HOUR,
                queries: 100,
                blocked: 10,
                cache_hits: 50,
                per_type: zero_per_type(),
                blocked_per_type: zero_per_type(),
            })
            .collect();
        ts.load(buckets, vec![]);

        let hourly = ts.hourly_snapshot();
        // 24 historical (capped) + 1 current (if queries > 0, but we didn't record)
        assert!(hourly.len() <= MAX_HOURLY + 1);
    }

    #[test]
    fn daily_cap_respects_max() {
        let ts = TimeSeries::new();
        let buckets: Vec<TimeBucket> = (0..12)
            .map(|i| TimeBucket {
                timestamp: i * SECS_PER_DAY,
                queries: 1000,
                blocked: 100,
                cache_hits: 500,
                per_type: zero_per_type(),
                blocked_per_type: zero_per_type(),
            })
            .collect();
        ts.load(vec![], buckets);

        let daily = ts.daily_snapshot();
        assert!(daily.len() <= MAX_DAILY + 1);
    }

    #[test]
    fn load_restores_historical_data() {
        let ts = TimeSeries::new();
        let hourly = vec![
            TimeBucket {
                timestamp: 1000 * SECS_PER_HOUR,
                queries: 50,
                blocked: 5,
                cache_hits: 20,
                per_type: zero_per_type(),
                blocked_per_type: zero_per_type(),
            },
            TimeBucket {
                timestamp: 1001 * SECS_PER_HOUR,
                queries: 60,
                blocked: 8,
                cache_hits: 25,
                per_type: zero_per_type(),
                blocked_per_type: zero_per_type(),
            },
        ];
        ts.load(hourly.clone(), vec![]);

        let snap = ts.hourly_snapshot();
        // Historical + possibly current
        assert!(snap.len() >= 2);
        assert_eq!(snap[0].queries, 50);
        assert_eq!(snap[1].queries, 60);
    }

    #[test]
    fn concurrent_record_produces_exact_total() {
        // Stress test: N threads × M records each → queries == N*M, no lost updates.
        use std::sync::Arc;
        use std::thread;

        let ts = Arc::new(TimeSeries::new());
        let n_threads: u64 = 16;
        let per_thread: u64 = 10_000;

        let handles: Vec<_> = (0..n_threads)
            .map(|i| {
                let ts = Arc::clone(&ts);
                thread::spawn(move || {
                    for j in 0..per_thread {
                        // Mix of blocked/cache-hit patterns keyed off (i, j)
                        let blocked = (i + j) % 3 == 0;
                        let cache_hit = (i * j) % 5 == 0;
                        // Sprint F — distribute across all 10 type buckets.
                        let bucket = ((i + j) as usize) % TYPE_BUCKET_COUNT;
                        ts.record(blocked, cache_hit, bucket);
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }

        let total_expected = n_threads * per_thread;
        let hourly = ts.hourly_snapshot();
        let hourly_queries: u64 = hourly.iter().map(|b| b.queries).sum();
        assert_eq!(
            hourly_queries, total_expected,
            "hourly queries should match total records with no lost updates"
        );
        // Sprint F — per_type sum across all buckets equals total queries
        // (no lost updates on the per-type counters either).
        let per_type_sum: u64 = hourly.iter().flat_map(|b| b.per_type.iter().copied()).sum();
        assert_eq!(per_type_sum, total_expected);
        let daily = ts.daily_snapshot();
        let daily_queries: u64 = daily.iter().map(|b| b.queries).sum();
        assert_eq!(daily_queries, total_expected);
        let daily_per_type_sum: u64 = daily.iter().flat_map(|b| b.per_type.iter().copied()).sum();
        assert_eq!(daily_per_type_sum, total_expected);
    }

    /// trk-time-series-wall-clock-backward: when the current bucket is
    /// newer than the incoming `ts` (a backward clock step), the event
    /// must fold into the current bucket — never install an older bucket
    /// and archive the newer one (which would seed an out-of-order
    /// timestamp in the archive deque). A genuine forward advance must
    /// still roll over. Drives `record_into` directly to control `ts`.
    #[test]
    fn record_into_backward_clock_folds_without_reorder() {
        let future_hour = 1000 * SECS_PER_HOUR;
        let earlier_hour = 999 * SECS_PER_HOUR;
        let current = ArcSwap::from_pointee(CurrentBucket::new(future_hour));
        let archive = Mutex::new(VecDeque::new());

        // Clock stepped back: ts < current bucket timestamp.
        record_into(
            &current,
            &archive,
            earlier_hour,
            MAX_HOURLY,
            false,
            false,
            0,
        );
        assert!(
            archive.lock().unwrap().is_empty(),
            "backward clock step must not archive a newer bucket"
        );
        assert_eq!(
            current.load().timestamp,
            future_hour,
            "current bucket must be unchanged on a backward step"
        );
        assert_eq!(
            current.load().queries.load(Ordering::Relaxed),
            1,
            "event must fold into the current bucket"
        );

        // Genuine forward advance still rolls over.
        let next_hour = 1001 * SECS_PER_HOUR;
        record_into(&current, &archive, next_hour, MAX_HOURLY, false, false, 0);
        assert_eq!(
            archive.lock().unwrap().len(),
            1,
            "forward advance must archive the old bucket"
        );
        assert_eq!(current.load().timestamp, next_hour);
    }

    /// Sprint F — `per_type_24h_snapshot` sums the trailing 24 hourly
    /// buckets (including in-flight current bucket if non-empty).
    /// Loaded ring of 30 historical buckets + a few live records exercises
    /// both the cap and the current-bucket inclusion.
    #[test]
    fn per_type_24h_snapshot_sums_trailing_24() {
        let ts = TimeSeries::new();

        // 30 historical buckets — 0..29. Each carries `i+1` queries on
        // bucket A (per_type[0]) and `1` blocked on bucket AAAA
        // (blocked_per_type[1]). With cap=24, the 24 newest are 6..29.
        // Sum of per_type[0] = 7+8+...+30 = (7+30)*24/2 = 444.
        // Sum of blocked_per_type[1] = 1 * 24 = 24.
        let buckets: Vec<TimeBucket> = (0..30)
            .map(|i| {
                let mut pt = zero_per_type();
                let mut bpt = zero_per_type();
                pt[0] = i + 1;
                bpt[1] = 1;
                TimeBucket {
                    timestamp: i * SECS_PER_HOUR,
                    queries: i + 1,
                    blocked: 1,
                    cache_hits: 0,
                    per_type: pt,
                    blocked_per_type: bpt,
                }
            })
            .collect();
        ts.load(buckets, vec![]);

        // No live records yet → current bucket empty → not counted.
        let (q, b) = ts.per_type_24h_snapshot();
        assert_eq!(
            q[0], 444,
            "per_type[0] sum across trailing 24 historical buckets"
        );
        assert_eq!(b[1], 24, "blocked_per_type[1] sum across trailing 24");

        // Add live records on the in-flight current bucket. They land
        // in slot A (0) for queries and slot AAAA (1) for blocked.
        ts.record(false, false, 0);
        ts.record(false, false, 0);
        ts.record(true, false, 1);
        // Current bucket now has 3 queries → counted in the window.
        // When the current bucket is added, the oldest historical (i=6,
        // queries=7) is evicted from the trailing-24, so per_type[0]
        // delta is `+2 (current) - 7 (evicted) = -5` → 444 - 5 = 439.
        let (q2, b2) = ts.per_type_24h_snapshot();
        assert_eq!(q2[0], 439);
        // blocked_per_type[1]: was 24 (all 24 historical contribute 1),
        // current adds 1, oldest historical also contributes 1 → -1 + 1 = 0.
        assert_eq!(b2[1], 24);
    }

    /// Sprint G test helper — construct a `TimeBucket` with zero
    /// `per_type` / `blocked_per_type` arrays. Used by the dedupe
    /// tests below.
    fn bucket(timestamp: u64, queries: u64, blocked: u64, cache_hits: u64) -> TimeBucket {
        TimeBucket {
            timestamp,
            queries,
            blocked,
            cache_hits,
            per_type: zero_per_type(),
            blocked_per_type: zero_per_type(),
        }
    }

    /// Sprint G — three same-timestamp fragments collapse into one
    /// bucket with summed counters; distinct-timestamp fragments stay
    /// separate; output is ascending by `timestamp`.
    #[test]
    fn load_dedupes_identical_timestamps_by_sum() {
        let ts = TimeSeries::new();
        let h = vec![
            bucket(100, 10, 3, 1),
            bucket(100, 5, 2, 0),
            bucket(200, 3, 1, 1),
        ];
        ts.load(h, vec![]);
        let out = ts.hourly_snapshot();
        let archived: Vec<&TimeBucket> = out.iter().filter(|b| b.queries > 0).collect();
        assert_eq!(archived.len(), 2);
        assert_eq!(archived[0].timestamp, 100);
        assert_eq!(archived[0].queries, 15);
        assert_eq!(archived[0].blocked, 5);
        assert_eq!(archived[0].cache_hits, 1);
        assert_eq!(archived[1].timestamp, 200);
        assert_eq!(archived[1].queries, 3);
        assert_eq!(archived[1].blocked, 1);
        assert_eq!(archived[1].cache_hits, 1);
    }

    /// Sprint G — `per_type` and `blocked_per_type` arrays merge
    /// element-wise, not by struct-replace.
    #[test]
    fn load_dedupes_per_type_arrays_element_wise() {
        let ts = TimeSeries::new();
        let mut a = bucket(100, 10, 0, 0);
        a.per_type[0] = 7;
        a.per_type[1] = 3;
        a.blocked_per_type[0] = 2;
        let mut b = bucket(100, 5, 0, 0);
        b.per_type[0] = 1;
        b.per_type[1] = 4;
        b.blocked_per_type[1] = 5;
        ts.load(vec![a, b], vec![]);
        let out = ts.hourly_snapshot();
        let merged = out
            .iter()
            .find(|x| x.timestamp == 100)
            .expect("merged bucket");
        assert_eq!(merged.per_type[0], 8);
        assert_eq!(merged.per_type[1], 7);
        assert_eq!(merged.blocked_per_type[0], 2);
        assert_eq!(merged.blocked_per_type[1], 5);
    }

    /// Sprint G — clean input (no duplicate timestamps) survives the
    /// dedupe pass without mutation; ordering preserved
    /// timestamp-ascending.
    #[test]
    fn load_preserves_already_clean_input() {
        let ts = TimeSeries::new();
        ts.load(vec![bucket(100, 5, 1, 0), bucket(200, 3, 0, 1)], vec![]);
        let out = ts.hourly_snapshot();
        let archived: Vec<&TimeBucket> = out.iter().filter(|b| b.queries > 0).collect();
        assert_eq!(archived.len(), 2);
        assert_eq!(archived[0].timestamp, 100);
        assert_eq!(archived[0].queries, 5);
        assert_eq!(archived[1].timestamp, 200);
        assert_eq!(archived[1].queries, 3);
    }

    // ── §4.26 follow-up: mid-hour-restart-dup ────────────────────
    //
    // Regression net for the bug surfaced by the post-hotfix CT smoke
    // 2026-05-12: a daemon restart inside the current hour produces a
    // snapshot vector with TWO entries sharing the same `timestamp` —
    // the archive entry restored from disk (pre-restart accumulator
    // for hour T) and the fresh in-flight `current_hour` bucket (also
    // hour T, post-restart). The fix folds the in-flight bucket into
    // the trailing archive entry when their timestamps match.

    /// `record()` after `load()` for the same hour MUST collapse into
    /// a single snapshot entry, not produce two same-timestamp rows.
    #[test]
    fn hourly_snapshot_collapses_in_flight_into_same_timestamp_archive() {
        let ts = TimeSeries::new();
        // Force the current bucket to a deterministic timestamp so
        // the test does not depend on wall-clock.
        let t = truncate_hour(now_secs());
        ts.current_hour
            .store(std::sync::Arc::new(CurrentBucket::new(t)));
        // Pretend pre-restart snapshot wrote an archive entry for the
        // same hour, then load restored it.
        ts.load(
            vec![TimeBucket {
                timestamp: t,
                queries: 41,
                blocked: 31,
                cache_hits: 2,
                per_type: [0; TYPE_BUCKET_COUNT],
                blocked_per_type: [0; TYPE_BUCKET_COUNT],
            }],
            vec![],
        );
        // Re-pin the current bucket to `t` because `load()` reset the
        // ArcSwap to a fresh, wall-clock-derived bucket. In production
        // the wall clock is the same instant before/after `load()`,
        // so this manual re-pin matches the real timing window the
        // bug occurs in.
        ts.current_hour
            .store(std::sync::Arc::new(CurrentBucket::new(t)));
        // Simulate 100 post-restart queries for the same hour.
        for _ in 0..100 {
            ts.record(false, false, 0);
        }
        // 26 of those get re-classified as blocked separately.
        for _ in 0..26 {
            ts.record(true, false, 0);
        }
        let snap = ts.hourly_snapshot();
        let same_ts: Vec<&TimeBucket> = snap.iter().filter(|b| b.timestamp == t).collect();
        assert_eq!(
            same_ts.len(),
            1,
            "snapshot must hold exactly one entry per timestamp; got: {snap:?}",
        );
        let b = same_ts[0];
        assert_eq!(b.queries, 41 + 100 + 26, "queries must sum across restart");
        assert_eq!(b.blocked, 31 + 26, "blocked must sum across restart");
        assert_eq!(b.cache_hits, 2, "cache_hits inherits archive value");
    }

    /// Same regression net for the daily bucket — `current_day`
    /// folding into the trailing daily archive entry.
    #[test]
    fn daily_snapshot_collapses_in_flight_into_same_timestamp_archive() {
        let ts = TimeSeries::new();
        let t = truncate_day(now_secs());
        ts.current_day
            .store(std::sync::Arc::new(CurrentBucket::new(t)));
        ts.load(
            vec![],
            vec![TimeBucket {
                timestamp: t,
                queries: 5_000,
                blocked: 2_000,
                cache_hits: 100,
                per_type: [0; TYPE_BUCKET_COUNT],
                blocked_per_type: [0; TYPE_BUCKET_COUNT],
            }],
        );
        ts.current_day
            .store(std::sync::Arc::new(CurrentBucket::new(t)));
        // `record()` increments BOTH current_hour and current_day, so
        // the hourly bucket also rises — the daily check below only
        // cares about the per-day collapse.
        for _ in 0..300 {
            ts.record(true, false, 0);
        }
        let snap = ts.daily_snapshot();
        let same_ts: Vec<&TimeBucket> = snap.iter().filter(|b| b.timestamp == t).collect();
        assert_eq!(
            same_ts.len(),
            1,
            "daily snapshot must hold exactly one entry per timestamp; got: {snap:?}",
        );
        let b = same_ts[0];
        assert_eq!(b.queries, 5_000 + 300, "daily queries sum across restart");
        assert_eq!(b.blocked, 2_000 + 300, "daily blocked sum across restart");
        assert_eq!(b.cache_hits, 100, "daily cache_hits inherits archive value");
    }
}
