//! Core stats engine — global counters, per-client tracking, domain frequency.
//!
//! All hot-path operations use atomics (zero allocation, zero lock).
//! The `DashMap` for per-client stats uses shard-level locking — concurrent
//! updates to different client IPs never contend.

use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwap;
use compact_str::CompactString;
use dashmap::mapref::entry::Entry;
use dashmap::DashMap;

use hickory_proto::rr::RecordType;

use crate::config::settings::{LogMode, TrackingConfig};

use super::prefetch::{HitTracker, PrefetchTrackerConfig};
use super::query_log::{QueryLog, QueryLogDropSnapshot, QueryLogEntry};
use super::query_type::{TypeBucket, TYPE_BUCKET_COUNT};
use super::time_series::TimeSeries;
use super::top_n::TopNSnapshot;

/// Global counters — all-time totals, updated atomically on every query.
pub struct GlobalStats {
    pub total_queries: AtomicU64,
    pub total_blocked: AtomicU64,
    pub total_cache_hits: AtomicU64,
    /// Subset of `total_cache_hits`: fresh hits where the cached response was
    /// a negative (NXDOMAIN or NODATA). Surfaced in the TUI Security view so
    /// operators can see how much upstream load the negative cache is saving.
    pub total_cache_negative_hits: AtomicU64,
    /// Queries refused because the source IP was not in `server.allow_from`
    /// (P0-5 open-resolver guard). Diagnostic counter — not persisted in
    /// snapshots, resets on restart.
    pub total_refused_acl: AtomicU64,
    /// Queries refused by a security pre-query gate or rate limiter
    /// (REFUSED / RRL_DROP: rate-limit, invalid-chars, rebinding,
    /// anti-bypass, tunneling). These carry `blocked:true` and so are
    /// also counted in `total_blocked` (commit 9f60205 — "refusals
    /// visible in stats"); this dedicated counter lets an operator
    /// separate security refusals from content blocks in the block-rate
    /// signal (rev-2606 engine-03). Diagnostic — not persisted in
    /// snapshots, resets on restart.
    pub total_refused_security: AtomicU64,
    /// Per-`TypeBucket` query counter, indexed by `bucket as usize`. Sums
    /// across all clients; matches `total_queries` modulo races. Used by
    /// the TUI QTYPE distribution widget and the `qtype_distribution` IPC
    /// field. See `tracking::query_type::TypeBucket` for the bucket set.
    pub per_type: [AtomicU64; TYPE_BUCKET_COUNT],
    /// Per-`TypeBucket` BLOCKED query counter — parallel to `per_type`,
    /// only incremented when `record_query` is called with `blocked=true`.
    /// Sum across buckets matches `total_blocked` modulo races. Surfaced
    /// in the Dashboard QTYPE chart card as the second (red) bar per
    /// bucket and in the `qtype_blocked_distribution` IPC field.
    pub blocked_per_type: [AtomicU64; TYPE_BUCKET_COUNT],
}

impl GlobalStats {
    fn new() -> Self {
        Self {
            total_queries: AtomicU64::new(0),
            total_blocked: AtomicU64::new(0),
            total_cache_hits: AtomicU64::new(0),
            total_cache_negative_hits: AtomicU64::new(0),
            total_refused_acl: AtomicU64::new(0),
            total_refused_security: AtomicU64::new(0),
            per_type: std::array::from_fn(|_| AtomicU64::new(0)),
            blocked_per_type: std::array::from_fn(|_| AtomicU64::new(0)),
        }
    }

    /// Snapshot the per-type counters in canonical bucket order
    /// (`TypeBucket::ALL`). Cheap — 10 relaxed atomic loads.
    pub fn per_type_snapshot(&self) -> [u64; TYPE_BUCKET_COUNT] {
        std::array::from_fn(|i| self.per_type[i].load(Ordering::Relaxed))
    }

    /// Snapshot the per-type BLOCKED counters in canonical bucket order.
    /// Mirrors `per_type_snapshot`. Sum equals `total_blocked` modulo
    /// concurrent updates.
    pub fn blocked_per_type_snapshot(&self) -> [u64; TYPE_BUCKET_COUNT] {
        std::array::from_fn(|i| self.blocked_per_type[i].load(Ordering::Relaxed))
    }
}

/// Number of hourly buckets in the per-entity ring. 24 covers the
/// last calendar day at hour granularity, which is what the Devices
/// tab's side-card sparkline renders.
pub const DEVICE_HOURLY_SLOTS: usize = 24;

/// §4.39 (s-orphans-disc-1) — generation-tagged hourly ring slots.
///
/// Each `AtomicU64` slot packs `(hour << 32) | count`: the high 32
/// bits are the absolute hour index (`unix_secs / 3600`), the low 32
/// bits are the event count recorded in that hour. A slot is "stale"
/// (left over from a prior rotation of the 24-slot ring) iff its
/// packed hour differs from the hour being recorded or read.
///
/// This replaces the pre-§4.39 `anchor_hour` + lazy zero-loop design,
/// which had an hour-boundary race: the CAS winner zeroed slots
/// *after* publishing the new anchor, so a concurrent recorder could
/// `fetch_add` a slot the winner was about to `store(0)` and lose the
/// count. With self-describing slots there is no shared anchor and no
/// zeroing loop — a stale slot is overwritten by the first recorder
/// of the new hour (one CAS), and readers ignore any slot whose hour
/// falls outside the trailing-24h window. The advance race is
/// structurally impossible.
const HOUR_SHIFT: u32 = 32;
const COUNT_MASK: u64 = 0xFFFF_FFFF;

#[inline]
fn pack_slot(hour: u64, count: u64) -> u64 {
    (hour << HOUR_SHIFT) | (count & COUNT_MASK)
}

#[inline]
fn unpack_slot(v: u64) -> (u64, u64) {
    (v >> HOUR_SHIFT, v & COUNT_MASK)
}

/// `true` when a slot's packed `hour` falls inside the trailing-24h
/// window ending at `current_hour` — i.e. the slot's count is still
/// live and should be summed by a reader.
#[inline]
fn slot_in_window(hour: u64, current_hour: u64) -> bool {
    hour <= current_hour && current_hour - hour < DEVICE_HOURLY_SLOTS as u64
}

/// Record one event into a generation-tagged 24-slot ring for the hour
/// `now_secs` falls into. Lock-free, alloc-free, race-free: a CAS loop
/// on a single slot.
///
/// - Slot already on `current_hour` → CAS `count + 1` (saturating at
///   `COUNT_MASK` so a count overflow can never carry into the hour
///   bits — 4.29 G events/hour/slot is unreachable in practice).
/// - Slot on an older hour (stale ring rotation, or first write) →
///   CAS to `(current_hour, 1)`.
/// - Slot on a *newer* hour (clock skew / reordered record) → drop the
///   count rather than clobber a newer hour's data.
///
/// A failed CAS just reloads and retries — under contention the worst
/// case is a short spin, never a lost or double-counted event.
#[inline]
fn record_into_ring(slots: &[AtomicU64; DEVICE_HOURLY_SLOTS], now_secs: u64) {
    let current_hour = now_secs / 3600;
    let slot = &slots[(current_hour % DEVICE_HOURLY_SLOTS as u64) as usize];
    let mut cur = slot.load(Ordering::Relaxed);
    loop {
        let (hour, count) = unpack_slot(cur);
        let next = if hour == current_hour {
            if count >= COUNT_MASK {
                return; // saturated — refuse to carry into the hour bits
            }
            pack_slot(current_hour, count + 1)
        } else if hour > current_hour {
            return; // slot owned by a newer hour — don't clobber it
        } else {
            pack_slot(current_hour, 1)
        };
        match slot.compare_exchange_weak(cur, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return,
            Err(observed) => cur = observed,
        }
    }
}

/// Sum the counts of every slot whose packed hour is inside the
/// trailing-24h window ending at `now_secs`'s hour. Pure reads — no
/// mutation, no advance step (slots are self-describing).
#[inline]
fn sum_ring_last_24h(slots: &[AtomicU64; DEVICE_HOURLY_SLOTS], now_secs: u64) -> u64 {
    let current_hour = now_secs / 3600;
    slots
        .iter()
        .map(|s| {
            let (hour, count) = unpack_slot(s.load(Ordering::Relaxed));
            if slot_in_window(hour, current_hour) {
                count
            } else {
                0
            }
        })
        .sum()
}

/// Snapshot the trailing 24h of a ring in chronological order —
/// `out[0]` is "23 hours ago", `out[23]` is the current hour. A slot
/// whose packed hour does not match the expected hour for its position
/// (never written, or stale) reads as 0.
#[inline]
fn ring_last_24h_chrono(slots: &[AtomicU64; DEVICE_HOURLY_SLOTS], now_secs: u64) -> Vec<u64> {
    let current_hour = now_secs / 3600;
    let mut out = Vec::with_capacity(DEVICE_HOURLY_SLOTS);
    for offset in (0..DEVICE_HOURLY_SLOTS as u64).rev() {
        let hour = current_hour.saturating_sub(offset);
        let slot = (hour % DEVICE_HOURLY_SLOTS as u64) as usize;
        let (slot_hour, count) = unpack_slot(slots[slot].load(Ordering::Relaxed));
        out.push(if slot_hour == hour { count } else { 0 });
    }
    out
}

/// Reusable 24-slot hourly ring buffer for per-entity 24h-rolling
/// counters (per-domain queries / blocks, per-list blocks). Each slot
/// is generation-tagged (see [`record_into_ring`]) so there is no
/// shared anchor and no hour-boundary advance race; it stands on its
/// own so non-device call sites (top_n Top-N 24h ranking, per-list
/// block counts) don't need the rest of the `DeviceStats` weight.
///
/// Hot path: `record(now)` is one atomic load + one CAS on a single
/// slot. No rollover branch — a stale slot is overwritten in the same
/// CAS that records the new hour's first event.
///
/// Memory: 24×8B slots = 192B per ring. With ~10k domain entries × 2
/// (queried + blocked) + 64 list bits, worst-case ~4MB.
#[repr(align(64))]
pub struct HourlyRing {
    /// Generation-tagged slots — `(hour << 32) | count`. See
    /// [`pack_slot`] / [`unpack_slot`].
    pub slots: [AtomicU64; DEVICE_HOURLY_SLOTS],
}

impl Default for HourlyRing {
    fn default() -> Self {
        Self::new()
    }
}

impl HourlyRing {
    pub fn new() -> Self {
        Self {
            slots: std::array::from_fn(|_| AtomicU64::new(0)),
        }
    }

    /// Bump the slot for `now_secs`. Mirrors
    /// `DeviceStats::record_hourly_query`.
    pub fn record(&self, now_secs: u64) {
        record_into_ring(&self.slots, now_secs);
    }

    /// Sum the last 24h of slots. Slots are self-describing, so this is
    /// a pure read — 24 atomic loads, no advance step.
    pub fn sum_last_24h(&self, now_secs: u64) -> u64 {
        sum_ring_last_24h(&self.slots, now_secs)
    }
}

/// Per-device stats, cache-line aligned to prevent false sharing.
///
/// Each field that's updated on the hot path is an `AtomicU64`.
/// The `name` and `profile` fields are set once (or on config reload)
/// and read concurrently — they're behind the DashMap's shard lock.
///
/// 2026-04-29: `queries_today_baseline` + `today_day_index` enable a
/// "today only" view of queries on the Dashboard's Top Devices card
/// without changing the hot path. Both are written only on the
/// IPC-read path via `queries_today()`; `record_query` continues to
/// touch only the cumulative `queries` counter.
///
/// 2026-04-30 (S44): `hourly_queries` / `hourly_blocked` add 24-slot
/// rings of per-device queries-per-hour. §4.39 made the slots
/// generation-tagged (`(hour << 32) | count`) — hot path is one
/// atomic load + one CAS per query, no rollover branch, no anchor.
#[repr(align(64))]
pub struct DeviceStats {
    pub name: CompactString,
    pub profile: CompactString,
    pub queries: AtomicU64,
    pub blocked: AtomicU64,
    pub cache_hits: AtomicU64,
    pub last_seen: AtomicU64,
    /// Snapshot of `queries` taken at the start of the current calendar
    /// day. `queries_today = queries - queries_today_baseline` once
    /// `today_day_index` matches the current day. Initialised to 0
    /// (matches the cumulative counter at construction so first-day
    /// reads = "since this device was first observed today").
    pub queries_today_baseline: AtomicU64,
    /// Calendar day index (`unix_secs / 86400`) the baseline corresponds
    /// to. On read, callers compare with the current day and CAS-roll
    /// the baseline forward when they cross midnight.
    pub today_day_index: AtomicU64,
    /// 24-bucket ring of per-device queries-per-hour. Each slot is
    /// generation-tagged (`(hour << 32) | count` — see
    /// [`record_into_ring`]) so a stale slot is overwritten by the
    /// first recorder of the new hour; there is no shared anchor and
    /// no zeroing loop. Read via `hourly_queries_last_24h`, which
    /// returns oldest-first so the TUI can map `slot[N]` to "N hours
    /// ago" without arithmetic.
    pub hourly_queries: [AtomicU64; DEVICE_HOURLY_SLOTS],
    /// 24-bucket ring of per-device BLOCKED-queries-per-hour. Parallel
    /// to `hourly_queries`; each ring is independently
    /// generation-tagged, so the two can never disagree about the
    /// window boundary without needing a shared anchor. Drives the
    /// Dashboard Top Devices (24h) card's ranking.
    pub hourly_blocked: [AtomicU64; DEVICE_HOURLY_SLOTS],
    /// Per-`TypeBucket` query counter for this device. Same shape as
    /// `GlobalStats::per_type`. Sums match the device's cumulative
    /// `queries` counter modulo concurrent updates. Surfaced in
    /// per-device IPC responses so the TUI can show "this client's
    /// query mix" alongside the global pie.
    pub per_type: [AtomicU64; TYPE_BUCKET_COUNT],
    /// Per-`TypeBucket` BLOCKED query counter for this device. Mirrors
    /// `GlobalStats::blocked_per_type`. Sum matches device `blocked`
    /// counter modulo races.
    pub blocked_per_type: [AtomicU64; TYPE_BUCKET_COUNT],
}

impl DeviceStats {
    pub fn new(name: CompactString, profile: CompactString) -> Self {
        Self {
            name,
            profile,
            queries: AtomicU64::new(0),
            blocked: AtomicU64::new(0),
            cache_hits: AtomicU64::new(0),
            last_seen: AtomicU64::new(0),
            queries_today_baseline: AtomicU64::new(0),
            today_day_index: AtomicU64::new(0),
            hourly_queries: std::array::from_fn(|_| AtomicU64::new(0)),
            hourly_blocked: std::array::from_fn(|_| AtomicU64::new(0)),
            per_type: std::array::from_fn(|_| AtomicU64::new(0)),
            blocked_per_type: std::array::from_fn(|_| AtomicU64::new(0)),
        }
    }

    /// Snapshot this device's per-type counters in canonical bucket
    /// order. Mirrors `GlobalStats::per_type_snapshot`.
    pub fn per_type_snapshot(&self) -> [u64; TYPE_BUCKET_COUNT] {
        std::array::from_fn(|i| self.per_type[i].load(Ordering::Relaxed))
    }

    /// Snapshot this device's per-type BLOCKED counters in canonical
    /// order. Mirrors `GlobalStats::blocked_per_type_snapshot`.
    pub fn blocked_per_type_snapshot(&self) -> [u64; TYPE_BUCKET_COUNT] {
        std::array::from_fn(|i| self.blocked_per_type[i].load(Ordering::Relaxed))
    }

    /// Roll the "today" baseline forward when the calendar day changed
    /// since it was last seeded. `today` is the UTC day index
    /// (`now_secs / 86400`). Returns `true` when it rolled — i.e. the
    /// caller crossed into a new day or hit a never-seeded device, so
    /// "today" is 0. Idempotent within a day: once the stored index
    /// matches it is a single atomic load returning `false`.
    ///
    /// Seeds `queries_today_baseline = queries` and stamps the day. Two
    /// threads racing here store values differing by at most a handful
    /// of queries; the next read reports a 0..=N drift that disappears
    /// on subsequent ticks.
    ///
    /// Called from both the IPC read path ([`Self::queries_today`]) and
    /// the background snapshot sweep
    /// ([`StatsEngine::roll_today_baselines`]). The sweep is what makes
    /// the baseline anchor near real midnight on a headless box that no
    /// dashboard polls until hours into the day — without it, the first
    /// read of the day seeds `baseline = cumulative_now` and collapses
    /// "today" to ~0 for every device.
    fn maybe_roll_day(&self, today: u64) -> bool {
        if self.today_day_index.load(Ordering::Relaxed) != today {
            let queries = self.queries.load(Ordering::Relaxed);
            self.queries_today_baseline
                .store(queries, Ordering::Relaxed);
            self.today_day_index.store(today, Ordering::Relaxed);
            return true;
        }
        false
    }

    /// Return `queries` scoped to the current calendar day, rolling the
    /// baseline forward if the day index changed since the last read.
    /// Caller passes `now_secs` (Unix seconds) so a single IPC poll sees
    /// a consistent day boundary across all devices.
    ///
    /// Day boundary is UTC (`now_secs / 86400`). This trades operator
    /// "00:00 in my timezone" expectations for a zero-syscall read; if
    /// operators ask for local-tz boundaries later, swap the divisor
    /// for a tz-aware computation behind the same API.
    pub fn queries_today(&self, now_secs: u64) -> u64 {
        let today = now_secs / 86400;
        if self.maybe_roll_day(today) {
            return 0;
        }
        let queries = self.queries.load(Ordering::Relaxed);
        let baseline = self.queries_today_baseline.load(Ordering::Relaxed);
        queries.saturating_sub(baseline)
    }

    /// Bump the hour-of-day slot the current second falls into. Hot
    /// path — callers must already hold the device-stats entry. Cost
    /// in the steady state is one atomic load + one CAS on a single
    /// generation-tagged slot (see [`record_into_ring`]) — no rollover
    /// branch, no shared anchor. Pair with the cumulative
    /// `queries.fetch_add(1)` next to it; we don't fold the two into
    /// one helper because the existing call sites touch the cumulative
    /// counter through several different paths.
    pub fn record_hourly_query(&self, now_secs: u64) {
        record_into_ring(&self.hourly_queries, now_secs);
    }

    /// Bump the BLOCKED-queries hour-slot. Same shape as
    /// `record_hourly_query` but on the parallel `hourly_blocked`
    /// ring. Called only inside the `if blocked` branch of
    /// `record_query`. Hot-path cost matches the queries ring.
    ///
    /// Invariant note: this and `record_hourly_query` are two
    /// separate atomic operations on disjoint arrays. A concurrent
    /// reader can observe `hourly_queries[slot] = n+1` while
    /// `hourly_blocked[slot] = m` (or vice versa); the skew is at
    /// most one count and self-heals on the next query. Same
    /// nature as the existing `queries`/`hourly_queries` skew.
    pub fn record_hourly_blocked(&self, now_secs: u64) {
        record_into_ring(&self.hourly_blocked, now_secs);
    }

    /// Snapshot the last 24 hours of per-device queries in
    /// chronological order — `out[0]` is "23 hours ago", `out[23]` is
    /// the current hour. Slots not written within the last 24h (or
    /// left stale from a prior ring rotation) read as 0.
    pub fn hourly_queries_last_24h(&self, now_secs: u64) -> Vec<u64> {
        ring_last_24h_chrono(&self.hourly_queries, now_secs)
    }

    /// Sum the last 24h of BLOCKED queries for this device. Drives the
    /// Dashboard Top Devices (24h) ranking. Matches
    /// `HourlyRing::sum_last_24h` shape.
    pub fn hourly_blocked_last_24h_sum(&self, now_secs: u64) -> u64 {
        sum_ring_last_24h(&self.hourly_blocked, now_secs)
    }
}

/// Central stats coordinator — owns all tracking state.
pub struct StatsEngine {
    pub global: GlobalStats,
    pub devices: DashMap<IpAddr, DeviceStats>,
    pub domain_queries: DashMap<CompactString, AtomicU64>,
    pub domain_blocked: DashMap<CompactString, AtomicU64>,
    /// Per-domain 24h-rolling ring of query counts. Parallel to
    /// `domain_queries`; the lifetime path stays byte-identical. Drives
    /// the Dashboard Top Domains (24h) narrow-fallback card and the
    /// `top_queried_24h` Top-N projection. Pruned by `prune_hourly_map`
    /// (entries with `sum_last_24h == 0` are dropped when the map
    /// exceeds capacity) so it doesn't diverge from the lifetime map.
    pub domain_queries_hourly: DashMap<CompactString, HourlyRing>,
    /// Per-domain 24h-rolling ring of BLOCK counts. Parallel to
    /// `domain_blocked`. Drives the Dashboard Top Blocked Domains
    /// (24h) card's ranking.
    pub domain_blocked_hourly: DashMap<CompactString, HourlyRing>,
    /// Sprint B Dashboard v2 — per-bit blocked-query counters keyed by
    /// the Tier 1 blocklist bit (0..=63) attributed to each block.
    /// Pre-seeded at start.rs with all bits configured in the active
    /// `source_bits` map, so the steady-state hot path is `get` +
    /// `Relaxed::fetch_add` — never `entry().or_insert_with()`. Mirrors
    /// `domain_blocked` discipline.
    pub list_blocked: DashMap<u8, AtomicU64>,
    /// Per-list 24h-rolling ring of BLOCK counts. Same pre-seeded
    /// discipline as `list_blocked` — the hot path is `get` +
    /// `HourlyRing::record`, never `entry().or_insert_with()`. Drives
    /// the Dashboard Top Lists (24h) card's ranking. Pre-seeded
    /// symmetrically at start.rs so missing bits silently drop on
    /// hot path (matches `list_blocked` semantics).
    pub list_blocked_hourly: DashMap<u8, HourlyRing>,
    /// O(1) size counters for the capacity-gated maps above. The hot-path
    /// insert gate reads these `Relaxed` instead of `DashMap::len()`, which
    /// read-locks and sums every shard — a permanent per-new-key tax once a
    /// map saturates (TRK-03). Each counter is adjusted by ±1 at every
    /// insert/evict site, so it is exact under serial use; concurrent
    /// inserts can transiently overshoot the *cap* (soft bound), not the
    /// counter. Re-synced from ground truth on the background prune / roll
    /// ticks as belt-and-braces.
    ///
    /// `devices_len` is `pub(crate)` so `snapshot::merge_into` maintains it
    /// on restore; the domain counters are only touched inside this module.
    pub(crate) devices_len: AtomicUsize,
    domain_queries_len: AtomicUsize,
    domain_blocked_len: AtomicUsize,
    domain_queries_hourly_len: AtomicUsize,
    domain_blocked_hourly_len: AtomicUsize,
    pub top_n: ArcSwap<TopNSnapshot>,
    pub time_series: TimeSeries,
    /// Soft cap on tracked devices. `pub(crate)` so `snapshot::merge_into`
    /// can enforce the same bound on restore that the hot path applies.
    pub(crate) max_devices: usize,
    pub config: TrackingConfig,
    /// Optional per-query file logger, swappable atomically so the daemon
    /// can attach / detach the writer on `handle_reload` without a restart
    /// (Sprint 38 QLP1). `None` when `query_log_enabled = false`; the fast
    /// `log_query_event` method reads the ArcSwap with a lock-free load
    /// and early-returns when the slot is empty, so the hot path pays one
    /// atomic read + branch when the feature is disabled.
    query_log: ArcSwap<Option<Arc<QueryLog>>>,
    /// Absolute path to the query log file, resolved at startup against the
    /// config directory. Wrapped in an `ArcSwap` so hot-reload can update
    /// it atomically together with `query_log` above. Exposed to read-side
    /// callers (IPC `query_logs` handler) so they don't re-resolve the raw
    /// relative string against the daemon's cwd (which is `/` under
    /// systemd).
    query_log_path: ArcSwap<Option<PathBuf>>,
    /// Hit-frequency tracker for cache-prefetch promotion (Sprint §4.4 P1).
    /// Phase 1/2 ships the data plane only; the set is observable via IPC
    /// but no DNS-side behaviour reads it yet. Default-disabled when built
    /// via `StatsEngine::new` — production callers pass a populated
    /// `PrefetchTrackerConfig` via `with_prefetch_config`.
    pub prefetch_tracker: Arc<HitTracker>,
}

/// Maximum entries in domain frequency maps before pruning.
const MAX_DOMAIN_FREQ_ENTRIES: usize = 10_000;

/// Entries sampled per over-cap device insert to pick an approximate-LRU
/// (stalest `last_seen`) eviction victim. Mirrors `security::bounded_map`'s
/// Redis-style sample-K (K=8): balances LRU fidelity against scan cost on the
/// insert-when-full slow path.
const DEVICE_EVICT_SAMPLE: usize = 8;

/// Seconds within which an observed device is considered "online now"
/// by Dashboard/TUI counters. Any `last_seen` within this window from
/// the current time counts toward the "online" total.
///
/// 60s aligns with the schedule re-evaluation tick in start.rs so the
/// operator sees a consistent view of who is active "right now".
pub const ONLINE_WINDOW_SECS: u64 = 60;

/// Immutable snapshot of a single observed device, produced by
/// `StatsEngine::list_observed_ips`. Contains everything the TUI
/// widget and IPC response need, already copied out so the caller
/// doesn't hold the DashMap shard lock.
#[derive(Debug, Clone)]
pub struct ObservedDevice {
    pub ip: IpAddr,
    /// Friendly name from `[[devices]]` if mapped, `"unknown"` otherwise.
    pub name: CompactString,
    /// Profile name applied to the most recent query from this IP.
    pub profile: CompactString,
    pub queries: u64,
    /// Queries received from this device since the start of the current
    /// calendar day (UTC). Resets every midnight. See
    /// `DeviceStats::queries_today` for the snapshot semantics.
    pub queries_today: u64,
    pub blocked: u64,
    /// Sum of the last 24 hours of BLOCKED queries for this device.
    /// Drives the Dashboard Top Devices (24h) card. 0 when no blocks
    /// landed in the last 24h. See
    /// `DeviceStats::hourly_blocked_last_24h_sum`.
    pub blocked_24h: u64,
    pub cache_hits: u64,
    /// Unix seconds, 0 if never (should not occur — inserts set it).
    pub last_seen: u64,
    /// Per-hour query counts for the last 24 hours, oldest-first.
    /// Drives the Devices tab side-card sparkline. Empty for snapshot
    /// callers that don't need the time series (kept opt-in to avoid
    /// the 24-element copy on the per-device-stats CLI path).
    pub hourly_queries: Vec<u64>,
}

impl ObservedDevice {
    /// True if `last_seen` is within `ONLINE_WINDOW_SECS` of `now`.
    /// `now` is passed in so callers can get a consistent snapshot
    /// across many devices without drifting timestamps.
    pub fn is_online(&self, now: u64) -> bool {
        now.saturating_sub(self.last_seen) <= ONLINE_WINDOW_SECS
    }
}

impl StatsEngine {
    /// Create a new engine from tracking config. The prefetch tracker is
    /// built from `PrefetchTrackerConfig::default()` (disabled) — this
    /// keeps tests cheap and pre-§4.4 callers behaviour-identical.
    /// Production code that wants a live tracker calls
    /// `with_prefetch_config`.
    pub fn new(config: &TrackingConfig) -> Self {
        Self::with_prefetch_config(config, &PrefetchTrackerConfig::default())
    }

    /// Create a new engine wired with a populated prefetch tracker.
    /// Sprint §4.4 P1 production constructor.
    pub fn with_prefetch_config(config: &TrackingConfig, prefetch: &PrefetchTrackerConfig) -> Self {
        Self {
            global: GlobalStats::new(),
            devices: DashMap::with_capacity(64),
            domain_queries: DashMap::with_capacity(1024),
            domain_blocked: DashMap::with_capacity(256),
            domain_queries_hourly: DashMap::with_capacity(1024),
            domain_blocked_hourly: DashMap::with_capacity(256),
            // Capacity 64 = the source bitmask ceiling; pre-seeding at
            // start.rs fills this in before traffic begins.
            list_blocked: DashMap::with_capacity(64),
            list_blocked_hourly: DashMap::with_capacity(64),
            devices_len: AtomicUsize::new(0),
            domain_queries_len: AtomicUsize::new(0),
            domain_blocked_len: AtomicUsize::new(0),
            domain_queries_hourly_len: AtomicUsize::new(0),
            domain_blocked_hourly_len: AtomicUsize::new(0),
            top_n: ArcSwap::from_pointee(TopNSnapshot::default()),
            time_series: TimeSeries::new(),
            max_devices: config.max_devices,
            config: config.clone(),
            query_log: ArcSwap::from_pointee(None),
            query_log_path: ArcSwap::from_pointee(None),
            prefetch_tracker: Arc::new(HitTracker::new(prefetch)),
        }
    }

    /// Attach a running `QueryLog` writer and memorise the resolved path.
    /// Takes `&self` (not `&mut self`) because the slots are `ArcSwap`:
    /// `handle_reload` can attach a writer at any time on an already-
    /// `Arc`-shared engine (Sprint 38 QLP1).
    ///
    /// After attachment, `log_query_event` forwards each entry to the
    /// background writer task; before attachment (or after `detach`) the
    /// method is a no-op.
    ///
    /// The `resolved_path` is the absolute path that the writer task
    /// actually opens — IPC read-side callers must use this, not the
    /// raw `config.query_log_path` string (which may be relative to the
    /// config dir, not the daemon's cwd).
    pub fn attach_query_log(&self, query_log: Arc<QueryLog>, resolved_path: PathBuf) {
        self.query_log.store(Arc::new(Some(query_log)));
        self.query_log_path.store(Arc::new(Some(resolved_path)));
    }

    /// Detach the currently-attached writer and return its handle so the
    /// caller can `.shutdown().await` it. Leaves the path slot cleared so
    /// subsequent reads see the reflective "logging disabled" state.
    ///
    /// Returns `None` when no writer is currently attached — safe to call
    /// unconditionally from a reload path that doesn't know the prior
    /// state.
    pub fn detach_query_log(&self) -> Option<Arc<QueryLog>> {
        // Clear the path slot first so a concurrent reader never observes
        // a path pointing at a writer that has already been unhooked.
        self.query_log_path.store(Arc::new(None));
        let old = self.query_log.swap(Arc::new(None));
        (*old).as_ref().cloned()
    }

    /// Resolved absolute path of the live query-log file, or `None` when
    /// logging is disabled. Cloned out of the `ArcSwap` so the caller
    /// doesn't hold the guard across later I/O.
    pub fn query_log_file_path(&self) -> Option<PathBuf> {
        let guard = self.query_log_path.load();
        (**guard).clone()
    }

    /// Snapshot of the query-log silent-drop counters (H-20). Returns
    /// `None` when no writer is attached so callers can render a
    /// "logging disabled" line instead of misleading zeros that imply
    /// "no drops observed". The lock-free `ArcSwap` load mirrors
    /// `query_log_file_path` — guard is dropped before returning.
    pub fn query_log_drop_counters(&self) -> Option<QueryLogDropSnapshot> {
        let guard = self.query_log.load();
        guard.as_ref().as_ref().map(|ql| ql.drop_counters())
    }

    /// Forward a per-query event to the file-based query log, if attached.
    /// No-op when the writer slot is empty, so the hot path pays one
    /// `ArcSwap::load` (~3 ns atomic relaxed read + Arc clone) plus a
    /// branch when the feature is disabled.
    ///
    /// Hot-path invariant: the `ArcSwap` guard is dropped BEFORE any
    /// further work (including the `.log` send). Holding a guard across
    /// a future `.await` or a long-running operation would pin the old
    /// `Arc<QueryLog>` value and defeat `detach_query_log`'s swap. Same
    /// discipline as `auth_error_for` in `socket_server.rs` (see
    /// `_docs/features/config_safety_v11.md` §8.3 pitfall 1).
    ///
    /// The sender uses `try_send` internally — if the channel is full,
    /// entries are dropped rather than blocking the DNS handler.
    #[inline]
    #[allow(clippy::too_many_arguments)]
    pub fn log_query_event(
        &self,
        client_ip: IpAddr,
        client_name: Option<&str>,
        domain: &str,
        query_type: &str,
        result: &'static str,
        blocked: bool,
        response_time_us: u64,
        cname_chain_via: Option<&str>,
        rewrote_from: Option<&str>,
    ) {
        // Sprint 38 QLP3: `log_mode` decides *before* we construct the
        // entry whether this query needs to be logged at all. This keeps
        // `BlockedOnly` and the `Sampled` allowed-path out of the
        // timestamp-format + `String::from(domain)` cost that dominates
        // a single entry's hot-path cost.
        //
        // engine-01 (rev-2606): gate on the `blocked` bool the decision
        // already carries — NOT a string compare on `result`. The hot
        // path sets blocked:true for content BLOCKs *and* security
        // refusals (REFUSED / RRL_DROP); matching only the literal
        // "BLOCKED" silently dropped every refusal from blocked-only
        // logs, exactly when the operator picked blocked-only to surface
        // attacks. `RRL_SLIP` is blocked:false and stays omitted.
        let is_blocked = blocked;
        match self.config.log_mode {
            LogMode::All => {}
            LogMode::BlockedOnly => {
                if !is_blocked {
                    return;
                }
            }
            LogMode::Sampled { allowed_rate } => {
                if !is_blocked && !sample_allowed(allowed_rate) {
                    return;
                }
            }
        }

        let guard = self.query_log.load();
        let Some(ql) = guard.as_ref() else {
            return;
        };
        let ql = ql.clone();
        drop(guard);

        let timestamp = time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default();
        ql.log(QueryLogEntry {
            timestamp,
            client_ip,
            client_name: client_name.map(|s| s.to_string()),
            domain: domain.to_string(),
            query_type: query_type.to_string(),
            result: result.to_string(),
            response_time_us,
            // §4.5 Sprint 2/2: populated by the two CNAME-chain-block call
            // sites in `dns/handler.rs`; `None` for every other outcome.
            cname_chain_via: cname_chain_via.map(|s| s.to_string()),
            // §4.12: populated by the post-filter rewrite hook in
            // `dns/handler.rs`; `None` on every query that did not rewrite.
            rewrote_from: rewrote_from.map(|s| s.to_string()),
        });
    }

    /// Record a completed query — called from the DNS handler hot path.
    ///
    /// All operations are atomic increments on existing entries.
    /// New client/domain entries use DashMap's shard-level insert (rare path).
    ///
    /// `record_type` lands in the `per_type` bucket counters on both the
    /// global stats and the device entry — see `query_type::TypeBucket`.
    /// All buckets are counted, including blocked and cache-hit queries,
    /// so the per-type distribution sums to `total_queries`.
    ///
    /// `block_list_bit` (Sprint B Dashboard v2) is `Some(bit)` only when
    /// the BLOCKED outcome is attributable to a single Tier 1 blocklist
    /// (`BlockSource::List(bit)`). Admin / rule / cname / IP blocks
    /// pass `None` — those don't pin to one list. The bit slot is
    /// pre-seeded at start.rs, so the hot path is a `get` + atomic
    /// add; bits not pre-seeded are silently ignored (no shard-lock).
    ///
    /// The 9-argument shape exceeds clippy's default threshold. The
    /// single production caller (`ForwardHandler::record_outcome`)
    /// already bundles these into `QueryDecision`, so adding a struct
    /// wrapper here would just renest the indirection on the hot path
    /// for no readability win.
    #[allow(clippy::too_many_arguments)]
    pub fn record_query(
        &self,
        client_ip: IpAddr,
        domain: &str,
        client_name: Option<&str>,
        client_profile: Option<&str>,
        record_type: RecordType,
        blocked: bool,
        cache_hit: bool,
        block_list_bit: Option<u8>,
    ) {
        let bucket = TypeBucket::classify(record_type) as usize;

        // Global counters
        self.global.total_queries.fetch_add(1, Ordering::Relaxed);
        self.global.per_type[bucket].fetch_add(1, Ordering::Relaxed);
        if blocked {
            self.global.total_blocked.fetch_add(1, Ordering::Relaxed);
            self.global.blocked_per_type[bucket].fetch_add(1, Ordering::Relaxed);
        }
        if cache_hit {
            self.global.total_cache_hits.fetch_add(1, Ordering::Relaxed);
        }

        // Per-device counters
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if let Some(entry) = self.devices.get(&client_ip) {
            // Fast path: device already tracked
            entry.queries.fetch_add(1, Ordering::Relaxed);
            entry.per_type[bucket].fetch_add(1, Ordering::Relaxed);
            if blocked {
                entry.blocked.fetch_add(1, Ordering::Relaxed);
                entry.blocked_per_type[bucket].fetch_add(1, Ordering::Relaxed);
                entry.record_hourly_blocked(now);
            }
            if cache_hit {
                entry.cache_hits.fetch_add(1, Ordering::Relaxed);
            }
            entry.last_seen.store(now, Ordering::Relaxed);
            // S44: drive the per-device hourly ring. One atomic load +
            // (in steady state) one atomic add. The hour-rollover
            // branch fires once per ticked hour, not per query.
            entry.record_hourly_query(now);
        } else if self.max_devices > 0 {
            // Slow path: IP not currently tracked and device tracking is
            // enabled. (`max_devices == 0` disables it — preserves the old
            // `len() < 0`-never-true semantics of never inserting, with no
            // wasted stats allocation.) Build the fresh row once, then insert
            // — evicting the approximately-stalest device first when the table
            // is at cap, so a saturated table self-heals (TRK-02) instead of
            // freezing and leaving new devices invisible until restart.
            let name = CompactString::from(client_name.unwrap_or("unknown"));
            let profile = CompactString::from(client_profile.unwrap_or("default"));
            let stats = DeviceStats::new(name, profile);
            stats.queries.store(1, Ordering::Relaxed);
            stats.per_type[bucket].store(1, Ordering::Relaxed);
            if blocked {
                stats.blocked.store(1, Ordering::Relaxed);
                stats.blocked_per_type[bucket].store(1, Ordering::Relaxed);
                stats.record_hourly_blocked(now);
            }
            if cache_hit {
                stats.cache_hits.store(1, Ordering::Relaxed);
            }
            stats.last_seen.store(now, Ordering::Relaxed);
            stats.record_hourly_query(now);
            // O(1) capacity gate (TRK-03): read the Relaxed counter, not
            // DashMap::len()'s all-shard sweep. At/over cap, evict the
            // approximately-stalest device first to make room (TRK-02).
            if self.devices_len.load(Ordering::Relaxed) >= self.max_devices {
                self.evict_stalest_device(client_ip);
            }
            // Another thread may have inserted between get() and here — only a
            // genuine Vacant insert bumps the counter, so the race can't
            // double-count. The loser's stats are dropped: one query's counts
            // lost, acceptable for stats (matches the prior or_insert).
            if let Entry::Vacant(e) = self.devices.entry(client_ip) {
                e.insert(stats);
                self.devices_len.fetch_add(1, Ordering::Relaxed);
            }
        }

        // Domain frequency. Pass the borrowed `&str` (DashMap lookups
        // accept `Borrow<str>`); the helpers build an owned CompactString
        // only when inserting a fresh entry, so the steady-state path
        // (domain already tracked) allocates nothing (hot-path zero-alloc).
        self.increment_domain_freq(&self.domain_queries, &self.domain_queries_len, domain);
        Self::record_hourly(
            &self.domain_queries_hourly,
            &self.domain_queries_hourly_len,
            domain,
            now,
        );
        if blocked {
            self.increment_domain_freq(&self.domain_blocked, &self.domain_blocked_len, domain);
            Self::record_hourly(
                &self.domain_blocked_hourly,
                &self.domain_blocked_hourly_len,
                domain,
                now,
            );
            // Sprint B Dashboard v2 — per-bit blocked counter. Pre-seeded
            // at start.rs so the hot path is `get` + `Relaxed::fetch_add`.
            // Bits not pre-seeded (anonymous overlay sources, future
            // legacy configs) are silently ignored — never lock a shard
            // at runtime.
            if let Some(bit) = block_list_bit {
                if let Some(counter) = self.list_blocked.get(&bit) {
                    counter.fetch_add(1, Ordering::Relaxed);
                }
                // Parallel 24h ring — same pre-seeded discipline. If a
                // bit isn't seeded, drop silently rather than locking
                // the shard. Pre-seed at start.rs keeps the two maps
                // symmetric.
                if let Some(ring) = self.list_blocked_hourly.get(&bit) {
                    ring.record(now);
                }
            }
        }

        // Time series — Sprint F: pass the already-classified bucket
        // so the per_type / blocked_per_type ring carries per-`TypeBucket`
        // counts. Drives `qtype_distribution_24h` on the dashboard.
        self.time_series.record(blocked, cache_hit, bucket);
    }

    /// Bump the negative-cache-hit counter. Called from the DNS handler's
    /// cache-hit branch when the cached entry represents NXDOMAIN or NODATA.
    /// Atomic-only — safe to call on the hot path.
    pub fn record_cache_negative_hit(&self) {
        self.global
            .total_cache_negative_hits
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Bump the security-refusal counter (rev-2606 engine-03). Called
    /// from `record_outcome` for the `REFUSED` / `RRL_DROP` outcomes.
    /// Those also carry `blocked:true` and so are counted in
    /// `total_blocked` as well; this keeps a content-block vs
    /// security-refusal breakdown available without changing the
    /// block-rate gauge. Atomic-only — safe on the hot path.
    #[inline]
    pub fn record_security_refusal(&self) {
        self.global
            .total_refused_security
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Notify the prefetch tracker that `domain` was just served from the
    /// positive cache. Called from the DNS handler's cache-hit branch.
    /// When the tracker is disabled (Phase 1 default) this is a single
    /// branch on a `bool` field — no allocation, no atomic increment.
    /// Sprint §4.4 P1 entry point.
    #[inline]
    pub fn record_cache_hit(&self, domain: &str) {
        if !self.prefetch_tracker.is_enabled() {
            return;
        }
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.prefetch_tracker.record_hit(domain, now_secs);
    }

    /// Evict the approximately-stalest device to free a slot when `devices`
    /// is at `max_devices` (TRK-02 self-healing). Samples up to
    /// `DEVICE_EVICT_SAMPLE` entries and removes the one with the smallest
    /// `last_seen`. The fast-path `last_seen.store(now)` keeps active devices
    /// fresh, so the victim is a genuinely idle device.
    ///
    /// Runs ONLY on the insert-when-full slow path, never on the steady-state
    /// per-query path. Mirrors
    /// `security::bounded_map::evict_approximate_oldest`.
    ///
    /// DashMap deadlock discipline: the victim key is collected and the
    /// iterator DROPPED before `remove`, so no shard reference is held across
    /// the mutation. Concurrent readers (`list_observed_ips`, snapshot
    /// `capture`) stay safe — the removal is a single-key op with no
    /// cross-shard reference held. `incoming` (the IP about to be inserted) is
    /// never chosen as the victim: it is not yet in the map, but the guard is
    /// cheap insurance against a concurrent insert of the same key.
    fn evict_stalest_device(&self, incoming: IpAddr) {
        // Scope the iteration so its shard read-locks are released before the
        // subsequent `remove` acquires a shard write-lock.
        let victim = {
            let mut oldest: Option<(IpAddr, u64)> = None;
            let mut scanned = 0usize;
            for entry in self.devices.iter() {
                let last_seen = entry.value().last_seen.load(Ordering::Relaxed);
                oldest = match oldest {
                    None => Some((*entry.key(), last_seen)),
                    Some((_, cur)) if last_seen < cur => Some((*entry.key(), last_seen)),
                    other => other,
                };
                scanned += 1;
                if scanned >= DEVICE_EVICT_SAMPLE {
                    break;
                }
            }
            oldest.map(|(k, _)| k)
        };
        if let Some(victim_ip) = victim {
            if victim_ip != incoming && self.devices.remove(&victim_ip).is_some() {
                self.devices_len.fetch_sub(1, Ordering::Relaxed);
            }
        }
    }

    /// Atomically increment a domain frequency counter.
    ///
    /// `size` is the map's O(1) sibling size counter (TRK-03): the capacity
    /// gate reads it `Relaxed` instead of `DashMap::len()`'s all-shard
    /// read-lock sweep. It is bumped only on a genuine `Vacant` insert, so a
    /// get-then-insert race between two threads for the same fresh domain
    /// counts once, not twice.
    fn increment_domain_freq(
        &self,
        map: &DashMap<CompactString, AtomicU64>,
        size: &AtomicUsize,
        domain: &str,
    ) {
        if let Some(entry) = map.get(domain) {
            entry.value().fetch_add(1, Ordering::Relaxed);
        } else if size.load(Ordering::Relaxed) < MAX_DOMAIN_FREQ_ENTRIES {
            match map.entry(CompactString::from(domain)) {
                // Lost the race — the fresh entry already exists. Just bump it.
                Entry::Occupied(e) => {
                    e.get().fetch_add(1, Ordering::Relaxed);
                }
                Entry::Vacant(e) => {
                    e.insert(AtomicU64::new(1));
                    size.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        // Over capacity: silently drop (pruning task will free space)
    }

    /// Record a domain's 24h-rolling ring entry. Mirrors
    /// `increment_domain_freq` shape: fast `get` path on existing
    /// entries, capacity-bounded insert (gated on the O(1) `size` counter,
    /// not `DashMap::len()`) for fresh entries. Over-capacity entries drop
    /// silently — `prune_hourly_map` reaps idle entries on the same 10s tick
    /// as `prune_domain_freq`.
    fn record_hourly(
        map: &DashMap<CompactString, HourlyRing>,
        size: &AtomicUsize,
        domain: &str,
        now: u64,
    ) {
        if let Some(entry) = map.get(domain) {
            entry.value().record(now);
        } else if size.load(Ordering::Relaxed) < MAX_DOMAIN_FREQ_ENTRIES {
            match map.entry(CompactString::from(domain)) {
                Entry::Occupied(e) => {
                    e.get().record(now);
                }
                Entry::Vacant(e) => {
                    e.insert(HourlyRing::default()).record(now);
                    size.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }

    /// Prune low-frequency entries from domain maps.
    /// Called periodically by the top-N background task.
    pub fn prune_domain_freq(&self) {
        prune_map(&self.domain_queries);
        // Re-sync the O(1) size counter from ground truth after the prune
        // frees entries — otherwise the counter stays pinned at cap and the
        // gate would drop every new domain forever (the exact freeze bug
        // TRK-03 fixes). Off the query path, so `.len()` is fine here.
        self.domain_queries_len
            .store(self.domain_queries.len(), Ordering::Relaxed);
        prune_map(&self.domain_blocked);
        self.domain_blocked_len
            .store(self.domain_blocked.len(), Ordering::Relaxed);
    }

    /// Prune idle-in-last-24h entries from the 24h-rolling rings.
    /// Mirrors `prune_domain_freq` cadence but uses `sum_last_24h > 0`
    /// as the retention predicate so the operator never sees a stale
    /// ring entry rank in Top-N 24h after its traffic has aged out.
    /// `now_secs` is passed in so caller can snapshot a single
    /// boundary for the prune + extract pair (top_n.rs).
    pub fn prune_hourly_domain_freq(&self, now_secs: u64) {
        prune_hourly_map(&self.domain_queries_hourly, now_secs);
        // Re-sync the O(1) size counter after the prune (see
        // `prune_domain_freq`). Off the query path.
        self.domain_queries_hourly_len
            .store(self.domain_queries_hourly.len(), Ordering::Relaxed);
        prune_hourly_map(&self.domain_blocked_hourly, now_secs);
        self.domain_blocked_hourly_len
            .store(self.domain_blocked_hourly.len(), Ordering::Relaxed);
    }

    /// Snapshot of every observed device (mapped + unmapped). Clones
    /// counters out of the `DashMap` so the caller doesn't hold any
    /// shard lock. Called from IPC `GetAllDevices` and the TUI dashboard
    /// poller — not hot-path, allocation is fine.
    ///
    /// The returned list includes any IP that has ever sent a query
    /// since startup (bounded by `max_devices`). Callers typically
    /// filter out stale entries via `ObservedDevice::is_online`.
    pub fn list_observed_ips(&self) -> Vec<ObservedDevice> {
        // Single timestamp for the whole iteration so every device's
        // today-rollover check sees the same boundary — avoids the
        // case where two devices, sampled milliseconds apart, disagree
        // about whether midnight has passed.
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.devices
            .iter()
            .map(|entry| ObservedDevice {
                ip: *entry.key(),
                name: entry.name.clone(),
                profile: entry.profile.clone(),
                queries: entry.queries.load(Ordering::Relaxed),
                queries_today: entry.queries_today(now_secs),
                blocked: entry.blocked.load(Ordering::Relaxed),
                blocked_24h: entry.hourly_blocked_last_24h_sum(now_secs),
                cache_hits: entry.cache_hits.load(Ordering::Relaxed),
                last_seen: entry.last_seen.load(Ordering::Relaxed),
                // 24-element snapshot — small allocation, mirrors the
                // ring's chronological order so the TUI's sparkline
                // can iterate left-to-right without re-mapping.
                hourly_queries: entry.hourly_queries_last_24h(now_secs),
            })
            .collect()
    }

    /// Roll every device's "today" baseline forward to `now_secs`'s UTC
    /// calendar day. Driven by the background snapshot task so the
    /// per-device `queries_today` anchor is seeded near real midnight
    /// even when no dashboard is polling — see
    /// [`DeviceStats::maybe_roll_day`] for why the read-path seed alone
    /// is not enough on a headless server. Cheap and NOT hot-path: one
    /// atomic load per device in the steady state (same day), a
    /// two-store roll at the boundary.
    pub fn roll_today_baselines(&self, now_secs: u64) {
        let today = now_secs / 86400;
        // Count devices during the existing sweep (no extra pass) and re-sync
        // the O(1) size counter from ground truth — belt-and-braces against
        // any drift accrued by concurrent insert/evict races on the hot path.
        // Off the query path (background snapshot tick), so exactness here is
        // free. Devices can now disappear between ticks (TRK-02 eviction);
        // this simply rolls whatever is currently present.
        let mut n = 0usize;
        for entry in self.devices.iter() {
            entry.value().maybe_roll_day(today);
            n += 1;
        }
        self.devices_len.store(n, Ordering::Relaxed);
    }

    /// Update a device's tracked name and profile in place.
    ///
    /// NOT currently wired into the reload path — no caller outside
    /// tests (hence `#[allow(dead_code)]`). Renamed / re-profiled devices
    /// therefore keep their stale name/profile in stats until restart;
    /// wiring this into reload is tracked as a follow-up
    /// (rev-2606 `s-rev2606-update-device-info-reload`).
    #[allow(dead_code)]
    pub fn update_device_info(&self, ip: IpAddr, name: &str, profile: &str) {
        if let Some(mut entry) = self.devices.get_mut(&ip) {
            entry.name = CompactString::from(name);
            entry.profile = CompactString::from(profile);
        }
    }
}

/// Sprint 38 QLP3: decide whether to log an allowed query under a
/// `Sampled { allowed_rate }` mode. Short-circuits at `rate <= 0.0`
/// and `rate >= 1.0` so the thread-local RNG step only runs when the
/// outcome is genuinely probabilistic.
///
/// Uses a per-thread xorshift64 PRNG (not the OS CSPRNG or the `rand`
/// crate) — this is a sampling decision, not a security boundary, so
/// quality of randomness is not material; hot-path cost is. Seeded
/// lazily from `SystemTime` nanos + thread id so parallel threads
/// don't produce identical streams.
#[inline]
fn sample_allowed(rate: f32) -> bool {
    if rate <= 0.0 {
        return false;
    }
    if rate >= 1.0 {
        return true;
    }
    thread_local! {
        static RNG_STATE: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    }
    RNG_STATE.with(|cell| {
        let mut x = cell.get();
        if x == 0 {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0xA5A5_A5A5_A5A5_A5A5);
            let tid_hash = {
                // Use the thread id's debug representation hashed — std
                // doesn't expose the underlying u64 publicly.
                use std::hash::{Hash, Hasher};
                let mut h = std::collections::hash_map::DefaultHasher::new();
                std::thread::current().id().hash(&mut h);
                h.finish()
            };
            x = nanos ^ tid_hash.rotate_left(17);
            if x == 0 {
                x = 0x9E37_79B9_7F4A_7C15;
            }
        }
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        cell.set(x);
        // Take 24 bits (bits 8..32 of the xorshift state, via the u32
        // cast then >> 8) as a f32 in [0, 1). Non-crypto by design —
        // uniform enough for allowed-query sampling.
        let frac = (x as u32 >> 8) as f32 / ((1u32 << 24) as f32);
        frac < rate
    })
}

/// Free room in a lifetime frequency map that has hit capacity.
///
/// First drops one-hit-wonders (`count <= 1`) — frees plenty in the
/// common case. But counts are monotonic, so once every survivor has
/// been queried ≥ 2 times the `retain` frees nothing, the map sits
/// pinned at cap forever, and `increment_domain_freq`'s miss branch then
/// drops every NEW domain: lifetime Top-N freezes for newcomers until
/// restart (rev-2606 engine-04). When that happens, decay — halve every
/// count and reap whatever falls to ≤ 1, so idle entries age out while
/// the popular Top-N keeps its relative order. The decay pass only runs
/// while still saturated, so it is self-limiting and cadence-independent
/// (steady-state pruning keeps its original single-pass cost).
pub fn prune_map(map: &DashMap<CompactString, AtomicU64>) {
    if map.len() <= MAX_DOMAIN_FREQ_ENTRIES {
        return;
    }
    map.retain(|_, count| count.load(Ordering::Relaxed) > 1);
    if map.len() > MAX_DOMAIN_FREQ_ENTRIES {
        map.retain(|_, count| {
            let decayed = count.load(Ordering::Relaxed) / 2;
            count.store(decayed, Ordering::Relaxed);
            decayed > 1
        });
    }
}

/// Drop ring entries that have summed to zero over the last 24h when
/// the map exceeds capacity. Keeps the per-entity 24h ring from
/// outliving its lifetime-map twin: a domain pruned from the lifetime
/// map but still holding ring entries would otherwise leak memory and
/// rank in Top-N 24h after its traffic genuinely aged out.
pub fn prune_hourly_map(map: &DashMap<CompactString, HourlyRing>, now_secs: u64) {
    if map.len() <= MAX_DOMAIN_FREQ_ENTRIES {
        return;
    }
    map.retain(|_, ring| ring.sum_last_24h(now_secs) > 0);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn test_config() -> TrackingConfig {
        TrackingConfig {
            max_devices: 3,
            ..TrackingConfig::default()
        }
    }

    /// `maybe_roll_day` rolls exactly once at a day boundary and is a
    /// no-op within the same day, so the baseline is stable across the
    /// many reads/sweeps that happen during a day.
    #[test]
    fn maybe_roll_day_is_idempotent_within_a_day() {
        let d = DeviceStats::new(CompactString::from("x"), CompactString::from("default"));
        d.queries.store(500, Ordering::Relaxed);
        let today: u64 = 20_641;

        // First call on a never-seeded device rolls: seeds baseline =
        // cumulative, stamps the day.
        assert!(d.maybe_roll_day(today));
        assert_eq!(d.queries_today_baseline.load(Ordering::Relaxed), 500);
        assert_eq!(d.today_day_index.load(Ordering::Relaxed), today);

        // Same day, more traffic: no roll, baseline preserved, today is
        // the real delta.
        d.queries.store(560, Ordering::Relaxed);
        assert!(!d.maybe_roll_day(today));
        assert_eq!(d.queries_today_baseline.load(Ordering::Relaxed), 500);
        assert_eq!(d.queries_today(today * 86_400 + 60), 60);

        // Next day: rolls again, baseline re-seeds, today resets to 0.
        assert!(d.maybe_roll_day(today + 1));
        assert_eq!(d.queries_today_baseline.load(Ordering::Relaxed), 560);
        assert_eq!(d.queries_today((today + 1) * 86_400 + 60), 0);
    }

    /// Regression for the Devices-tab "Q.TODAY all zero" bug: the
    /// background sweep must seed the baseline so the operator's *first*
    /// poll of the day returns the real same-day delta, not 0. Before
    /// the fix the baseline was seeded lazily on that first read, which
    /// collapsed today to 0 on a headless box no dashboard polled early.
    #[test]
    fn roll_today_baselines_seeds_before_first_read() {
        let engine = StatsEngine::new(&test_config());
        let ip: IpAddr = Ipv4Addr::new(10, 0, 0, 1).into();

        // Device restored from a prior-day snapshot: cumulative carried
        // over, baseline/day-index still at their never-seeded defaults.
        let stats = DeviceStats::new(CompactString::from("tv"), CompactString::from("default"));
        stats.queries.store(1_000, Ordering::Relaxed);
        engine.devices.insert(ip, stats);

        let today: u64 = 20_641;
        let now = today * 86_400 + 12 * 3_600; // noon UTC

        // Sweep runs (once per snapshot tick) and anchors the baseline.
        engine.roll_today_baselines(now);

        // Traffic arrives after the anchor.
        let dev = engine.devices.get(&ip).unwrap();
        dev.queries.fetch_add(7, Ordering::Relaxed);

        // First read of the day reports the real delta, not 0. Read with
        // the same controlled `now` (not `list_observed_ips`, which
        // samples the real clock and would make this a time-bomb test).
        assert_eq!(dev.queries_today(now), 7);
    }

    #[test]
    fn record_query_increments_global_counters() {
        let engine = StatsEngine::new(&test_config());
        let ip: IpAddr = Ipv4Addr::new(192, 168, 1, 1).into();

        engine.record_query(
            ip,
            "google.com",
            None,
            None,
            RecordType::A,
            false,
            false,
            None,
        );
        engine.record_query(
            ip,
            "ads.example.com",
            None,
            None,
            RecordType::A,
            true,
            false,
            None,
        );
        engine.record_query(
            ip,
            "google.com",
            None,
            None,
            RecordType::A,
            false,
            true,
            None,
        );

        assert_eq!(engine.global.total_queries.load(Ordering::Relaxed), 3);
        assert_eq!(engine.global.total_blocked.load(Ordering::Relaxed), 1);
        assert_eq!(engine.global.total_cache_hits.load(Ordering::Relaxed), 1);
        // §4.6 invariant: the per-type bucket distribution sums to
        // `total_queries`. Three A queries → bucket A == 3, others == 0.
        let per_type = engine.global.per_type_snapshot();
        assert_eq!(per_type.iter().sum::<u64>(), 3);
        assert_eq!(per_type[TypeBucket::A as usize], 3);
        for bucket in TypeBucket::ALL.iter().filter(|b| **b != TypeBucket::A) {
            assert_eq!(per_type[*bucket as usize], 0);
        }
        // Negative-hit counter is independent — record_query alone doesn't touch it.
        assert_eq!(
            engine
                .global
                .total_cache_negative_hits
                .load(Ordering::Relaxed),
            0
        );
    }

    /// §4.6 — per-type bucket counters fan out across both global and
    /// per-device stats, including blocked + cache-hit queries (the
    /// design doc's "count all queries into per-type" rule).
    #[test]
    fn record_query_fans_out_per_type_to_global_and_device() {
        let engine = StatsEngine::new(&test_config());
        let ip: IpAddr = Ipv4Addr::new(10, 0, 0, 1).into();

        engine.record_query(ip, "a.com", None, None, RecordType::A, false, false, None);
        engine.record_query(
            ip,
            "a6.com",
            None,
            None,
            RecordType::AAAA,
            false,
            false,
            None,
        );
        engine.record_query(
            ip,
            "spf.com",
            None,
            None,
            RecordType::TXT,
            true,
            false,
            None,
        );
        engine.record_query(
            ip,
            "rev.arpa",
            None,
            None,
            RecordType::PTR,
            false,
            true,
            None,
        );
        // CNAME folds into Other per design doc, alongside MX/ANY/CAA/etc.
        engine.record_query(
            ip,
            "alias.com",
            None,
            None,
            RecordType::CNAME,
            false,
            false,
            None,
        );

        let g = engine.global.per_type_snapshot();
        assert_eq!(g[TypeBucket::A as usize], 1);
        assert_eq!(g[TypeBucket::Aaaa as usize], 1);
        assert_eq!(g[TypeBucket::Txt as usize], 1);
        assert_eq!(g[TypeBucket::Ptr as usize], 1);
        assert_eq!(g[TypeBucket::Other as usize], 1, "CNAME → Other");
        assert_eq!(g.iter().sum::<u64>(), 5);

        // Per-device array tracks the same buckets independently.
        let device = engine.devices.get(&ip).unwrap();
        let d = device.per_type_snapshot();
        assert_eq!(d, g, "per-device matches global with a single client");
    }

    /// §4.6 — the slow-path device insert (first query from a new
    /// client) must seed the per-type bucket with `1`, not leave the
    /// fresh array at zero. Pin: regression of the slow-path branch
    /// would silently drop the bucket increment for the first query.
    #[test]
    fn record_query_first_query_seeds_device_per_type() {
        let engine = StatsEngine::new(&test_config());
        let ip: IpAddr = Ipv4Addr::new(10, 0, 0, 7).into();

        engine.record_query(
            ip,
            "a.com",
            None,
            None,
            RecordType::AAAA,
            false,
            false,
            None,
        );

        let device = engine.devices.get(&ip).unwrap();
        let d = device.per_type_snapshot();
        assert_eq!(d[TypeBucket::Aaaa as usize], 1);
        assert_eq!(d.iter().sum::<u64>(), 1);
    }

    #[test]
    fn stale_fallback_path_records_negative_cache_hit_and_query() {
        // L-2 (rev-2026-04-stats-stale-hit) regression pin: when the DNS
        // handler serves a stale entry because upstream failed, it must
        // (1) bump total_cache_hits via record_query(.., cache_hit=true)
        // and (2) bump total_cache_negative_hits via record_cache_negative_hit
        // when the stale entry is itself negative. This test pins the
        // exact StatsEngine surface the handler.rs upstream-failure branch
        // now drives — if the per-counter contract changes, the L-2 fix
        // becomes silently meaningless and operators see undercounted
        // cache hits during upstream flakiness.
        let engine = StatsEngine::new(&test_config());
        let ip: IpAddr = Ipv4Addr::new(10, 0, 0, 1).into();

        // Simulate a stale-fallback for a negative entry (NXDOMAIN/NODATA).
        engine.record_query(
            ip,
            "tracker.example.com",
            None,
            None,
            RecordType::A,
            false,
            true,
            None,
        );
        engine.record_cache_negative_hit();

        assert_eq!(engine.global.total_queries.load(Ordering::Relaxed), 1);
        assert_eq!(engine.global.total_cache_hits.load(Ordering::Relaxed), 1);
        assert_eq!(
            engine
                .global
                .total_cache_negative_hits
                .load(Ordering::Relaxed),
            1
        );
        // Stale-served queries are not blocked — they are queries that
        // upstream couldn't refresh. blocked counter must stay at 0.
        assert_eq!(engine.global.total_blocked.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn record_cache_negative_hit_is_independent_of_record_query() {
        let engine = StatsEngine::new(&test_config());

        engine.record_cache_negative_hit();
        engine.record_cache_negative_hit();

        assert_eq!(
            engine
                .global
                .total_cache_negative_hits
                .load(Ordering::Relaxed),
            2
        );
        // Calling record_cache_negative_hit does NOT bump total_queries or
        // total_cache_hits — those are record_query's responsibility. Keeping
        // the paths decoupled means the handler can compose them freely.
        assert_eq!(engine.global.total_queries.load(Ordering::Relaxed), 0);
        assert_eq!(engine.global.total_cache_hits.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn record_query_tracks_per_device() {
        let engine = StatsEngine::new(&test_config());
        let ip1: IpAddr = Ipv4Addr::new(192, 168, 1, 1).into();
        let ip2: IpAddr = Ipv4Addr::new(192, 168, 1, 2).into();

        engine.record_query(
            ip1,
            "a.com",
            Some("laptop"),
            Some("default"),
            RecordType::A,
            false,
            false,
            None,
        );
        engine.record_query(ip1, "b.com", None, None, RecordType::A, true, false, None);
        engine.record_query(
            ip2,
            "c.com",
            Some("tablet"),
            Some("kids"),
            RecordType::A,
            false,
            true,
            None,
        );

        assert_eq!(engine.devices.len(), 2);

        let c1 = engine.devices.get(&ip1).unwrap();
        assert_eq!(c1.queries.load(Ordering::Relaxed), 2);
        assert_eq!(c1.blocked.load(Ordering::Relaxed), 1);
        assert_eq!(c1.name.as_str(), "laptop");

        let c2 = engine.devices.get(&ip2).unwrap();
        assert_eq!(c2.queries.load(Ordering::Relaxed), 1);
        assert_eq!(c2.cache_hits.load(Ordering::Relaxed), 1);
        assert_eq!(c2.name.as_str(), "tablet");
        assert_eq!(c2.profile.as_str(), "kids");
    }

    #[test]
    fn max_devices_cap_enforced() {
        let engine = StatsEngine::new(&test_config()); // max_devices = 3
        for i in 0..5u8 {
            let ip: IpAddr = Ipv4Addr::new(10, 0, 0, i).into();
            engine.record_query(
                ip,
                "test.com",
                None,
                None,
                RecordType::A,
                false,
                false,
                None,
            );
        }
        assert_eq!(engine.devices.len(), 3);
    }

    /// TRK-02: a saturated `devices` table must self-heal — admit a new device
    /// by evicting the approximately-stalest (smallest `last_seen`) instead of
    /// freezing and leaving every new device invisible until restart (the
    /// IPv6-rotation-fills-the-cap failure mode).
    ///
    /// Deterministic because n_devices (3) <= `DEVICE_EVICT_SAMPLE` (8): the
    /// sample scans ALL entries, so it always picks the global-min `last_seen`.
    /// A future edit that fills a larger cap with >8 devices would make
    /// sample-of-N approximate — size any such fixture to the cap.
    #[test]
    fn devices_evicts_stalest_when_full() {
        let engine = StatsEngine::new(&test_config()); // max_devices = 3
        let ips: [IpAddr; 3] = [
            Ipv4Addr::new(10, 0, 0, 1).into(),
            Ipv4Addr::new(10, 0, 0, 2).into(),
            Ipv4Addr::new(10, 0, 0, 3).into(),
        ];
        for ip in ips {
            engine.record_query(
                ip,
                "seed.com",
                None,
                None,
                RecordType::A,
                false,
                false,
                None,
            );
        }
        assert_eq!(engine.devices.len(), 3, "table full at cap");

        // Backdate last_seen so ips[0] is the stalest, ips[2] the freshest.
        engine
            .devices
            .get(&ips[0])
            .unwrap()
            .last_seen
            .store(100, Ordering::Relaxed);
        engine
            .devices
            .get(&ips[1])
            .unwrap()
            .last_seen
            .store(300, Ordering::Relaxed);
        engine
            .devices
            .get(&ips[2])
            .unwrap()
            .last_seen
            .store(500, Ordering::Relaxed);

        // A query from a brand-new IP must be admitted, evicting the stalest.
        let new_ip: IpAddr = Ipv4Addr::new(10, 0, 0, 99).into();
        engine.record_query(
            new_ip,
            "new.com",
            None,
            None,
            RecordType::A,
            false,
            false,
            None,
        );

        assert_eq!(engine.devices.len(), 3, "still capped at max_devices");
        assert!(
            engine.devices.get(&new_ip).is_some(),
            "new device admitted (TRK-02 self-heal)"
        );
        assert!(
            engine.devices.get(&ips[0]).is_none(),
            "stalest (last_seen=100) evicted"
        );
        assert!(
            engine.devices.get(&ips[1]).is_some(),
            "fresher device retained"
        );
        assert!(
            engine.devices.get(&ips[2]).is_some(),
            "freshest device retained"
        );
        // The size counter stays consistent through the evict+insert (net 0).
        assert_eq!(
            engine.devices_len.load(Ordering::Relaxed),
            3,
            "counter tracks eviction"
        );
    }

    /// TRK-03: the O(1) size counters must exactly track their maps' `.len()`
    /// under serial use — every insert bumps by 1, and the hot-path gate
    /// reads the counter instead of `DashMap::len()`. `max_devices` is set
    /// high so device eviction never fires here (that path is covered by
    /// `devices_evicts_stalest_when_full`).
    #[test]
    fn size_counters_track_map_len_serial() {
        let config = TrackingConfig {
            max_devices: 1000,
            ..TrackingConfig::default()
        };
        let engine = StatsEngine::new(&config);
        for i in 0..60u8 {
            let ip: IpAddr = Ipv4Addr::new(10, 0, 0, i).into();
            engine.record_query(
                ip,
                &format!("domain{i}.example"),
                None,
                None,
                RecordType::A,
                i % 3 == 0, // ~1/3 blocked → exercises the blocked-only maps
                false,
                None,
            );
        }
        // Each counter equals its map's true length, exactly (serial use).
        assert_eq!(
            engine.devices_len.load(Ordering::Relaxed),
            engine.devices.len(),
            "devices_len"
        );
        assert_eq!(
            engine.domain_queries_len.load(Ordering::Relaxed),
            engine.domain_queries.len(),
            "domain_queries_len"
        );
        assert_eq!(
            engine.domain_blocked_len.load(Ordering::Relaxed),
            engine.domain_blocked.len(),
            "domain_blocked_len"
        );
        assert_eq!(
            engine.domain_queries_hourly_len.load(Ordering::Relaxed),
            engine.domain_queries_hourly.len(),
            "domain_queries_hourly_len"
        );
        assert_eq!(
            engine.domain_blocked_hourly_len.load(Ordering::Relaxed),
            engine.domain_blocked_hourly.len(),
            "domain_blocked_hourly_len"
        );
        // Sanity: the blocked maps are a strict, nonempty subset of queries.
        assert!(!engine.domain_blocked.is_empty());
        assert!(engine.domain_blocked.len() < engine.domain_queries.len());
    }

    /// TRK-03: `prune_domain_freq` must re-sync the size counter from ground
    /// truth. A counter left pinned at cap after a prune would make the gate
    /// drop every new domain forever (the freeze bug). Here the counter is
    /// deliberately desynced high; the prune tick corrects it to the real
    /// map length.
    #[test]
    fn prune_domain_freq_resyncs_size_counter() {
        let engine = StatsEngine::new(&test_config());
        engine
            .domain_queries
            .insert(CompactString::from("a.com"), AtomicU64::new(5));
        engine
            .domain_queries
            .insert(CompactString::from("b.com"), AtomicU64::new(5));
        // Simulate drift: counter claims the map is saturated.
        engine.domain_queries_len.store(9_999, Ordering::Relaxed);

        engine.prune_domain_freq();

        // Map is under MAX_DOMAIN_FREQ_ENTRIES so nothing decays; the counter
        // is simply re-synced to the true length (2).
        assert_eq!(engine.domain_queries_len.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn domain_frequency_tracked() {
        let engine = StatsEngine::new(&test_config());
        let ip: IpAddr = Ipv4Addr::new(10, 0, 0, 1).into();

        engine.record_query(
            ip,
            "google.com",
            None,
            None,
            RecordType::A,
            false,
            false,
            None,
        );
        engine.record_query(
            ip,
            "google.com",
            None,
            None,
            RecordType::A,
            false,
            false,
            None,
        );
        engine.record_query(ip, "ads.com", None, None, RecordType::A, true, false, None);

        assert_eq!(
            engine
                .domain_queries
                .get("google.com")
                .unwrap()
                .load(Ordering::Relaxed),
            2
        );
        assert_eq!(
            engine
                .domain_queries
                .get("ads.com")
                .unwrap()
                .load(Ordering::Relaxed),
            1
        );
        assert_eq!(
            engine
                .domain_blocked
                .get("ads.com")
                .unwrap()
                .load(Ordering::Relaxed),
            1
        );
        assert!(engine.domain_blocked.get("google.com").is_none());
    }

    #[test]
    fn prune_removes_low_frequency() {
        let engine = StatsEngine::new(&test_config());
        let ip: IpAddr = Ipv4Addr::new(10, 0, 0, 1).into();

        // Add entries — "popular.com" gets 5 hits, "rare.com" gets 1
        for _ in 0..5 {
            engine.record_query(
                ip,
                "popular.com",
                None,
                None,
                RecordType::A,
                false,
                false,
                None,
            );
        }
        engine.record_query(
            ip,
            "rare.com",
            None,
            None,
            RecordType::A,
            false,
            false,
            None,
        );

        // Force prune (normally only runs when over capacity)
        engine
            .domain_queries
            .retain(|_, count| count.load(Ordering::Relaxed) > 1);

        assert!(engine.domain_queries.get("popular.com").is_some());
        assert!(engine.domain_queries.get("rare.com").is_none());
    }

    #[test]
    fn update_device_info() {
        let engine = StatsEngine::new(&test_config());
        let ip: IpAddr = Ipv4Addr::new(192, 168, 1, 1).into();

        engine.record_query(
            ip,
            "test.com",
            Some("old-name"),
            Some("old-profile"),
            RecordType::A,
            false,
            false,
            None,
        );
        engine.update_device_info(ip, "new-name", "new-profile");

        let entry = engine.devices.get(&ip).unwrap();
        assert_eq!(entry.name.as_str(), "new-name");
        assert_eq!(entry.profile.as_str(), "new-profile");
    }

    #[test]
    fn last_seen_timestamp_set() {
        let engine = StatsEngine::new(&test_config());
        let ip: IpAddr = Ipv4Addr::new(10, 0, 0, 1).into();

        engine.record_query(
            ip,
            "test.com",
            None,
            None,
            RecordType::A,
            false,
            false,
            None,
        );

        let entry = engine.devices.get(&ip).unwrap();
        let ts = entry.last_seen.load(Ordering::Relaxed);
        // Should be a recent unix timestamp (> 2024-01-01)
        assert!(ts > 1_704_067_200);
    }

    // --- list_observed_ips (Sprint 22) ---

    #[test]
    fn list_observed_ips_empty_before_any_query() {
        let engine = StatsEngine::new(&test_config());
        assert!(engine.list_observed_ips().is_empty());
    }

    #[test]
    fn list_observed_ips_snapshots_counters() {
        let engine = StatsEngine::new(&test_config());
        let mapped: IpAddr = Ipv4Addr::new(192, 168, 1, 42).into();
        let unmapped: IpAddr = Ipv4Addr::new(10, 0, 0, 99).into();

        // Mapped client with a configured name+profile, 3 queries (1 blocked, 1 cache hit)
        engine.record_query(
            mapped,
            "good.com",
            Some("sam-ipad"),
            Some("kids"),
            RecordType::A,
            false,
            false,
            None,
        );
        engine.record_query(
            mapped,
            "ads.example",
            Some("sam-ipad"),
            Some("kids"),
            RecordType::A,
            true,
            false,
            None,
        );
        engine.record_query(
            mapped,
            "good.com",
            Some("sam-ipad"),
            Some("kids"),
            RecordType::A,
            false,
            true,
            None,
        );

        // Unmapped client: no name/profile → defaults to "unknown"/"default"
        engine.record_query(
            unmapped,
            "random.example",
            None,
            None,
            RecordType::A,
            false,
            false,
            None,
        );

        let mut observed = engine.list_observed_ips();
        observed.sort_by_key(|c| c.ip);

        assert_eq!(observed.len(), 2);

        let unmapped_entry = observed.iter().find(|c| c.ip == unmapped).unwrap();
        assert_eq!(unmapped_entry.name.as_str(), "unknown");
        assert_eq!(unmapped_entry.profile.as_str(), "default");
        assert_eq!(unmapped_entry.queries, 1);
        assert_eq!(unmapped_entry.blocked, 0);
        assert!(unmapped_entry.last_seen > 1_704_067_200);

        let mapped_entry = observed.iter().find(|c| c.ip == mapped).unwrap();
        assert_eq!(mapped_entry.name.as_str(), "sam-ipad");
        assert_eq!(mapped_entry.profile.as_str(), "kids");
        assert_eq!(mapped_entry.queries, 3);
        assert_eq!(mapped_entry.blocked, 1);
        assert_eq!(mapped_entry.cache_hits, 1);
    }

    #[test]
    fn observed_device_is_online_within_window() {
        let now = 1_000_000u64;
        let device = ObservedDevice {
            ip: Ipv4Addr::new(10, 0, 0, 1).into(),
            name: CompactString::from("test"),
            profile: CompactString::from("default"),
            queries: 1,
            queries_today: 1,
            blocked: 0,
            blocked_24h: 0,
            cache_hits: 0,
            last_seen: now - 30, // 30s ago: within 60s window
            hourly_queries: Vec::new(),
        };
        assert!(device.is_online(now));

        let stale = ObservedDevice {
            last_seen: now - 120, // 120s ago: outside window
            ..device.clone()
        };
        assert!(!stale.is_online(now));

        // Boundary: exactly 60s ago is still online
        let boundary = ObservedDevice {
            last_seen: now - ONLINE_WINDOW_SECS,
            ..device.clone()
        };
        assert!(boundary.is_online(now));
    }

    /// When no QueryLog is attached, `log_query_event` is a no-op — no panic,
    /// no side-effects, and calling it does not touch the global counters
    /// (those are still the job of `record_query`).
    #[test]
    fn log_query_event_without_log_is_noop() {
        let engine = StatsEngine::new(&test_config());
        let ip: IpAddr = Ipv4Addr::new(10, 0, 0, 1).into();

        engine.log_query_event(
            ip,
            Some("pc"),
            "google.com",
            "A",
            "ALLOWED",
            false,
            1234,
            None,
            None,
        );

        assert_eq!(engine.global.total_queries.load(Ordering::Relaxed), 0);
        assert_eq!(engine.devices.len(), 0);
    }

    /// With a QueryLog attached, events are forwarded to the writer and end
    /// up on disk. The writer is async, so this test spins up a tokio runtime
    /// and awaits the writer's `shutdown()` (which flushes pending entries).
    #[tokio::test]
    async fn log_query_event_with_log_writes_to_disk() {
        use std::sync::Arc;

        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("query.log");
        let ql = Arc::new(crate::tracking::query_log::QueryLog::start(
            log_path.clone(),
            1024 * 1024,
            3,
            7,
        ));

        let engine = StatsEngine::new(&test_config());
        engine.attach_query_log(ql.clone(), log_path.clone());

        let ip: IpAddr = Ipv4Addr::new(10, 0, 0, 2).into();
        engine.log_query_event(
            ip,
            Some("laptop"),
            "ads.example",
            "A",
            "BLOCKED",
            true,
            500,
            None,
            None,
        );
        engine.log_query_event(
            ip,
            None,
            "google.com",
            "AAAA",
            "ALLOWED",
            false,
            1200,
            None,
            None,
        );

        // Drop the engine so the ArcSwap holding its clone of `ql` is
        // released; the test's `ql` is then the only Arc and `shutdown()`
        // closes the channel cleanly.
        drop(engine);
        Arc::try_unwrap(ql)
            .ok()
            .expect("only one Arc should remain")
            .shutdown()
            .await;

        let content = std::fs::read_to_string(&log_path).unwrap();
        assert!(content.contains("ads.example"));
        assert!(content.contains("BLOCKED"));
        assert!(content.contains("google.com"));
        assert!(content.contains("ALLOWED"));
        assert!(content.contains("laptop"));
    }

    /// §4.5 Sprint 2/2: when the DNS handler hits the cache-hit re-check
    /// branch and `walk_response` returns `Verdict::Block`, it threads
    /// the offending hop into `log_query_event(...)` as the new
    /// `cname_chain_via` arg. The Query Log JSONL row carries the same
    /// value so the TUI can render the badge.
    #[tokio::test]
    async fn log_query_event_with_cname_chain_via_writes_field_to_disk() {
        use std::sync::Arc;

        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("query.log");
        let ql = Arc::new(crate::tracking::query_log::QueryLog::start(
            log_path.clone(),
            1024 * 1024,
            3,
            7,
        ));
        let engine = StatsEngine::new(&test_config());
        engine.attach_query_log(ql.clone(), log_path.clone());
        let ip: IpAddr = Ipv4Addr::new(10, 0, 0, 7).into();

        engine.log_query_event(
            ip,
            Some("phone"),
            "apex.example.com",
            "A",
            "BLOCKED",
            true,
            999,
            Some("offending.tracker.example"),
            None,
        );

        drop(engine);
        Arc::try_unwrap(ql)
            .ok()
            .expect("only one Arc should remain")
            .shutdown()
            .await;

        let content = std::fs::read_to_string(&log_path).unwrap();
        assert!(content.contains("\"cname_chain_via\":\"offending.tracker.example\""));
        assert!(content.contains("apex.example.com"));
        assert!(content.contains("BLOCKED"));
    }

    /// §4.12 — when the rewrite hook fires, `log_query_event` receives
    /// `rewrote_from = Some(original_qname)`. The Query Log JSONL row
    /// must carry both `domain` (rewritten) and `rewrote_from` (original)
    /// so audit grep on either side surfaces the migration trail.
    #[tokio::test]
    async fn log_query_event_with_rewrote_from_writes_field_to_disk() {
        use std::sync::Arc;

        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("query.log");
        let ql = Arc::new(crate::tracking::query_log::QueryLog::start(
            log_path.clone(),
            1024 * 1024,
            3,
            7,
        ));
        let engine = StatsEngine::new(&test_config());
        engine.attach_query_log(ql.clone(), log_path.clone());
        let ip: IpAddr = Ipv4Addr::new(10, 0, 0, 9).into();

        engine.log_query_event(
            ip,
            Some("laptop"),
            "api.new-corp.example-int",
            "A",
            "ALLOWED",
            false,
            420,
            None,
            Some("api.old-corp.example-int"),
        );

        drop(engine);
        Arc::try_unwrap(ql)
            .ok()
            .expect("only one Arc should remain")
            .shutdown()
            .await;

        let content = std::fs::read_to_string(&log_path).unwrap();
        assert!(
            content.contains("\"rewrote_from\":\"api.old-corp.example-int\""),
            "expected rewrote_from on disk, got: {content}"
        );
        assert!(content.contains("\"domain\":\"api.new-corp.example-int\""));
        // cname_chain_via stays absent (we passed None and serde-skips):
        assert!(!content.contains("cname_chain_via"));
    }

    /// §4.5 Sprint 2/2: a non-CNAME outcome calls `log_query_event`
    /// with `cname_chain_via = None`. The serialised row must NOT
    /// surface a spurious `cname_chain_via: null` line — same byte
    /// shape as pre-S4.5-P2 entries.
    #[tokio::test]
    async fn log_query_event_without_cname_chain_via_omits_field() {
        use std::sync::Arc;

        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("query.log");
        let ql = Arc::new(crate::tracking::query_log::QueryLog::start(
            log_path.clone(),
            1024 * 1024,
            3,
            7,
        ));
        let engine = StatsEngine::new(&test_config());
        engine.attach_query_log(ql.clone(), log_path.clone());
        let ip: IpAddr = Ipv4Addr::new(10, 0, 0, 8).into();

        engine.log_query_event(
            ip,
            None,
            "google.com",
            "A",
            "ALLOWED",
            false,
            100,
            None,
            None,
        );

        drop(engine);
        Arc::try_unwrap(ql)
            .ok()
            .expect("only one Arc should remain")
            .shutdown()
            .await;

        let content = std::fs::read_to_string(&log_path).unwrap();
        assert!(content.contains("google.com"));
        assert!(
            !content.contains("cname_chain_via"),
            "field must be skipped when None — got: {content}"
        );
    }

    /// Sprint 38 QLP1: `attach_query_log` fills both slots, `detach_query_log`
    /// clears them and hands back the writer handle so the caller can
    /// `.shutdown().await` it. Path slot tracks the writer slot exactly.
    #[tokio::test]
    async fn engine_attach_then_detach_leaves_slot_none() {
        use std::sync::Arc;

        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("query.log");
        let ql = Arc::new(crate::tracking::query_log::QueryLog::start(
            log_path.clone(),
            1024 * 1024,
            3,
            7,
        ));

        let engine = StatsEngine::new(&test_config());
        assert!(engine.query_log_file_path().is_none());

        engine.attach_query_log(ql.clone(), log_path.clone());
        assert_eq!(engine.query_log_file_path(), Some(log_path.clone()));

        let detached = engine.detach_query_log();
        assert!(detached.is_some(), "detach returned the writer handle");
        assert!(
            engine.query_log_file_path().is_none(),
            "path slot cleared after detach"
        );

        // Both the outer `ql` in the test and the `detached` Arc need to be
        // dropped before shutdown() can take sole ownership of the writer.
        drop(detached);
        Arc::try_unwrap(ql)
            .ok()
            .expect("only one Arc should remain after detach")
            .shutdown()
            .await;
    }

    /// Sprint 38 QLP1: a detached engine (post-`detach_query_log` or never
    /// attached) silently drops events — no panic, no send attempt, no
    /// file I/O.
    #[test]
    fn log_query_event_is_noop_when_detached() {
        let engine = StatsEngine::new(&test_config());
        // Never attached — should no-op.
        let ip: IpAddr = Ipv4Addr::new(10, 0, 0, 1).into();
        engine.log_query_event(
            ip,
            Some("pc"),
            "google.com",
            "A",
            "ALLOWED",
            false,
            1234,
            None,
            None,
        );

        // Explicitly detach (even though nothing was attached) — still no-op.
        assert!(engine.detach_query_log().is_none());
        engine.log_query_event(
            ip,
            Some("pc"),
            "google.com",
            "A",
            "ALLOWED",
            false,
            1234,
            None,
            None,
        );

        assert!(engine.query_log_file_path().is_none());
        assert_eq!(engine.global.total_queries.load(Ordering::Relaxed), 0);
    }

    /// Sprint 38 QLP1: detaching then re-attaching a fresh writer against
    /// the same path preserves the on-disk file — entries from both
    /// attachments land in the same log in order. Simulates the
    /// `query_log_enabled=true → false → true` toggle sequence that a
    /// live `warden reload` drives.
    #[tokio::test]
    async fn engine_hot_reattach_preserves_file() {
        use std::sync::Arc;

        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("query.log");
        let ip: IpAddr = Ipv4Addr::new(10, 0, 0, 3).into();

        let engine = StatsEngine::new(&test_config());

        // First attachment: write 2 entries.
        let ql1 = Arc::new(crate::tracking::query_log::QueryLog::start(
            log_path.clone(),
            1024 * 1024,
            3,
            7,
        ));
        engine.attach_query_log(ql1.clone(), log_path.clone());
        engine.log_query_event(
            ip,
            None,
            "first-a.example",
            "A",
            "ALLOWED",
            false,
            100,
            None,
            None,
        );
        engine.log_query_event(
            ip,
            None,
            "first-b.example",
            "A",
            "BLOCKED",
            true,
            200,
            None,
            None,
        );

        // Detach: drop the engine's clone, then await the writer's flush.
        let detached = engine
            .detach_query_log()
            .expect("detach returned the writer handle");
        drop(detached);
        Arc::try_unwrap(ql1)
            .ok()
            .expect("only one Arc should remain after detach")
            .shutdown()
            .await;

        // Second attachment on the SAME path: file should be preserved
        // (OpenOptions::append in the writer), not truncated.
        let ql2 = Arc::new(crate::tracking::query_log::QueryLog::start(
            log_path.clone(),
            1024 * 1024,
            3,
            7,
        ));
        engine.attach_query_log(ql2.clone(), log_path.clone());
        engine.log_query_event(
            ip,
            None,
            "second-a.example",
            "A",
            "ALLOWED",
            false,
            300,
            None,
            None,
        );
        engine.log_query_event(
            ip,
            None,
            "second-b.example",
            "A",
            "BLOCKED",
            true,
            400,
            None,
            None,
        );

        // Drop the engine so the second writer is released cleanly.
        drop(engine);
        Arc::try_unwrap(ql2)
            .ok()
            .expect("only one Arc should remain")
            .shutdown()
            .await;

        let content = std::fs::read_to_string(&log_path).unwrap();
        assert!(
            content.contains("first-a.example"),
            "first attachment entries preserved"
        );
        assert!(content.contains("first-b.example"));
        assert!(
            content.contains("second-a.example"),
            "second attachment appended"
        );
        assert!(content.contains("second-b.example"));
        let first_a = content.find("first-a.example").unwrap();
        let second_a = content.find("second-a.example").unwrap();
        assert!(first_a < second_a, "first attachment writes precede second");
    }

    // ── Sprint 38 QLP3: log_mode filtering ──────────────────────

    /// Build an engine configured with a given `log_mode`, then collect
    /// the entries that made it into the attached writer's file. Shared
    /// by the four `log_mode` filter-behaviour tests below so each one
    /// stays short.
    async fn run_log_mode_filter(
        mode: LogMode,
        events: &[(&str, &str)],
    ) -> Vec<crate::tracking::query_log::QueryLogEntry> {
        use std::sync::Arc;
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("query.log");
        let ql = Arc::new(crate::tracking::query_log::QueryLog::start(
            log_path.clone(),
            1024 * 1024,
            3,
            7,
        ));

        let mut cfg = test_config();
        cfg.log_mode = mode;
        let engine = StatsEngine::new(&cfg);
        engine.attach_query_log(ql.clone(), log_path.clone());

        let ip: IpAddr = Ipv4Addr::new(10, 0, 0, 9).into();
        for (domain, result) in events {
            // &'static str is required by log_query_event; these tests
            // pass a finite set of string literals via a match. The
            // `blocked` bool mirrors the handler's real assignment
            // (content blocks + security refusals are blocked:true;
            // RRL_SLIP and allowed are blocked:false).
            let (result_static, blocked): (&'static str, bool) = match *result {
                "BLOCKED" => ("BLOCKED", true),
                "REFUSED" => ("REFUSED", true),
                "RRL_DROP" => ("RRL_DROP", true),
                "RRL_SLIP" => ("RRL_SLIP", false),
                "ALLOWED" => ("ALLOWED", false),
                _ => panic!("unexpected result tag: {result}"),
            };
            engine.log_query_event(
                ip,
                None,
                domain,
                "A",
                result_static,
                blocked,
                100,
                None,
                None,
            );
        }

        drop(engine);
        Arc::try_unwrap(ql)
            .ok()
            .expect("only one Arc should remain")
            .shutdown()
            .await;

        std::fs::read_to_string(&log_path)
            .unwrap_or_default()
            .lines()
            .filter_map(|line| serde_json::from_str(line).ok())
            .collect()
    }

    #[tokio::test]
    async fn log_query_event_skips_allowed_when_blocked_only() {
        let entries = run_log_mode_filter(
            LogMode::BlockedOnly,
            &[
                ("a.example", "ALLOWED"),
                ("b.example", "ALLOWED"),
                ("c.example", "BLOCKED"),
            ],
        )
        .await;
        assert_eq!(
            entries.len(),
            1,
            "only blocked entries should make it through"
        );
        assert_eq!(entries[0].domain, "c.example");
    }

    #[tokio::test]
    async fn log_query_event_always_logs_blocked_when_blocked_only() {
        let entries = run_log_mode_filter(
            LogMode::BlockedOnly,
            &[
                ("b1.example", "BLOCKED"),
                ("b2.example", "BLOCKED"),
                ("b3.example", "BLOCKED"),
            ],
        )
        .await;
        assert_eq!(entries.len(), 3, "blocked entries always pass BlockedOnly");
    }

    /// engine-01 (rev-2606): the security refusals introduced by 9f60205
    /// (`REFUSED`, `RRL_DROP`) carry blocked:true and MUST reach the
    /// blocked-only log — the operator who picks blocked-only does so
    /// precisely to surface attack volume. `RRL_SLIP` (blocked:false) is
    /// a TC-retry hint, not a refusal, so it stays omitted like ALLOWED.
    /// Pre-fix the gate compared `result == "BLOCKED"`, so every refusal
    /// was silently dropped under the Pi/privacy-recommended default.
    #[tokio::test]
    async fn log_query_event_logs_security_refusals_when_blocked_only() {
        let entries = run_log_mode_filter(
            LogMode::BlockedOnly,
            &[
                ("refused.example", "REFUSED"),
                ("rrldrop.example", "RRL_DROP"),
                ("slip.example", "RRL_SLIP"),
                ("allowed.example", "ALLOWED"),
                ("blocked.example", "BLOCKED"),
            ],
        )
        .await;
        let domains: Vec<&str> = entries.iter().map(|e| e.domain.as_str()).collect();
        assert!(
            domains.contains(&"refused.example"),
            "REFUSED must reach the blocked-only log"
        );
        assert!(
            domains.contains(&"rrldrop.example"),
            "RRL_DROP must reach the blocked-only log"
        );
        assert!(domains.contains(&"blocked.example"));
        assert!(
            !domains.contains(&"slip.example"),
            "RRL_SLIP (blocked:false) stays omitted under blocked-only"
        );
        assert!(
            !domains.contains(&"allowed.example"),
            "ALLOWED stays omitted under blocked-only"
        );
        assert_eq!(entries.len(), 3);
    }

    #[tokio::test]
    async fn log_query_event_samples_allowed_at_configured_rate() {
        // rate = 0.0: blocked stays, allowed drops entirely.
        let deterministic_off = run_log_mode_filter(
            LogMode::Sampled { allowed_rate: 0.0 },
            &[
                ("a1.example", "ALLOWED"),
                ("a2.example", "ALLOWED"),
                ("b1.example", "BLOCKED"),
            ],
        )
        .await;
        assert_eq!(deterministic_off.len(), 1);
        assert_eq!(deterministic_off[0].domain, "b1.example");

        // rate = 1.0: allowed always passes through.
        let deterministic_on = run_log_mode_filter(
            LogMode::Sampled { allowed_rate: 1.0 },
            &[("a1.example", "ALLOWED"), ("a2.example", "ALLOWED")],
        )
        .await;
        assert_eq!(deterministic_on.len(), 2);

        // rate = 0.5: statistical sanity over 2000 allowed events.
        // Tolerate ±20% slack (wide enough that the test is not flaky
        // even with a fast xorshift PRNG that only has u64 state).
        use std::sync::Arc;
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("query.log");
        let ql = Arc::new(crate::tracking::query_log::QueryLog::start(
            log_path.clone(),
            4 * 1024 * 1024,
            3,
            7,
        ));
        let mut cfg = test_config();
        cfg.log_mode = LogMode::Sampled { allowed_rate: 0.5 };
        let engine = StatsEngine::new(&cfg);
        engine.attach_query_log(ql.clone(), log_path.clone());
        let ip: IpAddr = Ipv4Addr::new(10, 0, 0, 10).into();
        for i in 0..2000u32 {
            engine.log_query_event(
                ip,
                None,
                &format!("a{i}.example"),
                "A",
                "ALLOWED",
                false,
                100,
                None,
                None,
            );
        }
        drop(engine);
        Arc::try_unwrap(ql)
            .ok()
            .expect("only one Arc should remain")
            .shutdown()
            .await;
        let kept = std::fs::read_to_string(&log_path)
            .unwrap_or_default()
            .lines()
            .count();
        assert!(
            (800..=1200).contains(&kept),
            "at rate=0.5 we should keep ~1000 of 2000 allowed events, got {kept}"
        );
    }

    // ── Sprint 38 QLP3: TrackingConfig defaults ─────────────────

    #[test]
    fn tracking_config_default_retention_days_is_seven() {
        assert_eq!(TrackingConfig::default().retention_days, 7);
    }

    #[test]
    fn tracking_config_default_log_mode_is_all() {
        assert!(matches!(TrackingConfig::default().log_mode, LogMode::All));
    }

    /// Closes the Sprint 37 QL3 known gap: a partial `[tracking]`
    /// section that omits `query_log_enabled` must pick up the new
    /// `true` default via the named default fn (QLP3).
    #[test]
    fn partial_tracking_section_picks_up_new_query_log_enabled_default() {
        let src = r#"
enabled = true
"#;
        let cfg: TrackingConfig = toml::from_str(src).unwrap();
        assert!(
            cfg.query_log_enabled,
            "named default kicks in on partial section"
        );
        assert_eq!(cfg.retention_days, 7);
        assert!(matches!(cfg.log_mode, LogMode::All));
    }

    /// Sprint B Dashboard v2 — a `record_query` with
    /// `block_list_bit = Some(bit)` increments only the slot for
    /// that bit. Pre-seeding mirrors the start.rs pattern; bits
    /// not in the seed are silently ignored (no shard-lock).
    #[test]
    fn record_query_with_list_bit_increments_correct_slot() {
        let engine = StatsEngine::new(&test_config());
        // Pre-seed bits 0, 3, 7 — start.rs equivalent.
        for bit in [0u8, 3, 7] {
            engine
                .list_blocked
                .entry(bit)
                .or_insert_with(|| AtomicU64::new(0));
        }
        let ip: IpAddr = Ipv4Addr::new(192, 168, 1, 1).into();

        engine.record_query(
            ip,
            "tracker.example",
            None,
            None,
            RecordType::A,
            true,
            false,
            Some(3),
        );

        assert_eq!(
            engine.list_blocked.get(&3).unwrap().load(Ordering::Relaxed),
            1,
            "bit 3 incremented"
        );
        assert_eq!(
            engine.list_blocked.get(&0).unwrap().load(Ordering::Relaxed),
            0,
            "bit 0 untouched"
        );
        assert_eq!(
            engine.list_blocked.get(&7).unwrap().load(Ordering::Relaxed),
            0,
            "bit 7 untouched"
        );
        assert_eq!(
            engine.list_blocked.len(),
            3,
            "no new bit added — pre-seed only"
        );
    }

    /// Sprint B Dashboard v2 — admin-grade blocks (no `BlockSource::List`)
    /// pass `block_list_bit = None`. The `list_blocked` map must stay
    /// untouched even though the rest of the BLOCKED path runs (proven
    /// via the `domain_blocked` increment).
    #[test]
    fn record_query_admin_block_does_not_touch_list_map() {
        let engine = StatsEngine::new(&test_config());
        for bit in [0u8, 3] {
            engine
                .list_blocked
                .entry(bit)
                .or_insert_with(|| AtomicU64::new(0));
        }
        let ip: IpAddr = Ipv4Addr::new(192, 168, 1, 1).into();

        engine.record_query(
            ip,
            "evil.example",
            None,
            None,
            RecordType::A,
            true,
            false,
            None, // admin block — not list-attributed
        );

        assert_eq!(
            engine.list_blocked.get(&0).unwrap().load(Ordering::Relaxed),
            0,
            "bit 0 untouched on admin block"
        );
        assert_eq!(
            engine.list_blocked.get(&3).unwrap().load(Ordering::Relaxed),
            0,
            "bit 3 untouched on admin block"
        );
        // Sanity — the BLOCKED path actually ran (domain_blocked bumped).
        assert_eq!(
            engine
                .domain_blocked
                .get("evil.example")
                .unwrap()
                .load(Ordering::Relaxed),
            1,
            "domain_blocked incremented — block path executed"
        );
    }

    /// `HourlyRing::record` bumps the slot for the current hour and
    /// `sum_last_24h` returns the count. Cold ring sums to 0.
    #[test]
    fn hourly_ring_records_and_sums() {
        let ring = HourlyRing::new();
        let now: u64 = 12 * 3600 + 42;

        assert_eq!(ring.sum_last_24h(now), 0, "fresh ring sums to 0");

        for _ in 0..7 {
            ring.record(now);
        }
        assert_eq!(ring.sum_last_24h(now), 7);

        // Different second within the same hour lands in the same slot.
        for _ in 0..3 {
            ring.record(now + 600);
        }
        assert_eq!(ring.sum_last_24h(now + 600), 10);
    }

    /// Records older than 24h roll off the ring. Recording at hour H,
    /// then advancing to H + 25 must zero the stale slot.
    #[test]
    fn hourly_ring_rolls_over_after_24h() {
        let ring = HourlyRing::new();
        let h0: u64 = 100 * 3600;

        for _ in 0..10 {
            ring.record(h0);
        }
        assert_eq!(ring.sum_last_24h(h0), 10);

        // 25 hours later — h0's slot now holds a stale (out-of-window)
        // hour tag, so the reader excludes it and the h25 write lands
        // in a fresh slot. No zeroing — the slot self-describes.
        let h25 = h0 + 25 * 3600;
        for _ in 0..3 {
            ring.record(h25);
        }
        assert_eq!(
            ring.sum_last_24h(h25),
            3,
            "h0 slot out of the 24h window; only h25 writes summed"
        );
    }

    /// §4.39 (s-orphans-disc-1) — generation-tagged slots make the
    /// pre-§4.39 hour-boundary advance race structurally impossible.
    /// Stress it: pre-seed a slot with a STALE hour (prior ring
    /// rotation), then have many threads concurrently record into the
    /// NEW hour that maps to the same slot. Every thread either wins
    /// the stale→fresh CAS (exactly one, count = 1) or the +1 CAS; the
    /// final count must equal the total record count with zero losses.
    #[test]
    fn hourly_ring_no_lost_counts_at_boundary() {
        use std::sync::{Arc, Barrier};

        const THREADS: usize = 16;
        const PER_THREAD: u64 = 500;
        let total = THREADS as u64 * PER_THREAD;

        // h_old and h_new map to the same physical slot (24h apart),
        // so every record into h_new races a stale slot.
        let h_old: u64 = 1_000;
        let h_new: u64 = h_old + DEVICE_HOURLY_SLOTS as u64;
        let now_old = h_old * 3600;
        let now_new = h_new * 3600;

        let ring = Arc::new(HourlyRing::new());
        ring.record(now_old); // seed the slot with the stale hour

        let barrier = Arc::new(Barrier::new(THREADS));
        let mut handles = Vec::with_capacity(THREADS);
        for _ in 0..THREADS {
            let ring = Arc::clone(&ring);
            let barrier = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                for _ in 0..PER_THREAD {
                    ring.record(now_new);
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        // Every record into h_new must be accounted for — the stale
        // h_old seed is overwritten, never summed, nothing lost to a
        // concurrent advance.
        assert_eq!(
            ring.sum_last_24h(now_new),
            total,
            "no counts lost when many threads cross an hour boundary into a stale slot",
        );

        // Cross-check the parallel DeviceStats rings: the queries and
        // blocked rings advance independently with the same guarantee.
        let stats = Arc::new(DeviceStats::new("stress".into(), "default".into()));
        stats.record_hourly_query(now_old); // stale seed on the queries ring
        let barrier = Arc::new(Barrier::new(THREADS));
        let mut handles = Vec::with_capacity(THREADS);
        for _ in 0..THREADS {
            let stats = Arc::clone(&stats);
            let barrier = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                for _ in 0..PER_THREAD {
                    stats.record_hourly_query(now_new);
                    stats.record_hourly_blocked(now_new);
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(
            stats.hourly_queries_last_24h(now_new).iter().sum::<u64>(),
            total,
            "queries ring lost no counts at the hour boundary",
        );
        assert_eq!(
            stats.hourly_blocked_last_24h_sum(now_new),
            total,
            "blocked ring lost no counts at the hour boundary",
        );
    }

    /// `hourly_queries` and `hourly_blocked` are independent
    /// generation-tagged rings — a query that wasn't blocked must NOT
    /// bump the blocked ring, and vice versa.
    #[test]
    fn device_hourly_blocked_independent_of_queries() {
        let stats = DeviceStats::new("test".into(), "default".into());
        let now: u64 = 8 * 3600 + 7;

        // 5 queries, of which 2 blocked.
        for _ in 0..5 {
            stats.record_hourly_query(now);
        }
        for _ in 0..2 {
            stats.record_hourly_blocked(now);
        }

        // Sum via the public reader — raw slot loads now return the
        // packed `(hour << 32) | count`, not a bare count.
        let queries_sum: u64 = stats.hourly_queries_last_24h(now).iter().sum();
        assert_eq!(queries_sum, 5);
        assert_eq!(stats.hourly_blocked_last_24h_sum(now), 2);
    }

    /// `record_query` end-to-end on the hot path bumps both the
    /// lifetime DashMaps and the parallel `*_hourly` rings.
    #[test]
    fn record_query_increments_24h_rings() {
        let engine = StatsEngine::new(&test_config());
        // Pre-seed list_blocked + list_blocked_hourly the way start.rs
        // does (bit 3 here).
        engine.list_blocked.insert(3, AtomicU64::new(0));
        engine.list_blocked_hourly.insert(3, HourlyRing::new());

        let ip: IpAddr = Ipv4Addr::new(192, 168, 1, 1).into();
        engine.record_query(
            ip,
            "tracker.example",
            None,
            None,
            RecordType::A,
            true, // blocked
            false,
            Some(3),
        );

        // Lifetime maps bumped.
        assert_eq!(
            engine
                .domain_queries
                .get("tracker.example")
                .unwrap()
                .load(Ordering::Relaxed),
            1
        );
        assert_eq!(
            engine
                .domain_blocked
                .get("tracker.example")
                .unwrap()
                .load(Ordering::Relaxed),
            1
        );
        assert_eq!(
            engine.list_blocked.get(&3).unwrap().load(Ordering::Relaxed),
            1
        );

        // 24h rings populated under the current hour. Use a wall-clock
        // `now` so the assertion mirrors `record_query`'s own clock.
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert_eq!(
            engine
                .domain_queries_hourly
                .get("tracker.example")
                .unwrap()
                .sum_last_24h(now),
            1
        );
        assert_eq!(
            engine
                .domain_blocked_hourly
                .get("tracker.example")
                .unwrap()
                .sum_last_24h(now),
            1
        );
        assert_eq!(
            engine
                .list_blocked_hourly
                .get(&3)
                .unwrap()
                .sum_last_24h(now),
            1
        );
    }

    /// `prune_hourly_map` retains entries with non-zero 24h sums when
    /// the map exceeds capacity, and drops entries whose ring has aged
    /// to zero. Capacity check avoids the cost on small maps.
    #[test]
    fn prune_hourly_map_keeps_active_drops_idle() {
        let map: DashMap<CompactString, HourlyRing> = DashMap::new();
        let now: u64 = 50 * 3600;

        // Active: recorded recently → sum_last_24h > 0.
        let r_active = HourlyRing::new();
        r_active.record(now);
        map.insert(CompactString::from("active.com"), r_active);

        // Stale: recorded >24h ago.
        let r_stale = HourlyRing::new();
        r_stale.record(now.saturating_sub(48 * 3600));
        map.insert(CompactString::from("stale.com"), r_stale);

        // Below the capacity threshold — prune is a no-op.
        prune_hourly_map(&map, now);
        assert_eq!(map.len(), 2, "below MAX_DOMAIN_FREQ_ENTRIES — no prune");

        // Force pruning by adding > MAX_DOMAIN_FREQ_ENTRIES singleton
        // stale rings. They all have zero 24h sums, so they're all
        // dropped, but active.com is retained.
        for i in 0..(MAX_DOMAIN_FREQ_ENTRIES + 1) {
            let r = HourlyRing::new();
            r.record(now.saturating_sub(48 * 3600));
            map.insert(CompactString::from(format!("stale-{i}.com")), r);
        }
        prune_hourly_map(&map, now);
        assert!(map.contains_key("active.com"), "active entry retained");
        assert!(
            !map.contains_key("stale.com"),
            "stale entry dropped after capacity prune"
        );
    }

    /// engine-04 (rev-2606): a lifetime frequency map saturated with
    /// count>=2 entries must not stay pinned at cap — the `count > 1`
    /// retain alone frees nothing (counts are monotonic). The decay pass
    /// halves and reaps idle entries so newcomers can be tracked again,
    /// while a popular domain keeps its (halved) dominance.
    #[test]
    fn prune_map_decays_saturated_map_keeping_popular() {
        let map: DashMap<CompactString, AtomicU64> = DashMap::new();
        map.insert(
            CompactString::from("popular.example"),
            AtomicU64::new(1_000_000),
        );
        for i in 0..(MAX_DOMAIN_FREQ_ENTRIES + 100) {
            map.insert(
                CompactString::from(format!("rare{i}.example")),
                AtomicU64::new(2),
            );
        }
        assert!(map.len() > MAX_DOMAIN_FREQ_ENTRIES);

        prune_map(&map);

        assert!(
            map.len() <= MAX_DOMAIN_FREQ_ENTRIES,
            "saturated map must shed entries so newcomers fit, got len {}",
            map.len()
        );
        assert!(
            map.contains_key("popular.example"),
            "the popular domain must survive decay"
        );
        assert_eq!(
            map.get("popular.example").unwrap().load(Ordering::Relaxed),
            500_000,
            "popular count is halved by one decay pass, still dominant"
        );
    }
}
