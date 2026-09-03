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
    /// also counted in `total_blocked` — refusals are visible in stats;
    /// this dedicated counter lets an operator separate security
    /// refusals from content blocks in the block-rate signal.
    /// Diagnostic — not persisted in snapshots, resets on restart.
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

/// Generation-tagged hourly ring slots.
///
/// Each `AtomicU64` slot packs `(hour << 32) | count`: the high 32
/// bits are the absolute hour index (`unix_secs / 3600`), the low 32
/// bits are the event count recorded in that hour. A slot is "stale"
/// (left over from a prior rotation of the 24-slot ring) iff its
/// packed hour differs from the hour being recorded or read.
///
/// This replaces an earlier `anchor_hour` + lazy zero-loop design,
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
/// `queries_today_baseline` + `today_day_index` enable a "today only"
/// view of queries on the Dashboard's Top Devices card without changing
/// the hot path. Both are written only on the IPC-read path via
/// `queries_today()`; `record_query` continues to touch only the
/// cumulative `queries` counter.
///
/// `hourly_queries` / `hourly_blocked` add 24-slot rings of per-device
/// queries-per-hour. The slots are generation-tagged (`(hour << 32) |
/// count`) — hot path is one atomic load + one CAS per query, no
/// rollover branch, no anchor.
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
    /// Per-bit blocked-query counters keyed by the Tier 1 blocklist bit
    /// (0..=63) attributed to each block.
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
    /// map saturates. Each counter is adjusted by ±1 at every
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
    /// can attach / detach the writer on `handle_reload` without a restart.
    /// `None` when `query_log_enabled = false`; the fast
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
    /// Hit-frequency tracker for cache-prefetch promotion. The pool is
    /// observable via IPC and consumed by the proactive refresh worker
    /// (`prefetch_worker.rs`). Default-disabled when built via
    /// `StatsEngine::new` — production callers pass a populated
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
    /// keeps tests cheap and callers that don't need the tracker
    /// behaviour-identical. Production code that wants a live tracker
    /// calls `with_prefetch_config`.
    pub fn new(config: &TrackingConfig) -> Self {
        Self::with_prefetch_config(config, &PrefetchTrackerConfig::default())
    }

    /// Create a new engine wired with a populated prefetch tracker.
    /// The production constructor.
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
    /// `Arc`-shared engine.
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
    /// discipline as `auth_error_for` in `socket_server.rs`.
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
        // `log_mode` decides *before* we construct the entry whether
        // this query needs to be logged at all. This keeps `BlockedOnly`
        // and the `Sampled` allowed-path out of the timestamp-format +
        // `String::from(domain)` cost that dominates a single entry's
        // hot-path cost.
        //
        // Gate on the `blocked` bool the decision already carries — NOT
        // a string compare on `result`. The hot
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
            // Populated by the two CNAME-chain-block call sites in
            // `dns/handler.rs`; `None` for every other outcome.
            cname_chain_via: cname_chain_via.map(|s| s.to_string()),
            // Populated by the post-filter rewrite hook in
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
    /// `block_list_bit` is `Some(bit)` only when
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
            // Drive the per-device hourly ring. One atomic load +
            // (in steady state) one atomic add. The hour-rollover
            // branch fires once per ticked hour, not per query.
            entry.record_hourly_query(now);
        } else if self.max_devices > 0 {
            // Slow path: IP not currently tracked and device tracking is
            // enabled. (`max_devices == 0` disables it — preserves the old
            // `len() < 0`-never-true semantics of never inserting, with no
            // wasted stats allocation.) Build the fresh row once, then insert
            // — evicting the approximately-stalest device first when the table
            // is at cap, so a saturated table self-heals instead of
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
            // O(1) capacity gate: read the Relaxed counter, not
            // DashMap::len()'s all-shard sweep. At/over cap, evict the
            // approximately-stalest device first to make room.
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
            // Per-bit blocked counter. Pre-seeded at start.rs so the
            // hot path is `get` + `Relaxed::fetch_add`.
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

        // Time series: pass the already-classified bucket so the
        // per_type / blocked_per_type ring carries per-`TypeBucket`
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

    /// Bump the security-refusal counter. Called from `record_outcome`
    /// for the `REFUSED` / `RRL_DROP` outcomes.
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
    /// When the tracker is disabled (the default) this is a single
    /// branch on a `bool` field — no allocation, no atomic increment.
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
    /// is at `max_devices` (self-healing on saturation). Samples up to
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
    /// `size` is the map's O(1) sibling size counter: the capacity
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
        // gate would drop every new domain forever. Off the query path,
        // so `.len()` is fine here.
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
        // free. Devices can disappear between ticks (stalest-device
        // eviction); this simply rolls whatever is currently present.
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
    /// therefore keep their stale name/profile in stats until restart.
    #[allow(dead_code)]
    pub fn update_device_info(&self, ip: IpAddr, name: &str, profile: &str) {
        if let Some(mut entry) = self.devices.get_mut(&ip) {
            entry.name = CompactString::from(name);
            entry.profile = CompactString::from(profile);
        }
    }
}

/// Decide whether to log an allowed query under a
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
/// restart. When that happens, decay — halve every
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
mod tests;
