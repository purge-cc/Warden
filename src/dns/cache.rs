//! DNS response cache backed by moka.
//!
//! Cache key: `(domain, record_type, dns_class)`. The DNS class slot is
//! P1-6 — without it `version.bind/TXT/CH` would collide with a hypothetical
//! `version.bind/TXT/IN` entry. Domain is stored lowercase (`LowerName`
//! discipline upstream).
//!
//! Cache value: answer records + metadata.
//!
//! Per-entry TTL semantics:
//!   - Positive responses clamp the minimum record TTL to `[min_ttl, max_ttl]`.
//!   - Negative responses (NXDOMAIN, NODATA) take `max(soa_minimum_ttl,
//!     negative_ttl)` as a floor — RFC 2308 §5 — then cap at `max_ttl` so an
//!     upstream zone with `MINIMUM=86400` cannot pin a refusal for 24 h past
//!     the operator's chosen ceiling (M-11).
//!   - SERVFAIL and Refused are not cached.
//!
//! Stale entries are kept past their fresh TTL for upstream-failure fallback
//! (the serve-stale window, configurable via `cache.stale_buffer_secs`).

use std::sync::Arc;
use std::time::{Duration, Instant};

use compact_str::CompactString;
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::DNSClass;
use hickory_proto::rr::{Record, RecordType};
use moka::future::Cache;
use moka::Expiry;

use crate::config::settings::CacheConfig;
use crate::dns::edns::EcsPrefix;

/// Cache key: lowercase domain + query type + DNS class + optional ECS
/// prefix bucket.
///
/// Including `DNSClass` prevents CH/IN collision (P1-6). The
/// `Option<EcsPrefix>` dimension (§4.8 §2/2 T3) partitions the cache
/// when a per-profile ECS policy forwards the client subnet upstream:
/// two clients on different `/24`s receive their own CDN-tailored
/// answer and do not poison each other's bucket. When no ECS option
/// is emitted (master kill-switch off, or profile mode = Off, or
/// anonymous form) the field is `None` — the lookup is byte-identical
/// to the pre-§4.8 baseline.
/// cache-01 (rev-2606): `pub(crate)` so the handler can hold the key built
/// by [`DnsCache::lookup_keyed`] and hand it back to
/// [`DnsCache::fetch_with_keyed_state`] — one key construction (and one
/// `CompactString` heap alloc for >24-byte domains) per miss instead of two.
pub(crate) type CacheKey = (CompactString, RecordType, DNSClass, Option<EcsPrefix>);

/// Cached DNS response. Clone is O(1) — records are behind Arc.
#[derive(Clone)]
pub struct CacheEntry {
    records: Arc<[Record]>,
    response_code: ResponseCode,
    created_at: Instant,
    /// How long this entry is considered fresh.
    ttl: Duration,
}

impl CacheEntry {
    /// Whether this entry is still within its fresh TTL.
    pub fn is_fresh(&self) -> bool {
        self.created_at.elapsed() < self.ttl
    }

    /// Remaining fresh TTL (saturates to zero if expired).
    pub fn remaining_ttl(&self) -> Duration {
        self.ttl.saturating_sub(self.created_at.elapsed())
    }

    /// Records with TTL adjusted to remaining freshness (min 1 second).
    ///
    /// rev-2026-05 §1 dns-01 (accepted tradeoff, sibling to the M-13 note on
    /// `insert`): this returns an owned `Vec` — one heap allocation plus N
    /// `Record` clones — on every positive cache hit, the dominant hot-path
    /// outcome. It is inherent, not an oversight. The cached records live behind
    /// an immutable `Arc<[Record]>`, so their TTL cannot be rewritten in place,
    /// and the serve path (`send_cached`) must hand the response builder records
    /// carrying the *decremented* TTL — but hickory's
    /// `MessageResponseBuilder::build` borrows records and exposes no serve-time
    /// TTL override. Owned, TTL-rewritten copies are therefore required. The
    /// clones are cheap (`Name` labels are `Arc`-backed; A/AAAA `RData` is inline)
    /// and N is the answer size (typically 1–4). Eliminating the heap `Vec` would
    /// need a stack `SmallVec` scratch buffer (a new dependency) for a marginal
    /// win; folds to P2.
    pub fn records_with_remaining_ttl(&self) -> Vec<Record> {
        let remaining = self.remaining_ttl().as_secs().max(1) as u32;
        self.records
            .iter()
            .map(|r| {
                let mut rec = r.clone();
                rec.ttl = remaining;
                rec
            })
            .collect()
    }

    pub fn response_code(&self) -> ResponseCode {
        self.response_code
    }

    /// True if this entry represents a negative response (NXDOMAIN or NODATA).
    /// Used by the handler to bump the negative-cache-hit counter on fresh hits.
    pub fn is_negative(&self) -> bool {
        matches!(self.response_code, ResponseCode::NXDomain)
            || (self.response_code == ResponseCode::NoError && self.records.is_empty())
    }

    /// Whether this entry is near expiry and should be prefetched.
    ///
    /// Returns `true` when `remaining_ttl < threshold * original_ttl` and
    /// the entry is not already expired.
    ///
    /// M-14: defense in depth against a NaN/inf/out-of-range threshold —
    /// `Duration::mul_f64` panics on NaN, infinity, or overflow. The
    /// validator (`config/validator.rs::validate_cache`) rejects these at
    /// boot, but a corrupted in-memory config or a future caller passing
    /// a derived value should not crash the per-query task. NaN comparisons
    /// in Rust evaluate to `false` by default — `0.0..=1.0).contains(&NaN)`
    /// is `false`, so the explicit range check is the safe form.
    pub fn needs_prefetch(&self, threshold: f64) -> bool {
        if !threshold.is_finite() || !(0.0..=1.0).contains(&threshold) {
            return false;
        }
        let remaining = self.remaining_ttl();
        let threshold_dur = self.ttl.mul_f64(threshold);
        remaining < threshold_dur && remaining > Duration::ZERO
    }

    /// Sprint §4.4 P2 absolute-seconds gate, sibling to `needs_prefetch`.
    ///
    /// Returns `true` when the entry has at most `lead_secs` of fresh TTL
    /// remaining and is not already expired. Used by the background
    /// refresh worker which scans the promoted-domain set every
    /// `tick_secs` and proactively refreshes entries about to expire,
    /// independent of incoming query traffic.
    ///
    /// Distinct from `needs_prefetch(threshold: f64)` — that gate is a
    /// fraction of the original TTL (Approach A, Sprint 17, reactive on
    /// cache hits). This one is an absolute deadline that catches
    /// short-TTL entries Approach A would miss on a quiet network.
    pub fn needs_prefetch_lead(&self, lead_secs: u64) -> bool {
        let remaining = self.remaining_ttl();
        remaining <= Duration::from_secs(lead_secs) && remaining > Duration::ZERO
    }
}

impl CacheEntry {
    /// Borrow the cached answer records.
    ///
    /// Used by the request-path post-cache-hit filter re-check
    /// (s44-arch-cache-invalidate-on-block) and by tests.
    pub fn records(&self) -> &[Record] {
        &self.records
    }
}

#[cfg(all(test, feature = "dnssec"))]
impl CacheEntry {
    /// Test-only constructor: build an entry directly from records + rcode,
    /// fresh for 300 s. Lets cross-module tests (the §4.10-4b DNSSEC wire tests
    /// in `handler.rs`) exercise `send_cached` without the async insert/lookup
    /// dance. An empty `records` + `NoError` models a NODATA negative.
    pub(crate) fn for_test(records: Vec<Record>, response_code: ResponseCode) -> Self {
        Self {
            records: records.into(),
            response_code,
            created_at: Instant::now(),
            ttl: Duration::from_secs(300),
        }
    }
}

/// Result of a cache lookup — single operation returning tri-state.
pub enum CacheLookup {
    /// Fresh entry within TTL — serve immediately.
    Fresh(CacheEntry),
    /// Expired but within stale buffer — usable as upstream-failure fallback.
    Stale(CacheEntry),
    /// No entry found.
    Miss,
}

#[cfg(test)]
impl CacheLookup {
    /// Extract a fresh entry.
    pub fn fresh(self) -> Option<CacheEntry> {
        if let Self::Fresh(e) = self {
            Some(e)
        } else {
            None
        }
    }

    /// Extract a stale entry.
    pub fn stale(self) -> Option<CacheEntry> {
        if let Self::Stale(e) = self {
            Some(e)
        } else {
            None
        }
    }
}

/// Per-entry expiration: fresh TTL + stale buffer.
///
/// L-14 (rev-2026-05-cache-update-expiry-pin): both `expire_after_create`
/// and `expire_after_update` are implemented explicitly. Moka's documented
/// default for `expire_after_update` falls back to the create policy when
/// the impl is omitted, so today's behaviour is correct — but the prefetch
/// path at `dns/handler.rs` calls `cache.insert(...)` over a key that may
/// still be present, so an unanchored default would silently change semantics
/// if the moka maintainers ever flipped it. Pin the contract.
///
/// cache-03: the serve-stale window is configurable via
/// `cache.stale_buffer_secs` (default 300), carried as a field so the
/// expire-after policy uses the operator's value (unset ⇒ 300 ⇒ unchanged).
struct DnsExpiry {
    stale_buffer: Duration,
}

impl Expiry<CacheKey, CacheEntry> for DnsExpiry {
    fn expire_after_create(
        &self,
        _key: &CacheKey,
        value: &CacheEntry,
        _current_time: Instant,
    ) -> Option<Duration> {
        Some(value.ttl + self.stale_buffer)
    }

    fn expire_after_update(
        &self,
        _key: &CacheKey,
        value: &CacheEntry,
        _current_time: Instant,
        _current_duration: Option<Duration>,
    ) -> Option<Duration> {
        // Re-anchor moka's eviction timer against the new entry's TTL.
        // Mirrors expire_after_create — the prefetch / overwrite path at
        // `dns/handler.rs` then never serves a stale record past
        // `value.ttl + self.stale_buffer` of the most recent insert.
        Some(value.ttl + self.stale_buffer)
    }
}

/// Weight multiplier for positive cache entries.
/// A positive entry costs 10 units, a negative entry costs 1 unit.
/// This makes NXDOMAIN flood attacks 10x less effective at evicting
/// legitimate cached responses (SEC-1 cache busting mitigation).
const POSITIVE_WEIGHT: u32 = 10;
const NEGATIVE_WEIGHT: u32 = 1;

/// Failure outcome of a `DnsCache::lookup_or_fetch` call.
///
/// Carries the upstream error alongside any pre-existing stale entry so the
/// caller can decide between forwarding `Uncacheable` (SERVFAIL/Refused),
/// serving stale on transient transport failures, or propagating the error.
pub struct FetchFailure {
    /// Stale entry captured at probe time, if one existed. The entry was
    /// invalidated before `try_get_with` ran so this owned clone is the
    /// only remaining copy (moka's expire_after_create still bounds it,
    /// but we've kicked it out of cache to force the fetcher to run).
    pub stale: Option<CacheEntry>,
    /// Inner error from the closure, wrapped in `Arc` because moka's
    /// `try_get_with` shares the same error across all concurrent waiters.
    pub error: Arc<super::error::DnsError>,
}

impl std::fmt::Debug for FetchFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FetchFailure")
            .field("stale", &self.stale.is_some())
            .field("error", &self.error)
            .finish()
    }
}

/// Compute the negative-response TTL with the RFC 2308 §5 floor + M-11 cap.
///
/// `floor = max(soa_minimum, negative_ttl)`, then capped at `max_ttl`. The
/// cap (M-11) prevents an upstream zone with a long `MINIMUM` (e.g. 86 400)
/// from pinning NXDOMAIN past the operator's chosen ceiling. Free function
/// so both `DnsCache::insert` and the `lookup_or_fetch` singleflight closure
/// (T3.2.b M-12) can share the formula without `&self` plumbing through the
/// `try_get_with` future.
fn compute_negative_ttl(
    negative_ttl: Duration,
    max_ttl: Duration,
    soa_minimum_ttl: Option<u32>,
) -> Duration {
    let floor = match soa_minimum_ttl {
        Some(soa_secs) => Duration::from_secs(soa_secs as u64).max(negative_ttl),
        None => negative_ttl,
    };
    floor.min(max_ttl)
}

/// Flushed cache occupancy — see [`DnsCache::flushed_usage`].
///
/// Both fields come from the same `run_pending_tasks()` sync point, so a
/// caller reading both together (as `warden status` / `/api/status` /
/// `/metrics` all do) never sees them drawn from two different moments.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CacheUsage {
    /// Raw entry count (moka `entry_count()`). Informational — NOT
    /// comparable to `max_entries`/`max_capacity()`, which is a weight,
    /// not a count (mem2608-s3 / F-E).
    pub entries: u64,
    /// Weighted occupancy (moka `weighted_size()`) — directly comparable
    /// to [`DnsCache::max_capacity`] / the operator's `[cache] max_entries`.
    /// Positive entries cost `POSITIVE_WEIGHT` (10), negative entries cost
    /// `NEGATIVE_WEIGHT` (1); see [`DnsCache::new`].
    pub weighted_size: u64,
}

/// DNS response cache with per-entry TTL and stale-on-failure support.
#[derive(Clone)]
pub struct DnsCache {
    cache: Cache<CacheKey, CacheEntry>,
    min_ttl: Duration,
    max_ttl: Duration,
    negative_ttl: Duration,
}

impl DnsCache {
    /// Create a new cache from config.
    ///
    /// Uses weighted capacity (SEC-1): positive entries cost 10 units,
    /// negative entries cost 1 unit. This means `max_entries` of 10,000
    /// holds ~1,000 positive entries or ~10,000 negative entries, preventing
    /// NXDOMAIN floods from evicting legitimate cached responses.
    pub fn new(config: &CacheConfig) -> Self {
        let cache = Cache::builder()
            .weigher(|_key: &CacheKey, value: &CacheEntry| {
                if value.records.is_empty() {
                    NEGATIVE_WEIGHT
                } else {
                    POSITIVE_WEIGHT
                }
            })
            .max_capacity(config.max_entries)
            .expire_after(DnsExpiry {
                // cache-03: serve-stale window from config (default 300 ⇒
                // byte-identical to the pre-knob hardcoded buffer).
                stale_buffer: Duration::from_secs(config.stale_buffer_secs),
            })
            .build();

        Self {
            cache,
            min_ttl: Duration::from_secs(config.min_ttl_secs),
            max_ttl: Duration::from_secs(config.max_ttl_secs),
            negative_ttl: Duration::from_secs(config.negative_ttl_secs),
        }
    }

    /// Look up a cached entry. Single operation — avoids double hash + allocation.
    ///
    /// **§4.8 §2/2 (T3):** `ecs_prefix` partitions the lookup by ECS
    /// bucket. `None` keeps the baseline pre-§4.8 behaviour; `Some(p)`
    /// targets the slot that holds the upstream's CDN-specific answer
    /// for that prefix. Sprint 1's anonymous form (`source_prefix = 0`)
    /// already projects to `None` via
    /// [`crate::dns::edns::EdnsClientSubnet::as_cache_prefix`].
    pub async fn lookup(
        &self,
        domain: &str,
        record_type: RecordType,
        dns_class: DNSClass,
        ecs_prefix: Option<EcsPrefix>,
    ) -> CacheLookup {
        self.lookup_keyed(domain, record_type, dns_class, ecs_prefix)
            .await
            .1
    }

    /// cache-01 (rev-2606): like [`Self::lookup`] but also returns the built
    /// [`CacheKey`] so the caller can reuse it for
    /// [`Self::fetch_with_keyed_state`] without a second key construction
    /// and probe. The handler's miss path previously probed the cache three
    /// times (lookup → lookup_or_fetch pre-probe → try_get_with) and built
    /// the key twice.
    pub(crate) async fn lookup_keyed(
        &self,
        domain: &str,
        record_type: RecordType,
        dns_class: DNSClass,
        ecs_prefix: Option<EcsPrefix>,
    ) -> (CacheKey, CacheLookup) {
        let key = (
            CompactString::new(domain),
            record_type,
            dns_class,
            ecs_prefix,
        );
        let result = match self.cache.get(&key).await {
            Some(entry) if entry.is_fresh() => CacheLookup::Fresh(entry),
            Some(entry) => CacheLookup::Stale(entry),
            None => CacheLookup::Miss,
        };
        (key, result)
    }

    /// Lookup-or-fetch with singleflight stampede protection (T3.2.b M-12).
    ///
    /// On a fresh cache hit, returns the entry without invoking the fetcher.
    /// On miss or stale, runs `fetch` exactly once across concurrent callers
    /// with the same key — moka's `try_get_with` collapses N concurrent
    /// fetches into 1 upstream request, eliminating thundering herd on
    /// uncached domain bursts (e.g. cert renewals, social-login storms).
    ///
    /// The closure returns `(records, response_code, soa_minimum_ttl)`. The
    /// SOA hint flows through to the same `compute_negative_ttl` math as
    /// `insert` (RFC 2308 §5 floor + M-11 max_ttl cap) so a singleflight
    /// negative response gets the same TTL it would have gotten via
    /// `insert(..., soa_minimum_ttl)`.
    ///
    /// SERVFAIL/Refused exclusion: callers contracted to return
    /// `Err(DnsError::Uncacheable(rc))` for these — `try_get_with` then
    /// skips the cache insert. A defense-in-depth check inside the closure
    /// also rejects an Ok-with-SERVFAIL slip-through. The handler unwraps
    /// `Uncacheable` from the returned `FetchFailure.error` and forwards
    /// the response_code to the client without caching.
    ///
    /// Stale handling: if a non-fresh entry exists, it is captured into
    /// `stale_fallback` and the cache is invalidated for that key BEFORE
    /// `try_get_with` runs — otherwise moka would return the existing
    /// stale entry and skip the fetch entirely (its expire_after policy
    /// keeps stale entries in cache for the configured stale buffer). On fetch failure,
    /// the captured stale is returned via `FetchFailure.stale` so the
    /// caller can serve it as upstream-failure fallback.
    pub async fn lookup_or_fetch<F, Fut>(
        &self,
        domain: &str,
        record_type: RecordType,
        dns_class: DNSClass,
        ecs_prefix: Option<EcsPrefix>,
        fetch: F,
    ) -> Result<CacheEntry, FetchFailure>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<
            Output = Result<(Vec<Record>, ResponseCode, Option<u32>), super::error::DnsError>,
        >,
    {
        let (key, prior) = self
            .lookup_keyed(domain, record_type, dns_class, ecs_prefix)
            .await;
        match prior {
            CacheLookup::Fresh(entry) => Ok(entry),
            CacheLookup::Stale(entry) => self.fetch_with_keyed_state(key, Some(entry), fetch).await,
            CacheLookup::Miss => self.fetch_with_keyed_state(key, None, fetch).await,
        }
    }

    /// cache-01 (rev-2606): singleflight fetch over a key + probe state the
    /// caller already holds (from [`Self::lookup_keyed`]). Skips the
    /// pre-probe and second key build that [`Self::lookup_or_fetch`] would
    /// pay. `stale_prior` is the non-fresh entry captured at probe time, if
    /// any — it is invalidated here (so `try_get_with` actually runs the
    /// fetcher instead of returning the stale entry that moka's
    /// expire-after policy keeps alive for the configured stale buffer) and carried out
    /// via [`FetchFailure::stale`] on fetch failure.
    ///
    /// Race note (same window as the pre-split code): if a concurrent task
    /// repopulates the slot between the caller's probe and this call,
    /// `try_get_with` returns that entry without invoking `fetch` (miss
    /// path), or the invalidate kicks it and the fetch re-runs (stale
    /// path) — one redundant upstream RTT, never a wrong answer.
    pub(crate) async fn fetch_with_keyed_state<F, Fut>(
        &self,
        key: CacheKey,
        stale_prior: Option<CacheEntry>,
        fetch: F,
    ) -> Result<CacheEntry, FetchFailure>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<
            Output = Result<(Vec<Record>, ResponseCode, Option<u32>), super::error::DnsError>,
        >,
    {
        if stale_prior.is_some() {
            // Without this invalidate, moka's expire_after policy keeps the
            // stale entry alive for the configured stale buffer and try_get_with returns it
            // without ever calling fetch — we'd serve stale on every miss.
            self.cache.invalidate(&key).await;
        }

        // Capture TTL config for the closure (no &self capture across await)
        let min_ttl = self.min_ttl;
        let max_ttl = self.max_ttl;
        let neg_ttl = self.negative_ttl;

        // try_get_with: only one caller runs the init future, others wait.
        // Moka itself wraps the closure error in Arc — the closure returns
        // bare `DnsError`, the outer Result is `Result<_, Arc<DnsError>>`.
        let result = self
            .cache
            .try_get_with(key.clone(), async {
                let (records, response_code, soa_minimum_ttl) = fetch().await?;

                // Defense in depth: even if a future caller forgets to
                // return Err(Uncacheable) for a SERVFAIL/Refused response,
                // we refuse to cache it here. Mirrors the guard in `insert`.
                if matches!(
                    response_code,
                    ResponseCode::ServFail | ResponseCode::Refused
                ) {
                    return Err(super::error::DnsError::Uncacheable(response_code));
                }

                let ttl = if records.is_empty() {
                    compute_negative_ttl(neg_ttl, max_ttl, soa_minimum_ttl)
                } else {
                    let min_record_ttl = records.iter().map(|r| r.ttl).min().unwrap_or(0);
                    let secs = (min_record_ttl as u64)
                        .max(min_ttl.as_secs())
                        .min(max_ttl.as_secs());
                    Duration::from_secs(secs)
                };

                Ok(CacheEntry {
                    records: Arc::from(records),
                    response_code,
                    created_at: Instant::now(),
                    ttl,
                }) as Result<CacheEntry, super::error::DnsError>
            })
            .await;

        match result {
            Ok(entry) => Ok(entry),
            Err(error) => Err(FetchFailure {
                stale: stale_prior,
                error,
            }),
        }
    }

    /// Cache a DNS response. TTL is clamped to `[min_ttl, max_ttl]` for
    /// positive responses. Negative responses use
    /// `max(soa_minimum_ttl, negative_ttl).min(max_ttl)` — RFC 2308 §5: the
    /// operator's configured `negative_ttl` is a floor, the SOA-derived hint
    /// (when upstream provided one) is also a floor; `max_ttl` is the
    /// ceiling on top (M-11), so an upstream zone with `MINIMUM=86400`
    /// cannot pin NXDOMAIN past the operator's chosen cap.
    ///
    /// SERVFAIL and Refused are dropped without caching. They indicate
    /// transient upstream failures or policy refusals — caching would pin a
    /// wrong answer for `negative_ttl` seconds and hide upstream recovery.
    /// The handler's pre-cache branch sweeps all non-positive responses into
    /// this path, so the guard lives here as defense in depth.
    // §4.8 §2/2 (T3): insert gained `ecs_prefix` as its 7th positional
    // arg so per-profile ECS keying threads through one canonical
    // entry point. Clippy's 7-arg ceiling already considers `&self`,
    // so the 9-arg total trips `too_many_arguments`; refactoring the
    // arg list to a struct would lose the inline-arg ergonomics that
    // every test fixture and call site relies on without saving any
    // real complexity (the args are still required individually).
    #[allow(clippy::too_many_arguments)]
    pub async fn insert(
        &self,
        domain: &str,
        record_type: RecordType,
        dns_class: DNSClass,
        records: Vec<Record>,
        response_code: ResponseCode,
        soa_minimum_ttl: Option<u32>,
        ecs_prefix: Option<EcsPrefix>,
    ) {
        if matches!(
            response_code,
            ResponseCode::ServFail | ResponseCode::Refused
        ) {
            return;
        }

        let ttl = if records.is_empty() {
            compute_negative_ttl(self.negative_ttl, self.max_ttl, soa_minimum_ttl)
        } else {
            self.compute_ttl(&records)
        };

        // M-13: caller hands ownership of the Vec; `Arc::from(Vec<T>)` is O(1)
        // (re-uses the heap allocation). Pre-fix the signature was `&[Record]`
        // and this site did `Arc::from(records.to_vec())` — N record clones
        // per cache miss. The prefetch call site (handler.rs) is the main
        // beneficiary because it owns `resp.records` outright; the forward
        // hot path still pays one explicit clone because it streams the same
        // records into the response builder.
        let entry = CacheEntry {
            records: Arc::from(records),
            response_code,
            created_at: Instant::now(),
            ttl,
        };

        let key = (
            CompactString::new(domain),
            record_type,
            dns_class,
            ecs_prefix,
        );
        self.cache.insert(key, entry).await;
    }

    /// Compute TTL: min of all record TTLs, clamped to [min_ttl, max_ttl].
    fn compute_ttl(&self, records: &[Record]) -> Duration {
        let min_record_ttl = records.iter().map(|r| r.ttl).min().unwrap_or(0);

        let ttl_secs = (min_record_ttl as u64)
            .max(self.min_ttl.as_secs())
            .min(self.max_ttl.as_secs());

        Duration::from_secs(ttl_secs)
    }

    /// Number of entries currently in cache.
    pub fn entry_count(&self) -> u64 {
        self.cache.entry_count()
    }

    /// Configured weighted capacity (the `cache.max_entries` operator
    /// setting). Exposed so the IPC `Status` response can report the
    /// actual cap instead of forcing the dashboard to extrapolate from
    /// `entry_count`. Returns 0 when moka has no cap set (never the
    /// case in production — `Cache::builder().max_capacity(...)` is
    /// always called from `new`).
    pub fn max_capacity(&self) -> u64 {
        self.cache.policy().max_capacity().unwrap_or(0)
    }

    /// Settle moka's internal write buffer, then read entry count and
    /// weighted size together (mem2608-s3 / F-E).
    ///
    /// `entry_count()` and `weighted_size()` are each eventually
    /// consistent on `moka::future::Cache` — inserts land in a write
    /// buffer and are only folded into the maintained counters when
    /// `run_pending_tasks()` runs. A cold read of either (as every
    /// pre-mem2608-s3 status/metrics surface did) can report a live,
    /// actively-hit cache as empty.
    ///
    /// Not for the query hot path — `run_pending_tasks` is a real
    /// `.await`. This is for operator-initiated reporting only
    /// (`warden status`, `GET /api/status`, `GET /metrics`), which is
    /// off the `:53` path, so the cost is irrelevant there.
    pub async fn flushed_usage(&self) -> CacheUsage {
        self.cache.run_pending_tasks().await;
        CacheUsage {
            entries: self.cache.entry_count(),
            weighted_size: self.cache.weighted_size(),
        }
    }

    /// Clear all cached entries.
    pub async fn clear(&self) {
        self.cache.invalidate_all();
        self.cache.run_pending_tasks().await;
        tracing::info!("DNS cache cleared");
    }

    /// Invalidate one specific (domain, record_type, dns_class) tuple.
    ///
    /// Used by the request-path "filter-on-cache-hit" guard
    /// (s44-arch-cache-invalidate-on-block, M-12 follow-up): when a cached
    /// response contains a CNAME pointing to a newly-blocked target, or an
    /// A/AAAA record now caught by the IP blocklist, the handler invalidates
    /// the precise tuple it just looked up (no need to wipe all 22 type×class
    /// combinations). Same lowercase-normalization invariant as
    /// `invalidate_domain` (project rules §Key Design Rules #3).
    pub async fn invalidate_key(
        &self,
        domain: &str,
        record_type: RecordType,
        dns_class: DNSClass,
        ecs_prefix: Option<EcsPrefix>,
    ) {
        let mut normalized = CompactString::new(domain);
        normalized.make_ascii_lowercase();
        let key = (normalized, record_type, dns_class, ecs_prefix);
        self.cache.invalidate(&key).await;
        self.cache.run_pending_tasks().await;
    }

    /// Invalidate all entries for a specific domain (all common record types and classes).
    ///
    /// L-7 (rev-2026-04-cache-invalidate-types): the iteration covers the
    /// "common queryable" set — A, AAAA, CNAME, MX, TXT, NS, SOA, plus the
    /// modern types HTTPS, SVCB, SRV, TLSA that the handler caches. Pre-fix
    /// the latter four were silently left in cache after an admin
    /// invalidation, a debuggability trap when wiping a stale entry. Moka's
    /// API requires invalidate-by-key so we cannot do a true type-agnostic
    /// wipe without scanning the entire cache; the explicit list is a
    /// pragmatic balance between cost (one invalidate call per type) and
    /// coverage of the types operators actually query.
    ///
    /// **§4.8 §2/2 (T3) caveat:** when a per-profile ECS policy has
    /// populated cache entries with non-`None` `ecs_prefix` buckets,
    /// this admin path only invalidates the `None` slot — moka exposes
    /// no native "wipe by prefix" sweep over the key tuple, and we
    /// purposely keep the operator path snappy (22 probes, not 22 × N
    /// known prefixes). ECS-bucketed entries age out via TTL. Document
    /// this limitation in the CLI help and `warden cache flush
    /// --domain` semantics.
    pub async fn invalidate_domain(&self, domain: &str) {
        // H-04 (rev-2026-04-cache-01): cache keys are stored lowercase
        // (project rules §Key Design Rules #3). The hot path lookup/insert sites
        // are fed by `LowerName`, but the IPC admin path (`warden cache flush
        // --domain Example.COM`) reaches us with raw operator input. Without
        // this normalization the invalidation silently no-ops — a
        // debuggability trap. Done once outside the loop so the 22 inner
        // probes (2 classes × 11 record types) reuse a single lowercase key.
        let mut normalized = CompactString::new(domain);
        normalized.make_ascii_lowercase();

        for dns_class in [DNSClass::IN, DNSClass::CH] {
            for rt in [
                RecordType::A,
                RecordType::AAAA,
                RecordType::CNAME,
                RecordType::MX,
                RecordType::TXT,
                RecordType::NS,
                RecordType::SOA,
                RecordType::HTTPS,
                RecordType::SVCB,
                RecordType::SRV,
                RecordType::TLSA,
            ] {
                let key = (normalized.clone(), rt, dns_class, None);
                self.cache.invalidate(&key).await;
            }
        }
        self.cache.run_pending_tasks().await;
        tracing::info!(
            domain = normalized.as_str(),
            "cache entries invalidated for domain"
        );
    }
}

#[cfg(test)]
impl DnsCache {
    /// Force pending maintenance tasks (useful in tests).
    pub async fn run_pending_tasks(&self) {
        self.cache.run_pending_tasks().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::rr::rdata::A;
    use hickory_proto::rr::{Name, RData};
    use std::net::Ipv4Addr;

    fn test_config() -> CacheConfig {
        CacheConfig {
            max_entries: 100,
            max_ttl_secs: 3600,
            min_ttl_secs: 5,
            negative_ttl_secs: 60,
            stale_buffer_secs: 300,
            prefetch: true,
            prefetch_threshold: 0.1,
            prefetch_max_concurrent: 16,
            cname_max_depth: 16,
            prefetch_tracker_enabled: false,
            prefetch_tracker_window_secs: 300,
            prefetch_tracker_min_hits: 3,
            prefetch_tracker_max_pool_size: 1024,
            prefetch_tracker_tick_secs: 30,
            prefetch_tracker_lead_secs: 10,
        }
    }

    fn test_record(ttl: u32) -> Record {
        Record::from_rdata(
            Name::from_ascii("example.com.").unwrap(),
            ttl,
            RData::A(A(Ipv4Addr::new(1, 2, 3, 4))),
        )
    }

    #[tokio::test]
    async fn cache_hit() {
        let cache = DnsCache::new(&test_config());
        cache
            .insert(
                "example.com",
                RecordType::A,
                DNSClass::IN,
                vec![test_record(300)],
                ResponseCode::NoError,
                None,
                None,
            )
            .await;

        let entry = cache
            .lookup("example.com", RecordType::A, DNSClass::IN, None)
            .await
            .fresh()
            .unwrap();
        assert_eq!(entry.records().len(), 1);
        assert_eq!(entry.response_code(), ResponseCode::NoError);
    }

    #[tokio::test]
    async fn cache_miss() {
        let cache = DnsCache::new(&test_config());
        assert!(matches!(
            cache
                .lookup("example.com", RecordType::A, DNSClass::IN, None)
                .await,
            CacheLookup::Miss
        ));
    }

    #[tokio::test]
    async fn different_record_types_are_separate() {
        let cache = DnsCache::new(&test_config());
        cache
            .insert(
                "example.com",
                RecordType::A,
                DNSClass::IN,
                vec![test_record(300)],
                ResponseCode::NoError,
                None,
                None,
            )
            .await;

        assert!(cache
            .lookup("example.com", RecordType::A, DNSClass::IN, None)
            .await
            .fresh()
            .is_some());
        assert!(matches!(
            cache
                .lookup("example.com", RecordType::AAAA, DNSClass::IN, None)
                .await,
            CacheLookup::Miss
        ));
    }

    #[tokio::test]
    async fn different_domains_are_separate() {
        let cache = DnsCache::new(&test_config());
        cache
            .insert(
                "a.com",
                RecordType::A,
                DNSClass::IN,
                vec![test_record(300)],
                ResponseCode::NoError,
                None,
                None,
            )
            .await;

        assert!(cache
            .lookup("a.com", RecordType::A, DNSClass::IN, None)
            .await
            .fresh()
            .is_some());
        assert!(matches!(
            cache
                .lookup("b.com", RecordType::A, DNSClass::IN, None)
                .await,
            CacheLookup::Miss
        ));
    }

    #[tokio::test]
    async fn ttl_clamped_to_min() {
        let cache = DnsCache::new(&test_config()); // min_ttl = 5
        cache
            .insert(
                "example.com",
                RecordType::A,
                DNSClass::IN,
                vec![test_record(1)], // TTL=1, below min
                ResponseCode::NoError,
                None,
                None,
            )
            .await;

        let entry = cache
            .lookup("example.com", RecordType::A, DNSClass::IN, None)
            .await
            .fresh()
            .unwrap();
        // remaining_ttl should be ~5s (clamped from 1 to min_ttl=5), not ~1s
        assert!(entry.remaining_ttl().as_secs() >= 4);
    }

    #[tokio::test]
    async fn ttl_clamped_to_max() {
        let config = CacheConfig {
            max_ttl_secs: 60,
            ..test_config()
        };
        let cache = DnsCache::new(&config);
        cache
            .insert(
                "example.com",
                RecordType::A,
                DNSClass::IN,
                vec![test_record(99999)],
                ResponseCode::NoError,
                None,
                None,
            )
            .await;

        let entry = cache
            .lookup("example.com", RecordType::A, DNSClass::IN, None)
            .await
            .fresh()
            .unwrap();
        assert!(entry.remaining_ttl().as_secs() <= 60);
    }

    #[tokio::test]
    async fn negative_cache_nxdomain() {
        let cache = DnsCache::new(&test_config());
        cache
            .insert(
                "nonexistent.com",
                RecordType::A,
                DNSClass::IN,
                Vec::new(),
                ResponseCode::NXDomain,
                None,
                None,
            )
            .await;

        let entry = cache
            .lookup("nonexistent.com", RecordType::A, DNSClass::IN, None)
            .await
            .fresh()
            .unwrap();
        assert_eq!(entry.response_code(), ResponseCode::NXDomain);
        assert!(entry.records().is_empty());
        // Uses negative_ttl (60s)
        assert!(entry.remaining_ttl().as_secs() >= 55);
    }

    /// BUG-1 regression: NODATA (NoError + empty records) must use negative_ttl,
    /// not accidentally fall through to compute_ttl → min_ttl.
    #[tokio::test]
    async fn negative_cache_nodata_uses_negative_ttl() {
        let cache = DnsCache::new(&test_config()); // negative_ttl=60, min_ttl=5
        cache
            .insert(
                "example.com",
                RecordType::AAAA,
                DNSClass::IN,
                Vec::new(),
                ResponseCode::NoError, // NODATA
                None,
                None,
            )
            .await;

        let entry = cache
            .lookup("example.com", RecordType::AAAA, DNSClass::IN, None)
            .await
            .fresh()
            .unwrap();
        assert_eq!(entry.response_code(), ResponseCode::NoError);
        assert!(entry.records().is_empty());
        // Must use negative_ttl (60s), NOT min_ttl (5s)
        assert!(entry.remaining_ttl().as_secs() >= 55);
    }

    #[tokio::test]
    async fn insert_servfail_is_not_cached() {
        let cache = DnsCache::new(&test_config());
        cache
            .insert(
                "broken.example.com",
                RecordType::A,
                DNSClass::IN,
                Vec::new(),
                ResponseCode::ServFail,
                None,
                None,
            )
            .await;
        cache.run_pending_tasks().await;

        assert_eq!(cache.entry_count(), 0);
        assert!(matches!(
            cache
                .lookup("broken.example.com", RecordType::A, DNSClass::IN, None)
                .await,
            CacheLookup::Miss
        ));
    }

    #[tokio::test]
    async fn insert_refused_is_not_cached() {
        let cache = DnsCache::new(&test_config());
        cache
            .insert(
                "refused.example.com",
                RecordType::A,
                DNSClass::IN,
                Vec::new(),
                ResponseCode::Refused,
                None,
                None,
            )
            .await;
        cache.run_pending_tasks().await;

        assert_eq!(cache.entry_count(), 0);
        assert!(matches!(
            cache
                .lookup("refused.example.com", RecordType::A, DNSClass::IN, None)
                .await,
            CacheLookup::Miss
        ));
    }

    /// Regression guard: the SERVFAIL/Refused guard must not drop valid
    /// negative responses. NXDOMAIN stays cacheable.
    #[tokio::test]
    async fn servfail_guard_does_not_affect_nxdomain() {
        let cache = DnsCache::new(&test_config());
        cache
            .insert(
                "nonexistent.com",
                RecordType::A,
                DNSClass::IN,
                Vec::new(),
                ResponseCode::NXDomain,
                None,
                None,
            )
            .await;
        cache.run_pending_tasks().await;

        assert_eq!(cache.entry_count(), 1);
    }

    #[tokio::test]
    async fn is_negative_true_for_nxdomain() {
        let cache = DnsCache::new(&test_config());
        cache
            .insert(
                "nope.com",
                RecordType::A,
                DNSClass::IN,
                Vec::new(),
                ResponseCode::NXDomain,
                None,
                None,
            )
            .await;
        let entry = cache
            .lookup("nope.com", RecordType::A, DNSClass::IN, None)
            .await
            .fresh()
            .unwrap();
        assert!(entry.is_negative());
    }

    #[tokio::test]
    async fn is_negative_true_for_nodata() {
        let cache = DnsCache::new(&test_config());
        cache
            .insert(
                "example.com",
                RecordType::AAAA,
                DNSClass::IN,
                Vec::new(),
                ResponseCode::NoError,
                None,
                None,
            )
            .await;
        let entry = cache
            .lookup("example.com", RecordType::AAAA, DNSClass::IN, None)
            .await
            .fresh()
            .unwrap();
        assert!(entry.is_negative());
    }

    #[tokio::test]
    async fn is_negative_false_for_positive_response() {
        let cache = DnsCache::new(&test_config());
        cache
            .insert(
                "example.com",
                RecordType::A,
                DNSClass::IN,
                vec![test_record(300)],
                ResponseCode::NoError,
                None,
                None,
            )
            .await;
        let entry = cache
            .lookup("example.com", RecordType::A, DNSClass::IN, None)
            .await
            .fresh()
            .unwrap();
        assert!(!entry.is_negative());
    }

    /// RFC 2308 §5: SOA-derived negative TTL acts as a floor. When the
    /// upstream-provided SOA hint is larger than the operator's configured
    /// negative_ttl, the cache uses the SOA value — respecting the zone
    /// author's stated caching intent.
    #[tokio::test]
    async fn soa_minimum_larger_than_configured_wins() {
        // test_config has negative_ttl_secs = 60
        let cache = DnsCache::new(&test_config());
        cache
            .insert(
                "nonexistent.com",
                RecordType::A,
                DNSClass::IN,
                Vec::new(),
                ResponseCode::NXDomain,
                Some(3600), // SOA hint = 1 hour
                None,
            )
            .await;

        let entry = cache
            .lookup("nonexistent.com", RecordType::A, DNSClass::IN, None)
            .await
            .fresh()
            .unwrap();
        // TTL should be ~3600 (SOA hint), not 60 (configured).
        assert!(entry.remaining_ttl().as_secs() >= 3590);
    }

    /// RFC 2308 §5: when the SOA hint is smaller than the operator's
    /// configured negative_ttl, the configured value wins (floor semantics
    /// on BOTH sides — whichever is larger).
    #[tokio::test]
    async fn configured_negative_ttl_larger_than_soa_wins() {
        // test_config has negative_ttl_secs = 60
        let cache = DnsCache::new(&test_config());
        cache
            .insert(
                "nonexistent.com",
                RecordType::A,
                DNSClass::IN,
                Vec::new(),
                ResponseCode::NXDomain,
                Some(10), // SOA hint = 10 seconds (very short)
                None,
            )
            .await;

        let entry = cache
            .lookup("nonexistent.com", RecordType::A, DNSClass::IN, None)
            .await
            .fresh()
            .unwrap();
        // TTL should be ~60 (configured), not 10 (SOA hint).
        assert!(entry.remaining_ttl().as_secs() >= 55);
        assert!(entry.remaining_ttl().as_secs() <= 60);
    }

    /// M-11 (RFC 2308 §5): a long SOA `MINIMUM` cannot pin NXDOMAIN past
    /// the operator's `max_ttl_secs` ceiling. Pre-fix the negative path
    /// only floored — an upstream zone with `MINIMUM=86 400` would hold a
    /// negative answer for 24 h even if the operator capped responses at
    /// 1 h.
    #[tokio::test]
    async fn negative_ttl_capped_at_max_ttl() {
        let config = CacheConfig {
            max_ttl_secs: 3600,
            negative_ttl_secs: 60,
            ..test_config()
        };
        let cache = DnsCache::new(&config);
        cache
            .insert(
                "nonexistent.com",
                RecordType::A,
                DNSClass::IN,
                Vec::new(),
                ResponseCode::NXDomain,
                Some(86_400), // SOA MINIMUM = 24 h
                None,
            )
            .await;

        let entry = cache
            .lookup("nonexistent.com", RecordType::A, DNSClass::IN, None)
            .await
            .fresh()
            .unwrap();
        // TTL must cap at max_ttl (3 600), not 86 400.
        assert!(entry.remaining_ttl().as_secs() <= 3600);
        assert!(entry.remaining_ttl().as_secs() >= 3590);
    }

    /// Regression: no SOA hint → pre-SOA-floor behavior preserved.
    /// Negative entry still uses the configured `negative_ttl`.
    #[tokio::test]
    async fn no_soa_hint_uses_configured_negative_ttl() {
        let cache = DnsCache::new(&test_config()); // negative_ttl_secs=60
        cache
            .insert(
                "nonexistent.com",
                RecordType::A,
                DNSClass::IN,
                Vec::new(),
                ResponseCode::NXDomain,
                None,
                None,
            )
            .await;

        let entry = cache
            .lookup("nonexistent.com", RecordType::A, DNSClass::IN, None)
            .await
            .fresh()
            .unwrap();
        assert!(entry.remaining_ttl().as_secs() >= 55);
        assert!(entry.remaining_ttl().as_secs() <= 60);
    }

    /// Positive responses ignore the SOA hint — record TTLs drive caching.
    /// Prevents accidental regression where a caller passes an SOA hint
    /// alongside non-empty records (shouldn't happen in practice but the
    /// guard makes the invariant explicit).
    #[tokio::test]
    async fn positive_response_ignores_soa_hint() {
        let cache = DnsCache::new(&test_config()); // min_ttl=5, max_ttl=3600
        cache
            .insert(
                "example.com",
                RecordType::A,
                DNSClass::IN,
                vec![test_record(300)],
                ResponseCode::NoError,
                Some(99999), // would pin negative for ~27 hours if respected
                None,
            )
            .await;

        let entry = cache
            .lookup("example.com", RecordType::A, DNSClass::IN, None)
            .await
            .fresh()
            .unwrap();
        // TTL should be ~300 (record), not ~99999 (SOA hint).
        assert!(entry.remaining_ttl().as_secs() <= 300);
        assert!(entry.remaining_ttl().as_secs() >= 290);
    }

    #[tokio::test]
    async fn expired_entry_returns_stale() {
        let config = CacheConfig {
            min_ttl_secs: 0,
            ..test_config()
        };
        let cache = DnsCache::new(&config);
        cache
            .insert(
                "example.com",
                RecordType::A,
                DNSClass::IN,
                vec![test_record(1)],
                ResponseCode::NoError,
                None,
                None,
            )
            .await;

        tokio::time::sleep(Duration::from_millis(1100)).await;

        // Should be Stale, not Fresh, not Miss
        assert!(cache
            .lookup("example.com", RecordType::A, DNSClass::IN, None)
            .await
            .stale()
            .is_some());
    }

    #[tokio::test]
    async fn remaining_ttl_decrements() {
        let cache = DnsCache::new(&test_config());
        cache
            .insert(
                "example.com",
                RecordType::A,
                DNSClass::IN,
                vec![test_record(300)],
                ResponseCode::NoError,
                None,
                None,
            )
            .await;

        let ttl_before = cache
            .lookup("example.com", RecordType::A, DNSClass::IN, None)
            .await
            .fresh()
            .unwrap()
            .remaining_ttl();

        tokio::time::sleep(Duration::from_millis(100)).await;

        let ttl_after = cache
            .lookup("example.com", RecordType::A, DNSClass::IN, None)
            .await
            .fresh()
            .unwrap()
            .remaining_ttl();

        assert!(ttl_after < ttl_before);
    }

    #[tokio::test]
    async fn records_with_remaining_ttl_adjusts_ttl() {
        let cache = DnsCache::new(&test_config());
        cache
            .insert(
                "example.com",
                RecordType::A,
                DNSClass::IN,
                vec![test_record(300)],
                ResponseCode::NoError,
                None,
                None,
            )
            .await;

        let entry = cache
            .lookup("example.com", RecordType::A, DNSClass::IN, None)
            .await
            .fresh()
            .unwrap();
        let adjusted = entry.records_with_remaining_ttl();
        assert_eq!(adjusted.len(), 1);
        // TTL should be close to 300 but slightly less due to elapsed time
        assert!(adjusted[0].ttl <= 300);
        assert!(adjusted[0].ttl >= 295);
    }

    #[tokio::test]
    async fn entry_count() {
        let cache = DnsCache::new(&test_config());
        assert_eq!(cache.entry_count(), 0);

        cache
            .insert(
                "a.com",
                RecordType::A,
                DNSClass::IN,
                vec![test_record(300)],
                ResponseCode::NoError,
                None,
                None,
            )
            .await;
        cache
            .insert(
                "b.com",
                RecordType::A,
                DNSClass::IN,
                vec![test_record(300)],
                ResponseCode::NoError,
                None,
                None,
            )
            .await;

        cache.run_pending_tasks().await;
        assert_eq!(cache.entry_count(), 2);
    }

    /// mem2608-s3 / F-E: `flushed_usage()` must settle moka itself — the
    /// caller does NOT call `run_pending_tasks()` first here, unlike
    /// every other test in this file. This is the discriminating case:
    /// against a `flushed_usage` that forgot the internal flush (i.e.
    /// just read `entry_count()`/`weighted_size()` cold), this is flaky-
    /// to-failing; against the real implementation it is deterministic.
    #[tokio::test]
    async fn flushed_usage_reflects_inserts_without_manual_flush() {
        let cache = DnsCache::new(&test_config());

        cache
            .insert(
                "a.com",
                RecordType::A,
                DNSClass::IN,
                vec![test_record(300)],
                ResponseCode::NoError,
                None,
                None,
            )
            .await;
        cache
            .insert(
                "b.com",
                RecordType::A,
                DNSClass::IN,
                vec![test_record(300)],
                ResponseCode::NoError,
                None,
                None,
            )
            .await;

        // No `cache.run_pending_tasks().await` here — that's the point.
        let usage = cache.flushed_usage().await;
        assert_eq!(usage.entries, 2);
        assert_eq!(usage.weighted_size, 2 * u64::from(POSITIVE_WEIGHT));
    }

    /// The three call sites that read cache occupancy for reporting
    /// (`warden status`, `/api/status`, `/metrics`) all now route through
    /// this one method — this pins that it is self-consistent across
    /// repeated calls with no intervening mutation, which is what makes
    /// "two surfaces report different truths about the same cache"
    /// structurally unreachable rather than merely untested.
    #[tokio::test]
    async fn flushed_usage_is_consistent_across_repeated_calls() {
        let cache = DnsCache::new(&test_config());
        cache
            .insert(
                "a.com",
                RecordType::A,
                DNSClass::IN,
                vec![test_record(300)],
                ResponseCode::NoError,
                None,
                None,
            )
            .await;

        let first = cache.flushed_usage().await;
        let second = cache.flushed_usage().await;
        assert_eq!(first, second);
        assert_eq!(first.entries, 1);
    }

    #[tokio::test]
    async fn clear_removes_all_entries() {
        let cache = DnsCache::new(&test_config());
        cache
            .insert(
                "a.com",
                RecordType::A,
                DNSClass::IN,
                vec![test_record(300)],
                ResponseCode::NoError,
                None,
                None,
            )
            .await;
        cache
            .insert(
                "b.com",
                RecordType::A,
                DNSClass::IN,
                vec![test_record(300)],
                ResponseCode::NoError,
                None,
                None,
            )
            .await;
        cache.run_pending_tasks().await;
        assert_eq!(cache.entry_count(), 2);

        cache.clear().await;
        assert_eq!(cache.entry_count(), 0);
        assert!(matches!(
            cache
                .lookup("a.com", RecordType::A, DNSClass::IN, None)
                .await,
            CacheLookup::Miss
        ));
        assert!(matches!(
            cache
                .lookup("b.com", RecordType::A, DNSClass::IN, None)
                .await,
            CacheLookup::Miss
        ));
    }

    #[tokio::test]
    async fn invalidate_domain_removes_modern_record_types() {
        // L-7 (rev-2026-04-cache-invalidate-types) regression pin: the
        // pre-fix iteration only covered A/AAAA/CNAME/MX/TXT/NS/SOA. Modern
        // queryable types — HTTPS, SVCB, SRV, TLSA — were silently left in
        // cache after `invalidate_domain`, causing a debuggability trap
        // when an operator tried to clear stale entries. This test pins
        // that all four are invalidated.
        let cache = DnsCache::new(&test_config());
        for rt in [
            RecordType::HTTPS,
            RecordType::SVCB,
            RecordType::SRV,
            RecordType::TLSA,
        ] {
            cache
                .insert(
                    "modern.example.com",
                    rt,
                    DNSClass::IN,
                    Vec::new(),
                    ResponseCode::NoError,
                    None,
                    None,
                )
                .await;
            assert!(
                cache
                    .lookup("modern.example.com", rt, DNSClass::IN, None)
                    .await
                    .fresh()
                    .is_some(),
                "{rt} entry should be present before invalidate"
            );
        }

        cache.invalidate_domain("modern.example.com").await;

        for rt in [
            RecordType::HTTPS,
            RecordType::SVCB,
            RecordType::SRV,
            RecordType::TLSA,
        ] {
            assert!(
                matches!(
                    cache
                        .lookup("modern.example.com", rt, DNSClass::IN, None)
                        .await,
                    CacheLookup::Miss
                ),
                "{rt} entry should be invalidated"
            );
        }
    }

    #[tokio::test]
    async fn invalidate_domain_removes_all_types() {
        let cache = DnsCache::new(&test_config());
        cache
            .insert(
                "example.com",
                RecordType::A,
                DNSClass::IN,
                vec![test_record(300)],
                ResponseCode::NoError,
                None,
                None,
            )
            .await;
        cache
            .insert(
                "example.com",
                RecordType::AAAA,
                DNSClass::IN,
                Vec::new(),
                ResponseCode::NoError,
                None,
                None,
            )
            .await;
        cache
            .insert(
                "other.com",
                RecordType::A,
                DNSClass::IN,
                vec![test_record(300)],
                ResponseCode::NoError,
                None,
                None,
            )
            .await;

        cache.invalidate_domain("example.com").await;

        assert!(matches!(
            cache
                .lookup("example.com", RecordType::A, DNSClass::IN, None)
                .await,
            CacheLookup::Miss
        ));
        assert!(matches!(
            cache
                .lookup("example.com", RecordType::AAAA, DNSClass::IN, None)
                .await,
            CacheLookup::Miss
        ));
        // other.com should remain
        assert!(cache
            .lookup("other.com", RecordType::A, DNSClass::IN, None)
            .await
            .fresh()
            .is_some());
    }

    #[tokio::test]
    async fn invalidate_domain_normalizes_mixed_case_input() {
        // H-04 (rev-2026-04-cache-01) regression pin: cache keys are stored
        // lowercase but operators type whatever they want at the IPC admin
        // surface (`warden cache flush --domain Example.COM`). Pre-fix the
        // mixed-case key never matched any moka entry so the call was a
        // silent no-op — a debuggability trap. This test inserts under the
        // canonical lowercase form (mirroring the hot-path `LowerName`
        // pipeline) and invalidates with a mixed-case form, asserting the
        // entry is gone.
        let cache = DnsCache::new(&test_config());
        cache
            .insert(
                "example.com",
                RecordType::A,
                DNSClass::IN,
                vec![test_record(300)],
                ResponseCode::NoError,
                None,
                None,
            )
            .await;
        assert!(
            cache
                .lookup("example.com", RecordType::A, DNSClass::IN, None)
                .await
                .fresh()
                .is_some(),
            "lowercase entry must be present before invalidate"
        );

        cache.invalidate_domain("Example.COM").await;

        assert!(
            matches!(
                cache
                    .lookup("example.com", RecordType::A, DNSClass::IN, None)
                    .await,
                CacheLookup::Miss
            ),
            "mixed-case invalidate must remove the lowercase entry"
        );
    }

    #[tokio::test]
    async fn invalidate_key_removes_only_the_targeted_tuple() {
        // s44-arch-cache-invalidate-on-block (M-12 follow-up): the post-
        // cache-hit re-check invalidates the precise (domain, type, class)
        // tuple it just looked up — not the full 22-key sweep that
        // `invalidate_domain` does. Insert (D, A, IN), (D, AAAA, IN),
        // (D, A, CH); invalidate only (D, A, IN); the other two stay.
        let cache = DnsCache::new(&test_config());
        for (rt, class) in [
            (RecordType::A, DNSClass::IN),
            (RecordType::AAAA, DNSClass::IN),
            (RecordType::A, DNSClass::CH),
        ] {
            cache
                .insert(
                    "example.com",
                    rt,
                    class,
                    vec![test_record(300)],
                    ResponseCode::NoError,
                    None,
                    None,
                )
                .await;
        }

        cache
            .invalidate_key("example.com", RecordType::A, DNSClass::IN, None)
            .await;

        assert!(matches!(
            cache
                .lookup("example.com", RecordType::A, DNSClass::IN, None)
                .await,
            CacheLookup::Miss
        ));
        assert!(cache
            .lookup("example.com", RecordType::AAAA, DNSClass::IN, None)
            .await
            .fresh()
            .is_some());
        assert!(cache
            .lookup("example.com", RecordType::A, DNSClass::CH, None)
            .await
            .fresh()
            .is_some());
    }

    #[tokio::test]
    async fn invalidate_key_normalizes_mixed_case_input() {
        // Symmetric with `invalidate_domain_normalizes_mixed_case_input`:
        // the post-cache-hit invalidator sees the original `domain` slice
        // from the request, which is already lowercased by `LowerName`
        // upstream — but defense-in-depth at the cache boundary keeps the
        // contract self-enforcing for any future caller (and matches the
        // `invalidate_domain` precedent).
        let cache = DnsCache::new(&test_config());
        cache
            .insert(
                "example.com",
                RecordType::A,
                DNSClass::IN,
                vec![test_record(300)],
                ResponseCode::NoError,
                None,
                None,
            )
            .await;

        cache
            .invalidate_key("Example.COM", RecordType::A, DNSClass::IN, None)
            .await;

        assert!(matches!(
            cache
                .lookup("example.com", RecordType::A, DNSClass::IN, None)
                .await,
            CacheLookup::Miss
        ));
    }

    #[tokio::test]
    async fn invalidate_key_no_op_on_missing_key() {
        // Idempotent — invalidating an absent key is harmless. The
        // post-cache-hit splice may race with a concurrent reload that
        // already invalidated the entry; the second invalidate must not
        // panic or surface an error.
        let cache = DnsCache::new(&test_config());
        cache
            .invalidate_key("nope.example.com", RecordType::A, DNSClass::IN, None)
            .await;
        assert!(matches!(
            cache
                .lookup("nope.example.com", RecordType::A, DNSClass::IN, None)
                .await,
            CacheLookup::Miss
        ));
    }

    #[tokio::test]
    async fn overwrite_updates_entry() {
        let cache = DnsCache::new(&test_config());
        cache
            .insert(
                "example.com",
                RecordType::A,
                DNSClass::IN,
                vec![test_record(100)],
                ResponseCode::NoError,
                None,
                None,
            )
            .await;

        // Overwrite with different data
        let new_record = Record::from_rdata(
            Name::from_ascii("example.com.").unwrap(),
            200,
            RData::A(A(Ipv4Addr::new(5, 6, 7, 8))),
        );
        cache
            .insert(
                "example.com",
                RecordType::A,
                DNSClass::IN,
                vec![new_record],
                ResponseCode::NoError,
                None,
                None,
            )
            .await;

        let entry = cache
            .lookup("example.com", RecordType::A, DNSClass::IN, None)
            .await
            .fresh()
            .unwrap();
        assert_eq!(entry.records().len(), 1);
        // TTL should reflect the new record (200, clamped to min=5..max=3600 → 200)
        assert!(entry.remaining_ttl().as_secs() >= 195);
    }

    // --- needs_prefetch ---

    #[test]
    fn needs_prefetch_false_at_50_percent_ttl() {
        let entry = CacheEntry {
            records: Arc::from(vec![test_record(300)]),
            response_code: ResponseCode::NoError,
            created_at: Instant::now() - Duration::from_secs(150), // 50% elapsed
            ttl: Duration::from_secs(300),
        };
        // 150s remaining out of 300s = 50% → threshold 0.1 → not near expiry
        assert!(!entry.needs_prefetch(0.1));
    }

    #[test]
    fn needs_prefetch_true_at_5_percent_ttl() {
        let entry = CacheEntry {
            records: Arc::from(vec![test_record(300)]),
            response_code: ResponseCode::NoError,
            created_at: Instant::now() - Duration::from_secs(285), // 95% elapsed
            ttl: Duration::from_secs(300),
        };
        // 15s remaining out of 300s = 5% → threshold 0.1 → near expiry
        assert!(entry.needs_prefetch(0.1));
    }

    #[test]
    fn needs_prefetch_false_when_expired() {
        let entry = CacheEntry {
            records: Arc::from(vec![test_record(300)]),
            response_code: ResponseCode::NoError,
            created_at: Instant::now() - Duration::from_secs(600), // way past TTL
            ttl: Duration::from_secs(300),
        };
        // Expired → remaining is zero → should NOT prefetch
        assert!(!entry.needs_prefetch(0.1));
    }

    /// M-14: defense-in-depth guard. The validator rejects NaN/inf at boot,
    /// but `needs_prefetch` must also refuse them so a corrupted runtime
    /// value cannot panic the per-query task via `Duration::mul_f64`.
    #[test]
    fn needs_prefetch_false_for_nan_threshold() {
        let entry = CacheEntry {
            records: Arc::from(vec![test_record(300)]),
            response_code: ResponseCode::NoError,
            created_at: Instant::now() - Duration::from_secs(285),
            ttl: Duration::from_secs(300),
        };
        assert!(!entry.needs_prefetch(f64::NAN));
        assert!(!entry.needs_prefetch(f64::INFINITY));
        assert!(!entry.needs_prefetch(f64::NEG_INFINITY));
        assert!(!entry.needs_prefetch(-0.5));
        assert!(!entry.needs_prefetch(1.5));
    }

    // --- P1-6: DNSClass isolation ---

    #[tokio::test]
    async fn different_dns_classes_are_separate() {
        let cache = DnsCache::new(&test_config());
        cache
            .insert(
                "version.bind",
                RecordType::TXT,
                DNSClass::CH,
                vec![test_record(300)],
                ResponseCode::NoError,
                None,
                None,
            )
            .await;

        // CH entry present
        assert!(cache
            .lookup("version.bind", RecordType::TXT, DNSClass::CH, None)
            .await
            .fresh()
            .is_some());
        // IN entry absent — no collision
        assert!(matches!(
            cache
                .lookup("version.bind", RecordType::TXT, DNSClass::IN, None)
                .await,
            CacheLookup::Miss
        ));
    }

    // --- T3.2.b M-12: lookup_or_fetch contract ---

    #[tokio::test]
    async fn lookup_or_fetch_caps_negative_ttl_with_soa_hint() {
        // SOA hint of 86 400 from the closure must be capped at max_ttl
        // (RFC 2308 §5 + M-11), the same way `insert` caps it.
        let mut cfg = test_config();
        cfg.max_ttl_secs = 60;
        cfg.negative_ttl_secs = 5;
        let cache = DnsCache::new(&cfg);

        let entry = cache
            .lookup_or_fetch(
                "missing.example",
                RecordType::A,
                DNSClass::IN,
                None,
                || async move { Ok((Vec::new(), ResponseCode::NXDomain, Some(86_400))) },
            )
            .await
            .expect("lookup_or_fetch ok");

        assert_eq!(entry.response_code(), ResponseCode::NXDomain);
        assert!(entry.records().is_empty());
        // Capped at max_ttl=60, not pinned at SOA min=86 400.
        let ttl = entry.remaining_ttl();
        assert!(
            ttl <= Duration::from_secs(60),
            "negative TTL must be capped at max_ttl=60s, got {:?}",
            ttl
        );
        // Floor still respected: max(SOA=86400, neg_ttl=5) = 86400 → cap → 60.
        assert!(
            ttl >= Duration::from_secs(5),
            "negative TTL must be at least negative_ttl=5s, got {:?}",
            ttl
        );
    }

    #[tokio::test]
    async fn lookup_or_fetch_does_not_cache_servfail_via_uncacheable() {
        // Closure returns Err(Uncacheable) — try_get_with must skip insert.
        let cache = DnsCache::new(&test_config());

        let result = cache
            .lookup_or_fetch(
                "broken.example",
                RecordType::A,
                DNSClass::IN,
                None,
                || async move {
                    Err(super::super::error::DnsError::Uncacheable(
                        ResponseCode::ServFail,
                    ))
                },
            )
            .await;

        assert!(result.is_err());
        let failure = result.err().unwrap();
        assert!(
            matches!(
                failure.error.as_ref(),
                super::super::error::DnsError::Uncacheable(ResponseCode::ServFail)
            ),
            "expected Uncacheable(ServFail), got {:?}",
            failure.error
        );
        // Cache must remain empty — next lookup is a Miss.
        assert!(matches!(
            cache
                .lookup("broken.example", RecordType::A, DNSClass::IN, None)
                .await,
            CacheLookup::Miss
        ));
    }

    #[tokio::test]
    async fn lookup_or_fetch_defense_in_depth_rejects_ok_servfail() {
        // Even if the closure returns Ok with a SERVFAIL response_code (a
        // mistake), the inner guard must refuse to cache it.
        let cache = DnsCache::new(&test_config());

        let result = cache
            .lookup_or_fetch(
                "slip.example",
                RecordType::A,
                DNSClass::IN,
                None,
                || async move { Ok((Vec::new(), ResponseCode::ServFail, None)) },
            )
            .await;

        assert!(
            result.is_err(),
            "Ok-with-ServFail must be rejected by inner guard"
        );
        assert!(matches!(
            cache
                .lookup("slip.example", RecordType::A, DNSClass::IN, None)
                .await,
            CacheLookup::Miss
        ));
    }

    #[tokio::test]
    async fn lookup_or_fetch_returns_stale_on_fetch_failure() {
        // Pre-populate a positive entry that will go stale, then call
        // lookup_or_fetch with a failing closure; FetchFailure.stale must
        // surface the original entry for upstream-failure fallback.
        let mut cfg = test_config();
        cfg.max_ttl_secs = 1;
        cfg.min_ttl_secs = 1;
        let cache = DnsCache::new(&cfg);

        cache
            .insert(
                "stale.example",
                RecordType::A,
                DNSClass::IN,
                vec![test_record(1)],
                ResponseCode::NoError,
                None,
                None,
            )
            .await;

        // Wait past the fresh TTL but inside the stale buffer (default 300 s).
        tokio::time::sleep(Duration::from_millis(1100)).await;

        let result = cache
            .lookup_or_fetch(
                "stale.example",
                RecordType::A,
                DNSClass::IN,
                None,
                || async move {
                    Err(super::super::error::DnsError::UpstreamRequestFailed(
                        "synthetic timeout".into(),
                    ))
                },
            )
            .await;

        let failure = result.err().expect("fetcher failed");
        let stale = failure.stale.expect("stale fallback returned");
        assert_eq!(stale.records().len(), 1);
    }

    #[tokio::test]
    async fn lookup_or_fetch_serves_fresh_without_invoking_fetcher() {
        // Fast path: an existing fresh entry must short-circuit before
        // try_get_with, so the fetcher closure is never called.
        let cache = DnsCache::new(&test_config());
        cache
            .insert(
                "warm.example",
                RecordType::A,
                DNSClass::IN,
                vec![test_record(300)],
                ResponseCode::NoError,
                None,
                None,
            )
            .await;

        let counter = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let counter_c = Arc::clone(&counter);

        let entry = cache
            .lookup_or_fetch(
                "warm.example",
                RecordType::A,
                DNSClass::IN,
                None,
                move || async move {
                    counter_c.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    Ok((Vec::new(), ResponseCode::NoError, None))
                },
            )
            .await
            .expect("fresh hit");

        assert_eq!(entry.records().len(), 1);
        assert_eq!(
            counter.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "fresh-hit fast path must not invoke the fetcher"
        );
    }

    #[tokio::test]
    async fn re_insert_resets_entry_ttl() {
        // L-14 (rev-2026-05-cache-update-expiry-pin) regression pin: when
        // `cache.insert` is called over an existing key (the prefetch
        // path at `dns/handler.rs`), the new entry's TTL must drive the
        // freshness window — not the original entry's. Pre-pin moka's
        // default `expire_after_update` already does this, but the impl
        // is now explicit so a future moka behaviour change cannot
        // silently regress the prefetch path.
        let config = CacheConfig {
            min_ttl_secs: 1,
            max_ttl_secs: 3600,
            ..test_config()
        };
        let cache = DnsCache::new(&config);

        // First insert: long TTL.
        cache
            .insert(
                "warm.example.com",
                RecordType::A,
                DNSClass::IN,
                vec![test_record(3600)],
                ResponseCode::NoError,
                None,
                None,
            )
            .await;
        let first = cache
            .lookup("warm.example.com", RecordType::A, DNSClass::IN, None)
            .await
            .fresh()
            .expect("first insert must be fresh");
        let first_remaining = first.remaining_ttl().as_secs();
        assert!(
            first_remaining >= 3500,
            "first insert remaining TTL ≈ 3600, got {first_remaining}"
        );

        // Re-insert same key with a much shorter TTL.
        cache
            .insert(
                "warm.example.com",
                RecordType::A,
                DNSClass::IN,
                vec![test_record(5)],
                ResponseCode::NoError,
                None,
                None,
            )
            .await;
        let second = cache
            .lookup("warm.example.com", RecordType::A, DNSClass::IN, None)
            .await
            .fresh()
            .expect("re-insert must be fresh");
        let second_remaining = second.remaining_ttl().as_secs();
        assert!(
            second_remaining <= 5,
            "re-insert remaining TTL ≈ 5, got {second_remaining} — expire_after_update did not re-anchor"
        );
    }

    // ── §4.8 §2/2 T3: cache partitioning by ECS prefix ─────────

    fn ecs_prefix(addr: &str, prefix: u8) -> EcsPrefix {
        EcsPrefix {
            addr: addr.parse().unwrap(),
            prefix,
        }
    }

    #[tokio::test]
    async fn cache_partitioning_two_subnets_do_not_collide() {
        // Two clients on different /24s under Subnet mode should get
        // their own cached answer for the same domain — a CDN-routed
        // response for /24=10.10.1 must NOT poison /24=10.10.2.
        let cache = DnsCache::new(&test_config());
        let p1 = ecs_prefix("192.0.2.0", 24);
        let p2 = ecs_prefix("10.10.2.0", 24);
        cache
            .insert(
                "cdn.example.com",
                RecordType::A,
                DNSClass::IN,
                vec![Record::from_rdata(
                    Name::from_ascii("cdn.example.com.").unwrap(),
                    300,
                    RData::A(A(Ipv4Addr::new(1, 1, 1, 1))),
                )],
                ResponseCode::NoError,
                None,
                Some(p1),
            )
            .await;
        let hit = cache
            .lookup("cdn.example.com", RecordType::A, DNSClass::IN, Some(p1))
            .await
            .fresh()
            .expect("p1 slot is fresh");
        assert_eq!(hit.records().len(), 1);
        let miss = cache
            .lookup("cdn.example.com", RecordType::A, DNSClass::IN, Some(p2))
            .await;
        assert!(
            matches!(miss, CacheLookup::Miss),
            "different /24 must miss — cross-subnet poison guard"
        );
    }

    #[tokio::test]
    async fn cache_partitioning_none_prefix_is_baseline_slot() {
        // Inserting with ecs_prefix = None and looking up with
        // Some(prefix) is a miss, AND vice versa. None is a distinct
        // cache slot — the byte-identical-to-pre-§4.8 baseline.
        let cache = DnsCache::new(&test_config());
        cache
            .insert(
                "baseline.example.com",
                RecordType::A,
                DNSClass::IN,
                vec![Record::from_rdata(
                    Name::from_ascii("baseline.example.com.").unwrap(),
                    300,
                    RData::A(A(Ipv4Addr::new(2, 2, 2, 2))),
                )],
                ResponseCode::NoError,
                None,
                None,
            )
            .await;
        let baseline_hit = cache
            .lookup("baseline.example.com", RecordType::A, DNSClass::IN, None)
            .await
            .fresh();
        assert!(baseline_hit.is_some(), "baseline slot must be fresh");
        let ecs_miss = cache
            .lookup(
                "baseline.example.com",
                RecordType::A,
                DNSClass::IN,
                Some(ecs_prefix("192.0.2.0", 24)),
            )
            .await;
        assert!(
            matches!(ecs_miss, CacheLookup::Miss),
            "ECS-bucketed lookup against None-bucket cache must miss"
        );
    }

    #[tokio::test]
    async fn cache_partitioning_invalidate_key_targets_single_bucket() {
        // invalidate_key with Some(prefix) wipes only that bucket; the
        // None-bucket slot for the same (domain, qtype) survives.
        let cache = DnsCache::new(&test_config());
        let p1 = ecs_prefix("192.0.2.0", 24);
        for prefix_arg in [None, Some(p1)] {
            cache
                .insert(
                    "twin.example.com",
                    RecordType::A,
                    DNSClass::IN,
                    vec![Record::from_rdata(
                        Name::from_ascii("twin.example.com.").unwrap(),
                        300,
                        RData::A(A(Ipv4Addr::new(3, 3, 3, 3))),
                    )],
                    ResponseCode::NoError,
                    None,
                    prefix_arg,
                )
                .await;
        }
        // Both buckets fresh before.
        assert!(cache
            .lookup("twin.example.com", RecordType::A, DNSClass::IN, None)
            .await
            .fresh()
            .is_some());
        assert!(cache
            .lookup("twin.example.com", RecordType::A, DNSClass::IN, Some(p1))
            .await
            .fresh()
            .is_some());
        cache
            .invalidate_key("twin.example.com", RecordType::A, DNSClass::IN, Some(p1))
            .await;
        // ECS bucket gone, None bucket survives.
        assert!(matches!(
            cache
                .lookup("twin.example.com", RecordType::A, DNSClass::IN, Some(p1))
                .await,
            CacheLookup::Miss
        ));
        assert!(cache
            .lookup("twin.example.com", RecordType::A, DNSClass::IN, None)
            .await
            .fresh()
            .is_some());
    }
}
