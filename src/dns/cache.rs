//! DNS response cache backed by moka.
//!
//! Cache key: `(domain, record_type, dns_class)`. The DNS class slot
//! matters — without it `version.bind/TXT/CH` would collide with a
//! hypothetical `version.bind/TXT/IN` entry. Domain is stored lowercase
//! (`LowerName` discipline upstream).
//!
//! Cache value: answer records + metadata.
//!
//! Per-entry TTL semantics:
//!   - Positive responses clamp the minimum record TTL to `[min_ttl, max_ttl]`.
//!   - Negative responses (NXDOMAIN, NODATA) take `max(soa_minimum_ttl,
//!     negative_ttl)` as a floor — RFC 2308 §5 — then cap at `max_ttl` so an
//!     upstream zone with `MINIMUM=86400` cannot pin a refusal for 24 h past
//!     the operator's chosen ceiling.
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
/// Including `DNSClass` prevents CH/IN collision. The
/// `Option<EcsPrefix>` dimension partitions the cache when a
/// per-profile ECS policy forwards the client subnet upstream: two
/// clients on different `/24`s receive their own CDN-tailored answer
/// and do not poison each other's bucket. When no ECS option is
/// emitted (master kill-switch off, or profile mode = Off, or
/// anonymous form) the field is `None` — the lookup is unaffected by
/// ECS bucketing.
///
/// `pub(crate)` so the handler can hold the key built by
/// [`DnsCache::lookup_keyed`] and hand it back to
/// [`DnsCache::fetch_with_keyed_state`] — one key construction (and one
/// `CompactString` heap alloc for >24-byte domains) per miss instead of
/// two.
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
    /// This is an accepted tradeoff: it returns an owned `Vec` — one heap
    /// allocation plus N `Record` clones — on every positive cache hit,
    /// the dominant hot-path outcome. It is inherent, not an oversight.
    /// The cached records live behind an immutable `Arc<[Record]>`, so
    /// their TTL cannot be rewritten in place, and the serve path
    /// (`send_cached`) must hand the response builder records carrying
    /// the *decremented* TTL — but hickory's
    /// `MessageResponseBuilder::build` borrows records and exposes no
    /// serve-time TTL override. Owned, TTL-rewritten copies are
    /// therefore required. The clones are cheap (`Name` labels are
    /// `Arc`-backed; A/AAAA `RData` is inline) and N is the answer size
    /// (typically 1–4). Eliminating the heap `Vec` would need a stack
    /// `SmallVec` scratch buffer (a new dependency) for a marginal win.
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
    /// Defense in depth against a NaN/inf/out-of-range threshold —
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

    /// Absolute-seconds gate, sibling to `needs_prefetch`.
    ///
    /// Returns `true` when the entry has at most `lead_secs` of fresh TTL
    /// remaining and is not already expired. Used by the background
    /// refresh worker which scans the promoted-domain set every
    /// `tick_secs` and proactively refreshes entries about to expire,
    /// independent of incoming query traffic.
    ///
    /// Distinct from `needs_prefetch(threshold: f64)`, which is a
    /// fraction of the original TTL and only fires reactively on cache
    /// hits. This one is an absolute deadline that catches short-TTL
    /// entries the reactive gate would miss on a quiet network.
    pub fn needs_prefetch_lead(&self, lead_secs: u64) -> bool {
        let remaining = self.remaining_ttl();
        remaining <= Duration::from_secs(lead_secs) && remaining > Duration::ZERO
    }
}

impl CacheEntry {
    /// Borrow the cached answer records.
    ///
    /// Used by the request-path post-cache-hit filter re-check and by
    /// tests.
    pub fn records(&self) -> &[Record] {
        &self.records
    }
}

#[cfg(all(test, feature = "dnssec"))]
impl CacheEntry {
    /// Test-only constructor: build an entry directly from records + rcode,
    /// fresh for 300 s. Lets cross-module tests (the DNSSEC wire tests in
    /// `handler.rs`) exercise `send_cached` without the async insert/lookup
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

/// Per-entry expiration: fresh TTL + stale buffer.
///
/// Both `expire_after_create` and `expire_after_update` are implemented
/// explicitly. Moka's documented default for `expire_after_update` falls
/// back to the create policy when the impl is omitted, so today's
/// behaviour is correct — but the prefetch path at `dns/handler.rs`
/// calls `cache.insert(...)` over a key that may still be present, so an
/// unanchored default would silently change semantics if the moka
/// maintainers ever flipped it. Pin the contract.
///
/// The serve-stale window is configurable via `cache.stale_buffer_secs`
/// (default 300), carried as a field so the expire-after policy uses
/// the operator's value (unset ⇒ 300 ⇒ unchanged).
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
/// legitimate cached responses (cache-busting mitigation).
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

/// Compute the negative-response TTL with the RFC 2308 §5 floor and a cap.
///
/// `floor = max(soa_minimum, negative_ttl)`, then capped at `max_ttl`. The
/// cap prevents an upstream zone with a long `MINIMUM` (e.g. 86 400) from
/// pinning NXDOMAIN past the operator's chosen ceiling. Free function so
/// both `DnsCache::insert` and the `lookup_or_fetch` singleflight closure
/// can share the formula without `&self` plumbing through the
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
    /// not a count.
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
    /// Uses weighted capacity: positive entries cost 10 units, negative
    /// entries cost 1 unit. This means `max_entries` of 10,000
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
                // Serve-stale window from config (default 300 ⇒
                // byte-identical to the earlier hardcoded buffer).
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
    /// `ecs_prefix` partitions the lookup by ECS bucket. `None` keeps
    /// the baseline (no ECS) behaviour; `Some(p)` targets the slot that
    /// holds the upstream's CDN-specific answer for that prefix. The
    /// anonymous form (`source_prefix = 0`) already projects to `None`
    /// via [`crate::dns::edns::EdnsClientSubnet::as_cache_prefix`].
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

    /// Like [`Self::lookup`] but also returns the built [`CacheKey`] so
    /// the caller can reuse it for [`Self::fetch_with_keyed_state`]
    /// without a second key construction and probe. The handler's miss
    /// path previously probed the cache three times (lookup →
    /// lookup_or_fetch pre-probe → try_get_with) and built the key
    /// twice.
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

    /// Lookup-or-fetch with singleflight stampede protection.
    ///
    /// On a fresh cache hit, returns the entry without invoking the fetcher.
    /// On miss or stale, runs `fetch` exactly once across concurrent callers
    /// with the same key — moka's `try_get_with` collapses N concurrent
    /// fetches into 1 upstream request, eliminating thundering herd on
    /// uncached domain bursts (e.g. cert renewals, social-login storms).
    ///
    /// The closure returns `(records, response_code, soa_minimum_ttl)`. The
    /// SOA hint flows through to the same `compute_negative_ttl` math as
    /// `insert` (RFC 2308 §5 floor + `max_ttl` cap) so a singleflight
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

    /// Singleflight fetch over a key + probe state the caller already
    /// holds (from [`Self::lookup_keyed`]). Skips the pre-probe and
    /// second key build that [`Self::lookup_or_fetch`] would pay.
    /// `stale_prior` is the non-fresh entry captured at probe time, if
    /// any — it is invalidated here (so `try_get_with` actually runs the
    /// fetcher instead of returning the stale entry that moka's
    /// expire-after policy keeps alive for the configured stale buffer)
    /// and carried out via [`FetchFailure::stale`] on fetch failure.
    ///
    /// Race note: if a concurrent task repopulates the slot between the
    /// caller's probe and this call,
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
    /// ceiling on top, so an upstream zone with `MINIMUM=86400` cannot
    /// pin NXDOMAIN past the operator's chosen cap.
    ///
    /// SERVFAIL and Refused are dropped without caching. They indicate
    /// transient upstream failures or policy refusals — caching would pin a
    /// wrong answer for `negative_ttl` seconds and hide upstream recovery.
    /// The handler's pre-cache branch sweeps all non-positive responses into
    /// this path, so the guard lives here as defense in depth.
    // `ecs_prefix` is a positional arg so per-profile ECS keying threads
    // through one canonical entry point. Clippy's 7-arg ceiling already
    // considers `&self`, so the 9-arg total trips `too_many_arguments`;
    // refactoring the arg list to a struct would lose the inline-arg
    // ergonomics that every test fixture and call site relies on
    // without saving any real complexity (the args are still required
    // individually).
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

        // The caller hands ownership of the Vec; `Arc::from(Vec<T>)` is O(1)
        // (re-uses the heap allocation). An earlier signature took `&[Record]`
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
    /// weighted size together.
    ///
    /// `entry_count()` and `weighted_size()` are each eventually
    /// consistent on `moka::future::Cache` — inserts land in a write
    /// buffer and are only folded into the maintained counters when
    /// `run_pending_tasks()` runs. A cold read of either can report a
    /// live, actively-hit cache as empty.
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
    /// Used by the request-path "filter-on-cache-hit" guard: when a
    /// cached response contains a CNAME pointing to a newly-blocked
    /// target, or an A/AAAA record now caught by the IP blocklist, the
    /// handler invalidates the precise tuple it just looked up (no need
    /// to wipe all 22 type×class combinations). Same
    /// lowercase-normalization invariant as `invalidate_domain`.
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
    /// The iteration covers the "common queryable" set — A, AAAA, CNAME,
    /// MX, TXT, NS, SOA, plus the modern types HTTPS, SVCB, SRV, TLSA
    /// that the handler caches. An earlier version silently left the
    /// latter four in cache after an admin invalidation, a
    /// debuggability trap when wiping a stale entry. Moka's API
    /// requires invalidate-by-key so we cannot do a true type-agnostic
    /// wipe without scanning the entire cache; the explicit list is a
    /// pragmatic balance between cost (one invalidate call per type) and
    /// coverage of the types operators actually query.
    ///
    /// **Caveat:** when a per-profile ECS policy has populated cache
    /// entries with non-`None` `ecs_prefix` buckets,
    /// this admin path only invalidates the `None` slot — moka exposes
    /// no native "wipe by prefix" sweep over the key tuple, and we
    /// purposely keep the operator path snappy (22 probes, not 22 × N
    /// known prefixes). ECS-bucketed entries age out via TTL. Document
    /// this limitation in the CLI help and `warden cache flush
    /// --domain` semantics.
    pub async fn invalidate_domain(&self, domain: &str) {
        // Cache keys are stored lowercase. The hot path lookup/insert
        // sites are fed by `LowerName`, but the IPC admin path (`warden cache flush
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
mod tests;
