//! Background prefetch refresh worker.
//!
//! Reads the promoted-domain set from `HitTracker` every `tick_secs` and
//! proactively refreshes any entry whose remaining TTL has dropped below
//! `lead_secs`. Coexists with the TTL-triggered Approach A in
//! `dns::handler` — both share the `prefetch_semaphore` to bound total
//! concurrent in-flight refreshes.
//!
//! The worker refreshes `RecordType::A` only by design. The `HitTracker`
//! indexes by domain (no record type), so the worker has no signal for
//! which type to refresh. `A` covers the dominant traffic share; `AAAA`
//! / `HTTPS` / others fall back to Approach A on the next user query
//! within their TTL threshold window.
//!
//! Failure handling: a failed refresh logs `tracing::debug!` and does
//! NOT evict the about-to-expire entry. Approach A would do the same on
//! the next user query; the worker just retries on the next `tick_secs`.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use compact_str::CompactString;
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::DNSClass;
use hickory_proto::rr::{Name, RecordType};
use tokio::sync::Semaphore;
use tokio::time::{interval, MissedTickBehavior};

use crate::dns::cache::{CacheLookup, DnsCache};
use crate::dns::handler::cname_chain_blocked;
use crate::filter::cname::NamePolicy;
use crate::filter::ip_filter::IpFilter;
use crate::filter::FilterEngine;
use crate::tracking::HitTracker;
use crate::upstream::Upstream;

/// Run the worker forever. Spawned from `cli::commands::start::run` when
/// `cache.prefetch_tracker_enabled = true` and the shared
/// `prefetch_semaphore` is allocated. The future never returns under
/// normal operation; it dies with the process tokio runtime.
///
/// `cache` is taken by value because `DnsCache` is `#[derive(Clone)]`
/// (cheap moka-internal `Arc`), matching the pattern in
/// `handler.rs:739` where the existing Approach A spawn does
/// `let cache = cache.clone();` inline.
///
/// The 8-arg fan-out is intentional: this is the orchestrator entry
/// point and bundling the dependencies into a struct would just shift
/// the wiring noise from this signature into `start.rs` without
/// reducing the surface that has to be passed in.
#[allow(clippy::too_many_arguments)]
pub async fn run(
    upstream: Arc<dyn Upstream>,
    cache: DnsCache,
    filter: Arc<FilterEngine>,
    ip_filter: Option<Arc<IpFilter>>,
    tracker: Arc<HitTracker>,
    semaphore: Arc<Semaphore>,
    tick_secs: u64,
    lead_secs: u64,
    cname_max_depth: usize,
) {
    let mut ticker = interval(Duration::from_secs(tick_secs.max(1)));
    // After a long pause (laptop suspend, GC stall) we don't want a
    // catch-up burst of N refreshes — skip and resume normal cadence.
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    tracing::info!(
        tick_secs,
        lead_secs,
        worker = "prefetch",
        "background refresh worker started"
    );
    loop {
        ticker.tick().await;
        // Time-demote domains that have gone cold before refreshing, so
        // the worker stops keeping dead domains warm upstream. `now_secs`
        // is the same unix clock `record_hit` uses to stamp window
        // boundaries.
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let pool = tracker.snapshot_promoted_pruning_stale(now_secs);
        if pool.is_empty() {
            continue;
        }
        for domain in pool {
            // Worker invariant: refresh A only. AAAA/HTTPS rely on
            // Approach A. See module docs.
            let lookup = cache
                .lookup(&domain, RecordType::A, DNSClass::IN, None)
                .await;
            let CacheLookup::Fresh(entry) = lookup else {
                continue;
            };
            if !entry.needs_prefetch_lead(lead_secs) {
                continue;
            }
            // Non-blocking acquire: if the semaphore is saturated by
            // Approach A or a previous tick's refreshes, back off
            // until the next tick. Intentional bandwidth cap on
            // Pi-class hardware.
            let Ok(permit) = semaphore.clone().try_acquire_owned() else {
                continue;
            };
            let upstream_t = upstream.clone();
            let cache_t = cache.clone();
            let filter_t = filter.clone();
            let ip_filter_t = ip_filter.clone();
            let domain_t = domain.clone();
            tokio::spawn(async move {
                let _permit = permit;
                refresh_one(
                    upstream_t,
                    cache_t,
                    filter_t,
                    ip_filter_t,
                    &domain_t,
                    cname_max_depth,
                )
                .await;
            });
        }
    }
}

/// Issue one refresh upstream lookup for `domain` (RecordType::A,
/// DNSClass::IN) and insert the response into the cache iff the answer
/// is NoError + non-empty + the CNAME chain is clean. Mirrors the
/// Approach A spawn body in `handler.rs:734-800` so an operator
/// grepping for "prefetch" sees consistent behaviour.
async fn refresh_one(
    upstream: Arc<dyn Upstream>,
    cache: DnsCache,
    filter: Arc<FilterEngine>,
    ip_filter: Option<Arc<IpFilter>>,
    domain: &CompactString,
    cname_max_depth: usize,
) {
    // Re-check the apex against the blocklist before doing any work. A
    // domain promoted while allowed can be added to a blocklist *after*
    // promotion; the worker pulls from the promoted pool and would
    // otherwise keep it warm in cache. Not a bypass — the serve path
    // re-checks the filter on cache hit — but wasted upstream traffic +
    // cache occupancy. Mirrors the CNAME/IP guards below for apex
    // symmetry.
    if filter.is_blocked(domain.as_str()) {
        tracing::debug!(
            domain = %domain,
            worker = "prefetch",
            "refresh: apex now blocked, skipping"
        );
        return;
    }
    // Hickory's Name parser rejects the trailing-dot-less form for some
    // edge cases; the cache stores keys without trailing dot, so build
    // the Name fresh from the domain string.
    let name = match Name::from_ascii(format!("{domain}.")) {
        Ok(n) => n,
        Err(e) => {
            tracing::debug!(
                domain = %domain,
                worker = "prefetch",
                error = %e,
                "refresh: skipping (Name parse failed)"
            );
            return;
        }
    };
    // The prefetch worker has no per-client context — it refreshes the
    // shared (None-bucket) cache slot, so it passes `ecs = None` (and
    // the matching `ecs_prefix = None` below). Per-client ECS slots age
    // out via TTL and are repopulated on demand by the request path.
    match upstream
        .lookup_domain(domain.as_str(), &name, RecordType::A, None)
        .await
    {
        Ok(resp) if resp.response_code == ResponseCode::NoError && !resp.records.is_empty() => {
            // Mirror Approach A's CNAME safety check (handler.rs:762).
            // The worker has no per-client profile context — it works
            // against the shared filter engine only, same as Approach A.
            let cname_blocked =
                cname_chain_blocked(&resp.records, cname_max_depth, |t| filter.is_blocked(t))
                    .is_some();
            // IP-blocklist parity with the serve paths — pre-fix the
            // worker cached entries whose A/AAAA records the
            // request-path guard would refuse.
            //
            // `check_response` takes a `NamePolicy`, and this worker
            // passes `Neutral` for the same reason it passes the flat
            // `filter.is_blocked` closure above — it has no per-client
            // context and refreshes the SHARED cache slot, so the entry
            // it stores must be one every client may see. Fail-closed: a
            // name some device allows, whose answer is blocked, is simply
            // never prefetched. Hit-rate cost only; the request path
            // still allows it under that device's policy.
            let ip_blocked = ip_filter
                .as_deref()
                .and_then(|f| f.check_response(&resp.records, NamePolicy::Neutral))
                .is_some();
            if cname_blocked || ip_blocked {
                tracing::debug!(
                    domain = %domain,
                    worker = "prefetch",
                    cname = cname_blocked,
                    ip = ip_blocked,
                    "refresh: blocked content, skipping"
                );
                return;
            }
            cache
                .insert(
                    domain.as_str(),
                    RecordType::A,
                    DNSClass::IN,
                    resp.records,
                    ResponseCode::NoError,
                    None,
                    None, // ecs_prefix placeholder — prefetch worker has no client_ip
                )
                .await;
            tracing::debug!(
                domain = %domain,
                worker = "prefetch",
                "refresh complete"
            );
        }
        Ok(resp) => {
            tracing::debug!(
                domain = %domain,
                worker = "prefetch",
                response_code = ?resp.response_code,
                records_len = resp.records.len(),
                "refresh: skipping (non-NoError or empty response)"
            );
        }
        Err(e) => {
            tracing::debug!(
                domain = %domain,
                worker = "prefetch",
                error = %e,
                "refresh failed (no eviction)"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::settings::CacheConfig;
    use crate::dns::error::DnsError;
    use crate::tracking::PrefetchTrackerConfig;
    use crate::upstream::UpstreamResponse;
    use async_trait::async_trait;
    use hickory_proto::rr::Record;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    /// Mock upstream that records each lookup_domain call and returns
    /// a configurable response. Used to verify the worker's behaviour
    /// without standing up real DNS infrastructure.
    struct MockUpstream {
        calls: AtomicUsize,
        // Optional override: if Some, return this response; else NoError
        // with one synthetic A record so the cache.insert path runs.
        response: Mutex<Option<Result<UpstreamResponse, DnsError>>>,
    }

    impl MockUpstream {
        fn new() -> Self {
            Self {
                calls: AtomicUsize::new(0),
                response: Mutex::new(None),
            }
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::Relaxed)
        }
    }

    #[async_trait]
    impl Upstream for MockUpstream {
        async fn lookup(
            &self,
            name: &Name,
            _record_type: RecordType,
            _ecs: Option<crate::dns::edns::EdnsClientSubnet>,
        ) -> Result<UpstreamResponse, DnsError> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            let mut guard = self.response.lock().unwrap();
            if let Some(r) = guard.take() {
                return r;
            }
            // Default: synthetic NoError with one A record (TTL 60).
            let rdata = hickory_proto::rr::RData::A(hickory_proto::rr::rdata::A(
                std::net::Ipv4Addr::new(1, 2, 3, 4),
            ));
            let rec = Record::from_rdata(name.clone(), 60, rdata);
            Ok(UpstreamResponse {
                records: vec![rec],
                response_code: ResponseCode::NoError,
                soa_minimum_ttl: None,
                #[cfg(feature = "dnssec")]
                authority: vec![],
            })
        }
    }

    fn enabled_tracker_cfg() -> PrefetchTrackerConfig {
        PrefetchTrackerConfig {
            enabled: true,
            window_secs: 60,
            min_hits: 3,
            max_pool_size: 64,
        }
    }

    fn empty_filter_engine() -> Arc<FilterEngine> {
        // Empty engine — nothing blocked. Sufficient for the worker's
        // CNAME check (no records = no blocks).
        Arc::new(FilterEngine::new())
    }

    fn fresh_cache_config() -> CacheConfig {
        // Default config is sufficient — CacheConfig::default carries
        // the same fields the worker needs, and the worker is class-IN
        // / type-A only so most knobs are irrelevant.
        CacheConfig::default()
    }

    #[tokio::test]
    async fn worker_skips_when_pool_is_empty() {
        // No domains promoted → snapshot_promoted empty → no upstream
        // calls regardless of cache state.
        let upstream = Arc::new(MockUpstream::new());
        let cache = DnsCache::new(&fresh_cache_config());
        let filter = empty_filter_engine();
        let tracker = Arc::new(HitTracker::new(&enabled_tracker_cfg()));
        let sem = Arc::new(Semaphore::new(8));
        // refresh_one would be reached only if pool had entries — call
        // the inner step directly to verify pool guard.
        let pool = tracker.snapshot_promoted();
        assert!(pool.is_empty());
        // Sanity: no lookup_domain happens via direct loop reproduction.
        for d in pool {
            refresh_one(
                upstream.clone() as Arc<dyn Upstream>,
                cache.clone(),
                filter.clone(),
                None,
                &d,
                16,
            )
            .await;
        }
        assert_eq!(upstream.calls(), 0);
        assert_eq!(sem.available_permits(), 8);
    }

    #[tokio::test]
    async fn refresh_one_inserts_on_noerror_response() {
        let upstream = Arc::new(MockUpstream::new());
        let cache = DnsCache::new(&fresh_cache_config());
        let filter = empty_filter_engine();
        let domain = CompactString::from("hot.example");
        // Pre-condition: cache empty for this key.
        let lookup = cache
            .lookup(&domain, RecordType::A, DNSClass::IN, None)
            .await;
        assert!(matches!(lookup, CacheLookup::Miss));
        refresh_one(
            upstream.clone() as Arc<dyn Upstream>,
            cache.clone(),
            filter,
            None,
            &domain,
            16,
        )
        .await;
        assert_eq!(upstream.calls(), 1);
        // Post-condition: cache now has a fresh entry.
        let lookup = cache
            .lookup(&domain, RecordType::A, DNSClass::IN, None)
            .await;
        assert!(matches!(lookup, CacheLookup::Fresh(_)));
    }

    #[tokio::test]
    async fn refresh_one_skips_on_ip_blocked_response() {
        // A refresh whose answer contains an IP-blocklisted address must
        // NOT land in the cache — parity with the request-path serve
        // guards.
        let upstream = Arc::new(MockUpstream::new());
        // MockUpstream default answer is 1.2.3.4 — blocklist exactly that.
        let mut ips: std::collections::HashSet<std::net::IpAddr, ahash::RandomState> =
            std::collections::HashSet::default();
        ips.insert(std::net::IpAddr::from(std::net::Ipv4Addr::new(1, 2, 3, 4)));
        let ip_filter = Some(Arc::new(IpFilter::with_ips(ips)));
        let cache = DnsCache::new(&fresh_cache_config());
        let filter = empty_filter_engine();
        let domain = CompactString::from("ipblocked.example");
        refresh_one(
            upstream.clone() as Arc<dyn Upstream>,
            cache.clone(),
            filter,
            ip_filter,
            &domain,
            16,
        )
        .await;
        assert_eq!(upstream.calls(), 1);
        // Cache stays empty — the blocked answer was discarded.
        let lookup = cache
            .lookup(&domain, RecordType::A, DNSClass::IN, None)
            .await;
        assert!(matches!(lookup, CacheLookup::Miss));
    }

    #[tokio::test]
    async fn refresh_one_does_not_insert_on_servfail() {
        let upstream = Arc::new(MockUpstream::new());
        // Override: return SERVFAIL, no records.
        *upstream.response.lock().unwrap() = Some(Ok(UpstreamResponse {
            records: vec![],
            response_code: ResponseCode::ServFail,
            soa_minimum_ttl: None,
            #[cfg(feature = "dnssec")]
            authority: vec![],
        }));
        let cache = DnsCache::new(&fresh_cache_config());
        let filter = empty_filter_engine();
        let domain = CompactString::from("broken.example");
        refresh_one(
            upstream.clone() as Arc<dyn Upstream>,
            cache.clone(),
            filter,
            None,
            &domain,
            16,
        )
        .await;
        assert_eq!(upstream.calls(), 1);
        // Cache unchanged — SERVFAIL is not cached, no eviction either.
        let lookup = cache
            .lookup(&domain, RecordType::A, DNSClass::IN, None)
            .await;
        assert!(matches!(lookup, CacheLookup::Miss));
    }

    #[tokio::test]
    async fn refresh_one_does_not_insert_on_upstream_error() {
        let upstream = Arc::new(MockUpstream::new());
        *upstream.response.lock().unwrap() =
            Some(Err(DnsError::UpstreamRequestFailed("synthetic".into())));
        let cache = DnsCache::new(&fresh_cache_config());
        let filter = empty_filter_engine();
        let domain = CompactString::from("timeout.example");
        refresh_one(
            upstream.clone() as Arc<dyn Upstream>,
            cache.clone(),
            filter,
            None,
            &domain,
            16,
        )
        .await;
        assert_eq!(upstream.calls(), 1);
        let lookup = cache
            .lookup(&domain, RecordType::A, DNSClass::IN, None)
            .await;
        assert!(matches!(lookup, CacheLookup::Miss));
    }

    #[tokio::test]
    async fn refresh_one_skips_on_invalid_domain_name() {
        // A domain that fails Name::from_ascii — no upstream call should
        // happen, no panic, no insert.
        let upstream = Arc::new(MockUpstream::new());
        let cache = DnsCache::new(&fresh_cache_config());
        let filter = empty_filter_engine();
        // ".." after the format!("{domain}.") becomes "...", which is an
        // invalid empty-label sequence.
        let domain = CompactString::from("..");
        refresh_one(
            upstream.clone() as Arc<dyn Upstream>,
            cache.clone(),
            filter,
            None,
            &domain,
            16,
        )
        .await;
        assert_eq!(upstream.calls(), 0);
    }
}
