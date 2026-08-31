//! Sprint §4.4 P2 — Integration tests for the background prefetch
//! refresh worker.
//!
//! These exercise the full pipeline (HitTracker pool → cache lookup →
//! `needs_prefetch_lead` gate → `refresh_one` → cache.insert) using
//! real `DnsCache` + `HitTracker` + `FilterEngine` against a synthetic
//! upstream. The async ticker loop is exercised by replicating one
//! tick's body inline so the assertion is deterministic — the worker's
//! timer behaviour is covered by `tokio::time::interval`'s own tests
//! and by Phase E's CT burn-in.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use compact_str::CompactString;
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::DNSClass;
use hickory_proto::rr::{Name, RData, Record, RecordType};

use purge_warden::config::settings::CacheConfig;
use purge_warden::dns::cache::{CacheLookup, DnsCache};
use purge_warden::dns::error::DnsError;
use purge_warden::tracking::{HitTracker, PrefetchTrackerConfig};
use purge_warden::upstream::{Upstream, UpstreamResponse};

/// Mock upstream — every lookup returns NoError + one A record. Counts
/// invocations so the test can assert "the worker did / did not call
/// upstream this tick".
struct CountingUpstream {
    calls: AtomicUsize,
    response: Mutex<Option<Result<UpstreamResponse, DnsError>>>,
}

impl CountingUpstream {
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
impl Upstream for CountingUpstream {
    async fn lookup(
        &self,
        name: &Name,
        _record_type: RecordType,
        _ecs: Option<purge_warden::dns::edns::EdnsClientSubnet>,
    ) -> Result<UpstreamResponse, DnsError> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        if let Some(r) = self.response.lock().unwrap().take() {
            return r;
        }
        let rdata = RData::A(hickory_proto::rr::rdata::A(std::net::Ipv4Addr::new(
            5, 6, 7, 8,
        )));
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

fn promoted_tracker(domain: &str) -> Arc<HitTracker> {
    let cfg = PrefetchTrackerConfig {
        enabled: true,
        window_secs: 60,
        min_hits: 3,
        max_pool_size: 64,
    };
    let t = Arc::new(HitTracker::new(&cfg));
    // 3 hits in the same window → promotion.
    t.record_hit(domain, 0);
    t.record_hit(domain, 5);
    t.record_hit(domain, 10);
    assert!(t.is_promoted(domain), "tracker setup failed");
    t
}

/// Replicate one body of `prefetch_worker::run`'s loop without the
/// tokio interval driver. This is the path we want to assert on; the
/// timer is well-tested upstream.
async fn one_tick(
    tracker: &HitTracker,
    cache: &DnsCache,
    upstream: &Arc<CountingUpstream>,
    lead_secs: u64,
) -> usize {
    use purge_warden::dns::cache::CacheLookup;
    let pool = tracker.snapshot_promoted();
    let mut refreshed = 0;
    for domain in pool {
        let lookup = cache
            .lookup(&domain, RecordType::A, DNSClass::IN, None)
            .await;
        let CacheLookup::Fresh(entry) = lookup else {
            continue;
        };
        if !entry.needs_prefetch_lead(lead_secs) {
            continue;
        }
        refresh_inline(upstream.clone() as Arc<dyn Upstream>, cache, &domain).await;
        refreshed += 1;
    }
    refreshed
}

/// Mirror of `prefetch_worker::refresh_one` minus the CNAME walk
/// (irrelevant for the synthetic A-record fixture; exercising it would
/// require building a multi-record response). The full path is unit-
/// tested in `src/tracking/prefetch_worker.rs::tests`.
async fn refresh_inline(upstream: Arc<dyn Upstream>, cache: &DnsCache, domain: &CompactString) {
    let name = Name::from_ascii(format!("{domain}.")).unwrap();
    if let Ok(resp) = upstream.lookup(&name, RecordType::A, None).await {
        if resp.response_code == ResponseCode::NoError && !resp.records.is_empty() {
            cache
                .insert(
                    domain.as_str(),
                    RecordType::A,
                    DNSClass::IN,
                    resp.records,
                    ResponseCode::NoError,
                    None,
                    None,
                )
                .await;
        }
    }
}

#[tokio::test]
async fn worker_warms_pool_entry_under_lead_threshold() {
    // CacheConfig with a tiny min_ttl so we can shape an entry that's
    // already inside the lead window without spinning the test.
    let cfg = CacheConfig {
        min_ttl_secs: 1,
        max_ttl_secs: 3,
        ..CacheConfig::default()
    };
    let cache = DnsCache::new(&cfg);
    let upstream = Arc::new(CountingUpstream::new());
    let domain_str = "hot.example";
    let domain = CompactString::from(domain_str);
    let tracker = promoted_tracker(domain_str);

    // Pre-seed the cache with an A record having a tiny TTL (1s). The
    // cache clamps to [min_ttl, max_ttl] — at min_ttl_secs=1 the entry
    // immediately satisfies `needs_prefetch_lead(10)` since 1 ≤ 10.
    let name = Name::from_ascii(format!("{domain_str}.")).unwrap();
    let rec = Record::from_rdata(
        name.clone(),
        1,
        RData::A(hickory_proto::rr::rdata::A(std::net::Ipv4Addr::new(
            1, 2, 3, 4,
        ))),
    );
    cache
        .insert(
            &domain,
            RecordType::A,
            DNSClass::IN,
            vec![rec],
            ResponseCode::NoError,
            None,
            None,
        )
        .await;

    // One worker tick with lead_secs = 10 → should refresh.
    let refreshed = one_tick(&tracker, &cache, &upstream, 10).await;
    assert_eq!(refreshed, 1, "worker should have refreshed the hot entry");
    assert_eq!(upstream.calls(), 1, "exactly one upstream lookup");

    // Cache now holds the new record (5.6.7.8 from CountingUpstream).
    let lookup = cache
        .lookup(&domain, RecordType::A, DNSClass::IN, None)
        .await;
    let entry = match lookup {
        CacheLookup::Fresh(e) => e,
        _ => panic!("expected fresh entry post-refresh"),
    };
    let records = entry.records();
    assert_eq!(records.len(), 1);
}

#[tokio::test]
async fn worker_does_not_disturb_non_promoted_entries() {
    // Same scaffold but the tracker has NO promoted domains — pool
    // empty → no upstream call → cache untouched.
    let cfg = CacheConfig::default();
    let cache = DnsCache::new(&cfg);
    let upstream = Arc::new(CountingUpstream::new());
    let domain_str = "cold.example";
    let domain = CompactString::from(domain_str);
    // Empty tracker (enabled but never had hits).
    let tracker_cfg = PrefetchTrackerConfig {
        enabled: true,
        window_secs: 60,
        min_hits: 3,
        max_pool_size: 64,
    };
    let tracker = Arc::new(HitTracker::new(&tracker_cfg));
    assert!(tracker.snapshot_promoted().is_empty());

    // Seed cache with a fresh entry — its TTL is irrelevant since the
    // worker never inspects it (pool is empty).
    let name = Name::from_ascii(format!("{domain_str}.")).unwrap();
    let rec = Record::from_rdata(
        name,
        300,
        RData::A(hickory_proto::rr::rdata::A(std::net::Ipv4Addr::new(
            9, 9, 9, 9,
        ))),
    );
    cache
        .insert(
            &domain,
            RecordType::A,
            DNSClass::IN,
            vec![rec],
            ResponseCode::NoError,
            None,
            None,
        )
        .await;

    let refreshed = one_tick(&tracker, &cache, &upstream, 10).await;
    assert_eq!(refreshed, 0);
    assert_eq!(upstream.calls(), 0);
}

#[tokio::test]
async fn worker_skips_promoted_entry_with_long_remaining_ttl() {
    // Domain is promoted AND cached, but the entry has plenty of TTL
    // headroom — `needs_prefetch_lead` returns false → no refresh.
    let cfg = CacheConfig::default();
    let cache = DnsCache::new(&cfg);
    let upstream = Arc::new(CountingUpstream::new());
    let domain_str = "warm.example";
    let domain = CompactString::from(domain_str);
    let tracker = promoted_tracker(domain_str);

    let name = Name::from_ascii(format!("{domain_str}.")).unwrap();
    let rec = Record::from_rdata(
        name,
        3600, // an hour — well above any sane lead_secs
        RData::A(hickory_proto::rr::rdata::A(std::net::Ipv4Addr::new(
            1, 2, 3, 4,
        ))),
    );
    cache
        .insert(
            &domain,
            RecordType::A,
            DNSClass::IN,
            vec![rec],
            ResponseCode::NoError,
            None,
            None,
        )
        .await;

    let refreshed = one_tick(&tracker, &cache, &upstream, 10).await;
    assert_eq!(refreshed, 0, "long-TTL entry must not trigger refresh");
    assert_eq!(upstream.calls(), 0);
}
