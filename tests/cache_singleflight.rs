//! Integration test for T3.2.b M-12 — singleflight stampede protection.
//!
//! `DnsCache::lookup_or_fetch` wraps moka's `try_get_with`, which collapses
//! N concurrent fetches for the same key into 1 closure invocation. The
//! handler's cache MISS branch (handler.rs::handle_inner, post-T3.2.b)
//! relies on this to prevent thundering-herd upstream queries when N
//! clients race for an uncached hot domain (cert renewals, social-login
//! storms, fresh CDN endpoints).
//!
//! The unit tests in `src/dns/cache.rs` (T3.2.b commit 2/4) cover the
//! contract surface in isolation: SOA-hint propagation, Uncacheable
//! exclusion, defense-in-depth Ok-with-SERVFAIL rejection, stale fallback,
//! fresh-hit fast path. This integration test pins the *coalescing*
//! invariant — the architectural value of the wire-up — by spawning N
//! concurrent tasks against a counter-backed mock fetcher and asserting
//! the counter ends at exactly 1.
//!
//! Without this test the singleflight property is mole-blind: an
//! accidental refactor that bypasses `try_get_with` (e.g. switching to
//! `get_with` then a manual insert) would still pass every unit test
//! while regressing N→1 to N→N upstream calls.

use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use hickory_proto::op::ResponseCode;
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::DNSClass;
use hickory_proto::rr::{Name, RData, Record, RecordType};

use purge_warden::config::settings::CacheConfig;
use purge_warden::dns::cache::DnsCache;
use purge_warden::dns::error::DnsError;

fn cache_config() -> CacheConfig {
    CacheConfig {
        max_entries: 1024,
        max_ttl_secs: 3600,
        min_ttl_secs: 5,
        negative_ttl_secs: 60,
        stale_buffer_secs: 300,
        prefetch: false,
        prefetch_threshold: 0.0,
        prefetch_max_concurrent: 1,
        cname_max_depth: 16,
        prefetch_tracker_enabled: false,
        prefetch_tracker_window_secs: 300,
        prefetch_tracker_min_hits: 3,
        prefetch_tracker_max_pool_size: 1024,
        prefetch_tracker_tick_secs: 30,
        prefetch_tracker_lead_secs: 10,
    }
}

fn a_record(domain: &str, ttl: u32) -> Record {
    Record::from_rdata(
        Name::from_ascii(format!("{}.", domain)).unwrap(),
        ttl,
        RData::A(A(Ipv4Addr::new(1, 2, 3, 4))),
    )
}

/// Spawn N concurrent `lookup_or_fetch` tasks for the same key against a
/// counter-backed fetcher that sleeps long enough for waiters to pile up
/// on the singleflight registry, then assert the counter is exactly 1.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn singleflight_collapses_concurrent_misses_to_one_fetch() {
    const N: usize = 32;
    let cache = Arc::new(DnsCache::new(&cache_config()));
    let counter = Arc::new(AtomicU64::new(0));

    let mut handles = Vec::with_capacity(N);
    for _ in 0..N {
        let cache = Arc::clone(&cache);
        let counter = Arc::clone(&counter);
        handles.push(tokio::spawn(async move {
            cache
                .lookup_or_fetch(
                    "example.com",
                    RecordType::A,
                    DNSClass::IN,
                    None,
                    move || async move {
                        // Bump counter then sleep so concurrent waiters
                        // queue up on the singleflight registry before
                        // this leader closure resolves.
                        counter.fetch_add(1, Ordering::SeqCst);
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        Ok((
                            vec![a_record("example.com", 300)],
                            ResponseCode::NoError,
                            None,
                        ))
                    },
                )
                .await
                .map(|entry| entry.records().len())
        }));
    }

    let mut ok_count = 0usize;
    for h in handles {
        if let Ok(Ok(len)) = h.await {
            assert_eq!(
                len, 1,
                "every concurrent caller must see the 1-record response"
            );
            ok_count += 1;
        }
    }

    assert_eq!(
        ok_count, N,
        "all {} concurrent callers must converge on Ok",
        N
    );
    let observed = counter.load(Ordering::SeqCst);
    assert_eq!(
        observed, 1,
        "singleflight invariant violated: expected 1 fetcher invocation across {} concurrent callers, observed {}",
        N, observed
    );
}

/// Negative-response equivalent: N concurrent NXDOMAIN fetches must also
/// coalesce to 1 closure invocation. The closure carries the SOA hint
/// through to the cache entry, and try_get_with caches the negative
/// result so subsequent waiters see it without re-fetching.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn singleflight_collapses_concurrent_negative_misses() {
    const N: usize = 16;
    let cache = Arc::new(DnsCache::new(&cache_config()));
    let counter = Arc::new(AtomicU64::new(0));

    let mut handles = Vec::with_capacity(N);
    for _ in 0..N {
        let cache = Arc::clone(&cache);
        let counter = Arc::clone(&counter);
        handles.push(tokio::spawn(async move {
            cache
                .lookup_or_fetch(
                    "missing.example",
                    RecordType::A,
                    DNSClass::IN,
                    None,
                    move || async move {
                        counter.fetch_add(1, Ordering::SeqCst);
                        tokio::time::sleep(Duration::from_millis(30)).await;
                        Ok((Vec::new(), ResponseCode::NXDomain, Some(300)))
                    },
                )
                .await
                .map(|entry| entry.response_code())
        }));
    }

    for h in handles {
        let rc = h.await.expect("spawn").expect("ok");
        assert_eq!(rc, ResponseCode::NXDomain);
    }
    assert_eq!(
        counter.load(Ordering::SeqCst),
        1,
        "negative-response singleflight invariant violated"
    );
}

/// SERVFAIL coalesces too — N concurrent waiters all share the same Err,
/// but the result is NOT cached so a follow-up call after they complete
/// runs a fresh fetcher. Validates that try_get_with semantics give us
/// "coalesce in flight, never cache" for non-cacheable responses.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn singleflight_servfail_coalesces_in_flight_but_does_not_cache() {
    const N: usize = 8;
    let cache = Arc::new(DnsCache::new(&cache_config()));
    let counter = Arc::new(AtomicU64::new(0));

    // Round 1: N concurrent SERVFAIL fetches → 1 closure invocation.
    let mut handles = Vec::with_capacity(N);
    for _ in 0..N {
        let cache = Arc::clone(&cache);
        let counter = Arc::clone(&counter);
        handles.push(tokio::spawn(async move {
            cache
                .lookup_or_fetch(
                    "broken.example",
                    RecordType::A,
                    DNSClass::IN,
                    None,
                    move || async move {
                        counter.fetch_add(1, Ordering::SeqCst);
                        tokio::time::sleep(Duration::from_millis(30)).await;
                        Err(DnsError::Uncacheable(ResponseCode::ServFail))
                    },
                )
                .await
                .err()
                .map(|f| match f.error.as_ref() {
                    DnsError::Uncacheable(rc) => *rc,
                    _ => panic!("expected Uncacheable"),
                })
        }));
    }
    for h in handles {
        let rc = h.await.expect("spawn").expect("err");
        assert_eq!(rc, ResponseCode::ServFail);
    }
    assert_eq!(
        counter.load(Ordering::SeqCst),
        1,
        "round 1: in-flight SERVFAIL must coalesce to 1 closure invocation"
    );

    // Round 2: try_get_with did NOT cache the SERVFAIL — the next call
    // runs a fresh closure invocation, bringing the counter to 2.
    let counter_round2 = Arc::clone(&counter);
    let _ = cache
        .lookup_or_fetch(
            "broken.example",
            RecordType::A,
            DNSClass::IN,
            None,
            move || async move {
                counter_round2.fetch_add(1, Ordering::SeqCst);
                Err(DnsError::Uncacheable(ResponseCode::ServFail))
            },
        )
        .await;
    assert_eq!(
        counter.load(Ordering::SeqCst),
        2,
        "round 2: SERVFAIL must NOT have been cached — closure must run again"
    );
}
