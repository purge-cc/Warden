use super::*;
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData};
use std::net::Ipv4Addr;

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

impl DnsCache {
    /// Force pending maintenance tasks (useful in tests).
    pub async fn run_pending_tasks(&self) {
        self.cache.run_pending_tasks().await;
    }
}

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
    let p1 = ecs_prefix("10.10.1.0", 24);
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
            Some(ecs_prefix("10.10.1.0", 24)),
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
    let p1 = ecs_prefix("10.10.1.0", 24);
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
