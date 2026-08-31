//! Integration tests for s44-arch-cache-invalidate-on-block (M-12 follow-up).
//!
//! The post-cache-hit splice in `dns::handler::handle_inner` re-runs the
//! CNAME chain and IP-blocklist checks against the cached `entry.records()`
//! before serving them. On trip it invalidates the precise cache tuple and
//! falls back to the canned block path. These integration tests drive the
//! exact composition (insert → lookup → re-check → invalidate_key) through
//! the public crate surface, mirroring what the hot-path splice does on a
//! real cache hit. End-to-end DNS handler tests with a live listener live
//! in the CT smoke matrix on `the lab host` (see `_docs/features/...` handoff
//! and the kickoff `s44-arch-cache-invalidate-on-block` in TODO.json).
//!
//! Two scenarios pin M-12 specifically:
//! 1. **CNAME race:** cached `D CNAME → C` survives across an operator
//!    `warden rule add deny C` until the cache TTL expires unless the
//!    handler invalidates on hit. The first integration test drives this.
//! 2. **IP-blocklist race:** cached `D A 1.2.3.4` survives across an
//!    operator adding 1.2.3.4 to the IP blocklist until TTL. The second
//!    integration test drives this.
//!
//! Reload-race coverage is folded into both tests: the filter / blocklist
//! is constructed AFTER the cache entry is populated, mirroring the
//! "cache populated → operator adds rule → next query" timeline.

use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;

use compact_str::CompactString;
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::rdata::{A, CNAME};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};

use purge_warden::config::settings::CacheConfig;
use purge_warden::dns::cache::{CacheLookup, DnsCache};
use purge_warden::filter::cname::NamePolicy;
use purge_warden::filter::ip_filter::IpFilter;
use purge_warden::filter::FilterEngine;

fn config() -> CacheConfig {
    CacheConfig {
        max_entries: 100,
        max_ttl_secs: 3600,
        min_ttl_secs: 5,
        negative_ttl_secs: 60,
        stale_buffer_secs: 300,
        prefetch: false,
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

fn cname_record(alias: &str, target: &str, ttl: u32) -> Record {
    Record::from_rdata(
        Name::from_str(alias).unwrap(),
        ttl,
        RData::CNAME(CNAME(Name::from_str(target).unwrap())),
    )
}

fn a_record(domain: &str, ip: [u8; 4], ttl: u32) -> Record {
    Record::from_rdata(
        Name::from_str(domain).unwrap(),
        ttl,
        RData::A(A(Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]))),
    )
}

#[tokio::test]
async fn m12_cname_race_post_population_rule_add_invalidates_on_hit() {
    // Timeline:
    //   T0: dig alias.example.com → upstream returns CNAME → tracker.evil.com
    //       → A 1.2.3.4. Cache populated.
    //   T1: operator runs `warden rule add deny tracker.evil.com`. The
    //       filter snapshot now contains tracker.evil.com.
    //   T2: dig alias.example.com (again). The handler:
    //       (a) evaluate_with_overlay(alias.example.com) is allow (not
    //           directly blocked).
    //       (b) cache.lookup returns Fresh.
    //       (c) post-cache-hit re-check (this branch) runs
    //           check_cname_chain on entry.records() and catches
    //           tracker.evil.com — invalidate_key + canned block.
    //       (d) cache.lookup is now a miss; subsequent dig would go
    //           upstream and re-check from the top.
    let cache = DnsCache::new(&config());
    cache
        .insert(
            "alias.example.com",
            RecordType::A,
            DNSClass::IN,
            vec![
                cname_record("alias.example.com.", "tracker.evil.com.", 300),
                a_record("tracker.evil.com.", [1, 2, 3, 4], 300),
            ],
            ResponseCode::NoError,
            None,
            None,
        )
        .await;

    // T1: operator adds the deny rule. This is the moment a filter
    // snapshot ArcSwap fires in production.
    let blocked: ahash::HashSet<CompactString> =
        std::iter::once(CompactString::from("tracker.evil.com")).collect();
    let filter = FilterEngine::with_domains(blocked);

    // T2: simulate the cache-hit branch's re-check.
    let lookup = cache
        .lookup("alias.example.com", RecordType::A, DNSClass::IN, None)
        .await;
    let entry = match lookup {
        CacheLookup::Fresh(e) => e,
        _ => panic!("entry was just populated, must be fresh"),
    };

    // The new helper in handler.rs is `check_cname_chain` — but for the
    // integration test we use the same lower-level walker the splice
    // exercises: any CNAME target landing in the deny set must trip.
    let mut tripped: Option<String> = None;
    for record in entry.records() {
        if record.record_type() == RecordType::CNAME {
            if let RData::CNAME(ref t) = record.data {
                let target = t.to_string();
                let target_norm = target.trim_end_matches('.').to_ascii_lowercase();
                if filter.is_blocked(&target_norm) {
                    tripped = Some(target_norm);
                    break;
                }
            }
        }
    }
    let tripped = tripped.expect("M-12 CNAME race must trip the post-cache-hit re-check");
    assert_eq!(tripped, "tracker.evil.com");

    // The handler's splice now invalidates the exact tuple it just
    // looked up, then sends a canned block. The cache must NOT serve
    // this entry again.
    cache
        .invalidate_key("alias.example.com", RecordType::A, DNSClass::IN, None)
        .await;
    assert!(matches!(
        cache
            .lookup("alias.example.com", RecordType::A, DNSClass::IN, None)
            .await,
        CacheLookup::Miss
    ));
}

#[tokio::test]
async fn m12_ip_blocklist_race_post_population_invalidates_on_hit() {
    // Symmetric to the CNAME race but for the IP blocklist axis. A
    // cached A record points at 1.2.3.4. After the cache populates, the
    // operator adds 1.2.3.4 to the IP blocklist. The next cache hit
    // must trip the IP re-check, invalidate, and block.
    let cache = DnsCache::new(&config());
    cache
        .insert(
            "fastflux.example.com",
            RecordType::A,
            DNSClass::IN,
            vec![a_record("fastflux.example.com.", [1, 2, 3, 4], 300)],
            ResponseCode::NoError,
            None,
            None,
        )
        .await;

    let mut bad_ips: ahash::HashSet<IpAddr> = ahash::HashSet::default();
    bad_ips.insert(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));
    let ipf = IpFilter::with_ips(bad_ips);

    let entry = match cache
        .lookup("fastflux.example.com", RecordType::A, DNSClass::IN, None)
        .await
    {
        CacheLookup::Fresh(e) => e,
        _ => panic!("entry was just populated, must be fresh"),
    };

    assert_eq!(
        ipf.check_response(entry.records(), NamePolicy::Neutral),
        Some(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))),
        "M-12 IP race must trip the post-cache-hit re-check"
    );

    cache
        .invalidate_key("fastflux.example.com", RecordType::A, DNSClass::IN, None)
        .await;
    assert!(matches!(
        cache
            .lookup("fastflux.example.com", RecordType::A, DNSClass::IN, None)
            .await,
        CacheLookup::Miss
    ));
}

// --- §4.42 stale-fallback re-check coverage ---
//
// The §4.42 fix in `dns/handler.rs` mirrors the M-12 fresh-cache-hit
// guard onto the stale-cache fallback path (the
// `Err(FetchFailure { stale: Some(entry), error })` arm). Pre-fix, a
// deny rule added at runtime while upstream was unreachable was
// silently bypassed for any pre-existing cached entry. Post-fix, the
// stale arm runs the same `walk_response` + `ip_filter.check_response`
// guards before serving the cached records, invalidates on trip, and
// dispatches the canned block response via the shared helper.
//
// These tests follow the same composition shape as the M-12 tests
// above: drive the lower-level walker against records pulled from the
// cache, with the filter / IP blocklist constructed AFTER the cache
// populated (mirrors the "cached → operator adds rule → upstream goes
// down → stale serve" timeline). End-to-end handler wiring is pinned
// by the CT-smoke matrix on `the lab host` (forced upstream outage +
// runtime rule add).

#[tokio::test]
async fn stale_path_cname_block_re_check_invalidates() {
    // Timeline:
    //   T0: cache populated with alias.example.com CNAME → tracker.evil.com,
    //       record TTL = 1s. CacheConfig.min_ttl_secs = 0 so the cache
    //       does not clamp the TTL upward.
    //   T1: 1.1s wait — entry transitions Fresh → Stale (post-TTL but
    //       still within the stale buffer that handler.rs falls back on
    //       when upstream fails).
    //   T2: operator runs `warden rule add deny tracker.evil.com`.
    //   T3: upstream fails. handler.rs's `Err(FetchFailure { stale:
    //       Some(entry), .. })` arm (post-§4.42) re-runs walk_response
    //       on entry.records() — must trip on tracker.evil.com instead
    //       of serving the cached A record via send_cached.
    let cfg = CacheConfig {
        min_ttl_secs: 0,
        ..config()
    };
    let cache = DnsCache::new(&cfg);
    cache
        .insert(
            "alias.example.com",
            RecordType::A,
            DNSClass::IN,
            vec![
                cname_record("alias.example.com.", "tracker.evil.com.", 1),
                a_record("tracker.evil.com.", [1, 2, 3, 4], 1),
            ],
            ResponseCode::NoError,
            None,
            None,
        )
        .await;

    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;

    let lookup = cache
        .lookup("alias.example.com", RecordType::A, DNSClass::IN, None)
        .await;
    let entry = match lookup {
        CacheLookup::Stale(e) => e,
        _ => panic!("entry should be Stale after TTL expiry (pre-stale-buffer)"),
    };

    // Post-population rule add — mirrors a runtime ArcSwap of the filter.
    let blocked: ahash::HashSet<CompactString> =
        std::iter::once(CompactString::from("tracker.evil.com")).collect();
    let filter = FilterEngine::with_domains(blocked);

    // Mirror what the §4.42 stale-fallback guard does: scan the cached
    // CNAME chain for a deny-set hit. The handler's live path uses
    // `walk_response` from `filter::cname`; we open-code the same scan
    // to match the existing M-12 test pattern and avoid pulling in
    // ResolvedProfile fixtures.
    let mut tripped: Option<String> = None;
    for record in entry.records() {
        if record.record_type() == RecordType::CNAME {
            if let RData::CNAME(ref t) = record.data {
                let target = t.to_string();
                let target_norm = target.trim_end_matches('.').to_ascii_lowercase();
                if filter.is_blocked(&target_norm) {
                    tripped = Some(target_norm);
                    break;
                }
            }
        }
    }
    let tripped = tripped.expect(
        "§4.42 stale-fallback guard must trip on cached CNAME chain when target now denied",
    );
    assert_eq!(tripped, "tracker.evil.com");

    // After the live helper invalidates the bucket, the cache must not
    // surface the entry again — not even as Stale.
    cache
        .invalidate_key("alias.example.com", RecordType::A, DNSClass::IN, None)
        .await;
    assert!(matches!(
        cache
            .lookup("alias.example.com", RecordType::A, DNSClass::IN, None)
            .await,
        CacheLookup::Miss
    ));
}

#[tokio::test]
async fn stale_path_ip_block_re_check_invalidates() {
    // Symmetric to `stale_path_cname_block_re_check_invalidates` for the
    // IP-blocklist axis: cache populated with an A record, runtime
    // blocklist add for the response IP, then verify the §4.42 stale
    // guard would trip via `ip_filter::IpFilter::check_response`.
    let cfg = CacheConfig {
        min_ttl_secs: 0,
        ..config()
    };
    let cache = DnsCache::new(&cfg);
    cache
        .insert(
            "fastflux.example.com",
            RecordType::A,
            DNSClass::IN,
            vec![a_record("fastflux.example.com.", [1, 2, 3, 4], 1)],
            ResponseCode::NoError,
            None,
            None,
        )
        .await;

    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;

    let lookup = cache
        .lookup("fastflux.example.com", RecordType::A, DNSClass::IN, None)
        .await;
    let entry = match lookup {
        CacheLookup::Stale(e) => e,
        _ => panic!("entry should be Stale after TTL expiry (pre-stale-buffer)"),
    };

    let mut bad_ips: ahash::HashSet<IpAddr> = ahash::HashSet::default();
    bad_ips.insert(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));
    let ipf = IpFilter::with_ips(bad_ips);

    assert_eq!(
        ipf.check_response(entry.records(), NamePolicy::Neutral),
        Some(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))),
        "§4.42 stale-fallback guard must trip on the cached A record's now-blocked IP"
    );

    cache
        .invalidate_key("fastflux.example.com", RecordType::A, DNSClass::IN, None)
        .await;
    assert!(matches!(
        cache
            .lookup("fastflux.example.com", RecordType::A, DNSClass::IN, None)
            .await,
        CacheLookup::Miss
    ));
}
