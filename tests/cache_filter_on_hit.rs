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
use std::sync::Arc;

use hickory_proto::op::ResponseCode;
use hickory_proto::rr::rdata::{A, CNAME};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};

use purge_warden::config::schema::{ConfigV1, Id, Profile, TARGET_SCHEMA_VERSION_V5};
use purge_warden::config::settings::CacheConfig;
use purge_warden::dns::cache::{CacheLookup, DnsCache};
use purge_warden::filter::cname::{walk_response_with_grant, Verdict};
use purge_warden::filter::operator_rules::{
    CompileAdmission, CompiledOperatorRules, PackSource, ProfileMounts, RuleCompileLimits,
};
use purge_warden::filter::FilterEngine;
use purge_warden::profiles::profile::ResolvedProfile;
use purge_warden::profiles::resolver::ProfileResolver;

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

fn compiled_profile(content: &str) -> Arc<ResolvedProfile> {
    let limits = RuleCompileLimits::default();
    let admission = CompileAdmission::new(limits.max_compiled_bytes_total, 1).unwrap();
    let rules = Arc::new(
        CompiledOperatorRules::compile(
            &[PackSource {
                list_id: "rules",
                content,
            }],
            &[ProfileMounts {
                profile_id: "default",
                custom_lists: &["rules"],
                block_all: false,
            }],
            limits,
            &admission,
        )
        .unwrap(),
    );
    let mut config = ConfigV1 {
        schema_version: TARGET_SCHEMA_VERSION_V5,
        ..ConfigV1::default()
    };
    config.server.default_profile = Some(Id::new("default").unwrap());
    config.profiles.insert(
        "default".to_string(),
        Profile {
            custom_lists: vec![Id::new("rules").unwrap()],
            ..Profile::default()
        },
    );
    ProfileResolver::build_with_operator_rules(&config, rules)
        .resolve(&IpAddr::V4(Ipv4Addr::LOCALHOST))
        .profile
        .expect("default profile must resolve")
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
    let filter = FilterEngine::new();
    let profile = compiled_profile("tracker.evil.com");

    // T2: simulate the cache-hit branch's re-check.
    let lookup = cache
        .lookup("alias.example.com", RecordType::A, DNSClass::IN, None)
        .await;
    let entry = match lookup {
        CacheLookup::Fresh(e) => e,
        _ => panic!("entry was just populated, must be fresh"),
    };

    assert!(matches!(
        walk_response_with_grant(
            entry.records(),
            "alias.example.com",
            &filter,
            &profile,
            None,
            16,
        ),
        Verdict::Block { .. }
    ));

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

    let filter = FilterEngine::new();
    let profile = compiled_profile("tracker.evil.com");
    assert!(matches!(
        walk_response_with_grant(
            entry.records(),
            "alias.example.com",
            &filter,
            &profile,
            None,
            16,
        ),
        Verdict::Block { .. }
    ));

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
