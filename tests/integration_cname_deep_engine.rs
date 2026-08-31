//! §4.5 Sprint 2/2 integration tests — CNAME chain deep inspection
//! engine end-to-end.
//!
//! Sprint 1/2 shipped `filter::cname::walk_response` as a pure
//! profile-aware walker with 14 unit tests covering the threat
//! coverage matrix in isolation. Sprint 2/2 wires it into the DNS
//! handler at the cache-hit re-check site (M-12 race fix) and the
//! post-upstream-fetch site, plus emits a `cname_block` audit log
//! record and a `[CNAME]` Query Log enrichment row on each block.
//!
//! These integration tests pin the behaviour at the crate-public
//! surface, mirroring the splice the handler does on a real cache
//! hit — same composition pattern as `tests/cache_filter_on_hit.rs`
//! (which pinned the M-12 wire prior to Sprint 2 typing it). End-to-end
//! coverage with a live DNS listener lives in the CT smoke matrix on
//! `the lab host`.
//!
//! What this file pins:
//! 1. Clean chain forwards through `walk_response` with the same
//!    `ResolvedProfile` the hot path resolves once per query.
//! 2. Tail-blocked chain trips with the right `BlockSource` (deny set
//!    via profile rule).
//! 3. Loop-blocked chain trips with `BlockSource::CnameLoop`.
//! 4. Depth-exceeded chain trips with `BlockSource::CnameDepthExceeded`.
//! 5. Admin allow on a hop overrides a tail block (admin trust wins).
//! 6. Block path emits no cache poison: invalidate_key removes the
//!    cached tuple so a subsequent lookup is a Miss (M-12 invariant
//!    preserved by the wire-in).
//! 7. The offending CompactString carries the expected case-normalised
//!    bytes for the audit log + Query Log enrichment.

use std::str::FromStr;
use std::sync::Arc;

use ahash::HashSet;
use compact_str::CompactString;
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::rdata::{A, CNAME};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};

use purge_warden::config::settings::CacheConfig;
use purge_warden::dns::cache::{CacheLookup, DnsCache};
use purge_warden::filter::cname::{walk_response, BlockSource, NamePolicy, Verdict};
use purge_warden::filter::FilterEngine;
use purge_warden::profiles::profile::ResolvedProfile;

fn cache_config() -> CacheConfig {
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

fn a_record(domain: &str, octets: [u8; 4], ttl: u32) -> Record {
    Record::from_rdata(
        Name::from_str(domain).unwrap(),
        ttl,
        RData::A(A(std::net::Ipv4Addr::new(
            octets[0], octets[1], octets[2], octets[3],
        ))),
    )
}

fn filter_with_blocked(domains: &[&str]) -> FilterEngine {
    let set: HashSet<CompactString> = domains.iter().map(|d| CompactString::from(*d)).collect();
    FilterEngine::with_domains(set)
}

/// Build a `ResolvedProfile` whose `deny_domains` set carries the given
/// domains. `walk_response`'s chain trips fire through
/// `engine.evaluate(target, profile)` which scans the profile's
/// `deny_domains` (priority 0) — `permissive_default()` alone has no
/// admin-layer denies, so a flat `FilterEngine::with_domains(...)` is
/// not enough to make the walker block. This helper is the integration
/// equivalent of "operator added a deny rule for X" in the live wire
/// path.
fn profile_denying(domains: &[&str]) -> ResolvedProfile {
    let mut profile = ResolvedProfile::permissive_default();
    profile.deny_domains = domains
        .iter()
        .map(|d| CompactString::from(*d))
        .collect::<std::collections::HashSet<_, _>>()
        .into();
    profile
}

#[test]
fn clean_chain_forwards_through_walker() {
    let filter = filter_with_blocked(&["tracker.evil.example"]);
    let profile = ResolvedProfile::permissive_default();
    let records = vec![
        cname_record("apex.example.com.", "cdn.cloudflare.example.", 300),
        a_record("cdn.cloudflare.example.", [1, 2, 3, 4], 300),
    ];
    let verdict = walk_response(&records, &filter, &profile, NamePolicy::Neutral, 16);
    assert_eq!(verdict, Verdict::Allow);
}

#[test]
fn tail_blocked_chain_trips_with_admin_block_source() {
    // The tail hop is admin-denied in the resolved profile.
    // Sprint 1's attribution heuristic priorities
    // (`Rule` > `deny_domains` > `List(bit)` > `AdminBlock`) — with
    // only deny_domains populated, the heuristic returns `AdminBlock`.
    let filter = filter_with_blocked(&[]);
    let profile = profile_denying(&["tracker.evil.example"]);
    let records = vec![
        cname_record("apex.example.com.", "tracker.evil.example.", 300),
        a_record("tracker.evil.example.", [1, 2, 3, 4], 300),
    ];
    match walk_response(&records, &filter, &profile, NamePolicy::Neutral, 16) {
        Verdict::Block { offending, source } => {
            assert_eq!(offending.as_str(), "tracker.evil.example");
            assert_eq!(source, BlockSource::AdminBlock);
            assert_eq!(source.label(), "admin_block");
        }
        Verdict::Allow => panic!("tail-blocked chain must produce Verdict::Block"),
    }
}

#[test]
fn cname_loop_chain_trips_with_cname_loop_source() {
    // A → B → A loop. Sprint 1 §X decision #2: the visited stack's
    // slot 0 holds the queried apex (alias of the first CNAME record),
    // so cycle detection catches the second hop's target=A. Without
    // that slot, the cycle is invisible to a target-only walker.
    let filter = filter_with_blocked(&[]);
    let profile = ResolvedProfile::permissive_default();
    let records = vec![
        cname_record("apex.example.com.", "alias.example.com.", 300),
        cname_record("alias.example.com.", "apex.example.com.", 300),
    ];
    match walk_response(&records, &filter, &profile, NamePolicy::Neutral, 16) {
        Verdict::Block { source, .. } => {
            assert_eq!(source, BlockSource::CnameLoop);
            assert_eq!(source.label(), "cname_loop");
        }
        Verdict::Allow => panic!("loop chain must produce Verdict::Block(CnameLoop)"),
    }
}

#[test]
fn depth_exceeded_chain_trips_with_depth_exceeded_source() {
    // 5 hops, max_depth=2 → walker stops at hop 2 with depth_exceeded.
    let filter = filter_with_blocked(&[]);
    let profile = ResolvedProfile::permissive_default();
    let records = vec![
        cname_record("apex.example.com.", "h1.example.com.", 300),
        cname_record("h1.example.com.", "h2.example.com.", 300),
        cname_record("h2.example.com.", "h3.example.com.", 300),
        cname_record("h3.example.com.", "h4.example.com.", 300),
        cname_record("h4.example.com.", "h5.example.com.", 300),
    ];
    match walk_response(&records, &filter, &profile, NamePolicy::Neutral, 2) {
        Verdict::Block { source, .. } => {
            assert_eq!(source, BlockSource::CnameDepthExceeded);
            assert_eq!(source.label(), "cname_depth_exceeded");
        }
        Verdict::Allow => panic!("depth-exceeded chain must produce Verdict::Block"),
    }
}

#[test]
fn admin_allow_on_hop_overrides_tail_block() {
    // The chain hits a tail that the resolved profile WOULD deny via
    // `deny_domains`, but the same name is also in the profile's
    // `allow_domains`. The walker's admin-allow short-circuit
    // (`domain_matches_set(target, &profile.allow_domains)`) returns
    // `Verdict::Allow` BEFORE the engine.evaluate probe — admin trust
    // wins. Pinning this confirms Sprint 1 §X decision #5 stays live
    // through the wire-in.
    let filter = filter_with_blocked(&[]);
    let mut profile = profile_denying(&["tracker.evil.example"]);
    profile.allow_domains = std::iter::once(CompactString::from("tracker.evil.example"))
        .collect::<std::collections::HashSet<_, _>>()
        .into();
    let records = vec![
        cname_record("apex.example.com.", "tracker.evil.example.", 300),
        a_record("tracker.evil.example.", [1, 2, 3, 4], 300),
    ];
    let verdict = walk_response(&records, &filter, &profile, NamePolicy::Neutral, 16);
    assert_eq!(
        verdict,
        Verdict::Allow,
        "admin allow_domains must override tail block"
    );
}

#[tokio::test]
async fn block_path_invalidates_cache_no_poison() {
    // Mirror of the cache-hit re-check splice: cache is populated
    // before the filter trip, the chain walker returns Block, the
    // handler invalidates the precise tuple, and the next lookup
    // is a Miss. M-12 race invariant — the no-cache-poison contract
    // the wire-in inherits from §4.4 P2's cache invalidation API.
    let cache = DnsCache::new(&cache_config());
    let records = vec![
        cname_record("apex.example.com.", "tracker.evil.example.", 300),
        a_record("tracker.evil.example.", [1, 2, 3, 4], 300),
    ];
    cache
        .insert(
            "apex.example.com",
            RecordType::A,
            DNSClass::IN,
            records.clone(),
            ResponseCode::NoError,
            None,
            None,
        )
        .await;
    let entry = match cache
        .lookup("apex.example.com", RecordType::A, DNSClass::IN, None)
        .await
    {
        CacheLookup::Fresh(e) => e,
        _ => panic!("expected Fresh entry after insert"),
    };

    let filter = filter_with_blocked(&[]);
    let profile = Arc::new(profile_denying(&["tracker.evil.example"]));
    let verdict = walk_response(entry.records(), &filter, &profile, NamePolicy::Neutral, 16);
    let offending = match verdict {
        Verdict::Block { offending, .. } => offending,
        Verdict::Allow => panic!("post-cache-hit chain must trip"),
    };
    assert_eq!(offending.as_str(), "tracker.evil.example");

    // Wire-in semantics: on Block, the handler calls invalidate_key.
    cache
        .invalidate_key("apex.example.com", RecordType::A, DNSClass::IN, None)
        .await;
    assert!(
        matches!(
            cache
                .lookup("apex.example.com", RecordType::A, DNSClass::IN, None)
                .await,
            CacheLookup::Miss
        ),
        "M-12: post-block invalidation must remove the cached entry — \
         no cache poison across repeat queries"
    );
}

#[test]
fn offending_byte_identity_carries_into_audit_label() {
    // The Sprint 2 audit log record stores `cname_target =
    // verdict.offending`. The walker case-normalises and strips the
    // trailing dot. This test pins the exact byte sequence the audit
    // log writes — frozen at "tracker.evil.example" lowercase, no
    // dot, regardless of upstream-supplied case / dot-form.
    let filter = filter_with_blocked(&[]);
    let profile = profile_denying(&["tracker.evil.example"]);
    let records = vec![
        cname_record("apex.example.com.", "Tracker.EVIL.Example.", 300),
        a_record("tracker.evil.example.", [1, 2, 3, 4], 300),
    ];
    match walk_response(&records, &filter, &profile, NamePolicy::Neutral, 16) {
        Verdict::Block { offending, .. } => {
            assert_eq!(offending.as_str(), "tracker.evil.example");
        }
        Verdict::Allow => panic!("case-mixed tail must still trip"),
    }
}
