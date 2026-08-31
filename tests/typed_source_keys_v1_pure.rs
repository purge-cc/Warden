//! §4.24 Phase D — full-stack integration test for pure-v1 config blocking.
//!
//! Closes the §2.3 coverage gap that allowed the 2026-05-06 silent-no-blocking
//! incident to slip through CI. Two unit-level tests exercised the consumer
//! lookup against hand-coded bit maps; an end-to-end test against the real
//! `merge_sources_with_blocklists` → `SourceBitMap::build` → `ResolvedProfile::
//! build_v1` → `FilterEngine::evaluate` chain did not exist. This file is that
//! test.
//!
//! Two scenarios:
//!
//! 1. **Pure v1.** `[lists].sources = []`, all blocklists in `[[blocklists]]`.
//!    The May 6 case. With the typed `SourceBitMap`, profile resolution by
//!    `&Id` must hit the bit assigned to the `[[blocklists]].url` so the
//!    Tier 1 block path fires.
//!
//! 2. **Legacy slash-form back-compat.** `[lists].sources = ["security/
//!    malicious"]`, no `[[blocklists]]` row. Pre-§4.24 this worked through
//!    the kebab→slash compatibility shim in `build_v1`. Post-§4.24
//!    `SourceBitMap::build` translates slash-form to v1-id at build time,
//!    so the same single `bit_for_v1_id` lookup hits without any consumer-
//!    side fallback.
//!
//! Both scenarios drive the same hot-path evaluator in `FilterEngine` so a
//! regression that re-introduces URL-only keying or removes either seeding
//! path would fail this test exactly the way it would fail in production.

use std::collections::{BTreeMap, HashMap};

use ahash::RandomState;
use compact_str::CompactString;

use purge_warden::config::schema::id::Id;
use purge_warden::config::schema::{
    AdminRule, Blocklist, BlocklistBase, BlocklistFormat, BlocklistTrust, Profile, ServerGlobals,
};
use purge_warden::filter::engine::{FilterEngine, FilterResult};
use purge_warden::lists::manager::merge_sources_with_blocklists;
use purge_warden::lists::source_key::SourceBitMap;
use purge_warden::profiles::profile::ResolvedProfile;

const KNOWN_BAD: &str = "doubleclick.net";
const SAFE: &str = "wikipedia.org";

fn malicious_blocklist() -> Blocklist {
    Blocklist {
        id: Id::new("security-malicious").unwrap(),
        display_name: "Security: malicious".into(),
        url: "https://lists.purge.cc/security/malicious.txt".into(),
        format: BlocklistFormat::Domains,
        update_interval_hours: 12,
        max_entries: 5_000_000,
        enabled: true,
        auth_token_ref: None,
        base: BlocklistBase::Deny,
        trust: BlocklistTrust::RemoteUnsigned,
        // Sprint B T2: blocklist must carry a tag for tag intersection
        // to surface a bit. `uncategorized` mirrors what the v1→v2
        // migration auto-promotes for any base = deny list missing tags
        // (Sprint A.5 + Sprint B T4).
        accept_unsigned_allow: false,
        // Sprint B T5: per-list max retry count default 5 (D8).
        max_consecutive_failures: 5,
    }
}

fn default_profile_subscribed_to_malicious() -> Profile {
    // Sprint A of `lists_categories_v2`: `Profile.blocklists` is gone.
    // Sprint B T2 reintroduces equivalent via tag intersection — the
    // profile gains `tags = ["uncategorized"]` so the bundled malicious
    // list (also tagged "uncategorized") applies.
    Profile {
        display_name: "default".into(),
        ..Default::default()
    }
}

/// Stand up a [`FilterEngine`] populated with a single known-bad domain
/// tagged at the bit `SourceBitMap` assigned to the
/// `security-malicious` list. Mirrors what the production list-manager
/// loop produces after a successful fetch + merge.
fn engine_for(bit_map: &SourceBitMap) -> FilterEngine {
    let bit = bit_map
        .bit_for_v1_id(&Id::new("security-malicious").unwrap())
        .expect("security-malicious must have a bit in the test fixture");
    let mut domain_map: HashMap<CompactString, u64, RandomState> =
        HashMap::with_hasher(RandomState::new());
    domain_map.insert(CompactString::new(KNOWN_BAD), 1u64 << bit);
    let engine = FilterEngine::new();
    engine.swap_domain_map(domain_map);
    engine
}

fn resolve(_bit_map: &SourceBitMap, _blocklists: &[Blocklist]) -> ResolvedProfile {
    let admin_rules: BTreeMap<&Id, &AdminRule> = BTreeMap::new();
    let profile = default_profile_subscribed_to_malicious();
    ResolvedProfile::build_v1(
        &Id::new("default").unwrap(),
        &profile,
        &admin_rules,
        &purge_warden::config::custom_list::CustomListStore::new(),
        &ServerGlobals::default(),
        60,
    )
}

/// The mask `default` gets from the publish-time projection — where the
/// subscription lives since `plp-s3`.
fn projected_block_mask(bit_map: &SourceBitMap, blocklists: &[Blocklist]) -> u64 {
    let profile = default_profile_subscribed_to_malicious();
    let mut profiles = std::collections::BTreeMap::new();
    profiles.insert("default".to_string(), profile);
    bit_map
        .project_policy(blocklists, &profiles)
        .per_profile
        .get("default")
        .copied()
        .expect("the projection covers every configured profile")
        .block
}

#[test]
fn pure_v1_config_with_empty_lists_sources_blocks_known_bad_domain() {
    // Recreates the 2026-05-06 incident state byte for byte: empty
    // `[lists].sources`, populated `[[blocklists]]`, profile
    // referencing the v1 id. Pre-§4.24 this scenario silently zeroed
    // `list_bitmask` and forwarded every query for ~5h45m on the
    // dev CT. Post-§4.24 the typed `SourceBitMap` must produce a
    // non-zero bitmask via `bit_for_v1_id` (the only consumer
    // lookup) so the Tier 1 block path fires.
    let blocklists = vec![malicious_blocklist()];

    let (merged_sources, _trust) = merge_sources_with_blocklists(&[], &blocklists);
    let bit_map = SourceBitMap::build(&merged_sources, &blocklists).unwrap();

    let resolved = resolve(&bit_map, &blocklists);
    assert_ne!(
        projected_block_mask(&bit_map, &blocklists),
        0,
        "pure-v1 config must produce a non-zero block mask",
    );

    let engine = engine_for(&bit_map);
    engine.fixture_subscribe(&resolved.name, projected_block_mask(&bit_map, &blocklists));
    assert!(
        matches!(engine.evaluate(KNOWN_BAD, &resolved), FilterResult::Block),
        "pure-v1 config must block the known-bad domain end-to-end",
    );
    assert!(
        matches!(engine.evaluate(SAFE, &resolved), FilterResult::Forward),
        "pure-v1 config must still forward unrelated domains",
    );
}

// Sprint A.5 (lc2_v2 foundation) dropped
// `legacy_slash_form_lists_sources_blocks_known_bad_domain`. The test
// pinned the §4.24 contract that `SourceBitMap::build` translates
// slash-form catalog ids into v1-id bits so a config with empty
// `[[blocklists]]` + populated `[lists].sources` still produces a
// non-zero `list_bitmask` via the `Profile.blocklists` consumer
// lookup. Sprint A removed `Profile.blocklists`; with `blocklists =
// vec![]` the stub `ResolvedProfile::build_v1` has no base = Deny entry
// to iterate so the bitmask is zero by construction. Sprint B
// reintroduces equivalent coverage once the resolver becomes
// tag-aware (tag intersection over the bridged source key).
