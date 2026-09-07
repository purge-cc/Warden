//! Compatibility regression pins for the legacy merger and bitmap helpers.
//!
//! Production construction uses `ResolvedSourcePlan`; this file preserves
//! historical behavior for callers that explicitly use the compatibility APIs.
//!
//! A catalog-resolvable slug and matching row share the legacy helper's
//! fetch bit, so the profile mask reaches downloaded domains.
//!
//! The non-catalog case below is compatibility-only. Plan-backed construction
//! resolves that alias to the enabled row's fetch URL.

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

fn blocklist(id: &str, url: &str) -> Blocklist {
    Blocklist {
        id: Id::new(id).unwrap(),
        display_name: id.into(),
        url: url.into(),
        format: BlocklistFormat::Domains,
        update_interval_hours: None,
        max_entries: None,
        enabled: true,
        auth_token_ref: None,
        base: BlocklistBase::Deny,
        trust: BlocklistTrust::RemoteUnsigned,
        accept_unsigned_allow: false,
        max_consecutive_failures: 5,
    }
}

fn default_profile() -> Profile {
    Profile {
        display_name: "default".into(),
        ..Default::default()
    }
}

fn resolve(_bit_map: &SourceBitMap, _blocklists: &[Blocklist]) -> ResolvedProfile {
    let admin_rules: BTreeMap<&Id, &AdminRule> = BTreeMap::new();
    let profile = default_profile();
    ResolvedProfile::build_v1(
        &Id::new("default").unwrap(),
        &profile,
        &admin_rules,
        &purge_warden::config::custom_list::CustomListStore::new(),
        &ServerGlobals::default(),
        60,
    )
}

/// The block mask for the default profile.
fn projected_block_mask(bit_map: &SourceBitMap, blocklists: &[Blocklist]) -> u64 {
    let mut profiles = std::collections::BTreeMap::new();
    profiles.insert("default".to_string(), default_profile());
    bit_map
        .project_policy(blocklists, &profiles)
        .per_profile
        .get("default")
        .copied()
        .expect("the projection covers every configured profile")
        .block
}

/// Populate only the source bits this fixture treats as fetched.
fn engine_with_fetched(
    bit_map: &SourceBitMap,
    merged_sources: &[String],
    fetched: &[usize],
) -> FilterEngine {
    let mut bits: u64 = 0;
    for &i in fetched {
        let bit = bit_map
            .bit_for_url(&merged_sources[i])
            .expect("every merged source has a url bit");
        bits |= 1u64 << bit;
    }
    let mut domain_map: HashMap<CompactString, u64, RandomState> =
        HashMap::with_hasher(RandomState::new());
    domain_map.insert(CompactString::new(KNOWN_BAD), bits);
    let engine = FilterEngine::new();
    engine.swap_domain_map(domain_map);
    engine
}

/// Compatibility aliases must retain the slug fetch bits.
#[test]
fn scaffold_dual_channel_shape_blocks_via_slug_bits() {
    let slugs = [
        "security/malicious".to_string(),
        "privacy/ads".to_string(),
        "privacy/tracking".to_string(),
    ];
    // These row URLs must not add compatibility fetch bits.
    let blocklists = vec![
        blocklist(
            "security-malicious",
            "https://lists.purge.cc/security/malicious.txt",
        ),
        blocklist("privacy-ads", "https://lists.purge.cc/privacy/ads.txt"),
        blocklist(
            "privacy-tracking",
            "https://lists.purge.cc/privacy/tracking.txt",
        ),
    ];

    let (merged, _trust) = merge_sources_with_blocklists(&slugs, &blocklists);
    assert_eq!(
        merged,
        slugs.to_vec(),
        "same-list entities must collapse onto their slugs — no second \
         fetch channel, no second bit"
    );

    let bit_map = SourceBitMap::build(&merged, &blocklists).unwrap();
    let resolved = resolve(&bit_map, &blocklists);

    // The projected policy must cover the fetched slug bits.
    let fetched_bits: u64 = (0..merged.len()).fold(0, |acc, i| acc | (1u64 << i));
    assert_eq!(
        projected_block_mask(&bit_map, &blocklists),
        fetched_bits,
        "profile mask bits must equal fetched-source bits"
    );

    // Fetched slug bits block the domain.
    let engine = engine_with_fetched(&bit_map, &merged, &[0, 1, 2]);
    assert!(
        matches!(engine.evaluate(KNOWN_BAD, &resolved), FilterResult::Block),
        "dual-channel scaffold shape must block end-to-end via the slug bits"
    );
    assert!(matches!(
        engine.evaluate(SAFE, &resolved),
        FilterResult::Forward
    ));
}

/// Matching catalog aliases share one compatibility bit.
#[test]
fn migrate_shaped_dual_channel_with_catalog_url_collapses() {
    let slugs = ["security/malicious".to_string()];
    // The catalog URL joins the slug's compatibility bit.
    let blocklists = vec![blocklist(
        "security-malicious",
        "https://lists.purge.cc/malicious.txt",
    )];

    let (merged, _trust) = merge_sources_with_blocklists(&slugs, &blocklists);
    assert_eq!(merged, slugs.to_vec());

    let bit_map = SourceBitMap::build(&merged, &blocklists).unwrap();
    assert_eq!(
        bit_map.bit_for_v1_id(&Id::new("security-malicious").unwrap()),
        bit_map.bit_for_legacy_catalog_id("security/malicious"),
        "entity id and slug must share one bit"
    );

    let resolved = resolve(&bit_map, &blocklists);
    assert_eq!(projected_block_mask(&bit_map, &blocklists), 0b1);

    let engine = engine_with_fetched(&bit_map, &merged, &[0]);
    assert!(matches!(
        engine.evaluate(KNOWN_BAD, &resolved),
        FilterResult::Block
    ));
}

/// The compatibility helper retains a non-catalog slug and its row URL.
#[test]
fn compatibility_merge_keeps_non_catalog_slug_and_row_url_separate() {
    let slugs = ["mycompany".to_string()];
    let blocklists = vec![blocklist(
        "mycompany",
        "https://imported.local/mycompany.txt",
    )];

    let (merged, _trust) = merge_sources_with_blocklists(&slugs, &blocklists);
    assert_eq!(
        merged,
        vec![
            "mycompany".to_string(),
            "https://imported.local/mycompany.txt".to_string(),
        ],
        "non-catalog slug must NOT swallow the entity's URL fetch"
    );

    let bit_map = SourceBitMap::build(&merged, &blocklists).unwrap();
    let resolved = resolve(&bit_map, &blocklists);

    // The row Id maps policy to its URL bit.
    let url_bit = bit_map
        .bit_for_url("https://imported.local/mycompany.txt")
        .unwrap();
    assert_eq!(projected_block_mask(&bit_map, &blocklists), 1u64 << url_bit);

    // The fetched URL bit blocks the domain.
    let engine = engine_with_fetched(&bit_map, &merged, &[1]);
    assert!(matches!(
        engine.evaluate(KNOWN_BAD, &resolved),
        FilterResult::Block
    ));
}

/// Disabled rows do not enter the compatibility merge.
#[test]
fn disabled_entity_still_skipped() {
    let mut b = blocklist("security-malicious", "https://lists.purge.cc/malicious.txt");
    b.enabled = false;
    let (merged, _trust) = merge_sources_with_blocklists(&[], &[b]);
    assert!(merged.is_empty());
}
