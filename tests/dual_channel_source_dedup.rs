//! rev-2606 `init-scaffold-silent-no-blocking` — regression pins for the
//! dual-channel list shape.
//!
//! The pre-rework `warden init` scaffold wired the same 3 lists through
//! BOTH config channels: `[lists].sources` catalog slugs AND
//! `[[blocklists]]` URL entities. `merge_sources_with_blocklists`
//! dedup'd by URL string only, so slug + entity became SEPARATE merged
//! sources with separate filter bits; `SourceBitMap::build`'s entity
//! loop then re-pointed `by_v1_id[entity-id]` from the slug's bit to
//! the URL's bit, while the fetch loop populated Tier 1 under the
//! slug's bit (the entity URLs were 404 path-form fiction on top).
//! Net: profile mask ∩ populated bits = ∅ — the daemon held ~8M
//! domains and blocked nothing (container-reproduced 2026-06-10).
//!
//! The S50 T5.5 / §4.24 test (`typed_source_keys_v1_pure.rs`) pinned the
//! single-channel shapes; this file pins the dual-channel shape: the
//! merge collapses a catalog-resolvable slug + same-id entity onto the
//! slug's single bit, so the profile mask points at the bit the
//! download actually populates ("mask bits == fetched bits").
//!
//! The guard case is pinned too: a NON-catalog slug + same-id entity
//! (the `imported.local` bridge shape) must keep the entity's URL fetch
//! — there the slug channel can't download anything, so collapsing onto
//! it would recreate the same silent no-blocking through the other door.

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
        update_interval_hours: 12,
        max_entries: 5_000_000,
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

/// The mask `default` gets from the publish-time projection.
///
/// `plp-s3`: the subscription left `ResolvedProfile`, so the bit-identity
/// assertions in this file read it where it now lives. Same bits, same
/// question — see `_docs/features/profile_list_policy.md` §2.4.
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

/// Populate the engine the way the production fetch loop does: the
/// known-bad domain lands under the bit of every merged source that
/// "downloads" in this scenario (`fetched`: indices into
/// `merged_sources`). The mask-vs-populated split IS the bug class, so
/// the fixture must model which sources download, not mirror the mask.
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

/// The exact pre-rework scaffold shape: 3 catalog slugs in
/// `[lists].sources` AND 3 same-id entities whose URLs are the 404
/// path-form fiction. Post-dedup the entities must NOT become extra
/// sources; the mask must sit on the slug bits — the only bits the
/// downloads populate.
#[test]
fn scaffold_dual_channel_shape_blocks_via_slug_bits() {
    let slugs = [
        "security/malicious".to_string(),
        "privacy/ads".to_string(),
        "privacy/tracking".to_string(),
    ];
    // Path-form URLs: what the pre-rework scaffold shipped; these 404
    // on the live CDN, so their bits would never populate.
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

    // Bit identity: the mask covers exactly the slug bits — the bits
    // the fetch loop populates.
    let fetched_bits: u64 = (0..merged.len()).fold(0, |acc, i| acc | (1u64 << i));
    assert_eq!(
        projected_block_mask(&bit_map, &blocklists),
        fetched_bits,
        "profile mask bits must equal fetched-source bits"
    );

    // Only the slug channel downloads (the entity URLs are 404) — and
    // that is now sufficient to block.
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

/// `warden migrate` deliberately emits dual-channel configs (it derives
/// `[lists].sources` from `[[blocklists]]`, entity URLs matching the
/// catalog). Same collapse, no shadow warning case — pinned separately
/// so a migrate-output config stays single-fetch.
#[test]
fn migrate_shaped_dual_channel_with_catalog_url_collapses() {
    let slugs = ["security/malicious".to_string()];
    // Flat URL: what the catalog actually serves (and migrate emits).
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

/// Guard regression: a slug the catalog does NOT know, paired with a
/// same-id entity carrying the real URL (the `imported.local` bridge
/// shape). The slug channel cannot download anything here, so the
/// entity's URL fetch must survive the merge — and blocking must work
/// through the URL bit.
#[test]
fn non_catalog_slug_with_same_id_entity_keeps_url_fetch() {
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

    // URL-alias-wins (§4.24 entity loop): the mask points at the URL
    // bit — the channel that actually downloads in this shape.
    let url_bit = bit_map
        .bit_for_url("https://imported.local/mycompany.txt")
        .unwrap();
    assert_eq!(projected_block_mask(&bit_map, &blocklists), 1u64 << url_bit);

    // Only the URL source downloads (index 1); the unknown slug fetch
    // fails. Blocking must still fire.
    let engine = engine_with_fetched(&bit_map, &merged, &[1]);
    assert!(matches!(
        engine.evaluate(KNOWN_BAD, &resolved),
        FilterResult::Block
    ));
}

/// A disabled entity must stay excluded from the merge regardless of
/// the dedup path (pre-existing contract, re-pinned here because the
/// dedup rewrote the loop's skip conditions).
#[test]
fn disabled_entity_still_skipped() {
    let mut b = blocklist("security-malicious", "https://lists.purge.cc/malicious.txt");
    b.enabled = false;
    let (merged, _trust) = merge_sources_with_blocklists(&[], &[b]);
    assert!(merged.is_empty());
}
