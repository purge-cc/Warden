//! §4.24 Phase 2 D — full-stack integration test for typed source-key
//! parity across the entire facade family.
//!
//! Phase 1's `tests/typed_source_keys_v1_pure.rs` proved `SourceBitMap`
//! produces a non-zero `list_bitmask` for pure-v1 configs. Phase 2
//! extends the coverage to the three sibling facades — `SourceTrustMap`,
//! `SourceTokenMap`, `ListStatusRegistry` — and pins the coherency
//! invariant: a `&Id` lookup must resolve to consistent values across
//! all four typed facades when the underlying config is the same.
//!
//! The §11.4 test discipline ("every fixture goes through `Facade::
//! build`, never a hand-coded HashMap") is preserved verbatim — these
//! tests construct the typed facades exactly the way the daemon does,
//! so a regression that diverges any of the four builders from the
//! others would fail this test the same way it would fail in
//! production.
//!
//! Three scenarios:
//!
//! 1. **Pure v1.** `[lists].sources = []`, all blocklists in
//!    `[[blocklists]]`. All four typed facades resolve the same v1
//!    `Id` to consistent values: bit assignment, trust, status slot
//!    presence.
//!
//! 2. **Type-safety contract negatives.** Passing a v1-id-string into
//!    `*_for_url` returns `None` (the typed contract pins May 6 at the
//!    type level — a URL-keyed producer + id-keyed consumer mismatch
//!    cannot recur because the call line uses different methods).
//!
//! 3. **Legacy slash-form back-compat.** `[lists].sources =
//!    ["security/malicious"]`, no `[[blocklists]]` row. The auto
//!    kebab→slash translation at construction seeds v1-id lookups on
//!    `SourceBitMap` AND `ListStatusRegistry`; `SourceTrustMap` (whose
//!    data is *only* from `[[blocklists]]`) returns `None` for
//!    v1-id, which is correct — the legacy source carries no schema
//!    trust info.

use purge_warden::config::schema::id::Id;
use purge_warden::config::schema::{Blocklist, BlocklistBase, BlocklistFormat, BlocklistTrust};
use purge_warden::lists::manager::merge_sources_with_blocklists;
use purge_warden::lists::source_key::{SourceBitMap, SourceTokenMap};
use purge_warden::lists::status::{ListStatus, ListStatusRegistry, ParsedCounts};

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
        trust: BlocklistTrust::Signed,
        accept_unsigned_allow: false,
        max_consecutive_failures: 5,
    }
}

#[test]
fn phase2_pure_v1_all_facades_resolve_v1_id_coherently() {
    // The May 6 incident byte for byte: empty `[lists].sources`,
    // populated `[[blocklists]]`. Phase 1 proved `SourceBitMap` hits
    // the v1-id; Phase 2 proves the sibling facades follow suit.
    let blocklists = vec![malicious_blocklist()];
    let legacy: Vec<String> = vec![];
    let url = blocklists[0].url.clone();
    let v1_id = Id::new("security-malicious").unwrap();

    // Producer: matches the daemon's start.rs / update.rs pattern.
    let (merged_sources, trust_map) = merge_sources_with_blocklists(&legacy, &blocklists);
    assert_eq!(
        merged_sources.as_slice(),
        [url.as_str()],
        "merged sources must surface the v1 URL when legacy is empty",
    );

    // Facade 1 — SourceBitMap (Phase 1 surface, unchanged).
    let bit_map = SourceBitMap::build(&merged_sources, &blocklists).unwrap();
    let bit = bit_map
        .bit_for_v1_id(&v1_id)
        .expect("v1-id must have a bit on pure-v1 configs (the §4.24 P1 contract)");
    assert_eq!(
        bit_map.bit_for_url(&url),
        Some(bit),
        "URL and v1-id must resolve to the same bit",
    );

    // Facade 2 — SourceTrustMap (Phase 2 P2-A surface).
    assert_eq!(
        trust_map.trust_for_v1_id(&v1_id),
        Some(BlocklistTrust::Signed),
        "v1-id trust lookup must match the [[blocklists]] row's trust value",
    );
    assert_eq!(
        trust_map.trust_for_url(&url),
        Some(BlocklistTrust::Signed),
        "URL trust lookup must agree with the v1-id lookup",
    );

    // Facade 3 — SourceTokenMap (Phase 2 P2-B surface). No
    // `auth_token_ref` on this row, so both lookups return None — the
    // contract is that the typed surface exists and answers correctly
    // for the absent case (anonymous fetch).
    let empty_secrets = purge_warden::config::secrets::Secrets::empty();
    let config = purge_warden::config::schema::ConfigV1 {
        blocklists: blocklists.clone(),
        ..Default::default()
    };
    let token_map = SourceTokenMap::build(&config, &empty_secrets);
    assert!(
        token_map.is_empty(),
        "blocklist without auth_token_ref must produce an empty token map",
    );
    assert_eq!(token_map.token_for_v1_id(&v1_id), None);
    assert_eq!(token_map.token_for_url(&url), None);

    // Facade 4 — ListStatusRegistry (Phase 2 P2-C surface). The
    // daemon constructs the registry from `merged_sources`, then
    // calls `populate_v1_id_index(blocklists)` to wire the typed
    // index. Test mirrors this two-step exactly.
    let registry = ListStatusRegistry::new(&merged_sources);
    registry.populate_v1_id_index(&blocklists);
    // Slot is materialised but never refreshed yet — both lookups
    // should return the default `NeverFetched` status.
    let by_url = registry
        .status_for_url(&url)
        .expect("URL slot must exist for the merged source");
    let by_id = registry
        .status_for_v1_id(&v1_id)
        .expect("v1-id lookup must hit the same slot via the typed index");
    assert_eq!(
        by_url.entries, by_id.entries,
        "URL and v1-id lookups must reach the same ArcSwap slot",
    );

    // Update the slot via the typed URL surface, then verify the
    // v1-id lookup sees the new payload — pins the index → slot
    // chain end to end.
    let now = time::OffsetDateTime::now_utc();
    registry.update_for_url(
        &url,
        ListStatus::from_refresh(42, ParsedCounts::default(), None, now),
    );
    let by_id_after = registry
        .status_for_v1_id(&v1_id)
        .expect("v1-id lookup must still resolve after the slot update");
    assert_eq!(
        by_id_after.entries, 42,
        "v1-id lookup must observe the URL-keyed update",
    );
}

#[test]
fn phase2_typed_apis_reject_url_lookup_when_passed_a_v1_id_string() {
    // The type-safety contract: passing a kebab-form v1-id string into
    // `*_for_url` must return None. This is the line that would have
    // compiled-but-silently-mis-matched on May 6 if the facade had
    // been a `HashMap<String, _>` with an `enum SourceKey` wrapper.
    // Pinning the negative across all four facades.
    let blocklists = vec![malicious_blocklist()];
    let (merged_sources, trust_map) = merge_sources_with_blocklists(&[], &blocklists);
    let bit_map = SourceBitMap::build(&merged_sources, &blocklists).unwrap();
    let registry = ListStatusRegistry::new(&merged_sources);
    registry.populate_v1_id_index(&blocklists);

    // Passing the kebab id-string into `bit_for_url` / `trust_for_url`
    // / `status_for_url` — silent mismatch attempts. All return None.
    assert_eq!(bit_map.bit_for_url("security-malicious"), None);
    assert_eq!(trust_map.trust_for_url("security-malicious"), None);
    assert!(registry.status_for_url("security-malicious").is_none());

    // Passing the v1-id newtype into the v1-id surface — the correct
    // call line, must hit.
    let v1_id = Id::new("security-malicious").unwrap();
    assert!(bit_map.bit_for_v1_id(&v1_id).is_some());
    assert!(trust_map.trust_for_v1_id(&v1_id).is_some());
    assert!(registry.status_for_v1_id(&v1_id).is_some());
}

#[test]
fn phase2_legacy_slash_form_only_seeds_status_and_bitmap_via_auto_translation() {
    // Pre-v1 configs (slash-form catalog ids only) preserve the
    // §4.24 P1 auto-translation: `SourceBitMap::build` and
    // `ListStatusRegistry::new` both translate `"privacy/ads"` →
    // `Id::new("privacy-ads")` at construction. `SourceTrustMap`
    // returns None because trust info only comes from
    // `[[blocklists]]` rows — a pure-legacy config carries no trust
    // and the consumer applies its `RemoteUnsigned` default downstream.
    let legacy = vec!["privacy/ads".to_string()];
    let (merged_sources, trust_map) = merge_sources_with_blocklists(&legacy, &[]);
    let bit_map = SourceBitMap::build(&merged_sources, &[]).unwrap();
    let registry = ListStatusRegistry::new(&merged_sources);
    // Note: no populate_v1_id_index call here — the constructor's
    // auto-seeding for slash-form sources is what we're testing.

    let v1_id = Id::new("privacy-ads").unwrap();

    // SourceBitMap auto-aliases the legacy id → bit at construction
    // (Phase 1 §11.2 invariant; preserved as the prerequisite for
    // Phase 2 facades to follow the same convention).
    assert!(bit_map.bit_for_v1_id(&v1_id).is_some());
    assert!(bit_map.bit_for_legacy_catalog_id("privacy/ads").is_some());

    // SourceTrustMap returns None — no [[blocklists]] row, so no
    // trust info. The manager.rs:1000 lookup applies the
    // `unwrap_or(BlocklistTrust::RemoteUnsigned)` default downstream,
    // matching pre-§4.24-P2 behaviour byte for byte.
    assert_eq!(trust_map.trust_for_v1_id(&v1_id), None);
    assert_eq!(trust_map.trust_for_url("privacy/ads"), None);

    // ListStatusRegistry auto-translates the slash-form slot key at
    // construction, so v1-id status lookup hits without any subsequent
    // `populate_v1_id_index` call. Symmetric to SourceBitMap.
    let now = time::OffsetDateTime::now_utc();
    registry.update_for_url(
        "privacy/ads",
        ListStatus::from_refresh(7, ParsedCounts::default(), None, now),
    );
    let by_id = registry
        .status_for_v1_id(&v1_id)
        .expect("legacy slash-form must auto-translate to v1-id at construction");
    assert_eq!(by_id.entries, 7);
}
