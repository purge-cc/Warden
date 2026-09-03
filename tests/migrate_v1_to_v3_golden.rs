//! Sprint A.5 (lc2_v2 foundation) — golden test for `warden migrate-config
//! --from v1 --to v2`. Pins the byte-for-byte output of the migrator
//! against the live CT config shape so a regression in the
//! transformation layer surfaces immediately.
//!
//! The CT-known v1 fixture below mirrors `/etc/purge-warden/config.toml`
//! on `the lab host` (192.0.2.10) post the 2026-05-07 incident manual
//! restore: `mycompany` allow-list, three deny lists pulled from
//! `lists.purge.cc`, the default profile carrying a `blocklists = [...]`
//! array, and one device. The expected v2 output mirrors the §7 mapping
//! rules from `_docs/features/lists_categories_v2.md`.
//!
//! Pre-`apply_v1_to_v2_transformations` rewrites this fixture would
//! either:
//! - fail to parse via `ConfigV1::deserialize` because Sprint A removed
//!   `Profile.blocklists` and slammed `deny_unknown_fields` on, or
//! - fail to round-trip through the v2 loader because allow-lists
//!   without `tags` need a different mapping than deny-lists.
//!
//! The golden assertion below pins the post-transformation output
//! end-to-end: invoke the migrator on a temp dir, read the produced
//! file, compare bytes, and re-load through the production v2 loader
//! to confirm it lints clean.

use std::fs;

use purge_warden::cli::commands::migrate::{migrate_v1_to_v3, V1ToV3Summary};
use purge_warden::config::loader::load_config;
use purge_warden::config::schema::{effective_direction, BlocklistBase, Id, ListPolicy};

/// Live CT config, post 2026-05-07 incident restore.
const V1_CT_LIVE_FIXTURE: &str = r##"schema_version = 2

[server]
listen = "0.0.0.0:53"
default_profile = "default"
allow_from = ["10.10.1.0/24", "127.0.0.0/8"]

[upstream]
mode = "plain"
servers = ["1.1.1.1:53", "1.0.0.1:53"]
timeout_ms = 5000

[lists]
sources = []
update_interval_secs = 43200

[[blocklists]]
id = "mycompany"
display_name = "MyCompany allow"
url = "https://imported.local/mycompany"
format = "domains"
kind = "allow"
trust = "local"

[[blocklists]]
id = "privacy-ads"
display_name = "Privacy: ads"
url = "https://lists.purge.cc/privacy/ads.txt"
format = "domains"

[[blocklists]]
id = "privacy-tracking"
display_name = "Privacy: tracking"
url = "https://lists.purge.cc/privacy/tracking.txt"
format = "domains"

[[blocklists]]
id = "security-malicious"
display_name = "Security: malicious"
url = "https://lists.purge.cc/security/malicious.txt"
format = "domains"

[profiles.default]
display_name = "Default household profile"
blocklists = ["mycompany", "privacy-ads", "privacy-tracking", "security-malicious"]

[[devices]]
id = "operator-iphone"
display_name = "iPhone di Operator"
ip = "10.10.1.107"
profile = "default"

[cache]
max_entries = 10000
max_ttl_secs = 3600
min_ttl_secs = 60
negative_ttl_secs = 300

[socket]
path = "/run/purge-warden/control.sock"
"##;

#[test]
fn migrate_v1_to_v3_ct_live_config_byte_pinned() {
    let tmp = tempfile::tempdir().unwrap();
    let from = tmp.path().join("ct-v1.toml");
    fs::write(&from, V1_CT_LIVE_FIXTURE).unwrap();
    let target = tmp.path().join("v3-out.toml");

    let summary: V1ToV3Summary =
        migrate_v1_to_v3(&from, &target, false).expect("migration must succeed");

    // The v1→v2 shape change is reused verbatim, so its counts still pin
    // the §7 mapping rules: 3 deny lists promoted, 1 allow-list kept
    // empty, 1 device tagged, 1 profile dropped.
    assert_eq!(summary.v2.blocklists_promoted_to_uncategorized, 3);
    assert_eq!(summary.v2.blocklists_kept_empty_tags, 1);
    assert_eq!(summary.v2.devices_tagged_uncategorized, 1);
    assert_eq!(summary.v2.profiles_dropped_blocklists_field, 1);
    assert_eq!(summary.v2.subnets_tagged_empty, 0);
    assert_eq!(summary.v2.categories_blocks_dropped, 0);

    // The v3 half. The v1 profile subscribed to all four lists, so all
    // four pairs are kept and none is written `ignore`. This is the
    // measurement that separates the direct route from the v1→v2→v3
    // chain: the chain would have REFUSED this fixture outright (its own
    // step 4 tags `operator-iphone`, and `tagged_sub_profile_entities`
    // refuses tagged devices), and with that refusal suppressed it would
    // have written `ignore` for all four — a config that loads, lints
    // clean, and filters nothing.
    assert_eq!(summary.pairs_kept, 4, "all four lists were subscribed");
    assert_eq!(summary.pairs_ignored, 0);
    assert_eq!(summary.profiles_given_lists, 1);
    assert_eq!(
        summary.lists_renamed_kind_to_base, 1,
        "only `mycompany` declared a `kind`"
    );

    // The produced file lints clean through the production v3 loader.
    let now = time::OffsetDateTime::now_utc();
    let loaded = load_config(&target, now).expect("v3 output must lint clean");

    // Allow-list keeps tags = [] (D2: auto-allow for everyone is a sec
    // risk; operator tags allow-lists explicitly).
    let mycompany = loaded
        .config
        .blocklists
        .iter()
        .find(|b| b.id.as_str() == "mycompany")
        .expect("mycompany allow-list must survive");
    assert_eq!(mycompany.base, BlocklistBase::Allow);

    // **The tag assertions that stood here are gone, and what they were
    // measuring is why.** They read `bl.tags` back off `load_config` and
    // expected `["uncategorized"]` on every deny list — but `migrate`
    // deliberately writes no `tags` key at all (see
    // `apply_v2_to_v3_transformations`), so what they measured was the
    // LOADER's `auto_promote_blocklists`, not the migration's output.
    // `plp-s5a` removed both the field and the promotion, so the
    // assertions had nothing left to observe. The direction assertions
    // below are the v3 contract and are untouched.
    for id in ["privacy-ads", "privacy-tracking", "security-malicious"] {
        let bl = loaded
            .config
            .blocklists
            .iter()
            .find(|b| b.id.as_str() == id)
            .unwrap_or_else(|| panic!("deny list `{id}` must survive"));
        assert_eq!(bl.base, BlocklistBase::Deny);
    }

    // Profile.blocklists field is gone. What replaces it is `lists`,
    // carrying the SAME association the v1 array expressed — every list
    // named, each at its own direction.
    let default = loaded
        .config
        .profiles
        .get("default")
        .expect("default profile must survive");
    assert_eq!(
        default.lists.len(),
        4,
        "every (profile, list) pair is stated, not just the overrides: {:?}",
        default.lists
    );
    for (id, want) in [
        ("mycompany", ListPolicy::Allow),
        ("privacy-ads", ListPolicy::Deny),
        ("privacy-tracking", ListPolicy::Deny),
        ("security-malicious", ListPolicy::Deny),
    ] {
        let got = default
            .lists
            .get(&Id::new(id).unwrap())
            .copied()
            .unwrap_or_else(|| panic!("profile must state a policy for `{id}`"));
        assert_eq!(got, want, "wrong direction carried over for `{id}`");
    }

    // And the association really is what the engine will act on — asked
    // through the one function that answers it, not re-derived here.
    for b in &loaded.config.blocklists {
        let want = if b.id.as_str() == "mycompany" {
            ListPolicy::Allow
        } else {
            ListPolicy::Deny
        };
        assert_eq!(
            effective_direction(default, b),
            want,
            "effective direction for `{}`",
            b.id
        );
    }

    // Device picks up the sentinel tag and the unfiltered=false default.
    let dev = loaded
        .config
        .devices
        .iter()
        .find(|d| d.id.as_str() == "operator-iphone")
        .expect("operator-iphone device must survive");
    assert!(!dev.unfiltered);
}

#[test]
fn migrate_v1_to_v3_drops_legacy_categories_block_and_category_field() {
    // A v1 config with the now-removed `[[categories]]` entity and
    // `Blocklist.category = "..."` field must round-trip through the
    // migrator: the entity block is dropped wholesale, the legacy
    // field is stripped per blocklist, and the resulting blocklists
    // get tags assigned by `kind` (deny → uncategorized, allow → []).
    let tmp = tempfile::tempdir().unwrap();
    let from = tmp.path().join("with-categories.toml");
    let target = tmp.path().join("v2-out.toml");
    let v1_with_categories = r##"schema_version = 2

[server]
default_profile = "default"

[[categories]]
id = "default"
display_name = "Default"

[[categories]]
id = "lavoro"
display_name = "Lavoro"

[[blocklists]]
id = "ads"
display_name = "Ads"
url = "https://example.com/ads.txt"
category = "default"

[[blocklists]]
id = "work-allowlist"
display_name = "Work allowlist"
url = "https://example.com/work.txt"
kind = "allow"
trust = "local"
category = "lavoro"

[profiles.default]
display_name = "Default"

[upstream]
servers = ["192.0.2.1:53"]
"##;
    fs::write(&from, v1_with_categories).unwrap();

    let summary = migrate_v1_to_v3(&from, &target, false).expect("migration must succeed");
    assert_eq!(summary.v2.categories_blocks_dropped, 2);
    assert_eq!(summary.v2.blocklists_promoted_to_uncategorized, 1);
    assert_eq!(summary.v2.blocklists_kept_empty_tags, 1);

    // The output lints clean — `[[categories]]` and the per-blocklist
    // `category` fields are gone, so deny_unknown_fields is happy.
    let now = time::OffsetDateTime::now_utc();
    let _ = load_config(&target, now).expect("v3 output must lint clean");
}

#[test]
fn migrate_v1_to_v3_subnet_gains_empty_tags() {
    // A v1 config with subnets must produce v2 subnets carrying
    // `tags = []` per D6 — subnets contribute tags only to devices
    // that fall in their CIDR and have no explicit `[[devices]]`
    // record. Empty by default; operator customises post-migrate.
    let tmp = tempfile::tempdir().unwrap();
    let from = tmp.path().join("with-subnets.toml");
    let target = tmp.path().join("v2-out.toml");
    let v1_with_subnets = r##"schema_version = 2

[server]
default_profile = "default"

[profiles.default]
display_name = "Default"

[[subnets]]
id = "lan"
display_name = "LAN"
cidrs = ["10.10.1.0/24"]
profile = "default"

[[subnets]]
id = "guest"
display_name = "Guest VLAN"
cidrs = ["10.10.99.0/24"]
profile = "default"
priority = 5

[upstream]
servers = ["192.0.2.1:53"]
"##;
    fs::write(&from, v1_with_subnets).unwrap();

    let summary = migrate_v1_to_v3(&from, &target, false).expect("migration must succeed");
    assert_eq!(summary.v2.subnets_tagged_empty, 2);

    // The v3 output must still lint clean — that half is the migration's
    // contract and stays. `summary.v2.subnets_tagged_empty` above is the
    // other half that still measures the migration: it counts what the
    // migrator SAW in the v1 input. The loop that read the tags back off
    // the v3 output measured the LOADER's auto-promotion instead, and
    // `plp-s5a` removed the field it read.
    let now = time::OffsetDateTime::now_utc();
    load_config(&target, now).expect("v3 output must lint clean");
}

#[test]
fn migrate_v1_to_v3_unknown_input_path_errors_cleanly() {
    let tmp = tempfile::tempdir().unwrap();
    let from = tmp.path().join("does-not-exist.toml");
    let target = tmp.path().join("out.toml");
    let err = migrate_v1_to_v3(&from, &target, false).expect_err("missing input must error");
    assert!(
        err.to_string().contains("v1 config not found"),
        "expected `v1 config not found` substring; got: {err}"
    );
}
