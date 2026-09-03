//! `plp-s5a` F1 — a config still carrying `tags = [...]` must LOAD.
//!
//! # Why this is the highest-stakes test in the sprint
//!
//! All five entity structs (`Blocklist`, `Profile`, `Device`, `Group`,
//! `Subnet`) carry `#[serde(deny_unknown_fields)]`. That is deliberate —
//! a typo'd key is refused rather than silently ignored — but it turns
//! *removing* a field into a breaking change for every config already on
//! disk: the minute `tags` stops being a field, `unknown field \`tags\``
//! refuses the whole load and the daemon does not start.
//!
//! Both shipped hosts were measured carrying the key (`the lab host` 5
//! occurrences, `the lab host` 4), and both serve a household's DNS. A
//! config that does not load is a house with no name resolution until
//! someone SSHes in.
//!
//! The remedy is `config::schema::retired_keys::strip_retired_tag_keys`,
//! called from **both** loader deserialise sites. This file is what says
//! so: break either one and a test here goes red.
//!
//! # What this file replaces
//!
//! It was `tmc_cli_entity_tags.rs`, the end-to-end cover for the six
//! `warden <entity> tag add|remove` verbs. `plp-s3` refused those writes,
//! `plp-s5c` removed the verbs from the clap tree, and `plp-s5a` removed
//! the field they wrote. Its last two tests went with the surface:
//!
//! - `apply_tags_inner_refuses_a_delta_and_passes_a_no_op` — the file's
//!   own header said *"when wave B removes the TUI's tag editors, this is
//!   the test that says whether the primitive still has a caller"*. Wave B
//!   is this sprint; `apply_tags_inner` had none left, so it and the
//!   primitive left together.
//! - `existing_tags_still_load` — a compatibility guarantee about configs
//!   already on disk. **It did not leave; it is what this whole file
//!   became.** It asserted that removing the *writers* must not turn a
//!   stored tag into a load error. Removing the *field* is the larger
//!   version of exactly that claim, so the guarantee is not weaker here —
//!   it is pinned harder, on both loader exits, plus the operator notice
//!   and a control arm the old test had no reason to carry.

use std::path::{Path, PathBuf};

use purge_warden::config::loader::{load_config, load_config_collect};

fn now() -> time::OffsetDateTime {
    time::OffsetDateTime::now_utc()
}

fn write(root: &Path, rel: &str, body: &str) -> PathBuf {
    let full = root.join(rel);
    if let Some(parent) = full.parent() {
        std::fs::create_dir_all(parent).expect("mkdir");
    }
    std::fs::write(&full, body).expect("write");
    full
}

/// The shape both live hosts actually carry: `tags` on `[[blocklists]]`
/// entries and on `[profiles.<id>]`. Every other taggable entity is
/// present too, because a config from a third party may tag any of them
/// and `deny_unknown_fields` sits on all five.
const V2_MASTER_WITH_TAGS: &str = r#"schema_version = 3

[server]
default_profile = "default"

[profiles.default]
display_name = "Default"

[profiles.kids]
display_name = "Kids"
tags = ["ads", "tracking"]

[[devices]]
id = "kids-tablet"
display_name = "Kids tablet"
ip = "192.0.2.20"
tags = ["mobile"]

[[groups]]
id = "iot"
display_name = "IoT"
profile = "default"
priority = 10
tags = ["iot-monitoring"]

[[subnets]]
id = "guest"
display_name = "Guest"
profile = "default"
cidrs = ["192.0.2.0/24"]
priority = 5
tags = ["guest-block"]

[[blocklists]]
id = "ads-list"
display_name = "Ads"
url = "https://lists.purge.cc/ads.txt"
tags = ["ads"]

[upstream]
servers = ["192.0.2.1:53"]
"#;

/// **The single-file fast path — the shipped layout.**
///
/// This is the arm a strip wired only into `normalise_deprecated_keys`
/// would fail: that function mutates a `toml::Table` the fast path
/// discards, because it re-parses the raw bytes through
/// `schema::load::parse_v1`.
#[test]
fn a_single_file_config_carrying_tags_still_loads() {
    let dir = tempfile::tempdir().unwrap();
    let master = write(dir.path(), "config.toml", V2_MASTER_WITH_TAGS);

    let loaded = load_config(&master, now()).expect(
        "a config carrying the retired `tags` key must LOAD — every entity is \
         deny_unknown_fields, so a missing strip is the daemon refusing to start",
    );
    assert_eq!(
        loaded.files_loaded.len(),
        1,
        "must be the single-file fast path, or this arm proves nothing about it"
    );
    // The entities themselves survive intact — the strip removes one key,
    // it does not drop the entry that carried it.
    assert!(loaded.config.profiles.contains_key("kids"));
    assert_eq!(loaded.config.blocklists.len(), 1);
    assert_eq!(loaded.config.devices.len(), 1);
    assert_eq!(loaded.config.groups.len(), 1);
    assert_eq!(loaded.config.subnets.len(), 1);
}

/// **The multi-file merge path — the other exit.**
///
/// Split so the tagged entities live in an include, which is where a real
/// deployment keeps its `blocklists.d/`. A strip wired only into
/// `parse_v1` would fail here.
#[test]
fn a_multi_file_config_carrying_tags_still_loads() {
    let dir = tempfile::tempdir().unwrap();
    let master = write(
        dir.path(),
        "config.toml",
        r#"schema_version = 3
includes = ["blocklists.d/*.toml"]

[server]
default_profile = "default"

[profiles.default]
display_name = "Default"

[profiles.kids]
display_name = "Kids"
tags = ["ads"]

[upstream]
servers = ["192.0.2.1:53"]
"#,
    );
    write(
        dir.path(),
        "blocklists.d/ads.toml",
        r#"[[blocklists]]
id = "ads-list"
display_name = "Ads"
url = "https://lists.purge.cc/ads.txt"
tags = ["ads"]
"#,
    );

    let loaded = load_config(&master, now())
        .expect("the merge path must strip the retired key too, not only the fast path");
    assert_eq!(
        loaded.files_loaded.len(),
        2,
        "must be the multi-file merge path, or this arm proves nothing about it"
    );
    assert_eq!(loaded.config.blocklists.len(), 1);
    assert!(loaded.config.profiles.contains_key("kids"));
}

/// Loading past the key silently is the failure this workstream exists to
/// kill. The operator has to be told, by name, on the path they actually
/// run — and `warden config lint` reads exactly this channel.
#[test]
fn the_operator_is_told_which_entities_carried_the_retired_key() {
    let dir = tempfile::tempdir().unwrap();
    let master = write(dir.path(), "config.toml", V2_MASTER_WITH_TAGS);

    let (result, warns) = load_config_collect(&master, now());
    assert!(result.is_ok(), "load must succeed: {result:?}");

    for entity in [
        "blocklists.ads-list",
        "devices.kids-tablet",
        "groups.iot",
        "subnets.guest",
        "profiles.kids",
    ] {
        assert!(
            warns.iter().any(|w| w.contains(entity)),
            "the notice must name '{entity}' so the operator can find it in the file: {warns:?}"
        );
    }
    assert!(
        warns.iter().any(|w| w.contains("profiles.<id>.lists")),
        "and it must name the replacement, not merely report a removal: {warns:?}"
    );
}

/// **The second brick, end to end.** `LabelKind::Tag` was a serde enum
/// variant, not a struct field: deleting it turns `kind = "tag"` into an
/// unknown *variant*, which serde refuses whether or not the struct denies
/// unknown fields. So it needed covering separately, and a config carrying
/// one has no `tags` key for the key scan to notice.
///
/// The surrounding vocabulary must survive — a row-level strip that took
/// its neighbours would silently empty an operator's label registry.
#[test]
fn a_config_declaring_a_retired_tag_label_still_loads() {
    let dir = tempfile::tempdir().unwrap();
    let master = write(
        dir.path(),
        "config.toml",
        r#"schema_version = 3

[server]
default_profile = "default"

[profiles.default]
display_name = "Default"

[[labels]]
id = "dweller"
kind = "owner"
display_name = "Dweller"

[[labels]]
id = "ads"
kind = "tag"
display_name = "Ads"

[[labels]]
id = "famiglia"
kind = "department"
display_name = "Famiglia"

[upstream]
servers = ["192.0.2.1:53"]
"#,
    );

    let (result, warns) = load_config_collect(&master, now());
    let loaded = result.expect(
        "a `kind = \"tag\"` label must not refuse the load — LabelKind is a serde \
         enum, so the retired variant is an unknown VARIANT, not an ignorable field",
    );
    assert_eq!(
        loaded
            .config
            .labels
            .iter()
            .map(|l| l.id.as_str())
            .collect::<Vec<_>>(),
        vec!["dweller", "famiglia"],
        "the retired row goes and its neighbours stay"
    );
    assert!(
        warns.iter().any(|w| w.contains("labels.ads")),
        "and the operator is told which row was dropped: {warns:?}"
    );
}

/// **A quoted key is the same key.** TOML lets `tags` be written bare,
/// `"tags"` or `'tags'`, and serde resolves all three to one field — so
/// `deny_unknown_fields` refuses all three equally.
///
/// This is the arm that catches a pre-check written to match only the bare
/// spelling: `strip_retired_tag_keys` works on the parsed table and would
/// find it regardless, but the fast path never gets there, because the
/// cheap scan decides whether the slow path runs at all. A false negative
/// in that scan is the daemon not starting.
#[test]
fn a_quoted_retired_tags_key_is_stripped_too() {
    let dir = tempfile::tempdir().unwrap();
    let master = write(
        dir.path(),
        "config.toml",
        r#"schema_version = 3

[server]
default_profile = "default"

[profiles.default]
display_name = "Default"

[[blocklists]]
id = "ads-list"
display_name = "Ads"
url = "https://lists.purge.cc/ads.txt"
"tags" = ["ads"]

[upstream]
servers = ["192.0.2.1:53"]
"#,
    );

    let loaded = load_config(&master, now())
        .expect("`\"tags\"` is the same key as `tags` — serde refuses both alike");
    assert_eq!(loaded.files_loaded.len(), 1, "must be the fast path");
    assert_eq!(loaded.config.blocklists.len(), 1);
}

/// **Control arm.** The strip must remove one named key, not soften
/// `deny_unknown_fields` into ignoring whatever it does not recognise.
///
/// Without this, a "fix" that simply dropped `deny_unknown_fields` from
/// the five structs would pass every other test in this file — and take
/// the typo protection with it.
#[test]
fn an_unknown_key_that_is_not_tags_is_still_refused() {
    let dir = tempfile::tempdir().unwrap();
    let master = write(
        dir.path(),
        "config.toml",
        r#"schema_version = 3

[server]
default_profile = "default"

[profiles.default]
display_name = "Default"

[[blocklists]]
id = "ads-list"
display_name = "Ads"
url = "https://lists.purge.cc/ads.txt"
tagz = ["ads"]

[upstream]
servers = ["192.0.2.1:53"]
"#,
    );

    let errs = load_config(&master, now()).expect_err(
        "a misspelled key must still be refused — that is what deny_unknown_fields buys",
    );
    assert!(
        format!("{errs:?}").contains("tagz"),
        "and the refusal must name the key: {errs:?}"
    );
}

/// The other half of the control: `tags` on a section that never had the
/// field is not silently swallowed either. The strip is scoped to the
/// five entity sections, not to the string `tags`.
#[test]
fn a_tags_key_on_a_daemon_section_is_still_refused() {
    let dir = tempfile::tempdir().unwrap();
    let master = write(
        dir.path(),
        "config.toml",
        r#"schema_version = 3

[server]
default_profile = "default"
tags = ["nope"]

[profiles.default]
display_name = "Default"

[upstream]
servers = ["192.0.2.1:53"]
"#,
    );

    load_config(&master, now())
        .expect_err("`[server].tags` was never a field and must not be stripped");
}
