use super::*;
use crate::config::schema::{Blocklist, BlocklistBase, BlocklistFormat, BlocklistTrust};

/// A modal populated the way the operator's buffers would be, for the
/// given enum triple. Built from the production `build_add_modal` so
/// the test cannot drift from the real default set.
fn modal_with(
    format: BlocklistFormat,
    base: BlocklistBase,
    trust: BlocklistTrust,
) -> app::EditListModal {
    let mut m = tabs::lists::build_add_modal();
    m.blocklist_id = "privacy-ads".to_string();
    m.display_name = "Privacy: Ads".to_string();
    m.url = "https://lists.purge.cc/privacy/ads.txt".to_string();
    m.format = format;
    m.nature = base;
    m.original.trust = trust;
    m
}

/// The discriminating probe: serialise the payload the way the save
/// path does (TOML text on disk) and read it back through the schema's
/// own `Deserialize`. Serde layer only — driving this through the
/// validator instead would fail for *legitimate* policy reasons
/// (`trust = signed` is parked; `base = allow` demands `trust = local`)
/// and drown the drift signal.
#[test]
fn save_payload_round_trips_for_every_enum_variant() {
    let formats = [
        BlocklistFormat::Domains,
        BlocklistFormat::Adguard,
        BlocklistFormat::Hosts,
    ];
    // All three, deliberately. The array was two-valued when
    // `BlocklistBase` was, and a round-trip fence that skips a variant
    // proves nothing about the variant it skips — which is exactly how
    // `s-tui-lists-edit-save-rejected` shipped: a token the save path
    // wrote and the schema could not read.
    let kinds = [
        BlocklistBase::Deny,
        BlocklistBase::Allow,
        BlocklistBase::Ignore,
    ];
    let trusts = [
        BlocklistTrust::Local,
        BlocklistTrust::Signed,
        BlocklistTrust::RemoteUnsigned,
    ];

    for format in formats {
        for kind in kinds {
            for trust in trusts {
                let modal = modal_with(format, kind, trust);
                let value = build_blocklist_value(&modal)
                    .unwrap_or_else(|e| panic!("payload must build for {kind:?}/{trust:?}: {e}"));
                let text = toml::to_string_pretty(&value).expect("payload serialises");
                let back: Blocklist = toml::from_str(&text).unwrap_or_else(|e| {
                    panic!(
                        "TUI save payload is unreadable by the schema \
                             ({format:?}/{kind:?}/{trust:?}): {e}\n--- payload ---\n{text}"
                    )
                });
                assert_eq!(back.format, format, "format drifted:\n{text}");
                assert_eq!(back.base, kind, "kind drifted:\n{text}");
                assert_eq!(back.trust, trust, "trust drifted:\n{text}");
            }
        }
    }
}

/// Step-2 probe from the brief, kept as the end-to-end fence: drive the
/// modal's payload through the *whole* save pipeline
/// (`build_blocklist_value` → `upsert_id_keyed` → `write_value_validated`)
/// against a hand-written minimal config. This is the closest local
/// equivalent of the operator pressing Save.
#[test]
fn save_pipeline_lands_an_edit_on_a_minimal_config() {
    use crate::cli::commands::target::{
        read_or_empty, resolve_target_file, upsert_id_keyed, write_value_validated, EntityClass,
    };

    let dir = tempfile::tempdir().unwrap();
    let master = dir.path().join("config.toml");
    std::fs::write(
        &master,
        r#"schema_version = 3

[upstream]
servers = ["192.0.2.1:53"]

[profiles.default]
display_name = "Default"

[[blocklists]]
id = "privacy-ads"
display_name = "Privacy: Ads"
url = "https://lists.purge.cc/privacy/ads.txt"
format = "domains"
update_interval_hours = 12
max_entries = 5000000
enabled = true
base = "deny"
trust = "remote-unsigned"
tags = ["uncategorized"]
"#,
    )
    .unwrap();

    // The operator renames the list and presses Save.
    let mut modal = modal_with(
        BlocklistFormat::Domains,
        BlocklistBase::Deny,
        BlocklistTrust::RemoteUnsigned,
    );
    modal.display_name = "Privacy: Ads (renamed)".to_string();

    let value = build_blocklist_value(&modal).expect("payload builds");
    let target = resolve_target_file(&master, EntityClass::Blocklists, None).unwrap();
    let (mut doc, _) = read_or_empty(&target).unwrap();
    upsert_id_keyed(
        &mut doc,
        EntityClass::Blocklists.toml_key(),
        "privacy-ads",
        value,
    )
    .unwrap();
    write_value_validated(&master, &target, &doc)
        .expect("the TUI's own payload must survive the validator");

    let on_disk = std::fs::read_to_string(&target).unwrap();
    assert!(
        on_disk.contains("Privacy: Ads (renamed)"),
        "edit did not land:\n{on_disk}"
    );
    assert!(
        on_disk.contains("base = \"deny\""),
        "wire token for kind must be `deny`:\n{on_disk}"
    );
}

/// `lists-s3-surface-5m`: `build_add_modal`'s `original.max_entries`
/// used to hardcode `5_000_000` — a stale copy of the daemon-wide
/// default (raised to 10M) that the modal's comment claimed was "the
/// daemon-wide default" while no longer reading it. Since the
/// fail-closed corpus guard, exceeding `max_entries` refuses the
/// whole source (keeping the previous generation) instead of
/// truncating it, so this is what actually reaches the operator's
/// TOML on save, not just what the builder's struct holds — the bug
/// lived in the emitted bytes, so this asserts those bytes.
#[test]
fn add_modal_save_payload_writes_the_shared_default_max_entries() {
    let mut modal = tabs::lists::build_add_modal();
    modal.blocklist_id = "fresh-list".to_string();
    modal.display_name = "Fresh List".to_string();
    modal.url = "https://lists.purge.cc/fresh.txt".to_string();

    let value = build_blocklist_value(&modal).expect("payload builds");
    let text = toml::to_string_pretty(&value).expect("payload serialises");

    assert!(
        text.contains(&format!(
            "max_entries = {}",
            crate::lists::parser::DEFAULT_MAX_LIST_ENTRIES
        )),
        "modal save payload must emit the shared default, not a stale \
             5M copy:\n{text}"
    );

    let back: Blocklist = toml::from_str(&text).expect("payload deserialises");
    assert_eq!(
        back.max_entries,
        crate::lists::parser::DEFAULT_MAX_LIST_ENTRIES as u64,
        "value that reaches the schema after a round-trip must match \
             the shared default"
    );
}
