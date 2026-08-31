use super::*;

/// Minimal config: one profile, one subnet tagged `["ads"]`. Real
/// `load_config` (not a hand-built `ConfigV1`) so `set_fields_inner`
/// / `apply_tags_inner` see the same TOML document shape they do in
/// production.
fn fixture() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let master = dir.path().join("config.toml");
    std::fs::write(
        &master,
        r#"schema_version = 3

[upstream]
servers = ["192.0.2.1:53"]

[server]
default_profile = "home"

[profiles.home]
display_name = "Home"

[[subnets]]
id = "lan"
display_name = "LAN"
cidrs = ["10.0.0.0/24"]
profile = "home"
tags = ["ads"]
"#,
    )
    .unwrap();
    (dir, master)
}

// `plp-s5d` removed `submit_subnet_edit_refuses_a_tags_delta_now` and
// `submit_subnet_edit_refuses_scalar_and_tags_together`.
//
// Both drove `ResolvedForm.tags` into `submit_subnet_edit` and asserted
// it came back `Failed(TAGS_RETIRED)`. `ResolvedForm` no longer HAS a
// `tags` field, so neither test can be written any more — and the
// guarantee they bought is not lost, it is stronger: a tag write from
// this path was refused at runtime, and is now unrepresentable in the
// type. The compiler is the assertion.
//
// What DID leave with them is the atomicity claim they doubled as: a
// Save that touched both a scalar and the tag set failed as a whole.
// There is no longer a second thing to touch, so `submit_subnet_edit`
// is a single `set_fields_inner` write and atomic by construction —
// see its doc-comment.

#[test]
fn submit_subnet_edit_reports_unchanged_when_nothing_diverges() {
    let (_dir, master) = fixture();
    let original = subnet_modal::OriginalSnapshot {
        id: "lan".into(),
        display_name: "LAN".into(),
        cidrs: vec!["10.0.0.0/24".into()],
        profile: "home".into(),
        priority: 0,
    };
    let resolved = subnet_modal::ResolvedForm {
        id: "lan".into(),
        display_name: "LAN".into(),
        cidrs: vec!["10.0.0.0/24".into()],
        profile: "home".into(),
        priority: 0,
    };

    let outcome = submit_subnet_edit(&master, &original, &resolved);
    match outcome {
        subnet_modal::SubmitOutcome::Ok(msg) => assert!(msg.contains("unchanged"), "{msg}"),
        subnet_modal::SubmitOutcome::Failed(e) => panic!("expected Ok, got: {e}"),
    }
}

// ── Id is the only mode-dependent step left in the cycle ──────────

/// `plp-s5d`: this used to be
/// `next_editable_field_skips_tags_in_add_mode_and_id_in_edit_mode`.
/// With the picker gone there is no Add/Edit asymmetry below the
/// action row, so both modes now walk Priority -> Submit; the Id skip
/// on Edit is the one rule that survives, and it is what this pins.
#[test]
fn next_editable_field_skips_id_in_edit_mode_only() {
    use subnet_modal::{FormField, FormMode};
    // Both modes: Priority is the last field before the action row.
    assert_eq!(
        next_editable_field(FormField::Priority, FormMode::Add),
        FormField::Submit
    );
    assert_eq!(
        next_editable_field(FormField::Priority, FormMode::Edit),
        FormField::Submit
    );
    // Edit still skips Id.
    assert_eq!(
        next_editable_field(FormField::Cancel, FormMode::Edit),
        FormField::DisplayName
    );
    // Add does NOT skip Id (it's a normal editable field there).
    assert_eq!(
        next_editable_field(FormField::Cancel, FormMode::Add),
        FormField::Id
    );
}
