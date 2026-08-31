use super::*;
use crate::config::schema::Group;

/// Minimal config: two profiles, two devices, and a group carrying a
/// populated `devices` list AND a populated `tags` array. Real
/// `load_config` (not a hand-built `ConfigV1`) so the writers see the
/// same TOML document shape they do in production.
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

[profiles.kids]
display_name = "Kids"

[[devices]]
id = "phone-1"
display_name = "Phone 1"
mac = "AA:BB:CC:DD:EE:01"

[[devices]]
id = "phone-2"
display_name = "Phone 2"
mac = "AA:BB:CC:DD:EE:02"

[[groups]]
id = "phones"
display_name = "Phones"
profile = "home"
priority = 7
devices = ["phone-1", "phone-2"]
tags = ["ads"]
"#,
    )
    .unwrap();
    (dir, master)
}

/// Read the `[[groups]]` row straight out of the **file**.
///
/// §9.1 of the design doc is explicit that the round-trip assertion
/// goes against the file, not the loaded struct, and that is not
/// pedantry: the loader synthesises values the file does not carry
/// (`auto_promote_blocklists` putting `uncategorized` on untagged
/// lists is the scar this rule came from). A struct-level assertion
/// would pass on a file that had lost the field and gained it back
/// from a default.
fn raw_group(config_path: &std::path::Path, id: &str) -> toml::value::Table {
    let text = std::fs::read_to_string(config_path).unwrap();
    let doc: toml::Value = toml::from_str(&text).unwrap();
    doc.get("groups")
        .and_then(|v| v.as_array())
        .expect("[[groups]] array must exist in the file")
        .iter()
        .find(|item| item.get("id").and_then(|v| v.as_str()) == Some(id))
        .unwrap_or_else(|| panic!("group {id} not in the file"))
        .as_table()
        .unwrap()
        .clone()
}

fn raw_str_array(tbl: &toml::value::Table, key: &str) -> Vec<String> {
    tbl.get(key)
        .and_then(|v| v.as_array())
        .map(|a| a.iter().map(|v| v.as_str().unwrap().to_string()).collect())
        .unwrap_or_default()
}

fn loaded_group(config_path: &std::path::Path, id: &str) -> Group {
    crate::config::loader::load_config(config_path, time::OffsetDateTime::now_utc())
        .unwrap()
        .config
        .groups
        .iter()
        .find(|g| g.id.as_str() == id)
        .unwrap()
        .clone()
}

/// An `App` whose only non-default state is the config read from
/// `config_path`. Struct-update rather than default-then-assign:
/// `clippy::field_reassign_with_default` rejects the latter, and the
/// former also makes it obvious that nothing *else* about the app is
/// primed — these tests exercise `handle_groups_key` against a bare
/// dashboard, which is the state the key first arrives in.
fn app_on(config_path: &std::path::Path) -> App {
    App {
        loaded_config: load_v1_config(config_path),
        ..App::default()
    }
}

fn snapshot_of(g: &Group) -> group_modal::OriginalSnapshot {
    group_modal::OriginalSnapshot {
        id: g.id.as_str().to_string(),
        display_name: g.display_name.clone(),
        devices: g.devices.iter().map(|d| d.as_str().to_string()).collect(),
        profile: g.profile.as_str().to_string(),
        priority: g.priority,
    }
}

// ── §9.1 (2): the round-trip that would have caught the
//              `accept_unsigned_allow` bug ──────────────────────────

/// **The DG5 gate for the TUI submit path.** Rename a group that
/// carries both `devices` and `tags`, then read the file back and
/// assert nothing else moved.
///
/// `groups.rs` already pins this for `add_inner`'s row builder. This
/// is the other end of the same hazard and the one §9.1 asks for by
/// name: `upsert_id_keyed` replaces a matched row outright
/// (`*item = entry`), so the moment any surface reconstructs a whole
/// `Group` table to save an edit, every field it forgot is reset to
/// its serde default — on save of *anything*, not of that field. That
/// is exactly how a list lost its consent flag to a rename and became
/// uneditable.
///
/// `submit_group_edit` avoids the class structurally (DG4) by routing
/// through the field-surgical `set_fields_inner`. This test is what
/// stops someone swapping in a row builder for convenience, and the
/// exhaustive destructuring below is what stops a **seventh** field
/// being added to `Group` and silently vanishing here.
#[test]
fn dg5_a_tui_rename_preserves_every_other_group_field_on_disk() {
    let (_dir, master) = fixture();
    let before = loaded_group(&master, "phones");
    let original = snapshot_of(&before);

    let resolved = group_modal::ResolvedForm {
        id: "phones".into(),
        display_name: "Family phones".into(), // the ONLY change
        devices: vec!["phone-1".into(), "phone-2".into()],
        profile: "home".into(),
        priority: 7,
    };

    match submit_group_edit(&master, &original, &resolved) {
        group_modal::SubmitOutcome::Ok(msg) => {
            assert!(msg.contains("field"), "expected a field-change note: {msg}");
        }
        group_modal::SubmitOutcome::Failed(e) => panic!("expected Ok, got: {e}"),
    }

    // Assert on the FILE. See `raw_group`.
    let row = raw_group(&master, "phones");
    assert_eq!(
        row.get("display_name").and_then(|v| v.as_str()),
        Some("Family phones")
    );
    assert_eq!(
        raw_str_array(&row, "devices"),
        vec!["phone-1".to_string(), "phone-2".to_string()],
        "membership is the group's entire substance and must survive a rename"
    );
    // **`plp-s5d`: this assertion is load-bearing, and more so than
    // before.** It used to guard a second writer (`entity_tags`) that
    // ran alongside the scalar batch. That writer is gone, and the
    // modal no longer shows or carries `tags` at all — so this is now
    // the proof that removing the picker did NOT quietly start
    // stripping the operator's `tags` array from the file on every
    // save. `set_fields_inner` writes only the fields it is handed, so
    // an untouched key survives; that is the property, and this reads
    // the FILE back to check it rather than trusting the writer.
    assert_eq!(
        raw_str_array(&row, "tags"),
        vec!["ads".to_string()],
        "a scalar-only save must leave the operator's tags array on disk untouched"
    );
    assert_eq!(row.get("profile").and_then(|v| v.as_str()), Some("home"));
    assert_eq!(row.get("priority").and_then(|v| v.as_integer()), Some(7));

    // Exhaustive on purpose — no `..`. The day someone adds a field to
    // `Group`, THIS STOPS COMPILING and they have to decide whether the
    // TUI edit path carries it, instead of discovering months later
    // that it vanishes on the next save. Prose does not fail a build;
    // this does — and it earned its keep in `plp-s5a`, which removed a
    // field and was named by this line rather than by a grep.
    let Group {
        id,
        display_name,
        profile,
        priority,
        devices,
    } = loaded_group(&master, "phones");
    assert_eq!(id.as_str(), "phones");
    assert_eq!(display_name, "Family phones");
    assert_eq!(profile.as_str(), "home");
    assert_eq!(priority, 7);
    assert_eq!(
        devices.iter().map(|d| d.as_str()).collect::<Vec<_>>(),
        vec!["phone-1", "phone-2"]
    );
}

// `plp-s5d` removed `dg12_a_tags_only_edit_is_refused_now` and
// `a_scalar_and_a_tag_change_in_one_save_are_refused_together`, for the
// same reason as their subnet twins: both drove `ResolvedForm.tags`
// into `submit_group_edit` and asserted `Failed(TAGS_RETIRED)`.
// `ResolvedForm` has no `tags` field, so neither can be written any
// more — the runtime refusal became a type-level impossibility, which
// is the stronger form of the same guarantee.
//
// The one thing they also bought that is NOT structural — that a save
// leaves the operator's on-disk `tags` array alone — did not leave with
// them: `dg5_a_tui_rename_preserves_every_other_group_field_on_disk`
// asserts it against the FILE, and its comment says why that matters
// more now than it did before.

#[test]
fn an_edit_that_diverges_in_nothing_reports_unchanged() {
    let (_dir, master) = fixture();
    let g = loaded_group(&master, "phones");
    let original = snapshot_of(&g);
    let resolved = group_modal::ResolvedForm {
        id: "phones".into(),
        display_name: "Phones".into(),
        devices: vec!["phone-1".into(), "phone-2".into()],
        profile: "home".into(),
        priority: 7,
    };
    match submit_group_edit(&master, &original, &resolved) {
        group_modal::SubmitOutcome::Ok(msg) => assert!(msg.contains("unchanged"), "{msg}"),
        group_modal::SubmitOutcome::Failed(e) => panic!("expected Ok, got: {e}"),
    }
}

/// An undefined device id is refused, and **nothing lands** — not the
/// rename that shared the same batch.
///
/// `set_fields_inner` does not call `validate_group_refs` (only
/// `add_inner` does), so this refusal comes from
/// `write_value_validated` validating the combined final state before
/// promoting — `check_groups` in the validator. That is exactly why
/// the modal does not pre-flight device ids itself: a TUI-side copy
/// would be a second place for the two to disagree. This test is what
/// says the delegation actually holds.
#[test]
fn an_unknown_device_id_is_refused_and_the_batch_leaves_nothing_behind() {
    let (_dir, master) = fixture();
    let original = snapshot_of(&loaded_group(&master, "phones"));

    let resolved = group_modal::ResolvedForm {
        id: "phones".into(),
        display_name: "Renamed".into(), // shares the atomic batch
        devices: vec!["phone-1".into(), "ghost".into()],
        profile: "home".into(),
        priority: 7,
    };

    match submit_group_edit(&master, &original, &resolved) {
        group_modal::SubmitOutcome::Ok(msg) => {
            panic!("an undefined device must be refused, got Ok: {msg}")
        }
        group_modal::SubmitOutcome::Failed(e) => {
            assert!(e.contains("ghost"), "the message must name the id: {e}");
        }
    }

    let row = raw_group(&master, "phones");
    assert_eq!(
        row.get("display_name").and_then(|v| v.as_str()),
        Some("Phones"),
        "the rename shared the atomic batch and must NOT have landed"
    );
    assert_eq!(
        raw_str_array(&row, "devices"),
        vec!["phone-1".to_string(), "phone-2".to_string()],
        "membership must be untouched after a refused batch"
    );
}

// ── Key handling ──────────────────────────────────────────────────

/// **The whole reason `a` sits above the empty-list guard.**
///
/// A config with zero groups is the exact state in which an operator
/// most needs to create one, and it is the state in which the old
/// handler returned before looking at the key at all. It is also the
/// state `tabs::groups::EMPTY_HINT` now promises works — that copy is
/// a lie no compiler catches if this guard is ever reordered.
#[test]
fn groups_add_opens_on_an_empty_config() {
    let dir = tempfile::tempdir().unwrap();
    let master = dir.path().join("config.toml");
    std::fs::write(
            &master,
            "schema_version = 3\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n\n[server]\ndefault_profile = \"home\"\n\n\
             [profiles.home]\ndisplay_name = \"Home\"\n",
        )
        .unwrap();

    let mut app = app_on(&master);
    assert!(
        app.loaded_config
            .as_ref()
            .is_some_and(|l| l.config.groups.is_empty()),
        "fixture must have zero groups — that is the state under test"
    );

    handle_groups_key(&mut app, KeyEvent::from(KeyCode::Char('a')));
    assert!(
        app.groups.modal.is_some(),
        "`a` must open the Add modal with zero groups configured"
    );
    // And the form is usable: the profile snapshot was captured, so
    // `try_resolve` can produce a group rather than erroring on an
    // empty vocabulary.
    let form = app.groups.modal.as_ref().unwrap().form().unwrap();
    assert_eq!(form.profiles_snapshot, vec!["home".to_string()]);
}

/// The differential: `e` and `d` genuinely need a row, so they must
/// stay *below* the empty-list guard. Without this arm a handler that
/// moved every opener above it would pass the test before.
#[test]
fn groups_edit_and_delete_stay_inert_on_an_empty_config() {
    let dir = tempfile::tempdir().unwrap();
    let master = dir.path().join("config.toml");
    std::fs::write(
            &master,
            "schema_version = 3\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n\n[server]\ndefault_profile = \"home\"\n\n\
             [profiles.home]\ndisplay_name = \"Home\"\n",
        )
        .unwrap();
    let mut app = app_on(&master);

    handle_groups_key(&mut app, KeyEvent::from(KeyCode::Char('e')));
    assert!(app.groups.modal.is_none(), "`e` has nothing to edit");
    handle_groups_key(&mut app, KeyEvent::from(KeyCode::Char('d')));
    assert!(app.groups.modal.is_none(), "`d` has nothing to remove");
}

/// **The third arm, and the one that distinguishes the two guards.**
///
/// A config that failed to load is NOT a config with no groups. With
/// no `loaded_config` there is no profile snapshot either, so an Add
/// form opened here would tell the operator "no profiles defined —
/// create one first" — false twice over: their profiles exist, and
/// the actual problem is that the file did not parse. The leaf is
/// already saying so on screen ("could not load config — press r").
///
/// Without this test the two guards are indistinguishable: the
/// zero-groups case above passes either way, because it has a config.
#[test]
fn no_key_opens_a_modal_when_the_config_did_not_load() {
    for key in ['a', 'e', 'd', 'j', 'k'] {
        // `App::default()` leaves `loaded_config: None` — the
        // parse-failure state, not the empty-config one.
        let mut app = App::default();
        handle_groups_key(&mut app, KeyEvent::from(KeyCode::Char(key)));
        assert!(
            app.groups.modal.is_none(),
            "`{key}` must stay inert while the config is unreadable — \
                 an Add form here reports a missing profile vocabulary that \
                 is not actually missing"
        );
    }
}

#[test]
fn groups_edit_opens_prefilled_from_the_focused_row() {
    let (_dir, master) = fixture();
    let mut app = app_on(&master);

    handle_groups_key(&mut app, KeyEvent::from(KeyCode::Char('e')));
    let form = app
        .groups
        .modal
        .as_ref()
        .expect("`e` opens on the first row when nothing is anchored")
        .form()
        .unwrap();
    assert_eq!(form.mode, group_modal::FormMode::Edit);
    assert_eq!(form.id, "phones");
    assert_eq!(form.devices, "phone-1, phone-2");
    assert_eq!(form.priority_input, "7");
}

#[test]
fn groups_delete_confirm_carries_the_members_that_lose_the_binding() {
    let (_dir, master) = fixture();
    let mut app = app_on(&master);

    handle_groups_key(&mut app, KeyEvent::from(KeyCode::Char('d')));
    let rc = app
        .groups
        .modal
        .as_ref()
        .expect("`d` opens the confirm")
        .remove()
        .unwrap();
    assert_eq!(rc.id, "phones");
    assert_eq!(
        rc.devices,
        vec!["phone-1".to_string(), "phone-2".to_string()]
    );
}

#[test]
/// `plp-s5d`: was
/// `next_editable_group_field_skips_tags_on_add_and_id_on_edit`. With
/// the picker gone there is no Add/Edit asymmetry below the action
/// row, so both modes walk Priority -> Submit; the Id skip on Edit is
/// the one rule that survives.
fn next_editable_group_field_skips_id_in_edit_mode_only() {
    use group_modal::{FormField, FormMode};
    // Both modes: Priority is the last field before the action row.
    assert_eq!(
        next_editable_group_field(FormField::Priority, FormMode::Add),
        FormField::Submit
    );
    assert_eq!(
        next_editable_group_field(FormField::Priority, FormMode::Edit),
        FormField::Submit
    );
    // Edit still skips Id.
    assert_eq!(
        next_editable_group_field(FormField::Cancel, FormMode::Edit),
        FormField::DisplayName
    );
    // Add does NOT skip Id (it's a normal editable field there).
    assert_eq!(
        next_editable_group_field(FormField::Cancel, FormMode::Add),
        FormField::Id
    );
    // And backwards, so a skip that only works one way is caught.
    assert_eq!(
        prev_editable_group_field(FormField::Submit, FormMode::Add),
        FormField::Priority
    );
    assert_eq!(
        prev_editable_group_field(FormField::DisplayName, FormMode::Edit),
        FormField::Cancel
    );
}
