use super::*;
use crate::config::schema::{ConfigV1, CustomList, Id};
use crate::operator_rules::{Capabilities, ListDetail, Metadata, TransportLimits};
use crate::tui::operator_policy::PolicyCatalog;

fn loaded_with(ids: &[&str]) -> crate::config::loader::LoadedConfig {
    crate::config::loader::LoadedConfig {
        config: ConfigV1 {
            custom_lists: ids
                .iter()
                .map(|i| CustomList {
                    id: Id::new(*i).unwrap(),
                    display_name: String::new(),
                    description: String::new(),
                })
                .collect(),
            ..Default::default()
        },
        master_path: std::path::PathBuf::from("/tmp/dummy.toml"),
        files_loaded: Vec::new(),
        total_bytes: 0,
        provenance: Default::default(),
        custom_lists: Default::default(),
    }
}

fn app_with(ids: &[&str]) -> App {
    let mut app = App::new();
    app.active_leaf = Leaf::CustomLists;
    app.loaded_config = Some(loaded_with(ids));
    app.operator_catalog = Some(PolicyCatalog {
        capabilities: Capabilities {
            contract_version: crate::operator_rules::CONTRACT_VERSION,
            schema_version: 5,
            operator_rule_grammar: 1,
            operations: Vec::new(),
            semantic_hash: true,
            activation_ack: true,
            cluster_artifact: false,
            limits: TransportLimits::IPC,
        },
        metadata: Metadata {
            contract_version: crate::operator_rules::CONTRACT_VERSION,
            schema_version: 5,
            config_revision: "config-r1".into(),
            desired_operator_policy_hash: String::new(),
            active_policy: None,
            activation_in_sync: true,
            lists: ids.len(),
            mounted_lists: 0,
            orphan_packs: 0,
        },
        lists: ids
            .iter()
            .map(|id| ListDetail {
                id: (*id).to_string(),
                display_name: (*id).to_string(),
                description: String::new(),
                config_revision: "config-r1".into(),
                pack_revision: format!("{id}-r1"),
                bytes: 0,
                rule_count: 0,
                invalid_rows: 0,
                profiles: Vec::new(),
            })
            .collect(),
        orphan_packs: Vec::new(),
    });
    app
}

fn press(app: &mut App, code: KeyCode) {
    handle_custom_lists_key(app, KeyEvent::new(code, KeyModifiers::NONE));
}

#[test]
fn the_cursor_seeds_to_the_first_list_on_the_first_keystroke() {
    let mut app = app_with(&["a", "b"]);
    assert_eq!(app.custom_lists.selected_id, None);
    press(&mut app, KeyCode::Down);
    // Seeded to "a" and *then* stepped — the first Down must not skip
    // the row the operator has not seen highlighted yet.
    assert_eq!(app.custom_lists.selected_id.as_deref(), Some("b"));
}

/// A clamp, not a wrap: these are rows, not a small value cycler.
#[test]
fn the_cursor_clamps_at_both_ends() {
    let mut app = app_with(&["a", "b"]);
    app.custom_lists.selected_id = Some("b".to_string());
    press(&mut app, KeyCode::Down);
    assert_eq!(app.custom_lists.selected_id.as_deref(), Some("b"));
    press(&mut app, KeyCode::Up);
    press(&mut app, KeyCode::Up);
    assert_eq!(app.custom_lists.selected_id.as_deref(), Some("a"));
}

#[test]
fn home_and_end_jump_to_the_ends() {
    let mut app = app_with(&["a", "b", "c"]);
    press(&mut app, KeyCode::End);
    assert_eq!(app.custom_lists.selected_id.as_deref(), Some("c"));
    press(&mut app, KeyCode::Home);
    assert_eq!(app.custom_lists.selected_id.as_deref(), Some("a"));
}

/// Vim aliases are deliberately absent; the Rules pane is reachable with
/// the explicit panel switch even at the narrow floor, where it replaces
/// the master.
#[test]
fn vim_aliases_stay_unbound_and_arrows_reach_rules_at_narrow_width() {
    for ch in ['h', 'j', 'k', 'l'] {
        let mut app = app_with(&["a", "b"]);
        app.custom_lists.selected_id = Some("a".to_string());
        press(&mut app, KeyCode::Char(ch));
        assert_eq!(
            app.custom_lists.selected_id.as_deref(),
            Some("a"),
            "`{ch}` must not move the cursor"
        );
        assert!(
            app.leaf_key_unhandled,
            "`{ch}` must report as unhandled so the help overlay is restored"
        );
    }

    let mut app = app_with(&["a"]);
    app.custom_lists.focus = CustomListsFocus::Lists;
    app.custom_lists.rules_pane_painted = false;
    press(&mut app, KeyCode::Char('v'));
    assert_eq!(
        app.custom_lists.focus,
        CustomListsFocus::Rules,
        "v must reach the full-width Rules pane"
    );
    press(&mut app, KeyCode::Left);
    assert_eq!(
        app.custom_lists.focus,
        CustomListsFocus::Lists,
        "Left must return to the master pane"
    );
}

/// At 80×24 Rules takes the full body when focused, so a narrow terminal
/// must not reject the explicit panel transition.
#[test]
fn narrow_rules_focus_is_reachable() {
    let mut app = app_with(&["a"]);
    app.custom_lists.rules_pane_painted = false;
    press(&mut app, KeyCode::Char('v'));
    assert_eq!(app.custom_lists.focus, CustomListsFocus::Rules);
    assert!(!app.leaf_key_unhandled);
}

/// The anchor names a list the config no longer declares — the renderer
/// falls back to row 0, so the state has to agree before an opener acts
/// on a row other than the highlighted one.
#[test]
fn a_dangling_anchor_is_repaired_to_the_first_row() {
    let mut app = app_with(&["a", "b"]);
    app.custom_lists.selected_id = Some("deleted".to_string());
    ensure_custom_list_selection_seeded(&mut app);
    assert_eq!(app.custom_lists.selected_id.as_deref(), Some("a"));
}

/// **"No catalogue" is not "a catalogue with no custom lists".** This runs on
/// every dirty render, so without the guard a failed load would discard
/// the operator's place with nobody pressing a key.
#[test]
fn a_failed_load_does_not_wipe_the_anchor() {
    let mut app = app_with(&["a"]);
    app.custom_lists.selected_id = Some("a".to_string());
    app.operator_catalog = None;
    ensure_custom_list_selection_seeded(&mut app);
    assert_eq!(app.custom_lists.selected_id.as_deref(), Some("a"));
    press(&mut app, KeyCode::Down);
    assert_eq!(app.custom_lists.selected_id.as_deref(), Some("a"));
}
