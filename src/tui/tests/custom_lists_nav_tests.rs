use super::*;
use crate::config::schema::{ConfigV1, CustomList, Id};

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

/// **`h` and `l` are bound here; `j` and `k` are not — and the split is
/// deliberate, not an oversight.**
///
/// The four vim aliases were deleted TUI-wide, and this leaf is the
/// only place any of them came back. The operator asked for it, and
/// the reason it is coherent is the axis: this is the one leaf with two
/// side-by-side panes, so `h`/`l` name a movement that exists here and
/// nowhere else. `j`/`k` would duplicate `↑`/`↓`, which every leaf
/// already has, so they stay unbound.
///
/// Pinning both halves is what makes this a test rather than a note: a
/// build that bound all four, or none, fails.
#[test]
fn h_and_l_move_the_focus_while_j_and_k_stay_unbound() {
    for ch in ['j', 'k'] {
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
    press(&mut app, KeyCode::Char('l'));
    assert_eq!(
        app.custom_lists.focus,
        CustomListsFocus::Rules,
        "`l` must reach the rule pane"
    );
    press(&mut app, KeyCode::Char('h'));
    assert_eq!(
        app.custom_lists.focus,
        CustomListsFocus::Lists,
        "`h` must come back"
    );
}

/// Focus must never rest on a pane the layout does not paint. At the
/// 80x24 floor the split collapses, so this is the DEFAULT state there,
/// not an edge case — and a `Rules` focus would leave the operator
/// moving a cursor on a table that is not on screen.
#[test]
fn the_focus_cannot_enter_a_rule_pane_the_layout_does_not_paint() {
    let mut app = app_with(&["a"]);
    app.custom_lists.rules_pane_painted = false;
    press(&mut app, KeyCode::Enter);
    assert_eq!(app.custom_lists.focus, CustomListsFocus::Lists);
    assert!(
        app.leaf_key_unhandled,
        "a refused focus move must report unhandled, not swallow the key"
    );
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

/// **"No config" is not "a config with no custom lists".** This runs on
/// every dirty render, so without the guard a failed load would discard
/// the operator's place with nobody pressing a key.
#[test]
fn a_failed_load_does_not_wipe_the_anchor() {
    let mut app = app_with(&["a"]);
    app.custom_lists.selected_id = Some("a".to_string());
    app.loaded_config = None;
    ensure_custom_list_selection_seeded(&mut app);
    assert_eq!(app.custom_lists.selected_id.as_deref(), Some("a"));
    press(&mut app, KeyCode::Down);
    assert_eq!(app.custom_lists.selected_id.as_deref(), Some("a"));
}
