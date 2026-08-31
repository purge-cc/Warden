use super::*;
use crate::config::loader::LoadedConfig;
use crate::config::schema::{AdminRule, ConfigV1, Id, Profile, Subnet};
use crate::lists::status::BlocklistStatusDto;
use std::collections::BTreeMap;

fn loaded(cfg: ConfigV1) -> LoadedConfig {
    LoadedConfig {
        config: cfg,
        master_path: std::path::PathBuf::from("/tmp/dummy.toml"),
        files_loaded: Vec::new(),
        total_bytes: 0,
        provenance: Default::default(),
        custom_lists: Default::default(),
    }
}

// ── Lists ───────────────────────────────────────────────────────────

fn dto(id: &str) -> BlocklistStatusDto {
    BlocklistStatusDto {
        source: format!("https://example.test/{id}.txt"),
        id: Some(id.to_string()),
        ..Default::default()
    }
}

/// The Lists table is a flat row-per-blocklist model (no grouping
/// header) — list `n` sits at index `n`.
fn app_with_lists(ids: &[&str]) -> App {
    let mut app = App::new();
    app.active_leaf = Leaf::Lists;
    app.lists.entries = ids.iter().map(|id| dto(id)).collect();
    app
}

/// Focus a list row the way ↑/↓ does — visual index and stable anchor
/// moved together.
fn focus_list(app: &mut App, id: &str) {
    let want = format!("id:{id}");
    let rows = tabs::lists::build_grouped_rows(app);
    let idx = rows
        .iter()
        .position(|r| tabs::lists::row_key(r).as_deref() == Some(want.as_str()))
        .expect("row exists");
    app.lists.table_state.select(Some(idx));
    app.lists.selected_id = tabs::lists::row_key(&rows[idx]);
}

#[test]
fn lists_poll_that_drops_the_selected_row_leaves_a_live_cursor() {
    let mut app = app_with_lists(&["a", "b", "c"]);
    focus_list(&mut app, "c");
    assert_eq!(app.lists.table_state.selected(), Some(2), "last row");

    // The poll fires on its own and `c` is gone (a TUI delete, an
    // external `warden list remove`, a config reload). The row set
    // shrinks under a cursor the operator never touched.
    app.lists.entries = vec![dto("a"), dto("b")];
    reconcile_lists_selection(&mut app);

    assert_eq!(
        app.lists.table_state.selected(),
        Some(1),
        "degrades to the new last row — and to a selectable one"
    );
    let focused = tabs::lists::focused_list(&app).expect("cursor addresses a live row");
    assert_eq!(
        focused.selection_key(),
        "id:b",
        "Enter/K act on a real list instead of becoming silent no-ops"
    );
    assert_eq!(
        app.lists.selected_id.as_deref(),
        Some("id:b"),
        "the anchor is re-seeded where we landed, so the NEXT poll tracks that list"
    );
}

#[test]
fn lists_row_vanishing_above_the_cursor_does_not_retarget_the_action() {
    // Rows: [a, b, c, d] (flat table, no header) — the operator is
    // on `c` at index 2.
    let mut app = app_with_lists(&["a", "b", "c", "d"]);
    focus_list(&mut app, "c");
    assert_eq!(app.lists.table_state.selected(), Some(2));

    // A poll lands with `a` removed. Rows are now [b, c, d]: index 2
    // is `d`, and it is still perfectly IN RANGE — so a clamp does
    // nothing, leaves the cursor on `d`, and Enter edits the wrong
    // list. This is the half of the bug clamping cannot reach.
    app.lists.entries = vec![dto("b"), dto("c"), dto("d")];
    reconcile_lists_selection(&mut app);

    assert_eq!(
        app.lists.table_state.selected(),
        Some(1),
        "the highlight follows `c` to its new index rather than holding the old slot"
    );
    assert_eq!(
        tabs::lists::focused_list(&app).map(|m| m.selection_key()),
        Some("id:c".to_string()),
        "Enter/K must still target `c` — never the list that slid into its index"
    );
}

#[test]
fn lists_cursor_clears_when_every_row_disappears() {
    let mut app = app_with_lists(&["a", "b"]);
    focus_list(&mut app, "b");

    // An IPC error clears `entries` (the poll's Err arm does exactly
    // this). No rows means no valid selection.
    app.lists.entries.clear();
    reconcile_lists_selection(&mut app);

    assert_eq!(app.lists.table_state.selected(), None);
    assert_eq!(app.lists.selected_id, None);
    assert!(tabs::lists::focused_list(&app).is_none());
}

#[test]
fn lists_untouched_tab_is_left_unseeded() {
    // Pre-fix behaviour worth keeping: entering the tab does not
    // auto-highlight a row — the first ↑/↓ seeds the cursor.
    let mut app = app_with_lists(&["a", "b"]);
    reconcile_lists_selection(&mut app);
    assert_eq!(app.lists.table_state.selected(), None);
    assert_eq!(app.lists.selected_id, None);
}

// ── Rules ───────────────────────────────────────────────────────────

fn app_with_rules(rules: &[(&str, &str)]) -> App {
    let admin_rules: Vec<AdminRule> = rules
        .iter()
        .map(|(id, rule)| AdminRule {
            id: Id::new(*id).unwrap(),
            rule: (*rule).to_string(),
        })
        .collect();
    let mut app = App::new();
    app.active_leaf = Leaf::Rules;
    app.loaded_config = Some(loaded(ConfigV1 {
        admin_rules,
        ..Default::default()
    }));
    app
}

/// Simulate a reload: rewrite `loaded_config` with a new rule set, as
/// every `app.loaded_config = load_v1_config(…)` site does.
fn reload_rules(app: &mut App, rules: &[(&str, &str)]) {
    let admin_rules: Vec<AdminRule> = rules
        .iter()
        .map(|(id, rule)| AdminRule {
            id: Id::new(*id).unwrap(),
            rule: (*rule).to_string(),
        })
        .collect();
    app.loaded_config = Some(loaded(ConfigV1 {
        admin_rules,
        ..Default::default()
    }));
}

fn focus_rule(app: &mut App, id: &str) {
    let rows = tabs::rules::visible_rule_rows(app);
    let idx = rows
        .iter()
        .position(|r| r.id == id)
        .expect("rule is visible");
    app.rules.table_state.select(Some(idx));
    app.rules.selected_id = Some(id.to_string());
}

#[test]
fn rules_delete_of_the_last_rule_leaves_a_live_cursor() {
    let mut app = app_with_rules(&[
        ("r1", "||a.example^"),
        ("r2", "||b.example^"),
        ("r3", "||c.example^"),
    ]);
    focus_rule(&mut app, "r3");
    assert_eq!(app.rules.table_state.selected(), Some(2));

    // The tab's own `d` → confirm → the delete succeeds and
    // `loaded_config` is reloaded one row shorter. Pre-fix the cursor
    // stayed at index 2, out of range: `build_rule_edit_modal_for` read
    // `None`, so Enter and `d` did nothing at all and the cursor was
    // dead until the operator pressed `Up`.
    reload_rules(&mut app, &[("r1", "||a.example^"), ("r2", "||b.example^")]);
    reconcile_rules_selection(&mut app);

    assert_eq!(
        app.rules.table_state.selected(),
        Some(1),
        "cursor snaps to the new last rule instead of dangling past the end"
    );
    let modal = tabs::rules::build_rule_edit_modal_for(&app)
        .expect("Enter/d still open a modal on a real rule");
    assert_eq!(modal.rule_id, "r2");
    assert_eq!(app.rules.selected_id.as_deref(), Some("r2"));
}

#[test]
fn rules_rule_deleted_above_the_cursor_does_not_retarget_the_action() {
    // The action chip is on Deny, so the *visible* vec is the three
    // block rules — `r2` (an allow rule) is filtered out. The cursor
    // index is an index into THAT vec, which is also what
    // `build_rule_edit_modal_for` indexes: resolving against the
    // unfiltered rule list instead would land on a different row.
    let mut app = app_with_rules(&[
        ("r1", "||a.example^"),
        ("r2", "@@||b.example^"),
        ("r3", "||c.example^"),
        ("r4", "||d.example^"),
    ]);
    app.rules.filter = app::RulesFilter::Deny;
    focus_rule(&mut app, "r3");
    assert_eq!(
        app.rules.table_state.selected(),
        Some(1),
        "visible (deny-only) rows are [r1, r3, r4] — r3 is index 1"
    );

    // An external edit + the post-`$EDITOR` reload drops `r1`. Visible
    // rows become [r3, r4]: index 1 is now `r4` and is still IN RANGE,
    // so a clamp leaves the cursor there and `d` deletes the wrong rule.
    reload_rules(
        &mut app,
        &[
            ("r2", "@@||b.example^"),
            ("r3", "||c.example^"),
            ("r4", "||d.example^"),
        ],
    );
    reconcile_rules_selection(&mut app);

    assert_eq!(
        app.rules.table_state.selected(),
        Some(0),
        "r3 tracked to its new index in the FILTERED vec (it is index 1 in the unfiltered one)"
    );
    let modal = tabs::rules::build_rule_edit_modal_for(&app).expect("modal opens");
    assert_eq!(
        modal.rule_id, "r3",
        "Enter edits, and d deletes, the rule the operator is looking at — never r4"
    );
}

#[test]
fn rules_cursor_clears_when_every_rule_is_deleted() {
    let mut app = app_with_rules(&[("r1", "||a.example^")]);
    focus_rule(&mut app, "r1");

    reload_rules(&mut app, &[]);
    reconcile_rules_selection(&mut app);

    assert_eq!(app.rules.table_state.selected(), None);
    assert_eq!(app.rules.selected_id, None);
    assert!(tabs::rules::build_rule_edit_modal_for(&app).is_none());
}

// ── Audit #8 — master/detail must agree after a reload drops the row ──

fn app_with_profiles(ids: &[&str]) -> App {
    let mut profiles = BTreeMap::new();
    for id in ids {
        profiles.insert((*id).to_string(), Profile::default());
    }
    let mut app = App::new();
    app.active_leaf = Leaf::Profiles;
    app.loaded_config = Some(loaded(ConfigV1 {
        profiles,
        ..Default::default()
    }));
    app
}

#[test]
fn profiles_dangling_selection_is_repaired_so_master_and_detail_agree() {
    let mut app = app_with_profiles(&["default", "kids"]);
    app.profiles.selected_id = Some("kids".to_string());
    app.profiles.table_state.select(Some(1));

    // `kids` is deleted outside the TUI; the operator presses `r`.
    // The id now resolves to nothing. Pre-fix `ensure_profile_selection_seeded`
    // returned early on `is_some()`, so the dead id survived: the master
    // fell back to highlighting row 0 on a *local* TableState while the
    // detail card re-read the same dead id and painted "select a profile
    // on the left". Master highlighted; detail empty.
    app.loaded_config = Some(loaded(ConfigV1 {
        profiles: [("default".to_string(), Profile::default())]
            .into_iter()
            .collect(),
        ..Default::default()
    }));
    reconcile_active_leaf_selection(&mut app);

    assert_eq!(
        app.profiles.selected_id.as_deref(),
        Some("default"),
        "the id is re-anchored to row 0 — the same row the master falls back to"
    );
    assert_eq!(app.profiles.table_state.selected(), Some(0));
    // The detail card reads `selected_id` straight out of the config;
    // it now resolves, so it renders the same profile the master
    // highlights instead of its empty stub.
    assert!(
        focused_profile(&app).is_some(),
        "detail card resolves the selection the master is highlighting"
    );
}

#[test]
fn profiles_selection_clears_when_the_last_profile_is_deleted() {
    let mut app = app_with_profiles(&["default"]);
    app.profiles.selected_id = Some("default".to_string());
    app.profiles.table_state.select(Some(0));

    app.loaded_config = Some(loaded(ConfigV1::default()));
    reconcile_active_leaf_selection(&mut app);

    assert_eq!(app.profiles.selected_id, None);
    assert_eq!(app.profiles.table_state.selected(), None);
}

#[test]
fn subnets_dangling_selection_is_repaired_so_master_and_detail_agree() {
    fn subnet(id: &str) -> Subnet {
        Subnet {
            id: Id::new(id).unwrap(),
            display_name: id.to_string(),
            cidrs: vec!["192.0.2.0/24".to_string()],
            profile: Id::new("default").unwrap(),
            priority: 0,
        }
    }

    let mut app = App::new();
    app.active_leaf = Leaf::Subnets;
    app.loaded_config = Some(loaded(ConfigV1 {
        subnets: vec![subnet("lan-a"), subnet("lan-b")],
        ..Default::default()
    }));
    app.subnets.selected_id = Some("lan-b".to_string());
    app.subnets.table_state.select(Some(1));

    // `lan-b` is deleted outside the TUI — same desync as Profiles.
    app.loaded_config = Some(loaded(ConfigV1 {
        subnets: vec![subnet("lan-a")],
        ..Default::default()
    }));
    reconcile_active_leaf_selection(&mut app);

    assert_eq!(
        app.subnets.selected_id.as_deref(),
        Some("lan-a"),
        "re-anchored to row 0 — configured subnets come first in the master list"
    );
    assert_eq!(app.subnets.table_state.selected(), Some(0));
    assert!(
        focused_configured_subnet(&app).is_some(),
        "detail card resolves the selection the master is highlighting"
    );
}
