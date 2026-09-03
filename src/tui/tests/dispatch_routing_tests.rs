use super::*;
use crate::config::settings::TrackingConfig;
use crate::tui::app::{App, Leaf, TrackingFocus, TrackingPanelState};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use std::path::{Path, PathBuf};

fn key(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

fn dummy_poller(dir: &Path) -> IpcPoller {
    IpcPoller::new(&dir.join("ghost.sock"))
}

fn mk_master(dir: &tempfile::TempDir) -> PathBuf {
    let master = dir.path().join("config.toml");
    std::fs::write(
        &master,
        r#"schema_version = 3

[upstream]
servers = ["192.0.2.1:53"]

[server]
default_profile = "default"

[profiles.default]
display_name = "Default"
"#,
    )
    .unwrap();
    master
}

fn mk_app(master: &Path) -> App {
    let mut app = App::new();
    // Same loader the live `r` refresh + startup path use.
    app.loaded_config = load_v1_config(master);
    app
}

// ── settings-03: the Tracking form must own its keystrokes ──────

fn tracking_app(master: &Path) -> App {
    let mut app = mk_app(master);
    app.active_leaf = Leaf::Settings;
    app.settings.tracking_panel = Some(TrackingPanelState::from_config(&TrackingConfig::default()));
    app
}

#[tokio::test]
async fn settings_03_s_submits_form_not_global_resolver() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    let poller = dummy_poller(dir.path());
    let mut app = tracking_app(&master);
    // Default retention (7) is in range so `s` reaches the submit
    // path; the ghost socket fails the IPC, but a `submit_message`
    // is set either way — proving `s` hit the form, not the global
    // resolver hotkey.
    handle_key(&mut app, key(KeyCode::Char('s')), &poller, &master).await;
    assert!(
        app.resolver_modal.is_none(),
        "`s` must not open the global resolver modal while the Tracking form is open"
    );
    assert!(
        app.settings.tracking_panel.is_some(),
        "the form stays open across submit"
    );
    assert!(
        app.settings
            .tracking_panel
            .as_ref()
            .unwrap()
            .submit_message
            .is_some(),
        "`s` triggered the form submit path"
    );
}

#[tokio::test]
async fn settings_03_digit_lands_in_retention_not_section_nav() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    let poller = dummy_poller(dir.path());
    let mut app = tracking_app(&master);
    {
        let p = app.settings.tracking_panel.as_mut().unwrap();
        p.focus = TrackingFocus::Retention;
        p.retention_input.clear();
    }
    handle_key(&mut app, key(KeyCode::Char('3')), &poller, &master).await;
    assert_eq!(
        app.active_leaf,
        Leaf::Settings,
        "a digit typed into the retention field must not jump to the Network section"
    );
    assert_eq!(
        app.settings
            .tracking_panel
            .as_ref()
            .unwrap()
            .retention_input,
        "3",
        "the digit lands in the retention buffer"
    );
}

#[tokio::test]
async fn settings_03_tab_cycles_field_not_leaf() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    let poller = dummy_poller(dir.path());
    let mut app = tracking_app(&master);
    let before = app.settings.tracking_panel.as_ref().unwrap().focus;
    handle_key(&mut app, key(KeyCode::Tab), &poller, &master).await;
    assert_eq!(
        app.active_leaf,
        Leaf::Settings,
        "Tab must cycle form fields, not leaves, while the Tracking form is open"
    );
    assert_ne!(
        before,
        app.settings.tracking_panel.as_ref().unwrap().focus,
        "Tab advances the focused field"
    );
}

// ── ldns-04 → N6: there is no panel to switch any more ──────────

fn ldns_app(master: &Path) -> App {
    let mut app = mk_app(master);
    app.active_leaf = Leaf::LocalDns;
    app
}

/// A master with records in BOTH scopes, so "reachable without a
/// panel switch" is a claim with something behind it.
fn ldns_master(dir: &tempfile::TempDir) -> PathBuf {
    let master = dir.path().join("config.toml");
    std::fs::write(
        &master,
        r#"schema_version = 3

[upstream]
servers = ["192.0.2.1:53"]

[server]
default_profile = "default"

[profiles.default]
display_name = "Default"

[profiles.kids]
display_name = "Kids"
local_records = [{ domain = "youtube.local", type = "A", value = "10.10.1.9" }]

[[local_dns.records]]
domain = "nas.home"
type = "A"
value = "192.168.1.50"
"#,
    )
    .unwrap();
    master
}

/// **Rewritten for N6, not deleted.** It used to assert that `o`
/// flipped `focused_panel` without cycling the leaf. Both halves have
/// moved: there is no `focused_panel`, so `o` is unbound — and the
/// reachability it bought is now free, because `↓` walks out of
/// Global and into the profile records over the group header.
///
/// The half that has NOT moved is the one the name was really about:
/// whatever the leaf does with its own keys, it must not cycle the
/// leaf. Asserted for `o` still, precisely because `o` is now unbound
/// — an unbound key reaching the global match would be worse than the
/// shadowing bug this test was written for.
#[tokio::test]
async fn ldns_04_panel_switch_is_gone_and_down_crosses_the_scope_boundary() {
    let dir = tempfile::tempdir().unwrap();
    let master = ldns_master(&dir);
    let poller = dummy_poller(dir.path());
    let mut app = ldns_app(&master);

    // `o` is unbound: no leaf change, no state change, nothing opened.
    handle_key(&mut app, key(KeyCode::Char('o')), &poller, &master).await;
    assert_eq!(
        app.active_leaf,
        Leaf::LocalDns,
        "an unbound leaf key must not fall through into a leaf cycle"
    );
    assert!(app.local_dns.modal.is_none());

    // Down from the last (only) Global record lands on the first
    // profile record — the reachability `o` used to gate.
    handle_key(&mut app, key(KeyCode::Down), &poller, &master).await;
    assert_eq!(
        app.local_dns.selected_id,
        Some(("profile:kids".to_string(), "youtube.local".to_string())),
        "Down must cross from Global into the profile group, stepping \
             over the header — no `o`, no `n`, no second key"
    );
}

/// `n` / `N` retired with the panels. They cycled the focused
/// profile; there is no focused profile.
#[tokio::test]
async fn n6_n_and_capital_n_are_unbound_on_local_dns() {
    let dir = tempfile::tempdir().unwrap();
    let master = ldns_master(&dir);
    let poller = dummy_poller(dir.path());
    let mut app = ldns_app(&master);
    handle_key(&mut app, key(KeyCode::Down), &poller, &master).await;
    let anchored = app.local_dns.selected_id.clone();

    for code in [KeyCode::Char('n'), KeyCode::Char('N')] {
        handle_key(&mut app, key(code), &poller, &master).await;
        assert_eq!(
            app.local_dns.selected_id, anchored,
            "{code:?} must not move the cursor — it is unbound"
        );
        assert_eq!(app.active_leaf, Leaf::LocalDns);
    }
}

#[tokio::test]
async fn ldns_04_tab_still_cycles_leaf() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    let poller = dummy_poller(dir.path());
    let mut app = ldns_app(&master);
    handle_key(&mut app, key(KeyCode::Tab), &poller, &master).await;
    assert_ne!(
        app.active_leaf,
        Leaf::LocalDns,
        "Tab keeps its global cycle-leaves meaning on Local DNS"
    );
}

// ── §4.68 UX8: Labels is navigated on the axis it is drawn ────────
//
// **Every test here drives `handle_key`, never `handle_labels_key`.**
// That is the whole point of the block. A test that calls the leaf
// handler directly passes on a dispatcher that never routes the key
// to it — which is exactly how `Tab` behaved before this sprint: it
// was swallowed by the global leaf-cycle arm and could not reach
// Labels at all. G4 lost a sprint to the same shape on `Space`.

use crate::config::schema::LabelKind;

fn mk_labels_master(dir: &tempfile::TempDir) -> PathBuf {
    let master = dir.path().join("config.toml");
    std::fs::write(
        &master,
        r#"schema_version = 3

[upstream]
servers = ["192.0.2.1:53"]

[server]
default_profile = "default"

[profiles.default]
display_name = "Default"

[[labels]]
id = "dweller"
kind = "owner"
display_name = "Dweller"

[[labels]]
id = "dweller2"
kind = "owner"
display_name = "Dweller2"

[[labels]]
id = "laptop"
kind = "device-type"
display_name = "Laptop"
"#,
    )
    .unwrap();
    master
}

fn labels_app(master: &Path) -> App {
    let mut app = mk_app(master);
    app.active_leaf = Leaf::Labels;
    assert!(
        app.loaded_config.is_some(),
        "fixture must parse — every assertion below is vacuous otherwise"
    );
    app
}

/// **Labels must NOT shadow `Tab`.** Deliberate twin of
/// `ldns_04_tab_still_cycles_leaf`, and the pin on a reverted design.
///
/// A two-pane focus switch on `Tab` was built here and taken out: the
/// complaint that opened §4.68 was "Labels does not behave like the
/// other tabs", and making Labels the only leaf where `Tab` means
/// something else recreates that defect somewhere new. Which key
/// switches pane in a two-card layout is a TUI-wide decision, taken
/// once for every leaf, not per leaf.
///
/// Without this test the shadow could be reintroduced by a future
/// session and nothing would notice — a reverted design leaves no
/// trace in the code it was removed from.
#[tokio::test]
async fn ux8_tab_still_cycles_leaves_on_labels() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_labels_master(&dir);
    let poller = dummy_poller(dir.path());
    let mut app = labels_app(&master);
    let focus_before = app.labels.focus;

    handle_key(&mut app, key(KeyCode::Tab), &poller, &master).await;
    assert_ne!(
        app.active_leaf,
        Leaf::Labels,
        "Tab keeps its global cycle-leaves meaning on Labels"
    );
    assert_eq!(
        app.labels.focus, focus_before,
        "and must not have moved the pane focus on the way out"
    );
}

/// `←`/`→` are **absolute**, not toggles, and that is what makes an
/// omitted arm detectable. With a two-variant focus, three toggling
/// keys would be indistinguishable: deleting the `Left` arm, or
/// swapping the `Left` and `Right` bodies, would pass every test.
/// Here `Left` from `Entries` must land on `KindMenu`.
#[tokio::test]
async fn ux8_right_focuses_the_entries_and_left_focuses_the_menu() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_labels_master(&dir);
    let poller = dummy_poller(dir.path());
    let mut app = labels_app(&master);

    handle_key(&mut app, key(KeyCode::Right), &poller, &master).await;
    assert_eq!(app.labels.focus, LabelsFocus::Entries, "Right → entries");
    // Idempotent: Right again stays put rather than bouncing back.
    handle_key(&mut app, key(KeyCode::Right), &poller, &master).await;
    assert_eq!(
        app.labels.focus,
        LabelsFocus::Entries,
        "Right is absolute — a second press is not a toggle"
    );

    handle_key(&mut app, key(KeyCode::Left), &poller, &master).await;
    assert_eq!(app.labels.focus, LabelsFocus::KindMenu, "Left → menu");
    handle_key(&mut app, key(KeyCode::Left), &poller, &master).await;
    assert_eq!(
        app.labels.focus,
        LabelsFocus::KindMenu,
        "Left is absolute too"
    );
}

/// N3 (2026-08-24): `h` / `l` were silent aliases of `\u{2190}` / `\u{2192}` here and
/// are **deleted**. This test used to assert the alias fired; it now
/// asserts it does not. Inverted rather than removed on purpose \u{2014} a
/// deletion nothing pins is a deletion the next session undoes.
#[tokio::test]
async fn ux8_h_and_l_are_no_longer_bound_on_labels() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_labels_master(&dir);
    let poller = dummy_poller(dir.path());
    let mut app = labels_app(&master);

    handle_key(&mut app, key(KeyCode::Char('l')), &poller, &master).await;
    assert_eq!(
        app.labels.focus,
        LabelsFocus::KindMenu,
        "`l` is unbound \u{2014} focus stays on the menu it started on"
    );
    handle_key(&mut app, key(KeyCode::Right), &poller, &master).await;
    assert_eq!(
        app.labels.focus,
        LabelsFocus::Entries,
        "the real binding still works"
    );
    handle_key(&mut app, key(KeyCode::Char('h')), &poller, &master).await;
    assert_eq!(
        app.labels.focus,
        LabelsFocus::Entries,
        "`h` is unbound \u{2014} it does not walk back to the menu"
    );
}

#[tokio::test]
async fn ux8_down_walks_the_kind_menu_while_the_menu_has_focus() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_labels_master(&dir);
    let poller = dummy_poller(dir.path());
    let mut app = labels_app(&master);
    assert_eq!(app.labels.selected_kind, LabelKind::Owner);

    handle_key(&mut app, key(KeyCode::Down), &poller, &master).await;
    assert_eq!(
        app.labels.selected_kind,
        LabelKind::DeviceType,
        "with the menu focused, the vertical key walks the menu — the \
             axis this sprint exists to fix"
    );
}

/// `Up` and `Down` must not be interchangeable: a handler that routed
/// both through one body would pass a same-direction test.
#[tokio::test]
async fn ux8_up_and_down_move_opposite_ways_in_the_menu() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_labels_master(&dir);
    let poller = dummy_poller(dir.path());
    let mut app = labels_app(&master);

    handle_key(&mut app, key(KeyCode::Up), &poller, &master).await;
    assert_eq!(
        app.labels.selected_kind,
        LabelKind::Department,
        "Up from the first kind wraps to the last of the THREE the menu \
             shows — landing on Tag would mean the handler is still walking \
             LabelKind::ALL"
    );
}

#[tokio::test]
async fn ux8_down_walks_the_entries_while_they_have_focus() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_labels_master(&dir);
    let poller = dummy_poller(dir.path());
    let mut app = labels_app(&master);

    handle_key(&mut app, key(KeyCode::Right), &poller, &master).await;
    let kind_before = app.labels.selected_kind;
    handle_key(&mut app, key(KeyCode::Down), &poller, &master).await;
    assert_eq!(
        app.labels.selected_id.as_deref(),
        Some("dweller2"),
        "with the entries focused the vertical key walks rows"
    );
    assert_eq!(
        app.labels.selected_kind, kind_before,
        "and must not also move the kind — one key, one pane"
    );
}

/// N3 mirror of [`ux8_h_and_l_are_no_longer_bound_on_labels`] for the
/// vertical pair.
#[tokio::test]
async fn ux8_j_and_k_are_no_longer_bound_on_labels() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_labels_master(&dir);
    let poller = dummy_poller(dir.path());
    let mut app = labels_app(&master);
    handle_key(&mut app, key(KeyCode::Right), &poller, &master).await;

    handle_key(&mut app, key(KeyCode::Char('j')), &poller, &master).await;
    assert_eq!(
        app.labels.selected_id.as_deref(),
        Some("dweller"),
        "`j` is unbound \u{2014} the cursor stays on row 0. (It is not `None`: \
             `handle_labels_key` seeds the anchor before the match, for ANY \
             key \u{2014} see `ux8_the_row_anchor_is_seeded_on_the_first_keystroke`. \
             Asserting `None` here would be asserting on state the product \
             establishes regardless of the binding under test.)"
    );
    handle_key(&mut app, key(KeyCode::Down), &poller, &master).await;
    assert_eq!(
        app.labels.selected_id.as_deref(),
        Some("dweller2"),
        "the real binding still walks rows"
    );
    handle_key(&mut app, key(KeyCode::Char('k')), &poller, &master).await;
    assert_eq!(
        app.labels.selected_id.as_deref(),
        Some("dweller2"),
        "`k` is unbound \u{2014} the cursor stays put"
    );
}

/// The latent desync: the renderer highlights row 0 when the anchor
/// is `None`, so the operator sees a cursor the state does not have.
/// Read-only today, load-bearing the moment L2's CRUD lands.
#[tokio::test]
async fn ux8_the_row_anchor_is_seeded_on_the_first_keystroke() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_labels_master(&dir);
    let poller = dummy_poller(dir.path());
    let mut app = labels_app(&master);
    assert_eq!(app.labels.selected_id, None, "nothing has been pressed yet");

    // A key that moves neither pane — the seed must not depend on
    // the operator happening to press a navigation key.
    handle_key(&mut app, key(KeyCode::Char('z')), &poller, &master).await;
    assert_eq!(
        app.labels.selected_id.as_deref(),
        Some("dweller"),
        "the anchor agrees with the row the renderer already paints"
    );
}

#[tokio::test]
async fn ux8_changing_kind_reseeds_the_anchor_rather_than_clearing_it() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_labels_master(&dir);
    let poller = dummy_poller(dir.path());
    let mut app = labels_app(&master);

    handle_key(&mut app, key(KeyCode::Down), &poller, &master).await;
    assert_eq!(app.labels.selected_kind, LabelKind::DeviceType);
    assert_eq!(
        app.labels.selected_id.as_deref(),
        Some("laptop"),
        "an id from the old vocabulary is dropped, but the new one is \
             seeded in the same breath — otherwise the desync reopens for \
             a frame on every kind change"
    );
}

/// §4.68 UX8: at the D18 floor the focus must NOT be `KindMenu` —
/// there is no kind menu on screen to own it.
///
/// The default focus is `KindMenu`, so at 80 columns an unclamped
/// build leaves the cursor on a pane that is never painted and `↑`/
/// `↓` swap the whole table's contents instead of moving a row.
#[test]
fn ux8_the_floor_width_forces_focus_off_the_unpainted_menu() {
    let mut app = App::new();
    app.active_leaf = Leaf::Labels;
    assert_eq!(
        app.labels.focus,
        LabelsFocus::KindMenu,
        "the default is the pane that the floor does not paint"
    );

    clamp_labels_focus_to_layout(&mut app, 80);
    assert_eq!(
        app.labels.focus,
        LabelsFocus::Entries,
        "at 80x24 the split collapses, so the menu cannot hold focus"
    );
}

/// The differential: a terminal wide enough to paint the menu must
/// leave the operator's choice alone. Without this, a clamp that
/// simply always wrote `Entries` would pass the test above.
#[test]
fn ux8_a_wide_terminal_leaves_the_focus_alone() {
    let mut app = App::new();
    app.active_leaf = Leaf::Labels;
    clamp_labels_focus_to_layout(&mut app, 100);
    assert_eq!(
        app.labels.focus,
        LabelsFocus::KindMenu,
        "100 columns paints both panes — nothing to clamp"
    );
}

/// The clamp is scoped to its own leaf. It runs on every dirty
/// render, so an unguarded version would rewrite Labels state while
/// the operator is on a different tab entirely.
#[test]
fn ux8_the_clamp_does_not_fire_on_another_leaf() {
    let mut app = App::new();
    app.active_leaf = Leaf::Groups;
    clamp_labels_focus_to_layout(&mut app, 80);
    assert_eq!(
        app.labels.focus,
        LabelsFocus::KindMenu,
        "not the active leaf — leave its state untouched"
    );
}

/// A broken config must not cost the operator their place.
///
/// The seed runs on *every* keystroke, so ordering it above the
/// no-config guard would have it find zero labels and write `None` —
/// one stray key during a failed load silently discarding an anchor
/// that had survived it. The leaf is already painting "could not load
/// config — fix it and press r to retry"; every key stays inert until
/// it does.
#[tokio::test]
async fn ux8_a_failed_load_does_not_wipe_the_anchor() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_labels_master(&dir);
    let poller = dummy_poller(dir.path());
    let mut app = labels_app(&master);
    handle_key(&mut app, key(KeyCode::Right), &poller, &master).await;
    handle_key(&mut app, key(KeyCode::Down), &poller, &master).await;
    assert_eq!(app.labels.selected_id.as_deref(), Some("dweller2"));

    // What a parse failure leaves behind.
    app.loaded_config = None;
    handle_key(&mut app, key(KeyCode::Down), &poller, &master).await;
    assert_eq!(
        app.labels.selected_id.as_deref(),
        Some("dweller2"),
        "the anchor must survive a failed load, not be reset by it"
    );

    // **The path that actually mattered.** This one needs no
    // keystroke: it runs before every dirty render, so a guard that
    // only covered `handle_labels_key` would have been cosmetic —
    // the very next frame would have wiped the anchor anyway.
    reconcile_active_leaf_selection(&mut app);
    assert_eq!(
        app.labels.selected_id.as_deref(),
        Some("dweller2"),
        "the render-time reconcile must not reset it either"
    );
}

/// A kind with no entries must leave the anchor `None`: there is no
/// row, so there must be no cursor claiming one.
#[tokio::test]
async fn ux8_an_empty_kind_anchors_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_labels_master(&dir);
    let poller = dummy_poller(dir.path());
    let mut app = labels_app(&master);

    handle_key(&mut app, key(KeyCode::Up), &poller, &master).await;
    assert_eq!(app.labels.selected_kind, LabelKind::Department);
    assert_eq!(
        app.labels.selected_id, None,
        "no departments declared — nothing to anchor"
    );
}

// ── §4.66 L7: the Labels leaf authors its own vocabulary ──────────
//
// Same rule as the UX8 block above: **every test drives `handle_key`,
// never `handle_labels_key`**. A test that calls the leaf handler
// directly passes on a dispatcher that never routes the key to it —
// and this sprint adds a second dispatcher hop (the modal gate ahead
// of the leaf match), so there are now two ways to be unreachable.

/// A config that parses and declares nothing. The empty vocabulary is
/// not a corner case here: §4.68 UX8 measured **zero** `[[labels]]`
/// rows on both live boxes, so this is the state an operator meets on
/// the day the feature ships.
fn mk_empty_labels_master(dir: &tempfile::TempDir) -> PathBuf {
    let master = dir.path().join("config.toml");
    std::fs::write(
        &master,
        r#"schema_version = 3

[upstream]
servers = ["192.0.2.1:53"]

[server]
default_profile = "default"

[profiles.default]
display_name = "Default"
"#,
    )
    .unwrap();
    master
}

fn labels_of(master: &Path) -> Vec<crate::config::schema::Label> {
    crate::config::loader::load_config(master, time::OffsetDateTime::now_utc())
        .expect("fixture must load")
        .config
        .labels
}

/// `a` must reach the operator on the config they actually have. The
/// guard ordering is the whole point: an emptiness check above `a`
/// would kill the verb precisely where it is the only way in.
#[tokio::test]
async fn l7_a_opens_the_add_modal_on_an_empty_vocabulary() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_empty_labels_master(&dir);
    let poller = dummy_poller(dir.path());
    let mut app = labels_app(&master);
    assert!(
        app.loaded_config.as_ref().unwrap().config.labels.is_empty(),
        "fixture must have no labels — otherwise this asserts nothing"
    );

    handle_key(&mut app, key(KeyCode::Char('a')), &poller, &master).await;
    let modal = app.labels.modal.as_ref().expect("`a` opens the Add modal");
    let form = modal.form().expect("Add opens on the form stage");
    assert_eq!(form.mode, label_modal::FormMode::Add);
    assert_eq!(
        form.kind,
        LabelKind::Owner,
        "the modal binds the focused kind"
    );
}

/// `e` and `d` are the opposite predicate, and they are a **different**
/// predicate from the one above: there is nothing to edit or remove.
#[tokio::test]
async fn l7_e_and_d_stay_inert_on_an_empty_kind() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_empty_labels_master(&dir);
    let poller = dummy_poller(dir.path());
    let mut app = labels_app(&master);

    for k in [KeyCode::Char('e'), KeyCode::Char('d'), KeyCode::Delete] {
        handle_key(&mut app, key(k), &poller, &master).await;
        assert!(
            app.labels.modal.is_none(),
            "{k:?} must not open a modal with nothing selected"
        );
    }
}

/// "No config" is not "a config with no labels". A parse failure
/// leaves every key inert, including `a`: the Add form would be built
/// over a config the writers cannot load anyway.
#[tokio::test]
async fn l7_no_key_opens_a_modal_when_the_config_did_not_load() {
    let dir = tempfile::tempdir().unwrap();
    let master = dir.path().join("broken.toml");
    std::fs::write(&master, "this is not = = toml").unwrap();
    let poller = dummy_poller(dir.path());
    let mut app = mk_app(&master);
    app.active_leaf = Leaf::Labels;
    assert!(
        app.loaded_config.is_none(),
        "fixture must fail to load — otherwise this asserts nothing"
    );

    for k in [
        KeyCode::Char('a'),
        KeyCode::Char('e'),
        KeyCode::Char('d'),
        KeyCode::Delete,
    ] {
        handle_key(&mut app, key(k), &poller, &master).await;
        assert!(
            app.labels.modal.is_none(),
            "{k:?} must stay inert while the config is unreadable"
        );
    }
}

/// The operator's own words: *"questo menù è contestuale alla
/// selezione — se è presente su Owners, il menu parlerà di Owners"*.
/// A modal that always opened on `Owner` would be the context desync
/// the design rejected.
#[tokio::test]
async fn l7_the_add_modal_binds_the_focused_kind_not_the_default() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_labels_master(&dir);
    let poller = dummy_poller(dir.path());
    let mut app = labels_app(&master);

    // Walk the kind menu to Device types, then Add.
    handle_key(&mut app, key(KeyCode::Down), &poller, &master).await;
    assert_eq!(app.labels.selected_kind, LabelKind::DeviceType);

    handle_key(&mut app, key(KeyCode::Char('a')), &poller, &master).await;
    assert_eq!(
        app.labels.modal.as_ref().unwrap().form().unwrap().kind,
        LabelKind::DeviceType,
        "the modal must follow the pane, not the default"
    );
}

/// **The hazard §4.68 UX8 named for this sprint, pinned.** Its step 3
/// warned that `h`/`l` clear `selected_id` while `render_entries`
/// auto-highlights row 0 — *"innocuo finché read-only, portante appena
/// arriva la CRUD"*. If `e` resolved that `None` differently from the
/// renderer, the operator would edit a row other than the highlighted
/// one and nothing on screen would say so.
///
/// Asserted against the **rendered buffer**, not against the resolver:
/// a test that compared two calls to the same helper would pass on a
/// build where the helper disagreed with the table.
///
/// **The property turned out to be guarded twice, and that was found
/// by mutation rather than by reading.** Removing
/// `ensure_labels_selection_seeded` from the handler leaves this green
/// — `focused_label`'s `unwrap_or(0)` covers it. Removing that
/// fallback also leaves it green — the seeding covers it. Only
/// removing **both** reddens this test, which was verified. So neither
/// guard is dead code and neither is load-bearing alone; this test is
/// the one thing that notices if a future change takes both. A
/// mutation report claiming "the fallback is unreachable, delete it"
/// is reading one guard while the other is standing.
#[tokio::test]
async fn l7_edit_acts_on_the_row_the_table_highlights() {
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    let dir = tempfile::tempdir().unwrap();
    let master = mk_labels_master(&dir);
    let poller = dummy_poller(dir.path());
    let mut app = labels_app(&master);

    // The exact state the warning describes: focus on the table, no
    // anchor. The renderer falls back to row 0; `e` must too.
    app.labels.focus = app::LabelsFocus::Entries;
    app.labels.selected_id = None;

    // 80 columns: below `NARROW_THRESHOLD`, so the kind menu is not
    // painted and the only `▸ ` in the buffer is the table's own
    // highlight symbol.
    let mut term = Terminal::new(TestBackend::new(80, 24)).unwrap();
    term.draw(|f| tabs::labels::render(f, f.area(), &mut app))
        .unwrap();
    let dump = term.backend().to_string();
    let highlighted = dump
        .lines()
        .find(|l| l.contains("\u{25b8} "))
        .expect("the table highlights a row")
        .to_string();

    handle_key(&mut app, key(KeyCode::Char('e')), &poller, &master).await;
    let form = app
        .labels
        .modal
        .as_ref()
        .expect("`e` opens the Edit modal")
        .form()
        .unwrap();
    assert_eq!(form.mode, label_modal::FormMode::Edit);
    assert!(
        highlighted.contains(&form.id),
        "`e` opened on \"{}\" but the table highlights: {highlighted}",
        form.id
    );
}

/// Save writes the **file**, not the in-memory struct — and the table
/// learns about it without the operator pressing `r`, because this
/// leaf never polls.
#[tokio::test]
async fn l7_add_writes_the_row_to_disk_and_the_leaf_sees_it() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_empty_labels_master(&dir);
    let poller = dummy_poller(dir.path());
    let mut app = labels_app(&master);

    handle_key(&mut app, key(KeyCode::Char('a')), &poller, &master).await;
    for c in "dweller".chars() {
        handle_key(&mut app, key(KeyCode::Char(c)), &poller, &master).await;
    }
    // Tab past the read-only kind row onto display name, and type the
    // value the devices actually carry — the half that makes
    // `DEVICE_METADATA_UNKNOWN_LABEL` stop firing.
    handle_key(&mut app, key(KeyCode::Tab), &poller, &master).await;
    for c in "Dweller".chars() {
        handle_key(&mut app, key(KeyCode::Char(c)), &poller, &master).await;
    }
    handle_key(&mut app, key(KeyCode::Enter), &poller, &master).await;

    let on_disk = labels_of(&master);
    assert_eq!(on_disk.len(), 1, "one row on disk; got {on_disk:?}");
    assert_eq!(on_disk[0].id.as_str(), "dweller");
    assert_eq!(on_disk[0].kind, LabelKind::Owner);
    assert_eq!(on_disk[0].display_name, "Dweller");
    assert_eq!(
        app.loaded_config.as_ref().unwrap().config.labels.len(),
        1,
        "the cached config is re-read on success — without it the \
             table renders unchanged and reads as a failed write"
    );
}

/// **The trap the task's own text prescribed, pinned as a test.** The
/// original wording said to write through `target::upsert_id_keyed`,
/// which compares `item["id"]` alone; a label's identity is the
/// `(kind, id)` pair, so following it would overwrite the `owner` row
/// while adding a `device-type` of the same id. Validator R1 legalises
/// that collision deliberately.
#[tokio::test]
async fn l7_the_same_id_under_two_kinds_makes_two_rows() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_empty_labels_master(&dir);
    let poller = dummy_poller(dir.path());
    let mut app = labels_app(&master);

    for kind_steps in [0usize, 1] {
        for _ in 0..kind_steps {
            handle_key(&mut app, key(KeyCode::Down), &poller, &master).await;
        }
        handle_key(&mut app, key(KeyCode::Char('a')), &poller, &master).await;
        for c in "shared".chars() {
            handle_key(&mut app, key(KeyCode::Char(c)), &poller, &master).await;
        }
        handle_key(&mut app, key(KeyCode::Enter), &poller, &master).await;
        // Dismiss the outcome screen.
        handle_key(&mut app, key(KeyCode::Esc), &poller, &master).await;
    }

    let on_disk = labels_of(&master);
    assert_eq!(
        on_disk.len(),
        2,
        "an owner and a device-type sharing an id are two rows; got {on_disk:?}"
    );
    assert!(on_disk
        .iter()
        .any(|l| l.kind == LabelKind::Owner && l.id.as_str() == "shared"));
    assert!(on_disk
        .iter()
        .any(|l| l.kind == LabelKind::DeviceType && l.id.as_str() == "shared"));
}

/// `labels::remove_inner` is **not** `groups::remove_inner`: it has no
/// `Ok(None)`, so an already-absent row arrives as `Err`. Reporting
/// that as a success would tell the operator a write happened when the
/// file was never touched.
#[tokio::test]
async fn l7_removing_a_row_that_is_already_gone_reports_it() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_labels_master(&dir);
    let poller = dummy_poller(dir.path());
    let mut app = labels_app(&master);
    app.labels.focus = app::LabelsFocus::Entries;
    app.labels.selected_id = Some("dweller".to_string());

    handle_key(&mut app, key(KeyCode::Char('d')), &poller, &master).await;
    assert!(app.labels.modal.is_some(), "`d` opens the confirm");

    // The row vanishes under the open modal — another session, or the
    // CLI. The captured snapshot still names it.
    let text = std::fs::read_to_string(&master).unwrap();
    let without = text.replace(
        "[[labels]]\nid = \"dweller\"\nkind = \"owner\"\ndisplay_name = \"Dweller\"\n",
        "",
    );
    assert_ne!(
        text, without,
        "the fixture edit must actually remove the row"
    );
    std::fs::write(&master, without).unwrap();

    handle_key(&mut app, key(KeyCode::Char('y')), &poller, &master).await;
    let stage = &app.labels.modal.as_ref().unwrap().stage;
    match stage {
        label_modal::Stage::Submitted(label_modal::SubmitOutcome::Failed(msg)) => {
            assert!(
                msg.contains("already gone"),
                "the operator must learn the row was stale; got: {msg}"
            );
        }
        other => panic!("expected a Failed outcome, got {other:?}"),
    }
}

/// **`tui-mod-05` (2026-08-28 review) retired `set_inner`-per-field for
/// `submit_label_edit`** — the last surviving instance of the
/// partial-apply trap `subnet_modal-01` already closed for Subnets — in
/// favour of `labels::set_fields_inner`, which lands every changed field
/// in one validated write.
///
/// This replaces `l7_a_half_applied_edit_names_what_landed`, which
/// asserted the OLD defect as if it were correct: a validator refusal on
/// `description` left an already-landed `display_name` write on disk,
/// so Discard implied nothing was saved when something was. With one
/// write, a refusal on either field must leave BOTH exactly as they
/// were — there is no longer a "what already landed" to name.
///
/// The forced failure is unchanged: a description past
/// `FREE_TEXT_MAX_BYTES`, which the validator refuses. Under the old
/// per-field loop that refusal fired only on the second call, after
/// `display_name` had already been promoted; under one write it must
/// refuse before either field reaches disk.
#[tokio::test]
async fn l7_a_refused_edit_leaves_the_label_byte_identical_on_disk() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_labels_master(&dir);
    let poller = dummy_poller(dir.path());
    let mut app = labels_app(&master);

    let before_labels = labels_of(&master);
    let before = before_labels
        .iter()
        .find(|l| l.id.as_str() == "dweller")
        .unwrap();
    let before_display_name = before.display_name.clone();
    let before_description = before.description.clone();

    app.labels.modal = Some(label_modal::LabelModal::open_edit(before));
    {
        let form = app.labels.modal.as_mut().unwrap().form_mut().unwrap();
        // `display_name` alone would succeed — the OLD loop's proof that
        // it lands is exactly the bug. One atomic write means it must
        // NOT land either, refused alongside the oversized description.
        form.display_name = "Dweller P".to_string();
        form.description = "x".repeat(2000);
    }
    handle_key(&mut app, key(KeyCode::Enter), &poller, &master).await;

    let form = app
        .labels
        .modal
        .as_ref()
        .expect("a form failure keeps the modal open")
        .form()
        .expect("and keeps it on the form stage");
    assert!(
        form.error_message.is_some(),
        "the refusal must land on the inline validation line"
    );

    let after_labels = labels_of(&master);
    let after = after_labels
        .iter()
        .find(|l| l.id.as_str() == "dweller")
        .unwrap();
    assert_eq!(
        after.display_name, before_display_name,
        "a refusal on ANY field must leave every field as it was — \
         display_name is individually valid and would have landed under \
         the old per-field loop"
    );
    assert_eq!(
        after.description, before_description,
        "the field that actually failed must also be unchanged"
    );
}

/// **A success message that loses its own tail is worse than a
/// shorter one**, and this was measured on a real terminal rather
/// than reasoned about: the message used to append the file it wrote
/// to, `prose_row` truncates at the modal's 62-column body, and the
/// ellipsis ate the path *and* the trailing field names — the part
/// the operator is actually checking. The path now lives in the
/// audit line, which has no column budget.
#[tokio::test]
async fn l7_the_success_message_fits_the_modal_body() {
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    let dir = tempfile::tempdir().unwrap();
    let master = mk_labels_master(&dir);
    let poller = dummy_poller(dir.path());
    let mut app = labels_app(&master);

    app.labels.modal = Some(label_modal::LabelModal::open_edit(
        labels_of(&master)
            .iter()
            .find(|l| l.id.as_str() == "dweller")
            .unwrap(),
    ));
    {
        let form = app.labels.modal.as_mut().unwrap().form_mut().unwrap();
        form.display_name = "Dweller P".to_string();
        form.description = "studio".to_string();
    }
    handle_key(&mut app, key(KeyCode::Enter), &poller, &master).await;

    let modal = app.labels.modal.as_ref().expect("the outcome screen");
    let mut term = Terminal::new(TestBackend::new(100, 30)).unwrap();
    term.draw(|f| label_modal::render_overlay(f, f.area(), modal))
        .unwrap();
    let dump = term.backend().to_string();
    assert!(
        dump.contains("updated owner dweller (display_name, description)"),
        "the whole message must reach the screen; got:\n{dump}"
    );
    assert!(
        !dump.contains("\u{2026}"),
        "no ellipsis — the message is inside the body budget; got:\n{dump}"
    );
}

/// **Anti-missing-arm.** `handle_labels_key` ends in `_ => {}`, which
/// swallows every unbound key silently — that is exactly how half of
/// L2 read as shipped for two sprints.
///
/// Verified by mutation the way UX8 verified its own: deleting an arm
/// reddens this, and so does **swapping the `e` and `d` bodies**. The
/// swap is the load-bearing half — it proves the test asserts which
/// modal each key opens, not merely that some modal opened.
#[tokio::test]
async fn l7_each_opener_opens_its_own_stage() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_labels_master(&dir);
    let poller = dummy_poller(dir.path());

    for (k, want_add, want_remove) in [
        (KeyCode::Char('a'), true, false),
        (KeyCode::Char('e'), false, false),
        (KeyCode::Char('d'), false, true),
        (KeyCode::Delete, false, true),
    ] {
        let mut app = labels_app(&master);
        app.labels.selected_id = Some("dweller".to_string());
        handle_key(&mut app, key(k), &poller, &master).await;
        let modal = app
            .labels
            .modal
            .as_ref()
            .unwrap_or_else(|| panic!("{k:?} must open a modal"));
        if want_remove {
            assert!(
                modal.remove().is_some(),
                "{k:?} must open the remove confirm, not a form"
            );
        } else {
            let form = modal
                .form()
                .unwrap_or_else(|| panic!("{k:?} must open a form, not a confirm"));
            let is_add = form.mode == label_modal::FormMode::Add;
            assert_eq!(
                is_add, want_add,
                "{k:?} opened the wrong form mode ({:?})",
                form.mode
            );
        }
    }
}

// ── §4.66 L7b: what an external audit found the tests above missed ──
//
// Every one of these covers a mutation that kept the first round of L7
// tests green. They are grouped rather than scattered so the next
// reader can see the shape of the gap: the first round asserted that
// the right modal OPENED, and barely that the right bytes LANDED.

/// **At the declared 80×24 floor the kind was unreachable, so `a` could
/// only ever add an `owner`.** `clamp_labels_focus_to_layout` runs in
/// the render loop and pins focus to the table on every frame when the
/// menu is not painted, so a `←` that asked for `KindMenu` was undone
/// before the next keystroke was read. Two of the three vocabularies
/// could not be authored at the product's own minimum terminal size.
///
/// The loop below is the render loop's real order — clamp, then key —
/// because the defect only exists in that order.
#[tokio::test]
async fn l7b_the_kind_is_reachable_at_the_eighty_column_floor() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_labels_master(&dir);
    let poller = dummy_poller(dir.path());
    let mut app = labels_app(&master);

    macro_rules! press {
        ($k:expr) => {{
            clamp_labels_focus_to_layout(&mut app, 80);
            handle_key(&mut app, key($k), &poller, &master).await;
        }};
    }

    press!(KeyCode::Right);
    assert_eq!(
        app.labels.selected_kind,
        LabelKind::DeviceType,
        "at the floor the horizontal keys must carry the kind — there is \
             no second pane for them to move focus to"
    );
    press!(KeyCode::Left);
    assert_eq!(
        app.labels.selected_kind,
        LabelKind::Owner,
        "and they must go both ways"
    );

    // And the whole point: Add follows it.
    press!(KeyCode::Right);
    press!(KeyCode::Char('a'));
    assert_eq!(
        app.labels.modal.as_ref().unwrap().form().unwrap().kind,
        LabelKind::DeviceType,
        "a device-type must be addable at 80 columns"
    );
}

/// Wide terminals keep the two-pane model UX8 shipped — the fix above
/// must not leak into the layout where the menu exists.
#[tokio::test]
async fn l7b_a_wide_terminal_still_moves_focus_rather_than_the_kind() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_labels_master(&dir);
    let poller = dummy_poller(dir.path());
    let mut app = labels_app(&master);

    clamp_labels_focus_to_layout(&mut app, 200);
    handle_key(&mut app, key(KeyCode::Right), &poller, &master).await;
    assert_eq!(app.labels.focus, app::LabelsFocus::Entries);
    assert_eq!(
        app.labels.selected_kind,
        LabelKind::Owner,
        "wide, `→` moves focus and must NOT change the kind"
    );
}

/// **`e` and `d` must act on the row the cursor is on, not on row 0.**
/// The first round pinned this only with `selected_id = None`, which
/// after seeding resolves to row 0 — so a `focused_label` that ignored
/// the anchor entirely and always returned `rows[0]` passed. The
/// fixture's second owner is what makes this discriminate.
#[tokio::test]
async fn l7b_edit_and_delete_follow_the_cursor_to_the_second_row() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_labels_master(&dir);
    let poller = dummy_poller(dir.path());

    for k in [KeyCode::Char('e'), KeyCode::Char('d')] {
        let mut app = labels_app(&master);
        app.labels.focus = app::LabelsFocus::Entries;
        // Walk down one row: dweller -> dweller2.
        handle_key(&mut app, key(KeyCode::Down), &poller, &master).await;
        assert_eq!(app.labels.selected_id.as_deref(), Some("dweller2"));

        handle_key(&mut app, key(k), &poller, &master).await;
        let modal = app.labels.modal.as_ref().expect("modal opens");
        let acted_on = match k {
            KeyCode::Char('e') => modal.form().unwrap().id.clone(),
            _ => modal.remove().unwrap().id.clone(),
        };
        assert_eq!(
            acted_on, "dweller2",
            "{k:?} acted on the wrong row — it must follow the cursor"
        );
    }
}

/// Delete's happy path, asserted **on disk**. The first round only
/// pinned the stale-row refusal, so a `y` that removed the wrong row —
/// or nothing at all — went unnoticed.
#[tokio::test]
async fn l7b_a_confirmed_delete_removes_that_row_and_only_that_row() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_labels_master(&dir);
    let poller = dummy_poller(dir.path());
    let mut app = labels_app(&master);
    app.labels.focus = app::LabelsFocus::Entries;
    handle_key(&mut app, key(KeyCode::Down), &poller, &master).await;

    handle_key(&mut app, key(KeyCode::Char('d')), &poller, &master).await;
    handle_key(&mut app, key(KeyCode::Char('y')), &poller, &master).await;

    let on_disk = labels_of(&master);
    assert!(
        !on_disk
            .iter()
            .any(|l| l.id.as_str() == "dweller2" && l.kind == LabelKind::Owner),
        "the confirmed row must be gone; got {on_disk:?}"
    );
    assert!(
        on_disk
            .iter()
            .any(|l| l.id.as_str() == "dweller" && l.kind == LabelKind::Owner),
        "and its neighbour must survive; got {on_disk:?}"
    );
    assert!(
        on_disk
            .iter()
            .any(|l| l.id.as_str() == "laptop" && l.kind == LabelKind::DeviceType),
        "as must the other kind; got {on_disk:?}"
    );
}

/// Edit's happy path, asserted **on disk**. The first round asserted
/// the message and the half-failure, never that a clean two-field save
/// wrote both values.
#[tokio::test]
async fn l7b_a_clean_edit_writes_both_fields_to_disk() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_labels_master(&dir);
    let poller = dummy_poller(dir.path());
    let mut app = labels_app(&master);

    app.labels.modal = Some(label_modal::LabelModal::open_edit(
        labels_of(&master)
            .iter()
            .find(|l| l.id.as_str() == "dweller")
            .unwrap(),
    ));
    {
        let form = app.labels.modal.as_mut().unwrap().form_mut().unwrap();
        form.display_name = "Dweller P".to_string();
        form.description = "studio".to_string();
    }
    handle_key(&mut app, key(KeyCode::Enter), &poller, &master).await;

    let row = labels_of(&master)
        .into_iter()
        .find(|l| l.id.as_str() == "dweller")
        .expect("the row survives an edit");
    assert_eq!(row.display_name, "Dweller P");
    assert_eq!(row.description.as_deref(), Some("studio"));
    assert_eq!(row.kind, LabelKind::Owner, "the kind is not touched");
}

/// **`tui-mod-05` retired the partial-apply trap this test used to name.**
/// Before the atomic-write fix, a validator refusal on `description`
/// still left the already-landed `display_name` write on disk, and this
/// test pinned the consequence: the cached config had to be told about
/// that partial write, or the table would render a name the file no
/// longer had. One atomic write means there is no longer a partial
/// write to be told about, so this replaces
/// `l7b_a_half_applied_edit_still_refreshes_the_cached_config` with the
/// inverse claim — a refusal changes neither the file nor the cache nor
/// the form's re-anchor snapshot.
#[tokio::test]
async fn l7b_a_refused_edit_leaves_the_cached_config_and_the_form_snapshot_untouched() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_labels_master(&dir);
    let poller = dummy_poller(dir.path());
    let mut app = labels_app(&master);

    app.labels.modal = Some(label_modal::LabelModal::open_edit(
        labels_of(&master)
            .iter()
            .find(|l| l.id.as_str() == "dweller")
            .unwrap(),
    ));
    {
        let form = app.labels.modal.as_mut().unwrap().form_mut().unwrap();
        form.display_name = "Dweller P".to_string();
        form.description = "x".repeat(2000);
    }
    handle_key(&mut app, key(KeyCode::Enter), &poller, &master).await;

    let cached = app
        .loaded_config
        .as_ref()
        .unwrap()
        .config
        .labels
        .iter()
        .find(|l| l.id.as_str() == "dweller")
        .expect("the row is still there")
        .display_name
        .clone();
    assert_eq!(
        cached, "Dweller",
        "the cached config must not drift ahead of a file nothing was written to"
    );

    // Nothing landed, so the snapshot has nothing to re-anchor to.
    let original = app
        .labels
        .modal
        .as_ref()
        .unwrap()
        .form()
        .unwrap()
        .original
        .as_ref()
        .unwrap();
    assert_eq!(original.display_name, "Dweller");
}

/// The footer advertises `Ctrl+s` while this form is open. It does not
/// save — that is Groups' precedent and it is pinned there. What Groups
/// does **not** pin is that it must also not type an `s` into the
/// focused field, which is what an unmasked `Char(c)` arm does.
#[tokio::test]
async fn l7b_ctrl_s_neither_saves_nor_types_into_the_field() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_empty_labels_master(&dir);
    let poller = dummy_poller(dir.path());
    let mut app = labels_app(&master);

    handle_key(&mut app, key(KeyCode::Char('a')), &poller, &master).await;
    handle_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('s'), KeyModifiers::CONTROL),
        &poller,
        &master,
    )
    .await;

    let form = app
        .labels
        .modal
        .as_ref()
        .expect("Ctrl+s must not close the modal")
        .form()
        .expect("nor submit it");
    assert_eq!(form.id, "", "Ctrl+s must not type into the focused field");
    assert!(labels_of(&master).is_empty(), "and must not write");
}

/// Paste is how an operator gets `Apple TV` byte-exact out of the
/// Devices tab instead of retyping it and inventing the near-duplicate
/// this vocabulary exists to prevent. It was inert **and silent**.
#[tokio::test]
async fn l7b_paste_reaches_the_label_form() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_empty_labels_master(&dir);
    let poller = dummy_poller(dir.path());
    let mut app = labels_app(&master);

    handle_key(&mut app, key(KeyCode::Char('a')), &poller, &master).await;
    // Move to display name, where a value with a space belongs.
    handle_key(&mut app, key(KeyCode::Tab), &poller, &master).await;
    handle_paste(&mut app, "Apple TV".to_string());

    assert_eq!(
        app.labels
            .modal
            .as_ref()
            .unwrap()
            .form()
            .unwrap()
            .display_name,
        "Apple TV",
        "paste must land in the focused field"
    );
}

// ── rev-2607 (#9): Profile modal must honor ↑/↓ like its siblings ──
//
// The shared modal legend (`modal_form::keys_line`) advertises
// "↹/↑↓ move" under every grid modal. Subnet and Local-DNS already
// bind both Tab/BackTab and Down/Up to focus_next/focus_prev; the
// Profile modal bound only Tab/BackTab, so Down/Up fell through to
// the catch-all no-op arm.
#[tokio::test]
async fn profile_modal_down_up_move_focus_same_as_tab_backtab() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    let poller = dummy_poller(dir.path());
    let mut app = mk_app(&master);
    app.active_leaf = Leaf::Profiles;
    app.profiles.modal = Some(profile_modal::ProfileModal::open_add());

    let focused = |app: &App| app.profiles.modal.as_ref().unwrap().form().unwrap().focused;
    assert_eq!(
        focused(&app),
        profile_modal::FormField::Id,
        "Add-mode form opens focused on Id"
    );

    handle_profile_modal_key(&mut app, key(KeyCode::Down), &poller, &master).await;
    assert_eq!(
        focused(&app),
        profile_modal::FormField::DisplayName,
        "Down must move focus forward, matching Tab — the shared legend advertises both"
    );

    handle_profile_modal_key(&mut app, key(KeyCode::Down), &poller, &master).await;
    assert_eq!(focused(&app), profile_modal::FormField::Submit);

    handle_profile_modal_key(&mut app, key(KeyCode::Up), &poller, &master).await;
    assert_eq!(
        focused(&app),
        profile_modal::FormField::DisplayName,
        "Up must move focus backward, matching BackTab"
    );
}
