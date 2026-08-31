use super::*;
use crate::tui::app::{App, Leaf};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use std::path::{Path, PathBuf};

fn key(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

fn poller(dir: &Path) -> IpcPoller {
    IpcPoller::new(&dir.join("ghost.sock"))
}

/// Two global records and two profiles with records, plus one empty
/// profile — enough for the boundary crossing, the header skip and
/// the omission to all be observable.
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

[profiles.empty]
display_name = "Empty"

[profiles.kids]
display_name = "Kids"
local_records = [{ domain = "youtube.local", type = "A", value = "192.0.2.9" }]

[profiles.work]
display_name = "Work"
local_records = [{ domain = "vpn.work", type = "A", value = "10.10.2.9" }]

[[local_dns.records]]
domain = "nas.home"
type = "A"
value = "192.168.1.50"

[[local_dns.records]]
domain = "printer.home"
type = "A"
value = "192.168.1.60"
"#,
    )
    .unwrap();
    master
}

fn empty_master(dir: &tempfile::TempDir) -> PathBuf {
    let master = dir.path().join("config.toml");
    std::fs::write(
        &master,
        "schema_version = 3\n\n\
             [upstream]\nservers = [\"192.0.2.1:53\"]\n\n\
             [server]\ndefault_profile = \"default\"\n\n\
             [profiles.default]\ndisplay_name = \"Default\"\n\n\
             [profiles.kids]\ndisplay_name = \"Kids\"\n",
    )
    .unwrap();
    master
}

fn app_on(master: &Path) -> App {
    let mut app = App::new();
    app.loaded_config = load_v1_config(master);
    app.active_leaf = Leaf::LocalDns;
    assert!(app.loaded_config.is_some(), "fixture must parse");
    app
}

async fn press(app: &mut App, code: KeyCode, master: &Path) {
    handle_key(app, key(code), &poller(master.parent().unwrap()), master).await;
}

fn anchor(app: &App) -> (String, String) {
    app.local_dns
        .selected_id
        .clone()
        .expect("cursor must be anchored")
}

// ── one list, one cursor ────────────────────────────────────────

/// `↓` walks Global → profile `kids` → profile `work` without a
/// panel switch and without ever landing on a header.
#[tokio::test]
async fn n6_down_walks_every_scope_in_one_pass() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    let mut app = app_on(&master);

    // First keystroke seeds on the first record.
    press(&mut app, KeyCode::Down, &master).await;
    assert_eq!(anchor(&app), ("global".into(), "printer.home".into()));
    press(&mut app, KeyCode::Down, &master).await;
    assert_eq!(
        anchor(&app),
        ("profile:kids".into(), "youtube.local".into()),
        "crosses into the profile group over its header"
    );
    press(&mut app, KeyCode::Down, &master).await;
    assert_eq!(
        anchor(&app),
        ("profile:work".into(), "vpn.work".into()),
        "and on into the next profile group"
    );
    press(&mut app, KeyCode::Down, &master).await;
    assert_eq!(
        anchor(&app),
        ("profile:work".into(), "vpn.work".into()),
        "N4: the last record clamps"
    );
}

#[tokio::test]
async fn n6_up_clamps_on_the_first_record_not_onto_its_header() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    let mut app = app_on(&master);

    press(&mut app, KeyCode::End, &master).await;
    assert_eq!(anchor(&app), ("profile:work".into(), "vpn.work".into()));
    press(&mut app, KeyCode::Home, &master).await;
    assert_eq!(anchor(&app), ("global".into(), "nas.home".into()));
    press(&mut app, KeyCode::Up, &master).await;
    assert_eq!(
        anchor(&app),
        ("global".into(), "nas.home".into()),
        "Up on the first record stays put — and never selects the \
             `Global` header above it"
    );
}

/// `o` is unbound and, critically, must not fall through into the
/// global match and cycle the leaf.
#[tokio::test]
async fn n6_o_is_unbound_and_does_not_reach_the_global_match() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    let mut app = app_on(&master);
    press(&mut app, KeyCode::Down, &master).await;
    let before = anchor(&app);

    press(&mut app, KeyCode::Char('o'), &master).await;

    assert_eq!(app.active_leaf, Leaf::LocalDns, "`o` must not cycle leaf");
    assert_eq!(anchor(&app), before, "and must not move the cursor");
    assert!(app.local_dns.modal.is_none());
}

/// N1 reaffirmed: `Tab` is the leaf cycle here as everywhere. This is
/// the twin of `ldns_04_tab_still_cycles_leaf` on the new model.
#[tokio::test]
async fn n6_tab_still_cycles_the_leaf() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    let mut app = app_on(&master);
    press(&mut app, KeyCode::Tab, &master).await;
    assert_ne!(app.active_leaf, Leaf::LocalDns);
}

// ── the side-card ───────────────────────────────────────────────

/// Enter opens the audit side-card on the focused record; Esc closes
/// it. Unchanged by N6, which is exactly why it is pinned here.
#[tokio::test]
async fn n6_enter_opens_the_audit_card_on_the_focused_record_and_esc_closes_it() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    let mut app = app_on(&master);

    press(&mut app, KeyCode::Down, &master).await; // printer.home
    press(&mut app, KeyCode::Enter, &master).await;
    let view = app
        .local_dns
        .audit_view
        .as_ref()
        .expect("Enter opens the side-card");
    assert_eq!(view.scope_tag, "global");
    assert_eq!(view.domain, "printer.home", "on the FOCUSED record");

    press(&mut app, KeyCode::Esc, &master).await;
    assert!(app.local_dns.audit_view.is_none(), "Esc closes it");
}

/// And it follows the cursor across a scope boundary — the card
/// showing a Global record while a profile record is highlighted is
/// the desync the follow-block exists to prevent.
#[tokio::test]
async fn n6_the_side_card_follows_the_cursor_across_scopes() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    let mut app = app_on(&master);

    press(&mut app, KeyCode::Enter, &master).await;
    assert_eq!(
        app.local_dns.audit_view.as_ref().unwrap().domain,
        "nas.home"
    );

    press(&mut app, KeyCode::End, &master).await;
    let view = app.local_dns.audit_view.as_ref().unwrap();
    assert_eq!(view.scope_tag, "profile");
    assert_eq!(view.target_id, "work");
    assert_eq!(view.domain, "vpn.work");
}

// ── `a` must not guess the scope ────────────────────────────────

/// **The one that matters.** With a profile record focused, Add opens
/// pre-selected on THAT profile. Writing to Global instead is a silent
/// policy error: nothing afterwards says the record went elsewhere.
#[tokio::test]
async fn n6_add_prefills_the_focused_rows_profile_scope() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    let mut app = app_on(&master);

    press(&mut app, KeyCode::End, &master).await; // profile:work
    assert_eq!(anchor(&app).0, "profile:work");
    press(&mut app, KeyCode::Char('a'), &master).await;

    let modal = app.local_dns.modal.as_ref().expect("Add modal open");
    let local_dns_modal::Stage::EditingForm(form) = &modal.stage else {
        panic!("expected EditingForm");
    };
    // Slot 0 is Global; profiles follow in config order
    // (default, empty, kids, work) → `work` is slot 4.
    let profiles = snapshot_profile_ids(&app);
    let want = profiles.iter().position(|p| p == "work").unwrap() + 1;
    assert_eq!(
        form.profile_idx, want,
        "Add must open on the focused row's profile, not on Global"
    );
}

#[tokio::test]
async fn n6_add_prefills_global_when_a_global_row_is_focused() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    let mut app = app_on(&master);

    press(&mut app, KeyCode::Home, &master).await;
    assert_eq!(anchor(&app).0, "global");
    press(&mut app, KeyCode::Char('a'), &master).await;

    let modal = app.local_dns.modal.as_ref().unwrap();
    let local_dns_modal::Stage::EditingForm(form) = &modal.stage else {
        panic!("expected EditingForm");
    };
    assert_eq!(form.profile_idx, 0, "slot 0 is Global");
    assert!(
        app.status_text().is_none(),
        "a focused row is an answer, not a guess — no note needed"
    );
}

/// `a` as the very FIRST key on the leaf, with no cursor moved. The
/// handler seeds the anchor before the openers run, so this still
/// resolves to a real row rather than defaulting to Global.
#[tokio::test]
async fn n6_add_as_the_first_keystroke_still_resolves_a_real_row() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    let mut app = app_on(&master);
    assert!(app.local_dns.selected_id.is_none(), "nothing pressed yet");

    press(&mut app, KeyCode::Char('a'), &master).await;

    assert_eq!(
        anchor(&app),
        ("global".into(), "nas.home".into()),
        "the anchor is seeded before `a` runs, matching what the \
             renderer already highlights"
    );
    assert!(app.status_text().is_none());
}

/// **The ask-case.** An empty list has no row to infer a scope from,
/// so Add does not silently pick one: it opens with the Profile field
/// focused and says which scope it opened on.
#[tokio::test]
async fn n6_add_on_an_empty_list_asks_rather_than_guessing() {
    let dir = tempfile::tempdir().unwrap();
    let master = empty_master(&dir);
    let mut app = app_on(&master);

    press(&mut app, KeyCode::Char('a'), &master).await;

    let modal = app.local_dns.modal.as_ref().expect("Add modal open");
    let local_dns_modal::Stage::EditingForm(form) = &modal.stage else {
        panic!("expected EditingForm");
    };
    assert_eq!(
        form.focused,
        local_dns_modal::FormField::Profile,
        "with nothing to infer from, the form opens ON the scope field \
             so the operator reads it before typing a domain"
    );
    let note = app.status_text().expect("and says so");
    assert!(
        note.contains("Global"),
        "the note must name the scope it opened on: {note}"
    );
}

// ── e / d still act on the focused record ───────────────────────

#[tokio::test]
async fn n6_edit_and_delete_target_the_focused_record_in_either_scope() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);

    let mut app = app_on(&master);
    press(&mut app, KeyCode::End, &master).await; // profile:work / vpn.work
    press(&mut app, KeyCode::Char('e'), &master).await;
    let modal = app.local_dns.modal.as_ref().expect("Edit modal open");
    let local_dns_modal::Stage::EditingForm(form) = &modal.stage else {
        panic!("expected EditingForm");
    };
    assert_eq!(form.domain, "vpn.work", "Edit opens on the focused record");

    let mut app = app_on(&master);
    press(&mut app, KeyCode::Home, &master).await;
    press(&mut app, KeyCode::Char('d'), &master).await;
    assert!(
        app.local_dns.modal.is_some(),
        "Delete opens a confirm on the focused record"
    );
    assert!(app.status_text().is_none(), "and does not complain");
}
