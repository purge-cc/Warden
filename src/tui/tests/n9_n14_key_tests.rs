use super::*;
use crate::tui::app::{App, Leaf};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use std::path::{Path, PathBuf};

fn key(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

fn ctrl_s() -> KeyEvent {
    KeyEvent::new(KeyCode::Char('s'), KeyModifiers::CONTROL)
}

fn poller(dir: &Path) -> IpcPoller {
    IpcPoller::new(&dir.join("ghost.sock"))
}

fn mk_master(dir: &tempfile::TempDir) -> PathBuf {
    let master = dir.path().join("config.toml");
    std::fs::write(
        &master,
        "schema_version = 3\n\n\
             [upstream]\nservers = [\"192.0.2.1:53\"]\n\n\
             [server]\ndefault_profile = \"default\"\n\n\
             [profiles.default]\ndisplay_name = \"Default\"\n\n\
             [[labels]]\nid = \"dweller\"\nkind = \"owner\"\ndisplay_name = \"Dweller\"\n",
    )
    .unwrap();
    master
}

fn app_on(master: &Path, leaf: Leaf) -> App {
    let mut app = App::new();
    app.loaded_config = load_v1_config(master);
    app.active_leaf = leaf;
    assert!(app.loaded_config.is_some(), "fixture must parse");
    app
}

async fn press(app: &mut App, k: KeyEvent, master: &Path) {
    handle_key(app, k, &poller(master.parent().unwrap()), master).await;
}

// ── N9 ──────────────────────────────────────────────────────────

/// `/` on Tags takes the `InputMode` path, not the popup. Driven
/// through `handle_key` because the modal gate sits ahead of the leaf
/// match — a leaf-handler test could not tell the two apart.
// `plp-s5d` removed the five `n9_*` tests with the Tags tab.
//
// N9 put the Tags search on the same `drive_text_input` path as Lists
// and Rules instead of a bespoke popup, and these pinned it end to
// end: `/` enters filter-input mode, the buffer seeds from the
// committed filter, Enter commits while Esc discards the EDIT and not
// the filter, Normal-mode Esc clears both search and chip, and a
// commit re-anchors the selection immediately.
//
// **The path they were protecting is not gone** — `drive_text_input`
// still serves the Lists and Rules filters, and their own `n9`-shaped
// coverage is unaffected by this lane. What left is the Tags-specific
// wiring into it.

#[tokio::test]
async fn n14_ctrl_s_saves_the_label_modal() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    let mut app = app_on(&master, Leaf::Labels);
    press(&mut app, key(KeyCode::Char('a')), &master).await;
    assert!(app.labels.modal.is_some(), "Add modal must be open");

    press(&mut app, ctrl_s(), &master).await;

    assert!(
        app.status_text().is_some(),
        "Ctrl+s must reach the submit path — before N14 it fell through \
             to the Char(c) arm and typed a literal `s`"
    );
}

#[tokio::test]
async fn n14_ctrl_s_saves_the_local_dns_modal() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    let mut app = app_on(&master, Leaf::LocalDns);
    press(&mut app, key(KeyCode::Char('a')), &master).await;
    assert!(app.local_dns.modal.is_some(), "Add modal must be open");

    press(&mut app, ctrl_s(), &master).await;

    assert!(
        app.status_text().is_some(),
        "Ctrl+s must reach the submit path"
    );
}

/// **The chord must not reach an Archetype-C confirm screen.** Those
/// keep `[y]` / `[n]`; putting a Save on them would let one chord
/// perform a delete the operator was being asked to confirm.
#[tokio::test]
async fn n14_ctrl_s_does_not_fire_a_delete_confirm() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    let mut app = app_on(&master, Leaf::Labels);

    press(&mut app, key(KeyCode::Char('d')), &master).await;
    let opened = app.labels.modal.is_some();
    assert!(opened, "delete confirm must be open");

    press(&mut app, ctrl_s(), &master).await;

    assert!(
        app.labels.modal.is_some(),
        "the confirm stays open — Ctrl+s is a form chord, and a confirm \
             screen is not a form"
    );
    assert!(
        app.status_text().is_none(),
        "and nothing was applied: {:?}",
        app.status_text()
    );
}
