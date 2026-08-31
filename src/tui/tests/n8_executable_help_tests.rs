use super::*;
use crate::tui::app::{App, Leaf};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use std::path::{Path, PathBuf};

fn key(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

fn ctrl(c: char) -> KeyEvent {
    KeyEvent::new(KeyCode::Char(c), KeyModifiers::CONTROL)
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
             [server]\ndefault_profile = \"home\"\n\n\
             [profiles.home]\ndisplay_name = \"Home\"\n",
    )
    .unwrap();
    master
}

/// Help already open on the given leaf.
fn helping(master: &Path, leaf: Leaf) -> App {
    let mut app = App::new();
    app.loaded_config = load_v1_config(master);
    app.active_leaf = leaf;
    app.show_help = true;
    app
}

async fn press(app: &mut App, k: KeyEvent, master: &Path) -> bool {
    handle_key(app, k, &poller(master.parent().unwrap()), master).await
}

// ── the three closers, and the quit ─────────────────────────────

#[tokio::test]
async fn n8_question_esc_and_q_close_without_acting() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    for code in [KeyCode::Char('?'), KeyCode::Esc, KeyCode::Char('q')] {
        let mut app = helping(&master, Leaf::Lists);
        let quit = press(&mut app, key(code), &master).await;
        assert!(!quit, "{code:?} must not quit the TUI");
        assert!(!app.show_help, "{code:?} closes the overlay");
        assert_eq!(
            app.active_leaf,
            Leaf::Lists,
            "{code:?} must not also change leaf"
        );
        assert!(
            app.lists.edit_modal.is_none() && app.lists.catalog_picker.is_none(),
            "{code:?} must not also open a modal"
        );
    }
}

/// `?` closing must not be the fall-through re-toggling it. Both
/// readings leave `show_help == false` after ONE press, so the second
/// press is what tells them apart: a re-toggle would have left it open.
#[tokio::test]
async fn n8_question_does_not_toggle_back_on_through_the_fall_through() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    let mut app = helping(&master, Leaf::Lists);
    press(&mut app, key(KeyCode::Char('?')), &master).await;
    assert!(!app.show_help);
    press(&mut app, key(KeyCode::Char('?')), &master).await;
    assert!(app.show_help, "from Normal mode `?` still opens help");
}

#[tokio::test]
async fn n8_ctrl_c_still_quits_from_help() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    let mut app = helping(&master, Leaf::Lists);
    assert!(
        press(&mut app, ctrl('c'), &master).await,
        "Ctrl+C quits even with the overlay open"
    );
}

// ── a listed key runs, and the overlay gets out of the way ──────

#[tokio::test]
async fn n8_a_on_lists_opens_the_add_modal_and_closes_help() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    let mut app = helping(&master, Leaf::Lists);

    press(&mut app, key(KeyCode::Char('a')), &master).await;

    assert!(!app.show_help, "a listed key closes the overlay behind it");
    assert!(
        app.lists.edit_modal.is_some(),
        "and runs the action, as if help had never been open"
    );
}

#[tokio::test]
async fn n8_a_global_key_runs_from_help() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    let mut app = helping(&master, Leaf::Lists);

    press(&mut app, key(KeyCode::Char('2')), &master).await;

    assert!(!app.show_help);
    assert_eq!(
        app.active_leaf,
        Leaf::QueryLog,
        "`2` is a global, and globals dispatch from help too"
    );
}

/// `p` (pause) is a global with no visible modal, so it also checks
/// that "handled" is not being inferred from "a modal appeared".
#[tokio::test]
async fn n8_a_global_with_no_modal_still_counts_as_handled() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    let mut app = helping(&master, Leaf::Lists);
    let paused_before = app.paused;

    press(&mut app, key(KeyCode::Char('p')), &master).await;

    assert_ne!(app.paused, paused_before, "`p` toggled pause");
    assert!(!app.show_help, "and the overlay closed behind it");
}

// ── an unbound key changes nothing, including the overlay ───────

#[tokio::test]
async fn n8_an_unbound_key_leaves_help_open_and_opens_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    let mut app = helping(&master, Leaf::Lists);

    press(&mut app, key(KeyCode::Char('x')), &master).await;

    assert!(
        app.show_help,
        "an unbound key must leave the overlay open — a typo while \
             reading help must not cost the operator their place"
    );
    assert!(app.lists.edit_modal.is_none());
    assert_eq!(app.active_leaf, Leaf::Lists);
}

/// The same key, on a leaf that has no list at all. Dashboard's handler
/// was an `if let` and could not report a miss until N8 widened it —
/// the one leaf where this would silently have closed the overlay.
#[tokio::test]
async fn n8_an_unbound_key_leaves_help_open_on_dashboard_too() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    let mut app = helping(&master, Leaf::Dashboard);

    press(&mut app, key(KeyCode::Char('x')), &master).await;
    assert!(
        app.show_help,
        "Dashboard must report the miss like the rest"
    );

    press(&mut app, key(KeyCode::Char('d')), &master).await;
    assert!(
        !app.show_help,
        "and its one real binding must still dispatch"
    );
}

/// `g` arms the mnemonic prefix and the overlay goes; the second key
/// lands in Normal mode with nothing painted over the tab.
#[tokio::test]
async fn n8_g_arms_the_mnemonic_and_the_overlay_goes_first() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    let mut app = helping(&master, Leaf::Lists);

    press(&mut app, key(KeyCode::Char('g')), &master).await;
    assert!(!app.show_help, "the overlay is gone before the second key");
    assert!(app.pending_goto, "and the prefix is armed");

    // `plp-s5d`: was `g t` → `Leaf::Tags`. The tab is gone and `t` is
    // deliberately left UNBOUND, so this uses `b` (laBels), a
    // surviving Configuration leaf. The property under test is the
    // two-key `g <leaf>` sequence completing in Normal mode after the
    // overlay closes — not which letter it lands on.
    press(&mut app, key(KeyCode::Char('b')), &master).await;
    assert_eq!(
        app.active_leaf,
        Leaf::Labels,
        "`g b` completed in Normal mode"
    );
}

/// **The overlay must not become a way to reach a key the leaf does
/// not have.** `B` opens the catalog picker on Lists and is unbound on
/// Profiles; from help on Profiles it must do neither.
#[tokio::test]
async fn n8_help_does_not_widen_a_leafs_bindings() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    let mut app = helping(&master, Leaf::Profiles);

    press(&mut app, key(KeyCode::Char('B')), &master).await;

    assert!(app.show_help, "`B` is not a Profiles binding");
    assert!(app.lists.catalog_picker.is_none(), "and nothing opened");
    assert!(app.profiles.modal.is_none());
}
