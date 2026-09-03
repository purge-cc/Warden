use super::*;
use crate::tui::app::{App, Leaf};
use crate::tui::cfg_scan::{looks_like_test_cfg_attr, strip_test_items};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use std::path::{Path, PathBuf};

fn key(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

fn dummy_poller(dir: &Path) -> IpcPoller {
    IpcPoller::new(&dir.join("ghost.sock"))
}

/// One group with a populated `devices` list and one tag, plus a
/// device carrying two *other* tags — so the chip picker has real
/// suggestions to focus. `filter_tag_suggestions` drops tags the
/// group already holds, so a fixture whose only known tag is the
/// group's own would make the picker permanently empty and the
/// stale-focus assertion below vacuous.
fn mk_groups_master(dir: &tempfile::TempDir) -> PathBuf {
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

[[devices]]
id = "phone-1"
display_name = "Phone 1"
mac = "AA:BB:CC:DD:EE:01"
tags = ["media", "trusted"]

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
    master
}

fn groups_app(master: &Path) -> App {
    let mut app = App::new();
    app.loaded_config = load_v1_config(master);
    app.active_leaf = Leaf::Groups;
    assert!(
        app.loaded_config.is_some(),
        "fixture must parse — every assertion below is vacuous otherwise"
    );
    app
}

fn form_of(app: &App) -> &group_modal::AddForm {
    match &app.groups.modal.as_ref().expect("modal must be open").stage {
        group_modal::Stage::EditingForm(f) => f,
        other => panic!("expected EditingForm, got {other:?}"),
    }
}

/// The field the task is really about. `devices` is a comma-separated
/// id list — the one value an operator copies from another screen
/// instead of retyping, and the reason an inert paste here is worse
/// than an inert paste on a display name.
#[tokio::test]
async fn ux13_paste_lands_in_the_groups_devices_field() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_groups_master(&dir);
    let poller = dummy_poller(dir.path());
    let mut app = groups_app(&master);

    handle_key(&mut app, key(KeyCode::Char('e')), &poller, &master).await;
    // Edit opens on DisplayName (Id is read-only); one Tab reaches Devices.
    handle_key(&mut app, key(KeyCode::Tab), &poller, &master).await;
    assert_eq!(
        form_of(&app).focused,
        group_modal::FormField::Devices,
        "field order changed — retarget this test, do not relax it"
    );

    handle_paste(&mut app, ", phone-3".to_string());

    assert_eq!(
        form_of(&app).devices,
        "phone-1, phone-2, phone-3",
        "paste must append to the focused text field"
    );
}

// `plp-s5d` removed
// `ux13_paste_on_tags_fills_type_ahead_and_drops_stale_picker_focus`
// with the chip picker it drove. It pinned a REAL hazard — a paste that
// refilters the suggestion list while leaving `tags_picker_focus` armed
// commits a different tag than the one on screen — but the hazard was a
// property of the picker, and this modal no longer has one. Nothing here
// substitutes for it because nothing here can reproduce it: paste on
// every surviving group field lands in a plain text buffer with no
// index to go stale. The same guard on the Lists tab's picker, which
// does survive, still lives in `tabs::lists`.

/// The remove gate owns no buffer, and it is a confirm: paste must
/// not reach it. Pinned because the interceptor added for the form
/// runs on the whole modal, not on one stage.
#[tokio::test]
async fn ux13_paste_is_inert_in_the_groups_remove_confirm() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_groups_master(&dir);
    let poller = dummy_poller(dir.path());
    let mut app = groups_app(&master);

    handle_key(&mut app, key(KeyCode::Char('d')), &poller, &master).await;
    let before = std::fs::read_to_string(&master).unwrap();

    handle_paste(&mut app, "phones".to_string());

    assert!(
        matches!(
            app.groups.modal.as_ref().map(|m| &m.stage),
            Some(group_modal::Stage::ConfirmingRemove(_))
        ),
        "paste must leave the confirm stage exactly where it was"
    );
    assert_eq!(
        std::fs::read_to_string(&master).unwrap(),
        before,
        "nothing may be written by a paste"
    );
}

// ── §4.65 UX14: one confirm convention, pinned ────────────────────
//
// **The convention: `y|Y` to confirm and `n|N` to cancel, at every
// single-key gate, lowercase first.**
//
// Recorded here so the next session does not re-litigate it. An
// uppercase `Y` is not a different key to an operator holding Shift
// or running with CapsLock on — it is the same intent — and a modal
// that drops the keystroke gives no feedback whatever, so a rejected
// key is indistinguishable from a hung one. Before this, six gates
// took only `y` and three took `y|Y`: the same finger confirmed a
// subnet delete and did nothing at all to a group delete.
//
// `n` was widened for the same reason and is not cosmetic symmetry:
// fixing only `y` would leave that operator able to **confirm** a
// destructive gate but not to cancel it.
//
// Order is fixed at lowercase-first so the rule stays mechanical. An
// author writing `Char('Y') | Char('y')` gets a red on otherwise
// correct code and should reorder rather than relax the scan.

/// `mod.rs` with every `#[cfg(test)]` item removed.
///
/// Stripping is not a nicety: this module's own literals spell out
/// the exact patterns the scan looks for, so a self-referencing scan
/// would pass on its own text. A structural pin was deleted from this
/// file once before for precisely that reason — see the note in
/// `dispatch_routing_tests`.
///
/// **Column-0 delimiters, not brace depth.** Every `#[cfg(test)]`
/// module here sits at column 0 and rustfmt closes it with a `}` at
/// column 0, whereas brace counting is fooled by braces inside live
/// string literals — this file has
/// `panic!("expected Submitted{{ok:true,..}}, got {other:?}")` in a
/// test module. The lone indented marker is
/// `TerminalGuard::with_restore`, a three-line fn that binds no keys;
/// `ux14_the_stripper_actually_strips` pins that it is the *only*
/// survivor, so a walk that quietly gave up cannot pass.
///
/// **Scope, stated because it is a real boundary and not an obvious
/// one.** This reads `mod.rs` and nothing else. That is complete
/// today — measured 2026-08-08,
/// `grep -rn "KeyCode::Char('y')" src/ --include=*.rs` returns hits in
/// this file only, as does the same needle for `Y`/`n`/`N` — because
/// every key handler in the TUI lives here. It is not complete by
/// construction: a modal whose handler is added in a *new* file gets a
/// green scan no matter what case it accepts. Such a handler needs
/// either its own scan or to move here.
fn production_source() -> String {
    strip_test_items(include_str!("../mod.rs"))
}

/// Whitespace-collapsed view, so a rustfmt line-break between the two
/// halves of an or-pattern neither hides a compliant site nor excuses
/// a bare one. Both wrapped forms exist in this file today: the scope
/// modal's guarded arm and the Local DNS tuple arms all exceed 100
/// columns once both cases are spelled out.
fn collapsed(src: &str) -> String {
    src.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Every occurrence of `needle`, each with the text that follows it —
/// enough to name the offending site in a failure message.
fn sites_of<'a>(hay: &'a str, needle: &str) -> Vec<&'a str> {
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(i) = hay[from..].find(needle) {
        let start = from + i;
        let mut end = (start + 96).min(hay.len());
        // The file is not pure ASCII (box glyphs, em dashes) and
        // slicing mid-codepoint panics.
        while !hay.is_char_boundary(end) {
            end -= 1;
        }
        out.push(&hay[start..end]);
        from = start + needle.len();
    }
    out
}

const CONFIRM: &str = "KeyCode::Char('y')";
const CONFIRM_SHIFTED: &str = " | KeyCode::Char('Y')";
const CANCEL: &str = "KeyCode::Char('n')";
const CANCEL_SHIFTED: &str = " | KeyCode::Char('N')";

/// Structural, not behavioural, and deliberately so: a behavioural
/// test can only cover the modals that exist today, and the point of
/// the convention is that the *next* modal cannot be born incoherent.
#[test]
fn ux14_every_single_key_confirm_accepts_both_cases() {
    let src = collapsed(&production_source());
    let sites = sites_of(&src, CONFIRM);

    // Vacuity guard. "Every site complies" is trivially true of no
    // sites, so a broken stripper or a stale needle would read green.
    // A floor, not an equality — a correctly-written new gate must
    // not turn this red.
    assert!(
        sites.len() >= 9,
        "expected at least the 9 known confirm gates, found {} — either \
             the stripper or the needle is broken (this invariant is vacuous \
             over no sites), or a modal was legitimately deleted, in which \
             case lower the floor rather than removing it",
        sites.len()
    );

    let bare: Vec<&str> = sites
        .iter()
        .filter(|s| !s[CONFIRM.len()..].starts_with(CONFIRM_SHIFTED))
        .copied()
        .collect();
    assert!(
        bare.is_empty(),
        "these confirm gates take `y` but ignore `Y` — an operator with \
             CapsLock presses a key that does nothing and is told nothing:\n{}",
        bare.join("\n\n")
    );
}

/// The cancel half — **and as of N6 (2026-08-24) it has no exception
/// left.**
///
/// It used to allow exactly one bare `n`, by identity: the Local DNS
/// leaf bound `n` to "next profile" and `N` to "previous profile" —
/// the vim search idiom, where the two cases mean *opposite* things,
/// so merging those arms would have been a bug rather than a fix.
///
/// N6 retired the panel model those two keys served, so the binding is
/// gone and with it the carve-out. The floor drops 10 → 9 and the
/// allowance drops 1 → 0, which is the direction that makes an
/// invariant stronger: every single-key cancel in the TUI now takes
/// both cases, with nothing exempted.
///
/// The floor was lowered rather than removed, exactly as the message
/// on the `y` twin instructs — a count of zero would make this test
/// pass over an empty set, which is how a scan quietly stops
/// scanning.
#[test]
fn ux14_every_single_key_cancel_accepts_both_cases() {
    let src = collapsed(&production_source());
    let sites = sites_of(&src, CANCEL);

    assert!(
        sites.len() >= 9,
        "expected at least the 9 known `n` sites, found {} — either the \
             stripper or the needle is broken (this invariant is vacuous \
             over no sites), or a modal was legitimately deleted, in which \
             case lower the floor rather than removing it",
        sites.len()
    );

    let bare: Vec<&str> = sites
        .iter()
        .filter(|s| !s[CANCEL.len()..].starts_with(CANCEL_SHIFTED))
        .copied()
        .collect();

    assert!(
        bare.is_empty(),
        "these cancel gates take `n` but ignore `N` — an operator with \
             CapsLock presses a key that does nothing and is told nothing. \
             The Local DNS next-profile binding used to be a legitimate bare \
             `n` here; N6 deleted it, so there is no exception any more:\n{}",
        bare.join("\n\n")
    );
}

/// The two scans are worth exactly as much as the stripper.
///
/// A walk that terminated early would leave this module's own
/// literals in scope — and they are written to satisfy the very rule
/// being checked, so the invariant would pass by reading itself. The
/// marker below lives in the file's **last** test module, which is
/// the one an early-terminating walk keeps.
#[test]
fn ux14_the_stripper_actually_strips() {
    let raw = include_str!("../mod.rs");
    let stripped = production_source();

    assert!(
        stripped.contains("fn paste_into_group_modal"),
        "production code must survive the strip"
    );

    // Presence in `raw` is asserted before absence in `stripped`. An
    // absence-only assertion goes silently vacuous the day its needle moves
    // to another file — it then passes by reading nothing, which is exactly
    // how three assertions here stopped testing anything.
    for needle in [
        // every relocated module's declaration
        "#[path = \"tests/",
        // the one marker that is not the plain `#[cfg(test)]` spelling
        "#[cfg(all(test",
        // a column-0 standalone test helper, the kept exception
        "device_update_patch",
    ] {
        assert!(
            raw.contains(needle),
            "{needle:?} is no longer in mod.rs, so asserting its absence \
             proves nothing — repoint this at something the file still holds"
        );
        assert!(
            !stripped.contains(needle),
            "{needle:?} survived the strip — the scans would then be reading \
             test source as production code"
        );
    }

    // Same predicate the strip logic itself uses, so this count and the
    // strip cannot silently diverge the way an independent
    // `== "#[cfg(test)]"` check once did.
    let survivors: Vec<&str> = stripped
        .lines()
        .filter(|l| looks_like_test_cfg_attr(l.trim()))
        .collect();
    assert_eq!(
        survivors.len(),
        1,
        "exactly one test-cfg marker is indented (TerminalGuard::with_restore) \
             and so is not a column-0 module the walk removes; more than one \
             means whole test modules are being left behind: {survivors:?}"
    );
    assert!(
        survivors[0].starts_with(char::is_whitespace),
        "the one survivor must be indented — a column-0 survivor means a \
             real test module failed to strip: {:?}",
        survivors[0]
    );
    assert!(
        stripped.contains("    #[cfg(test)]\n    fn with_restore"),
        "the survivor must be `TerminalGuard::with_restore` specifically — a \
         count of one is also satisfied by an unrelated indented marker while \
         that one went missing"
    );
}

/// Discipline pin for the mod.rs decomposition: every `#[cfg(test)] mod
/// { ... }` block that lived in `mod.rs` has been relocated to
/// `src/tui/tests/<name>.rs` via `#[path]`. Unlike
/// `ux14_the_stripper_actually_strips` (which checks what
/// `production_source()` leaves *after* stripping), this scans the raw
/// file directly for any marker that still opens a brace-delimited
/// block — so a future rebase or merge that pastes a test module back
/// into `mod.rs` fails here, loud, instead of quietly regrowing the
/// file this axis just cut in half.
#[test]
fn no_brace_form_test_module_remains_in_mod_rs() {
    crate::tui::cfg_scan::assert_no_inline_test_module("mod.rs", include_str!("../mod.rs"));
}

/// A bare-`y` gate before this change, driven end to end through the
/// dispatcher. The **write** is the assertion — modal state alone
/// would pass on a gate that consumed the key and did nothing.
///
/// `KeyModifiers::NONE` is not a shortcut: CapsLock delivers
/// `Char('Y')` with no modifier set, which is exactly the operator
/// this change is for. The arms match on `key.code` alone, so the
/// Shift-held variant takes the same path.
#[tokio::test]
async fn ux14_shifted_confirm_removes_a_group() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_groups_master(&dir);
    let poller = dummy_poller(dir.path());
    let mut app = groups_app(&master);

    handle_key(&mut app, key(KeyCode::Char('d')), &poller, &master).await;
    assert!(
        app.groups.modal.is_some(),
        "`d` must open the remove confirm"
    );

    handle_key(&mut app, key(KeyCode::Char('Y')), &poller, &master).await;

    assert!(
        !std::fs::read_to_string(&master).unwrap().contains("phones"),
        "a shifted Y must remove the group, exactly as `y` does"
    );
}

/// The cancel half, end to end.
#[tokio::test]
async fn ux14_shifted_cancel_closes_the_gate_without_writing() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_groups_master(&dir);
    let poller = dummy_poller(dir.path());
    let mut app = groups_app(&master);

    handle_key(&mut app, key(KeyCode::Char('d')), &poller, &master).await;
    let before = std::fs::read_to_string(&master).unwrap();

    handle_key(&mut app, key(KeyCode::Char('N')), &poller, &master).await;

    assert!(
        app.groups.modal.is_none(),
        "a shifted N must close the confirm, exactly as `n` does"
    );
    assert_eq!(
        std::fs::read_to_string(&master).unwrap(),
        before,
        "cancelling writes nothing"
    );
}

fn mk_local_dns_master(dir: &tempfile::TempDir) -> PathBuf {
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

[[local_dns.records]]
domain = "nas.home"
type = "A"
value = "192.0.2.50"
"#,
    )
    .unwrap();
    master
}

/// The tuple-pattern gate, and the one a looser scan waves through.
///
/// Its cancel arm reads
/// `(ConfirmTier::SingleKeypress, KeyCode::Char('n')) | (_, KeyCode::Esc)`
/// — already a `|` right after the char — so a check that merely
/// asked for "a pipe follows" would have called it compliant while
/// `N` stayed dead. That is why both scans above match the shifted
/// literal specifically rather than a separator.
///
/// Global scope with `match_subdomains` defaulting false is the
/// `SingleKeypress` tier (`ConfirmTier::for_remove`); the typed-phrase
/// tier is a different gate and takes no single key at all.
#[tokio::test]
async fn ux14_shifted_confirm_removes_a_local_dns_record() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_local_dns_master(&dir);
    let poller = dummy_poller(dir.path());
    let mut app = App::new();
    app.loaded_config = load_v1_config(&master);
    app.active_leaf = Leaf::LocalDns;
    // N6: one cursor, anchored by (scope, domain).
    app.local_dns.selected_id = Some(("global".to_string(), "nas.home".to_string()));
    assert!(
        app.loaded_config.is_some(),
        "fixture must parse — every assertion below is vacuous otherwise"
    );

    handle_key(&mut app, key(KeyCode::Char('d')), &poller, &master).await;
    assert!(
        app.local_dns.modal.is_some(),
        "`d` must open the remove confirm"
    );

    handle_key(&mut app, key(KeyCode::Char('Y')), &poller, &master).await;

    assert!(
        !std::fs::read_to_string(&master)
            .unwrap()
            .contains("nas.home"),
        "a shifted Y must remove the record at the single-keypress tier"
    );
}
