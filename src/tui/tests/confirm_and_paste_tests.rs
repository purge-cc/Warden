use super::*;
use crate::tui::app::{App, Leaf};
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

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum StripState {
    Normal,
    Classifying,
    SkippingBlock,
}

/// Splits a line that opens with `#[` into the attribute's own text
/// (everything between the brackets) and whatever follows the closing
/// `]` on the same physical line — e.g. `#[cfg(test)]` -> `("cfg(test)",
/// "")`, `#[cfg(test)] mod tests;` -> `("cfg(test)", "mod tests;")`.
/// Matches `[`/`]` depth rather than a fixed suffix, with quoted string
/// contents masked first, so a bracket inside a string value can never
/// be mistaken for the attribute's own close. Returns `None` if the
/// line does not start with `#[`, or if the brackets never close on
/// this physical line — the caller decides what that means.
fn split_leading_attr(line: &str) -> Option<(&str, &str)> {
    let rest = line.strip_prefix('#')?.strip_prefix('[')?;
    let bytes = rest.as_bytes();
    let mut depth: i32 = 1;
    let mut in_string = false;
    for (i, &b) in bytes.iter().enumerate() {
        match b {
            b'"' => in_string = !in_string,
            b'[' if !in_string => depth += 1,
            b']' if !in_string => {
                depth -= 1;
                if depth == 0 {
                    return Some((&rest[..i], rest[i + 1..].trim_start()));
                }
            }
            _ => {}
        }
    }
    None
}

/// `cfg(PREDICATE)` -> `Some("PREDICATE")`; anything else (a non-`cfg`
/// attribute like `allow(dead_code)`) -> `None`.
fn cfg_inner_predicate(attr: &str) -> Option<&str> {
    attr.strip_prefix("cfg(")?.strip_suffix(')')
}

/// True when `test` appears as a bare predicate token inside a
/// `cfg(...)` attribute's predicate text — matches `test`,
/// `all(test, unix)`, `any(test, feature = "x")`. False for
/// `feature = "test"` (a string value, not an identifier — quotes are
/// masked before the token search) and for `not(test)` (that predicate
/// compiles *outside* test builds — the opposite of what stripping
/// means). Panics on any other combination of `not(` with the `test`
/// token: a real cfg-expression parser is out of scope, and a loud
/// failure here beats silently classifying a shape nobody has reasoned
/// about.
fn cfg_predicate_names_test(predicate: &str) -> bool {
    let mut masked = String::with_capacity(predicate.len());
    let mut in_string = false;
    for c in predicate.chars() {
        if c == '"' {
            in_string = !in_string;
            masked.push(' ');
        } else if in_string {
            masked.push(' ');
        } else {
            masked.push(c);
        }
    }
    let no_ws: String = masked.chars().filter(|c| !c.is_whitespace()).collect();
    if no_ws == "not(test)" {
        return false;
    }
    let has_test_token = masked
        .split(|c: char| !c.is_alphanumeric() && c != '_')
        .any(|tok| tok == "test");
    if !has_test_token {
        return false;
    }
    assert!(
        !no_ws.contains("not("),
        "cfg predicate {predicate:?} combines `not(` with a `test` token in \
             a shape other than exactly `not(test)` — this needs a real \
             cfg-expression parser to classify correctly, not this heuristic"
    );
    true
}

/// True when `line` is a column-0 marker beginning a `#[cfg(...)]`
/// attribute whose predicate names the `test` cfg flag. Indented lines
/// (the one deliberate exception, `TerminalGuard::with_restore`) are
/// never markers — column 0 is the signal; see `production_source`'s
/// doc comment above for why brace-depth is not used instead. Returns
/// the marker line's own tail (what follows the attribute on the same
/// line), so the caller can tell a bare declaration (`mod tests;`)
/// apart from a block opener (`mod tests {`).
fn is_test_cfg_marker(line: &str) -> Option<&str> {
    if line.starts_with(char::is_whitespace) {
        return None;
    }
    let (attr, tail) = split_leading_attr(line)?;
    let predicate = cfg_inner_predicate(attr)?;
    cfg_predicate_names_test(predicate).then_some(tail)
}

/// Same predicate as `is_test_cfg_marker`, applied without the
/// column-0 gate — used by `ux14_the_stripper_actually_strips` to
/// count every surviving test-cfg marker regardless of indentation, so
/// the strip logic and its self-check share one definition of "looks
/// like a test marker" instead of two that can drift apart.
fn looks_like_test_cfg_attr(trimmed_line: &str) -> bool {
    split_leading_attr(trimmed_line)
        .and_then(|(attr, _tail)| cfg_inner_predicate(attr))
        .map(cfg_predicate_names_test)
        .unwrap_or(false)
}

fn classify_tail(tail: &str) -> StripState {
    if tail.is_empty() {
        StripState::Classifying
    } else if tail.ends_with('{') {
        StripState::SkippingBlock
    } else if tail.ends_with(';') {
        StripState::Normal
    } else {
        StripState::Classifying
    }
}

/// The actual strip: a 3-state walk over `src`'s lines. `Normal` looks
/// for the next test-cfg marker; `Classifying` peeks forward (through
/// any stacked attributes, or a multi-line item signature) until it
/// finds out whether the marked item is a bare declaration (skip one
/// logical item, done) or a brace-delimited block (skip to its
/// column-0 close); `SkippingBlock` does that skip. Panics rather than
/// silently mis-stripping if an attribute's brackets never close on
/// one physical line, or if a marked item's close is never found
/// before EOF.
fn strip_test_items(src: &str) -> String {
    let mut out = String::new();
    let mut state = StripState::Normal;
    for line in src.lines() {
        state = match state {
            StripState::Normal => {
                if let Some(tail) = is_test_cfg_marker(line) {
                    classify_tail(tail)
                } else {
                    out.push_str(line);
                    out.push('\n');
                    StripState::Normal
                }
            }
            StripState::Classifying => {
                if line.starts_with("#[") {
                    match split_leading_attr(line) {
                        Some((_, tail)) => classify_tail(tail),
                        None => panic!(
                            "attribute at {line:?} did not close its brackets \
                                 on one physical line; strip_test_items cannot \
                                 classify what follows it — reformat to one line \
                                 or extend split_leading_attr for multi-line \
                                 attributes"
                        ),
                    }
                } else {
                    classify_tail(line.trim_end())
                }
            }
            StripState::SkippingBlock => {
                if line == "}" {
                    StripState::Normal
                } else {
                    StripState::SkippingBlock
                }
            }
        };
    }
    assert_eq!(
        state,
        StripState::Normal,
        "strip_test_items ended in {state:?} at EOF — a test item's \
             closing brace or semicolon was never found; the walk ran off \
             the end of the file and silently dropped every line after the \
             last marker"
    );
    out
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
    let stripped = production_source();

    assert!(
        stripped.contains("fn paste_into_group_modal"),
        "production code must survive the strip"
    );
    assert!(
        !stripped.contains("ux14_the_stripper_actually_strips"),
        "this module is `#[cfg(test)]` and must not survive — the scans \
             would then be reading their own needles"
    );
    assert!(
        !stripped.contains("#[tokio::test]"),
        "no production item carries a test attribute"
    );
    assert!(
        !stripped.contains("success_exit_returns_none"),
        "editor_failure_tests is `#[cfg(all(test, unix))]`, not the exact \
             literal `#[cfg(test)]` — it must be stripped like every other \
             test module, not leaked through by a spelling the old check missed"
    );

    // Same predicate the strip logic itself uses (`looks_like_test_cfg_attr`
    // wraps `split_leading_attr` + `cfg_inner_predicate` +
    // `cfg_predicate_names_test`), so this count and the strip cannot
    // silently diverge the way an independent `== "#[cfg(test)]"` check
    // once did.
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
}

/// Every line in `src` that opens a brace-form `#[cfg(test)] mod { ... }`
/// block, by line number. Deliberately blind to a `#[cfg(test)] fn`
/// opener — the 5 standalone helpers (device_update_patch and friends)
/// also end in `{` and are a kept, accepted exception, not a
/// regression.
fn brace_form_test_mod_offenders(src: &str) -> Vec<String> {
    let lines: Vec<&str> = src.lines().collect();
    let mut offenders = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        let Some(tail) = is_test_cfg_marker(line) else {
            continue;
        };
        // Same-line form (`#[cfg(test)] mod x {`) puts the opener in
        // `tail`; the far more common next-line form puts it on the
        // following line.
        let opener = if tail.is_empty() {
            lines.get(i + 1).copied().unwrap_or("").trim_end()
        } else {
            tail
        };
        if classify_tail(opener) == StripState::SkippingBlock
            && opener.trim_start().starts_with("mod ")
        {
            offenders.push(format!("mod.rs:{}: {line}", i + 1));
        }
    }
    offenders
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
    let offenders = brace_form_test_mod_offenders(include_str!("../mod.rs"));
    assert!(
        offenders.is_empty(),
        "a brace-form #[cfg(test)] mod block is back inline in mod.rs — this \
         axis moved every one of them to src/tui/tests/<name>.rs via #[path]; \
         a new test module belongs there too, not inline:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn brace_form_test_mod_offenders_fires_on_a_mod_block() {
    let src = "PROD\n#[cfg(test)]\nmod t {\nTEST_BODY\n}\nPROD\n";
    let offenders = brace_form_test_mod_offenders(src);
    assert_eq!(
        offenders.len(),
        1,
        "expected exactly one hit: {offenders:?}"
    );
}

#[test]
fn brace_form_test_mod_offenders_ignores_a_standalone_fn() {
    let src = "PROD\n#[cfg(test)]\nfn h(x: i32) -> i32 {\n    x\n}\nPROD\n";
    let offenders = brace_form_test_mod_offenders(src);
    assert!(
        offenders.is_empty(),
        "a standalone #[cfg(test)] fn is the accepted exception, not an \
         offender: {offenders:?}"
    );
}

// `strip_test_items` fixture table. Every fixture below is a single-line
// escaped string, never a `r#"..."#` block — a raw multi-line string
// would place its own content at real column 0 inside `mod.rs`'s own
// source, which both this file's `include_str!` self-read AND
// `labels.rs`'s recursive directory walk would then read as if it were
// real code.

#[test]
fn strip_test_items_removes_a_block_form_test_module() {
    let src = "PROD_BEFORE\n#[cfg(test)]\nmod t {\nTEST_BODY\n}\nPROD_AFTER\n";
    let out = strip_test_items(src);
    assert!(out.contains("PROD_BEFORE") && out.contains("PROD_AFTER"));
    assert!(!out.contains("TEST_BODY"));
}

#[test]
fn strip_test_items_removes_a_bare_mod_declaration() {
    // The fix for failure mode #1: a bare declaration has no closing
    // brace of its own. Before this fix, the old exact-string checker
    // would keep skipping past PROD_AFTER looking for some unrelated
    // later `}`.
    let src = "PROD_BEFORE\n#[cfg(test)]\nmod t;\nPROD_AFTER\n";
    let out = strip_test_items(src);
    assert!(out.contains("PROD_BEFORE"));
    assert!(
        out.contains("PROD_AFTER"),
        "a bare `mod t;` declaration swallowed real content past itself: {out:?}"
    );
    assert!(!out.contains("mod t;"));
}

#[test]
fn strip_test_items_removes_a_same_line_bare_declaration() {
    let src = "PROD_BEFORE\n#[cfg(test)] mod t;\nPROD_AFTER\n";
    let out = strip_test_items(src);
    assert!(out.contains("PROD_BEFORE") && out.contains("PROD_AFTER"));
    assert!(!out.contains("mod t;"));
}

#[test]
fn strip_test_items_removes_a_cfg_all_test_module() {
    // The fix for failure mode #2, live today: `editor_failure_tests`
    // is spelled exactly this way and used to leak through.
    let src = "PROD_BEFORE\n#[cfg(all(test, unix))]\nmod t {\nTEST_BODY\n}\nPROD_AFTER\n";
    let out = strip_test_items(src);
    assert!(out.contains("PROD_BEFORE") && out.contains("PROD_AFTER"));
    assert!(!out.contains("TEST_BODY"));
}

#[test]
fn strip_test_items_removes_a_cfg_any_test_module() {
    let src =
        "PROD_BEFORE\n#[cfg(any(test, feature = \"x\"))]\nmod t {\nTEST_BODY\n}\nPROD_AFTER\n";
    let out = strip_test_items(src);
    assert!(out.contains("PROD_BEFORE") && out.contains("PROD_AFTER"));
    assert!(!out.contains("TEST_BODY"));
}

#[test]
fn strip_test_items_keeps_a_cfg_feature_named_test() {
    // Negative control: a cargo feature literally named "test" is a
    // string value, not the `test` build-mode identifier.
    let src = "#[cfg(feature = \"test\")]\nfn real() {\nBODY\n}\n";
    let out = strip_test_items(src);
    assert!(out.contains("fn real"));
    assert!(out.contains("BODY"));
}

#[test]
fn strip_test_items_keeps_a_cfg_not_test() {
    // Negative control: `not(test)` compiles OUTSIDE test builds — the
    // opposite of what stripping means.
    let src = "#[cfg(not(test))]\nfn real() {\nBODY\n}\n";
    let out = strip_test_items(src);
    assert!(out.contains("fn real"));
    assert!(out.contains("BODY"));
}

#[test]
fn strip_test_items_keeps_a_cfg_attr_test() {
    // Negative control: `cfg_attr` conditionally decorates an item
    // that exists in every build — it never gates existence.
    let src = "#[cfg_attr(test, allow(dead_code))]\nfn real() {\nBODY\n}\n";
    let out = strip_test_items(src);
    assert!(out.contains("fn real"));
    assert!(out.contains("BODY"));
}

#[test]
fn strip_test_items_keeps_an_indented_marker() {
    // The TerminalGuard::with_restore shape: indented, so column 0
    // never sees it as a marker.
    let src = "impl X {\n    #[cfg(test)]\n    fn with_restore() {}\n}\n";
    let out = strip_test_items(src);
    assert_eq!(
        out, src,
        "an indented test-cfg marker must survive verbatim"
    );
}

#[test]
fn strip_test_items_is_not_fooled_by_a_brace_inside_a_string_literal() {
    // A line containing `}` characters that is not, in its entirety,
    // the literal line `}` must not be mistaken for the block's close.
    let src = "PROD_BEFORE\n#[cfg(test)]\nmod t {\n    let s = \"a}b\";\n}\nPROD_AFTER\n";
    let out = strip_test_items(src);
    assert!(out.contains("PROD_BEFORE") && out.contains("PROD_AFTER"));
    assert!(!out.contains("a}b"));
}

#[test]
fn strip_test_items_keeps_stripping_the_five_standalone_test_fns_correctly() {
    // The `device_update_patch`-shaped case: a bare `#[cfg(test)] fn`
    // at column 0, not inside a `mod {}` block.
    let src = "PROD_BEFORE\n#[cfg(test)]\npub(crate) fn h(x: i32) -> i32 {\n    x\n}\nPROD_AFTER\n";
    let out = strip_test_items(src);
    assert!(out.contains("PROD_BEFORE") && out.contains("PROD_AFTER"));
    assert!(!out.contains("pub(crate) fn h"));
}

#[test]
#[should_panic(expected = "did not close its brackets")]
fn strip_test_items_panics_on_a_multiline_attribute_it_cannot_classify() {
    let src = "#[cfg(test)]\n#[cfg(\n    unix\n)]\nmod t {\n}\n";
    strip_test_items(src);
}

#[test]
#[should_panic(expected = "ended in")]
fn strip_test_items_panics_on_an_unclosed_marker_at_eof() {
    let src = "#[cfg(test)]\nmod t {\nTEST_BODY\n";
    strip_test_items(src);
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
