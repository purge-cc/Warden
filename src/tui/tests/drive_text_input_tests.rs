use super::*;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

fn key(code: KeyCode, mods: KeyModifiers) -> KeyEvent {
    KeyEvent::new(code, mods)
}

#[test]
fn plain_char_inserts() {
    let mut buf = String::new();
    let out = drive_text_input(&mut buf, key(KeyCode::Char('c'), KeyModifiers::NONE));
    assert!(matches!(out, TextInputOutcome::Continue));
    assert_eq!(buf, "c");
}

#[test]
fn shift_char_still_inserts() {
    // SHIFT must NOT be masked — capitals still type into a filter.
    let mut buf = String::new();
    drive_text_input(&mut buf, key(KeyCode::Char('C'), KeyModifiers::SHIFT));
    assert_eq!(buf, "C");
}

#[test]
fn ctrl_c_is_a_no_op_not_a_literal() {
    // Regression for tui-ctrlc-ignored-in-filter-input: Ctrl+C in a
    // `/`-filter buffer must be a no-op, not push a literal 'c'.
    let mut buf = String::new();
    let out = drive_text_input(&mut buf, key(KeyCode::Char('c'), KeyModifiers::CONTROL));
    assert!(matches!(out, TextInputOutcome::Continue));
    assert!(
        buf.is_empty(),
        "Ctrl+C must not insert a literal; got {buf:?}"
    );
}

#[test]
fn alt_char_is_a_no_op() {
    let mut buf = String::new();
    drive_text_input(&mut buf, key(KeyCode::Char('x'), KeyModifiers::ALT));
    assert!(
        buf.is_empty(),
        "Alt+x must not insert a literal; got {buf:?}"
    );
}
