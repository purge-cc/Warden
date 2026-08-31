//! Frozen strings for the `/` section-jump popup of the File tab.
//!
//! The popup came from tui-wave1/settings-sidebar, where it replaced the
//! permanent left "Sections" sidebar; §4.67-b MN3 moved it to
//! `tabs/file.rs` with the document viewer it navigates. The strings
//! themselves did NOT change — only the module that owns them — so this
//! file moved its `include_str!` target, not its expectations.
//!
//! Pins the popup title bar and the footer hint line byte-for-byte, same
//! `include_str!` + literal-contains idiom as
//! `frozen_strings_s49_profile_editor_tui.rs`. If either string needs a
//! legitimate re-word, update it here in the same commit as the source
//! change — this is the trip-wire, not documentation.

const SECTION_JUMP_TITLE: &str = " Jump to section ";
const SECTION_JUMP_HINT: &str = "Enter: jump · Esc: cancel";

fn file_src() -> &'static str {
    include_str!("../src/tui/tabs/file.rs")
}

#[test]
fn section_jump_title_is_pinned() {
    let src = file_src();
    let needle = format!("\"{SECTION_JUMP_TITLE}\"");
    assert!(
        src.contains(&needle),
        "settings.rs must spell the section-jump popup title exactly as \
         `{SECTION_JUMP_TITLE}` (looked for literal `{needle}`)"
    );
}

#[test]
fn section_jump_hint_is_pinned() {
    let src = file_src();
    let needle = format!("\"{SECTION_JUMP_HINT}\"");
    assert!(
        src.contains(&needle),
        "settings.rs must spell the section-jump popup hint line exactly as \
         `{SECTION_JUMP_HINT}` (looked for literal `{needle}`)"
    );
}
