//! Sprint 53 — Lists Edit Modal frozen-strings test.
//!
//! Pins byte-for-byte every operator-facing string coined in S53
//! (§6 of `_docs/features/lists_edit_modal.md`). The four strings are:
//!
//! - `LIST_EDIT_OK`              save flow success after reload.
//! - `LIST_DELETE_OK`             delete flow success after reload.
//! - `LIST_DELETE_CONFIRM_FAILED` typed-id confirm mismatch.
//! - `LIST_EDIT_DAEMON_UNREACHABLE` daemon-down save / delete fallback.
//!
//! The strings live in `src/cli/commands/blocklists.rs` next to the
//! S50 frozen-strings family. The format helpers (`format_list_edit_ok`
//! / `format_list_delete_ok`) substitute the `{id}` placeholder; we pin
//! both the raw template and the substituted output so a refactor that
//! drops the helper still trips this gate.
//!
//! When a string MUST change for legitimate reasons (UX re-wording,
//! typo fix, translation tooling), update the literal here AND the §6
//! frozen-strings table in the same commit. Byte-for-byte equality has
//! no escape hatch — that is the entire point of this trip-wire.

use purge_warden::cli::commands::blocklists::{
    format_list_delete_ok, format_list_edit_ok, LIST_DELETE_CONFIRM_FAILED, LIST_DELETE_OK,
    LIST_EDIT_DAEMON_UNREACHABLE, LIST_EDIT_OK,
};

#[test]
fn s53_list_edit_ok_const_pinned_byte_for_byte() {
    assert_eq!(LIST_EDIT_OK, "List '{id}' updated; reload OK");
}

#[test]
fn s53_format_list_edit_ok_substitutes_id() {
    let out = format_list_edit_ok("privacy-ads");
    assert_eq!(out, "List 'privacy-ads' updated; reload OK");
    assert!(!out.contains('{'), "leftover placeholder in {out:?}");
}

#[test]
fn s53_list_delete_ok_const_pinned_byte_for_byte() {
    assert_eq!(LIST_DELETE_OK, "List '{id}' deleted; reload OK");
}

#[test]
fn s53_format_list_delete_ok_substitutes_id() {
    let out = format_list_delete_ok("privacy-ads");
    assert_eq!(out, "List 'privacy-ads' deleted; reload OK");
    assert!(!out.contains('{'), "leftover placeholder in {out:?}");
}

#[test]
fn s53_list_delete_confirm_failed_const_pinned_byte_for_byte() {
    assert_eq!(
        LIST_DELETE_CONFIRM_FAILED,
        "Confirmation failed; list not deleted"
    );
    // Length sanity — guards against a trailing-newline injection or
    // a casing tweak that wouldn't show up in casual visual review.
    assert_eq!(LIST_DELETE_CONFIRM_FAILED.len(), 37);
}

#[test]
fn s53_list_edit_daemon_unreachable_const_pinned_byte_for_byte() {
    assert_eq!(
        LIST_EDIT_DAEMON_UNREACHABLE,
        "Saved to disk; restart daemon to apply"
    );
    assert_eq!(LIST_EDIT_DAEMON_UNREACHABLE.len(), 38);
}

#[test]
fn s53_strings_have_no_trailing_period() {
    // §6 says "no trailing period" for all four strings — guards
    // against a copy-edit that breaks tonal consistency with the rest
    // of the S35/S36/S50 string family.
    for s in [
        LIST_EDIT_OK,
        LIST_DELETE_OK,
        LIST_DELETE_CONFIRM_FAILED,
        LIST_EDIT_DAEMON_UNREACHABLE,
    ] {
        assert!(
            !s.ends_with('.'),
            "S53 frozen string must not end with a period: {s:?}"
        );
    }
}
