//! Sprint 47 (Query Log Quick-Action UX) — T5 frozen-strings test.
//!
//! Pins byte-for-byte the three neutral footer messages introduced in
//! T2 (`QUERY_NOT_ACTIONABLE_*` in `src/tui/tabs/query_log.rs`) plus a
//! regression net over the four rule-action templates already pinned
//! by Sprint 43 T6 in `tests/frozen_strings_s43.rs`. Re-asserting the
//! S43 strings here is intentional: an accidental removal of the S43
//! file (or a careless edit) cannot leave them unprotected, because
//! this file would still fail.
//!
//! See `_docs/features/query_log_quick_action_ux.md` §3 for the authoritative
//! status → message mapping the three new strings implement, and §4 for
//! the lexicon decision (D3) that keeps the four S43 templates locked
//! while the modal title/header copy changes around them.
//!
//! When a string MUST change for legitimate reasons (UX re-wording,
//! typo fix), update the literal here AND the §3 / §4 design-doc
//! tables in the same commit. Byte-for-byte equality has no escape
//! hatch — that is the entire point of this trip-wire.

use purge_warden::cli::commands::rules::{
    RULE_APPLIED_DEFAULT, RULE_APPLIED_DEVICE, RULE_APPLIED_PROFILE, RULE_UNDO_OK,
};
use purge_warden::tui::{
    QUERY_NOT_ACTIONABLE_LOCAL, QUERY_NOT_ACTIONABLE_REFUSED, QUERY_NOT_ACTIONABLE_UNKNOWN,
};

// ── Sprint 47 T2 — neutral-status footer messages ────────────────────

#[test]
fn query_not_actionable_local_byte_for_byte() {
    assert_eq!(
        QUERY_NOT_ACTIONABLE_LOCAL,
        "Local DNS records are managed in the Local DNS tab."
    );
}

#[test]
fn query_not_actionable_refused_byte_for_byte() {
    // Note: em-dash (U+2014) between "rule" and "allow/deny".
    // Reworded when the tunneling shape gate was retired: the old text
    // claimed "before filtering", which is false for the post-filter
    // subdomain-rate refusals, and named no remedy.
    assert_eq!(
        QUERY_NOT_ACTIONABLE_REFUSED,
        "Refused by a security check, not by a filter rule — allow/deny do not apply. \
         False positive? warden security tunneling exempt <domain>"
    );
}

#[test]
fn query_not_actionable_unknown_byte_for_byte() {
    assert_eq!(
        QUERY_NOT_ACTIONABLE_UNKNOWN,
        "This query status is not actionable from the Query Log."
    );
}

// ── Sprint 43 T6 — rule action templates (regression net) ────────────

#[test]
fn rule_applied_device_byte_for_byte() {
    assert_eq!(
        RULE_APPLIED_DEVICE,
        "{verb} {domain} on {device}. Other devices unaffected. To undo: warden rule undo"
    );
}

#[test]
fn rule_applied_profile_byte_for_byte() {
    assert_eq!(
        RULE_APPLIED_PROFILE,
        "{verb} {domain} on profile '{profile}'. Affects {n} devices currently. To undo: warden rule undo"
    );
}

#[test]
fn rule_applied_default_byte_for_byte() {
    assert_eq!(
        RULE_APPLIED_DEFAULT,
        "{verb} {domain} for unknown devices. Existing devices on a profile are unaffected. To undo: warden rule undo"
    );
}

#[test]
fn rule_undo_ok_byte_for_byte() {
    assert_eq!(RULE_UNDO_OK, "Removed last rule '{id}' ({rule_string}).");
}
