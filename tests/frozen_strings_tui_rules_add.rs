//! wave2/rules-add-key — frozen-strings test for the Rules-tab add-rule
//! modal (`src/tui/rule_add_modal.rs`).
//!
//! Pins byte-for-byte the modal title, field labels, hints, and the
//! Rules-tab empty-state lead hint the DoD requires ("leads with
//! `[a] add rule`"). Same pattern as `tests/frozen_strings_s47.rs` /
//! `tests/frozen_strings_s51.rs`: selective `pub` const reach into a
//! `pub mod` promoted specifically for this integration test.
//!
//! When a string MUST change (UX re-wording), update the literal here
//! AND this file's comment in the same commit — byte-for-byte equality
//! has no escape hatch.

use purge_warden::tui::rule_add_modal::{
    ADD_RULE_HINT_1, ADD_RULE_MODAL_TITLE, DOMAIN_PLACEHOLDER, LABEL_ACTION, LABEL_DOMAIN,
    LABEL_SCOPE, RULES_EMPTY_ADD_HINT,
};

#[test]
fn add_rule_modal_title_byte_for_byte() {
    assert_eq!(ADD_RULE_MODAL_TITLE, " Add rule ");
}

#[test]
fn add_rule_field_labels_byte_for_byte() {
    assert_eq!(LABEL_DOMAIN, "Domain");
    assert_eq!(LABEL_ACTION, "Action");
    assert_eq!(LABEL_SCOPE, "Scope");
}

#[test]
fn add_rule_domain_placeholder_byte_for_byte() {
    assert_eq!(DOMAIN_PLACEHOLDER, "(type a domain, e.g. ads.example.com)");
}

#[test]
fn add_rule_hints_byte_for_byte() {
    // N14 stripped the save/cancel clause (CONTRACT §3.1): the action
    // row now carries its own key per button (`[Esc] Discard` ·
    // `[Enter] Save`) instead of a blanket legend clause. `ADD_RULE_HINT_2`
    // ("  Esc cancel") was deleted rather than repointed — it had no
    // render call site, and its word ("cancel") is exactly what §3.1
    // forbids.
    assert_eq!(
        ADD_RULE_HINT_1,
        "  Tab/\u{2191}\u{2193} move  \u{2022}  \u{2190}/\u{2192} change action/scope"
    );
}

#[test]
fn rules_empty_state_leads_with_add_rule_hint() {
    // DoD: "Update the Rules empty-state to lead with `[a] add rule`,
    // keeping the Query Log hint + CLI hint as secondary."
    assert_eq!(
        RULES_EMPTY_ADD_HINT,
        "  [a] add rule — create one directly from this tab."
    );
    assert!(RULES_EMPTY_ADD_HINT.contains("[a] add rule"));
}
