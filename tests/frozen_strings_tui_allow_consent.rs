//! Frozen-string pins for the TUI's unsigned-allow consent gate.
//!
//! Sibling of `frozen_strings_unsigned_allow.rs`, which pins the
//! *validator's* view of the same decision. Two files rather than one,
//! because the two surfaces are deliberately allowed to word it
//! differently and must not be quietly merged: the validator's string is
//! a config diagnostic and speaks TOML ("set accept_unsigned_allow =
//! true"), which is the right answer for someone reading a log and the
//! wrong one for someone standing in front of a form. It is also ~300
//! characters, against a body whose prose ceiling is 7 rows with no
//! scrollbar — dropped in there it would be cut with nothing on screen
//! saying so.
//!
//! These strings are the operator's entire view of a decision that has
//! no undo affordance and leaves nothing on the Lists tab marking the
//! moment it was granted. When one MUST change (re-wording, typo), edit
//! the literal here in the same commit. Byte-for-byte equality has no
//! escape hatch — that is the point of a trip-wire.

use purge_warden::tui::{
    format_kind_toggle_ok, format_list_allow_consent_saved, KIND_TOGGLE_OK_ALLOW,
    KIND_TOGGLE_OK_BLOCK, LIST_ALLOW_CONSENT_SAVED, UNSIGNED_ALLOW_CONFIRM_DESC,
    UNSIGNED_ALLOW_CONFIRM_HINT, UNSIGNED_ALLOW_CONFIRM_MISMATCH, UNSIGNED_ALLOW_CONFIRM_PROMPT,
    UNSIGNED_ALLOW_CONFIRM_RISK_1, UNSIGNED_ALLOW_CONFIRM_RISK_2, UNSIGNED_ALLOW_CONFIRM_TITLE,
};

// ── the direction-aware field copy — RETIRED in `plp-s5f` ────────────
//
// Five assertions pinned `TAGS_EMPTY_NOTE_BLOCK` / `_ALLOW` and
// `TAGS_HINT_BLOCK` / `_ALLOW`: the chip picker's empty-state notes and
// focus hints. `plp-s5d` removed `EditField::Tags`, the picker and the
// `edit_focus_hint` arms that returned them, leaving the four consts
// reachable from nothing — kept standing only because THIS file imported
// them by name, and `tabs/lists.rs` said so at their declaration with the
// instruction to retire them here, with their assertions, in one commit.
//
// One of them had also gone false. `TAGS_EMPTY_NOTE_BLOCK` read
// "(none — filed under \"uncategorized\")", which was true while the
// loader auto-promoted untagged deny-lists. `plp-s5a` removed the field
// and that pass; the sentence survived, byte-pinned, describing a filing
// that no longer happens.

// ── the confirm notice ───────────────────────────────────────────────

#[test]
fn unsigned_allow_confirm_title_byte_for_byte() {
    assert_eq!(
        UNSIGNED_ALLOW_CONFIRM_TITLE,
        "Turn this into an allow list?"
    );
}

#[test]
fn unsigned_allow_confirm_desc_byte_for_byte() {
    assert_eq!(
        UNSIGNED_ALLOW_CONFIRM_DESC,
        "it would permit these domains instead of blocking them"
    );
}

/// The two risk rows carry the whole argument, so they are pinned
/// separately: a merge that dropped one would still leave a body that
/// renders and reads like a warning.
#[test]
fn unsigned_allow_confirm_risk_rows_byte_for_byte() {
    assert_eq!(
        UNSIGNED_ALLOW_CONFIRM_RISK_1,
        "warden cannot verify this source: whoever controls"
    );
    assert_eq!(
        UNSIGNED_ALLOW_CONFIRM_RISK_2,
        "the URL can unblock any domain, at every refresh."
    );
}

/// Word-for-word the delete gate's prompt. The two typed confirms in
/// this modal ask for the same thing; phrasing them differently would
/// teach the operator that they are different asks.
#[test]
fn unsigned_allow_confirm_prompt_matches_the_delete_gates_wording() {
    assert_eq!(
        UNSIGNED_ALLOW_CONFIRM_PROMPT,
        "type the id above verbatim, then Enter:"
    );
}

#[test]
fn unsigned_allow_confirm_hint_byte_for_byte() {
    assert_eq!(
        UNSIGNED_ALLOW_CONFIRM_HINT,
        "nothing is written unless what you type matches exactly"
    );
}

/// The dash is U+2014 EM DASH. A normalising editor that rewrites it
/// trips this, which is intended.
#[test]
fn unsigned_allow_confirm_mismatch_byte_for_byte() {
    assert_eq!(
        UNSIGNED_ALLOW_CONFIRM_MISMATCH,
        "that is not the list id — type it exactly to accept"
    );
}

// ── the tag gate ─────────────────────────────────────────────────────
//
// `list_allow_needs_tag_byte_for_byte` and `kind_toggle_needs_tag_...`
// stood here. `profile_list_policy` §2.5 retired the gate they pinned —
// `AllowDirectionGates::needs_tag` is permanently `false` — and the S4c
// TUI lane removed the two branches that raised them along with the
// constants themselves. A byte-for-byte pin on a string nothing emits
// tests the string, not the product.
//
// The consent gate below is untouched and is the live half.

// ── the success toast ────────────────────────────────────────────────

/// Replaces the generic `LIST_EDIT_OK` on the save that carried a fresh
/// consent. Naming the standing per-load WARN is the one chance to tell
/// the operator the exposure did not end when the modal closed — and the
/// log is where they will next meet it.
#[test]
fn list_allow_consent_saved_byte_for_byte() {
    assert_eq!(
        LIST_ALLOW_CONSENT_SAVED,
        "List '{id}' is now an allow list; warden warns about it at every load"
    );
}

#[test]
fn format_list_allow_consent_saved_substitutes_the_id() {
    assert_eq!(
        format_list_allow_consent_saved("content-gambling"),
        "List 'content-gambling' is now an allow list; warden warns about it at every load"
    );
}

/// The no-consent-needed half: a local list, one whose file already
/// consents, or the way back to blocking.
#[test]
fn kind_toggle_ok_byte_for_byte() {
    assert_eq!(
        KIND_TOGGLE_OK_BLOCK,
        "List '{id}' is now a block list; reload triggered"
    );
    assert_eq!(
        KIND_TOGGLE_OK_ALLOW,
        "List '{id}' is now an allow list; reload triggered"
    );
}

/// Two constants instead of one `{kind}` slot, because the slot wanted
/// an article and the wire token cannot supply one — the first draft
/// rendered *"is now a allow list"*.
///
/// The assertion is on the class, not the instance: any toast built by
/// pasting a direction token after a fixed article breaks here, on
/// whichever half is wrong. A future third direction inherits the check.
#[test]
fn no_direction_toast_pastes_a_token_after_a_fixed_article() {
    for s in [
        KIND_TOGGLE_OK_BLOCK,
        KIND_TOGGLE_OK_ALLOW,
        LIST_ALLOW_CONSENT_SAVED,
    ] {
        for wrong in [" a allow", " a e", " a i", " a o", " an block", " an deny"] {
            assert!(
                !s.contains(wrong),
                "{s:?} reads ungrammatically ({wrong:?}) — the article and the \
                 direction word have to be chosen together"
            );
        }
    }
}

#[test]
fn format_kind_toggle_ok_picks_the_half_that_matches_the_direction() {
    use purge_warden::config::schema::BlocklistBase;
    assert_eq!(
        format_kind_toggle_ok("content-gambling", BlocklistBase::Deny),
        "List 'content-gambling' is now a block list; reload triggered"
    );
    assert_eq!(
        format_kind_toggle_ok("content-gambling", BlocklistBase::Allow),
        "List 'content-gambling' is now an allow list; reload triggered"
    );
}

/// The toast must not go quiet about the standing exposure. Asserting on
/// the *property* rather than only the literal, so a re-wording that
/// drops the recurrence — "warns once", or no warning clause at all —
/// fails even though the byte-pin above was updated in the same commit.
#[test]
fn the_consent_toast_says_the_warning_recurs() {
    assert!(
        LIST_ALLOW_CONSENT_SAVED.contains("every load"),
        "the consent is recorded once and applies at every refresh; a toast \
         that implies a one-off leaves the operator expecting it to lapse: \
         {LIST_ALLOW_CONSENT_SAVED}"
    );
}

// ── the retired copy must not come back ──────────────────────────────

/// The pre-consent TUI told the operator that a remote allow-list was
/// simply not available, because at the time it was not. Pinning the
/// absence matters because that sentence is what a revert or a merge
/// from a stale branch puts back: it would compile, the gate would still
/// work, and the only symptom would be an operator being told to stop
/// trying.
#[test]
fn retired_refusal_copy_is_not_reintroduced() {
    for (label, s) in [
        ("title", UNSIGNED_ALLOW_CONFIRM_TITLE),
        ("desc", UNSIGNED_ALLOW_CONFIRM_DESC),
        ("risk1", UNSIGNED_ALLOW_CONFIRM_RISK_1),
        ("risk2", UNSIGNED_ALLOW_CONFIRM_RISK_2),
    ] {
        let lower = s.to_ascii_lowercase();
        for retired in ["trust=local", "trust = local", "import-local", "cannot be"] {
            assert!(
                !lower.contains(retired),
                "{label} reintroduces the retired refusal ({retired:?}): {s}"
            );
        }
    }
}
