//! `profile_list_policy` §4 S4c — the per-list override panel's frozen
//! operator-facing strings.
//!
//! **Its own file, deliberately.** The panel is a new surface, and this
//! sprint runs three lanes at once; `frozen_strings_ipc_errors.rs` and
//! `frozen_strings_unsigned_allow.rs` belong to the IPC lane, and
//! `frozen_strings_s49_profile_editor_tui.rs` pins the §4.26 Phase-2
//! modal chrome. Adding rows to somebody else's file because it happens
//! to be nearby is how two lanes collide on one merge.
//!
//! **Pinned by VALUE, not by `include_str!` grep.** The Phase-2 file
//! greps `profile_modal.rs` for its literals, which passes just as
//! happily on a const nothing renders — the reason `tui/mod.rs` promoted
//! the `tabs::lists` consent copy to a re-export. `profile_modal` is a
//! `pub mod` for the same reason, so these are the real values.
//!
//! What renders them is asserted separately, on a real `TestBackend`, by
//! the inline tests in `src/tui/profile_modal.rs` — a value pin and a
//! render proof answer different questions and this repo has been bitten
//! by having only the first.

use purge_warden::tui::profile_modal::{
    LIST_OVERRIDE_HINT, LIST_OVERRIDE_IGNORE_ARMED, LIST_OVERRIDE_NEEDS_CONSENT, LIST_PANEL_EMPTY,
    LIST_POLICY_ALLOW, LIST_POLICY_BLOCK, LIST_POLICY_IGNORE, LIST_POLICY_INHERITED,
};

// ── the direction vocabulary ─────────────────────────────────────────

/// The three words are the **same** three the Lists modal's `nature` row
/// uses. They name the same three states one radius apart — `base` is
/// what every profile inherits, an override is what one profile declares
/// — so an operator who learned them on one surface must not have to
/// relearn them on the other. A rename here is a rename there.
#[test]
fn the_direction_words_are_the_lists_modal_vocabulary() {
    assert_eq!(LIST_POLICY_BLOCK, "Block");
    assert_eq!(LIST_POLICY_ALLOW, "Allow");
    assert_eq!(LIST_POLICY_IGNORE, "Ignore");
}

/// The provenance mark, and the fact that the **unmarked** form is the
/// declared one.
///
/// That asymmetry is the whole readout: a declaration is the plain
/// statement, inheritance is the qualified one. Pinned rather than left
/// to taste because inverting it is a one-character edit in
/// `list_policy_value` that leaves every row still saying a true thing —
/// just about the wrong list.
#[test]
fn the_inherited_mark_is_a_suffix_and_names_inheritance() {
    assert_eq!(LIST_POLICY_INHERITED, " (inherited)");
    assert!(
        LIST_POLICY_INHERITED.starts_with(' '),
        "it is appended to a direction word, not a row of its own"
    );
}

// ── the row guidance ─────────────────────────────────────────────────

/// The resting hint names `[i]` **and** that it takes two presses.
///
/// A legend advertising one keystroke for a two-keystroke valve teaches
/// the operator that the first press did nothing — which is exactly the
/// misreading the second press exists to prevent.
#[test]
fn the_resting_hint_names_the_two_press_valve() {
    assert!(
        LIST_OVERRIDE_HINT.contains("[i] twice"),
        "{LIST_OVERRIDE_HINT}"
    );
    assert!(LIST_OVERRIDE_HINT.contains("inert"), "{LIST_OVERRIDE_HINT}");
    assert!(
        LIST_OVERRIDE_HINT.contains("Block") && LIST_OVERRIDE_HINT.contains("Allow"),
        "the arrow cycle names its own states: {LIST_OVERRIDE_HINT}"
    );
    assert!(
        !LIST_OVERRIDE_HINT.to_ascii_lowercase().contains("tag"),
        "the tag model is retired — a hint that mentions it sends the \
         operator to a verb that now refuses: {LIST_OVERRIDE_HINT}"
    );
}

/// The armed confirm states the **consequence**, not the mechanic, and
/// names the list it is about to make inert.
///
/// "Sets ignore" is procedural and reads as harmless; "filters nothing in
/// this profile" is the thing the operator is being asked to authorise.
/// Making a list inert with no gate at any layer is the silent-unfiltering
/// shape of the 2026-05-07 incident P6 names, and this sentence is the
/// only place it is ever said.
#[test]
fn the_armed_confirm_states_the_consequence_and_names_the_list() {
    assert!(
        LIST_OVERRIDE_IGNORE_ARMED.contains("{id}"),
        "it substitutes the list id"
    );
    assert!(
        LIST_OVERRIDE_IGNORE_ARMED.contains("filters nothing"),
        "the consequence, not the mechanic: {LIST_OVERRIDE_IGNORE_ARMED}"
    );
    assert!(
        LIST_OVERRIDE_IGNORE_ARMED.contains("press [i] again"),
        "it names the key that commits: {LIST_OVERRIDE_IGNORE_ARMED}"
    );
    assert!(
        LIST_OVERRIDE_IGNORE_ARMED.contains("cancels"),
        "an accidental first press must be visibly recoverable: \
         {LIST_OVERRIDE_IGNORE_ARMED}"
    );
}

// ── the consent guidance ─────────────────────────────────────────────

/// The pending-allow notice names the CLI verb — **and not the Lists
/// tab** — and that is a measurement, not a preference for the terminal.
///
/// The TUI's Lists modal can only declare `accept_unsigned_allow` on the
/// way to making the list `base = allow` for *every* profile:
/// `allow_gate_for_modal` returns `Proceed` without consulting the gate
/// unless `nature == Allow`, and `[K]`'s gate sits behind
/// `target == Allow`. The common case this panel creates is an `allow`
/// override on a list that stays `base = deny` globally, so pointing at
/// the Lists tab would point somewhere that cannot do it — the
/// unsatisfiable refusal CLAUDE.md §Neutrality records this repo already
/// paying for once, in this very modal ecosystem.
///
/// `run_set_trust` writes the declaration whenever the flag is passed,
/// whatever the list's `base`, so the command below lands the consent on
/// a deny-direction list without changing anything else.
#[test]
fn the_consent_notice_names_a_command_that_actually_works() {
    assert!(
        LIST_OVERRIDE_NEEDS_CONSENT
            .contains("warden blocklist set-trust {id} remote-unsigned --accept-unsigned-allow"),
        "{LIST_OVERRIDE_NEEDS_CONSENT}"
    );
    assert!(
        LIST_OVERRIDE_NEEDS_CONSENT.contains('\n'),
        "the command is its own logical line so `hint_or_error_rows` wraps \
         it as a unit: {LIST_OVERRIDE_NEEDS_CONSENT:?}"
    );
    assert!(
        !LIST_OVERRIDE_NEEDS_CONSENT.contains("Lists tab"),
        "the Lists tab cannot declare consent without flipping the list's \
         own base to allow: {LIST_OVERRIDE_NEEDS_CONSENT}"
    );
}

/// The notice is guidance, never a gate: it must not claim to refuse
/// anything. The refusal is the daemon's, at the single write path, and a
/// second copy of it here would be the D11 class this workstream already
/// paid for.
#[test]
fn the_consent_notice_does_not_pretend_to_be_the_refusal() {
    let lower = LIST_OVERRIDE_NEEDS_CONSENT.to_ascii_lowercase();
    for claim in ["refused", "cannot save", "rejected", "type the list id"] {
        assert!(
            !lower.contains(claim),
            "the panel does not refuse and does not ask for a confirmation \
             ({claim:?}): {LIST_OVERRIDE_NEEDS_CONSENT}"
        );
    }
}

// ── the empty panel ──────────────────────────────────────────────────

#[test]
fn the_empty_panel_points_at_the_surface_that_adds_a_list() {
    assert_eq!(LIST_PANEL_EMPTY, "add one on the Lists tab");
}
