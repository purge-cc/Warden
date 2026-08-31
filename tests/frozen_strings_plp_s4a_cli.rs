//! Operator-facing strings owned by the `warden profile list-policy`
//! surface and by `warden profile show`'s list block.
//!
//! # Why a new file
//!
//! This repo pins operator-facing text so a refactor cannot reword it by
//! accident. The two neighbouring files that already carry list-policy
//! strings — `frozen_strings_ipc_errors.rs` and
//! `frozen_strings_unsigned_allow.rs` — pin text emitted on the *other*
//! side of the IPC boundary. A CLI string added to either would put this
//! surface's contract in a file this surface does not own.
//!
//! # What each pin is protecting
//!
//! Two of them carry an argument, not just a wording:
//!
//! - `PROFILE_TAGS_INERT` replaced a parenthetical that told the operator
//!   to run `warden profile tag add|remove` — a verb that *refuses*. An
//!   instruction to run a command that cannot succeed is worse than no
//!   instruction, so the replacement is pinned against drifting back into
//!   naming a verb.
//! - `LIST_POLICY_DISABLED_NOTE` exists because a switched-off list must
//!   not be reported as the `ignore` direction. If it ever reduced to the
//!   word `ignore`, the renderer would be telling the operator the profile
//!   made a decision the operator made.

use purge_warden::cli::commands::profiles_v1::{
    LIST_POLICY_DISABLED_NOTE, LIST_POLICY_INHERITED, LIST_POLICY_NO_LISTS, LIST_POLICY_OVERRIDDEN,
    PROFILE_TAGS_INERT,
};

#[test]
fn plp_s4a_frozen_list_policy_provenance_labels() {
    assert_eq!(LIST_POLICY_OVERRIDDEN, "set on this profile");
    assert_eq!(LIST_POLICY_INHERITED, "inherited from the list");
}

/// The two labels must stay distinguishable as substrings.
///
/// The renderer asserts "contains one, not the other", and that assertion
/// is vacuous the moment one label is a substring of the other — a rewrite
/// to `"set on this profile"` / `"inherited, not set on this profile"`
/// would keep both tests green with the distinction gone.
#[test]
fn plp_s4a_provenance_labels_are_not_substrings_of_each_other() {
    assert!(!LIST_POLICY_OVERRIDDEN.contains(LIST_POLICY_INHERITED));
    assert!(!LIST_POLICY_INHERITED.contains(LIST_POLICY_OVERRIDDEN));
}

#[test]
fn plp_s4a_frozen_disabled_note() {
    assert_eq!(
        LIST_POLICY_DISABLED_NOTE,
        " — list disabled, applies nothing"
    );
    assert!(
        !LIST_POLICY_DISABLED_NOTE.contains("ignore"),
        "a disabled list is not a profile ignoring it"
    );
}

/// The empty-state line must not just restate the count above it.
#[test]
fn plp_s4a_frozen_no_lists_names_the_repair() {
    assert_eq!(
        LIST_POLICY_NO_LISTS,
        "nothing for this profile to apply — subscribe to one with `warden blocklist add`"
    );
    assert!(
        LIST_POLICY_NO_LISTS.contains("warden blocklist add"),
        "the empty state is the one place a repair costs nothing to name"
    );
}

/// The retirement note must name the verb that works, and must not name
/// the one that refuses.
#[test]
fn plp_s4a_frozen_tags_inert_points_at_a_verb_that_exists() {
    assert_eq!(
        PROFILE_TAGS_INERT,
        "inert — decides nothing; set the direction with `warden profile list-policy set`"
    );
    assert!(
        !PROFILE_TAGS_INERT.contains("warden profile tag"),
        "the retired verb refuses; naming it here is an unsatisfiable instruction"
    );
}
