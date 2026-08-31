//! Cross-file byte-pins for the load-time diagnostics that tell an operator
//! **a list or a profile is filtering nothing**.
//!
//! # What this file used to be, and why it is not that any more
//!
//! It was `tests/frozen_strings_lc2_engine.rs`, pinning the four
//! `lists_categories_v2` §5.4 reload diagnostics — all four keyed on the
//! tag model. `plp-s3` cut tags out of the filtering decision and `plp-s5a`
//! removed the field, so all four became strings the product cannot emit.
//! A byte-pin on an unemittable string is green by construction: it protects
//! nothing and tells the next reader the diagnostic still exists.
//!
//! The contract did not evaporate, it **moved**, so the pins moved with it
//! rather than being deleted. What each retired row became:
//!
//! | withdrawn (§5.4) | replacement |
//! |---|---|
//! | `DEVICE_UNFILTERED_WITH_TAGS` (ERROR) | **none** — it priced a contradiction (`unfiltered = true` *and* tags) that the schema can no longer express |
//! | `DEVICE_NOT_FILTERED_NO_TAGS` | [`PROFILE_FILTERS_NO_LISTS`], pinned below |
//! | `PROFILE_CONTRIBUTES_NO_TAGS` | [`PROFILE_FILTERS_NO_LISTS`], pinned below |
//! | `ALLOW_LIST_NO_TAGS_NO_EFFECT` | premise **inverted** — an untagged allow-list is now maximally live, so [`ALLOW_DIRECTION_LIST_STANDING_EXPOSURE`] is the honest signal |
//! | `UNCATEGORIZED_MISSING_AT_RELOAD` (ERROR) | **none** — the `uncategorized` sentinel is retired; there is no registry left to miss it |
//!
//! # Why these three and not two
//!
//! [`BASE_IGNORE_LIST_IS_INERT`] is pinned here too although no §5.4 row
//! withdrew into it. It is the **only surviving** `InertListReason`, so it
//! is now the single string standing between an operator and the
//! 2026-05-07 failure (a list that installs, refreshes, and filters nothing,
//! silently). Until `plp-s5f` it was checked only by
//! `.contains("filters nothing")` in `tests/plp_s3b_rename_and_r7.rs` — a
//! substring survives any reword of the rest of the sentence, including the
//! qualifier that makes the claim true.

use purge_warden::config::schema::validator::{
    format_allow_direction_list_standing_exposure, format_base_ignore_list_is_inert,
    format_profile_filters_no_lists, ALLOW_DIRECTION_LIST_STANDING_EXPOSURE,
    BASE_IGNORE_LIST_IS_INERT, PROFILE_FILTERS_NO_LISTS,
};

/// Replaces §5.4 rows 1 and 2. Asked one hop earlier than they were: a
/// device inherits its profile's policy, so the profile is where the answer
/// is, and asking per device repeated one profile's answer once per member.
#[test]
fn profile_filters_no_lists_byte_pinned() {
    assert_eq!(
        PROFILE_FILTERS_NO_LISTS,
        "profile \"{id}\" filters on no list — every device resolving to it is unfiltered by lists"
    );
}

#[test]
fn profile_filters_no_lists_format_substitutes_id() {
    let s = format_profile_filters_no_lists("kids");
    // Pin the substitution AND the absence of a leftover placeholder — a
    // message that reaches the operator still carrying `{id}` names nothing.
    assert_eq!(
        s,
        "profile \"kids\" filters on no list — every device resolving to it is unfiltered by lists"
    );
    assert!(!s.contains("{id}"), "placeholder survived: {s}");
}

/// Replaces §5.4 row 3 with the **opposite** claim, which is why the old
/// text was not transferred. `ALLOW_LIST_NO_TAGS_NO_EFFECT` said an
/// untagged allow-list "has no effect"; under the base/override model every
/// profile that does not override it inherits it, so it permits its domains
/// everywhere. The exposure is standing, so the WARN fires at every load.
#[test]
fn allow_direction_list_standing_exposure_byte_pinned() {
    assert_eq!(
        ALLOW_DIRECTION_LIST_STANDING_EXPOSURE,
        "allow-list \"{id}\" is allow-direction — every profile that does not override it permits every domain this list carries, at every refresh"
    );
}

#[test]
fn allow_direction_list_standing_exposure_format_substitutes_id() {
    let s = format_allow_direction_list_standing_exposure("mycompany");
    assert!(
        s.starts_with("allow-list \"mycompany\" is allow-direction"),
        "{s}"
    );
    assert!(!s.contains("{id}"), "placeholder survived: {s}");
}

/// The one `InertListReason` with a producer. Its **qualifier** is the load-
/// bearing half: `inert_blocklists` deliberately does not report a list that
/// some profile overrides away from `ignore`, so the sentence has to say
/// "in any profile that does not override it" for `warden status`,
/// `warden config lint` and the journal to all be true at once.
#[test]
fn base_ignore_list_is_inert_byte_pinned() {
    assert_eq!(
        BASE_IGNORE_LIST_IS_INERT,
        "list \"{id}\" has base = \"ignore\" — it is downloaded and refreshed but filters nothing in any profile that does not override it"
    );
}

/// Guards the qualifier specifically, so a reword that keeps the alarming
/// half ("filters nothing") and drops the scoping half fails here with a
/// message naming what went missing — not merely as a byte diff.
#[test]
fn base_ignore_list_is_inert_keeps_its_override_qualifier() {
    let s = format_base_ignore_list_is_inert("privacy-ads");
    assert!(
        s.contains("filters nothing"),
        "the claim an operator acts on went missing: {s}"
    );
    assert!(
        s.contains("does not override it"),
        "the qualifier that makes the claim TRUE went missing — without it the \
         WARN says a list filters nothing while some profile is filtering with \
         it: {s}"
    );
    assert!(!s.contains("{id}"), "placeholder survived: {s}");
}
