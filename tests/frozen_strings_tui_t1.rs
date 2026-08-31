//! tui-wave1 `profiles-summary` — frozen-strings gate for the Profiles
//! detail-pane "What it blocks" summary.
//!
//! Pins the operator-facing literals byte-for-byte. Any drift in the TUI
//! copy must land in the same commit as the matching docs update,
//! otherwise this gate fails at `cargo test`.
//!
//! The consts live in the private `tabs::profiles` module; `src/tui/mod.rs`
//! re-exports them (same selective idiom as `SUBNET_SUGGESTED_TAG`) so this
//! integration test reaches them without promoting the whole `tabs` surface.

use purge_warden::tui::{
    PROFILE_BLOCKS_ALL_QUERIES, PROFILE_BLOCKS_LOADING, PROFILE_BLOCKS_NONE,
    PROFILE_BLOCKS_PARTIAL, PROFILE_CUSTOM_LISTS_NONE, PROFILE_LABEL_ALSO,
    PROFILE_LABEL_BLOCKLISTS, PROFILE_LABEL_CUSTOM_LISTS, PROFILE_LABEL_WHAT_IT_BLOCKS,
};

#[test]
fn what_it_blocks_section_labels_byte_for_byte() {
    assert_eq!(PROFILE_LABEL_WHAT_IT_BLOCKS, "What it blocks");
    assert_eq!(PROFILE_LABEL_BLOCKLISTS, "Blocklists");
    assert_eq!(PROFILE_LABEL_CUSTOM_LISTS, "Custom lists");
    assert_eq!(PROFILE_LABEL_ALSO, "Also");
}

#[test]
fn a_profile_mounting_no_custom_list_says_so_without_sounding_broken() {
    // Most profiles mount none. The wording has to read as a fact, not as a
    // fault — the row is drawn in the secondary colour for the same reason.
    assert_eq!(PROFILE_CUSTOM_LISTS_NONE, "none mounted");
}

#[test]
fn the_two_list_labels_do_not_collide() {
    // They sit on adjacent rows in the same section. A rename that made one a
    // prefix of the other would leave a substring assertion elsewhere passing
    // against the wrong row.
    assert_ne!(PROFILE_LABEL_CUSTOM_LISTS, PROFILE_LABEL_BLOCKLISTS);
    assert!(!PROFILE_LABEL_CUSTOM_LISTS.contains(PROFILE_LABEL_BLOCKLISTS));
    assert!(!PROFILE_LABEL_BLOCKLISTS.contains(PROFILE_LABEL_CUSTOM_LISTS));
}

#[test]
fn block_all_supersedes_lists_sentence() {
    assert_eq!(
        PROFILE_BLOCKS_ALL_QUERIES, "(all queries blocked)",
        "block_all=true must render this exact sentence on the Blocklists line; \
         update DOCUMENTATION.md if this changes"
    );
}

/// **Re-pinned in `plp-s5f`, and the old value is the point.** This read
/// "…(add tags in the Tags tab)" until then: a rendered string —
/// `blocklists_value` returns it whenever a profile resolves to zero lists
/// — sending the operator to a tab `plp-s5d` had deleted, via a verb that
/// already refused. The byte-pin held it in place perfectly, which is what
/// a byte-pin is for; what it cannot do is notice that the sentence stopped
/// being true.
#[test]
fn no_effective_lists_sentence() {
    assert_eq!(
        PROFILE_BLOCKS_NONE,
        "none — this profile blocks nothing via lists (set one to Block in this profile's editor)",
        "no-effective-lists must render this exact sentence; \
         update DOCUMENTATION.md if this changes"
    );
    // em dash (U+2014), not a hyphen — guards a silent glyph swap.
    assert!(PROFILE_BLOCKS_NONE.contains('\u{2014}'));
    // The remedy must name a surface that EXISTS. The retired model's two
    // dead ends are named here so re-introducing either fails loudly
    // instead of being re-frozen by whoever next runs this test.
    assert!(
        !PROFILE_BLOCKS_NONE.contains("Tags tab"),
        "the Tags tab was deleted in plp-s5d: {PROFILE_BLOCKS_NONE}"
    );
    assert!(
        !PROFILE_BLOCKS_NONE.to_ascii_lowercase().contains("tag"),
        "tags decide nothing since plp-s3 — a remedy naming them is a dead \
         end shown to an operator mid-task: {PROFILE_BLOCKS_NONE}"
    );
}

#[test]
fn count_state_suffixes_byte_for_byte() {
    // Not in the brief's required set but cheap to pin: the two count-line
    // state strings drive the loading vs partial distinction.
    assert_eq!(PROFILE_BLOCKS_LOADING, "(loading…)");
    assert_eq!(PROFILE_BLOCKS_PARTIAL, "(partial)");
    // horizontal ellipsis (U+2026), not three ASCII dots.
    assert!(PROFILE_BLOCKS_LOADING.contains('\u{2026}'));
}
