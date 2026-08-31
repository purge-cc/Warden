//! qlog-scan (wave2) — frozen-strings trip-wire for the Query Log tab
//! scannability redesign.
//!
//! WHAT THIS FILE CAN AND CANNOT PIN. The redesign is structural, not
//! copy: the RESULT cell is re-coloured (tri-colour severity), the DATE
//! column is folded into a relative TIME column, and the Filters card
//! collapses to a one-line strip — but it introduces essentially no new
//! *literal* label text (the strip reuses the identical control labels;
//! the time/colour logic is behaviour, not strings). The one public
//! string the new colour logic hinges on is the CNAME-chain block badge,
//! which the tri-colour rule keeps RED in the RESULT cell — pinned below.
//!
//! The new structural + behavioural contract (six headers, no DATE; the
//! `MM-DD HH:MM` fold; the severity buckets) is frozen as UNIT tests
//! inside `src/tui/tabs/query_log.rs`
//! (`format_log_time_*`, `result_severity_*`,
//! `header_columns_dropped_date_and_kept_time`) rather than here: those
//! items are `pub(crate)` behind a private `mod tabs`, so an integration
//! test cannot reach them, and the wave2 file-ownership fence forbids
//! adding a `pub use` re-export to `src/tui/mod.rs`. See REPORT.md.
//!
//! When one of these strings MUST change, update the literal here in the
//! same commit — byte-for-byte equality has no escape hatch.

use purge_warden::tui::{
    CNAME_CHAIN_BLOCK_BADGE, QUERY_NOT_ACTIONABLE_LOCAL, QUERY_NOT_ACTIONABLE_REFUSED,
    QUERY_NOT_ACTIONABLE_UNKNOWN,
};

// ── Tri-colour RESULT: the CNAME-chain block badge stays red ──────────
// qlog-scan keeps CNAME-chain rows in the Blocked (red) bucket and
// renders this badge in the RESULT cell instead of "BLOCKED". If the
// badge text drifts, the audit view silently reshapes — pin it.
#[test]
fn cname_chain_block_badge_byte_for_byte() {
    assert_eq!(CNAME_CHAIN_BLOCK_BADGE, "[CNAME]");
}

// ── Regression net: Enter-on-neutral-row footer messages ─────────────
// qlog-scan does not touch the Enter→scope-modal path, but the RESULT
// re-colour sits right beside these status strings; re-net them (the
// s47→s43 pattern) so a careless edit in this area cannot drop them
// unprotected.
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
