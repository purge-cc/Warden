//! rev-2606 §06 (lists refresh integrity) — frozen-strings test.
//!
//! Pins byte-for-byte the operator-facing strings coined by the
//! retention-guard fix (`manager-01`) and the supply-chain delta canary
//! (`status-01`). These surface in `warden blocklist show` (`failed: …`),
//! the TUI Lists tab, and the daemon's `audit` tracing target, so a silent
//! drift would change what an operator reads when a list is refused.
//!
//! When one of these strings MUST change for legitimate reasons (UX
//! re-wording, typo fix), update the literal here AND the corresponding
//! row in `CONFIG_GUIDE.md` + `CONFIG_GUIDE.public.md` in the same commit.

use purge_warden::lists::status::{
    format_blocklist_shrink_refused, BLOCKLIST_DELTA_WARN, BLOCKLIST_SHRINK_REFUSED,
};

#[test]
fn blocklist_delta_warn_const_is_frozen() {
    assert_eq!(
        BLOCKLIST_DELTA_WARN,
        "blocklist size changed sharply versus the previous refresh"
    );
}

#[test]
fn blocklist_shrink_refused_template_is_frozen() {
    assert_eq!(
        BLOCKLIST_SHRINK_REFUSED,
        "refresh refused: list shrank by {drop}% to {got} domains (was {kept}); \
         keeping the previous list — run `warden lists forget <source>` to accept"
    );
}

#[test]
fn blocklist_shrink_refused_format_helper_substitutes() {
    let got = format_blocklist_shrink_refused(100, 0, 12345);
    assert_eq!(
        got,
        "refresh refused: list shrank by 100% to 0 domains (was 12345); \
         keeping the previous list — run `warden lists forget <source>` to accept"
    );
    // No placeholder survives substitution.
    assert!(!got.contains("{drop}"));
    assert!(!got.contains("{got}"));
    assert!(!got.contains("{kept}"));
}
