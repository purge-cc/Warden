//! Sprint 51 T3 — Subnets master/detail TUI frozen-strings test.
//!
//! Pins the operator-facing marker that distinguishes auto-discovered
//! candidate rows from configured subnets in the master list. The
//! tag is a single locked literal; any drift in the TUI copy here
//! must land in the same commit as a TUI.md / DOCUMENTATION.md update,
//! otherwise this gate fails at `cargo test`.
//!
//! The marker reaches into the test via the `tui` module's selective
//! re-export — see the matching `pub use tabs::subnets::SUBNET_SUGGESTED_TAG`
//! in `src/tui/mod.rs`. Keeps the rest of the private `tabs::subnets`
//! surface unexposed.

use purge_warden::tui::SUBNET_SUGGESTED_TAG;

#[test]
fn s51_subnet_suggested_tag_byte_for_byte() {
    assert_eq!(
        SUBNET_SUGGESTED_TAG, " [suggested]",
        "auto-discovery suggestion marker must stay byte-for-byte; \
         update TUI.md + DOCUMENTATION.md if this changes"
    );
    // Length sanity — guards against a leading-space drop or a
    // trailing-newline injection without changing the visible glyphs.
    assert_eq!(
        SUBNET_SUGGESTED_TAG.len(),
        12,
        "marker is exactly 12 bytes (leading space + bracketed word)"
    );
    assert!(
        SUBNET_SUGGESTED_TAG.starts_with(' '),
        "marker starts with a leading space so it concatenates cleanly \
         after the canonical CIDR string in the master list"
    );
}
