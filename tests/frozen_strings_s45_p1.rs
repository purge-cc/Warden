//! §4.5 P1 frozen-string regression pins for [`BlockSource::label`].
//!
//! These labels feed Sprint 2/2 audit log records and the TUI Query Log
//! badge. A silent rename of any label in `src/filter/cname.rs` would
//! rewrite the downstream log schema with no compile-time signal — so
//! they live behind these tests until the schema is contractualised.

use compact_str::CompactString;
use purge_warden::filter::cname::BlockSource;

#[test]
fn list_label_is_frozen() {
    assert_eq!(BlockSource::List(0).label(), "list");
    assert_eq!(BlockSource::List(63).label(), "list");
}

#[test]
fn rule_label_is_frozen() {
    assert_eq!(
        BlockSource::Rule(CompactString::new("tracker.com")).label(),
        "rule"
    );
}

#[test]
fn admin_block_label_is_frozen() {
    assert_eq!(BlockSource::AdminBlock.label(), "admin_block");
}

#[test]
fn cname_loop_label_is_frozen() {
    assert_eq!(BlockSource::CnameLoop.label(), "cname_loop");
}

#[test]
fn cname_depth_exceeded_label_is_frozen() {
    assert_eq!(
        BlockSource::CnameDepthExceeded.label(),
        "cname_depth_exceeded"
    );
}
