//! §4.5 P2 frozen-string regression pins for the CNAME chain block
//! audit log + TUI badge.
//!
//! These two strings are the wire-format contract between the daemon
//! and the operator's tooling:
//!
//! - The audit log action label `"cname_block"` is emitted by
//!   [`AuditEvent::CnameBlock`] (via `serde(rename_all = "snake_case")`)
//!   and by [`AuditEvent::as_tag`]. Any tail-parser, log-shipper, or
//!   incident-response query that filters by action will silently miss
//!   chain-block events if the label drifts.
//! - The TUI badge `"[CNAME]"` is rendered in the Query Log RESULT
//!   column when an entry's `cname_chain_via` is populated. The width
//!   (7 visible chars, 8 grapheme cells with the brackets) was chosen
//!   to fit the existing 8-char RESULT column without layout changes.
//!
//! Sibling test: `tests/frozen_strings_s45_p1.rs` pins the five
//! [`BlockSource::label`] strings that this audit record's
//! `cname_source` field carries. Together they form the full §4.5
//! observability schema. A future sprint that touches either layer
//! must update both files in the same commit.
//!
//! §4.39 extended this file with `rewrote_from` pins: a CNAME block on
//! a domain the resolver rewrote (§4.12) must surface BOTH the
//! effective (rewritten) `domain` and the original `rewrote_from` in
//! the audit record, so the journal matches the wire packet.

use purge_warden::config::audit::{AuditEvent, AuditRecord, AuditResult};
use purge_warden::tui::CNAME_CHAIN_BLOCK_BADGE;

#[test]
fn cname_block_event_tag_is_frozen() {
    assert_eq!(AuditEvent::CnameBlock.as_tag(), "cname_block");
}

#[test]
fn cname_block_action_label_is_frozen() {
    let record = AuditRecord::new(AuditEvent::CnameBlock, AuditResult::Ok)
        .with_action("cname_block")
        .with_domain("apex.example.com")
        .with_cname_target("offending.tracker.example")
        .with_cname_source("rule");
    let json = serde_json::to_string(&record).expect("AuditRecord serialise");
    // The action field is the operator-visible verb tag — must equal
    // `"cname_block"` byte-for-byte. A drift here would silently break
    // every `warden audit tail | jq '.action == "cname_block"'`-style
    // pipeline.
    assert!(
        json.contains("\"action\":\"cname_block\""),
        "expected action=cname_block in serialised audit record, got: {json}"
    );
    // The event tag must also serialise to `"cname_block"` — same
    // string, distinct field. Both are consumed by audit log readers.
    assert!(
        json.contains("\"event\":\"cname_block\""),
        "expected event=cname_block in serialised audit record, got: {json}"
    );
}

#[test]
fn cname_chain_via_field_present_when_set() {
    let record = AuditRecord::new(AuditEvent::CnameBlock, AuditResult::Ok)
        .with_cname_target("offending.tracker.example")
        .with_cname_source("admin_block");
    let json = serde_json::to_string(&record).expect("AuditRecord serialise");
    assert!(
        json.contains("\"cname_target\":\"offending.tracker.example\""),
        "cname_target field must surface verbatim, got: {json}"
    );
    assert!(
        json.contains("\"cname_source\":\"admin_block\""),
        "cname_source field must surface verbatim, got: {json}"
    );
}

#[test]
fn cname_chain_via_fields_skipped_when_unset() {
    // Pre-S4.5-P2 lifecycle records (Boot/Reload/Shutdown/Restore) and
    // CLI-mutation records that do not touch CNAME chains must keep
    // their pre-S4.5-P2 wire shape — no spurious `cname_target: null` /
    // `cname_source: null` fields appended. The
    // `#[serde(skip_serializing_if = "Option::is_none")]` guard on
    // both fields enforces this.
    let record = AuditRecord::new(AuditEvent::Reload, AuditResult::Ok);
    let json = serde_json::to_string(&record).expect("AuditRecord serialise");
    assert!(
        !json.contains("cname_target"),
        "lifecycle records must not surface cname_target, got: {json}"
    );
    assert!(
        !json.contains("cname_source"),
        "lifecycle records must not surface cname_source, got: {json}"
    );
}

#[test]
fn cname_block_rewrote_from_present_when_set() {
    // §4.39 — when a §4.12 per-profile rewrite fired on the query, the
    // CNAME-block audit record must carry BOTH the effective
    // (rewritten) name in `domain` AND the original client-typed name
    // in `rewrote_from`. This is the audit-side mirror of the §4.29 h5
    // wire-packet fix: the journal must not silently diverge from what
    // the client actually asked for.
    let record = AuditRecord::new(AuditEvent::CnameBlock, AuditResult::Ok)
        .with_action("cname_block")
        .with_domain("api.new-corp.example") // effective (rewritten) name
        .with_cname_target("offending.tracker.example")
        .with_cname_source("rule")
        .with_rewrote_from(Some("api.old-corp.example")); // original qname
    let json = serde_json::to_string(&record).expect("AuditRecord serialise");
    assert!(
        json.contains("\"rewrote_from\":\"api.old-corp.example\""),
        "rewrote_from must surface the original qname verbatim, got: {json}"
    );
    assert!(
        json.contains("\"domain\":\"api.new-corp.example\""),
        "domain must still carry the effective (rewritten) name, got: {json}"
    );
}

#[test]
fn cname_block_rewrote_from_skipped_when_unset() {
    // The common case: no rewrite fired. `with_rewrote_from(None)` is a
    // no-op and the `#[serde(skip_serializing_if)]` guard keeps the
    // field off the wire — pre-§4.39 audit readers see no new key.
    let record = AuditRecord::new(AuditEvent::CnameBlock, AuditResult::Ok)
        .with_action("cname_block")
        .with_domain("plain.example")
        .with_cname_target("offending.tracker.example")
        .with_cname_source("list")
        .with_rewrote_from(None);
    let json = serde_json::to_string(&record).expect("AuditRecord serialise");
    assert!(
        !json.contains("rewrote_from"),
        "records with no rewrite must not surface rewrote_from, got: {json}"
    );
}

#[test]
fn cname_chain_block_tui_badge_is_frozen() {
    // The badge is what an operator sees in the Query Log RESULT
    // column when a row's `cname_chain_via` is populated. Width is
    // load-bearing: column is 8 chars, badge is 7. Any rename to a
    // 9+ char string would silently overflow / clip.
    assert_eq!(CNAME_CHAIN_BLOCK_BADGE, "[CNAME]");
}
