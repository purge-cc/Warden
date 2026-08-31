//! §4.8 §2/2 T6 — frozen-strings test for the ECS-injection audit log.
//!
//! Pins the operator-visible field names + identifiers carried in the
//! `tracing::debug!(target = "audit", event = "ecs_inject", ...)`
//! emit at the cache-miss upstream call site
//! (`src/dns/handler.rs` ~line 1011). A drift here silently breaks
//! every `RUST_LOG=audit=debug | jq .event=="ecs_inject"`-style
//! pipeline an operator might have wired up.
//!
//! Sibling test `tests/frozen_strings_s48_ecs.rs` already pins the
//! `[upstream.ecs]` validator strings, and `frozen_strings_s48_ecs_profile.rs`
//! pins the `[profile.X.ecs]` validator strings. This file pins the
//! third surface — the per-query tracing emit — so all three
//! observability layers stay frozen across refactors.

use purge_warden::dns::audit_ecs::{ANONYMOUS_PROFILE_TAG, AUDIT_ECS_INJECT_EVENT, AUDIT_TARGET};

#[test]
fn audit_target_is_frozen() {
    assert_eq!(AUDIT_TARGET, "audit");
}

#[test]
fn audit_ecs_inject_event_is_frozen() {
    assert_eq!(AUDIT_ECS_INJECT_EVENT, "ecs_inject");
}

#[test]
fn anonymous_profile_tag_is_frozen() {
    assert_eq!(ANONYMOUS_PROFILE_TAG, "<anonymous>");
}
