//! §4.8 §2/2 (T6) — frozen string constants for the ECS injection audit log.
//!
//! Lives in its own module so the constants are addressable from both
//! the emit site (`src/dns/handler.rs`) and the regression test
//! (`tests/frozen_strings_s48_audit.rs`). Touching any of these values
//! is a wire-format break for operators piping `RUST_LOG=audit=debug`
//! through log aggregators that filter on `event=` or `target=`.
//!
//! The audit emit is a structured `tracing::debug!` record, not a
//! [`crate::config::audit::AuditRecord`] JSON line. The two coexist:
//! `AuditRecord` tracks long-lived config-mutation lifecycle events
//! (boot, reload, CLI mutation, CNAME chain block); this module's
//! tracing record tracks high-volume per-query telemetry (one emit per
//! upstream RTT when ECS is active). Picking the right channel keeps
//! the audit JSON log free of per-query noise while still giving
//! operators a route to see ECS activity when they want it.

/// Tracing `target` for the ECS-injection log line. Matches the
/// existing audit-channel convention used by other `tracing::*` emits
/// elsewhere in the codebase that the operator filters on (`RUST_LOG=
/// audit=...`).
pub const AUDIT_TARGET: &str = "audit";

/// Event identifier for the ECS-injection record. Surfaces as the
/// `event=` field in the emitted tracing line.
pub const AUDIT_ECS_INJECT_EVENT: &str = "ecs_inject";

/// Placeholder profile-id when no profile resolved (level-5 REFUSED
/// path emits ECS only when the global default profile catches the
/// query — but for callers that hit the audit emit without a profile
/// resolution, we still want a stable token rather than an empty
/// string that log shippers might filter out).
pub const ANONYMOUS_PROFILE_TAG: &str = "<anonymous>";
