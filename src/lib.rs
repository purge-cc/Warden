//! # purge-warden — internal library target
//!
//! This library exists as an implementation detail of the `warden` binary
//! (and the `tests/` integration-test layout, which is why the modules
//! below are `pub`). It is **not** a public API: no stability guarantees,
//! no semver discipline on any item, and module paths may change in any
//! release without notice. Do not depend on `purge_warden` as a crate —
//! consume the `warden` binary instead. `publish = false` in Cargo.toml
//! enforces the same intent registry-side. (rev-2606 lib-01)

pub mod api;
pub mod auth;
pub mod cli;
/// §4.11 primary/secondary cluster replication serve-side. Feature-gated
/// (`cluster`, default OFF) so a node that does not replicate compiles none of
/// it. The feature carries no extra dependencies since cluster sync S1 removed
/// the domain-map transfer (`postcard` + `zstd` went with it); what it still
/// costs is the module's own code. The `[cluster]` CONFIG section is parsed
/// unconditionally (`config::schema::cluster`); this module is the serve LOGIC
/// (§4.11-2) that activates when `cluster.enabled && role == primary`.
#[cfg(feature = "cluster")]
pub mod cluster;
pub mod common;
pub mod config;
pub mod dns;
/// DNSSEC validation (RFC 4033-4035). Feature-gated (`dnssec`, default OFF) —
/// the ring-backed crypto primitives add binary size, so the default and
/// Raspberry Pi builds exclude it. §4.10-1 ships the trust anchor + DNSKEY/DS
/// parsing foundation; validation lands in later sprints.
#[cfg(feature = "dnssec")]
pub mod dnssec;
pub mod filter;
pub mod ipc;
pub mod lists;
pub mod oui;
pub mod profiles;
pub mod resource_budget;
pub mod security;
pub mod tracking;
pub mod tui;
pub mod upstream;
