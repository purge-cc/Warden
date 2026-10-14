//! # purge-warden — internal library target
//!
//! This library exists as an implementation detail of the `warden` binary
//! (and the `tests/` integration-test layout, which is why the modules
//! below are `pub`). It is **not** a public API: no stability guarantees,
//! no semver discipline on any item, and module paths may change in any
//! release without notice. Do not depend on `purge_warden` as a crate —
//! consume the `warden` binary instead. `publish = false` in Cargo.toml
//! enforces the same intent registry-side.

pub mod api;
pub mod auth;
pub mod cli;
/// Cluster replication: primary publication, node membership and secondary
/// pull. Feature-gated (`cluster`), on by default; `--no-default-features`
/// builds without it. The `[cluster]` config section is parsed in every
/// build (`config::schema::cluster`).
#[cfg(feature = "cluster")]
pub mod cluster;
pub mod common;
pub mod config;
pub mod dns;
/// DNSSEC validation (RFC 4033-4035). Feature-gated (`dnssec`, default OFF) —
/// the ring-backed crypto primitives add binary size, so the default and
/// Raspberry Pi builds exclude it.
#[cfg(feature = "dnssec")]
pub mod dnssec;
pub mod filter;
pub mod ipc;
pub mod lists;
pub mod operator_rules;
pub mod oui;
pub(crate) mod private_store;
pub mod profiles;
pub mod resource_budget;
pub mod security;
pub mod tracking;
pub mod tui;
pub mod upstream;
