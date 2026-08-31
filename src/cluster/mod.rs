//! §4.11 cluster sync — primary serve side (§4.11-2) + secondary apply side
//! (§4.11-3).
//!
//! Feature-gated (`cluster`, default OFF). The `[cluster]` CONFIG section is
//! parsed unconditionally (§4.11-1, [`crate::config::schema::cluster`]); this
//! module is the LOGIC that activates per role: a **primary**
//! (`cluster.enabled && role == primary`) serves policy over
//! [`crate::cluster::routes`]; a **secondary** runs the [`crate::cluster::poll`] loop that pulls +
//! [`crate::cluster::apply`]s them, reading its plaintext token via [`crate::cluster::secret`]. A feature-less binary
//! with `cluster.enabled` bails at startup ([`crate::cli::commands::start`]).
//! Mirrors the doq/dnssec gating so the default + Raspberry Pi binaries stay
//! byte-for-byte unchanged.
//!
//! See `_docs/features/cluster_sync.md` (CS1–CS10, §3 partition, §4 bundle,
//! §5 sync model).

pub mod apply;
pub mod dto;
pub mod observe;
pub mod pinned;
pub mod policy;
pub mod poll;
pub mod routes;
pub mod secret;
pub mod state;

pub use observe::{ClusterObserve, RosterRow, SyncStatus};
pub use state::ClusterState;
