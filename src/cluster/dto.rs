//! Wire DTOs for the `/api/cluster/*` endpoints (CS6 / §4.1). Plain serde JSON
//! over the existing axum server.

use serde::{Deserialize, Serialize};

use crate::config::schema::ClusterRole;

/// Liveness/stat counters exchanged on every heartbeat (CS6). A compact,
/// node-agnostic snapshot; the dashboard SHARE math (§4.11-4) is built from
/// these.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClusterStats {
    pub total_queries: u64,
    pub total_blocked: u64,
    pub cache_hits: u64,
}

/// `POST /api/cluster/heartbeat` request body — the secondary's own view. In
/// §4.11-2 the primary parses this (for the CS6 contract) but does not yet
/// retain the peer view; `stats` is dropped after deserialisation.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HeartbeatRequest {
    #[serde(default)]
    pub config_generation: u64,
    #[serde(default)]
    pub stats: ClusterStats,
    /// §4.11-4 — optional human-readable node label, retained in the primary's
    /// roster as the peer's display name. `#[serde(default)]` keeps a pre-4.11-4
    /// secondary's heartbeat (no field) deserialising cleanly.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_name: Option<String>,
}

/// `POST /api/cluster/heartbeat` response — the primary's authoritative view
/// (CS6). The secondary compares `config_hash` against its last-applied value
/// and fetches the bundle only on a mismatch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatResponse {
    pub config_generation: u64,
    pub config_hash: String,
    pub stats: ClusterStats,
    // roundup-01 (rev-2606): `role`/`priority` are echoed to any authenticated
    // peer. Harmless today (display only), but `priority` becomes security-
    // relevant once Phase-2 failover uses it for split-brain tiebreak — revisit
    // this disclosure then.
    pub role: ClusterRole,
    pub priority: u32,
}

/// `GET /api/cluster/status` response — this node's role / generation / hash
/// / stats. `peers` is always empty in §4.11-2 (no peer view exists until the
/// secondary/heartbeat-retention work in §4.11-3+).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterStatusResponse {
    pub role: ClusterRole,
    pub priority: u32,
    pub config_generation: u64,
    pub config_hash: String,
    pub stats: ClusterStats,
    pub peers: Vec<PeerView>,
}

/// A peer's last-known view, as seen by this node. Shape settled now for a
/// stable wire contract; populated from retained heartbeats in §4.11-3+.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerView {
    pub addr: String,
    pub role: ClusterRole,
    pub config_generation: u64,
    pub stats: ClusterStats,
}
