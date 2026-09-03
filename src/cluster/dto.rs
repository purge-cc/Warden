//! Wire DTOs for the `/api/cluster/*` endpoints. Plain serde JSON
//! over the existing axum server.

use serde::{Deserialize, Serialize};

use crate::config::schema::ClusterRole;

/// Liveness/stat counters exchanged on every heartbeat. A compact,
/// node-agnostic snapshot; the dashboard SHARE math is built from
/// these.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClusterStats {
    pub total_queries: u64,
    pub total_blocked: u64,
    pub cache_hits: u64,
}

/// `POST /api/cluster/heartbeat` request body — the secondary's own view. The
/// primary parses this but does not yet retain the peer view; `stats` is
/// dropped after deserialisation.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HeartbeatRequest {
    #[serde(default)]
    pub config_generation: u64,
    #[serde(default)]
    pub stats: ClusterStats,
    /// Optional human-readable node label, retained in the primary's
    /// roster as the peer's display name. `#[serde(default)]` keeps an older
    /// secondary's heartbeat (no field) deserialising cleanly.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_name: Option<String>,
}

/// `POST /api/cluster/heartbeat` response — the primary's authoritative view.
/// The secondary compares `config_hash` against its last-applied value
/// and fetches the bundle only on a mismatch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatResponse {
    pub config_generation: u64,
    pub config_hash: String,
    pub stats: ClusterStats,
    // `role`/`priority` are echoed to any authenticated peer. Harmless today
    // (display only), but `priority` becomes security-relevant once failover
    // logic uses it for split-brain tiebreak — revisit this disclosure then.
    pub role: ClusterRole,
    pub priority: u32,
}

/// `GET /api/cluster/status` response — this node's role / generation / hash
/// / stats. `peers` is always empty for now (no peer view exists until
/// heartbeat retention is implemented).
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
/// stable wire contract, ahead of retained heartbeats populating it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerView {
    pub addr: String,
    pub role: ClusterRole,
    pub config_generation: u64,
    pub stats: ClusterStats,
}
