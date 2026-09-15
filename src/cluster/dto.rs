//! Wire DTOs for the `/api/cluster/*` endpoints. Plain serde JSON
//! over the existing axum server.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactIdentity {
    pub primary_lineage: String,
    pub policy_epoch: u64,
    pub artifact_hash: String,
    pub config_revision: String,
    pub operator_policy_hash: String,
}

impl ArtifactIdentity {
    pub(crate) fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.policy_epoch > 0
                && [
                    &self.primary_lineage,
                    &self.artifact_hash,
                    &self.config_revision,
                    &self.operator_policy_hash,
                ]
                .into_iter()
                .all(|value| super::manifest::is_hash(value)),
            "ArtifactInvalidIdentity"
        );
        Ok(())
    }
}

impl From<&super::manifest::Manifest> for ArtifactIdentity {
    fn from(manifest: &super::manifest::Manifest) -> Self {
        Self {
            primary_lineage: manifest.primary_lineage.clone(),
            policy_epoch: manifest.policy_epoch,
            artifact_hash: manifest.artifact_hash.clone(),
            config_revision: manifest.config_revision.clone(),
            operator_policy_hash: manifest.operator_policy_hash.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ActiveArtifactAck {
    pub artifact: ArtifactIdentity,
    pub local_config_revision: String,
    pub daemon_instance_id: String,
    pub resolver_generation: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HeartbeatV2Request {
    pub artifact_format: u32,
    pub schema_version: u32,
    pub operator_rule_grammar: String,
    pub compiled_cost_version: u32,
    pub node_name: Option<String>,
    pub stats: ClusterStats,
    pub persisted: Option<ArtifactIdentity>,
    pub active: Option<ActiveArtifactAck>,
    #[serde(default)]
    pub persisted_corpus: Option<String>,
    #[serde(default)]
    pub active_corpus: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HeartbeatV2Response {
    pub desired: ArtifactIdentity,
    pub active_acknowledged: bool,
    #[serde(default)]
    pub desired_corpus: Option<String>,
    #[serde(default)]
    pub corpus_acknowledged: bool,
}

/// Optional Nodes management upgrade sent over an existing authenticated
/// replication connection.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ManagementCapabilityRequest {
    pub offer: super::node_control::ManagementOffer,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ManagementCapabilityResponse {
    pub grant: Option<super::node_control::ManagementGrant>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ManifestResponse {
    pub manifest: super::manifest::Manifest,
    pub available_until: u64,
}

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
