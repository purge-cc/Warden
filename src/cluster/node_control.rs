//! Durable control plane for target-issued node association and management.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{ensure, Context};
use async_trait::async_trait;
use axum::body::Body;
use axum::extract::{Path as RoutePath, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use super::dto::ArtifactIdentity;
use super::lifecycle::{LifecycleRequest, LifecycleStatus, NodeRole};
use super::membership::SecretString;
use super::store::PrivateStore;
use crate::auth::token::{generate_token, hash_token, verify_token};
use crate::config::write_lock::{acquire_for_migration, MigrationWriteLock};

const STORE: &str = ".warden-node-control";
const STATE: &str = "state.json";
const MAX_STATE_BYTES: u64 = 4 * 1024 * 1024;
const MAX_PEERS: usize = 64;
const MAX_OPERATIONS: usize = 256;
const FORMAT: u32 = 1;
const PROTOCOL_VERSION: u32 = 2;
const CONTROL_PORT: u16 = 8053;
const PREVIEW_TTL: u64 = 15 * 60;
/// PrepareAdd transfers and validates an exact policy/corpus snapshot before it
/// can return a review. It shares the local Nodes IPC mutation budget, while
/// ordinary management requests remain deliberately short.
const PREPARE_ADD_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(44 * 60);
pub(crate) const MAX_ASSOCIATION_TOKEN_BYTES: usize = 4096;
const BOOTSTRAP_TOKEN_PREFIX: &str = "wn2_";
const BOOTSTRAP_TOKEN_IPV4_BYTES: usize = 95;
const BOOTSTRAP_TOKEN_IPV6_BYTES: usize = 115;
const RECOVERY_TTL: u64 = 24 * 60 * 60;
const DETACH_RECEIPT_TTL: u64 = 60 * 60;
const OPERATION_RETENTION: u64 = 7 * 24 * 60 * 60;

/// Commands shared by local IPC, CLI and the Configuration / Nodes screen.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
pub enum NodeControlCommand {
    TokenPrepare {
        listen: Option<SocketAddr>,
    },
    TokenRevoke,
    PreviewAdd {
        name: String,
        endpoint: SocketAddr,
        token: SecretString,
    },
    PreviewEdit {
        node_id: String,
        name: String,
        endpoint: Option<SocketAddr>,
    },
    PreviewRemove {
        node_id: String,
    },
    Apply {
        preview_id: String,
    },
    Cancel {
        preview_id: String,
    },
    Resume {
        operation_id: String,
    },
    AbandonPreparingAdd {
        operation_id: String,
    },
    Status,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeOperationKind {
    Add,
    Edit,
    Remove,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeOperationPhase {
    Prepared,
    ApplyingPrimary,
    RestartingPrimary,
    PreparingTarget,
    ApplyingTarget,
    RestartingTarget,
    AwaitingDetach,
    Complete,
    Cancelled,
    Paused,
    Failed,
}

impl NodeOperationPhase {
    fn terminal(self) -> bool {
        matches!(self, Self::Complete | Self::Cancelled)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeRestartTarget {
    Primary,
    Secondary,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeRestartStep {
    pub step_id: String,
    pub target: NodeRestartTarget,
    pub requested: bool,
    pub acknowledged: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NodePreview {
    pub id: String,
    pub kind: NodeOperationKind,
    pub source_node_id: String,
    pub source_name: String,
    pub source_endpoint: Option<SocketAddr>,
    pub target_node_id: String,
    pub target_name: String,
    pub target_endpoint: SocketAddr,
    pub target_role: NodeRole,
    pub replacement_summary: Vec<String>,
    pub restart_steps: Vec<NodeRestartStep>,
    pub before_revision: String,
    pub expires_at: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NodeOperationProgress {
    pub operation_id: String,
    pub kind: NodeOperationKind,
    pub phase: NodeOperationPhase,
    pub target_node_id: String,
    pub message: String,
    pub last_verified_at: Option<u64>,
    pub recover_until: Option<u64>,
    pub restart_steps: Vec<NodeRestartStep>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeCapabilities {
    pub protocol_version: u32,
    pub persistent_management: bool,
    pub endpoint_transition: bool,
    pub durable_detach: bool,
}

impl NodeCapabilities {
    fn current() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            persistent_management: true,
            endpoint_transition: true,
            durable_detach: true,
        }
    }

    fn legacy() -> Self {
        Self {
            protocol_version: 1,
            persistent_management: false,
            endpoint_transition: false,
            durable_detach: false,
        }
    }

    #[must_use]
    pub fn supports_v2_management(&self) -> bool {
        self.protocol_version >= PROTOCOL_VERSION && self.persistent_management
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodePeerState {
    Pending,
    Active,
    PendingDetach,
    Detached,
    Unreachable,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NodePeer {
    pub node_id: String,
    pub name: String,
    pub endpoint: SocketAddr,
    pub role: NodeRole,
    pub state: NodePeerState,
    pub capabilities: NodeCapabilities,
    pub last_seen_at: Option<u64>,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NodeControlStatus {
    pub membership: LifecycleStatus,
    pub control_endpoint: Option<SocketAddr>,
    pub peers: Vec<NodePeer>,
    pub operations: Vec<NodeOperationProgress>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NodeControlReply {
    pub status: NodeControlStatus,
    pub preview: Option<NodePreview>,
    /// Present only in the response to an explicit token issuance command.
    pub token: Option<SecretString>,
    pub message: String,
}

#[derive(Debug, Error)]
#[error("{message}")]
pub struct NodeControlError {
    pub code: NodeControlErrorCode,
    pub message: String,
    #[source]
    source: Option<anyhow::Error>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeControlErrorCode {
    InvalidInput,
    ListenRequired,
    CapabilityUpgradeRequired,
    AuthorizationExpired,
    Conflict,
    PeerUnavailable,
    SupervisorUnsupported,
    RecoveryRequired,
    Internal,
}

impl NodeControlError {
    fn internal(error: anyhow::Error) -> Self {
        let detail = error.to_string();
        let (code, message) = if detail.starts_with("choose --listen")
            || detail.contains("automatic source endpoint selection")
        {
            (
                NodeControlErrorCode::ListenRequired,
                "Choose a reachable unicast Nodes address with --listen IP:PORT, or save node.control_listen first.".into(),
            )
        } else if detail.contains("explicit capability upgrade")
            || detail.contains("requires an upgrade")
        {
            (
                NodeControlErrorCode::CapabilityUpgradeRequired,
                "This node uses the compatible v1 membership protocol. Upgrade its Nodes management capability explicitly before this operation.".into(),
            )
        } else if detail.contains("expired") {
            (
                NodeControlErrorCode::AuthorizationExpired,
                "The association or review expired. Issue a new token and review it again.".into(),
            )
        } else if detail.contains("systemd") || detail.contains("managed restart") {
            (
                NodeControlErrorCode::SupervisorUnsupported,
                "Managed restart is unavailable. Run Warden as the supported systemd service with exit 75 configured, then resume the operation.".into(),
            )
        } else if detail.contains("changed") || detail.contains("conflict") {
            (
                NodeControlErrorCode::Conflict,
                "Configuration or reviewed artifacts changed. Prepare and review the operation again.".into(),
            )
        } else if detail.contains("TLS")
            || detail.contains("connect")
            || detail.contains("unavailable")
        {
            (
                NodeControlErrorCode::PeerUnavailable,
                "The managed node could not be reached through its pinned HTTPS endpoint. Check its address and retry or resume.".into(),
            )
        } else if detail.contains("restart") || detail.contains("recover") {
            (
                NodeControlErrorCode::RecoveryRequired,
                "The operation remains durable and needs recovery. Refresh Nodes and use Resume."
                    .into(),
            )
        } else if detail.starts_with("invalid")
            || detail.starts_with("choose")
            || detail.contains("requires")
            || detail.contains("cannot")
            || detail.contains("unknown node")
        {
            (
                NodeControlErrorCode::InvalidInput,
                "The Nodes request is not valid for the current node, address, or membership state. Review the fields and current status.".into(),
            )
        } else {
            (
                NodeControlErrorCode::Internal,
                "The Nodes operation could not be completed. Its durable status is still available."
                    .into(),
            )
        };
        Self {
            code,
            message,
            source: Some(error),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActivePolicyCorpus {
    pub policy: ArtifactIdentity,
    pub corpus_generation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagementOffer {
    pub endpoint: SocketAddr,
    pub fingerprint: String,
    pub incoming_credential: SecretString,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagementGrant {
    pub node_id: String,
    pub name: String,
    pub endpoint: SocketAddr,
    pub fingerprint: String,
    pub incoming_credential: SecretString,
}

#[async_trait]
pub trait ActivePairProvider: Send + Sync {
    fn active_pair(&self) -> Option<ActivePolicyCorpus>;
    async fn enrollment_pair(&self) -> anyhow::Result<ActivePolicyCorpus>;
}

/// Persist an exact verified policy snapshot for enrollment without advertising it.
pub(crate) fn capture_enrollment_policy(
    master: &Path,
    snapshot: Arc<super::artifact::PolicySnapshot>,
) -> anyhow::Result<ArtifactIdentity> {
    let guard = acquire_for_migration(master)?;
    let mut store = super::publication::PublicationStore::open(&guard)?;
    let now = super::membership::now()?;
    store.gc(now)?;
    let published = match store.find_committed_revision(snapshot.config_revision())? {
        Some(published) => published,
        None => {
            ensure!(
                !store
                    .pending_intents()?
                    .iter()
                    .any(|(reservation, _)| reservation.config_revision
                        == snapshot.config_revision()),
                "policy snapshot has an unresolved publication"
            );
            store.publish_capture(
                |lineage, epoch| snapshot.publication(lineage, epoch),
                &format!("enrollment:{}", snapshot.config_revision()),
            )?;
            store
                .find_committed_revision(snapshot.config_revision())?
                .context("enrollment policy publication is absent")?
        }
    };
    let manifest = super::manifest::Manifest::decode(&published.manifest)?;
    ensure!(
        manifest.operator_policy_hash == snapshot.operator_policy_hash()
            && manifest.policy_toml == super::manifest::ObjectRef::of(snapshot.toml()),
        "enrollment policy snapshot changed during publication"
    );
    Ok(ArtifactIdentity::from(&manifest))
}

#[derive(Clone)]
pub struct NodeListenerSpec {
    pub endpoint: SocketAddr,
    pub certificate_pem: String,
    pub private_key_pem: SecretString,
    pub scope: ListenerScope,
}

impl fmt::Debug for NodeListenerSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NodeListenerSpec")
            .field("endpoint", &self.endpoint)
            .field("certificate_pem", &"[certificate]")
            .field("private_key_pem", &"[redacted]")
            .field("scope", &self.scope)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListenerScope {
    Bootstrap,
    Management,
}

#[async_trait]
pub trait NodeListenerControl: Send + Sync {
    async fn existing_material(
        &self,
        _endpoint: SocketAddr,
    ) -> anyhow::Result<Option<NodeListenerSpec>> {
        Ok(None)
    }
    async fn prepare(&self, spec: NodeListenerSpec) -> anyhow::Result<()>;
    async fn retire(&self, endpoint: SocketAddr) -> anyhow::Result<()>;
}

#[derive(Debug, Clone)]
pub struct NodeRuntimePlan {
    pub listeners: Vec<NodeListenerSpec>,
    pub operations_to_resume: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootstrapToken {
    pub version: u32,
    pub target_node_id: String,
    pub endpoint: SocketAddr,
    pub fingerprint: String,
    pub expires_at: u64,
    pub secret: SecretString,
}

impl BootstrapToken {
    pub fn encode(&self) -> anyhow::Result<SecretString> {
        ensure!(
            self.version == PROTOCOL_VERSION
                && super::membership::valid_id(&self.target_node_id)
                && super::manifest::is_hash(&self.fingerprint)
                && self.endpoint.port() != 0,
            "invalid association token"
        );
        let secret = self
            .secret
            .0
            .strip_prefix("ps_")
            .context("invalid association token")?;
        ensure!(secret.len() == 64, "invalid association token");

        let mut node_id = [0_u8; 16];
        let compact_id = self.target_node_id.replace('-', "");
        hex::decode_to_slice(compact_id, &mut node_id)
            .map_err(|_| anyhow::anyhow!("invalid association token"))?;
        let mut fingerprint = [0_u8; 32];
        hex::decode_to_slice(&self.fingerprint, &mut fingerprint)
            .map_err(|_| anyhow::anyhow!("invalid association token"))?;
        let mut secret_bytes = [0_u8; 32];
        hex::decode_to_slice(secret, &mut secret_bytes)
            .map_err(|_| anyhow::anyhow!("invalid association token"))?;

        let mut bytes = Vec::with_capacity(match self.endpoint {
            SocketAddr::V4(_) => BOOTSTRAP_TOKEN_IPV4_BYTES,
            SocketAddr::V6(_) => BOOTSTRAP_TOKEN_IPV6_BYTES,
        });
        match self.endpoint.ip() {
            std::net::IpAddr::V4(address) => {
                bytes.push(4);
                bytes.extend_from_slice(&node_id);
                bytes.extend_from_slice(&address.octets());
            }
            std::net::IpAddr::V6(address) => {
                bytes.push(6);
                bytes.extend_from_slice(&node_id);
                bytes.extend_from_slice(&address.octets());
                if let SocketAddr::V6(endpoint) = self.endpoint {
                    bytes.extend_from_slice(&endpoint.flowinfo().to_be_bytes());
                    bytes.extend_from_slice(&endpoint.scope_id().to_be_bytes());
                }
            }
        }
        bytes.extend_from_slice(&self.endpoint.port().to_be_bytes());
        bytes.extend_from_slice(&self.expires_at.to_be_bytes());
        bytes.extend_from_slice(&fingerprint);
        bytes.extend_from_slice(&secret_bytes);
        Ok(SecretString(format!(
            "{BOOTSTRAP_TOKEN_PREFIX}{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
        )))
    }

    pub fn decode(encoded: &SecretString, now: u64) -> anyhow::Result<Self> {
        ensure!(
            encoded.0.len() <= MAX_ASSOCIATION_TOKEN_BYTES,
            "invalid association token"
        );
        let encoded = encoded.0.trim();
        let token = if let Some(payload) = encoded.strip_prefix(BOOTSTRAP_TOKEN_PREFIX) {
            Self::decode_compact(payload)?
        } else {
            Self::decode_legacy(encoded)?
        };
        token.validate(now)?;
        Ok(token)
    }

    fn decode_compact(encoded: &str) -> anyhow::Result<Self> {
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| anyhow::anyhow!("invalid association token"))?;
        let address_len = match bytes.first() {
            Some(4) => 4,
            Some(6) => 16,
            _ => anyhow::bail!("invalid association token"),
        };
        let expected_len = if address_len == 4 {
            BOOTSTRAP_TOKEN_IPV4_BYTES
        } else {
            BOOTSTRAP_TOKEN_IPV6_BYTES
        };
        ensure!(bytes.len() == expected_len, "invalid association token");

        let mut offset = 1;
        let node_id = &bytes[offset..offset + 16];
        offset += 16;
        let address = if address_len == 4 {
            let octets: [u8; 4] = bytes[offset..offset + 4].try_into().unwrap();
            offset += 4;
            std::net::IpAddr::V4(octets.into())
        } else {
            let octets: [u8; 16] = bytes[offset..offset + 16].try_into().unwrap();
            offset += 16;
            std::net::IpAddr::V6(octets.into())
        };
        let flowinfo = if address_len == 16 {
            let flowinfo = u32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap());
            offset += 4;
            flowinfo
        } else {
            0
        };
        let scope_id = if address_len == 16 {
            let scope_id = u32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap());
            offset += 4;
            scope_id
        } else {
            0
        };
        let port = u16::from_be_bytes(bytes[offset..offset + 2].try_into().unwrap());
        offset += 2;
        let expires_at = u64::from_be_bytes(bytes[offset..offset + 8].try_into().unwrap());
        offset += 8;
        let fingerprint = hex::encode(&bytes[offset..offset + 32]);
        offset += 32;
        let secret = format!("ps_{}", hex::encode(&bytes[offset..offset + 32]));
        let id = hex::encode(node_id);

        Ok(Self {
            version: PROTOCOL_VERSION,
            target_node_id: format!(
                "{}-{}-{}-{}-{}",
                &id[..8],
                &id[8..12],
                &id[12..16],
                &id[16..20],
                &id[20..]
            ),
            endpoint: match address {
                std::net::IpAddr::V4(address) => SocketAddr::new(address.into(), port),
                std::net::IpAddr::V6(address) => SocketAddr::V6(std::net::SocketAddrV6::new(
                    address, port, flowinfo, scope_id,
                )),
            },
            fingerprint,
            expires_at,
            secret: SecretString(secret),
        })
    }

    fn decode_legacy(encoded: &str) -> anyhow::Result<Self> {
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| anyhow::anyhow!("invalid association token"))?;
        serde_json::from_slice(&bytes).map_err(|_| anyhow::anyhow!("invalid association token"))
    }

    fn validate(&self, now: u64) -> anyhow::Result<()> {
        ensure!(
            self.version == PROTOCOL_VERSION
                && self.expires_at > now
                && self.expires_at <= now.saturating_add(PREVIEW_TTL)
                && super::membership::valid_id(&self.target_node_id)
                && super::manifest::is_hash(&self.fingerprint)
                && self.endpoint.port() != 0,
            "association token expired or unsupported"
        );
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootstrapClaimRequest {
    pub token: SecretString,
    pub operation_id: String,
    pub source_node_id: String,
    pub source_name: String,
    pub source_endpoint: SocketAddr,
    pub source_fingerprint: String,
    pub source_credential: SecretString,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootstrapClaimResponse {
    pub target_node_id: String,
    pub target_name: String,
    pub target_role: NodeRole,
    pub config_revision: String,
    pub capabilities: NodeCapabilities,
    pub target_credential: SecretString,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "request", rename_all = "snake_case", deny_unknown_fields)]
pub enum PeerManagementRequest {
    PrepareAdd {
        operation_id: String,
        name: String,
        cluster_id: String,
        primary_node_id: String,
        primary_endpoint: SocketAddr,
        primary_fingerprint: String,
        staged_pair: Box<ActivePolicyCorpus>,
        replication_credential: SecretString,
    },
    Apply {
        operation_id: String,
        preview_id: String,
    },
    Cancel {
        operation_id: String,
        #[serde(default)]
        preview_id: Option<String>,
    },
    PrepareEdit {
        operation_id: String,
        name: String,
        endpoint: Option<SocketAddr>,
    },
    PrepareRemove {
        operation_id: String,
    },
    Resume {
        operation_id: String,
    },
    ArmAddRecovery {
        operation_id: String,
        preview_id: String,
    },
    AcknowledgeEndpoint {
        operation_id: String,
    },
    AcknowledgeDetach {
        operation_id: String,
    },
    DetachReceipt {
        operation_id: String,
        target_node_id: String,
    },
    AdoptPrimaryEndpoint {
        operation_id: String,
        endpoint: SocketAddr,
        fingerprint: String,
    },
    Status,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerManagementReply {
    pub node_id: String,
    pub status: LifecycleStatus,
    pub preview_id: Option<String>,
    pub operation: Option<NodeOperationProgress>,
    pub capabilities: NodeCapabilities,
    pub backup_verified: bool,
    pub control_endpoint: Option<SocketAddr>,
    pub control_fingerprint: Option<String>,
    pub transition_acknowledged: bool,
    pub message: String,
}

struct PreparedAddCommand {
    operation_id: String,
    name: String,
    cluster_id: String,
    primary_node_id: String,
    primary_endpoint: SocketAddr,
    primary_fingerprint: String,
    staged_pair: ActivePolicyCorpus,
    replication_credential: SecretString,
}

#[derive(Clone, Serialize, Deserialize)]
struct BootstrapAuthorization {
    token_hash: String,
    endpoint: SocketAddr,
    target_node_id: String,
    fingerprint: String,
    certificate_pem: String,
    private_key_pem: SecretString,
    expires_at: u64,
    claimed_by: Option<String>,
    operation_id: Option<String>,
    issued_credential: Option<SecretString>,
}

#[derive(Clone, Serialize, Deserialize)]
struct ListenerMaterial {
    endpoint: SocketAddr,
    certificate_pem: String,
    private_key_pem: SecretString,
    fingerprint: String,
}

#[derive(Clone, Serialize, Deserialize)]
struct PendingPrimaryTransition {
    operation_id: String,
    primary_node_id: String,
    endpoint: SocketAddr,
    fingerprint: String,
    lifecycle_preview_id: String,
    restart_requested: bool,
    acknowledged: bool,
}

#[derive(Clone, Serialize, Deserialize)]
struct PeerRecord {
    view: NodePeer,
    outgoing_credential: SecretString,
    incoming_credential_hash: String,
    #[serde(default)]
    issued_incoming_credential: Option<SecretString>,
    source_fingerprint: String,
}

#[derive(Clone, Serialize, Deserialize)]
struct OperationRecord {
    preview: NodePreview,
    phase: NodeOperationPhase,
    #[serde(default)]
    paused_from: Option<NodeOperationPhase>,
    message: String,
    last_verified_at: Option<u64>,
    recover_until: Option<u64>,
    peer_preview_id: Option<String>,
    local_preview_id: Option<String>,
    #[serde(default)]
    staged_pair: Option<ActivePolicyCorpus>,
    #[serde(default)]
    prepared_certificate: Option<String>,
    #[serde(default)]
    prepared_private_key: Option<SecretString>,
    #[serde(default)]
    prepared_fingerprint: Option<String>,
    #[serde(default)]
    cluster_id: Option<String>,
    #[serde(default)]
    replication_credential: Option<SecretString>,
    #[serde(default)]
    backup_verified: bool,
    /// A cancellation request survives a lost management reply. A staging
    /// worker must never publish a prepared review after this is recorded.
    #[serde(default)]
    cancel_requested: bool,
    #[serde(default)]
    restart_requested_at: BTreeMap<String, u64>,
}

impl OperationRecord {
    fn acknowledge_secondary_restart(&mut self) {
        for step in &mut self.preview.restart_steps {
            if step.target == NodeRestartTarget::Secondary && !step.acknowledged {
                step.requested = true;
                step.acknowledged = true;
            }
        }
    }

    fn progress(&self) -> NodeOperationProgress {
        NodeOperationProgress {
            operation_id: self.preview.id.clone(),
            kind: self.preview.kind,
            phase: self.phase,
            target_node_id: self.preview.target_node_id.clone(),
            message: self.message.clone(),
            last_verified_at: self.last_verified_at,
            recover_until: self.recover_until,
            restart_steps: self.preview.restart_steps.clone(),
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct ControlState {
    format: u32,
    control_endpoint: Option<SocketAddr>,
    certificate_pem: Option<String>,
    private_key_pem: Option<SecretString>,
    certificate_fingerprint: Option<String>,
    #[serde(default)]
    previous_listener: Option<ListenerMaterial>,
    #[serde(default)]
    pending_primary_transition: Option<PendingPrimaryTransition>,
    bootstrap: Option<BootstrapAuthorization>,
    peers: BTreeMap<String, PeerRecord>,
    #[serde(default)]
    legacy_upgrade_required: BTreeSet<String>,
    #[serde(default)]
    detach_receipts: BTreeMap<String, u64>,
    #[serde(default)]
    released_corpus_pins: BTreeSet<String>,
    operations: BTreeMap<String, OperationRecord>,
    #[serde(default)]
    runtime_online: bool,
    #[serde(default)]
    last_shutdown_at: Option<u64>,
}

impl Default for ControlState {
    fn default() -> Self {
        Self {
            format: FORMAT,
            control_endpoint: None,
            certificate_pem: None,
            private_key_pem: None,
            certificate_fingerprint: None,
            previous_listener: None,
            pending_primary_transition: None,
            bootstrap: None,
            peers: BTreeMap::new(),
            legacy_upgrade_required: BTreeSet::new(),
            detach_receipts: BTreeMap::new(),
            released_corpus_pins: BTreeSet::new(),
            operations: BTreeMap::new(),
            runtime_online: false,
            last_shutdown_at: None,
        }
    }
}

pub struct NodeController {
    master: PathBuf,
    listeners: Arc<dyn NodeListenerControl>,
    restart: super::managed_restart::ManagedRestartHandle,
    active: Arc<dyn ActivePairProvider>,
    transition_gate: Arc<tokio::sync::Mutex<()>>,
}

impl NodeController {
    pub(crate) fn authoritative_peer_name_under_guard(
        &self,
        guard: &MigrationWriteLock,
        node_id: &str,
    ) -> anyhow::Result<Option<String>> {
        guard.verify_master(&self.master)?;
        let state = load_state(guard)?;
        Ok(state.peers.get(node_id).map(|peer| peer.view.name.clone()))
    }

    #[must_use]
    pub fn new(
        master: PathBuf,
        listeners: Arc<dyn NodeListenerControl>,
        restart: super::managed_restart::ManagedRestartHandle,
        active: Arc<dyn ActivePairProvider>,
    ) -> Arc<Self> {
        Arc::new(Self {
            master,
            listeners,
            restart,
            active,
            transition_gate: Arc::new(tokio::sync::Mutex::new(())),
        })
    }

    pub async fn handle(
        self: &Arc<Self>,
        command: NodeControlCommand,
    ) -> Result<NodeControlReply, NodeControlError> {
        if matches!(command, NodeControlCommand::Status) {
            return self
                .reply(None, None, "Status refreshed.")
                .await
                .map_err(NodeControlError::internal);
        }
        // Admit before spawning so disconnected callers cannot leave an
        // unbounded queue of detached mutations behind the transition gate.
        let transition = self.transition_gate.clone().lock_owned().await;
        let controller = self.clone();
        tokio::spawn(async move {
            let _transition = transition;
            controller.handle_admitted(command).await
        })
        .await
        .map_err(|error| NodeControlError::internal(anyhow::Error::new(error)))?
        .map_err(NodeControlError::internal)
    }

    async fn handle_admitted(
        &self,
        command: NodeControlCommand,
    ) -> anyhow::Result<NodeControlReply> {
        match command {
            NodeControlCommand::TokenPrepare { listen } => self.prepare_token(listen).await,
            NodeControlCommand::TokenRevoke => self.revoke_token().await,
            NodeControlCommand::PreviewAdd {
                name,
                endpoint,
                token,
            } => self.preview_add(name, endpoint, token).await,
            NodeControlCommand::PreviewEdit {
                node_id,
                name,
                endpoint,
            } => self.preview_edit(node_id, name, endpoint).await,
            NodeControlCommand::PreviewRemove { node_id } => self.preview_remove(node_id).await,
            NodeControlCommand::Apply { preview_id } => self.apply(&preview_id).await,
            NodeControlCommand::Cancel { preview_id } => self.cancel(&preview_id).await,
            NodeControlCommand::Resume { operation_id } => self.resume(&operation_id).await,
            NodeControlCommand::AbandonPreparingAdd { operation_id } => {
                self.abandon_preparing_add(&operation_id).await
            }
            NodeControlCommand::Status => unreachable!("status returned before admission"),
        }
    }

    pub async fn runtime_start(&self) -> anyhow::Result<NodeRuntimePlan> {
        let master = self.master.clone();
        let (listeners, operations_to_resume) = blocking(move || {
            let guard = acquire_for_migration(&master)?;
            let mut state = load_state(&guard)?;
            expire_state(&mut state, super::membership::now()?);
            state.runtime_online = true;
            save_state(&guard, &state)?;
            let listeners = listener_specs(&state);
            let operations: Vec<String> = state
                .operations
                .values()
                .filter(|operation| {
                    matches!(
                        operation.phase,
                        NodeOperationPhase::ApplyingPrimary
                            | NodeOperationPhase::RestartingPrimary
                            | NodeOperationPhase::ApplyingTarget
                            | NodeOperationPhase::RestartingTarget
                            | NodeOperationPhase::AwaitingDetach
                    )
                })
                .map(|operation| operation.preview.id.clone())
                .collect();
            Ok((listeners, operations))
        })
        .await?;
        Ok(NodeRuntimePlan {
            listeners,
            operations_to_resume,
        })
    }

    pub async fn runtime_ready(&self, endpoint: SocketAddr) -> anyhow::Result<()> {
        let _transition = self.transition_gate.lock().await;
        let lifecycle = {
            let master = self.master.clone();
            blocking(move || super::lifecycle::status(&master)).await?
        };
        let local_id = lifecycle.node_id.context("runtime node identity absent")?;
        let active = self.active.active_pair();
        let master = self.master.clone();
        let completed_pin_owners = blocking(move || {
            let guard = acquire_for_migration(&master)?;
            let mut state = load_state(&guard)?;
            let is_current_endpoint = state.control_endpoint == Some(endpoint);
            ensure!(
                is_current_endpoint
                    || state
                        .previous_listener
                        .as_ref()
                        .is_some_and(|listener| listener.endpoint == endpoint),
                "ready endpoint does not match durable Nodes listener"
            );
            let now = super::membership::now()?;
            let mut completed_peer_states = Vec::new();
            let mut completed_pin_owners = Vec::new();
            for operation in state.operations.values_mut() {
                let local_is_source = operation.preview.source_node_id == local_id;
                let local_is_target = operation.preview.target_node_id == local_id;
                for step in &mut operation.preview.restart_steps {
                    let belongs_here = match step.target {
                        NodeRestartTarget::Primary => local_is_source,
                        NodeRestartTarget::Secondary => local_is_target,
                    };
                    let pair_matches = match operation.preview.kind {
                        NodeOperationKind::Add => {
                            operation.staged_pair.as_ref().is_some_and(|expected| {
                                active.as_ref().is_some_and(|actual| {
                                    reviewed_pair_matches(&master, expected, actual)
                                        .unwrap_or(false)
                                })
                            })
                        }
                        NodeOperationKind::Edit => true,
                        NodeOperationKind::Remove => lifecycle.saved_role == NodeRole::Standalone,
                    };
                    if is_current_endpoint
                        && step.requested
                        && !step.acknowledged
                        && belongs_here
                        && pair_matches
                    {
                        step.acknowledged = true;
                        operation.last_verified_at = Some(now);
                    }
                }
                if local_is_target
                    && operation.phase == NodeOperationPhase::RestartingTarget
                    && operation
                        .preview
                        .restart_steps
                        .iter()
                        .all(|step| !step.requested || step.acknowledged)
                {
                    operation.phase = NodeOperationPhase::Complete;
                    operation.message = "Runtime readiness verified after restart.".into();
                    if operation.preview.kind == NodeOperationKind::Add {
                        completed_pin_owners.push(operation.preview.id.clone());
                        completed_peer_states.push((
                            operation.preview.source_node_id.clone(),
                            NodePeerState::Active,
                        ));
                    } else if operation.preview.kind == NodeOperationKind::Remove {
                        completed_peer_states.push((
                            operation.preview.source_node_id.clone(),
                            NodePeerState::PendingDetach,
                        ));
                    }
                }
            }
            for (peer_id, peer_state) in completed_peer_states {
                if let Some(peer) = state.peers.get_mut(&peer_id) {
                    peer.view.state = peer_state;
                }
            }
            save_state(&guard, &state)?;
            Ok(completed_pin_owners)
        })
        .await?;
        for owner in completed_pin_owners {
            let _ = self.release_completed_corpus_pin(&owner).await;
        }
        Ok(())
    }

    pub async fn runtime_shutdown(&self) -> anyhow::Result<()> {
        let master = self.master.clone();
        blocking(move || {
            let guard = acquire_for_migration(&master)?;
            let mut state = load_state(&guard)?;
            state.runtime_online = false;
            state.last_shutdown_at = Some(super::membership::now()?);
            save_state(&guard, &state)
        })
        .await
    }

    pub async fn management_offer(&self) -> anyhow::Result<Option<ManagementOffer>> {
        let _transition = self.transition_gate.lock().await;
        let status = {
            let master = self.master.clone();
            blocking(move || super::lifecycle::status(&master)).await?
        };
        if status.saved_role != NodeRole::Secondary {
            return Ok(None);
        }
        let primary_id = status
            .primary_node_id
            .clone()
            .context("secondary primary identity absent")?;
        let primary_name = status.primary_name.unwrap_or_else(|| "primary".into());
        let primary_endpoint = status
            .primary_address
            .as_deref()
            .and_then(parse_member_endpoint)
            .context("secondary primary endpoint absent")?;
        let primary_fingerprint = status
            .primary_fingerprint
            .context("secondary primary fingerprint absent")?;
        let material = self.ensure_management_material(primary_endpoint).await?;
        let master = self.master.clone();
        blocking(move || {
            let guard = acquire_for_migration(&master)?;
            let mut state = load_state(&guard)?;
            let peer = state.peers.entry(primary_id.clone()).or_insert_with(|| {
                let (credential, credential_hash) = generate_token();
                PeerRecord {
                    view: NodePeer {
                        node_id: primary_id,
                        name: primary_name,
                        endpoint: primary_endpoint,
                        role: NodeRole::Primary,
                        state: NodePeerState::Active,
                        capabilities: NodeCapabilities::legacy(),
                        last_seen_at: None,
                        last_error: None,
                    },
                    outgoing_credential: SecretString(String::new()),
                    incoming_credential_hash: credential_hash,
                    issued_incoming_credential: Some(SecretString(credential)),
                    source_fingerprint: primary_fingerprint,
                }
            });
            let incoming_credential = peer
                .issued_incoming_credential
                .clone()
                .context("durable management offer credential absent")?;
            save_state(&guard, &state)?;
            Ok(Some(ManagementOffer {
                endpoint: material.endpoint,
                fingerprint: material.fingerprint,
                incoming_credential,
            }))
        })
        .await
    }

    pub async fn accept_management_offer(
        &self,
        authenticated_node_id: &str,
        authenticated_name: &str,
        offer: ManagementOffer,
    ) -> anyhow::Result<Option<ManagementGrant>> {
        let _transition = self.transition_gate.lock().await;
        ensure!(
            super::membership::valid_id(authenticated_node_id)
                && super::manifest::is_hash(&offer.fingerprint)
                && offer.endpoint.port() != 0
                && !offer.incoming_credential.0.is_empty(),
            "invalid authenticated management capability offer"
        );
        super::membership::validate_name(authenticated_name)?;
        let status = {
            let master = self.master.clone();
            blocking(move || super::lifecycle::status(&master)).await?
        };
        if status.saved_role != NodeRole::Primary {
            return Ok(None);
        }
        let local_id = status.node_id.context("primary node identity absent")?;
        let material = self.ensure_management_material(offer.endpoint).await?;
        let master = self.master.clone();
        let peer_id = authenticated_node_id.to_owned();
        let peer_name = authenticated_name.to_owned();
        let grant = blocking(move || {
            let guard = acquire_for_migration(&master)?;
            require_active_management_member(&guard, &peer_id, &peer_name)?;
            let mut state = load_state(&guard)?;
            let peer = state.peers.entry(peer_id.clone()).or_insert_with(|| {
                let (credential, credential_hash) = generate_token();
                PeerRecord {
                    view: NodePeer {
                        node_id: peer_id.clone(),
                        name: peer_name.clone(),
                        endpoint: offer.endpoint,
                        role: NodeRole::Secondary,
                        state: NodePeerState::Active,
                        capabilities: NodeCapabilities::current(),
                        last_seen_at: None,
                        last_error: None,
                    },
                    outgoing_credential: offer.incoming_credential.clone(),
                    incoming_credential_hash: credential_hash,
                    issued_incoming_credential: Some(SecretString(credential)),
                    source_fingerprint: offer.fingerprint.clone(),
                }
            });
            peer.view.name = peer_name;
            peer.view.endpoint = offer.endpoint;
            peer.view.capabilities = NodeCapabilities::current();
            peer.view.state = NodePeerState::Active;
            peer.outgoing_credential = offer.incoming_credential;
            peer.source_fingerprint = offer.fingerprint;
            let incoming_credential = peer
                .issued_incoming_credential
                .clone()
                .context("durable management grant credential absent")?;
            state.legacy_upgrade_required.remove(&peer_id);
            save_state(&guard, &state)?;
            Ok(ManagementGrant {
                node_id: local_id,
                name: status.node_name,
                endpoint: material.endpoint,
                fingerprint: material.fingerprint,
                incoming_credential,
            })
        })
        .await?;
        Ok(Some(grant))
    }

    pub async fn accept_management_grant(&self, grant: ManagementGrant) -> anyhow::Result<()> {
        let _transition = self.transition_gate.lock().await;
        ensure!(
            super::membership::valid_id(&grant.node_id)
                && super::manifest::is_hash(&grant.fingerprint)
                && grant.endpoint.port() != 0
                && !grant.incoming_credential.0.is_empty(),
            "invalid authenticated management capability grant"
        );
        super::membership::validate_name(&grant.name)?;
        let master = self.master.clone();
        blocking(move || {
            let guard = acquire_for_migration(&master)?;
            let mut state = load_state(&guard)?;
            let peer = state
                .peers
                .get_mut(&grant.node_id)
                .context("management offer state absent")?;
            peer.view.name = grant.name;
            peer.view.endpoint = grant.endpoint;
            peer.view.capabilities = NodeCapabilities::current();
            peer.view.state = NodePeerState::Active;
            peer.outgoing_credential = grant.incoming_credential;
            peer.source_fingerprint = grant.fingerprint;
            state.legacy_upgrade_required.remove(&grant.node_id);
            save_state(&guard, &state)
        })
        .await
    }

    pub async fn note_management_upgrade_required(&self, peer_node_id: &str) -> anyhow::Result<()> {
        ensure!(
            super::membership::valid_id(peer_node_id),
            "invalid node identity"
        );
        let _transition = self.transition_gate.lock().await;
        let master = self.master.clone();
        let peer_node_id = peer_node_id.to_owned();
        blocking(move || {
            let guard = acquire_for_migration(&master)?;
            let mut state = load_state(&guard)?;
            state.legacy_upgrade_required.insert(peer_node_id);
            save_state(&guard, &state)
        })
        .await
    }

    async fn ensure_management_material(
        &self,
        destination: SocketAddr,
    ) -> anyhow::Result<ListenerMaterial> {
        let master = self.master.clone();
        if let Some(material) = blocking(move || {
            let guard = acquire_for_migration(&master)?;
            let state = load_state(&guard)?;
            Ok(current_listener_material(&state))
        })
        .await?
        {
            return Ok(material);
        }
        let master = self.master.clone();
        let endpoint = blocking(move || preferred_source_endpoint(&master, destination)).await?;
        let material = if let Some(spec) = self.listeners.existing_material(endpoint).await? {
            listener_material_from_spec(spec)?
        } else {
            let cert = super::certgen::generate_self_signed(
                &[super::certgen::San::Ip(endpoint.ip())],
                3650,
                time::OffsetDateTime::now_utc(),
            )?;
            ListenerMaterial {
                endpoint,
                certificate_pem: cert.cert_pem,
                private_key_pem: SecretString(cert.key_pem),
                fingerprint: cert.fingerprint_sha256,
            }
        };
        self.listeners
            .prepare(NodeListenerSpec {
                endpoint: material.endpoint,
                certificate_pem: material.certificate_pem.clone(),
                private_key_pem: material.private_key_pem.clone(),
                scope: ListenerScope::Management,
            })
            .await?;
        let master = self.master.clone();
        let saved = material.clone();
        blocking(move || {
            let guard = acquire_for_migration(&master)?;
            let mut state = load_state(&guard)?;
            promote_listener(
                &mut state,
                saved.endpoint,
                saved.certificate_pem.clone(),
                saved.private_key_pem.clone(),
                saved.fingerprint.clone(),
            )?;
            save_state(&guard, &state)
        })
        .await?;
        Ok(material)
    }

    /// Advance a bounded batch of already-applied durable work.
    pub async fn runtime_tick(self: &Arc<Self>) -> anyhow::Result<usize> {
        let local_node_id = {
            let master = self.master.clone();
            blocking(move || super::lifecycle::status(&master))
                .await?
                .node_id
        };
        let master = self.master.clone();
        let (
            expired_listeners,
            staged_listeners,
            cancelled_joins,
            completed_add_pins,
            pending_primary,
            detach_outbox,
            operations,
        ) = blocking(move || {
            let guard = acquire_for_migration(&master)?;
            let mut state = load_state(&guard)?;
            let now = super::membership::now()?;
            let before: BTreeSet<_> = listener_specs(&state)
                .into_iter()
                .map(|listener| listener.endpoint)
                .collect();
            expire_state(&mut state, now);
            let after: BTreeSet<_> = listener_specs(&state)
                .into_iter()
                .map(|listener| listener.endpoint)
                .collect();
            let expired = before.difference(&after).copied().collect::<Vec<_>>();
            let operations = rotating_batch(
                state
                    .operations
                    .values()
                    .filter(|operation| {
                        matches!(
                            operation.phase,
                            NodeOperationPhase::ApplyingPrimary
                                | NodeOperationPhase::RestartingPrimary
                                | NodeOperationPhase::ApplyingTarget
                                | NodeOperationPhase::RestartingTarget
                                | NodeOperationPhase::AwaitingDetach
                        )
                    })
                    .map(|operation| operation.preview.id.clone())
                    .collect(),
                now,
            );
            let staged_listeners = state
                .operations
                .values()
                .filter(|operation| {
                    matches!(
                        operation.phase,
                        NodeOperationPhase::Paused | NodeOperationPhase::Cancelled
                    ) && operation.prepared_certificate.is_some()
                        && state.control_endpoint != Some(operation.preview.target_endpoint)
                })
                .take(8)
                .map(|operation| operation.preview.id.clone())
                .collect::<Vec<_>>();
            let cancelled_joins = local_node_id
                .as_deref()
                .map(|local_id| {
                    state
                        .operations
                        .values()
                        .filter(|operation| {
                            operation.preview.kind == NodeOperationKind::Add
                                && operation.phase == NodeOperationPhase::Cancelled
                                && operation.preview.target_node_id == local_id
                                && operation.peer_preview_id.is_some()
                        })
                        .take(8)
                        .map(|operation| operation.preview.id.clone())
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            let completed_add_pins = local_node_id
                .as_deref()
                .map(|local_id| {
                    rotating_batch(
                        state
                            .operations
                            .values()
                            .filter(|operation| {
                                operation.preview.kind == NodeOperationKind::Add
                                    && operation.phase == NodeOperationPhase::Complete
                                    && operation.preview.target_node_id == local_id
                                    && !state.released_corpus_pins.contains(&operation.preview.id)
                            })
                            .map(|operation| operation.preview.id.clone())
                            .collect(),
                        now,
                    )
                })
                .unwrap_or_default();
            let pending_primary = state
                .pending_primary_transition
                .as_ref()
                .is_some_and(|pending| !pending.restart_requested && !pending.acknowledged);
            let detach_outbox = local_node_id
                .as_deref()
                .map(|local_id| detach_outbox_ids(&state, local_id, now))
                .unwrap_or_default();
            save_state(&guard, &state)?;
            Ok((
                expired,
                staged_listeners,
                cancelled_joins,
                completed_add_pins,
                pending_primary,
                detach_outbox,
                operations,
            ))
        })
        .await?;
        for endpoint in expired_listeners {
            let _ = self.listeners.retire(endpoint).await;
        }
        let mut advanced = 0;
        for operation_id in staged_listeners {
            if self.retire_prepared_listener(&operation_id).await? {
                advanced += 1;
            }
        }
        for operation_id in cancelled_joins {
            if self.cleanup_cancelled_join(&operation_id).await? {
                advanced += 1;
            }
        }
        for operation_id in completed_add_pins {
            if self.release_completed_corpus_pin(&operation_id).await? {
                advanced += 1;
            }
        }
        if pending_primary {
            if let Ok(transition) = self.transition_gate.clone().try_lock_owned() {
                let controller = self.clone();
                let task = tokio::spawn(async move {
                    let _transition = transition;
                    controller.apply_pending_primary_transition().await
                });
                if matches!(task.await, Ok(Ok(()))) {
                    advanced += 1;
                }
            }
        }
        for operation_id in detach_outbox {
            if let Ok(transition) = self.transition_gate.clone().try_lock_owned() {
                let controller = self.clone();
                let task = tokio::spawn(async move {
                    let _transition = transition;
                    controller.push_detach_receipt(&operation_id).await
                });
                if matches!(task.await, Ok(Ok(()))) {
                    advanced += 1;
                }
            }
        }
        for operation_id in operations {
            if let Ok(transition) = self.transition_gate.clone().try_lock_owned() {
                let controller = self.clone();
                let task = tokio::spawn(async move {
                    let _transition = transition;
                    controller.resume(&operation_id).await
                });
                if matches!(task.await, Ok(Ok(_))) {
                    advanced += 1;
                }
            }
        }
        Ok(advanced)
    }

    async fn ensure_identity(&self) -> anyhow::Result<LifecycleStatus> {
        let status = {
            let master = self.master.clone();
            blocking(move || super::lifecycle::status(&master)).await?
        };
        if status.node_id.is_some() {
            return Ok(status);
        }
        let preview =
            super::lifecycle::preview_nodes_metadata(&self.master, status.node_name.clone(), None)
                .await?;
        super::lifecycle::apply(&self.master, &preview.id).await?;
        let master = self.master.clone();
        blocking(move || super::lifecycle::status(&master)).await
    }

    async fn prepare_token(
        &self,
        requested: Option<SocketAddr>,
    ) -> anyhow::Result<NodeControlReply> {
        let master = self.master.clone();
        let existing_material = blocking(move || {
            let guard = acquire_for_migration(&master)?;
            let mut state = load_state(&guard)?;
            expire_state(&mut state, super::membership::now()?);
            ensure!(
                state.bootstrap.as_ref().is_none_or(|authorization| authorization.claimed_by.is_none()),
                "a claimed association is already bound to an operation; cancel or resume it before issuing another token"
            );
            ensure!(
                state
                    .peers
                    .values()
                    .all(|peer| peer.view.state == NodePeerState::Detached),
                "a managed node cannot issue a standalone association token"
            );
            let material = match (
                state.control_endpoint,
                state.certificate_pem.clone(),
                state.private_key_pem.clone(),
                state.certificate_fingerprint.clone(),
            ) {
                (Some(endpoint), Some(certificate), Some(key), Some(fingerprint)) => {
                    Some((endpoint, certificate, key, fingerprint))
                }
                _ => None,
            };
            save_state(&guard, &state)?;
            Ok(material)
        })
        .await?;
        let initial = {
            let master = self.master.clone();
            blocking(move || super::lifecycle::status(&master)).await?
        };
        ensure!(
            initial.saved_role == NodeRole::Standalone,
            "a clustered node cannot issue a standalone association token"
        );
        let identity = self.ensure_identity().await?;
        let master = self.master.clone();
        let endpoint = blocking(move || preferred_endpoint(&master, requested)).await?;
        let compatible_material = if existing_material
            .as_ref()
            .is_some_and(|material| material.0 == endpoint)
        {
            None
        } else {
            self.listeners
                .existing_material(endpoint)
                .await?
                .map(listener_material_from_spec)
                .transpose()?
        };
        let preview = super::lifecycle::preview_nodes_metadata(
            &self.master,
            identity.node_name.clone(),
            Some(endpoint),
        )
        .await?;
        super::lifecycle::apply(&self.master, &preview.id).await?;

        let (certificate, private_key, fingerprint) =
            if let Some((_saved_endpoint, certificate, key, fingerprint)) =
                existing_material.filter(|material| material.0 == endpoint)
            {
                (certificate, key, fingerprint)
            } else if let Some(material) = compatible_material {
                (
                    material.certificate_pem,
                    material.private_key_pem,
                    material.fingerprint,
                )
            } else {
                let cert = super::certgen::generate_self_signed(
                    &[super::certgen::San::Ip(endpoint.ip())],
                    3650,
                    time::OffsetDateTime::now_utc(),
                )?;
                (
                    cert.cert_pem,
                    SecretString(cert.key_pem),
                    cert.fingerprint_sha256,
                )
            };
        let now = super::membership::now()?;
        let expires_at = now.checked_add(PREVIEW_TTL).context("clock overflow")?;
        let (secret, token_hash) = generate_token();
        let target_node_id = identity
            .node_id
            .context("node identity initialization failed")?;
        let authorization = BootstrapAuthorization {
            token_hash,
            endpoint,
            target_node_id: target_node_id.clone(),
            fingerprint: fingerprint.clone(),
            certificate_pem: certificate.clone(),
            private_key_pem: private_key.clone(),
            expires_at,
            claimed_by: None,
            operation_id: None,
            issued_credential: None,
        };
        let spec = NodeListenerSpec {
            endpoint,
            certificate_pem: certificate,
            private_key_pem: private_key,
            scope: ListenerScope::Bootstrap,
        };
        let master = self.master.clone();
        blocking(move || {
            let guard = acquire_for_migration(&master)?;
            let mut state = load_state(&guard)?;
            ensure!(
                state.peers.values().all(|peer| {
                    matches!(
                        peer.view.state,
                        NodePeerState::Detached | NodePeerState::PendingDetach
                    )
                }),
                "an active member cannot issue a fresh bootstrap certificate"
            );
            state.control_endpoint = Some(endpoint);
            state.certificate_pem = Some(authorization.certificate_pem.clone());
            state.private_key_pem = Some(authorization.private_key_pem.clone());
            state.certificate_fingerprint = Some(authorization.fingerprint.clone());
            state.bootstrap = Some(authorization);
            save_state(&guard, &state)
        })
        .await?;
        if let Err(error) = self.listeners.prepare(spec).await {
            let master = self.master.clone();
            let _ = blocking(move || {
                let guard = acquire_for_migration(&master)?;
                let mut state = load_state(&guard)?;
                state.bootstrap = None;
                save_state(&guard, &state)
            })
            .await;
            return Err(error.context("Nodes HTTPS listener could not be prepared"));
        }
        let token = BootstrapToken {
            version: PROTOCOL_VERSION,
            target_node_id,
            endpoint,
            fingerprint,
            expires_at,
            secret: SecretString(secret),
        }
        .encode()?;
        self.reply(
            None,
            Some(token),
            "One-use association token issued for 15 minutes.",
        )
        .await
    }

    async fn revoke_token(&self) -> anyhow::Result<NodeControlReply> {
        let master = self.master.clone();
        let retire = blocking(move || {
            let guard = acquire_for_migration(&master)?;
            let mut state = load_state(&guard)?;
            let retire = state
                .bootstrap
                .as_ref()
                .filter(|authorization| authorization.claimed_by.is_none())
                .map(|authorization| authorization.endpoint);
            if state.bootstrap.as_ref().is_some_and(|authorization| authorization.claimed_by.is_some()) {
                anyhow::bail!("a claimed association cannot be revoked as an unused token; cancel its operation instead");
            }
            let has_management = state
                .peers
                .values()
                .any(|peer| peer.view.state != NodePeerState::Detached);
            state.bootstrap = None;
            if !has_management {
                state.control_endpoint = None;
                state.certificate_pem = None;
                state.private_key_pem = None;
                state.certificate_fingerprint = None;
            }
            save_state(&guard, &state)?;
            Ok(retire)
        })
        .await?;
        if let Some(endpoint) = retire {
            self.listeners.retire(endpoint).await?;
        }
        self.reply(None, None, "Unused association token revoked.")
            .await
    }

    async fn ensure_source_listener(
        &self,
        destination: SocketAddr,
    ) -> anyhow::Result<(SocketAddr, String)> {
        let master = self.master.clone();
        let existing = blocking(move || {
            let guard = acquire_for_migration(&master)?;
            let state = load_state(&guard)?;
            Ok(
                match (
                    state.control_endpoint,
                    state.certificate_pem,
                    state.private_key_pem,
                    state.certificate_fingerprint,
                ) {
                    (Some(endpoint), Some(cert), Some(key), Some(fingerprint)) => {
                        Some((endpoint, cert, key, fingerprint))
                    }
                    _ => None,
                },
            )
        })
        .await?;
        let needs_metadata = existing.is_none();
        let endpoint = if let Some((endpoint, ..)) = existing.as_ref() {
            *endpoint
        } else {
            let master = self.master.clone();
            blocking(move || preferred_source_endpoint(&master, destination)).await?
        };
        let transport_material = self.existing_listener_material(endpoint).await?;
        let generated = existing.is_none() && transport_material.is_none();
        let material = if let Some(material) = transport_material {
            material
        } else if let Some((endpoint, certificate, private_key, fingerprint)) = existing {
            ListenerMaterial {
                endpoint,
                certificate_pem: certificate,
                private_key_pem: private_key,
                fingerprint,
            }
        } else {
            let cert = super::certgen::generate_self_signed(
                &[super::certgen::San::Ip(endpoint.ip())],
                3650,
                time::OffsetDateTime::now_utc(),
            )?;
            ListenerMaterial {
                endpoint,
                certificate_pem: cert.cert_pem,
                private_key_pem: SecretString(cert.key_pem),
                fingerprint: cert.fingerprint_sha256,
            }
        };
        self.listeners
            .prepare(NodeListenerSpec {
                endpoint: material.endpoint,
                certificate_pem: material.certificate_pem.clone(),
                private_key_pem: material.private_key_pem.clone(),
                scope: ListenerScope::Management,
            })
            .await
            .context("Nodes source listener could not be prepared")?;
        if needs_metadata {
            let metadata_result = async {
                let identity = self.ensure_identity().await?;
                let metadata = super::lifecycle::preview_nodes_metadata(
                    &self.master,
                    identity.node_name,
                    Some(endpoint),
                )
                .await?;
                super::lifecycle::apply(&self.master, &metadata.id).await
            }
            .await;
            if let Err(error) = metadata_result {
                if generated {
                    let _ = self.listeners.retire(endpoint).await;
                }
                return Err(error.context("saving the Nodes source endpoint"));
            }
        }
        let master = self.master.clone();
        let saved = material.clone();
        if let Err(error) = blocking(move || {
            let guard = acquire_for_migration(&master)?;
            let mut state = load_state(&guard)?;
            state.control_endpoint = Some(saved.endpoint);
            state.certificate_pem = Some(saved.certificate_pem);
            state.private_key_pem = Some(saved.private_key_pem);
            state.certificate_fingerprint = Some(saved.fingerprint);
            save_state(&guard, &state)
        })
        .await
        {
            if generated {
                let _ = self.listeners.retire(endpoint).await;
            }
            return Err(error.context("saving the prepared Nodes source listener"));
        }
        Ok((endpoint, material.fingerprint))
    }

    async fn existing_listener_material(
        &self,
        endpoint: SocketAddr,
    ) -> anyhow::Result<Option<ListenerMaterial>> {
        self.listeners
            .existing_material(endpoint)
            .await?
            .map(listener_material_from_spec)
            .transpose()
    }

    async fn listener_material(&self, endpoint: SocketAddr) -> anyhow::Result<ListenerMaterial> {
        if let Some(material) = self.existing_listener_material(endpoint).await? {
            return Ok(material);
        }
        let certificate = super::certgen::generate_self_signed(
            &[super::certgen::San::Ip(endpoint.ip())],
            3650,
            time::OffsetDateTime::now_utc(),
        )?;
        Ok(ListenerMaterial {
            endpoint,
            certificate_pem: certificate.cert_pem,
            private_key_pem: SecretString(certificate.key_pem),
            fingerprint: certificate.fingerprint_sha256,
        })
    }

    async fn preview_add(
        &self,
        name: String,
        endpoint: SocketAddr,
        encoded: SecretString,
    ) -> anyhow::Result<NodeControlReply> {
        super::membership::validate_name(&name)?;
        let now = super::membership::now()?;
        let token = BootstrapToken::decode(&encoded, now)?;
        ensure!(
            token.endpoint == endpoint,
            "destination does not match the association token"
        );
        self.restart.preflight().await?;
        let local = self.ensure_identity().await?;
        ensure!(
            matches!(local.saved_role, NodeRole::Standalone | NodeRole::Primary),
            "only a standalone node or primary can add a node"
        );
        let primary_already_active = local.saved_role == NodeRole::Primary
            && !local.restart_required
            && self.active.active_pair().is_some();
        let source_has_membership = local.saved_role == NodeRole::Primary;
        let source_node_id = local.node_id.context("local node identity absent")?;
        ensure!(
            source_node_id != token.target_node_id,
            "a node cannot add itself"
        );
        let (source_endpoint, source_fingerprint) = self.ensure_source_listener(endpoint).await?;
        let staged_pair = self.active.enrollment_pair().await?;
        let operation_id = super::membership::random_id();
        let (source_secret, _) = generate_token();
        let source_credential = SecretString(source_secret);
        let request = BootstrapClaimRequest {
            token: token.secret.clone(),
            operation_id: operation_id.clone(),
            source_node_id: source_node_id.clone(),
            source_name: local.node_name.clone(),
            source_endpoint,
            source_fingerprint: source_fingerprint.clone(),
            source_credential: source_credential.clone(),
        };
        let response: BootstrapClaimResponse = post_pinned(
            endpoint,
            &token.fingerprint,
            "/api/nodes/v2/bootstrap/claim",
            None,
            &request,
        )
        .await
        .context("destination TLS bootstrap failed before association")?;
        ensure!(
            response.target_node_id == token.target_node_id,
            "destination identity differs from the token"
        );
        ensure!(
            response.target_role == NodeRole::Standalone,
            "destination already belongs to a cluster"
        );
        ensure!(
            response.capabilities.supports_v2_management(),
            "destination requires an upgrade before Add Node"
        );
        let before_revision = local_revision(&self.master).await?;
        let preview = NodePreview {
            id: operation_id.clone(),
            kind: NodeOperationKind::Add,
            source_node_id: source_node_id.clone(),
            source_name: local.node_name,
            source_endpoint: Some(source_endpoint),
            target_node_id: response.target_node_id.clone(),
            target_name: name.clone(),
            target_endpoint: endpoint,
            target_role: response.target_role,
            replacement_summary: vec![
                format!(
                    "Replace policy on {name} with exact policy {} and corpus {}.",
                    staged_pair.policy.artifact_hash, staged_pair.corpus_generation
                ),
                "Keep destination-local settings and create a verified transaction backup.".into(),
                "Activate and verify the primary before restarting the destination.".into(),
            ],
            restart_steps: vec![
                NodeRestartStep {
                    step_id: "primary".into(),
                    target: NodeRestartTarget::Primary,
                    requested: false,
                    acknowledged: primary_already_active,
                },
                NodeRestartStep {
                    step_id: "secondary".into(),
                    target: NodeRestartTarget::Secondary,
                    requested: false,
                    acknowledged: false,
                },
            ],
            before_revision,
            // This is not reviewable until the target verifies its private
            // backup. `Prepared` receives a fresh, ordinary review deadline.
            expires_at: now.checked_add(RECOVERY_TTL).context("clock overflow")?,
        };
        let cluster_id = local
            .cluster_id
            .clone()
            .unwrap_or_else(super::membership::random_id);
        let replication_credential = SecretString(generate_token().0);
        let record = OperationRecord {
            preview: preview.clone(),
            phase: NodeOperationPhase::PreparingTarget,
            paused_from: None,
            message: "Association prepared; no membership or policy has been applied.".into(),
            last_verified_at: Some(now),
            recover_until: Some(now.checked_add(RECOVERY_TTL).context("clock overflow")?),
            peer_preview_id: None,
            local_preview_id: None,
            staged_pair: Some(staged_pair.clone()),
            prepared_certificate: None,
            prepared_private_key: None,
            prepared_fingerprint: None,
            restart_requested_at: BTreeMap::new(),
            cluster_id: Some(cluster_id.clone()),
            replication_credential: Some(replication_credential.clone()),
            backup_verified: false,
            cancel_requested: false,
        };
        let peer = PeerRecord {
            view: NodePeer {
                node_id: response.target_node_id.clone(),
                name,
                endpoint,
                role: NodeRole::Standalone,
                state: NodePeerState::Pending,
                capabilities: response.capabilities,
                last_seen_at: Some(now),
                last_error: None,
            },
            outgoing_credential: response.target_credential,
            incoming_credential_hash: hash_token(&source_credential.0),
            issued_incoming_credential: Some(source_credential.clone()),
            source_fingerprint: token.fingerprint,
        };
        let master = self.master.clone();
        blocking(move || {
            let guard = acquire_for_migration(&master)?;
            let mut state = load_state(&guard)?;
            ensure!(
                state
                    .peers
                    .get(&peer.view.node_id)
                    .is_none_or(|existing| existing.view.state == NodePeerState::Detached),
                "node removal has not completed; wait for its detach receipt before adding it again"
            );
            if source_has_membership {
                let membership = super::membership::MembershipStore::open(&guard)?;
                ensure!(
                    membership
                        .views(super::membership::now()?)
                        .into_iter()
                        .find(|member| member.node_id == peer.view.node_id)
                        .is_none_or(|member| {
                            member.state == super::membership::MemberState::Revoked
                        }),
                    "node membership is still active or pending removal"
                );
            }
            ensure!(
                state.operations.len() < MAX_OPERATIONS,
                "too many retained Nodes operations"
            );
            state.peers.insert(peer.view.node_id.clone(), peer);
            state.operations.insert(operation_id, record);
            save_state(&guard, &state)
        })
        .await?;
        let peer = self.peer(&response.target_node_id).await?;
        let staged = send_management(
            &peer,
            &PeerManagementRequest::PrepareAdd {
                operation_id: preview.id.clone(),
                name: preview.target_name.clone(),
                cluster_id,
                primary_node_id: preview.source_node_id.clone(),
                primary_endpoint: source_endpoint,
                primary_fingerprint: source_fingerprint,
                staged_pair: Box::new(staged_pair),
                replication_credential,
            },
        )
        .await
        .context("destination could not stage the reviewed policy and backup")?;
        ensure!(
            staged.backup_verified && staged.preview_id.is_some(),
            "destination did not verify its replacement backup"
        );
        let mut operation = self.operation(&preview.id).await?;
        operation.peer_preview_id = staged.preview_id;
        operation.backup_verified = true;
        operation.phase = NodeOperationPhase::Prepared;
        operation.preview.expires_at = super::membership::now()?
            .checked_add(PREVIEW_TTL)
            .context("clock overflow")?;
        operation.message = "Exact policy and corpus plus a verified destination backup are staged; no membership is active.".into();
        let review = operation.preview.clone();
        self.save_operation(operation).await?;
        self.reply(Some(review), None, "Review prepared Add Node operation.")
            .await
    }

    async fn preview_edit(
        &self,
        node_id: String,
        name: String,
        endpoint: Option<SocketAddr>,
    ) -> anyhow::Result<NodeControlReply> {
        ensure!(
            super::membership::valid_id(&node_id),
            "invalid node identity"
        );
        super::membership::validate_name(&name)?;
        if let Some(endpoint) = endpoint {
            ensure!(
                endpoint.port() != 0
                    && !endpoint.ip().is_unspecified()
                    && !endpoint.ip().is_multicast(),
                "invalid Nodes control endpoint"
            );
        }
        let local = self.ensure_identity().await?;
        let local_id = local
            .node_id
            .clone()
            .context("local node identity absent")?;
        let now = super::membership::now()?;
        let recover_until = now.checked_add(RECOVERY_TTL).context("clock overflow")?;
        let master = self.master.clone();
        let requested_node_id = node_id.clone();
        let (peer, control_endpoint, fallback_endpoint, mut all_peers_ready, ready_peer_ids) =
            blocking(move || {
                let guard = acquire_for_migration(&master)?;
                let state = load_state(&guard)?;
                let fallback = load_config(&guard)?.config.api.listen;
                let peer = state.peers.get(&requested_node_id).cloned();
                let ready_peer_ids: BTreeSet<_> = state
                    .peers
                    .values()
                    .filter(|peer| {
                        peer.view.state == NodePeerState::Active
                            && peer.view.capabilities.endpoint_transition
                            && peer
                                .view
                                .last_seen_at
                                .is_some_and(|seen| now.saturating_sub(seen) <= 45)
                    })
                    .map(|peer| peer.view.node_id.clone())
                    .collect();
                let all_ready = state
                    .peers
                    .values()
                    .filter(|peer| peer.view.state != NodePeerState::Detached)
                    .all(|peer| ready_peer_ids.contains(&peer.view.node_id));
                Ok((
                    peer,
                    state.control_endpoint,
                    fallback,
                    all_ready,
                    ready_peer_ids,
                ))
            })
            .await?;
        all_peers_ready &= local
            .roster
            .iter()
            .filter(|member| member.state != super::membership::MemberState::Revoked)
            .all(|member| ready_peer_ids.contains(&member.node_id));
        ensure!(
            local.saved_role == NodeRole::Primary
                || (local.saved_role == NodeRole::Standalone && node_id == local_id),
            "edit this clustered node from its primary"
        );
        let target_endpoint = endpoint
            .or_else(|| peer.as_ref().map(|peer| peer.view.endpoint))
            .or(control_endpoint)
            .unwrap_or(fallback_endpoint);
        let target_role = if node_id == local_id {
            local.saved_role
        } else {
            peer.as_ref().context("unknown node identity")?.view.role
        };
        let current_target_endpoint = if node_id == local_id {
            control_endpoint
        } else {
            peer.as_ref().map(|peer| peer.view.endpoint)
        };
        let endpoint_changed = endpoint.is_some_and(|value| Some(value) != current_target_endpoint);
        if node_id == local_id && local.saved_role == NodeRole::Primary && endpoint_changed {
            ensure!(
                all_peers_ready,
                "all secondaries must be online and endpoint-transition capable before changing the primary endpoint"
            );
        }
        if node_id == local_id && endpoint_changed {
            self.restart.preflight().await?;
        }
        let operation_id = super::membership::random_id();
        let local_edit = node_id == local_id;
        let mut prepared_certificate = None;
        let mut prepared_private_key = None;
        let mut prepared_fingerprint = None;
        let peer_preview_id = if node_id == local_id {
            if endpoint_changed {
                let material = self.listener_material(target_endpoint).await?;
                self.listeners
                    .prepare(NodeListenerSpec {
                        endpoint: target_endpoint,
                        certificate_pem: material.certificate_pem.clone(),
                        private_key_pem: material.private_key_pem.clone(),
                        scope: ListenerScope::Management,
                    })
                    .await?;
                prepared_certificate = Some(material.certificate_pem);
                prepared_private_key = Some(material.private_key_pem);
                prepared_fingerprint = Some(material.fingerprint);
            }
            let preview = super::lifecycle::preview_nodes_metadata(
                &self.master,
                name.clone(),
                endpoint_changed.then_some(target_endpoint),
            )
            .await;
            let preview = match preview {
                Ok(preview) => preview,
                Err(error) => {
                    if endpoint_changed {
                        let _ = self.listeners.retire(target_endpoint).await;
                    }
                    return Err(error.context("preparing local node Edit"));
                }
            };
            Some(preview.id)
        } else {
            let peer = peer.as_ref().context("unknown node identity")?;
            ensure!(
                peer.view.capabilities.supports_v2_management(),
                "node requires an explicit capability upgrade before Edit"
            );
            let reply = send_management(
                peer,
                &PeerManagementRequest::PrepareEdit {
                    operation_id: operation_id.clone(),
                    name: name.clone(),
                    endpoint,
                },
            )
            .await?;
            reply.preview_id
        };
        let preview = NodePreview {
            id: operation_id.clone(),
            kind: NodeOperationKind::Edit,
            source_node_id: local_id,
            source_name: local.node_name,
            source_endpoint: control_endpoint,
            target_node_id: node_id,
            target_name: name,
            target_endpoint,
            target_role,
            replacement_summary: vec![
                "Preserve the stable Node ID while changing the reviewed name or endpoint.".into(),
                "Keep the old endpoint trusted until the new connection is acknowledged.".into(),
            ],
            restart_steps: vec![NodeRestartStep {
                step_id: "endpoint".into(),
                target: if target_role == NodeRole::Primary {
                    NodeRestartTarget::Primary
                } else {
                    NodeRestartTarget::Secondary
                },
                requested: false,
                acknowledged: !endpoint_changed,
            }],
            before_revision: local_revision(&self.master).await?,
            expires_at: now.checked_add(PREVIEW_TTL).context("clock overflow")?,
        };
        let record = OperationRecord {
            preview: preview.clone(),
            phase: NodeOperationPhase::Prepared,
            paused_from: None,
            message: "Node edit prepared; the active endpoint is unchanged.".into(),
            last_verified_at: Some(now),
            recover_until: Some(recover_until),
            peer_preview_id: peer_preview_id.clone(),
            local_preview_id: None,
            staged_pair: self.active.active_pair(),
            prepared_certificate,
            prepared_private_key,
            prepared_fingerprint,
            restart_requested_at: BTreeMap::new(),
            cluster_id: None,
            replication_credential: None,
            backup_verified: false,
            cancel_requested: false,
        };
        if let Err(error) = self.insert_operation(record).await {
            if local_edit {
                if let Some(preview_id) = peer_preview_id.as_deref() {
                    let _ = super::lifecycle::cancel(&self.master, preview_id).await;
                }
                if endpoint_changed {
                    let _ = self.listeners.retire(target_endpoint).await;
                }
            }
            return Err(error.context("saving prepared Edit"));
        }
        self.reply(Some(preview), None, "Review prepared Edit Node operation.")
            .await
    }

    async fn preview_remove(&self, node_id: String) -> anyhow::Result<NodeControlReply> {
        ensure!(
            super::membership::valid_id(&node_id),
            "invalid node identity"
        );
        let local = self.ensure_identity().await?;
        let local_id = local
            .node_id
            .clone()
            .context("local node identity absent")?;
        ensure!(node_id != local_id, "the local node cannot remove itself");
        ensure!(
            local.saved_role == NodeRole::Primary,
            "only the primary can remove another node"
        );
        self.restart.preflight().await?;
        let master = self.master.clone();
        let requested_node_id = node_id.clone();
        let peer = blocking(move || {
            let guard = acquire_for_migration(&master)?;
            load_state(&guard)?
                .peers
                .get(&requested_node_id)
                .cloned()
                .context("unknown node identity")
        })
        .await?;
        let operation_id = super::membership::random_id();
        let peer_preview_id = match send_management(
            &peer,
            &PeerManagementRequest::PrepareRemove {
                operation_id: operation_id.clone(),
            },
        )
        .await
        {
            Ok(reply) => reply.preview_id,
            Err(_) => None,
        };
        let now = super::membership::now()?;
        let recover_until = now.checked_add(RECOVERY_TTL).context("clock overflow")?;
        let preview = NodePreview {
            id: operation_id.clone(),
            kind: NodeOperationKind::Remove,
            source_node_id: local_id,
            source_name: local.node_name,
            source_endpoint: None,
            target_node_id: node_id,
            target_name: peer.view.name.clone(),
            target_endpoint: peer.view.endpoint,
            target_role: peer.view.role,
            replacement_summary: vec![
                "Revoke new policy delivery immediately.".into(),
                "Return an online secondary to standalone with its last complete policy.".into(),
                "Keep an offline removal pending until the detach receipt arrives.".into(),
            ],
            restart_steps: vec![NodeRestartStep {
                step_id: "detach".into(),
                target: NodeRestartTarget::Secondary,
                requested: false,
                acknowledged: false,
            }],
            before_revision: local_revision(&self.master).await?,
            expires_at: now.checked_add(PREVIEW_TTL).context("clock overflow")?,
        };
        self.insert_operation(OperationRecord {
            preview: preview.clone(),
            phase: NodeOperationPhase::Prepared,
            paused_from: None,
            message: if peer_preview_id.is_some() {
                "Online detach prepared; active policy is unchanged.".into()
            } else {
                "Peer is offline; apply will revoke delivery and retain a pending detach.".into()
            },
            last_verified_at: peer_preview_id.as_ref().map(|_| now),
            recover_until: Some(recover_until),
            peer_preview_id,
            local_preview_id: None,
            staged_pair: self.active.active_pair(),
            prepared_certificate: None,
            prepared_private_key: None,
            prepared_fingerprint: None,
            restart_requested_at: BTreeMap::new(),
            cluster_id: None,
            replication_credential: None,
            backup_verified: false,
            cancel_requested: false,
        })
        .await?;
        self.reply(
            Some(preview),
            None,
            "Review prepared Remove Node operation.",
        )
        .await
    }

    async fn insert_operation(&self, record: OperationRecord) -> anyhow::Result<()> {
        let master = self.master.clone();
        blocking(move || {
            let guard = acquire_for_migration(&master)?;
            let mut state = load_state(&guard)?;
            ensure!(
                state.operations.len() < MAX_OPERATIONS,
                "too many retained Nodes operations"
            );
            ensure!(
                state
                    .operations
                    .values()
                    .all(|existing| existing.phase.terminal()
                        || existing.preview.target_node_id != record.preview.target_node_id),
                "another operation is already pending for this node"
            );
            state.operations.insert(record.preview.id.clone(), record);
            save_state(&guard, &state)
        })
        .await
    }

    async fn apply(&self, operation_id: &str) -> anyhow::Result<NodeControlReply> {
        let operation = self.operation(operation_id).await?;
        ensure!(
            operation.phase == NodeOperationPhase::Prepared,
            "operation was already applied; use Resume to continue its durable state"
        );
        ensure!(
            !operation.cancel_requested,
            "cancellation is pending; wait for the destination acknowledgement"
        );
        ensure!(
            operation.preview.expires_at > super::membership::now()?,
            "review expired; prepare and confirm it again"
        );
        ensure!(
            operation.preview.before_revision == local_revision(&self.master).await?,
            "configuration changed since review; prepare it again"
        );
        match operation.preview.kind {
            NodeOperationKind::Add => self.apply_add(operation).await?,
            NodeOperationKind::Edit => self.apply_edit(operation).await?,
            NodeOperationKind::Remove => self.apply_remove(operation).await?,
        }
        self.reply(
            None,
            None,
            "Operation accepted; durable progress continues in the daemon.",
        )
        .await
    }

    async fn apply_add(&self, mut operation: OperationRecord) -> anyhow::Result<()> {
        self.arm_prepared_add_target(&operation).await?;
        let local = {
            let master = self.master.clone();
            blocking(move || super::lifecycle::status(&master)).await?
        };
        if local.saved_role == NodeRole::Standalone {
            let restart_permit = self.restart.preflight().await?;
            let master = self.master.clone();
            let (certificate, private_key, fingerprint) = blocking(move || {
                let guard = acquire_for_migration(&master)?;
                let state = load_state(&guard)?;
                Ok((
                    state.certificate_pem.context("Nodes certificate absent")?,
                    state.private_key_pem.context("Nodes private key absent")?,
                    state
                        .certificate_fingerprint
                        .context("Nodes certificate fingerprint absent")?,
                ))
            })
            .await?;
            let endpoint = operation
                .preview
                .source_endpoint
                .context("source Nodes endpoint absent")?;
            let preview = super::lifecycle::preview_nodes_primary(
                &self.master,
                super::lifecycle::NodesPrimaryMaterial {
                    cluster_id: operation
                        .cluster_id
                        .clone()
                        .context("prepared cluster identity absent")?,
                    endpoint,
                    certificate,
                    private_key,
                    fingerprint,
                },
            )
            .await?;
            operation.local_preview_id = Some(preview.id.clone());
            operation.phase = NodeOperationPhase::ApplyingPrimary;
            operation.message =
                "Applying primary membership with the reviewed local policy.".into();
            self.save_operation(operation.clone()).await?;
            super::lifecycle::apply(&self.master, &preview.id).await?;
            self.admit_prepared_target(&operation).await?;
            operation.phase = NodeOperationPhase::RestartingPrimary;
            operation.message =
                "Primary membership saved; waiting for its verified restart.".into();
            self.persist_restart_request(&mut operation, "primary")
                .await?;
            self.restart
                .request(
                    restart_permit,
                    super::managed_restart::ManagedRestartRequest {
                        operation_id: operation.preview.id,
                        step_id: "primary".into(),
                    },
                )
                .await?;
            return Ok(());
        }
        ensure!(
            local.saved_role == NodeRole::Primary,
            "Add Node requires the primary"
        );
        let needs_primary_restart = local.restart_required || self.active.active_pair().is_none();
        let restart_permit = if needs_primary_restart {
            Some(self.restart.preflight().await?)
        } else {
            None
        };
        operation.phase = NodeOperationPhase::ApplyingPrimary;
        operation.message = "Committing the reviewed target admission on the primary.".into();
        self.save_operation(operation.clone()).await?;
        self.admit_prepared_target(&operation).await?;
        if needs_primary_restart {
            operation.phase = NodeOperationPhase::RestartingPrimary;
            operation.message =
                "Prepared primary membership retained; waiting for verified activation.".into();
            self.persist_restart_request(&mut operation, "primary")
                .await?;
            self.restart
                .request(
                    restart_permit.context("managed restart permit absent")?,
                    super::managed_restart::ManagedRestartRequest {
                        operation_id: operation.preview.id,
                        step_id: "primary".into(),
                    },
                )
                .await?;
            return Ok(());
        }
        self.apply_prepared_target(operation).await
    }

    async fn apply_prepared_target(&self, mut operation: OperationRecord) -> anyhow::Result<()> {
        let target_phase = self.arm_prepared_add_target(&operation).await?;
        if target_phase != NodeOperationPhase::Prepared {
            operation.phase = target_phase;
            operation.last_verified_at = Some(super::membership::now()?);
            operation.message = "Destination Add recovery was already in progress.".into();
            if target_phase == NodeOperationPhase::Complete {
                operation.acknowledge_secondary_restart();
                self.activate_peer(&operation.preview.target_node_id)
                    .await?;
            }
            return self.save_operation(operation).await;
        }
        let staged = operation
            .staged_pair
            .as_ref()
            .context("reviewed policy and corpus identity absent")?;
        let active = self
            .active
            .active_pair()
            .context("primary has not activated a policy and corpus pair")?;
        ensure!(
            reviewed_pair_matches(&self.master, staged, &active)?,
            "active policy or corpus changed since review; prepare Add Node again"
        );
        ensure!(
            operation.backup_verified,
            "destination backup was not verified before apply"
        );
        let peer = self.peer(&operation.preview.target_node_id).await?;
        let peer_preview_id = operation
            .peer_preview_id
            .clone()
            .context("destination lifecycle preview absent")?;
        operation.phase = NodeOperationPhase::ApplyingTarget;
        operation.last_verified_at = Some(super::membership::now()?);
        operation.message =
            "Destination staged the reviewed policy and corpus; applying membership.".into();
        self.save_operation(operation.clone()).await?;
        let response = send_management(
            &peer,
            &PeerManagementRequest::Apply {
                operation_id: operation.preview.id.clone(),
                preview_id: peer_preview_id,
            },
        )
        .await?;
        operation.phase = if response
            .operation
            .as_ref()
            .is_some_and(|progress| progress.phase == NodeOperationPhase::Complete)
        {
            NodeOperationPhase::Complete
        } else {
            NodeOperationPhase::RestartingTarget
        };
        operation.message = if operation.phase == NodeOperationPhase::Complete {
            operation.acknowledge_secondary_restart();
            self.activate_peer(&operation.preview.target_node_id)
                .await?;
            "Destination acknowledged its verified restart.".into()
        } else {
            "Destination membership saved; waiting for its verified restart.".into()
        };
        self.save_operation(operation).await
    }

    async fn arm_prepared_add_target(
        &self,
        operation: &OperationRecord,
    ) -> anyhow::Result<NodeOperationPhase> {
        ensure!(
            operation.preview.kind == NodeOperationKind::Add && operation.backup_verified,
            "destination Add review is incomplete"
        );
        let peer = self.peer(&operation.preview.target_node_id).await?;
        let preview_id = operation
            .peer_preview_id
            .clone()
            .context("destination lifecycle preview absent")?;
        let response = send_management(
            &peer,
            &PeerManagementRequest::ArmAddRecovery {
                operation_id: operation.preview.id.clone(),
                preview_id: preview_id.clone(),
            },
        )
        .await?;
        let phase = response
            .operation
            .as_ref()
            .map(|progress| progress.phase)
            .context("destination Add recovery progress absent")?;
        ensure!(
            response.preview_id.as_deref() == Some(preview_id.as_str())
                && response.backup_verified
                && matches!(
                    phase,
                    NodeOperationPhase::Prepared
                        | NodeOperationPhase::ApplyingTarget
                        | NodeOperationPhase::RestartingTarget
                        | NodeOperationPhase::Complete
                ),
            "destination did not durably arm the reviewed Add recovery"
        );
        Ok(phase)
    }

    async fn admit_prepared_target(&self, operation: &OperationRecord) -> anyhow::Result<()> {
        let operation = operation.clone();
        let master = self.master.clone();
        blocking(move || {
            let guard = acquire_for_migration(&master)?;
            let mut membership = super::membership::MembershipStore::open(&guard)?;
            membership.admit_prepared(
                &operation.preview.id,
                &operation.preview.target_node_id,
                &operation.preview.target_name,
                operation.preview.target_endpoint,
                operation
                    .replication_credential
                    .as_ref()
                    .context("prepared replication credential absent")?,
                super::membership::now()?,
            )?;
            Ok(())
        })
        .await
    }

    async fn apply_edit(&self, mut operation: OperationRecord) -> anyhow::Result<()> {
        let local_id = {
            let master = self.master.clone();
            blocking(move || super::lifecycle::status(&master))
                .await?
                .node_id
        };
        if local_id.as_deref() == Some(&operation.preview.target_node_id) {
            let restart_permit = if operation.prepared_certificate.is_some() {
                Some(self.restart.preflight().await?)
            } else {
                None
            };
            let preview_id = operation
                .peer_preview_id
                .clone()
                .context("local edit preview absent")?;
            operation.phase = match operation.preview.target_role {
                NodeRole::Primary => NodeOperationPhase::ApplyingPrimary,
                _ => NodeOperationPhase::ApplyingTarget,
            };
            operation.message = "Applying the reviewed local node metadata.".into();
            self.save_operation(operation.clone()).await?;
            super::lifecycle::apply(&self.master, &preview_id).await?;
            if let (Some(cert), Some(key), Some(fingerprint)) = (
                operation.prepared_certificate.clone(),
                operation.prepared_private_key.clone(),
                operation.prepared_fingerprint.clone(),
            ) {
                let master = self.master.clone();
                let endpoint = operation.preview.target_endpoint;
                blocking(move || {
                    let guard = acquire_for_migration(&master)?;
                    let mut state = load_state(&guard)?;
                    promote_listener(&mut state, endpoint, cert, key, fingerprint)?;
                    save_state(&guard, &state)
                })
                .await?;
                operation.phase = match operation.preview.target_role {
                    NodeRole::Primary => NodeOperationPhase::RestartingPrimary,
                    _ => NodeOperationPhase::RestartingTarget,
                };
                self.persist_restart_request(&mut operation, "endpoint")
                    .await?;
                self.restart
                    .request(
                        restart_permit.context("managed restart permit absent")?,
                        super::managed_restart::ManagedRestartRequest {
                            operation_id: operation.preview.id,
                            step_id: "endpoint".into(),
                        },
                    )
                    .await?;
            } else {
                operation.phase = NodeOperationPhase::Complete;
                operation.message = "Node name updated; stable identity retained.".into();
                self.save_operation(operation).await?;
            }
            return Ok(());
        }
        let peer = self.peer(&operation.preview.target_node_id).await?;
        let preview_id = operation
            .peer_preview_id
            .clone()
            .context("peer edit preview absent")?;
        operation.phase = NodeOperationPhase::ApplyingTarget;
        operation.message = "Applying the reviewed peer metadata.".into();
        self.save_operation(operation.clone()).await?;
        let response = send_management(
            &peer,
            &PeerManagementRequest::Apply {
                operation_id: operation.preview.id.clone(),
                preview_id,
            },
        )
        .await?;
        if operation.preview.target_endpoint != peer.view.endpoint {
            operation.prepared_fingerprint = response.control_fingerprint.clone();
            ensure!(
                response.control_endpoint == Some(operation.preview.target_endpoint)
                    && operation.prepared_fingerprint.is_some(),
                "peer did not return its prepared endpoint identity"
            );
        }
        operation.phase = response
            .operation
            .map_or(NodeOperationPhase::RestartingTarget, |progress| {
                progress.phase
            });
        if operation.phase == NodeOperationPhase::Complete {
            self.persist_verified_peer_name(&operation).await?;
        }
        operation.message =
            "Peer edit applied; waiting for verified endpoint acknowledgement.".into();
        self.save_operation(operation).await
    }

    async fn apply_remove(&self, mut operation: OperationRecord) -> anyhow::Result<()> {
        operation.phase = NodeOperationPhase::AwaitingDetach;
        operation.message = "Revoking policy delivery before requesting the detach receipt.".into();
        self.save_operation(operation.clone()).await?;
        self.ensure_remove_revoked(&operation).await?;
        operation.message =
            "Policy delivery revoked; waiting for the secondary detach receipt.".into();
        self.save_operation(operation.clone()).await?;
        if let Some(preview_id) = operation.peer_preview_id.clone() {
            let peer = self.peer(&operation.preview.target_node_id).await?;
            if let Ok(response) = send_management(
                &peer,
                &PeerManagementRequest::Apply {
                    operation_id: operation.preview.id.clone(),
                    preview_id,
                },
            )
            .await
            {
                if response
                    .operation
                    .is_some_and(|progress| progress.phase == NodeOperationPhase::Complete)
                {
                    send_management(
                        &peer,
                        &PeerManagementRequest::AcknowledgeDetach {
                            operation_id: operation.preview.id.clone(),
                        },
                    )
                    .await?;
                    self.complete_detach(operation).await?;
                }
            }
        }
        Ok(())
    }

    async fn ensure_remove_revoked(&self, operation: &OperationRecord) -> anyhow::Result<()> {
        let revoke = super::lifecycle::preview(
            &self.master,
            LifecycleRequest::Revoke {
                node_id: operation.preview.target_node_id.clone(),
            },
        )
        .await?;
        super::lifecycle::apply(&self.master, &revoke.id).await?;
        let master = self.master.clone();
        let node_id = operation.preview.target_node_id.clone();
        blocking(move || {
            let guard = acquire_for_migration(&master)?;
            let mut state = load_state(&guard)?;
            let peer = state
                .peers
                .get_mut(&node_id)
                .context("managed peer absent")?;
            peer.view.state = NodePeerState::PendingDetach;
            save_state(&guard, &state)
        })
        .await
    }

    async fn cancel(&self, operation_id: &str) -> anyhow::Result<NodeControlReply> {
        let mut operation = self.operation(operation_id).await?;
        if operation.phase == NodeOperationPhase::Cancelled {
            ensure!(
                operation.preview.kind == NodeOperationKind::Add && operation.cancel_requested,
                "an applied operation cannot be cancelled; use Resume for recovery"
            );
            self.finish_cancelled_add_source_cleanup(&operation).await?;
            return self.reply(None, None, "Preview cancelled.").await;
        }
        ensure!(
            matches!(
                operation.phase,
                NodeOperationPhase::PreparingTarget | NodeOperationPhase::Prepared
            ) || (operation.phase == NodeOperationPhase::Paused
                && matches!(
                    operation.paused_from,
                    Some(NodeOperationPhase::PreparingTarget | NodeOperationPhase::Prepared)
                )
                && operation.preview.kind == NodeOperationKind::Add),
            "an applied operation cannot be cancelled; use Resume for recovery"
        );
        operation.cancel_requested = true;
        operation.message = "Cancellation requested; awaiting destination acknowledgement. Active policy is unchanged.".into();
        self.save_operation(operation.clone()).await?;
        if operation.preview.target_node_id == operation.preview.source_node_id {
            if let Some(preview_id) = operation.peer_preview_id.clone() {
                super::lifecycle::cancel(&self.master, &preview_id).await?;
            }
        } else {
            let peer = match self.peer(&operation.preview.target_node_id).await {
                Ok(peer) => peer,
                Err(error) => {
                    return self
                        .reply(
                            None,
                            None,
                            format!(
                                "Cancellation is pending because the destination cannot be reached: {error}"
                            ),
                        )
                        .await;
                }
            };
            if let Err(error) = send_management(
                &peer,
                &PeerManagementRequest::Cancel {
                    operation_id: operation.preview.id.clone(),
                    preview_id: operation.peer_preview_id.clone(),
                },
            )
            .await
            {
                return self.reply(None, None, format!(
                    "Cancellation is pending because the destination did not acknowledge it: {error}"
                )).await;
            }
        }
        operation.phase = NodeOperationPhase::Cancelled;
        operation.message = "Preview cancelled; membership and active policy are unchanged.".into();
        self.save_operation(operation.clone()).await?;
        if operation.preview.kind == NodeOperationKind::Add {
            self.finish_cancelled_add_source_cleanup(&operation).await?;
        } else {
            self.retire_prepared_listener(&operation.preview.id).await?;
        }
        self.reply(None, None, "Preview cancelled.").await
    }

    async fn abandon_preparing_add(&self, operation_id: &str) -> anyhow::Result<NodeControlReply> {
        let operation = self.operation(operation_id).await?;
        let local = self.ensure_identity().await?;
        let local_id = local.node_id.context("local node identity absent")?;
        ensure!(
            local.saved_role == NodeRole::Standalone
                && operation.preview.kind == NodeOperationKind::Add
                && operation.preview.target_node_id == local_id
                && (matches!(
                    operation.phase,
                    NodeOperationPhase::PreparingTarget | NodeOperationPhase::Prepared
                ) || (operation.phase == NodeOperationPhase::Paused
                    && matches!(
                        operation.paused_from,
                        Some(NodeOperationPhase::PreparingTarget | NodeOperationPhase::Prepared)
                    ))),
            "only this standalone target's unapplied pending Add can be abandoned"
        );
        let master = self.master.clone();
        let id = operation_id.to_owned();
        let local_id_for_check = local_id.clone();
        blocking(move || {
            let guard = acquire_for_migration(&master)?;
            let state = load_state(&guard)?;
            let operation = state
                .operations
                .get(&id)
                .context("Nodes operation disappeared")?;
            ensure!(
                operation.preview.kind == NodeOperationKind::Add
                    && operation.preview.target_node_id == local_id_for_check
                    && (matches!(
                        operation.phase,
                        NodeOperationPhase::PreparingTarget | NodeOperationPhase::Prepared
                    ) || (operation.phase == NodeOperationPhase::Paused
                        && matches!(
                            operation.paused_from,
                            Some(
                                NodeOperationPhase::PreparingTarget | NodeOperationPhase::Prepared
                            )
                        ))),
                "operation changed while abandoning it"
            );
            ensure!(
                state
                    .peers
                    .get(&operation.preview.source_node_id)
                    .is_some_and(|peer| peer.view.state == NodePeerState::Pending),
                "only an exact pending enrollment may be abandoned"
            );
            Ok(())
        })
        .await?;
        let lifecycle_id = operation
            .peer_preview_id
            .as_deref()
            .unwrap_or(operation.preview.id.as_str());
        super::lifecycle::cancel_nodes_staged_join_if_present(
            &self.master,
            lifecycle_id,
            &operation.preview.id,
        )
        .await?;
        let master = self.master.clone();
        let pin_owner = operation.preview.id.clone();
        blocking(move || {
            if let Some(store) = super::corpus::CorpusStore::open_existing(&master)? {
                store.release_private_manifest_pin(&pin_owner)?;
            }
            Ok(())
        })
        .await?;
        let master = self.master.clone();
        let id = operation_id.to_owned();
        blocking(move || {
            let guard = acquire_for_migration(&master)?;
            let mut state = load_state(&guard)?;
            let source_id = {
                let operation = state
                    .operations
                    .get_mut(&id)
                    .context("Nodes operation disappeared")?;
                ensure!(
                    operation.preview.kind == NodeOperationKind::Add
                        && operation.preview.target_node_id == local_id
                        && (matches!(
                            operation.phase,
                            NodeOperationPhase::PreparingTarget | NodeOperationPhase::Prepared
                        ) || (operation.phase == NodeOperationPhase::Paused
                            && matches!(
                                operation.paused_from,
                                Some(
                                    NodeOperationPhase::PreparingTarget
                                        | NodeOperationPhase::Prepared
                                )
                            ))),
                    "operation changed while abandoning it"
                );
                let source_id = operation.preview.source_node_id.clone();
                operation.cancel_requested = true;
                operation.phase = NodeOperationPhase::Cancelled;
                operation.message =
                    "Target-local pending enrollment abandoned; active policy unchanged.".into();
                source_id
            };
            let peer = state
                .peers
                .get_mut(&source_id)
                .context("pending enrollment peer disappeared")?;
            ensure!(
                peer.view.state == NodePeerState::Pending,
                "only an exact pending enrollment may be abandoned"
            );
            peer.view.state = NodePeerState::Detached;
            if state
                .bootstrap
                .as_ref()
                .is_some_and(|bootstrap| bootstrap.operation_id.as_deref() == Some(&id))
            {
                state.bootstrap = None;
            }
            save_state(&guard, &state)
        })
        .await?;
        self.reply(None, None, "Target-local pending enrollment abandoned.")
            .await
    }

    async fn resume(&self, operation_id: &str) -> anyhow::Result<NodeControlReply> {
        let mut operation = self.operation(operation_id).await?;
        if operation.cancel_requested {
            return self.cancel(operation_id).await;
        }
        let mut expired_add_review = false;
        if operation.phase == NodeOperationPhase::Paused {
            let previous = operation
                .paused_from
                .take()
                .context("expired review must be prepared again")?;
            ensure!(
                self.operation_has_persistent_peer(&operation).await?,
                "durable recovery requires its authenticated managed peer"
            );
            expired_add_review = previous == NodeOperationPhase::Prepared
                && operation.preview.kind == NodeOperationKind::Add;
            operation.phase = previous;
            operation.recover_until = Some(
                super::membership::now()?
                    .checked_add(RECOVERY_TTL)
                    .context("clock overflow")?,
            );
            operation.message = "Durable recovery authorization renewed by the operator.".into();
            self.save_operation(operation.clone()).await?;
        }
        if operation.preview.kind == NodeOperationKind::Add
            && operation.phase == NodeOperationPhase::PreparingTarget
        {
            ensure!(
                !operation.cancel_requested,
                "cancellation is pending; Resume cannot restart staging"
            );
            let local_id = {
                let master = self.master.clone();
                blocking(move || super::lifecycle::status(&master))
                    .await?
                    .node_id
            };
            if local_id.as_deref() != Some(&operation.preview.target_node_id) {
                self.resume_add_preparation(&operation).await?;
                operation = self.operation(operation_id).await?;
                ensure!(
                    operation.phase == NodeOperationPhase::Prepared && operation.backup_verified,
                    "destination staging is still in progress; Resume keeps the same operation ID"
                );
                ensure!(
                    operation.preview.expires_at > super::membership::now()?,
                    "review expired; prepare it again"
                );
                return self
                    .reply(
                        Some(operation.preview),
                        None,
                        "Prepared review reopened; apply still requires explicit confirmation.",
                    )
                    .await;
            }
        }
        if operation.phase == NodeOperationPhase::Prepared {
            ensure!(
                !operation.cancel_requested,
                "cancellation is pending; Resume cannot reopen this review"
            );
            if operation.preview.expires_at <= super::membership::now()? {
                ensure!(expired_add_review, "review expired; prepare it again");
                let local_id = {
                    let master = self.master.clone();
                    blocking(move || super::lifecycle::status(&master))
                        .await?
                        .node_id
                };
                if local_id.as_deref() != Some(&operation.preview.target_node_id) {
                    self.resume_add_preparation(&operation).await?;
                    let operation = self.operation(operation_id).await?;
                    return self
                        .reply(
                            Some(operation.preview),
                            None,
                            "Expired Add review recovered; apply still requires explicit confirmation.",
                        )
                        .await;
                }
                let preview_id = operation
                    .peer_preview_id
                    .clone()
                    .context("prepared destination lifecycle review absent")?;
                let expires_at = super::membership::now()?
                    .checked_add(PREVIEW_TTL)
                    .context("clock overflow")?;
                let lifecycle = super::lifecycle::renew_nodes_staged_join_review(
                    &self.master,
                    &preview_id,
                    &operation.preview.id,
                    expires_at,
                )
                .await?;
                operation.preview.expires_at = lifecycle.expires_at;
                operation.message =
                    "Expired Add review recovered from the exact unapplied destination backup."
                        .into();
                self.save_operation(operation.clone()).await?;
                return self
                    .reply(
                        Some(operation.preview),
                        None,
                        "Expired Add review recovered; apply still requires explicit confirmation.",
                    )
                    .await;
            }
            ensure!(
                operation.preview.expires_at > super::membership::now()?,
                "review expired; prepare it again"
            );
            return self
                .reply(
                    Some(operation.preview),
                    None,
                    "Prepared review reopened; apply still requires explicit confirmation.",
                )
                .await;
        }
        let local_id = {
            let master = self.master.clone();
            blocking(move || super::lifecycle::status(&master))
                .await?
                .node_id
        };
        if operation.preview.kind == NodeOperationKind::Add
            && local_id.as_deref() != Some(&operation.preview.target_node_id)
        {
            self.arm_prepared_add_target(&operation).await?;
        }
        if operation.phase == NodeOperationPhase::ApplyingTarget
            && local_id.as_deref() == Some(&operation.preview.target_node_id)
        {
            self.recover_target_apply(operation).await?;
            return self
                .reply(
                    None,
                    None,
                    "Recovered destination apply and restart request.",
                )
                .await;
        }
        if matches!(
            operation.phase,
            NodeOperationPhase::RestartingTarget | NodeOperationPhase::AwaitingDetach
        ) && local_id.as_deref() == Some(&operation.preview.target_node_id)
        {
            self.resume_local_operation(operation_id).await?;
            return self
                .reply(None, None, "Local operation recovery status refreshed.")
                .await;
        }
        if operation.phase == NodeOperationPhase::PreparingTarget
            && local_id.as_deref() == Some(&operation.preview.target_node_id)
        {
            self.recover_target_preparation(operation).await?;
            return self
                .reply(None, None, "Recovered private destination staging.")
                .await;
        }
        match operation.phase {
            NodeOperationPhase::ApplyingPrimary => {
                if operation.preview.kind == NodeOperationKind::Edit {
                    self.recover_local_edit(operation).await?;
                    return self
                        .reply(None, None, "Recovered local endpoint edit.")
                        .await;
                }
                let local = {
                    let master = self.master.clone();
                    blocking(move || super::lifecycle::status(&master)).await?
                };
                if local.saved_role == NodeRole::Primary {
                    self.admit_prepared_target(&operation).await?;
                    if !local.restart_required && self.active.active_pair().is_some() {
                        self.apply_prepared_target(operation).await?;
                        return self
                            .reply(None, None, "Recovered committed target admission.")
                            .await;
                    }
                    let permit = self.restart.preflight().await?;
                    operation.phase = NodeOperationPhase::RestartingPrimary;
                    operation.message =
                        "Primary admission recovered; waiting for verified activation.".into();
                    if !operation
                        .preview
                        .restart_steps
                        .iter()
                        .any(|step| step.step_id == "primary" && step.requested)
                    {
                        self.persist_restart_request(&mut operation, "primary")
                            .await?;
                        self.restart
                            .request(
                                permit,
                                super::managed_restart::ManagedRestartRequest {
                                    operation_id: operation.preview.id,
                                    step_id: "primary".into(),
                                },
                            )
                            .await?;
                    }
                    return self
                        .reply(None, None, "Recovered primary activation request.")
                        .await;
                }
                let permit = self.restart.preflight().await?;
                let preview_id = operation
                    .local_preview_id
                    .clone()
                    .context("primary lifecycle preview absent")?;
                super::lifecycle::apply(&self.master, &preview_id).await?;
                self.admit_prepared_target(&operation).await?;
                operation.phase = NodeOperationPhase::RestartingPrimary;
                operation.message = "Primary apply recovered; requesting its restart once.".into();
                if !operation
                    .preview
                    .restart_steps
                    .iter()
                    .any(|step| step.step_id == "primary" && step.requested)
                {
                    self.persist_restart_request(&mut operation, "primary")
                        .await?;
                    self.restart
                        .request(
                            permit,
                            super::managed_restart::ManagedRestartRequest {
                                operation_id: operation.preview.id,
                                step_id: "primary".into(),
                            },
                        )
                        .await?;
                }
            }
            NodeOperationPhase::RestartingPrimary => {
                let step_id = if operation.preview.kind == NodeOperationKind::Edit {
                    "endpoint"
                } else {
                    "primary"
                };
                let acknowledged = operation
                    .preview
                    .restart_steps
                    .iter()
                    .any(|step| step.step_id == step_id && step.acknowledged);
                ensure!(
                    acknowledged,
                    "primary restart has not reached verified readiness"
                );
                if operation.preview.kind == NodeOperationKind::Edit {
                    self.complete_primary_endpoint_transition(operation).await?;
                } else {
                    self.apply_prepared_target(operation).await?;
                }
            }
            NodeOperationPhase::RestartingTarget
            | NodeOperationPhase::AwaitingDetach
            | NodeOperationPhase::ApplyingTarget => {
                if operation.phase == NodeOperationPhase::AwaitingDetach
                    && operation.preview.kind == NodeOperationKind::Remove
                {
                    self.ensure_remove_revoked(&operation).await?;
                }
                let peer = self.peer(&operation.preview.target_node_id).await?;
                let response = if operation.phase == NodeOperationPhase::AwaitingDetach
                    && operation.preview.kind == NodeOperationKind::Remove
                    && operation.peer_preview_id.is_none()
                {
                    let prepared = send_management(
                        &peer,
                        &PeerManagementRequest::PrepareRemove {
                            operation_id: operation.preview.id.clone(),
                        },
                    )
                    .await?;
                    let preview_id = prepared
                        .preview_id
                        .clone()
                        .context("returned secondary detach preview absent")?;
                    operation.peer_preview_id = Some(preview_id.clone());
                    operation.last_verified_at = Some(super::membership::now()?);
                    operation.message =
                        "Returned secondary prepared; applying the retained removal.".into();
                    self.save_operation(operation.clone()).await?;
                    if prepared
                        .operation
                        .as_ref()
                        .is_some_and(|progress| progress.phase == NodeOperationPhase::Complete)
                    {
                        prepared
                    } else {
                        send_management(
                            &peer,
                            &PeerManagementRequest::Apply {
                                operation_id: operation.preview.id.clone(),
                                preview_id,
                            },
                        )
                        .await?
                    }
                } else {
                    let resumed = send_management(
                        &peer,
                        &PeerManagementRequest::Resume {
                            operation_id: operation.preview.id.clone(),
                        },
                    )
                    .await?;
                    if operation.phase == NodeOperationPhase::AwaitingDetach
                        && operation.preview.kind == NodeOperationKind::Remove
                        && resumed
                            .operation
                            .as_ref()
                            .is_some_and(|progress| progress.phase == NodeOperationPhase::Prepared)
                    {
                        send_management(
                            &peer,
                            &PeerManagementRequest::Apply {
                                operation_id: operation.preview.id.clone(),
                                preview_id: operation
                                    .peer_preview_id
                                    .clone()
                                    .context("retained secondary detach preview absent")?,
                            },
                        )
                        .await?
                    } else {
                        resumed
                    }
                };
                operation.last_verified_at = Some(super::membership::now()?);
                if operation.preview.kind == NodeOperationKind::Edit
                    && operation.preview.target_endpoint != peer.view.endpoint
                    && operation.prepared_fingerprint.is_none()
                {
                    ensure!(
                        response.control_endpoint == Some(operation.preview.target_endpoint)
                            && response.control_fingerprint.is_some(),
                        "peer did not return its active endpoint identity"
                    );
                    operation.prepared_fingerprint = response.control_fingerprint.clone();
                }
                if response
                    .operation
                    .as_ref()
                    .is_some_and(|progress| progress.phase == NodeOperationPhase::Complete)
                {
                    if operation.preview.kind == NodeOperationKind::Remove {
                        send_management(
                            &peer,
                            &PeerManagementRequest::AcknowledgeDetach {
                                operation_id: operation.preview.id.clone(),
                            },
                        )
                        .await?;
                        self.complete_detach(operation).await?;
                    } else if operation.preview.kind == NodeOperationKind::Edit
                        && operation.prepared_fingerprint.is_some()
                    {
                        self.complete_peer_endpoint_transition(operation).await?;
                    } else {
                        operation.phase = NodeOperationPhase::Complete;
                        operation.acknowledge_secondary_restart();
                        operation.message =
                            "Both nodes acknowledged the completed operation.".into();
                        if operation.preview.kind == NodeOperationKind::Edit {
                            self.persist_verified_peer_name(&operation).await?;
                        }
                        self.activate_peer(&operation.preview.target_node_id)
                            .await?;
                        self.save_operation(operation).await?;
                    }
                } else {
                    self.save_operation(operation).await?;
                }
            }
            NodeOperationPhase::Paused => unreachable!("paused recovery handled above"),
            NodeOperationPhase::Failed => anyhow::bail!(
                "recovery failed after durable authorization; inspect the node status and retry"
            ),
            NodeOperationPhase::Complete | NodeOperationPhase::Cancelled => {}
            _ => anyhow::bail!("operation is already progressing; refresh its status"),
        }
        self.reply(None, None, "Operation recovery advanced.").await
    }

    async fn persist_verified_peer_name(&self, operation: &OperationRecord) -> anyhow::Result<()> {
        ensure!(
            operation.preview.kind == NodeOperationKind::Edit,
            "peer name update requires a reviewed Edit"
        );
        let master = self.master.clone();
        let node_id = operation.preview.target_node_id.clone();
        let name = operation.preview.target_name.clone();
        blocking(move || {
            let guard = acquire_for_migration(&master)?;
            {
                let mut membership = super::membership::MembershipStore::open(&guard)?;
                membership.rename(&node_id, &name)?;
            }
            let mut state = load_state(&guard)?;
            let peer = state
                .peers
                .get_mut(&node_id)
                .context("managed peer absent")?;
            peer.view.name = name;
            save_state(&guard, &state)
        })
        .await
    }

    async fn recover_target_apply(&self, mut operation: OperationRecord) -> anyhow::Result<()> {
        let permit = self.restart.preflight().await?;
        let preview_id = operation
            .peer_preview_id
            .clone()
            .context("destination lifecycle preview absent")?;
        let active = if operation.preview.kind == NodeOperationKind::Remove {
            self.active
                .active_pair()
                .map(|pair| (pair.policy, pair.corpus_generation))
        } else {
            None
        };
        super::lifecycle::apply_with_active_pair(&self.master, &preview_id, active).await?;
        operation.phase = NodeOperationPhase::RestartingTarget;
        let step_id = operation
            .preview
            .restart_steps
            .first()
            .map(|step| step.step_id.clone())
            .context("restart step absent")?;
        if !operation
            .preview
            .restart_steps
            .iter()
            .any(|step| step.step_id == step_id && step.requested)
        {
            self.persist_restart_request(&mut operation, &step_id)
                .await?;
            self.restart
                .request(
                    permit,
                    super::managed_restart::ManagedRestartRequest {
                        operation_id: operation.preview.id,
                        step_id,
                    },
                )
                .await?;
        }
        Ok(())
    }

    async fn recover_local_edit(&self, mut operation: OperationRecord) -> anyhow::Result<()> {
        ensure!(
            operation.preview.kind == NodeOperationKind::Edit,
            "local edit recovery kind mismatch"
        );
        let permit = if operation.prepared_certificate.is_some() {
            Some(self.restart.preflight().await?)
        } else {
            None
        };
        let preview_id = operation
            .peer_preview_id
            .clone()
            .context("local edit preview absent")?;
        super::lifecycle::apply(&self.master, &preview_id).await?;
        if let (Some(certificate), Some(private_key), Some(fingerprint)) = (
            operation.prepared_certificate.clone(),
            operation.prepared_private_key.clone(),
            operation.prepared_fingerprint.clone(),
        ) {
            let master = self.master.clone();
            let endpoint = operation.preview.target_endpoint;
            blocking(move || {
                let guard = acquire_for_migration(&master)?;
                let mut state = load_state(&guard)?;
                promote_listener(&mut state, endpoint, certificate, private_key, fingerprint)?;
                save_state(&guard, &state)
            })
            .await?;
            operation.phase = match operation.preview.target_role {
                NodeRole::Primary => NodeOperationPhase::RestartingPrimary,
                _ => NodeOperationPhase::RestartingTarget,
            };
            if !operation
                .preview
                .restart_steps
                .iter()
                .any(|step| step.step_id == "endpoint" && step.requested)
            {
                self.persist_restart_request(&mut operation, "endpoint")
                    .await?;
                self.restart
                    .request(
                        permit.context("managed restart permit absent")?,
                        super::managed_restart::ManagedRestartRequest {
                            operation_id: operation.preview.id,
                            step_id: "endpoint".into(),
                        },
                    )
                    .await?;
            }
        } else {
            operation.phase = NodeOperationPhase::Complete;
            operation.message = "Node name updated; stable identity retained.".into();
            self.save_operation(operation).await?;
        }
        Ok(())
    }

    async fn complete_peer_endpoint_transition(
        &self,
        mut operation: OperationRecord,
    ) -> anyhow::Result<()> {
        let fingerprint = operation
            .prepared_fingerprint
            .clone()
            .context("reviewed peer endpoint fingerprint absent")?;
        let mut peer = self.peer(&operation.preview.target_node_id).await?;
        peer.view.endpoint = operation.preview.target_endpoint;
        peer.source_fingerprint = fingerprint;
        let master = self.master.clone();
        let node_id = operation.preview.target_node_id.clone();
        let operation_id = operation.preview.id.clone();
        let endpoint = peer.view.endpoint;
        let fingerprint = peer.source_fingerprint.clone();
        blocking(move || {
            let guard = acquire_for_migration(&master)?;
            let mut state = load_state(&guard)?;
            let stored_operation = state
                .operations
                .get_mut(&operation_id)
                .context("endpoint Edit operation disappeared")?;
            ensure!(
                stored_operation.preview.kind == NodeOperationKind::Edit
                    && stored_operation.preview.target_node_id == node_id
                    && stored_operation.preview.target_endpoint == endpoint
                    && stored_operation
                        .prepared_fingerprint
                        .as_ref()
                        .is_none_or(|stored| stored == &fingerprint),
                "endpoint Edit recovery journal changed"
            );
            stored_operation.prepared_fingerprint = Some(fingerprint.clone());
            stored_operation.message = "Awaiting durable endpoint acknowledgement.".into();
            let peer = state
                .peers
                .get_mut(&node_id)
                .context("managed peer absent")?;
            peer.view.endpoint = endpoint;
            peer.source_fingerprint = fingerprint;
            peer.view.last_error = Some("Awaiting endpoint acknowledgement.".into());
            save_state(&guard, &state)
        })
        .await?;
        send_management(
            &peer,
            &PeerManagementRequest::AcknowledgeEndpoint {
                operation_id: operation.preview.id.clone(),
            },
        )
        .await?;
        self.persist_verified_peer_name(&operation).await?;
        let master = self.master.clone();
        let node_id = operation.preview.target_node_id.clone();
        blocking(move || {
            let guard = acquire_for_migration(&master)?;
            let mut state = load_state(&guard)?;
            let peer = state
                .peers
                .get_mut(&node_id)
                .context("managed peer absent")?;
            peer.view.state = NodePeerState::Active;
            peer.view.last_seen_at = Some(super::membership::now()?);
            peer.view.last_error = None;
            save_state(&guard, &state)
        })
        .await?;
        operation.phase = NodeOperationPhase::Complete;
        operation.acknowledge_secondary_restart();
        operation.last_verified_at = Some(super::membership::now()?);
        operation.message = "New peer endpoint verified; previous listener retired.".into();
        self.save_operation(operation).await
    }

    async fn complete_primary_endpoint_transition(
        &self,
        mut operation: OperationRecord,
    ) -> anyhow::Result<()> {
        let fingerprint = operation
            .prepared_fingerprint
            .clone()
            .context("reviewed primary endpoint fingerprint absent")?;
        let master = self.master.clone();
        let peers = blocking(move || {
            let guard = acquire_for_migration(&master)?;
            Ok(load_state(&guard)?
                .peers
                .values()
                .filter(|peer| peer.view.state != NodePeerState::Detached)
                .cloned()
                .collect::<Vec<_>>())
        })
        .await?;
        for peer in peers {
            let response = send_management(
                &peer,
                &PeerManagementRequest::AdoptPrimaryEndpoint {
                    operation_id: operation.preview.id.clone(),
                    endpoint: operation.preview.target_endpoint,
                    fingerprint: fingerprint.clone(),
                },
            )
            .await?;
            ensure!(
                response.transition_acknowledged,
                "secondary has not proved a pinned policy pull from the new primary endpoint"
            );
        }
        let master = self.master.clone();
        let retired = blocking(move || {
            let guard = acquire_for_migration(&master)?;
            let mut state = load_state(&guard)?;
            let retired = state
                .previous_listener
                .take()
                .map(|listener| listener.endpoint);
            save_state(&guard, &state)?;
            Ok(retired)
        })
        .await?;
        if let Some(endpoint) = retired {
            self.listeners.retire(endpoint).await?;
        }
        operation.phase = NodeOperationPhase::Complete;
        operation.last_verified_at = Some(super::membership::now()?);
        operation.message = "All managed peers acknowledged the primary endpoint.".into();
        self.save_operation(operation).await
    }

    async fn recover_target_preparation(
        &self,
        mut operation: OperationRecord,
    ) -> anyhow::Result<()> {
        let peer = self.peer(&operation.preview.source_node_id).await?;
        let staged = operation
            .staged_pair
            .clone()
            .context("reviewed pair absent")?;
        let (manifest, objects) = fetch_staged_policy(&peer, &staged.policy).await?;
        let corpus = fetch_staged_corpus(
            &peer,
            &self.master,
            &staged.policy,
            &staged.corpus_generation,
            &operation.preview.id,
            operation
                .recover_until
                .context("destination recovery deadline absent")?,
        )
        .await?;
        let local_id = operation.preview.target_node_id.clone();
        let cluster_id = operation
            .cluster_id
            .clone()
            .context("prepared cluster identity absent")?;
        let credential = operation
            .replication_credential
            .clone()
            .context("prepared replication credential absent")?;
        let primary_endpoint = operation
            .preview
            .source_endpoint
            .context("primary endpoint absent")?;
        let preview = super::lifecycle::preview_nodes_staged_join(
            &self.master,
            super::lifecycle::NodesStagedJoin {
                cluster_id: cluster_id.clone(),
                primary_node_id: peer.view.node_id.clone(),
                primary_endpoint,
                primary_fingerprint: peer.source_fingerprint.clone(),
                credential: super::pairing::SecondaryCredential {
                    cluster_id,
                    node_id: local_id,
                    primary_node_id: peer.view.node_id,
                    primary: endpoint_url(primary_endpoint),
                    fingerprint: peer.source_fingerprint,
                    credential,
                },
                node_name: operation.preview.target_name.clone(),
                manifest,
                objects,
                corpus_generation: corpus.generation,
                corpus_pin_owner: operation.preview.id.clone(),
                corpus_pin_expires_at: operation
                    .recover_until
                    .context("destination recovery deadline absent")?,
            },
        )
        .await?;
        operation.peer_preview_id = Some(preview.id);
        operation.phase = NodeOperationPhase::Prepared;
        operation.backup_verified = true;
        operation.preview.expires_at = preview.expires_at;
        operation.message = "Exact policy, corpus and destination backup recovered.".into();
        self.save_operation(operation).await
    }

    async fn resume_add_preparation(&self, operation: &OperationRecord) -> anyhow::Result<()> {
        let peer = self.peer(&operation.preview.target_node_id).await?;
        let master = self.master.clone();
        let primary_fingerprint = blocking(move || {
            let guard = acquire_for_migration(&master)?;
            load_state(&guard)?
                .certificate_fingerprint
                .context("source Nodes certificate fingerprint absent")
        })
        .await?;
        let staged = send_management(
            &peer,
            &PeerManagementRequest::PrepareAdd {
                operation_id: operation.preview.id.clone(),
                name: operation.preview.target_name.clone(),
                cluster_id: operation
                    .cluster_id
                    .clone()
                    .context("prepared cluster identity absent")?,
                primary_node_id: operation.preview.source_node_id.clone(),
                primary_endpoint: operation
                    .preview
                    .source_endpoint
                    .context("source endpoint absent")?,
                primary_fingerprint,
                staged_pair: Box::new(
                    operation
                        .staged_pair
                        .clone()
                        .context("reviewed pair absent")?,
                ),
                replication_credential: operation
                    .replication_credential
                    .clone()
                    .context("prepared replication credential absent")?,
            },
        )
        .await?;
        ensure!(staged.backup_verified, "destination backup is not verified");
        let mut operation = operation.clone();
        operation.peer_preview_id = staged.preview_id;
        operation.backup_verified = true;
        operation.phase = NodeOperationPhase::Prepared;
        operation.preview.expires_at = super::membership::now()?
            .checked_add(PREVIEW_TTL)
            .context("clock overflow")?;
        operation.message = "Exact policy, corpus and verified backup are staged.".into();
        self.save_operation(operation).await
    }

    async fn operation(&self, operation_id: &str) -> anyhow::Result<OperationRecord> {
        ensure!(
            super::membership::valid_id(operation_id),
            "invalid operation identity"
        );
        let master = self.master.clone();
        let id = operation_id.to_owned();
        blocking(move || {
            let guard = acquire_for_migration(&master)?;
            load_state(&guard)?
                .operations
                .get(&id)
                .cloned()
                .context("unknown Nodes operation")
        })
        .await
    }

    async fn operation_has_persistent_peer(
        &self,
        operation: &OperationRecord,
    ) -> anyhow::Result<bool> {
        let master = self.master.clone();
        let source_id = operation.preview.source_node_id.clone();
        let target_id = operation.preview.target_node_id.clone();
        blocking(move || {
            let guard = acquire_for_migration(&master)?;
            let state = load_state(&guard)?;
            Ok([source_id, target_id].iter().any(|id| {
                state.peers.get(id).is_some_and(|peer| {
                    peer.view.state != NodePeerState::Detached
                        && peer.view.capabilities.persistent_management
                })
            }))
        })
        .await
    }

    async fn peer(&self, node_id: &str) -> anyhow::Result<PeerRecord> {
        let master = self.master.clone();
        let id = node_id.to_owned();
        blocking(move || {
            let guard = acquire_for_migration(&master)?;
            load_state(&guard)?
                .peers
                .get(&id)
                .cloned()
                .context("unknown managed node")
        })
        .await
    }

    async fn save_operation(&self, operation: OperationRecord) -> anyhow::Result<()> {
        let master = self.master.clone();
        blocking(move || {
            let guard = acquire_for_migration(&master)?;
            let mut state = load_state(&guard)?;
            ensure!(
                state.operations.contains_key(&operation.preview.id),
                "Nodes operation disappeared"
            );
            state
                .operations
                .insert(operation.preview.id.clone(), operation);
            save_state(&guard, &state)
        })
        .await
    }

    async fn retire_prepared_listener(&self, operation_id: &str) -> anyhow::Result<bool> {
        let master = self.master.clone();
        let id = operation_id.to_owned();
        let endpoint = blocking(move || {
            let guard = acquire_for_migration(&master)?;
            let state = load_state(&guard)?;
            Ok(state.operations.get(&id).and_then(|operation| {
                (matches!(
                    operation.phase,
                    NodeOperationPhase::Paused | NodeOperationPhase::Cancelled
                ) && operation.prepared_certificate.is_some()
                    && state.control_endpoint != Some(operation.preview.target_endpoint))
                .then_some(operation.preview.target_endpoint)
            }))
        })
        .await?;
        let Some(endpoint) = endpoint else {
            return Ok(false);
        };
        self.listeners.retire(endpoint).await?;
        let master = self.master.clone();
        let id = operation_id.to_owned();
        blocking(move || {
            let guard = acquire_for_migration(&master)?;
            let mut state = load_state(&guard)?;
            if let Some(operation) = state.operations.get_mut(&id) {
                if matches!(
                    operation.phase,
                    NodeOperationPhase::Paused | NodeOperationPhase::Cancelled
                ) && operation.preview.target_endpoint == endpoint
                {
                    operation.prepared_certificate = None;
                    operation.prepared_private_key = None;
                    operation.prepared_fingerprint = None;
                }
            }
            save_state(&guard, &state)
        })
        .await?;
        Ok(true)
    }

    async fn cleanup_cancelled_join(&self, operation_id: &str) -> anyhow::Result<bool> {
        let operation = self.operation(operation_id).await?;
        if operation.preview.kind != NodeOperationKind::Add
            || operation.phase != NodeOperationPhase::Cancelled
        {
            return Ok(false);
        }
        let Some(preview_id) = operation.peer_preview_id.clone() else {
            return Ok(false);
        };
        let _ = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            super::lifecycle::cancel(&self.master, &preview_id),
        )
        .await;
        if super::lifecycle::preview_exists(&self.master, &preview_id).await? {
            return Ok(false);
        }
        let master = self.master.clone();
        let id = operation_id.to_owned();
        blocking(move || {
            let guard = acquire_for_migration(&master)?;
            let mut state = load_state(&guard)?;
            if let Some(operation) = state.operations.get_mut(&id) {
                if operation.phase == NodeOperationPhase::Cancelled
                    && operation.peer_preview_id.as_deref() == Some(preview_id.as_str())
                {
                    operation.peer_preview_id = None;
                }
            }
            save_state(&guard, &state)
        })
        .await?;
        Ok(true)
    }

    async fn release_completed_corpus_pin(&self, operation_id: &str) -> anyhow::Result<bool> {
        let master = self.master.clone();
        let id = operation_id.to_owned();
        let pending = blocking(move || {
            let guard = acquire_for_migration(&master)?;
            let state = load_state(&guard)?;
            Ok(state.operations.get(&id).is_some_and(|operation| {
                operation.preview.kind == NodeOperationKind::Add
                    && operation.phase == NodeOperationPhase::Complete
                    && !state.released_corpus_pins.contains(&id)
            }))
        })
        .await?;
        if !pending {
            return Ok(false);
        }
        let master = self.master.clone();
        let owner = operation_id.to_owned();
        blocking(move || {
            super::corpus::CorpusStore::open(&master)?.release_private_manifest_pin(&owner)
        })
        .await?;
        let master = self.master.clone();
        let id = operation_id.to_owned();
        blocking(move || {
            let guard = acquire_for_migration(&master)?;
            let mut state = load_state(&guard)?;
            ensure!(
                state.operations.get(&id).is_some_and(|operation| {
                    operation.preview.kind == NodeOperationKind::Add
                        && operation.phase == NodeOperationPhase::Complete
                }),
                "completed Add disappeared before corpus pin release was recorded"
            );
            state.released_corpus_pins.insert(id);
            save_state(&guard, &state)
        })
        .await?;
        Ok(true)
    }

    async fn persist_restart_request(
        &self,
        operation: &mut OperationRecord,
        step_id: &str,
    ) -> anyhow::Result<()> {
        let now = super::membership::now()?;
        let step = operation
            .preview
            .restart_steps
            .iter_mut()
            .find(|step| step.step_id == step_id)
            .context("restart step absent")?;
        ensure!(!step.requested, "restart step was already consumed");
        step.requested = true;
        operation.restart_requested_at.insert(step_id.into(), now);
        self.save_operation(operation.clone()).await
    }

    async fn activate_peer(&self, node_id: &str) -> anyhow::Result<()> {
        let master = self.master.clone();
        let id = node_id.to_owned();
        blocking(move || {
            let guard = acquire_for_migration(&master)?;
            let mut state = load_state(&guard)?;
            let peer = state.peers.get_mut(&id).context("managed peer absent")?;
            peer.view.role = NodeRole::Secondary;
            peer.view.state = NodePeerState::Active;
            peer.view.last_seen_at = Some(super::membership::now()?);
            peer.view.last_error = None;
            save_state(&guard, &state)
        })
        .await
    }

    async fn complete_detach(&self, mut operation: OperationRecord) -> anyhow::Result<()> {
        let master = self.master.clone();
        let id = operation.preview.target_node_id.clone();
        blocking(move || {
            let guard = acquire_for_migration(&master)?;
            let mut state = load_state(&guard)?;
            let peer = state.peers.get_mut(&id).context("managed peer absent")?;
            peer.view.state = NodePeerState::Detached;
            peer.view.role = NodeRole::Standalone;
            peer.view.last_seen_at = Some(super::membership::now()?);
            save_state(&guard, &state)
        })
        .await?;
        operation.phase = NodeOperationPhase::Complete;
        operation.acknowledge_secondary_restart();
        operation.message =
            "Secondary acknowledged standalone detach with its last complete policy.".into();
        self.save_operation(operation).await
    }

    async fn finish_cancelled_add_source_cleanup(
        &self,
        operation: &OperationRecord,
    ) -> anyhow::Result<()> {
        ensure!(
            operation.preview.kind == NodeOperationKind::Add
                && operation.phase == NodeOperationPhase::Cancelled
                && operation.cancel_requested,
            "cancelled source cleanup does not match the exact enrollment"
        );
        let master = self.master.clone();
        let cancelled_id = operation.preview.id.clone();
        let target_id = operation.preview.target_node_id.clone();
        let cleanup_id = cancelled_id.clone();
        let cleanup_target = target_id.clone();
        let current = blocking(move || {
            let guard = acquire_for_migration(&master)?;
            let state = load_state(&guard)?;
            let stored = state
                .operations
                .get(&cancelled_id)
                .context("cancelled enrollment disappeared")?;
            ensure!(
                stored.preview.kind == NodeOperationKind::Add
                    && stored.phase == NodeOperationPhase::Cancelled
                    && stored.cancel_requested
                    && stored.preview.target_node_id == target_id,
                "cancelled source enrollment changed before cleanup"
            );
            Ok(!state.operations.values().any(|candidate| {
                candidate.preview.id != cancelled_id
                    && candidate.preview.kind == NodeOperationKind::Add
                    && !candidate.phase.terminal()
                    && candidate.preview.target_node_id == target_id
            }))
        })
        .await?;
        if !current {
            return self
                .acknowledge_cancelled_add_cleanup(&operation.preview.id)
                .await;
        }
        self.retire_prepared_listener(&operation.preview.id).await?;
        let master = self.master.clone();
        blocking(move || {
            let guard = acquire_for_migration(&master)?;
            let mut state = load_state(&guard)?;
            let stored = state
                .operations
                .get(&cleanup_id)
                .context("cancelled enrollment disappeared")?;
            ensure!(
                stored.preview.kind == NodeOperationKind::Add
                    && stored.phase == NodeOperationPhase::Cancelled
                    && stored.cancel_requested
                    && stored.preview.target_node_id == cleanup_target,
                "cancelled source enrollment changed before cleanup"
            );
            if !state.operations.values().any(|candidate| {
                candidate.preview.id != cleanup_id
                    && candidate.preview.kind == NodeOperationKind::Add
                    && !candidate.phase.terminal()
                    && candidate.preview.target_node_id == cleanup_target
            }) && state
                .peers
                .get(&cleanup_target)
                .is_some_and(|peer| peer.view.state == NodePeerState::Pending)
            {
                state.peers.remove(&cleanup_target);
            }
            state
                .operations
                .get_mut(&cleanup_id)
                .context("cancelled enrollment disappeared")?
                .cancel_requested = false;
            save_state(&guard, &state)?;
            Ok(())
        })
        .await
    }

    async fn acknowledge_cancelled_add_cleanup(&self, operation_id: &str) -> anyhow::Result<()> {
        let master = self.master.clone();
        let operation_id = operation_id.to_owned();
        blocking(move || {
            let guard = acquire_for_migration(&master)?;
            let mut state = load_state(&guard)?;
            let operation = state
                .operations
                .get_mut(&operation_id)
                .context("cancelled enrollment disappeared")?;
            ensure!(
                operation.preview.kind == NodeOperationKind::Add
                    && operation.phase == NodeOperationPhase::Cancelled,
                "cancelled enrollment changed before cleanup"
            );
            operation.cancel_requested = false;
            save_state(&guard, &state)
        })
        .await
    }

    async fn accept_bootstrap(
        &self,
        request: BootstrapClaimRequest,
    ) -> anyhow::Result<BootstrapClaimResponse> {
        ensure!(
            super::membership::valid_id(&request.operation_id)
                && super::membership::valid_id(&request.source_node_id)
                && super::manifest::is_hash(&request.source_fingerprint),
            "invalid bootstrap identity"
        );
        super::membership::validate_name(&request.source_name)?;
        ensure!(
            request.source_endpoint.port() != 0,
            "invalid source endpoint"
        );
        let master = self.master.clone();
        let response = blocking(move || {
            let guard = acquire_for_migration(&master)?;
            let loaded = load_config(&guard)?;
            let local = &loaded.config;
            let local_id = local
                .node
                .id
                .as_deref()
                .context("destination node identity absent")?;
            let role = config_role(local);
            let revision = capture_revision(&guard, &loaded)?;
            let mut state = load_state(&guard)?;
            let now = super::membership::now()?;
            let authorization = state
                .bootstrap
                .as_mut()
                .context("association authorization is not active")?;
            ensure!(
                authorization.expires_at > now
                    && authorization.target_node_id == local_id
                    && verify_token(&request.token.0, &authorization.token_hash),
                "association authorization expired, consumed or invalid"
            );
            ensure!(
                request.source_node_id != local_id,
                "a node cannot associate with itself"
            );
            if let Some(claimed_by) = &authorization.claimed_by {
                ensure!(
                    claimed_by == &request.source_node_id
                        && authorization.operation_id.as_deref() == Some(&request.operation_id),
                    "association token was already consumed"
                );
                let credential = authorization
                    .issued_credential
                    .clone()
                    .context("claimed authorization credential absent")?;
                return Ok(BootstrapClaimResponse {
                    target_node_id: local_id.into(),
                    target_name: local.node.display_name().into(),
                    target_role: role,
                    config_revision: revision,
                    capabilities: NodeCapabilities::current(),
                    target_credential: credential,
                });
            }
            ensure!(
                role == NodeRole::Standalone,
                "destination already belongs to a cluster"
            );
            ensure!(
                state.peers.len() < MAX_PEERS || state.peers.contains_key(&request.source_node_id),
                "managed peer capacity reached"
            );
            ensure!(
                state
                    .peers
                    .get(&request.source_node_id)
                    .is_none_or(|peer| peer.view.state == NodePeerState::Detached),
                "source node removal has not completed"
            );
            let (issued, issued_hash) = generate_token();
            let issued = SecretString(issued);
            authorization.claimed_by = Some(request.source_node_id.clone());
            authorization.operation_id = Some(request.operation_id.clone());
            authorization.issued_credential = Some(issued.clone());
            state.peers.insert(
                request.source_node_id.clone(),
                PeerRecord {
                    view: NodePeer {
                        node_id: request.source_node_id,
                        name: request.source_name,
                        endpoint: request.source_endpoint,
                        role: NodeRole::Primary,
                        state: NodePeerState::Pending,
                        capabilities: NodeCapabilities::current(),
                        last_seen_at: Some(now),
                        last_error: None,
                    },
                    outgoing_credential: request.source_credential,
                    incoming_credential_hash: issued_hash,
                    issued_incoming_credential: Some(issued.clone()),
                    source_fingerprint: request.source_fingerprint,
                },
            );
            save_state(&guard, &state)?;
            Ok(BootstrapClaimResponse {
                target_node_id: local_id.into(),
                target_name: local.node.display_name().into(),
                target_role: role,
                config_revision: revision,
                capabilities: NodeCapabilities::current(),
                target_credential: issued,
            })
        })
        .await?;
        Ok(response)
    }

    #[cfg(test)]
    async fn accept_management(
        &self,
        credential: &str,
        request: PeerManagementRequest,
    ) -> anyhow::Result<PeerManagementReply> {
        let _transition = self.transition_gate.clone().lock_owned().await;
        self.accept_management_admitted(credential, request).await
    }

    async fn accept_management_admitted(
        &self,
        credential: &str,
        request: PeerManagementRequest,
    ) -> anyhow::Result<PeerManagementReply> {
        let principal = self.authenticate_peer(credential).await?;
        if principal.view.state == NodePeerState::Pending {
            let cancelled_replay = match &request {
                PeerManagementRequest::Cancel {
                    operation_id,
                    preview_id,
                } => self
                    .operation(operation_id)
                    .await
                    .ok()
                    .is_some_and(|operation| {
                        operation.preview.kind == NodeOperationKind::Add
                            && operation.phase == NodeOperationPhase::Cancelled
                            && operation.preview.source_node_id == principal.view.node_id
                            && (preview_id.is_none()
                                || operation.peer_preview_id.as_deref() == preview_id.as_deref())
                    }),
                _ => false,
            };
            if !cancelled_replay {
                self.authorize_pending_request(&principal, &request).await?;
            }
        }
        if principal.view.state == NodePeerState::PendingDetach {
            ensure!(
                matches!(
                    request,
                    PeerManagementRequest::Status
                        | PeerManagementRequest::PrepareRemove { .. }
                        | PeerManagementRequest::Resume { .. }
                        | PeerManagementRequest::AcknowledgeEndpoint { .. }
                        | PeerManagementRequest::AcknowledgeDetach { .. }
                        | PeerManagementRequest::DetachReceipt { .. }
                ),
                "detached peer credential is limited to completion receipts"
            );
        }
        if principal.view.state == NodePeerState::Detached {
            ensure!(
                matches!(
                    request,
                    PeerManagementRequest::Cancel { .. }
                        | PeerManagementRequest::AcknowledgeDetach { .. }
                        | PeerManagementRequest::DetachReceipt { .. }
                ),
                "detached peer credential is limited to its retained receipt"
            );
        }
        self.touch_peer(&principal.view.node_id).await?;
        match request {
            PeerManagementRequest::PrepareAdd {
                operation_id,
                name,
                cluster_id,
                primary_node_id,
                primary_endpoint,
                primary_fingerprint,
                staged_pair,
                replication_credential,
            } => {
                self.accept_prepare_add(
                    &principal,
                    PreparedAddCommand {
                        operation_id,
                        name,
                        cluster_id,
                        primary_node_id,
                        primary_endpoint,
                        primary_fingerprint,
                        staged_pair: *staged_pair,
                        replication_credential,
                    },
                )
                .await
            }
            PeerManagementRequest::PrepareEdit {
                operation_id,
                name,
                endpoint,
            } => {
                self.accept_prepare_edit(&principal, operation_id, name, endpoint)
                    .await
            }
            PeerManagementRequest::PrepareRemove { operation_id } => {
                self.accept_prepare_remove(&principal, operation_id).await
            }
            PeerManagementRequest::Apply {
                operation_id,
                preview_id,
            } => {
                self.accept_peer_apply(&principal, operation_id, preview_id)
                    .await
            }
            PeerManagementRequest::Cancel {
                operation_id,
                preview_id,
            } => {
                self.accept_peer_cancel(&principal, operation_id, preview_id)
                    .await
            }
            PeerManagementRequest::Resume { operation_id } => {
                self.resume_local_operation(&operation_id).await?;
                self.peer_reply(Some(&operation_id), None, "Recovery status refreshed.")
                    .await
            }
            PeerManagementRequest::ArmAddRecovery {
                operation_id,
                preview_id,
            } => {
                self.accept_arm_add_recovery(&principal, operation_id, preview_id)
                    .await
            }
            PeerManagementRequest::AcknowledgeEndpoint { operation_id } => {
                self.accept_endpoint_ack(&principal, operation_id).await
            }
            PeerManagementRequest::AcknowledgeDetach { operation_id } => {
                self.accept_detach_ack(&principal, operation_id).await
            }
            PeerManagementRequest::DetachReceipt {
                operation_id,
                target_node_id,
            } => {
                self.accept_detach_receipt(&principal, operation_id, target_node_id)
                    .await
            }
            PeerManagementRequest::AdoptPrimaryEndpoint {
                operation_id,
                endpoint,
                fingerprint,
            } => {
                self.accept_primary_endpoint(&principal, operation_id, endpoint, fingerprint)
                    .await
            }
            PeerManagementRequest::Status => {
                self.peer_reply(None, None, "Management channel active.")
                    .await
            }
        }
    }

    async fn accept_endpoint_ack(
        &self,
        principal: &PeerRecord,
        operation_id: String,
    ) -> anyhow::Result<PeerManagementReply> {
        let operation = self.operation(&operation_id).await?;
        ensure!(
            operation.preview.kind == NodeOperationKind::Edit
                && operation.preview.source_node_id == principal.view.node_id
                && operation.phase == NodeOperationPhase::Complete,
            "endpoint acknowledgement does not match a completed edit"
        );
        let master = self.master.clone();
        let target_endpoint = operation.preview.target_endpoint;
        let retired = blocking(move || {
            let guard = acquire_for_migration(&master)?;
            let mut state = load_state(&guard)?;
            ensure!(
                state.control_endpoint == Some(target_endpoint),
                "endpoint acknowledgement does not match the active listener"
            );
            let retired = state
                .previous_listener
                .take()
                .map(|listener| listener.endpoint);
            save_state(&guard, &state)?;
            Ok(retired)
        })
        .await?;
        if let Some(endpoint) = retired {
            self.listeners.retire(endpoint).await?;
        }
        self.peer_reply(
            Some(&operation_id),
            operation.peer_preview_id,
            "New endpoint acknowledged; previous listener retired.",
        )
        .await
    }

    async fn accept_detach_ack(
        &self,
        principal: &PeerRecord,
        operation_id: String,
    ) -> anyhow::Result<PeerManagementReply> {
        let operation = self.operation(&operation_id).await?;
        ensure!(
            operation.preview.kind == NodeOperationKind::Remove
                && operation.preview.source_node_id == principal.view.node_id
                && operation.phase == NodeOperationPhase::Complete,
            "detach acknowledgement does not match a completed removal"
        );
        let master = self.master.clone();
        let receipt_id = operation_id.clone();
        let source_id = principal.view.node_id.clone();
        blocking(move || {
            let guard = acquire_for_migration(&master)?;
            let mut state = load_state(&guard)?;
            state
                .detach_receipts
                .entry(receipt_id.clone())
                .or_insert(super::membership::now()?);
            let peer = state
                .peers
                .get_mut(&source_id)
                .context("detaching primary management peer absent")?;
            ensure!(
                matches!(
                    peer.view.state,
                    NodePeerState::PendingDetach | NodePeerState::Detached
                ),
                "detach acknowledgement arrived before standalone readiness"
            );
            peer.view.state = NodePeerState::Detached;
            retire_claimed_bootstrap_after_completed_detach(&mut state, &receipt_id, &source_id)?;
            save_state(&guard, &state)
        })
        .await?;
        self.peer_reply(
            Some(&operation_id),
            operation.peer_preview_id,
            "Detach receipt acknowledged and retained for retry.",
        )
        .await
    }

    async fn accept_detach_receipt(
        &self,
        principal: &PeerRecord,
        operation_id: String,
        target_node_id: String,
    ) -> anyhow::Result<PeerManagementReply> {
        let operation = self.operation(&operation_id).await?;
        ensure!(
            operation.preview.kind == NodeOperationKind::Remove
                && operation.preview.target_node_id == principal.view.node_id
                && target_node_id == principal.view.node_id
                && matches!(
                    operation.phase,
                    NodeOperationPhase::AwaitingDetach | NodeOperationPhase::Complete
                ),
            "detach receipt does not match the retained removal"
        );
        if operation.phase != NodeOperationPhase::Complete {
            self.complete_detach(operation).await?;
        }
        let master = self.master.clone();
        let receipt_id = operation_id.clone();
        blocking(move || {
            let guard = acquire_for_migration(&master)?;
            let mut state = load_state(&guard)?;
            state
                .detach_receipts
                .entry(receipt_id.clone())
                .or_insert(super::membership::now()?);
            save_state(&guard, &state)
        })
        .await?;
        self.peer_reply(
            Some(&operation_id),
            None,
            "Durable detach completion receipt recorded.",
        )
        .await
    }

    async fn push_detach_receipt(&self, operation_id: &str) -> anyhow::Result<()> {
        let operation = self.operation(operation_id).await?;
        ensure!(
            operation.preview.kind == NodeOperationKind::Remove
                && operation.phase == NodeOperationPhase::Complete,
            "detach outbox entry is not complete"
        );
        let peer = self.peer(&operation.preview.source_node_id).await?;
        let response = send_management(
            &peer,
            &PeerManagementRequest::DetachReceipt {
                operation_id: operation.preview.id.clone(),
                target_node_id: operation.preview.target_node_id.clone(),
            },
        )
        .await?;
        ensure!(
            response
                .operation
                .as_ref()
                .is_some_and(|progress| progress.phase == NodeOperationPhase::Complete),
            "primary did not durably record detach completion"
        );
        let master = self.master.clone();
        let receipt_id = operation.preview.id;
        let source_id = operation.preview.source_node_id;
        blocking(move || {
            let guard = acquire_for_migration(&master)?;
            let mut state = load_state(&guard)?;
            state
                .detach_receipts
                .entry(receipt_id.clone())
                .or_insert(super::membership::now()?);
            let peer = state
                .peers
                .get_mut(&source_id)
                .context("detaching primary management peer absent")?;
            ensure!(
                matches!(
                    peer.view.state,
                    NodePeerState::PendingDetach | NodePeerState::Detached
                ),
                "detach receipt arrived before standalone readiness"
            );
            peer.view.state = NodePeerState::Detached;
            retire_claimed_bootstrap_after_completed_detach(&mut state, &receipt_id, &source_id)?;
            save_state(&guard, &state)
        })
        .await
    }

    async fn accept_primary_endpoint(
        &self,
        principal: &PeerRecord,
        operation_id: String,
        endpoint: SocketAddr,
        fingerprint: String,
    ) -> anyhow::Result<PeerManagementReply> {
        ensure!(
            principal.view.role == NodeRole::Primary
                && endpoint.port() != 0
                && super::manifest::is_hash(&fingerprint),
            "invalid primary endpoint transition"
        );
        let existing = {
            let master = self.master.clone();
            let operation_id = operation_id.clone();
            let primary_node_id = principal.view.node_id.clone();
            let fingerprint = fingerprint.clone();
            blocking(move || {
                let guard = acquire_for_migration(&master)?;
                let state = load_state(&guard)?;
                match state.pending_primary_transition.as_ref() {
                    Some(pending) => {
                        if pending.operation_id == operation_id {
                            ensure!(
                                pending.primary_node_id == primary_node_id
                                    && pending.endpoint == endpoint
                                    && pending.fingerprint == fingerprint,
                                "primary endpoint transition conflicts with durable recovery"
                            );
                            Ok(Some(pending.acknowledged))
                        } else {
                            ensure!(
                                pending.acknowledged,
                                "another primary endpoint transition is pending"
                            );
                            Ok(None)
                        }
                    }
                    None => Ok(None),
                }
            })
            .await?
        };
        if let Some(acknowledged) = existing {
            return self
                .primary_transition_reply(
                    acknowledged,
                    if acknowledged {
                        "Primary endpoint transition acknowledged."
                    } else {
                        "Primary endpoint transition is waiting for restart and pinned pull proof."
                    },
                )
                .await;
        }
        self.restart.preflight().await?;
        let lifecycle = super::node_connection::prepare_secondary_primary_rebind(
            &self.master,
            &principal.view.node_id,
            endpoint,
            &fingerprint,
        )
        .await?;
        let master = self.master.clone();
        let principal_id = principal.view.node_id.clone();
        let saved_operation_id = operation_id.clone();
        let saved_fingerprint = fingerprint.clone();
        blocking(move || {
            let guard = acquire_for_migration(&master)?;
            let mut state = load_state(&guard)?;
            ensure!(
                state
                    .pending_primary_transition
                    .as_ref()
                    .is_none_or(|pending| pending.acknowledged),
                "another primary endpoint transition is pending"
            );
            state.pending_primary_transition = Some(PendingPrimaryTransition {
                operation_id: saved_operation_id,
                primary_node_id: principal_id,
                endpoint,
                fingerprint: saved_fingerprint,
                lifecycle_preview_id: lifecycle.id,
                restart_requested: false,
                acknowledged: false,
            });
            save_state(&guard, &state)
        })
        .await?;
        self.apply_pending_primary_transition().await?;
        self.primary_transition_reply(
            false,
            "Primary endpoint transition saved; waiting for restart and pinned pull proof.",
        )
        .await
    }

    async fn primary_transition_reply(
        &self,
        acknowledged: bool,
        message: &str,
    ) -> anyhow::Result<PeerManagementReply> {
        let mut reply = self.peer_reply(None, None, message).await?;
        reply.transition_acknowledged = acknowledged;
        Ok(reply)
    }

    async fn apply_pending_primary_transition(&self) -> anyhow::Result<()> {
        let pending = {
            let master = self.master.clone();
            blocking(move || {
                let guard = acquire_for_migration(&master)?;
                Ok(load_state(&guard)?.pending_primary_transition)
            })
            .await?
        };
        let Some(pending) = pending else {
            return Ok(());
        };
        if pending.restart_requested || pending.acknowledged {
            return Ok(());
        }
        let permit = self.restart.preflight().await?;
        super::node_connection::apply_secondary_primary_rebind(
            &self.master,
            &pending.lifecycle_preview_id,
            &pending.primary_node_id,
            pending.endpoint,
            &pending.fingerprint,
        )
        .await?;
        let master = self.master.clone();
        let operation_id = pending.operation_id.clone();
        blocking(move || {
            let guard = acquire_for_migration(&master)?;
            let mut state = load_state(&guard)?;
            let current = state
                .pending_primary_transition
                .as_mut()
                .context("primary transition journal absent")?;
            ensure!(
                current.operation_id == operation_id,
                "primary transition journal changed"
            );
            current.restart_requested = true;
            save_state(&guard, &state)
        })
        .await?;
        self.restart
            .request(
                permit,
                super::managed_restart::ManagedRestartRequest {
                    operation_id: pending.operation_id,
                    step_id: "primary-transport".into(),
                },
            )
            .await?;
        Ok(())
    }

    pub async fn confirm_primary_endpoint_rebind(
        &self,
        endpoint: SocketAddr,
        fingerprint: &str,
    ) -> anyhow::Result<bool> {
        let _transition = self.transition_gate.lock().await;
        let pending = {
            let master = self.master.clone();
            blocking(move || {
                let guard = acquire_for_migration(&master)?;
                Ok(load_state(&guard)?.pending_primary_transition)
            })
            .await?
        };
        let Some(pending) = pending else {
            return Ok(false);
        };
        ensure!(
            pending.endpoint == endpoint
                && pending.fingerprint == fingerprint
                && pending.restart_requested
                && super::node_connection::verify_secondary_primary_rebind(
                    &self.master,
                    &pending.primary_node_id,
                    endpoint,
                    fingerprint,
                )?,
            "primary transport proof does not match the durable transition"
        );
        let master = self.master.clone();
        let fingerprint = fingerprint.to_owned();
        let operation_id = pending.operation_id;
        blocking(move || {
            let guard = acquire_for_migration(&master)?;
            let mut state = load_state(&guard)?;
            let pending = state
                .pending_primary_transition
                .as_mut()
                .context("primary transition proof is not pending")?;
            ensure!(
                pending.operation_id == operation_id
                    && pending.endpoint == endpoint
                    && pending.fingerprint == fingerprint,
                "primary transition journal changed before proof"
            );
            pending.acknowledged = true;
            let primary_id = pending.primary_node_id.clone();
            let peer = state
                .peers
                .get_mut(&primary_id)
                .context("primary management peer absent")?;
            peer.view.endpoint = endpoint;
            peer.source_fingerprint = fingerprint;
            peer.view.last_seen_at = Some(super::membership::now()?);
            peer.view.last_error = None;
            save_state(&guard, &state)?;
            Ok(true)
        })
        .await
    }

    async fn authenticate_peer(&self, credential: &str) -> anyhow::Result<PeerRecord> {
        let master = self.master.clone();
        let secret = credential.to_owned();
        blocking(move || {
            let guard = acquire_for_migration(&master)?;
            let mut state = load_state(&guard)?;
            expire_state(&mut state, super::membership::now()?);
            let mut principal = None;
            for peer in state.peers.values() {
                if verify_token(&secret, &peer.incoming_credential_hash) {
                    principal = Some(peer.clone());
                }
            }
            let principal = principal.context("managed node credential refused")?;
            save_state(&guard, &state)?;
            Ok(principal)
        })
        .await
    }

    async fn touch_peer(&self, peer_node_id: &str) -> anyhow::Result<()> {
        let master = self.master.clone();
        let peer_node_id = peer_node_id.to_owned();
        blocking(move || {
            let guard = acquire_for_migration(&master)?;
            let mut state = load_state(&guard)?;
            let peer = state
                .peers
                .get_mut(&peer_node_id)
                .context("managed peer disappeared")?;
            peer.view.last_seen_at = Some(super::membership::now()?);
            peer.view.last_error = None;
            save_state(&guard, &state)
        })
        .await
    }

    async fn authorize_pending_request(
        &self,
        principal: &PeerRecord,
        request: &PeerManagementRequest,
    ) -> anyhow::Result<()> {
        let operation_id = management_operation_id(request)
            .context("pending association is scoped to its enrollment operation")?;
        let master = self.master.clone();
        let principal_id = principal.view.node_id.clone();
        let operation_id = operation_id.to_owned();
        let is_prepare_add = matches!(request, PeerManagementRequest::PrepareAdd { .. });
        let is_add_recovery_arm = matches!(request, PeerManagementRequest::ArmAddRecovery { .. });
        let pending_verb_allowed = pending_enrollment_verb(request);
        blocking(move || {
            let guard = acquire_for_migration(&master)?;
            let state = load_state(&guard)?;
            let now = super::membership::now()?;
            if let Some(operation) = state.operations.get(&operation_id) {
                let verb_allowed =
                    operation.preview.kind == NodeOperationKind::Add && pending_verb_allowed;
                let recovery_authorized = operation.recover_until.is_some_and(|until| until > now)
                    || (is_add_recovery_arm
                        && add_recovery_was_armed(operation)
                        && operation.phase == NodeOperationPhase::Paused
                        && operation.paused_from.is_some());
                ensure!(
                    verb_allowed
                        && !operation.phase.terminal()
                        && recovery_authorized
                        && (operation.preview.source_node_id == principal_id
                            || operation.preview.target_node_id == principal_id),
                    "pending association recovery authorization expired"
                );
                return Ok(());
            }
            ensure!(
                is_prepare_add
                    && state.bootstrap.as_ref().is_some_and(|authorization| {
                        authorization.operation_id.as_deref() == Some(&operation_id)
                            && authorization.claimed_by.as_deref() == Some(&principal_id)
                            && authorization.expires_at > now
                    }),
                "pending association authorization expired"
            );
            Ok(())
        })
        .await
    }

    async fn accept_prepare_add(
        &self,
        principal: &PeerRecord,
        command: PreparedAddCommand,
    ) -> anyhow::Result<PeerManagementReply> {
        let PreparedAddCommand {
            operation_id,
            name,
            cluster_id,
            primary_node_id,
            primary_endpoint,
            primary_fingerprint,
            staged_pair,
            replication_credential,
        } = command;
        ensure!(
            super::membership::valid_id(&operation_id),
            "invalid operation identity"
        );
        super::membership::validate_name(&name)?;
        let local = self.ensure_identity().await?;
        ensure!(
            local.saved_role == NodeRole::Standalone,
            "destination membership changed since bootstrap"
        );
        if let Ok(mut existing) = self.operation(&operation_id).await {
            if existing.backup_verified {
                ensure!(
                    (existing.phase == NodeOperationPhase::Prepared
                        || (existing.phase == NodeOperationPhase::Paused
                            && existing.paused_from == Some(NodeOperationPhase::Prepared)))
                        && !existing.cancel_requested,
                    "prepared destination operation is no longer available for review recovery"
                );
                let preview_id = existing
                    .peer_preview_id
                    .clone()
                    .context("prepared destination lifecycle review absent")?;
                let expires_at = super::membership::now()?
                    .checked_add(PREVIEW_TTL)
                    .context("clock overflow")?;
                let lifecycle = super::lifecycle::renew_nodes_staged_join_review(
                    &self.master,
                    &preview_id,
                    &operation_id,
                    expires_at,
                )
                .await?;
                existing.phase = NodeOperationPhase::Prepared;
                existing.paused_from = None;
                existing.preview.expires_at = lifecycle.expires_at;
                existing.message =
                    "Exact staged backup remains unapplied; the reviewed deadline was renewed."
                        .into();
                self.save_operation(existing.clone()).await?;
                return self
                    .peer_reply(
                        Some(&operation_id),
                        existing.peer_preview_id,
                        "Destination preview recovered with a fresh review deadline.",
                    )
                    .await;
            }
        }
        let local_id = local
            .node_id
            .clone()
            .context("local node identity absent")?;
        let now = super::membership::now()?;
        let recover_until = now.checked_add(RECOVERY_TTL).context("clock overflow")?;
        let preview_shell = NodePreview {
            id: operation_id.clone(),
            kind: NodeOperationKind::Add,
            source_node_id: principal.view.node_id.clone(),
            source_name: principal.view.name.clone(),
            source_endpoint: Some(primary_endpoint),
            target_node_id: local_id,
            target_name: name.clone(),
            target_endpoint: self.control_endpoint().await?,
            target_role: NodeRole::Standalone,
            replacement_summary: vec![
                "Prepare exact primary policy and corpus without activating them.".into(),
            ],
            restart_steps: vec![NodeRestartStep {
                step_id: "secondary".into(),
                target: NodeRestartTarget::Secondary,
                requested: false,
                acknowledged: false,
            }],
            before_revision: local_revision(&self.master).await?,
            expires_at: now.checked_add(PREVIEW_TTL).context("clock overflow")?,
        };
        self.insert_or_recover_remote_operation(OperationRecord {
            preview: preview_shell,
            phase: NodeOperationPhase::PreparingTarget,
            paused_from: None,
            message: "Receiving exact policy and corpus from the authenticated primary.".into(),
            last_verified_at: Some(now),
            recover_until: Some(recover_until),
            peer_preview_id: None,
            local_preview_id: None,
            staged_pair: Some(staged_pair.clone()),
            prepared_certificate: None,
            prepared_private_key: None,
            prepared_fingerprint: None,
            restart_requested_at: BTreeMap::new(),
            cluster_id: Some(cluster_id.clone()),
            replication_credential: Some(replication_credential.clone()),
            backup_verified: false,
            cancel_requested: false,
        })
        .await?;
        ensure!(
            primary_node_id == principal.view.node_id
                && super::membership::valid_id(&cluster_id)
                && super::manifest::is_hash(&primary_fingerprint)
                && primary_fingerprint == principal.source_fingerprint,
            "prepared primary identity does not match authenticated peer"
        );
        let (manifest, objects) = fetch_staged_policy(principal, &staged_pair.policy)
            .await
            .context("fetching exact staged policy")?;
        let corpus = fetch_staged_corpus(
            principal,
            &self.master,
            &staged_pair.policy,
            &staged_pair.corpus_generation,
            &operation_id,
            recover_until,
        )
        .await
        .context("fetching exact staged corpus")?;
        let lifecycle = super::lifecycle::preview_nodes_staged_join(
            &self.master,
            super::lifecycle::NodesStagedJoin {
                cluster_id: cluster_id.clone(),
                primary_node_id: principal.view.node_id.clone(),
                primary_endpoint,
                primary_fingerprint: primary_fingerprint.clone(),
                credential: super::pairing::SecondaryCredential {
                    cluster_id,
                    node_id: local.node_id.clone().context("local identity absent")?,
                    primary_node_id: principal.view.node_id.clone(),
                    primary: endpoint_url(primary_endpoint),
                    fingerprint: primary_fingerprint,
                    credential: replication_credential.clone(),
                },
                node_name: name,
                manifest,
                objects,
                corpus_generation: corpus.generation,
                corpus_pin_owner: operation_id.clone(),
                corpus_pin_expires_at: recover_until,
            },
        )
        .await
        .context("preparing destination join and verified backup")?;
        let mut operation = self.operation(&operation_id).await?;
        if operation.cancel_requested || operation.phase == NodeOperationPhase::Cancelled {
            super::lifecycle::cancel(&self.master, &lifecycle.id).await?;
            anyhow::bail!("destination staging was cancelled before the review could be published");
        }
        operation.peer_preview_id = Some(lifecycle.id.clone());
        operation.phase = NodeOperationPhase::Prepared;
        operation.preview.expires_at = lifecycle.expires_at;
        operation.staged_pair = Some(staged_pair);
        operation.replication_credential = Some(replication_credential);
        operation.backup_verified = true;
        operation.message =
            "Exact policy and corpus staged privately; awaiting final apply.".into();
        self.save_operation(operation).await?;
        self.peer_reply(
            Some(&operation_id),
            Some(lifecycle.id),
            "Destination preview prepared.",
        )
        .await
    }

    async fn accept_prepare_edit(
        &self,
        principal: &PeerRecord,
        operation_id: String,
        name: String,
        endpoint: Option<SocketAddr>,
    ) -> anyhow::Result<PeerManagementReply> {
        ensure!(
            principal.view.role == NodeRole::Primary,
            "only the primary may edit this node"
        );
        let current_endpoint = self.control_endpoint().await?;
        let target_endpoint = endpoint.unwrap_or(current_endpoint);
        let endpoint_changed = target_endpoint != current_endpoint;
        if endpoint_changed {
            self.restart.preflight().await?;
        }
        let lifecycle = super::lifecycle::preview_nodes_metadata(
            &self.master,
            name.clone(),
            endpoint_changed.then_some(target_endpoint),
        )
        .await?;
        let local = self.ensure_identity().await?;
        let now = super::membership::now()?;
        let mut prepared_certificate = None;
        let mut prepared_private_key = None;
        let mut prepared_fingerprint = None;
        if endpoint_changed {
            let material = self.listener_material(target_endpoint).await?;
            if let Err(error) = self
                .listeners
                .prepare(NodeListenerSpec {
                    endpoint: target_endpoint,
                    certificate_pem: material.certificate_pem.clone(),
                    private_key_pem: material.private_key_pem.clone(),
                    scope: ListenerScope::Management,
                })
                .await
            {
                let _ = super::lifecycle::cancel(&self.master, &lifecycle.id).await;
                return Err(error.context("prepared Edit listener could not start"));
            }
            prepared_certificate = Some(material.certificate_pem);
            prepared_private_key = Some(material.private_key_pem);
            prepared_fingerprint = Some(material.fingerprint);
        }
        let preview = NodePreview {
            id: operation_id.clone(),
            kind: NodeOperationKind::Edit,
            source_node_id: principal.view.node_id.clone(),
            source_name: principal.view.name.clone(),
            source_endpoint: Some(principal.view.endpoint),
            target_node_id: local.node_id.context("local identity absent")?,
            target_name: name,
            target_endpoint,
            target_role: local.saved_role,
            replacement_summary: vec!["Stable Node ID and policy remain unchanged.".into()],
            restart_steps: vec![NodeRestartStep {
                step_id: "endpoint".into(),
                target: NodeRestartTarget::Secondary,
                requested: false,
                acknowledged: !endpoint_changed,
            }],
            before_revision: local_revision(&self.master).await?,
            expires_at: now.checked_add(PREVIEW_TTL).context("clock overflow")?,
        };
        let record = OperationRecord {
            preview,
            phase: NodeOperationPhase::Prepared,
            paused_from: None,
            message: "Peer-requested metadata change prepared.".into(),
            last_verified_at: Some(now),
            recover_until: Some(now.checked_add(RECOVERY_TTL).context("clock overflow")?),
            peer_preview_id: Some(lifecycle.id.clone()),
            local_preview_id: None,
            staged_pair: self.active.active_pair(),
            prepared_certificate,
            prepared_private_key,
            prepared_fingerprint,
            restart_requested_at: BTreeMap::new(),
            cluster_id: None,
            replication_credential: None,
            backup_verified: false,
            cancel_requested: false,
        };
        if let Err(error) = self.insert_or_recover_remote_operation(record).await {
            let _ = super::lifecycle::cancel(&self.master, &lifecycle.id).await;
            if endpoint_changed {
                let _ = self.listeners.retire(target_endpoint).await;
            }
            return Err(error.context("saving prepared peer Edit"));
        }
        self.peer_reply(Some(&operation_id), Some(lifecycle.id), "Edit prepared.")
            .await
    }

    async fn accept_prepare_remove(
        &self,
        principal: &PeerRecord,
        operation_id: String,
    ) -> anyhow::Result<PeerManagementReply> {
        ensure!(
            principal.view.role == NodeRole::Primary,
            "only the primary may remove this node"
        );
        if let Ok(existing) = self.operation(&operation_id).await {
            ensure!(
                existing.preview.kind == NodeOperationKind::Remove
                    && existing.preview.source_node_id == principal.view.node_id,
                "detach operation identity conflicts with retained history"
            );
            return self
                .peer_reply(
                    Some(&operation_id),
                    existing.peer_preview_id,
                    "Detach already prepared.",
                )
                .await;
        }
        ensure!(
            principal.view.state == NodePeerState::Active,
            "a new detach may only be prepared for an active managed peer"
        );
        let active = self
            .active
            .active_pair()
            .map(|pair| (pair.policy, pair.corpus_generation));
        let lifecycle = super::lifecycle::preview_with_active_pair(
            &self.master,
            LifecycleRequest::Leave,
            active,
        )
        .await?;
        let local = self.ensure_identity().await?;
        let now = super::membership::now()?;
        let preview = NodePreview {
            id: operation_id.clone(),
            kind: NodeOperationKind::Remove,
            source_node_id: principal.view.node_id.clone(),
            source_name: principal.view.name.clone(),
            source_endpoint: Some(principal.view.endpoint),
            target_node_id: local.node_id.context("local identity absent")?,
            target_name: local.node_name,
            target_endpoint: self.control_endpoint().await?,
            target_role: local.saved_role,
            replacement_summary: vec![
                "Retain the last complete policy while becoming standalone.".into()
            ],
            restart_steps: vec![NodeRestartStep {
                step_id: "detach".into(),
                target: NodeRestartTarget::Secondary,
                requested: false,
                acknowledged: false,
            }],
            before_revision: local_revision(&self.master).await?,
            expires_at: now.checked_add(PREVIEW_TTL).context("clock overflow")?,
        };
        self.insert_or_recover_remote_operation(OperationRecord {
            preview,
            phase: NodeOperationPhase::Prepared,
            paused_from: None,
            message: "Detach prepared; active policy remains in service.".into(),
            last_verified_at: Some(now),
            recover_until: Some(now.checked_add(RECOVERY_TTL).context("clock overflow")?),
            peer_preview_id: Some(lifecycle.id.clone()),
            local_preview_id: None,
            staged_pair: self.active.active_pair(),
            prepared_certificate: None,
            prepared_private_key: None,
            prepared_fingerprint: None,
            restart_requested_at: BTreeMap::new(),
            cluster_id: None,
            replication_credential: None,
            backup_verified: false,
            cancel_requested: false,
        })
        .await?;
        self.peer_reply(Some(&operation_id), Some(lifecycle.id), "Detach prepared.")
            .await
    }

    async fn accept_peer_apply(
        &self,
        principal: &PeerRecord,
        operation_id: String,
        preview_id: String,
    ) -> anyhow::Result<PeerManagementReply> {
        let mut operation = self.operation(&operation_id).await?;
        ensure!(
            operation.preview.source_node_id == principal.view.node_id
                && operation.peer_preview_id.as_deref() == Some(&preview_id),
            "peer apply does not match the prepared operation"
        );
        ensure!(
            operation.phase != NodeOperationPhase::Cancelled,
            "cancelled operation cannot be applied"
        );
        if operation.phase == NodeOperationPhase::Complete {
            return self
                .peer_reply(
                    Some(&operation_id),
                    Some(preview_id),
                    "Operation already complete.",
                )
                .await;
        }
        let active = if operation.preview.kind == NodeOperationKind::Remove {
            self.active
                .active_pair()
                .map(|pair| (pair.policy, pair.corpus_generation))
        } else {
            None
        };
        let needs_restart = operation.preview.kind != NodeOperationKind::Edit
            || operation.prepared_certificate.is_some();
        let restart_permit = if needs_restart {
            Some(self.restart.preflight().await?)
        } else {
            None
        };
        operation.phase = NodeOperationPhase::ApplyingTarget;
        operation.message = "Applying the verified destination lifecycle transaction.".into();
        self.save_operation(operation.clone()).await?;
        let result =
            super::lifecycle::apply_with_active_pair(&self.master, &preview_id, active).await?;
        if let (Some(certificate), Some(private_key), Some(fingerprint)) = (
            operation.prepared_certificate.clone(),
            operation.prepared_private_key.clone(),
            operation.prepared_fingerprint.clone(),
        ) {
            let master = self.master.clone();
            let endpoint = operation.preview.target_endpoint;
            blocking(move || {
                let guard = acquire_for_migration(&master)?;
                let mut state = load_state(&guard)?;
                promote_listener(&mut state, endpoint, certificate, private_key, fingerprint)?;
                save_state(&guard, &state)
            })
            .await?;
        }
        if result.status.restart_required
            || operation.prepared_certificate.is_some()
            || operation.preview.kind == NodeOperationKind::Remove
        {
            operation.phase = NodeOperationPhase::RestartingTarget;
            operation.message =
                "Saved with verified backup; waiting for local restart readiness.".into();
            let step_id = operation
                .preview
                .restart_steps
                .first()
                .map(|step| step.step_id.clone())
                .context("restart step absent")?;
            self.persist_restart_request(&mut operation, &step_id)
                .await?;
            self.restart
                .request(
                    restart_permit.context("managed restart permit absent")?,
                    super::managed_restart::ManagedRestartRequest {
                        operation_id: operation.preview.id.clone(),
                        step_id,
                    },
                )
                .await?;
        } else {
            operation.phase = NodeOperationPhase::Complete;
            operation.message = "Metadata update complete; stable identity retained.".into();
            operation.last_verified_at = Some(super::membership::now()?);
            self.save_operation(operation).await?;
        }
        self.peer_reply(Some(&operation_id), Some(preview_id), "Apply accepted.")
            .await
    }

    async fn accept_arm_add_recovery(
        &self,
        principal: &PeerRecord,
        operation_id: String,
        preview_id: String,
    ) -> anyhow::Result<PeerManagementReply> {
        let mut operation = self.operation(&operation_id).await?;
        ensure!(
            operation.preview.kind == NodeOperationKind::Add
                && operation.preview.source_node_id == principal.view.node_id
                && operation.peer_preview_id.as_deref() == Some(preview_id.as_str())
                && operation.backup_verified,
            "recovery arm does not match the reviewed Add operation"
        );
        if matches!(
            operation.phase,
            NodeOperationPhase::Prepared | NodeOperationPhase::Paused
        ) {
            let resumed_phase = operation
                .paused_from
                .unwrap_or(NodeOperationPhase::Prepared);
            let expires_at = super::membership::now()?
                .checked_add(RECOVERY_TTL)
                .context("clock overflow")?;
            super::lifecycle::extend_nodes_join_recovery(
                &self.master,
                &preview_id,
                &operation_id,
                expires_at,
            )
            .await?;
            operation.phase = resumed_phase;
            operation.paused_from = None;
            operation.preview.expires_at = expires_at;
            operation.recover_until = Some(expires_at);
            operation.message =
                "Final Add confirmation armed the reviewed destination recovery window.".into();
            self.save_operation(operation).await?;
        } else {
            ensure!(
                matches!(
                    operation.phase,
                    NodeOperationPhase::ApplyingTarget
                        | NodeOperationPhase::RestartingTarget
                        | NodeOperationPhase::Complete
                ),
                "Add operation cannot arm destination recovery in its current phase"
            );
        }
        self.peer_reply(
            Some(&operation_id),
            Some(preview_id),
            "Reviewed Add recovery is durably armed.",
        )
        .await
    }

    async fn accept_peer_cancel(
        &self,
        principal: &PeerRecord,
        operation_id: String,
        preview_id: Option<String>,
    ) -> anyhow::Result<PeerManagementReply> {
        let mut operation = self.operation(&operation_id).await?;
        if operation.phase == NodeOperationPhase::Cancelled
            && operation.preview.kind == NodeOperationKind::Add
            && operation.preview.source_node_id == principal.view.node_id
            && (preview_id.is_none()
                || operation.peer_preview_id.as_deref() == preview_id.as_deref())
        {
            self.finish_cancelled_add_target_cleanup(&operation, &principal.view.node_id)
                .await?;
            return self
                .peer_reply(
                    Some(&operation_id),
                    operation.peer_preview_id,
                    "Destination cancellation already acknowledged.",
                )
                .await;
        }
        ensure!(
            operation.preview.source_node_id == principal.view.node_id
                && (preview_id.is_none()
                    || operation.peer_preview_id.as_deref() == preview_id.as_deref()),
            "peer cancel does not match the prepared operation"
        );
        ensure!(
            matches!(
                operation.phase,
                NodeOperationPhase::PreparingTarget | NodeOperationPhase::Prepared
            ) || (operation.phase == NodeOperationPhase::Paused
                && operation.preview.kind == NodeOperationKind::Add
                && matches!(
                    operation.paused_from,
                    Some(NodeOperationPhase::PreparingTarget | NodeOperationPhase::Prepared)
                )),
            "applied operation cannot be cancelled"
        );
        operation.cancel_requested = true;
        let lifecycle_id = operation
            .peer_preview_id
            .as_deref()
            .unwrap_or(operation.preview.id.as_str());
        super::lifecycle::cancel_nodes_staged_join_if_present(
            &self.master,
            lifecycle_id,
            &operation.preview.id,
        )
        .await?;
        let master = self.master.clone();
        let pin_owner = operation.preview.id.clone();
        blocking(move || {
            if let Some(store) = super::corpus::CorpusStore::open_existing(&master)? {
                store.release_private_manifest_pin(&pin_owner)?;
            }
            Ok(())
        })
        .await?;
        operation.phase = NodeOperationPhase::Cancelled;
        operation.message = "Destination staging cancelled; active policy unchanged.".into();
        self.save_operation(operation).await?;
        let operation = self.operation(&operation_id).await?;
        self.finish_cancelled_add_target_cleanup(&operation, &principal.view.node_id)
            .await?;
        self.peer_reply(Some(&operation_id), None, "Preview cancelled.")
            .await
    }

    async fn finish_cancelled_add_target_cleanup(
        &self,
        operation: &OperationRecord,
        source_id: &str,
    ) -> anyhow::Result<()> {
        ensure!(
            operation.preview.kind == NodeOperationKind::Add
                && operation.phase == NodeOperationPhase::Cancelled
                && operation.preview.source_node_id == source_id,
            "cancelled target cleanup does not match the exact enrollment"
        );
        let master = self.master.clone();
        let source_id = source_id.to_owned();
        let cancelled_id = operation.preview.id.clone();
        let cleanup_source = source_id.clone();
        let cleanup_id = cancelled_id.clone();
        let current = blocking(move || {
            let guard = acquire_for_migration(&master)?;
            let state = load_state(&guard)?;
            let stored = state
                .operations
                .get(&cancelled_id)
                .context("cancelled enrollment disappeared")?;
            ensure!(
                stored.preview.kind == NodeOperationKind::Add
                    && stored.phase == NodeOperationPhase::Cancelled
                    && stored.preview.source_node_id == source_id,
                "cancelled enrollment changed before cleanup"
            );
            Ok(state.bootstrap.as_ref().is_none_or(|authorization| {
                authorization.operation_id.as_deref() == Some(&cancelled_id)
            }) && !state.operations.values().any(|candidate| {
                candidate.preview.id != cancelled_id
                    && candidate.preview.kind == NodeOperationKind::Add
                    && !candidate.phase.terminal()
                    && candidate.preview.source_node_id == source_id
            }))
        })
        .await?;
        if !current {
            return self
                .acknowledge_cancelled_add_cleanup(&operation.preview.id)
                .await;
        }
        self.retire_prepared_listener(&operation.preview.id).await?;
        let master = self.master.clone();
        blocking(move || {
            let guard = acquire_for_migration(&master)?;
            let mut state = load_state(&guard)?;
            let stored = state
                .operations
                .get(&cleanup_id)
                .context("cancelled enrollment disappeared")?;
            ensure!(
                stored.preview.kind == NodeOperationKind::Add
                    && stored.phase == NodeOperationPhase::Cancelled
                    && stored.preview.source_node_id == cleanup_source,
                "cancelled enrollment changed before cleanup"
            );
            if state.bootstrap.as_ref().is_some_and(|authorization| {
                authorization.operation_id.as_deref() != Some(&cleanup_id)
            }) || state.operations.values().any(|candidate| {
                candidate.preview.id != cleanup_id
                    && candidate.preview.kind == NodeOperationKind::Add
                    && !candidate.phase.terminal()
                    && candidate.preview.source_node_id == cleanup_source
            }) {
                state
                    .operations
                    .get_mut(&cleanup_id)
                    .context("cancelled enrollment disappeared")?
                    .cancel_requested = false;
                save_state(&guard, &state)?;
                return Ok(());
            }
            let peer = state
                .peers
                .get_mut(&cleanup_source)
                .context("cancelled enrollment peer disappeared")?;
            ensure!(
                matches!(
                    peer.view.state,
                    NodePeerState::Pending | NodePeerState::Detached
                ),
                "cancelled enrollment peer changed before cleanup"
            );
            peer.view.state = NodePeerState::Detached;
            if state.bootstrap.as_ref().is_some() {
                state.bootstrap = None;
            }
            state
                .operations
                .get_mut(&cleanup_id)
                .context("cancelled enrollment disappeared")?
                .cancel_requested = false;
            save_state(&guard, &state)
        })
        .await
    }

    async fn resume_local_operation(&self, operation_id: &str) -> anyhow::Result<()> {
        let operation = self.operation(operation_id).await?;
        match operation.phase {
            NodeOperationPhase::RestartingTarget => {
                ensure!(
                    operation
                        .preview
                        .restart_steps
                        .iter()
                        .all(|step| !step.requested || step.acknowledged),
                    "restart is still awaiting verified readiness"
                );
                let mut operation = operation;
                operation.phase = NodeOperationPhase::Complete;
                operation.last_verified_at = Some(super::membership::now()?);
                operation.message = if operation.preview.kind == NodeOperationKind::Remove {
                    "Standalone detach complete; completion receipt retained.".into()
                } else {
                    "Runtime acknowledged the exact reviewed policy and corpus.".into()
                };
                self.save_operation(operation.clone()).await?;
                if matches!(
                    operation.preview.kind,
                    NodeOperationKind::Add | NodeOperationKind::Remove
                ) {
                    let master = self.master.clone();
                    let source_id = operation.preview.source_node_id;
                    let peer_state = if operation.preview.kind == NodeOperationKind::Remove {
                        NodePeerState::PendingDetach
                    } else {
                        NodePeerState::Active
                    };
                    blocking(move || {
                        let guard = acquire_for_migration(&master)?;
                        let mut state = load_state(&guard)?;
                        let peer = state
                            .peers
                            .get_mut(&source_id)
                            .context("removing primary management peer absent")?;
                        peer.view.state = peer_state;
                        save_state(&guard, &state)
                    })
                    .await?;
                }
                Ok(())
            }
            NodeOperationPhase::Complete | NodeOperationPhase::Cancelled => Ok(()),
            _ => Ok(()),
        }
    }

    async fn insert_or_recover_remote_operation(
        &self,
        record: OperationRecord,
    ) -> anyhow::Result<()> {
        let master = self.master.clone();
        blocking(move || {
            let guard = acquire_for_migration(&master)?;
            let mut state = load_state(&guard)?;
            if let Some(existing) = state.operations.get(&record.preview.id) {
                ensure!(
                    existing.preview.kind == record.preview.kind
                        && existing.preview.source_node_id == record.preview.source_node_id
                        && existing.preview.target_node_id == record.preview.target_node_id
                        && !existing.phase.terminal(),
                    "operation identity conflicts with retained history"
                );
                return Ok(());
            }
            ensure!(
                state.operations.len() < MAX_OPERATIONS,
                "too many retained Nodes operations"
            );
            state.operations.insert(record.preview.id.clone(), record);
            save_state(&guard, &state)
        })
        .await
    }

    async fn control_endpoint(&self) -> anyhow::Result<SocketAddr> {
        let master = self.master.clone();
        blocking(move || {
            let guard = acquire_for_migration(&master)?;
            load_state(&guard)?
                .control_endpoint
                .context("Nodes control endpoint is not prepared")
        })
        .await
    }

    async fn peer_reply(
        &self,
        operation_id: Option<&str>,
        preview_id: Option<String>,
        message: impl Into<String>,
    ) -> anyhow::Result<PeerManagementReply> {
        let status = {
            let master = self.master.clone();
            blocking(move || super::lifecycle::status(&master)).await?
        };
        let operation = match operation_id {
            Some(id) => Some(self.operation(id).await?.progress()),
            None => None,
        };
        let node_id = status
            .node_id
            .clone()
            .context("local node identity absent")?;
        let backup_verified = operation_id.map(|id| async move {
            self.operation(id)
                .await
                .map(|operation| operation.backup_verified)
        });
        let backup_verified = match backup_verified {
            Some(future) => future.await?,
            None => false,
        };
        let master = self.master.clone();
        let reply_operation_id = operation_id.map(str::to_owned);
        let (control_endpoint, control_fingerprint, transition_acknowledged) =
            blocking(move || {
                let guard = acquire_for_migration(&master)?;
                let state = load_state(&guard)?;
                let acknowledged = reply_operation_id.as_ref().is_some_and(|operation_id| {
                    state
                        .pending_primary_transition
                        .as_ref()
                        .is_some_and(|transition| {
                            transition.operation_id == *operation_id && transition.acknowledged
                        })
                });
                Ok((
                    state.control_endpoint,
                    state.certificate_fingerprint,
                    acknowledged,
                ))
            })
            .await?;
        Ok(PeerManagementReply {
            node_id,
            status,
            preview_id,
            operation,
            capabilities: NodeCapabilities::current(),
            backup_verified,
            control_endpoint,
            control_fingerprint,
            transition_acknowledged,
            message: message.into(),
        })
    }

    async fn status(&self) -> anyhow::Result<NodeControlStatus> {
        let master = self.master.clone();
        let active = self.active.active_pair();
        blocking(move || {
            let mut membership = super::lifecycle::status(&master)?;
            if let Some(active) = active {
                membership.active_policy = Some(active.policy);
                membership.active_corpus = Some(active.corpus_generation);
            }
            if membership.saved_role == NodeRole::Standalone
                && membership.node_id.is_none()
                && !has_configured_control_endpoint(&master)?
            {
                return Ok(NodeControlStatus {
                    membership,
                    control_endpoint: None,
                    peers: Vec::new(),
                    operations: Vec::new(),
                });
            }
            let guard = acquire_for_migration(&master)?;
            let mut state = load_state(&guard)?;
            expire_state(&mut state, super::membership::now()?);
            let mut peers: Vec<_> = state.peers.values().map(|peer| peer.view.clone()).collect();
            for member in &membership.roster {
                if peers.iter().any(|peer| peer.node_id == member.node_id) {
                    continue;
                }
                let Some(endpoint) = member.endpoint.as_deref().and_then(parse_member_endpoint)
                else {
                    continue;
                };
                peers.push(NodePeer {
                    node_id: member.node_id.clone(),
                    name: member.name.clone(),
                    endpoint,
                    role: NodeRole::Secondary,
                    state: match member.state {
                        super::membership::MemberState::Pending => NodePeerState::Pending,
                        super::membership::MemberState::Active => NodePeerState::Active,
                        super::membership::MemberState::Revoked => NodePeerState::Detached,
                    },
                    capabilities: NodeCapabilities::legacy(),
                    last_seen_at: member.last_confirmation_secs.map(|seconds| {
                        super::membership::now()
                            .unwrap_or_default()
                            .saturating_sub(seconds)
                    }),
                    last_error: None,
                });
            }
            peers.sort_by(|left, right| left.node_id.cmp(&right.node_id));
            let mut operations: Vec<_> = state
                .operations
                .values()
                .map(OperationRecord::progress)
                .collect();
            operations.sort_by(|left, right| left.operation_id.cmp(&right.operation_id));
            Ok(NodeControlStatus {
                membership,
                control_endpoint: state.control_endpoint,
                peers,
                operations,
            })
        })
        .await
    }

    async fn reply(
        &self,
        preview: Option<NodePreview>,
        token: Option<SecretString>,
        message: impl Into<String>,
    ) -> anyhow::Result<NodeControlReply> {
        Ok(NodeControlReply {
            status: self.status().await?,
            preview,
            token,
            message: message.into(),
        })
    }
}

async fn blocking<T: Send + 'static>(
    work: impl FnOnce() -> anyhow::Result<T> + Send + 'static,
) -> anyhow::Result<T> {
    tokio::task::spawn_blocking(work).await?
}

fn load_config(
    guard: &MigrationWriteLock,
) -> anyhow::Result<crate::config::loader::LoadedConfigV5> {
    crate::config::loader::load_config_v5_with_policy_overlays_under_service_migration_guard(
        guard,
        guard.canonical_master(),
        time::OffsetDateTime::now_utc(),
        None,
        None,
    )
    .map_err(|_| anyhow::anyhow!("configuration is unavailable for Nodes control"))
}

fn capture_revision(
    guard: &MigrationWriteLock,
    loaded: &crate::config::loader::LoadedConfigV5,
) -> anyhow::Result<String> {
    let (snapshot, _) =
        crate::config::policy_revision::capture_coherent_loaded_v5_under_migration_guard(
            guard,
            loaded,
            time::OffsetDateTime::now_utc(),
        )?;
    Ok(snapshot.revision().to_string())
}

fn config_role(config: &crate::config::schema::ConfigV5) -> NodeRole {
    if !config.cluster.enabled {
        NodeRole::Standalone
    } else if config.cluster.role == crate::config::schema::ClusterRole::Primary {
        NodeRole::Primary
    } else {
        NodeRole::Secondary
    }
}

fn preferred_endpoint(master: &Path, requested: Option<SocketAddr>) -> anyhow::Result<SocketAddr> {
    let guard = acquire_for_migration(master)?;
    let loaded = load_config(&guard)?;
    let endpoint = requested
        .or(loaded.config.node.control_listen)
        .or_else(|| {
            let api = loaded.config.api.listen;
            (!api.ip().is_unspecified()).then_some(api)
        })
        .context("choose --listen IP:PORT for a reachable Nodes HTTPS endpoint")?;
    ensure!(
        endpoint.port() != 0 && !endpoint.ip().is_unspecified() && !endpoint.ip().is_multicast(),
        "choose a specific unicast IP and nonzero port for the Nodes endpoint"
    );
    Ok(endpoint)
}

fn preferred_source_endpoint(master: &Path, destination: SocketAddr) -> anyhow::Result<SocketAddr> {
    let guard = acquire_for_migration(master)?;
    if let Some(endpoint) = load_config(&guard)?.config.node.control_listen {
        return Ok(endpoint);
    }
    drop(guard);
    let bind = if destination.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = std::net::UdpSocket::bind(bind)?;
    socket.connect(destination)?;
    let local = socket.local_addr()?;
    ensure!(
        !local.ip().is_unspecified() && !local.ip().is_loopback() && !local.ip().is_multicast(),
        "automatic source endpoint selection did not find a routable local address"
    );
    Ok(SocketAddr::new(local.ip(), CONTROL_PORT))
}

fn has_configured_control_endpoint(master: &Path) -> anyhow::Result<bool> {
    let guard = acquire_for_migration(master)?;
    Ok(load_config(&guard)?.config.node.control_listen.is_some())
}

fn reviewed_pair_matches(
    master: &Path,
    reviewed: &ActivePolicyCorpus,
    active: &ActivePolicyCorpus,
) -> anyhow::Result<bool> {
    if reviewed.policy.operator_policy_hash != active.policy.operator_policy_hash {
        return Ok(false);
    }
    let Some(store) = super::corpus::CorpusStore::open_existing(master)? else {
        return Ok(false);
    };
    let reviewed_corpus = store.manifest_metadata(&reviewed.corpus_generation)?;
    let active_corpus = store.manifest_metadata(&active.corpus_generation)?;
    Ok(
        reviewed_corpus.source_plan_hash == active_corpus.source_plan_hash
            && reviewed_corpus.sources == active_corpus.sources
            && reviewed_corpus.auxiliary == active_corpus.auxiliary,
    )
}

async fn local_revision(master: &Path) -> anyhow::Result<String> {
    let master = master.to_owned();
    blocking(move || {
        let guard = acquire_for_migration(&master)?;
        let loaded = load_config(&guard)?;
        capture_revision(&guard, &loaded)
    })
    .await
}

async fn post_pinned<T: Serialize + ?Sized, R: serde::de::DeserializeOwned>(
    endpoint: SocketAddr,
    fingerprint: &str,
    path: &str,
    bearer: Option<&str>,
    value: &T,
) -> anyhow::Result<R> {
    post_pinned_with_timeout(
        endpoint,
        fingerprint,
        path,
        bearer,
        value,
        std::time::Duration::from_secs(30),
    )
    .await
}

async fn post_pinned_with_timeout<T: Serialize + ?Sized, R: serde::de::DeserializeOwned>(
    endpoint: SocketAddr,
    fingerprint: &str,
    path: &str,
    bearer: Option<&str>,
    value: &T,
    timeout: std::time::Duration,
) -> anyhow::Result<R> {
    let origin = endpoint_url(endpoint);
    let client = super::pinned::build_fingerprint_client(&origin, fingerprint, timeout)?;
    let mut request = client.post(format!("{origin}{path}")).json(value);
    if let Some(bearer) = bearer {
        request = request.bearer_auth(bearer);
    }
    let response = request.send().await.context("Nodes HTTPS request failed")?;
    ensure!(
        response.status().is_success(),
        "managed node refused the request ({})",
        response.status()
    );
    let bytes = read_bounded(response, 512 * 1024).await?;
    serde_json::from_slice(&bytes).context("invalid managed node response")
}

async fn send_management(
    peer: &PeerRecord,
    request: &PeerManagementRequest,
) -> anyhow::Result<PeerManagementReply> {
    let timeout = if matches!(request, PeerManagementRequest::PrepareAdd { .. }) {
        PREPARE_ADD_TIMEOUT
    } else {
        std::time::Duration::from_secs(30)
    };
    post_pinned_with_timeout(
        peer.view.endpoint,
        &peer.source_fingerprint,
        "/api/nodes/v2/manage",
        Some(&peer.outgoing_credential.0),
        request,
        timeout,
    )
    .await
}

async fn get_pinned(peer: &PeerRecord, path: &str) -> anyhow::Result<reqwest::Response> {
    let origin = endpoint_url(peer.view.endpoint);
    super::pinned::build_fingerprint_client(
        &origin,
        &peer.source_fingerprint,
        std::time::Duration::from_secs(300),
    )?
    .get(format!("{origin}{path}"))
    .bearer_auth(&peer.outgoing_credential.0)
    .send()
    .await
    .context("staged Nodes transfer failed")
}

async fn read_bounded(mut response: reqwest::Response, limit: u64) -> anyhow::Result<Vec<u8>> {
    ensure!(response.status().is_success(), "staged object unavailable");
    ensure!(
        response
            .content_length()
            .is_none_or(|length| length <= limit),
        "staged object exceeds reviewed size"
    );
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        ensure!(
            (bytes.len() as u64).saturating_add(chunk.len() as u64) <= limit,
            "staged object exceeds reviewed size"
        );
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

async fn fetch_staged_policy(
    peer: &PeerRecord,
    identity: &ArtifactIdentity,
) -> anyhow::Result<(super::manifest::Manifest, BTreeMap<String, Arc<[u8]>>)> {
    let delivery: super::dto::ManifestResponse = serde_json::from_slice(
        &read_bounded(
            get_pinned(
                peer,
                &format!(
                    "/api/nodes/v2/staging/artifacts/{}/manifest",
                    identity.artifact_hash
                ),
            )
            .await?,
            (super::manifest::MAX_MANIFEST_BYTES + 128) as u64,
        )
        .await?,
    )?;
    ensure!(
        delivery.available_until > super::membership::now()?,
        "staged policy availability expired"
    );
    delivery.manifest.validate()?;
    ensure!(
        ArtifactIdentity::from(&delivery.manifest) == *identity,
        "staged policy identity changed"
    );
    let mut objects = BTreeMap::new();
    let mut total = 0u64;
    for object in std::iter::once(delivery.manifest.policy_toml.clone())
        .chain(delivery.manifest.packs.iter().map(|pack| pack.object()))
    {
        if objects.contains_key(&object.sha256) {
            continue;
        }
        total = total
            .checked_add(object.bytes)
            .context("policy size overflow")?;
        ensure!(
            total <= super::manifest::MAX_APPLY_BYTES as u64,
            "reviewed policy exceeds transfer limit"
        );
        let bytes = read_bounded(
            get_pinned(
                peer,
                &format!(
                    "/api/nodes/v2/staging/artifacts/{}/objects/{}",
                    identity.artifact_hash, object.sha256
                ),
            )
            .await?,
            object.bytes,
        )
        .await?;
        ensure!(
            super::manifest::ObjectRef::of(&bytes) == object,
            "staged policy object digest mismatch"
        );
        objects.insert(object.sha256, Arc::from(bytes));
    }
    super::artifact::verify_objects(&delivery.manifest, &objects)?;
    Ok((delivery.manifest, objects))
}

async fn fetch_staged_corpus(
    peer: &PeerRecord,
    master: &Path,
    identity: &ArtifactIdentity,
    expected_generation: &str,
    pin_owner: &str,
    pin_expires_at: u64,
) -> anyhow::Result<super::corpus::CorpusManifest> {
    let manifest: super::corpus::CorpusManifest = serde_json::from_slice(
        &read_bounded(
            get_pinned(
                peer,
                &format!(
                    "/api/nodes/v2/staging/corpus/{}/manifest",
                    identity.artifact_hash
                ),
            )
            .await?,
            super::corpus::MAX_MANIFEST_BYTES as u64,
        )
        .await?,
    )?;
    manifest.validate()?;
    ensure!(
        &manifest.artifact == identity && manifest.generation == expected_generation,
        "staged corpus identity changed"
    );
    let store = Arc::new(
        super::corpus::CorpusStore::open(master)
            .context("opening private destination corpus store")?,
    );
    let mut objects = BTreeMap::new();
    for object in manifest.objects() {
        if let Some(previous) = objects.insert(object.sha256.clone(), object.clone()) {
            ensure!(previous == *object, "staged corpus object size conflict");
        }
    }
    for object in objects.into_values() {
        let owned = Arc::clone(&store);
        let expected = object.clone();
        if blocking(move || Ok(owned.has_object(&expected))).await? {
            continue;
        }
        let owned = Arc::clone(&store);
        let expected = object.clone();
        let mut stage = blocking(move || owned.stage(&expected))
            .await
            .context("creating destination corpus object stage")?;
        let mut response = get_pinned(
            peer,
            &format!("/api/nodes/v2/staging/corpus/objects/{}", object.sha256),
        )
        .await?;
        ensure!(
            response.status().is_success(),
            "staged corpus object unavailable"
        );
        ensure!(
            response
                .content_length()
                .is_none_or(|length| length == object.bytes),
            "staged corpus object length mismatch"
        );
        while let Some(chunk) = response.chunk().await? {
            stage = blocking(move || {
                stage.write_chunk(&chunk)?;
                Ok(stage)
            })
            .await
            .context("writing destination corpus object stage")?;
        }
        let owned = Arc::clone(&store);
        blocking(move || stage.finish(&owned))
            .await
            .context("verifying destination corpus object stage")?;
    }
    let prepared = manifest.clone();
    let owner = pin_owner.to_owned();
    blocking(move || store.prepare_manifest_private_pinned(&prepared, &owner, pin_expires_at))
        .await
        .context("pinning private destination corpus manifest")?;
    Ok(manifest)
}

fn load_state(guard: &MigrationWriteLock) -> anyhow::Result<ControlState> {
    let files = PrivateStore::open(guard, STORE)?;
    let state = files
        .read(STATE, MAX_STATE_BYTES)?
        .map(|bytes| serde_json::from_slice(&bytes))
        .transpose()?
        .unwrap_or_default();
    validate_state(&state)?;
    Ok(state)
}

fn save_state(guard: &MigrationWriteLock, state: &ControlState) -> anyhow::Result<()> {
    validate_state(state)?;
    PrivateStore::open(guard, STORE)?.write(STATE, &serde_json::to_vec(state)?)
}

fn promote_listener(
    state: &mut ControlState,
    endpoint: SocketAddr,
    certificate_pem: String,
    private_key_pem: SecretString,
    fingerprint: String,
) -> anyhow::Result<()> {
    if state.control_endpoint != Some(endpoint) {
        if let (
            Some(previous_endpoint),
            Some(previous_certificate),
            Some(previous_key),
            Some(previous_fingerprint),
        ) = (
            state.control_endpoint,
            state.certificate_pem.clone(),
            state.private_key_pem.clone(),
            state.certificate_fingerprint.clone(),
        ) {
            state.previous_listener = Some(ListenerMaterial {
                endpoint: previous_endpoint,
                certificate_pem: previous_certificate,
                private_key_pem: previous_key,
                fingerprint: previous_fingerprint,
            });
        }
    }
    state.control_endpoint = Some(endpoint);
    state.certificate_pem = Some(certificate_pem);
    state.private_key_pem = Some(private_key_pem);
    state.certificate_fingerprint = Some(fingerprint);
    Ok(())
}

fn current_listener_material(state: &ControlState) -> Option<ListenerMaterial> {
    Some(ListenerMaterial {
        endpoint: state.control_endpoint?,
        certificate_pem: state.certificate_pem.clone()?,
        private_key_pem: state.private_key_pem.clone()?,
        fingerprint: state.certificate_fingerprint.clone()?,
    })
}

fn listener_material_from_spec(spec: NodeListenerSpec) -> anyhow::Result<ListenerMaterial> {
    use rustls::pki_types::pem::PemObject;

    let certificate =
        rustls::pki_types::CertificateDer::pem_slice_iter(spec.certificate_pem.as_bytes())
            .next()
            .context("compatible listener certificate is empty")??;
    Ok(ListenerMaterial {
        endpoint: spec.endpoint,
        fingerprint: hex::encode(Sha256::digest(certificate.as_ref())),
        certificate_pem: spec.certificate_pem,
        private_key_pem: spec.private_key_pem,
    })
}

fn validate_state(state: &ControlState) -> anyhow::Result<()> {
    ensure!(
        state.format == FORMAT
            && state.peers.len() <= MAX_PEERS
            && state.operations.len() <= MAX_OPERATIONS,
        "invalid Nodes control state"
    );
    for (id, peer) in &state.peers {
        ensure!(
            id == &peer.view.node_id
                && super::membership::valid_id(id)
                && peer.view.endpoint.port() != 0
                && (peer.view.state == NodePeerState::Detached
                    || super::manifest::is_hash(&peer.incoming_credential_hash))
                && super::manifest::is_hash(&peer.source_fingerprint),
            "invalid managed peer"
        );
        super::membership::validate_name(&peer.view.name)?;
    }
    for (id, operation) in &state.operations {
        ensure!(
            id == &operation.preview.id
                && super::membership::valid_id(id)
                && super::membership::valid_id(&operation.preview.source_node_id)
                && super::membership::valid_id(&operation.preview.target_node_id),
            "invalid durable Nodes operation"
        );
    }
    ensure!(
        state.released_corpus_pins.iter().all(|operation_id| {
            super::membership::valid_id(operation_id) && state.operations.contains_key(operation_id)
        }),
        "invalid released corpus pin record"
    );
    Ok(())
}

fn add_recovery_was_armed(operation: &OperationRecord) -> bool {
    operation.preview.kind == NodeOperationKind::Add
        && operation.backup_verified
        && operation.recover_until == Some(operation.preview.expires_at)
}

fn verified_add_recovery_is_live(operation: &OperationRecord, now: u64) -> bool {
    operation.preview.kind == NodeOperationKind::Add
        && operation.backup_verified
        && operation.recover_until.is_some_and(|until| until > now)
        && matches!(
            operation.phase,
            NodeOperationPhase::Prepared | NodeOperationPhase::Paused
        )
}

fn retire_claimed_bootstrap_after_completed_detach(
    state: &mut ControlState,
    operation_id: &str,
    source_id: &str,
) -> anyhow::Result<()> {
    let operation = state
        .operations
        .get(operation_id)
        .context("completed detach operation absent")?;
    ensure!(
        operation.preview.kind == NodeOperationKind::Remove
            && operation.preview.source_node_id == source_id
            && operation.phase == NodeOperationPhase::Complete,
        "bootstrap retirement requires a completed detach operation"
    );
    if state
        .bootstrap
        .as_ref()
        .is_some_and(|authorization| authorization.claimed_by.as_deref() == Some(source_id))
    {
        state.bootstrap = None;
    }
    Ok(())
}

fn expire_state(state: &mut ControlState, now: u64) {
    let expired_bootstrap_peer = state.bootstrap.as_ref().and_then(|authorization| {
        let expired = authorization.expires_at <= now;
        let retained_operation = authorization
            .operation_id
            .as_ref()
            .and_then(|id| state.operations.get(id))
            .is_some_and(|operation| {
                !operation.phase.terminal()
                    && ((operation.phase == NodeOperationPhase::PreparingTarget
                        && operation.recover_until.is_some_and(|until| until > now))
                        || verified_add_recovery_is_live(operation, now)
                        || add_recovery_was_armed(operation))
            });
        (expired && !retained_operation)
            .then(|| authorization.claimed_by.clone())
            .flatten()
    });
    if state.bootstrap.as_ref().is_some_and(|authorization| {
        authorization.expires_at <= now
            && (authorization.claimed_by.is_none() || expired_bootstrap_peer.is_some())
    }) {
        state.bootstrap = None;
    }
    if let Some(peer_id) = expired_bootstrap_peer {
        if let Some(peer) = state.peers.get_mut(&peer_id) {
            if peer.view.state == NodePeerState::Pending {
                peer.view.state = NodePeerState::Detached;
                peer.outgoing_credential.0.clear();
                peer.incoming_credential_hash.clear();
                peer.issued_incoming_credential = None;
            }
        }
    }
    for operation in state.operations.values_mut() {
        if operation.phase == NodeOperationPhase::Prepared
            && operation.preview.expires_at <= now
            && !add_recovery_was_armed(operation)
        {
            if operation.preview.kind == NodeOperationKind::Add {
                operation.paused_from = Some(NodeOperationPhase::Prepared);
                operation.phase = NodeOperationPhase::Paused;
                operation.message = "Review expired while the remote Add remains recoverable; cancel or resume the exact operation.".into();
            } else {
                operation.phase = NodeOperationPhase::Paused;
                operation.message = "Review expired; prepare the operation again.".into();
            }
        } else if operation.recover_until.is_some_and(|deadline| {
            deadline <= now
                && !operation.phase.terminal()
                && operation.phase != NodeOperationPhase::Paused
        }) {
            operation.paused_from = Some(operation.phase);
            operation.phase = NodeOperationPhase::Paused;
            operation.message = "Recovery paused; an operator may renew it with Resume.".into();
        }
    }
    let expired_receipts: Vec<_> = state
        .detach_receipts
        .iter()
        .filter(|(_, acknowledged_at)| acknowledged_at.saturating_add(DETACH_RECEIPT_TTL) <= now)
        .map(|(operation_id, _)| operation_id.clone())
        .collect();
    for operation_id in expired_receipts {
        if let Some((source_id, target_id)) =
            state.operations.get(&operation_id).and_then(|operation| {
                (operation.preview.kind == NodeOperationKind::Remove
                    && operation.phase == NodeOperationPhase::Complete)
                    .then(|| {
                        (
                            operation.preview.source_node_id.clone(),
                            operation.preview.target_node_id.clone(),
                        )
                    })
            })
        {
            for peer_id in [source_id, target_id] {
                if let Some(peer) = state.peers.get_mut(&peer_id) {
                    if matches!(
                        peer.view.state,
                        NodePeerState::PendingDetach | NodePeerState::Detached
                    ) {
                        peer.view.state = NodePeerState::Detached;
                        peer.outgoing_credential.0.clear();
                        peer.incoming_credential_hash.clear();
                        peer.issued_incoming_credential = None;
                    }
                }
            }
        }
    }
    let protected_transition = state
        .pending_primary_transition
        .as_ref()
        .map(|pending| pending.operation_id.clone());
    let detach_receipts = state.detach_receipts.clone();
    state.operations.retain(|operation_id, operation| {
        let pending_detach_receipt = operation.preview.kind == NodeOperationKind::Remove
            && operation.phase == NodeOperationPhase::Complete
            && !detach_receipts.contains_key(operation_id);
        let retained_detach_receipt =
            detach_receipts
                .get(operation_id)
                .is_some_and(|acknowledged_at| {
                    acknowledged_at.saturating_add(OPERATION_RETENTION) > now
                });
        let protected = pending_detach_receipt
            || retained_detach_receipt
            || protected_transition.as_deref() == Some(operation_id);
        let retained_at = operation
            .last_verified_at
            .unwrap_or(operation.preview.expires_at);
        protected
            || !operation.phase.terminal()
            || retained_at.saturating_add(OPERATION_RETENTION) > now
    });
    let retained_operations: BTreeSet<_> = state.operations.keys().cloned().collect();
    state
        .detach_receipts
        .retain(|operation_id, acknowledged_at| {
            retained_operations.contains(operation_id)
                && acknowledged_at.saturating_add(OPERATION_RETENTION) > now
        });
    state
        .released_corpus_pins
        .retain(|operation_id| retained_operations.contains(operation_id));
}

fn rotating_batch(mut operation_ids: Vec<String>, now: u64) -> Vec<String> {
    if operation_ids.len() <= 8 {
        return operation_ids;
    }
    let offset = (now as usize) % operation_ids.len();
    operation_ids.rotate_left(offset);
    operation_ids.truncate(8);
    operation_ids
}

fn detach_outbox_ids(state: &ControlState, local_node_id: &str, now: u64) -> Vec<String> {
    rotating_batch(
        state
            .operations
            .values()
            .filter(|operation| {
                operation.preview.kind == NodeOperationKind::Remove
                    && operation.phase == NodeOperationPhase::Complete
                    && operation.preview.target_node_id == local_node_id
                    && !state.detach_receipts.contains_key(&operation.preview.id)
            })
            .map(|operation| operation.preview.id.clone())
            .collect(),
        now,
    )
}

fn listener_specs(state: &ControlState) -> Vec<NodeListenerSpec> {
    let mut listeners = Vec::new();
    let now = super::membership::now().unwrap_or_default();
    let authorized = state.bootstrap.is_some()
        || state
            .detach_receipts
            .values()
            .any(|acknowledged_at| acknowledged_at.saturating_add(DETACH_RECEIPT_TTL) > now)
        || state
            .peers
            .values()
            .any(|peer| peer.view.state != NodePeerState::Detached);
    if !authorized {
        return listeners;
    }
    if let Some(previous) = state.previous_listener.as_ref() {
        listeners.push(NodeListenerSpec {
            endpoint: previous.endpoint,
            certificate_pem: previous.certificate_pem.clone(),
            private_key_pem: previous.private_key_pem.clone(),
            scope: ListenerScope::Management,
        });
    }
    if let (Some(endpoint), Some(certificate_pem), Some(private_key_pem)) = (
        state.control_endpoint,
        state.certificate_pem.clone(),
        state.private_key_pem.clone(),
    ) {
        listeners.push(NodeListenerSpec {
            endpoint,
            certificate_pem,
            private_key_pem,
            scope: if state.bootstrap.is_some() && state.peers.is_empty() {
                ListenerScope::Bootstrap
            } else {
                ListenerScope::Management
            },
        });
    }
    listeners
}

fn endpoint_url(endpoint: SocketAddr) -> String {
    format!("https://{endpoint}")
}

fn parse_member_endpoint(value: &str) -> Option<SocketAddr> {
    value
        .strip_prefix("https://")
        .unwrap_or(value)
        .trim_end_matches('/')
        .parse()
        .ok()
}

fn management_operation_id(request: &PeerManagementRequest) -> Option<&str> {
    match request {
        PeerManagementRequest::PrepareAdd { operation_id, .. }
        | PeerManagementRequest::Apply { operation_id, .. }
        | PeerManagementRequest::Cancel { operation_id, .. }
        | PeerManagementRequest::PrepareEdit { operation_id, .. }
        | PeerManagementRequest::PrepareRemove { operation_id }
        | PeerManagementRequest::Resume { operation_id }
        | PeerManagementRequest::ArmAddRecovery { operation_id, .. }
        | PeerManagementRequest::AcknowledgeEndpoint { operation_id }
        | PeerManagementRequest::AcknowledgeDetach { operation_id }
        | PeerManagementRequest::DetachReceipt { operation_id, .. }
        | PeerManagementRequest::AdoptPrimaryEndpoint { operation_id, .. } => Some(operation_id),
        PeerManagementRequest::Status => None,
    }
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
}

/// Router mounted by the runtime on a Nodes TLS listener or a compatible shared socket.
pub fn node_router(controller: Arc<NodeController>) -> Router {
    Router::new()
        .route("/api/nodes/v2/bootstrap/claim", post(bootstrap_claim))
        .route("/api/nodes/v2/manage", post(peer_manage))
        .route(
            "/api/nodes/v2/staging/artifacts/{artifact}/manifest",
            get(staged_artifact_manifest),
        )
        .route(
            "/api/nodes/v2/staging/artifacts/{artifact}/objects/{object}",
            get(staged_artifact_object),
        )
        .route(
            "/api/nodes/v2/staging/corpus/{artifact}/manifest",
            get(staged_corpus_manifest),
        )
        .route(
            "/api/nodes/v2/staging/corpus/objects/{object}",
            get(staged_corpus_object),
        )
        .route("/api/nodes/v2/health", get(node_health))
        .with_state(controller)
}

async fn node_health() -> StatusCode {
    StatusCode::NO_CONTENT
}

async fn bootstrap_claim(
    State(controller): State<Arc<NodeController>>,
    Json(request): Json<BootstrapClaimRequest>,
) -> Response {
    match controller.accept_bootstrap(request).await {
        Ok(reply) => (StatusCode::OK, Json(reply)).into_response(),
        Err(error) => safe_error(error),
    }
}

async fn peer_manage(
    State(controller): State<Arc<NodeController>>,
    headers: HeaderMap,
    Json(request): Json<PeerManagementRequest>,
) -> Response {
    let Some(credential) = bearer(&headers).map(str::to_owned) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let Ok(transition) = controller.transition_gate.clone().try_lock_owned() else {
        return StatusCode::CONFLICT.into_response();
    };
    // Admission happens before spawning. Once admitted, the body owns the
    // guard until all blocking work finishes even if this response is dropped.
    let worker = controller.clone();
    match tokio::spawn(async move {
        let _transition = transition;
        worker
            .accept_management_admitted(&credential, request)
            .await
    })
    .await
    {
        Ok(Ok(reply)) => (StatusCode::OK, Json(reply)).into_response(),
        Ok(Err(error)) => safe_error(error),
        Err(error) => safe_error(anyhow::Error::new(error)),
    }
}

async fn staged_artifact_manifest(
    State(controller): State<Arc<NodeController>>,
    headers: HeaderMap,
    RoutePath(artifact): RoutePath<String>,
) -> Response {
    if authorize_staging(
        &controller,
        &headers,
        StagingResource::Artifact(artifact.clone()),
    )
    .await
    .is_err()
    {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let master = controller.master.clone();
    match blocking(move || {
        let guard = acquire_for_migration(&master)?;
        let mut store = super::publication::PublicationStore::open(&guard)?;
        let delivery = store.deliver_manifest(&artifact, super::membership::now()?)?;
        Ok(super::dto::ManifestResponse {
            manifest: super::manifest::Manifest::decode(&delivery.artifact.manifest)?,
            available_until: delivery.available_until,
        })
    })
    .await
    {
        Ok(manifest) => Json(manifest).into_response(),
        Err(error) => safe_error(error),
    }
}

async fn staged_artifact_object(
    State(controller): State<Arc<NodeController>>,
    headers: HeaderMap,
    RoutePath((artifact, object)): RoutePath<(String, String)>,
) -> Response {
    if authorize_staging(
        &controller,
        &headers,
        StagingResource::ArtifactObject {
            artifact: artifact.clone(),
            object: object.clone(),
        },
    )
    .await
    .is_err()
    {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let master = controller.master.clone();
    match blocking(move || {
        let guard = acquire_for_migration(&master)?;
        super::publication::PublicationStore::open(&guard)?.object(&artifact, &object)
    })
    .await
    {
        Ok(bytes) => (
            [(header::CONTENT_TYPE, "application/octet-stream")],
            axum::body::Bytes::from_owner(bytes),
        )
            .into_response(),
        Err(error) => safe_error(error),
    }
}

async fn staged_corpus_manifest(
    State(controller): State<Arc<NodeController>>,
    headers: HeaderMap,
    RoutePath(artifact): RoutePath<String>,
) -> Response {
    if authorize_staging(
        &controller,
        &headers,
        StagingResource::Corpus(artifact.clone()),
    )
    .await
    .is_err()
    {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let master = controller.master.clone();
    match blocking(move || {
        super::corpus::CorpusStore::open(&master)?.manifest_for_artifact(&artifact)
    })
    .await
    {
        Ok(manifest) => Json(manifest).into_response(),
        Err(error) => safe_error(error),
    }
}

async fn staged_corpus_object(
    State(controller): State<Arc<NodeController>>,
    headers: HeaderMap,
    RoutePath(object): RoutePath<String>,
) -> Response {
    if authorize_staging(
        &controller,
        &headers,
        StagingResource::CorpusObject(object.clone()),
    )
    .await
    .is_err()
    {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let master = controller.master.clone();
    match blocking(move || super::corpus::CorpusStore::open(&master)?.authorized_object(&object))
        .await
    {
        Ok(file) => {
            let Ok(length) = file.metadata().map(|metadata| metadata.len()) else {
                return StatusCode::SERVICE_UNAVAILABLE.into_response();
            };
            let body = Body::from_stream(tokio_util::io::ReaderStream::new(
                tokio::fs::File::from_std(file),
            ));
            (
                [
                    (header::CONTENT_TYPE, "application/octet-stream".into()),
                    (header::CONTENT_LENGTH, length.to_string()),
                ],
                body,
            )
                .into_response()
        }
        Err(error) => safe_error(error),
    }
}

fn require_active_management_member(
    guard: &MigrationWriteLock,
    node_id: &str,
    name: &str,
) -> anyhow::Result<()> {
    let member = super::membership::MembershipStore::open(guard)?
        .views(super::membership::now()?)
        .into_iter()
        .find(|member| member.node_id == node_id)
        .context("authenticated node is absent from primary membership")?;
    ensure!(
        member.state == super::membership::MemberState::Active && member.name == name,
        "authenticated node is no longer an active member"
    );
    Ok(())
}

fn pending_enrollment_verb(request: &PeerManagementRequest) -> bool {
    matches!(
        request,
        PeerManagementRequest::PrepareAdd { .. }
            | PeerManagementRequest::Apply { .. }
            | PeerManagementRequest::Cancel { .. }
            | PeerManagementRequest::Resume { .. }
            | PeerManagementRequest::ArmAddRecovery { .. }
    )
}

enum StagingResource {
    Artifact(String),
    ArtifactObject { artifact: String, object: String },
    Corpus(String),
    CorpusObject(String),
}

fn authorize_reviewed_resource(
    guard: &MigrationWriteLock,
    master: &Path,
    reviewed: &ActivePolicyCorpus,
    resource: StagingResource,
) -> anyhow::Result<()> {
    match resource {
        StagingResource::Artifact(artifact) => ensure!(
            super::manifest::is_hash(&artifact) && artifact == reviewed.policy.artifact_hash,
            "artifact is outside the reviewed enrollment"
        ),
        StagingResource::ArtifactObject { artifact, object } => {
            ensure!(
                super::manifest::is_hash(&artifact)
                    && super::manifest::is_hash(&object)
                    && artifact == reviewed.policy.artifact_hash,
                "artifact object is outside the reviewed enrollment"
            );
            super::publication::PublicationStore::open(guard)?.object(&artifact, &object)?;
        }
        StagingResource::Corpus(artifact) => ensure!(
            super::manifest::is_hash(&artifact) && artifact == reviewed.policy.artifact_hash,
            "corpus is outside the reviewed enrollment"
        ),
        StagingResource::CorpusObject(object) => {
            ensure!(
                super::manifest::is_hash(&object),
                "invalid corpus object identity"
            );
            let manifest = super::corpus::CorpusStore::open(master)?
                .manifest_metadata(&reviewed.corpus_generation)?;
            ensure!(
                manifest.objects().any(|expected| expected.sha256 == object),
                "corpus object is outside the reviewed enrollment"
            );
        }
    }
    Ok(())
}

async fn authorize_staging(
    controller: &NodeController,
    headers: &HeaderMap,
    resource: StagingResource,
) -> anyhow::Result<()> {
    let credential = bearer(headers).context("missing managed node credential")?;
    let peer = controller.authenticate_peer(credential).await?;
    ensure!(
        matches!(
            peer.view.state,
            NodePeerState::Pending | NodePeerState::Active
        ),
        "peer may not receive staged policy"
    );
    let master = controller.master.clone();
    let peer_node_id = peer.view.node_id.clone();
    blocking(move || {
        let guard = acquire_for_migration(&master)?;
        let state = load_state(&guard)?;
        let now = super::membership::now()?;
        let reviewed = state.operations.values().find_map(|operation| {
            (operation.preview.kind == NodeOperationKind::Add
                && operation.preview.target_node_id == peer.view.node_id
                && !operation.phase.terminal()
                && ((operation.phase == NodeOperationPhase::PreparingTarget
                    && operation.recover_until.is_some_and(|until| until > now))
                    || (operation.phase == NodeOperationPhase::Prepared
                        && operation.preview.expires_at > now
                        && !operation.cancel_requested)))
                .then_some(operation.staged_pair.as_ref())
                .flatten()
        });
        let reviewed = reviewed.context("no live staged enrollment for peer")?;
        authorize_reviewed_resource(&guard, &master, reviewed, resource)
    })
    .await?;
    controller.touch_peer(&peer_node_id).await
}

fn safe_error(error: anyhow::Error) -> Response {
    tracing::warn!(error = ?error, "Nodes control request refused");
    (StatusCode::BAD_REQUEST, "Nodes operation refused").into_response()
}

#[cfg(test)]
mod security_tests;
#[cfg(test)]
mod tests;
