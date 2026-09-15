//! Shared, reviewed node lifecycle operations for CLI and local IPC.

pub use super::membership::SecretString;
use super::membership::{MemberState, MemberView};
use anyhow::{ensure, Context};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum LifecycleRequest {
    Create {
        san: Vec<String>,
        api_listen: Option<SocketAddr>,
        #[serde(default)]
        migrate_legacy: bool,
    },
    Join {
        primary: String,
        invitation: SecretString,
        #[serde(default)]
        node_name: Option<String>,
    },
    Leave,
    ResetIdentity,
    Rename {
        name: String,
    },
    Invite,
    Revoke {
        node_id: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleOperation {
    Create,
    Join,
    Leave,
    Rename,
    Invite,
    Revoke,
    Cancel,
    ResetIdentity,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LifecyclePreview {
    pub id: String,
    pub operation: LifecycleOperation,
    pub local_node_id: String,
    pub local_node_name: String,
    pub primary_node_id: Option<String>,
    pub primary_address: Option<String>,
    pub primary_fingerprint: Option<String>,
    pub replacement_summary: Vec<String>,
    pub restart_required: bool,
    pub expires_at: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeRole {
    #[default]
    Standalone,
    Primary,
    Secondary,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct LifecycleStatus {
    pub node_id: Option<String>,
    pub node_name: String,
    pub saved_role: NodeRole,
    /// None means no runtime evidence was supplied by the local daemon.
    pub active_role: Option<NodeRole>,
    pub restart_required: bool,
    pub legacy_migration_required: bool,
    pub can_edit_policy: bool,
    pub pending_join: bool,
    pub pending_preview_id: Option<String>,
    pub cluster_id: Option<String>,
    pub primary_node_id: Option<String>,
    pub primary_name: Option<String>,
    pub primary_address: Option<String>,
    pub primary_fingerprint: Option<String>,
    pub roster: Vec<MemberView>,
    pub desired_policy: Option<super::dto::ArtifactIdentity>,
    pub active_policy: Option<super::dto::ArtifactIdentity>,
    pub desired_corpus: Option<String>,
    pub active_corpus: Option<String>,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LifecycleResult {
    pub operation: LifecycleOperation,
    pub status: LifecycleStatus,
    pub backup_id: Option<String>,
    /// Returned only by an explicit invitation creation operation.
    pub invitation: Option<SecretString>,
    pub message: String,
}

#[derive(Clone, Serialize, Deserialize)]
struct PreparedPlan {
    preview: LifecyclePreview,
    before_revision: String,
    candidate: Vec<PlanMember>,
    credential: Option<super::pairing::SecondaryCredential>,
    #[serde(default)]
    credential_replacement: bool,
    #[serde(default)]
    primary_fingerprint_replacement: bool,
    #[serde(default)]
    superseded_runtime_preview: Option<String>,
    manifest: Option<super::manifest::Manifest>,
    #[serde(default)]
    corpus_generation: Option<String>,
    #[serde(default)]
    private_corpus_pin_owner: Option<String>,
    #[serde(default)]
    private_corpus_pin_expires_at: Option<u64>,
    revoke_id: Option<String>,
    create_material: Option<CreateMaterial>,
    committed: bool,
    #[serde(default)]
    runtime_acknowledged: bool,
    #[serde(default)]
    completed_at: Option<u64>,
    #[serde(default)]
    pending_expires_at: Option<u64>,
    #[serde(default)]
    backup_id: Option<String>,
    #[serde(default)]
    invitation: Option<SecretString>,
}
#[derive(Clone, Serialize, Deserialize)]
struct CreateMaterial {
    cluster_id: String,
    certificate: String,
    key: SecretString,
    fingerprint: String,
}
#[derive(Clone, Serialize, Deserialize)]
struct PlanMember {
    path: PathBuf,
    kind: u8,
    #[serde(with = "plan_bytes")]
    bytes: Vec<u8>,
}

use super::store::PrivateStore;
use crate::config::loader::{self, LoadedConfigV5};
use crate::config::policy_revision::{
    PolicyMemberKind, PolicyMemberState, PolicyRevisionInventory, PolicyRevisionMember,
};
use crate::config::policy_transaction::{self, Persistence, PrepareOutcome, ReceiptStore};
use crate::config::write_lock::{acquire_for_migration, MigrationWriteLock};
const PLANS: &str = ".warden-node-lifecycle";
const MAX_PLAN: u64 = 128 * 1024 * 1024;

pub fn status(master: &Path) -> anyhow::Result<LifecycleStatus> {
    let guard = acquire_for_migration(master)?;
    let loaded = load(&guard)?;
    status_locked(&guard, &loaded)
}

fn status_locked(
    guard: &MigrationWriteLock,
    loaded: &LoadedConfigV5,
) -> anyhow::Result<LifecycleStatus> {
    let c = &loaded.config;
    let role = role_of(c);
    let mut primary_name = None;
    let roster = if role == NodeRole::Primary && c.cluster.membership_version == Some(1) {
        super::membership::MembershipStore::open(guard)?.views(super::membership::now()?)
    } else if role == NodeRole::Secondary && c.cluster.membership_version == Some(1) {
        let files = PrivateStore::open(guard, super::membership::STORE)?;
        if let Some(bytes) = files.read("roster-cache.json", 128 * 1024)? {
            let mut cached: super::pairing::CachedRoster = serde_json::from_slice(&bytes)?;
            ensure!(
                c.cluster.cluster_id.as_deref() == Some(&cached.cluster_id)
                    && c.cluster.primary_node_id.as_deref() == Some(&cached.primary_node_id),
                "cached roster belongs to another membership"
            );
            primary_name = Some(cached.primary_name.clone());
            let elapsed = super::membership::now()?.saturating_sub(cached.observed_at);
            for peer in &mut cached.peers {
                peer.last_confirmation_secs = peer
                    .last_confirmation_secs
                    .map(|secs| secs.saturating_add(elapsed));
                if elapsed > 45 && peer.state != MemberState::Revoked {
                    peer.sync = Some("stale".into());
                }
            }
            cached.peers.push(MemberView {
                node_id: cached.primary_node_id,
                name: cached.primary_name,
                state: MemberState::Active,
                admitted_at: 0,
                expires_at: None,
                endpoint: c.cluster.peer.clone(),
                sync: Some(if elapsed > 45 { "stale" } else { "current" }.into()),
                last_confirmation_secs: Some(elapsed),
                fingerprint: c.cluster.primary_cert_fingerprint.clone(),
            });
            cached.peers
        } else {
            Vec::new()
        }
    } else {
        Vec::new()
    };
    let files = PrivateStore::open(guard, PLANS)?;
    let pending: Option<PendingMarker> = files
        .read("pending.lockdata", 512)?
        .map(|bytes| serde_json::from_slice(&bytes))
        .transpose()?;
    let runtime: Option<RuntimeMarker> = files
        .read("runtime.lockdata", 512)?
        .map(|bytes| serde_json::from_slice(&bytes))
        .transpose()?;
    for id in pending
        .as_ref()
        .map(|m| &m.preview_id)
        .into_iter()
        .chain(runtime.as_ref().map(|m| &m.preview_id))
    {
        ensure!(
            super::membership::valid_id(id),
            "invalid node transition identity"
        );
    }
    let now = super::membership::now()?;
    let pending_join = pending.as_ref().is_some_and(|m| m.expires_at > now);
    let pending_preview_id = pending.filter(|_| pending_join).map(|m| m.preview_id);
    let restart_required = runtime.is_some_and(|m| m.committed);
    let mut desired_policy = None;
    let mut desired_corpus = None;
    if role == NodeRole::Secondary && c.cluster.membership_version == Some(1) {
        if let Some(store) = super::corpus::CorpusStore::open_existing(guard.canonical_master())? {
            let pair = store.pair_state()?;
            if let Some(generation) = pair.desired.or(pair.persisted) {
                let manifest = store.manifest_metadata(&generation)?;
                desired_policy = Some(manifest.artifact);
                desired_corpus = Some(generation);
            }
        }
    }
    Ok(LifecycleStatus {
        desired_policy,
        desired_corpus,
        node_id: c.node.id.clone(),
        node_name: c.node.display_name().into(),
        saved_role: role,
        restart_required,
        legacy_migration_required: c.cluster.enabled && c.cluster.membership_version != Some(1),
        can_edit_policy: role != NodeRole::Secondary
            && !pending_join
            && policy_edit_allowed_under_migration_guard(guard)?,
        pending_join,
        pending_preview_id,
        cluster_id: c.cluster.cluster_id.clone(),
        primary_node_id: c.cluster.primary_node_id.clone(),
        primary_name,
        primary_address: c.cluster.peer.clone(),
        primary_fingerprint: c.cluster.primary_cert_fingerprint.clone(),
        roster,
        ..Default::default()
    })
}

fn role_of(config: &crate::config::schema::ConfigV5) -> NodeRole {
    if !config.cluster.enabled {
        NodeRole::Standalone
    } else if config.cluster.role == crate::config::schema::ClusterRole::Primary {
        NodeRole::Primary
    } else {
        NodeRole::Secondary
    }
}

pub async fn preview(master: &Path, request: LifecycleRequest) -> anyhow::Result<LifecyclePreview> {
    preview_with_active_pair(master, request, None).await
}

#[derive(Clone)]
pub(crate) struct NodesPrimaryMaterial {
    pub cluster_id: String,
    pub endpoint: SocketAddr,
    pub certificate: String,
    pub private_key: SecretString,
    pub fingerprint: String,
}

/// Prepare primary membership on the Nodes listener while preserving API settings.
pub(crate) async fn preview_nodes_primary(
    master: &Path,
    material: NodesPrimaryMaterial,
) -> anyhow::Result<LifecyclePreview> {
    let path = master.to_path_buf();
    tokio::task::spawn_blocking(move || prepare_nodes_primary_local(&path, material)).await?
}

/// Prepare node metadata and listener changes without changing its stable identity.
pub(crate) async fn preview_nodes_metadata(
    master: &Path,
    name: String,
    endpoint: Option<SocketAddr>,
) -> anyhow::Result<LifecyclePreview> {
    let path = master.to_path_buf();
    tokio::task::spawn_blocking(move || prepare_nodes_metadata_local(&path, name, endpoint)).await?
}

pub async fn preview_primary_activation_recovery(
    master: &Path,
    endpoint: SocketAddr,
) -> anyhow::Result<LifecyclePreview> {
    let path = master.to_path_buf();
    tokio::task::spawn_blocking(move || prepare_primary_activation_recovery_local(&path, endpoint))
        .await?
}

pub async fn apply_primary_activation_recovery(
    master: &Path,
    preview_id: &str,
) -> anyhow::Result<LifecycleResult> {
    let path = master.to_path_buf();
    let id = preview_id.to_owned();
    tokio::task::spawn_blocking(move || {
        let guard = acquire_for_migration(&path)?;
        let plan = read_plan(&guard, &id)?;
        ensure!(
            plan.primary_fingerprint_replacement,
            "preview is not a primary activation recovery"
        );
        Ok::<_, anyhow::Error>(())
    })
    .await??;
    apply(master, preview_id).await
}

pub(crate) async fn preview_nodes_secondary_primary_rebind(
    master: &Path,
    primary_node_id: String,
    endpoint: SocketAddr,
    fingerprint: String,
) -> anyhow::Result<LifecyclePreview> {
    let path = master.to_path_buf();
    tokio::task::spawn_blocking(move || {
        prepare_nodes_secondary_primary_rebind_local(&path, primary_node_id, endpoint, fingerprint)
    })
    .await?
}

pub async fn preview_with_active_pair(
    master: &Path,
    request: LifecycleRequest,
    expected_active: Option<(super::dto::ArtifactIdentity, String)>,
) -> anyhow::Result<LifecyclePreview> {
    let path = master.to_path_buf();
    let join = match &request {
        LifecycleRequest::Join {
            primary,
            invitation,
            ..
        } => Some((
            primary.clone(),
            super::membership::Invitation::decode(invitation, super::membership::now()?)?,
        )),
        _ => None,
    };
    let mut plan = tokio::task::spawn_blocking(move || {
        prepare_local_with_active_pair(&path, request, expected_active.as_ref())
    })
    .await??;
    if let Some((primary, invitation)) = join {
        let credential = plan.credential.as_ref().context("join credential absent")?;
        if let Err(error) = super::pairing::enroll(
            &primary,
            &invitation,
            credential,
            &plan.preview.local_node_name,
        )
        .await
        {
            anyhow::bail!(
                "enrollment incomplete; cancel preview {} or let pending admission expire: {error}",
                plan.preview.id
            );
        }
        let (manifest, objects) =
            super::pairing::fetch_policy(credential)
                .await
                .map_err(|error| {
                    anyhow::anyhow!(
                        "policy preview incomplete; cancel preview {}: {error}",
                        plan.preview.id
                    )
                })?;
        let corpus = super::pairing::fetch_join_corpus(
            master,
            credential,
            &super::dto::ArtifactIdentity::from(&manifest),
        )
        .await?;
        plan.corpus_generation = Some(corpus.generation);
        let path = master.to_path_buf();
        plan = tokio::task::spawn_blocking(move || finish_join(&path, plan, manifest, objects))
            .await??;
    }
    Ok(plan.preview)
}

#[cfg(test)]
fn prepare_local(master: &Path, request: LifecycleRequest) -> anyhow::Result<PreparedPlan> {
    prepare_local_with_active_pair(master, request, None)
}

fn prepare_local_with_active_pair(
    master: &Path,
    request: LifecycleRequest,
    expected_active: Option<&(super::dto::ArtifactIdentity, String)>,
) -> anyhow::Result<PreparedPlan> {
    prepare_local_with_active_pair_and_id(master, request, expected_active, None)
}

fn prepare_local_with_active_pair_and_id(
    master: &Path,
    request: LifecycleRequest,
    expected_active: Option<&(super::dto::ArtifactIdentity, String)>,
    preview_id: Option<&str>,
) -> anyhow::Result<PreparedPlan> {
    if let Some(id) = preview_id {
        ensure!(
            super::membership::valid_id(id),
            "invalid lifecycle preview identity"
        );
    }
    let guard = acquire_for_migration(master)?;
    let receipts = receipts(&guard)?;
    ensure!(
        policy_transaction::recover_active(&guard, &receipts)?
            != policy_transaction::RecoveryOutcome::LegacyActive,
        "migration recovery required"
    );
    if !matches!(
        &request,
        LifecycleRequest::Rename { .. }
            | LifecycleRequest::Invite
            | LifecycleRequest::Revoke { .. }
    ) {
        ensure!(
            policy_edit_allowed_under_migration_guard(&guard)?,
            "a node transition is pending; cancel its preview or restart after applying it"
        );
    }
    if matches!(&request, LifecycleRequest::Leave) {
        check_leave_active_pair(&guard, expected_active)?;
    }
    let loaded = load(&guard)?;
    let (snapshot, loaded) =
        crate::config::policy_revision::capture_coherent_loaded_v5_under_migration_guard(
            &guard,
            &loaded,
            time::OffsetDateTime::now_utc(),
        )?;
    let mut config = loaded.config.clone();
    config.node.ensure_identity().map_err(anyhow::Error::msg)?;
    let mut plan = PreparedPlan {
        preview: LifecyclePreview {
            id: preview_id
                .map(str::to_owned)
                .unwrap_or_else(super::membership::random_id),
            operation: LifecycleOperation::Rename,
            local_node_id: config.node.id.clone().unwrap(),
            local_node_name: config.node.display_name().into(),
            primary_node_id: None,
            primary_address: None,
            primary_fingerprint: None,
            replacement_summary: Vec::new(),
            restart_required: false,
            expires_at: super::membership::now()?
                .checked_add(super::membership::INVITE_TTL)
                .context("clock overflow")?,
        },
        before_revision: snapshot.revision().to_string(),
        candidate: Vec::new(),
        credential: None,
        credential_replacement: false,
        primary_fingerprint_replacement: false,
        superseded_runtime_preview: None,
        manifest: None,
        corpus_generation: None,
        private_corpus_pin_owner: None,
        private_corpus_pin_expires_at: None,
        revoke_id: None,
        create_material: None,
        committed: false,
        runtime_acknowledged: false,
        completed_at: None,
        pending_expires_at: None,
        backup_id: None,
        invitation: None,
    };
    let current_role = role_of(&config);
    match request {
        LifecycleRequest::Join {
            primary,
            invitation,
            node_name,
        } => {
            plan.pending_expires_at = Some(
                super::membership::now()?
                    .checked_add(super::membership::PENDING_TTL)
                    .context("clock overflow")?,
            );
            ensure!(current_role == NodeRole::Standalone, "leave existing membership before association; legacy membership requires explicit migration");
            let invite =
                super::membership::Invitation::decode(&invitation, super::membership::now()?)?;
            if let Some(name) = node_name {
                config.node.name = Some(name);
                config.node.validate().map_err(anyhow::Error::msg)?;
            }
            let credential = super::pairing::SecondaryCredential {
                cluster_id: invite.cluster_id.clone(),
                node_id: config.node.id.clone().unwrap(),
                primary_node_id: invite.primary_node_id.clone(),
                primary: primary.clone(),
                fingerprint: invite.fingerprint.clone(),
                credential: SecretString(crate::auth::token::generate_token().0),
            };
            super::pairing::secondary_client(&credential)?;
            plan.preview.operation = LifecycleOperation::Join;
            plan.preview.local_node_name = config.node.display_name().into();
            plan.preview.primary_node_id = Some(invite.primary_node_id.clone());
            plan.preview.primary_address = Some(primary.clone());
            plan.preview.primary_fingerprint = Some(invite.fingerprint.clone());
            plan.preview.restart_required = true;
            plan.preview.replacement_summary = vec!["Replace this node's policy with the primary's reviewed policy; keep local settings and verified transaction backup.".into()];
            config.cluster.enabled = true;
            config.cluster.role = crate::config::schema::ClusterRole::Secondary;
            config.cluster.membership_version = Some(1);
            config.cluster.cluster_id = Some(invite.cluster_id);
            config.cluster.primary_node_id = Some(invite.primary_node_id);
            config.cluster.primary_cert_fingerprint = Some(invite.fingerprint);
            config.cluster.peer = Some(primary);
            config.cluster.token_hash = None;
            config.cluster.peer_cert = None;
            plan.credential = Some(credential);
        }
        LifecycleRequest::Create {
            san,
            api_listen,
            migrate_legacy,
        } => {
            ensure!(
                current_role == NodeRole::Standalone
                    || (migrate_legacy && config.cluster.membership_version != Some(1)),
                "node is already a member; legacy conversion requires explicit migration"
            );
            ensure!(
                current_role != NodeRole::Secondary,
                "secondary must leave before creating a primary"
            );
            let sans = san
                .iter()
                .map(|s| super::certgen::classify_san(s).map_err(anyhow::Error::msg))
                .collect::<anyhow::Result<Vec<_>>>()?;
            let cert =
                super::certgen::generate_self_signed(&sans, 3650, time::OffsetDateTime::now_utc())?;
            let cluster_id = super::membership::random_id();
            config.cluster.enabled = true;
            config.cluster.role = crate::config::schema::ClusterRole::Primary;
            config.cluster.membership_version = Some(1);
            config.cluster.cluster_id = Some(cluster_id.clone());
            config.cluster.primary_node_id = config.node.id.clone();
            config.cluster.primary_cert_fingerprint = Some(cert.fingerprint_sha256.clone());
            config.cluster.token_hash = None;
            config.cluster.peer = None;
            config.cluster.peer_cert = None;
            config.api.enabled = true;
            if let Some(listen) = api_listen {
                config.api.listen = listen;
            }
            ensure!(config.api.listen.port() != 0, "choose an API listen port");
            config.api.tls_cert = Some(
                guard
                    .identity()
                    .root
                    .join(format!("nodes-{}.crt", plan.preview.id)),
            );
            config.api.tls_key = Some(
                guard
                    .identity()
                    .root
                    .join(format!("nodes-{}.key", plan.preview.id)),
            );
            plan.create_material = Some(CreateMaterial {
                cluster_id,
                certificate: cert.cert_pem,
                key: SecretString(cert.key_pem),
                fingerprint: cert.fingerprint_sha256,
            });
            plan.preview.operation = LifecycleOperation::Create;
            plan.preview.restart_required = true;
            plan.preview.replacement_summary.push("Create primary membership; retained backup includes the previous local configuration. Existing shared credentials stop working after restart.".into());
        }
        LifecycleRequest::Leave => {
            if current_role == NodeRole::Primary {
                ensure!(
                    config.cluster.membership_version == Some(1),
                    "legacy primary requires explicit migration before leave"
                );
                let members = super::membership::MembershipStore::open(&guard)?
                    .views(super::membership::now()?);
                ensure!(
                    !members.iter().any(|m| m.state != MemberState::Revoked),
                    "primary cannot leave with active or pending peers; revoke them first"
                );
            }
            config.cluster = Default::default();
            if config.api.token_hash.as_deref().is_none_or(str::is_empty) {
                config.api.enabled = false;
            }
            plan.preview.operation = LifecycleOperation::Leave;
            plan.preview.restart_required = current_role != NodeRole::Standalone;
            plan.preview.replacement_summary.push("Retain current committed policy and Custom Lists as standalone; disconnect replication. Restoring the prior backup is a separate operation.".into());
        }
        LifecycleRequest::ResetIdentity => {
            ensure!(
                current_role == NodeRole::Standalone,
                "leave membership before resetting node identity"
            );
            config.node.id =
                Some(crate::config::schema::node::generate_node_id().map_err(anyhow::Error::msg)?);
            plan.preview.local_node_id = config.node.id.clone().unwrap();
            plan.preview.operation = LifecycleOperation::ResetIdentity;
            plan.preview.restart_required = true;
        }
        LifecycleRequest::Rename { name } => {
            crate::config::schema::node::validate_node_name(&name).map_err(anyhow::Error::msg)?;
            config.node.name = Some(name.clone());
            plan.preview.local_node_name = name;
        }
        LifecycleRequest::Invite => {
            ensure!(
                current_role == NodeRole::Primary && config.cluster.membership_version == Some(1),
                "invitations require a modern primary"
            );
            plan.preview.operation = LifecycleOperation::Invite;
        }
        LifecycleRequest::Revoke { node_id } => {
            ensure!(
                current_role == NodeRole::Primary && config.cluster.membership_version == Some(1),
                "revocation requires a modern primary"
            );
            ensure!(
                super::membership::MembershipStore::open(&guard)?
                    .views(super::membership::now()?)
                    .iter()
                    .any(|m| m.node_id == node_id),
                "unknown node identity"
            );
            plan.preview.operation = LifecycleOperation::Revoke;
            plan.revoke_id = Some(node_id);
        }
    }
    if matches!(
        plan.preview.operation,
        LifecycleOperation::Rename | LifecycleOperation::Invite | LifecycleOperation::Revoke
    ) {
        plan.candidate = inventory_plan(snapshot.inventory());
        if plan.preview.operation == LifecycleOperation::Rename {
            let main = plan
                .candidate
                .iter_mut()
                .find(|m| m.kind == 0)
                .context("master absent")?;
            let mut value: toml::Value = std::str::from_utf8(&main.bytes)?.parse()?;
            value
                .as_table_mut()
                .context("master table absent")?
                .insert("node".into(), toml::Value::try_from(&config.node)?);
            main.bytes = toml::to_string_pretty(&value)?.into_bytes();
        }
    } else {
        config.includes.clear();
        plan.candidate.push(PlanMember {
            path: guard
                .canonical_master()
                .strip_prefix(&guard.identity().root)?
                .to_owned(),
            kind: 0,
            bytes: toml::to_string_pretty(&config)?.into_bytes(),
        });
        plan.candidate.extend(
            inventory_plan(snapshot.inventory())
                .into_iter()
                .filter(|m| m.kind == 2),
        );
    }
    if plan.credential.is_none() {
        validate_plan(&guard, snapshot.inventory(), &plan)?;
    }
    save_plan(&guard, &plan)?;
    Ok(plan)
}

fn prepare_nodes_primary_local(
    master: &Path,
    material: NodesPrimaryMaterial,
) -> anyhow::Result<LifecyclePreview> {
    ensure!(
        material.endpoint.port() != 0
            && !material.endpoint.ip().is_unspecified()
            && !material.endpoint.ip().is_multicast()
            && super::manifest::is_hash(&material.fingerprint),
        "invalid Nodes primary endpoint or certificate"
    );
    let original_api = {
        let guard = acquire_for_migration(master)?;
        load(&guard)?.config.api.clone()
    };
    let mut plan = prepare_local_with_active_pair(
        master,
        LifecycleRequest::Create {
            san: vec![material.endpoint.ip().to_string()],
            api_listen: None,
            migrate_legacy: false,
        },
        None,
    )?;
    let guard = acquire_for_migration(master)?;
    let main = plan
        .candidate
        .iter_mut()
        .find(|member| member.kind == 0)
        .context("master candidate absent")?;
    let mut config: crate::config::schema::ConfigV5 =
        toml::from_str(std::str::from_utf8(&main.bytes)?)?;
    config.api = original_api;
    config.node.control_listen = Some(material.endpoint);
    config.cluster.primary_cert_fingerprint = Some(material.fingerprint.clone());
    main.bytes = toml::to_string_pretty(&config)?.into_bytes();
    let create = plan
        .create_material
        .as_mut()
        .context("primary material absent")?;
    create.certificate = material.certificate;
    create.key = material.private_key;
    create.fingerprint = material.fingerprint;
    create.cluster_id = material.cluster_id.clone();
    config.cluster.cluster_id = Some(material.cluster_id);
    main.bytes = toml::to_string_pretty(&config)?.into_bytes();
    let loaded = load(&guard)?;
    let (snapshot, _) =
        crate::config::policy_revision::capture_coherent_loaded_v5_under_migration_guard(
            &guard,
            &loaded,
            time::OffsetDateTime::now_utc(),
        )?;
    validate_plan(&guard, snapshot.inventory(), &plan)?;
    save_plan(&guard, &plan)?;
    Ok(plan.preview)
}

pub(crate) struct NodesStagedJoin {
    pub cluster_id: String,
    pub primary_node_id: String,
    pub primary_endpoint: SocketAddr,
    pub primary_fingerprint: String,
    pub credential: super::pairing::SecondaryCredential,
    pub node_name: String,
    pub manifest: super::manifest::Manifest,
    pub objects: BTreeMap<String, std::sync::Arc<[u8]>>,
    pub corpus_generation: String,
    pub corpus_pin_owner: String,
    pub corpus_pin_expires_at: u64,
}

pub(crate) async fn preview_nodes_staged_join(
    master: &Path,
    staged: NodesStagedJoin,
) -> anyhow::Result<LifecyclePreview> {
    let path = master.to_path_buf();
    tokio::task::spawn_blocking(move || {
        let existing = {
            let guard = acquire_for_migration(&path)?;
            let exists = {
                let files = PrivateStore::open(&guard, PLANS)?;
                read_index(&files)?
                    .entries
                    .contains_key(&staged.corpus_pin_owner)
            };
            exists
                .then(|| read_plan(&guard, &staged.corpus_pin_owner))
                .transpose()?
        };
        let invitation = super::membership::Invitation {
            version: super::membership::MEMBERSHIP_VERSION,
            cluster_id: staged.cluster_id.clone(),
            primary_node_id: staged.primary_node_id.clone(),
            fingerprint: staged.primary_fingerprint.clone(),
            expires_at: super::membership::now()?
                .checked_add(super::membership::INVITE_TTL)
                .context("clock overflow")?,
            secret: SecretString(crate::auth::token::generate_token().0),
        };
        let encoded = invitation.encode()?;
        let mut plan = if let Some(existing) = existing {
            ensure!(
                existing.preview.operation == LifecycleOperation::Join
                    && !existing.committed
                    && existing.preview.id == staged.corpus_pin_owner,
                "staged join recovery conflicts with retained lifecycle state"
            );
            existing
        } else {
            prepare_local_with_active_pair_and_id(
                &path,
                LifecycleRequest::Join {
                    primary: endpoint_url(staged.primary_endpoint),
                    invitation: encoded,
                    node_name: Some(staged.node_name),
                },
                None,
                Some(&staged.corpus_pin_owner),
            )?
        };
        if let Some(existing_manifest) = plan.manifest.as_ref() {
            let existing_credential = plan
                .credential
                .as_ref()
                .context("staged join recovery credential absent")?;
            ensure!(
                serde_json::to_vec(existing_credential)? == serde_json::to_vec(&staged.credential)?
                    && existing_manifest.encode()? == staged.manifest.encode()?
                    && plan.corpus_generation.as_deref() == Some(staged.corpus_generation.as_str()),
                "staged join inputs changed during recovery"
            );
        }
        plan.credential = Some(staged.credential);
        plan.corpus_generation = Some(staged.corpus_generation.clone());
        plan.private_corpus_pin_owner = Some(staged.corpus_pin_owner.clone());
        plan.private_corpus_pin_expires_at = Some(staged.corpus_pin_expires_at);
        if plan.manifest.is_some() {
            let guard = acquire_for_migration(&path)?;
            renew_private_corpus_pin(&guard, &plan, staged.corpus_pin_expires_at)?;
            save_plan(&guard, &plan)?;
        } else {
            plan = finish_join(&path, plan, staged.manifest, staged.objects)?;
        }
        let guard = acquire_for_migration(&path)?;
        let loaded = load(&guard)?;
        let (snapshot, _) =
            crate::config::policy_revision::capture_coherent_loaded_v5_under_migration_guard(
                &guard,
                &loaded,
                time::OffsetDateTime::now_utc(),
            )?;
        let backup = serde_json::to_vec(&inventory_plan(snapshot.inventory()))?;
        {
            let files = PrivateStore::open(&guard, PLANS)?;
            let name = format!("backup-{}.data", plan.preview.id);
            if let Some(existing) = files.read(&name, MAX_PLAN)? {
                ensure!(existing == backup, "verified backup changed during preview");
            } else {
                files.create(&name, &backup)?;
            }
            ensure!(
                files.read(&name, MAX_PLAN)?.as_deref() == Some(backup.as_slice()),
                "backup verification failed"
            );
        }
        // A staged join becomes reviewable only after its exact private
        // backup is verified. Refresh the durable lifecycle plan here, rather
        // than only the controller's display copy of the deadline.
        let review_expires_at = super::membership::now()?
            .checked_add(super::membership::INVITE_TTL)
            .context("clock overflow")?;
        renew_private_corpus_pin(&guard, &plan, review_expires_at)?;
        plan.private_corpus_pin_expires_at = Some(review_expires_at);
        plan.pending_expires_at = Some(review_expires_at);
        plan.preview.expires_at = review_expires_at;
        save_plan(&guard, &plan)?;
        Ok(plan.preview)
    })
    .await?
}

fn endpoint_url(endpoint: SocketAddr) -> String {
    format!("https://{endpoint}")
}

fn prepare_primary_activation_recovery_local(
    master: &Path,
    endpoint: SocketAddr,
) -> anyhow::Result<LifecyclePreview> {
    ensure_local_listener_endpoint(endpoint)?;
    let (superseded, cluster_id, node_id, node_name) = {
        let guard = acquire_for_migration(master)?;
        let loaded = load(&guard)?;
        let config = &loaded.config;
        ensure!(
            role_of(config) == NodeRole::Primary
                && config.cluster.membership_version == Some(1)
                && config.api.enabled,
            "primary activation recovery requires a saved modern primary with API enabled"
        );
        let node_id = config
            .node
            .id
            .clone()
            .context("saved primary node identity absent")?;
        let cluster_id = config
            .cluster
            .cluster_id
            .clone()
            .context("saved primary cluster identity absent")?;
        ensure!(
            config.cluster.primary_node_id.as_deref() == Some(&node_id),
            "saved primary identity is inconsistent"
        );
        let marker: RuntimeMarker = {
            let files = PrivateStore::open(&guard, PLANS)?;
            serde_json::from_slice(
                &files
                    .read("runtime.lockdata", 512)?
                    .context("saved primary has no pending activation")?,
            )?
        };
        ensure!(
            marker.committed,
            "primary activation transaction has not committed"
        );
        let original = read_plan(&guard, &marker.preview_id)?;
        ensure!(
            original.preview.operation == LifecycleOperation::Create
                && original.committed
                && !original.runtime_acknowledged
                && original.preview.local_node_id == node_id,
            "pending activation is not an unacknowledged primary creation"
        );
        let members = super::membership::MembershipStore::open(&guard)?;
        ensure!(
            members.matches(&cluster_id, &node_id)
                && members
                    .views(super::membership::now()?)
                    .iter()
                    .all(|member| member.state == MemberState::Revoked),
            "primary activation recovery requires the original peerless membership"
        );
        (
            marker.preview_id,
            cluster_id,
            node_id,
            config.node.display_name().to_owned(),
        )
    };
    let certificate = super::certgen::generate_self_signed(
        &[super::certgen::San::Ip(endpoint.ip())],
        3650,
        time::OffsetDateTime::now_utc(),
    )?;
    let mut plan =
        prepare_local_with_active_pair(master, LifecycleRequest::Rename { name: node_name }, None)?;
    ensure!(
        plan.preview.local_node_id == node_id,
        "stable node identity changed during recovery preview"
    );
    let guard = acquire_for_migration(master)?;
    let main = plan
        .candidate
        .iter_mut()
        .find(|member| member.kind == 0)
        .context("master candidate absent")?;
    let mut config: crate::config::schema::ConfigV5 =
        toml::from_str(std::str::from_utf8(&main.bytes)?)?;
    config.node.control_listen = Some(endpoint);
    config.api.listen = endpoint;
    config.api.tls_cert = Some(
        guard
            .identity()
            .root
            .join(format!("nodes-{}.crt", plan.preview.id)),
    );
    config.api.tls_key = Some(
        guard
            .identity()
            .root
            .join(format!("nodes-{}.key", plan.preview.id)),
    );
    config.cluster.primary_cert_fingerprint = Some(certificate.fingerprint_sha256.clone());
    main.bytes = toml::to_string_pretty(&config)?.into_bytes();
    plan.create_material = Some(CreateMaterial {
        cluster_id: cluster_id.clone(),
        certificate: certificate.cert_pem,
        key: SecretString(certificate.key_pem),
        fingerprint: certificate.fingerprint_sha256.clone(),
    });
    plan.primary_fingerprint_replacement = true;
    plan.superseded_runtime_preview = Some(superseded);
    plan.preview.restart_required = true;
    plan.preview.primary_address = Some(endpoint_url(endpoint));
    plan.preview.primary_fingerprint = Some(certificate.fingerprint_sha256.clone());
    plan.preview.replacement_summary = vec![
        format!("Keep stable primary Node ID {node_id} and cluster ID {cluster_id}."),
        format!("Replace the pending primary listener with {endpoint}."),
        format!(
            "Replace the API and membership certificate pin with {}.",
            certificate.fingerprint_sha256
        ),
        "Keep all policy and Custom Lists unchanged; restart remains operator-controlled.".into(),
    ];
    let loaded = load(&guard)?;
    let (snapshot, _) =
        crate::config::policy_revision::capture_coherent_loaded_v5_under_migration_guard(
            &guard,
            &loaded,
            time::OffsetDateTime::now_utc(),
        )?;
    validate_plan(&guard, snapshot.inventory(), &plan)?;
    save_plan(&guard, &plan)?;
    Ok(plan.preview)
}

fn prepare_nodes_metadata_local(
    master: &Path,
    name: String,
    endpoint: Option<SocketAddr>,
) -> anyhow::Result<LifecyclePreview> {
    let mut plan = prepare_local_with_active_pair(master, LifecycleRequest::Rename { name }, None)?;
    if let Some(endpoint) = endpoint {
        ensure!(
            endpoint.port() != 0
                && !endpoint.ip().is_unspecified()
                && !endpoint.ip().is_multicast(),
            "invalid Nodes control endpoint"
        );
        let guard = acquire_for_migration(master)?;
        let main = plan
            .candidate
            .iter_mut()
            .find(|member| member.kind == 0)
            .context("master candidate absent")?;
        let mut value: toml::Value = std::str::from_utf8(&main.bytes)?.parse()?;
        let table = value.as_table_mut().context("master table absent")?;
        let node = table
            .entry("node")
            .or_insert_with(|| toml::Value::Table(toml::Table::new()))
            .as_table_mut()
            .context("node table invalid")?;
        node.insert(
            "control_listen".into(),
            toml::Value::String(endpoint.to_string()),
        );
        main.bytes = toml::to_string_pretty(&value)?.into_bytes();
        let loaded = load(&guard)?;
        let (snapshot, _) =
            crate::config::policy_revision::capture_coherent_loaded_v5_under_migration_guard(
                &guard,
                &loaded,
                time::OffsetDateTime::now_utc(),
            )?;
        validate_plan(&guard, snapshot.inventory(), &plan)?;
        save_plan(&guard, &plan)?;
    }
    Ok(plan.preview)
}

fn prepare_nodes_secondary_primary_rebind_local(
    master: &Path,
    primary_node_id: String,
    endpoint: SocketAddr,
    fingerprint: String,
) -> anyhow::Result<LifecyclePreview> {
    ensure!(
        endpoint.port() != 0
            && !endpoint.ip().is_unspecified()
            && !endpoint.ip().is_multicast()
            && super::membership::valid_id(&primary_node_id)
            && super::manifest::is_hash(&fingerprint),
        "invalid primary endpoint transition"
    );
    let status = status(master)?;
    ensure!(
        status.saved_role == NodeRole::Secondary
            && status.primary_node_id.as_deref() == Some(&primary_node_id),
        "primary endpoint transition does not match saved membership"
    );
    let mut credential = super::pairing::load_secondary_credential(master)?;
    ensure!(
        credential.primary_node_id == primary_node_id,
        "primary credential identity changed"
    );
    let mut plan = prepare_local_with_active_pair(
        master,
        LifecycleRequest::Rename {
            name: status.node_name,
        },
        None,
    )?;
    let guard = acquire_for_migration(master)?;
    let main = plan
        .candidate
        .iter_mut()
        .find(|member| member.kind == 0)
        .context("master candidate absent")?;
    let mut value: toml::Value = std::str::from_utf8(&main.bytes)?.parse()?;
    let cluster = value
        .as_table_mut()
        .context("master table absent")?
        .get_mut("cluster")
        .and_then(toml::Value::as_table_mut)
        .context("cluster table absent")?;
    let primary = endpoint_url(endpoint);
    cluster.insert("peer".into(), toml::Value::String(primary.clone()));
    cluster.insert(
        "primary_cert_fingerprint".into(),
        toml::Value::String(fingerprint.clone()),
    );
    main.bytes = toml::to_string_pretty(&value)?.into_bytes();
    credential.primary = primary.clone();
    credential.fingerprint = fingerprint.clone();
    plan.credential = Some(credential);
    plan.credential_replacement = true;
    plan.preview.restart_required = true;
    plan.preview.primary_address = Some(primary);
    plan.preview.primary_fingerprint = Some(fingerprint);
    plan.preview
        .replacement_summary
        .push("Replace the primary endpoint and exact certificate pin after restart.".into());
    let loaded = load(&guard)?;
    let (snapshot, _) =
        crate::config::policy_revision::capture_coherent_loaded_v5_under_migration_guard(
            &guard,
            &loaded,
            time::OffsetDateTime::now_utc(),
        )?;
    validate_plan(&guard, snapshot.inventory(), &plan)?;
    save_plan(&guard, &plan)?;
    Ok(plan.preview)
}

fn finish_join(
    master: &Path,
    mut plan: PreparedPlan,
    manifest: super::manifest::Manifest,
    objects: BTreeMap<String, std::sync::Arc<[u8]>>,
) -> anyhow::Result<PreparedPlan> {
    let guard = acquire_for_migration(master)?;
    {
        let files = PrivateStore::open(&guard, PLANS)?;
        let index = read_index(&files)?;
        ensure!(
            index
                .entries
                .get(&plan.preview.id)
                .is_some_and(|entry| !entry.committed),
            "join preview is no longer pending"
        );
        let bytes = files
            .read("pending.lockdata", 512)?
            .context("join preview is no longer pending")?;
        let marker: PendingMarker = serde_json::from_slice(&bytes)?;
        ensure!(
            marker.preview_id == plan.preview.id && marker.expires_at > super::membership::now()?,
            "join preview is no longer pending"
        );
    }
    let loaded = load(&guard)?;
    let (snapshot, _) =
        crate::config::policy_revision::capture_coherent_loaded_v5_under_migration_guard(
            &guard,
            &loaded,
            time::OffsetDateTime::now_utc(),
        )?;
    ensure!(
        snapshot.revision().to_string() == plan.before_revision,
        "configuration changed during join preview; cancel and review again"
    );
    let main = plan
        .candidate
        .iter_mut()
        .find(|m| m.kind == 0)
        .context("master absent")?;
    let original: toml::Value = std::str::from_utf8(&main.bytes)?.parse()?;
    let original = original.as_table().context("master table absent")?;
    let mut local = toml::Table::new();
    local.insert("schema_version".into(), toml::Value::Integer(5));
    for key in crate::config::schema::TARGET_V5_NODE_LOCAL_SECTIONS {
        if let Some(value) = original.get(*key) {
            local.insert((*key).into(), value.clone());
        }
    }
    let mut server = toml::Table::new();
    if let Some(source) = original.get("server").and_then(toml::Value::as_table) {
        for key in super::artifact::ARTIFACT_NODE_LOCAL_SERVER_FIELDS {
            if let Some(value) = source.get(*key) {
                server.insert((*key).into(), value.clone());
            }
        }
    }
    local.insert("server".into(), toml::Value::Table(server));
    local.insert(
        "includes".into(),
        toml::Value::Array(vec![toml::Value::String(
            super::transaction::BUNDLE_PATH.into(),
        )]),
    );
    main.bytes = toml::to_string_pretty(&local)?.into_bytes();
    plan.candidate.retain(|m| m.kind == 0);
    for (path, object) in super::transaction::expected_objects(&manifest) {
        plan.candidate.push(PlanMember {
            kind: if path == super::transaction::BUNDLE_PATH {
                1
            } else {
                2
            },
            path: PathBuf::from(path),
            bytes: objects
                .get(&object.sha256)
                .context("missing policy object")?
                .to_vec(),
        });
    }
    plan.preview.replacement_summary.push(format!(
        "Reviewed policy epoch {}, {} Custom List packs, policy hash {}.",
        manifest.policy_epoch,
        manifest.packs.len(),
        manifest.operator_policy_hash
    ));
    plan.manifest = Some(manifest);
    validate_plan(&guard, snapshot.inventory(), &plan)?;
    plan.pending_expires_at = Some(pending_deadline(&plan));
    ensure!(
        super::membership::now()? < pending_deadline(&plan),
        "pending admission expired during transfer"
    );
    plan.preview.expires_at = super::membership::now()?
        .checked_add(super::membership::INVITE_TTL)
        .context("clock overflow")?;
    match (
        plan.private_corpus_pin_owner.as_deref(),
        plan.private_corpus_pin_expires_at,
    ) {
        (Some(_), Some(expires_at)) => renew_private_corpus_pin(&guard, &plan, expires_at)?,
        (None, None) => {}
        _ => anyhow::bail!("private corpus pin record is incomplete"),
    }
    save_plan(&guard, &plan)?;
    Ok(plan)
}

fn renew_private_corpus_pin(
    guard: &MigrationWriteLock,
    plan: &PreparedPlan,
    expires_at: u64,
) -> anyhow::Result<()> {
    let owner = plan
        .private_corpus_pin_owner
        .as_deref()
        .context("private corpus pin owner absent")?;
    let generation = plan
        .corpus_generation
        .as_deref()
        .context("join corpus generation absent")?;
    let store = super::corpus::CorpusStore::open(guard.canonical_master())?;
    let corpus = store.manifest_metadata(generation)?;
    let policy = plan
        .manifest
        .as_ref()
        .context("join policy manifest absent")?;
    ensure!(
        corpus.artifact == super::dto::ArtifactIdentity::from(policy),
        "private corpus pin identity mismatch"
    );
    store.prepare_manifest_private_pinned(&corpus, owner, expires_at)
}

pub(crate) async fn extend_nodes_join_recovery(
    master: &Path,
    preview_id: &str,
    pin_owner: &str,
    expires_at: u64,
) -> anyhow::Result<()> {
    let path = master.to_path_buf();
    let id = preview_id.to_owned();
    let owner = pin_owner.to_owned();
    tokio::task::spawn_blocking(move || {
        ensure!(
            super::membership::valid_id(&owner),
            "invalid private corpus pin owner"
        );
        let now = super::membership::now()?;
        ensure!(expires_at > now, "join recovery deadline already expired");
        let guard = acquire_for_migration(&path)?;
        let mut plan = read_plan(&guard, &id)?;
        ensure!(
            plan.preview.operation == LifecycleOperation::Join
                && plan.private_corpus_pin_owner.as_deref() == Some(owner.as_str()),
            "join recovery does not match the reviewed private corpus"
        );
        if plan.committed {
            return Ok(());
        }
        renew_private_corpus_pin(&guard, &plan, expires_at)?;
        plan.private_corpus_pin_expires_at = Some(expires_at);
        plan.pending_expires_at = Some(expires_at);
        plan.preview.expires_at = expires_at;
        save_plan(&guard, &plan)
    })
    .await?
}

/// Refresh an exact, unapplied staged-join review after a lost reply.
pub(crate) async fn renew_nodes_staged_join_review(
    master: &Path,
    preview_id: &str,
    pin_owner: &str,
    expires_at: u64,
) -> anyhow::Result<LifecyclePreview> {
    let path = master.to_path_buf();
    let id = preview_id.to_owned();
    let owner = pin_owner.to_owned();
    tokio::task::spawn_blocking(move || {
        ensure!(
            super::membership::valid_id(&owner),
            "invalid private corpus pin owner"
        );
        let now = super::membership::now()?;
        ensure!(expires_at > now, "join review deadline already expired");
        let guard = acquire_for_migration(&path)?;
        let mut plan = read_plan(&guard, &id)?;
        ensure!(
            plan.preview.operation == LifecycleOperation::Join
                && plan.private_corpus_pin_owner.as_deref() == Some(owner.as_str())
                && !plan.committed,
            "join review does not match the exact unapplied private corpus"
        );
        renew_private_corpus_pin(&guard, &plan, expires_at)?;
        plan.private_corpus_pin_expires_at = Some(expires_at);
        plan.pending_expires_at = Some(expires_at);
        plan.preview.expires_at = expires_at;
        let preview = plan.preview.clone();
        save_plan(&guard, &plan)?;
        Ok(preview)
    })
    .await?
}

/// Cancel one retained, unapplied staged Join only when its private owner is
/// the exact Nodes operation that requested the cleanup.
pub(crate) async fn cancel_nodes_staged_join_if_present(
    master: &Path,
    preview_id: &str,
    pin_owner: &str,
) -> anyhow::Result<bool> {
    let path = master.to_path_buf();
    let id = preview_id.to_owned();
    let owner = pin_owner.to_owned();
    let present = tokio::task::spawn_blocking(move || {
        ensure!(
            super::membership::valid_id(&owner),
            "invalid private corpus pin owner"
        );
        let guard = acquire_for_migration(&path)?;
        let present = {
            let files = PrivateStore::open(&guard, PLANS)?;
            read_index(&files)?.entries.contains_key(&id)
        };
        if !present {
            return Ok(false);
        }
        let plan = read_plan(&guard, &id)?;
        ensure!(
            plan.preview.operation == LifecycleOperation::Join
                && plan.private_corpus_pin_owner.as_deref() == Some(owner.as_str())
                && !plan.committed,
            "staged Join cleanup does not match the exact unapplied private corpus"
        );
        Ok(true)
    })
    .await??;
    if present {
        cancel(master, preview_id).await?;
    }
    Ok(present)
}

pub async fn apply(master: &Path, preview_id: &str) -> anyhow::Result<LifecycleResult> {
    apply_with_active_pair(master, preview_id, None).await
}

pub async fn apply_with_active_pair(
    master: &Path,
    preview_id: &str,
    expected_active: Option<(super::dto::ArtifactIdentity, String)>,
) -> anyhow::Result<LifecycleResult> {
    let path = master.to_path_buf();
    let id = preview_id.to_owned();
    let (mut result, credential) = tokio::task::spawn_blocking(move || {
        let (result, credential) =
            apply_local_with_active_pair(&path, &id, expected_active.as_ref())?;
        let credential = current_activation_credential(&path, credential)?;
        Ok::<_, anyhow::Error>((result, credential))
    })
    .await??;
    if let Some(credential) = credential {
        if let Err(error) = super::pairing::activate(&credential).await {
            result.message = format!("Saved with verified backup; restart required. Admission remains pending; restart retries activation: {error}");
            result.status.pending_join = true;
        }
    }
    Ok(result)
}

fn current_activation_credential(
    master: &Path,
    prepared: Option<super::pairing::SecondaryCredential>,
) -> anyhow::Result<Option<super::pairing::SecondaryCredential>> {
    let Some(prepared) = prepared else {
        return Ok(None);
    };
    let Ok(current) = super::pairing::load_secondary_credential(master) else {
        return Ok(None);
    };
    // The loader verifies the saved role, identities, endpoint and exact certificate pin.
    // Match the private credential too so old receipts cannot activate a later association.
    Ok((serde_json::to_vec(&current)? == serde_json::to_vec(&prepared)?).then_some(current))
}

fn validate_primary_activation_recovery_apply(
    guard: &MigrationWriteLock,
    plan: &PreparedPlan,
) -> anyhow::Result<()> {
    if !plan.primary_fingerprint_replacement {
        ensure!(
            plan.superseded_runtime_preview.is_none(),
            "invalid primary recovery plan"
        );
        return Ok(());
    }
    let superseded = plan
        .superseded_runtime_preview
        .as_deref()
        .context("superseded primary activation absent")?;
    let material = plan
        .create_material
        .as_ref()
        .context("primary recovery certificate material absent")?;
    let candidate = plan
        .candidate
        .iter()
        .find(|member| member.kind == 0)
        .context("primary recovery master candidate absent")?;
    let candidate: crate::config::schema::ConfigV5 =
        toml::from_str(std::str::from_utf8(&candidate.bytes)?)?;
    let endpoint = candidate
        .node
        .control_listen
        .context("primary recovery listener absent")?;
    ensure!(
        candidate.api.enabled
            && candidate.api.listen == endpoint
            && candidate.cluster.primary_cert_fingerprint.as_deref()
                == Some(material.fingerprint.as_str()),
        "primary recovery candidate endpoint or pin changed"
    );
    ensure_local_listener_endpoint(endpoint)?;
    let marker: RuntimeMarker = {
        let files = PrivateStore::open(guard, PLANS)?;
        serde_json::from_slice(
            &files
                .read("runtime.lockdata", 512)?
                .context("primary activation recovery restart fence absent")?,
        )?
    };
    ensure!(
        marker.committed
            && (marker.preview_id == superseded || marker.preview_id == plan.preview.id),
        "primary activation recovery restart fence changed"
    );
    let original = read_plan(guard, superseded)?;
    ensure!(
        original.preview.operation == LifecycleOperation::Create
            && original.committed
            && !original.runtime_acknowledged
            && original.preview.local_node_id == plan.preview.local_node_id,
        "superseded primary activation is no longer recoverable"
    );
    let original_fingerprint = original
        .create_material
        .as_ref()
        .map(|value| value.fingerprint.as_str())
        .context("superseded primary certificate material absent")?;
    let loaded = load(guard)?;
    let config = &loaded.config;
    ensure!(
        role_of(config) == NodeRole::Primary
            && config.cluster.membership_version == Some(1)
            && config.node.id.as_deref() == Some(&plan.preview.local_node_id)
            && config.cluster.primary_node_id.as_deref() == Some(&plan.preview.local_node_id)
            && config.cluster.cluster_id.as_deref() == Some(&material.cluster_id),
        "saved primary identity changed during activation recovery"
    );
    let configured_fingerprint = config
        .cluster
        .primary_cert_fingerprint
        .as_deref()
        .context("saved primary certificate pin absent")?;
    ensure!(
        configured_fingerprint == original_fingerprint
            || configured_fingerprint == material.fingerprint,
        "saved primary certificate pin changed during activation recovery"
    );
    let members = super::membership::MembershipStore::open(guard)?;
    ensure!(
        members.matches(&material.cluster_id, &plan.preview.local_node_id)
            && [original_fingerprint, material.fingerprint.as_str()]
                .contains(&members.primary_fingerprint())
            && members
                .views(super::membership::now()?)
                .iter()
                .all(|member| member.state == MemberState::Revoked),
        "primary membership changed during activation recovery"
    );
    Ok(())
}

fn ensure_local_listener_endpoint(endpoint: SocketAddr) -> anyhow::Result<()> {
    ensure!(
        endpoint.port() != 0 && !endpoint.ip().is_unspecified() && !endpoint.ip().is_multicast(),
        "invalid primary recovery endpoint"
    );
    std::net::TcpListener::bind(SocketAddr::new(endpoint.ip(), 0)).with_context(|| {
        format!(
            "primary recovery IP {} is not assigned locally",
            endpoint.ip()
        )
    })?;
    Ok(())
}

fn apply_local(
    master: &Path,
    preview_id: &str,
) -> anyhow::Result<(LifecycleResult, Option<super::pairing::SecondaryCredential>)> {
    apply_local_with_active_pair(master, preview_id, None)
}

fn apply_local_with_active_pair(
    master: &Path,
    preview_id: &str,
    expected_active: Option<&(super::dto::ArtifactIdentity, String)>,
) -> anyhow::Result<(LifecycleResult, Option<super::pairing::SecondaryCredential>)> {
    let guard = acquire_for_migration(master)?;
    let receipts = receipts(&guard)?;
    ensure!(
        policy_transaction::recover_active(&guard, &receipts)?
            != policy_transaction::RecoveryOutcome::LegacyActive,
        "migration recovery required"
    );
    let mut plan = read_plan(&guard, preview_id)?;
    validate_primary_activation_recovery_apply(&guard, &plan)?;
    if plan.preview.operation == LifecycleOperation::Leave && !plan.committed {
        check_leave_active_pair(&guard, expected_active)?;
    }
    let actor = format!("nodes:{}", plan.preview.local_node_id);
    let receipt_actor = if let Some(manifest) = &plan.manifest {
        format!("cluster:{}", manifest.primary_lineage)
    } else {
        actor.clone()
    };
    let previous =
        policy_transaction::lookup_receipt(&guard, &receipts, &receipt_actor, preview_id)?;
    let loaded = load(&guard)?;
    let (snapshot, _) =
        crate::config::policy_revision::capture_coherent_loaded_v5_under_migration_guard(
            &guard,
            &loaded,
            time::OffsetDateTime::now_utc(),
        )?;
    if !plan.committed
        && !previous
            .as_ref()
            .is_some_and(|r| r.persistence == Persistence::Committed && !r.rollback_restored)
    {
        ensure!(
            super::membership::now()? < plan.preview.expires_at,
            "preview expired; cancel and review again"
        );
        ensure!(
            snapshot.revision().to_string() == plan.before_revision,
            "configuration changed since preview; review again"
        );
    }
    let mut invitation = plan.invitation.clone();
    let mut backup_id = previous
        .as_ref()
        .map(|r| r.transaction_id.clone())
        .or_else(|| plan.backup_id.clone());
    if !plan.committed
        && matches!(
            plan.preview.operation,
            LifecycleOperation::Invite | LifecycleOperation::Revoke
        )
    {
        ensure!(
            loaded.config.cluster.membership_version == Some(1)
                && role_of(&loaded.config) == NodeRole::Primary,
            "modern primary required"
        );
        let mut members = super::membership::MembershipStore::open(&guard)?;
        if plan.preview.operation == LifecycleOperation::Invite {
            invitation = Some(members.invite(super::membership::now()?)?.encode()?);
        } else {
            members.revoke(
                plan.revoke_id
                    .as_deref()
                    .context("revocation identity absent")?,
            )?;
        }
        plan.committed = true;
        plan.completed_at = Some(super::membership::now()?);
        plan.invitation = invitation.clone();
        save_plan(&guard, &plan)?;
    } else if !plan.committed {
        if plan.preview.operation == LifecycleOperation::Leave
            && role_of(&loaded.config) == NodeRole::Primary
        {
            ensure!(
                !super::membership::MembershipStore::open(&guard)?
                    .views(super::membership::now()?)
                    .iter()
                    .any(|m| m.state != MemberState::Revoked),
                "primary gained active or pending peers since preview"
            );
        }
        if plan.credential.is_some() && !plan.credential_replacement {
            ensure!(
                plan.manifest.is_some(),
                "join preview incomplete; cancel it"
            );
        }
        let before = snapshot.inventory();
        let after = plan_inventory(&plan)?;
        if previous.is_none() {
            let files = PrivateStore::open(&guard, PLANS)?;
            let backup = serde_json::to_vec(&inventory_plan(before))?;
            let name = format!("backup-{}.data", plan.preview.id);
            if let Some(saved) = files.read(&name, MAX_PLAN)? {
                ensure!(saved == backup, "backup conflicts with current policy");
            } else {
                files.create(&name, &backup)?;
            }
            ensure!(
                files.read(&name, MAX_PLAN)?.as_deref() == Some(backup.as_slice()),
                "backup verification failed"
            );
        }
        if plan.preview.restart_required && !plan.primary_fingerprint_replacement {
            write_runtime_marker(&guard, &plan.preview.id, false)?;
        }
        if let Some(material) = &plan.create_material {
            publish_material(
                &guard,
                &format!("nodes-{}.crt", plan.preview.id),
                material.certificate.as_bytes(),
            )?;
            publish_material(
                &guard,
                &format!("nodes-{}.key", plan.preview.id),
                material.key.0.as_bytes(),
            )?;
            match super::membership::MembershipStore::open(&guard) {
                Ok(store) => ensure!(
                    store.matches(&material.cluster_id, &plan.preview.local_node_id),
                    "membership identity conflicts with prepared creation"
                ),
                Err(_) => {
                    super::membership::MembershipStore::initialize(
                        &guard,
                        &material.cluster_id,
                        &plan.preview.local_node_id,
                        &material.fingerprint,
                    )?;
                }
            }
        }
        if !plan.credential_replacement {
            if let Some(credential) = &plan.credential {
                let files = PrivateStore::open(&guard, super::membership::STORE)?;
                let bytes = serde_json::to_vec(credential)?;
                if let Some(saved) = files.read("secondary.json", 8192)? {
                    ensure!(saved == bytes, "another secondary credential is present");
                } else {
                    files.create("secondary.json", &bytes)?;
                }
            }
        }
        let receipt = if let Some(receipt) = previous {
            receipt
        } else if let Some(manifest) = &plan.manifest {
            validate_plan(&guard, before, &plan)?;
            let mut ownership = super::ledger::OwnershipStore::open(&guard)?;
            if ownership.pending().is_some() {
                ownership.recover(&receipts, &super::transaction::ExistingReceiptAdapter)?;
            }
            let pending = ownership.begin_enrollment(
                manifest,
                before,
                &after.revision().to_string(),
                &receipt_actor,
                preview_id,
            )?;
            let prepared = super::transaction::prepare_apply_verified(
                &guard,
                &receipts,
                &pending,
                before,
                &after,
                None,
                || Ok(()),
            )?;
            let receipt = match prepared {
                PrepareOutcome::Prepared(transaction) => {
                    ownership.bind_prepared(&transaction.receipt())?;
                    transaction.commit()?
                }
                PrepareOutcome::Replay(receipt) => *receipt,
            };
            use super::transaction::EvidenceResolver;
            let evidence = super::transaction::ExistingReceiptAdapter
                .lookup(&guard, &receipts, &receipt_actor, preview_id)?
                .context("join transaction evidence absent")?;
            ownership.complete(&evidence)?;
            receipt
        } else {
            let request = policy_transaction::TransactionRequest {
                request_id: preview_id.into(),
                actor: actor.clone(),
                origin: "nodes".into(),
                operation: if plan.preview.operation == LifecycleOperation::Leave {
                    "nodes.leave"
                } else {
                    "nodes.local"
                }
                .into(),
                payload: serde_json::to_vec(&plan.preview)?,
                expected_revision: before.revision(),
                source_schema: 5,
                target_schema: 5,
            };
            policy_transaction::apply(&guard, &receipts, &request, before, &after, || {
                validate_plan(&guard, before, &plan)
            })?
        };
        ensure!(
            receipt.persistence == Persistence::Committed && !receipt.rollback_restored,
            "lifecycle transaction did not commit"
        );
        if plan.credential_replacement {
            let credential = plan
                .credential
                .as_ref()
                .context("replacement secondary credential absent")?;
            PrivateStore::open(&guard, super::membership::STORE)?
                .write("secondary.json", &serde_json::to_vec(credential)?)?;
        }
        if plan.primary_fingerprint_replacement {
            let material = plan
                .create_material
                .as_ref()
                .context("primary recovery certificate material absent")?;
            super::membership::MembershipStore::open(&guard)?.replace_primary_fingerprint(
                &material.cluster_id,
                &plan.preview.local_node_id,
                &material.fingerprint,
                super::membership::now()?,
            )?;
        }
        backup_id = Some(receipt.transaction_id.clone());
        if plan.manifest.is_some() {
            let mut ownership = super::ledger::OwnershipStore::open(&guard)?;
            if ownership.pending().is_some() {
                ownership.recover(&receipts, &super::transaction::ExistingReceiptAdapter)?;
            }
            ensure!(
                ownership.current().is_some(),
                "join ownership recovery incomplete"
            );
        }
        if plan.preview.operation == LifecycleOperation::Leave {
            super::ledger::OwnershipStore::open(&guard)?.release_after_leave(&receipt)?;
            let files = PrivateStore::open(&guard, super::membership::STORE)?;
            files.remove("secondary.json")?;
            files.remove("roster-cache.json")?;
            files.remove("roster.json")?;
            remove_legacy_token(&guard)?;
        }
        if let (Some(manifest), Some(generation)) = (&plan.manifest, &plan.corpus_generation) {
            let store = super::corpus::CorpusStore::open(guard.canonical_master())?;
            let corpus = store.manifest_metadata(generation)?;
            ensure!(
                corpus.artifact == super::dto::ArtifactIdentity::from(manifest),
                "reviewed corpus identity mismatch"
            );
            store.install_manifest(&corpus)?;
        }
        plan.committed = true;
        plan.completed_at = Some(super::membership::now()?);
        plan.backup_id = backup_id.clone();
        save_plan(&guard, &plan)?;
    }
    let loaded = load(&guard)?;
    let result = LifecycleResult {
        operation: plan.preview.operation,
        status: status_locked(&guard, &loaded)?,
        backup_id,
        invitation,
        message: if plan.preview.restart_required && !plan.runtime_acknowledged {
            "Saved with verified backup. Restart this node to activate membership."
        } else {
            "Saved."
        }
        .into(),
    };
    let activation = (!plan.credential_replacement)
        .then_some(plan.credential)
        .flatten();
    Ok((result, activation))
}

pub async fn cancel(master: &Path, preview_id: &str) -> anyhow::Result<LifecycleResult> {
    let path = master.to_path_buf();
    let id = preview_id.to_owned();
    let credential = tokio::task::spawn_blocking(move || {
        let guard = acquire_for_migration(&path)?;
        let plan = read_plan(&guard, &id)?;
        ensure!(!plan.committed, "applied lifecycle operation cannot be cancelled; use leave or retained backup recovery");
        let receipts = receipts(&guard)?;
        policy_transaction::recover_active(&guard, &receipts)?;
        let actor = plan.manifest.as_ref().map(|m| format!("cluster:{}",m.primary_lineage)).unwrap_or_else(||format!("nodes:{}",plan.preview.local_node_id));
        let receipt=policy_transaction::lookup_receipt(&guard,&receipts,&actor,&id)?;
        ensure!(receipt.as_ref().is_none_or(|r|r.persistence==Persistence::Aborted || r.rollback_restored), "transaction already started; apply the same preview to recover");
        if plan.manifest.is_some() {
            let mut ownership=super::ledger::OwnershipStore::open(&guard)?;
            if ownership.pending().is_some() {ownership.recover(&receipts,&super::transaction::ExistingReceiptAdapter)?;}
        }
        if !plan.credential_replacement {
            if let Some(credential)=&plan.credential {
                let files=PrivateStore::open(&guard,super::membership::STORE)?;
                if let Some(bytes)=files.read("secondary.json",8192)? {
                    ensure!(bytes==serde_json::to_vec(credential)?,"another node credential replaced the cancelled preview");
                    files.remove("secondary.json")?;
                }
            }
        }
        if let Some(material)=&plan.create_material {
            for (name,bytes) in [(format!("nodes-{}.crt",id),material.certificate.as_bytes()),(format!("nodes-{}.key",id),material.key.0.as_bytes())] {
                let target=guard.tree_io().plan_root_file_no_follow(Path::new(&name))?;
                if !target.is_new() {ensure!(target.read_original()?.as_deref().map(str::as_bytes)==Some(bytes),"creation material changed; manual recovery required");target.materialize()?.unlink()?;}
            }
            if !plan.primary_fingerprint_replacement {
                if let Ok(members)=super::membership::MembershipStore::open(&guard) {
                    ensure!(members.matches(&material.cluster_id,&plan.preview.local_node_id) && members.views(super::membership::now()?).iter().all(|m|m.state==MemberState::Revoked),"created membership has admitted peers");
                    drop(members);
                    PrivateStore::open(&guard,super::membership::STORE)?.remove("roster.json")?;
                }
            }
        }

        if let Some(owner) = plan.private_corpus_pin_owner.as_deref() {
            super::corpus::CorpusStore::open(guard.canonical_master())?
                .release_private_manifest_pin(owner)?;
        }

        let files=PrivateStore::open(&guard, PLANS)?;
        remove_runtime_marker(&files, &id)?;
        files.remove(&plan_name(&id)?)?;
        let mut index = read_index(&files)?;
        index.entries.remove(&id);
        write_index(&files, &index)?;
        if plan.credential.is_some() && !plan.credential_replacement { remove_pending_marker(&files, &id)?; }
        Ok::<_,anyhow::Error>(plan.credential.filter(|_| !plan.credential_replacement))
    }).await??;
    let mut message = "Preview cancelled; local policy unchanged.".to_owned();
    if let Some(credential) = credential {
        if super::pairing::cancel(&credential).await.is_err() {
            message.push_str(
                " Primary unavailable; pending admission expires automatically within 24 hours.",
            );
        }
    }
    let path = master.to_path_buf();
    let state = tokio::task::spawn_blocking(move || status(&path)).await??;
    Ok(LifecycleResult {
        operation: LifecycleOperation::Cancel,
        status: state,
        backup_id: None,
        invitation: None,
        message,
    })
}

pub(crate) async fn preview_exists(master: &Path, preview_id: &str) -> anyhow::Result<bool> {
    let path = master.to_path_buf();
    let id = preview_id.to_owned();
    tokio::task::spawn_blocking(move || {
        let guard = acquire_for_migration(&path)?;
        let files = PrivateStore::open(&guard, PLANS)?;
        Ok(read_index(&files)?.entries.contains_key(&id))
    })
    .await?
}

fn load(guard: &MigrationWriteLock) -> anyhow::Result<LoadedConfigV5> {
    loader::load_config_v5_with_policy_overlays_under_service_migration_guard(
        guard,
        guard.canonical_master(),
        time::OffsetDateTime::now_utc(),
        None,
        None,
    )
    .map_err(|error| anyhow::anyhow!("configuration admission failed: {error:?}"))
}
fn receipts(guard: &MigrationWriteLock) -> anyhow::Result<ReceiptStore> {
    ReceiptStore::open(&crate::config::state_dir::open_for_migration(guard)?, guard)
}
fn plan_name(id: &str) -> anyhow::Result<String> {
    ensure!(super::membership::valid_id(id), "invalid preview identity");
    Ok(format!("{id}.json"))
}
#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PlanIndex {
    entries: BTreeMap<String, PlanEntry>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PlanEntry {
    compact: bool,
    committed: bool,
    restart_required: bool,
    runtime_acknowledged: bool,
    completed_at: Option<u64>,
}
impl PlanEntry {
    fn full(plan: &PreparedPlan) -> Self {
        Self {
            compact: false,
            committed: plan.committed,
            restart_required: plan.preview.restart_required,
            runtime_acknowledged: plan.runtime_acknowledged,
            completed_at: plan.completed_at,
        }
    }
    fn unresolved(&self) -> bool {
        !self.committed || (self.restart_required && !self.runtime_acknowledged)
    }
}
const INDEX: &str = "plan-index.data";
const MAX_INDEX_BYTES: u64 = 2 * 1024 * 1024;
const MAX_UNRESOLVED_PLANS: usize = 128;
const MAX_REPLAY_RECORDS: usize = policy_transaction::MAX_RECEIPTS;
const REPLAY_SECONDS: u64 = policy_transaction::MIN_RETENTION_SECONDS;

fn completed_name(id: &str) -> anyhow::Result<String> {
    ensure!(super::membership::valid_id(id), "invalid preview identity");
    Ok(format!("completed-{id}.data"))
}
fn write_index(files: &PrivateStore<'_>, index: &PlanIndex) -> anyhow::Result<()> {
    let bytes = serde_json::to_vec(index)?;
    ensure!(
        bytes.len() as u64 <= MAX_INDEX_BYTES,
        "lifecycle history exceeds metadata limit"
    );
    files.write(INDEX, &bytes)
}
fn read_index(files: &PrivateStore<'_>) -> anyhow::Result<PlanIndex> {
    if let Some(bytes) = files.read(INDEX, MAX_INDEX_BYTES)? {
        let index: PlanIndex = serde_json::from_slice(&bytes)?;
        ensure!(
            index.entries.len() <= MAX_REPLAY_RECORDS,
            "lifecycle history exceeds record limit"
        );
        for (id, entry) in &index.entries {
            ensure!(
                super::membership::valid_id(id)
                    && (!entry.compact || (!entry.unresolved() && entry.completed_at.is_some())),
                "invalid lifecycle history entry"
            );
        }
        return Ok(index);
    }
    // Import existing full plans once. Backups remain outside the active-plan quota.
    let mut index = PlanIndex::default();
    for name in files.names(32 * 1024)? {
        let Some(id) = name.strip_suffix(".json") else {
            continue;
        };
        ensure!(
            super::membership::valid_id(id),
            "invalid lifecycle plan filename"
        );
        let plan: PreparedPlan = serde_json::from_slice(
            &files
                .read(&name, MAX_PLAN)?
                .context("lifecycle plan disappeared")?,
        )?;
        ensure!(plan.preview.id == id, "lifecycle plan identity mismatch");
        ensure!(
            index.entries.len() < MAX_REPLAY_RECORDS,
            "too many existing lifecycle plans"
        );
        index.entries.insert(id.into(), PlanEntry::full(&plan));
    }
    write_index(files, &index)?;
    Ok(index)
}
fn protected_preview_ids(
    files: &PrivateStore<'_>,
) -> anyhow::Result<std::collections::BTreeSet<String>> {
    let mut ids = std::collections::BTreeSet::new();
    if let Some(bytes) = files.read("runtime.lockdata", 512)? {
        let marker: RuntimeMarker = serde_json::from_slice(&bytes)?;
        ids.insert(marker.preview_id);
    }
    if let Some(bytes) = files.read("pending.lockdata", 512)? {
        let marker: PendingMarker = serde_json::from_slice(&bytes)?;
        ids.insert(marker.preview_id);
    }
    ensure!(
        ids.iter().all(|id| super::membership::valid_id(id)),
        "invalid protected lifecycle identity"
    );
    Ok(ids)
}

fn retire_history(files: &PrivateStore<'_>, index: &mut PlanIndex, now: u64) -> anyhow::Result<()> {
    let protected = protected_preview_ids(files)?;
    let expired = index
        .entries
        .iter()
        .filter(|(id, entry)| {
            !protected.contains(*id)
                && entry.compact
                && entry
                    .completed_at
                    .is_some_and(|at| at.saturating_add(REPLAY_SECONDS) <= now)
        })
        .map(|(id, _)| id.clone())
        .collect::<Vec<_>>();
    for id in expired {
        files.remove(&completed_name(&id)?)?;
        files.remove(&plan_name(&id)?)?;
        index.entries.remove(&id);
    }
    // Neither retained backup files nor the transaction/ownership journals are retired here.
    write_index(files, index)
}
fn compact_completed(
    files: &PrivateStore<'_>,
    index: &mut PlanIndex,
    plan: &PreparedPlan,
) -> anyhow::Result<()> {
    if !plan.committed || (plan.preview.restart_required && !plan.runtime_acknowledged) {
        return Ok(());
    }
    let compact = PreparedPlan {
        preview: plan.preview.clone(),
        before_revision: plan.before_revision.clone(),
        candidate: Vec::new(),
        credential: plan.credential.clone(),
        credential_replacement: plan.credential_replacement,
        primary_fingerprint_replacement: plan.primary_fingerprint_replacement,
        superseded_runtime_preview: plan.superseded_runtime_preview.clone(),
        manifest: plan.manifest.clone(),
        corpus_generation: plan.corpus_generation.clone(),
        private_corpus_pin_owner: None,
        private_corpus_pin_expires_at: None,
        revoke_id: plan.revoke_id.clone(),
        create_material: None,
        committed: true,
        runtime_acknowledged: plan.runtime_acknowledged,
        completed_at: Some(plan.completed_at.unwrap_or(super::membership::now()?)),
        pending_expires_at: plan.pending_expires_at,
        backup_id: plan.backup_id.clone(),
        invitation: plan.invitation.clone(),
    };
    files.write(
        &completed_name(&plan.preview.id)?,
        &serde_json::to_vec(&compact)?,
    )?;
    let mut entry = PlanEntry::full(&compact);
    entry.compact = true;
    index.entries.insert(plan.preview.id.clone(), entry);
    write_index(files, index)?;
    // Publish the replacement before removing the full recovery record.
    files.remove(&plan_name(&plan.preview.id)?)
}
fn pending_deadline(plan: &PreparedPlan) -> u64 {
    plan.pending_expires_at.unwrap_or_else(|| {
        plan.preview
            .expires_at
            .saturating_sub(super::membership::INVITE_TTL)
            .saturating_add(super::membership::PENDING_TTL)
    })
}

fn save_plan(guard: &MigrationWriteLock, plan: &PreparedPlan) -> anyhow::Result<()> {
    if plan.committed && plan.preview.restart_required && !plan.runtime_acknowledged {
        if let Some(superseded) = plan.superseded_runtime_preview.as_deref() {
            replace_runtime_marker(guard, superseded, &plan.preview.id)?;
        } else {
            write_runtime_marker(guard, &plan.preview.id, true)?;
        }
    }
    let files = PrivateStore::open(guard, PLANS)?;
    let mut index = read_index(&files)?;
    retire_history(&files, &mut index, super::membership::now()?)?;
    if !index.entries.contains_key(&plan.preview.id) {
        ensure!(
            index
                .entries
                .values()
                .filter(|entry| entry.unresolved())
                .count()
                < MAX_UNRESOLVED_PLANS,
            "too many unresolved previews; cancel pending previews or finish node recovery"
        );
        ensure!(
            index.entries.len() < MAX_REPLAY_RECORDS,
            "lifecycle replay history is full; retry after the 24-hour retention window"
        );
        index
            .entries
            .insert(plan.preview.id.clone(), PlanEntry::full(plan));
        write_index(&files, &index)?;
    }
    if plan.credential.is_some() {
        if plan.committed {
            remove_pending_marker(&files, &plan.preview.id)?;
        } else {
            if let Some(bytes) = files.read("pending.lockdata", 512)? {
                let marker: PendingMarker = serde_json::from_slice(&bytes)?;
                ensure!(
                    marker.preview_id == plan.preview.id
                        || marker.expires_at <= super::membership::now()?,
                    "another join is pending; cancel it first"
                );
            }
            files.write(
                "pending.lockdata",
                &serde_json::to_vec(&PendingMarker {
                    preview_id: plan.preview.id.clone(),
                    expires_at: pending_deadline(plan),
                })?,
            )?;
        }
    }
    files.write(&plan_name(&plan.preview.id)?, &serde_json::to_vec(plan)?)?;
    index
        .entries
        .insert(plan.preview.id.clone(), PlanEntry::full(plan));
    write_index(&files, &index)?;
    compact_completed(&files, &mut index, plan)
}
fn read_plan(guard: &MigrationWriteLock, id: &str) -> anyhow::Result<PreparedPlan> {
    let files = PrivateStore::open(guard, PLANS)?;
    let index = read_index(&files)?;
    let entry = index
        .entries
        .get(id)
        .context("unknown or retired preview identity")?;
    let now = super::membership::now()?;
    let protected = protected_preview_ids(&files)?;
    ensure!(
        !entry.compact
            || protected.contains(id)
            || entry
                .completed_at
                .is_some_and(|at| at.saturating_add(REPLAY_SECONDS) > now),
        "completed preview replay window expired"
    );
    let name = if entry.compact {
        completed_name(id)?
    } else {
        plan_name(id)?
    };
    let plan: PreparedPlan =
        serde_json::from_slice(&files.read(&name, MAX_PLAN)?.context(
            "lifecycle record unavailable; retained recovery evidence must be inspected",
        )?)?;
    ensure!(
        plan.preview.id == id
            && (!entry.compact
                || (plan.committed
                    && (!plan.preview.restart_required || plan.runtime_acknowledged))),
        "lifecycle record identity mismatch"
    );
    Ok(plan)
}

fn inventory_plan(inventory: &PolicyRevisionInventory) -> Vec<PlanMember> {
    inventory
        .members()
        .iter()
        .filter_map(|m| {
            if let PolicyMemberState::Present(bytes) = m.state() {
                Some(PlanMember {
                    path: m.path().to_owned(),
                    kind: match m.kind() {
                        PolicyMemberKind::Master => 0,
                        PolicyMemberKind::Include => 1,
                        PolicyMemberKind::Pack => 2,
                    },
                    bytes: bytes.clone(),
                })
            } else {
                None
            }
        })
        .collect()
}
fn plan_inventory(plan: &PreparedPlan) -> anyhow::Result<PolicyRevisionInventory> {
    Ok(PolicyRevisionInventory::new(
        plan.candidate
            .iter()
            .map(|m| {
                Ok(PolicyRevisionMember::present(
                    match m.kind {
                        0 => PolicyMemberKind::Master,
                        1 => PolicyMemberKind::Include,
                        2 => PolicyMemberKind::Pack,
                        _ => anyhow::bail!("invalid candidate member"),
                    },
                    m.path.clone(),
                    m.bytes.clone(),
                )?)
            })
            .collect::<anyhow::Result<Vec<_>>>()?,
    )?)
}
fn validate_plan(
    guard: &MigrationWriteLock,
    before: &PolicyRevisionInventory,
    plan: &PreparedPlan,
) -> anyhow::Result<()> {
    let after = plan_inventory(plan)?;
    let mut toml = loader::LoaderOverlay::default();
    let mut packs = crate::config::custom_list::PackOverlay::default();
    for member in after.members() {
        let PolicyMemberState::Present(bytes) = member.state() else {
            anyhow::bail!("absent candidate member");
        };
        if member.kind() == PolicyMemberKind::Pack {
            packs.stage(
                crate::config::schema::Id::new(
                    member
                        .path()
                        .file_stem()
                        .and_then(|s| s.to_str())
                        .context("invalid pack path")?,
                )?,
                bytes.clone(),
            );
        } else {
            toml.stage_plan_reachable_only(
                &guard.tree_io().plan_root_file_no_follow(member.path())?,
                String::from_utf8(bytes.clone())?,
            )?;
        }
    }
    for member in before
        .members()
        .iter()
        .filter(|m| !after.members().iter().any(|a| a.path() == m.path()))
    {
        if member.kind() == PolicyMemberKind::Pack {
            packs.omit(crate::config::schema::Id::new(
                member
                    .path()
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .context("invalid pack path")?,
            )?);
        } else {
            toml.omit_plan(&guard.tree_io().plan_root_file_no_follow(member.path())?)?;
        }
    }
    let loaded = loader::load_config_v5_with_policy_overlays_under_service_migration_guard(
        guard,
        guard.canonical_master(),
        time::OffsetDateTime::now_utc(),
        Some(&toml),
        Some(&packs),
    )
    .map_err(|error| anyhow::anyhow!("candidate validation failed: {error:?}"))?;
    if let Some(manifest) = &plan.manifest {
        let generation = plan
            .corpus_generation
            .as_deref()
            .context("join corpus preview incomplete")?;
        let store = super::corpus::CorpusStore::open(guard.canonical_master())?;
        let corpus = store.manifest_metadata(generation)?;
        ensure!(
            corpus.artifact == super::dto::ArtifactIdentity::from(manifest),
            "reviewed corpus identity mismatch"
        );
        crate::cli::commands::start::preflight_received_manifest(
            guard.canonical_master(),
            &loaded.config.validation_projection()?,
            &corpus,
        )?;
        let semantic = loaded
            .pack_bodies
            .iter()
            .map(|(id, body)| crate::operator_rules::SemanticPack {
                id: id.as_str(),
                body: body.as_ref(),
            })
            .collect::<Vec<_>>();
        ensure!(
            crate::operator_rules::hash_policy_candidate(&loaded.config, &semantic)?.to_string()
                == manifest.operator_policy_hash,
            "candidate does not match reviewed primary policy"
        );
    }
    Ok(())
}
fn publish_material(guard: &MigrationWriteLock, name: &str, bytes: &[u8]) -> anyhow::Result<()> {
    use std::io::Write;
    let plan = guard.tree_io().plan_root_file_no_follow(Path::new(name))?;
    if !plan.is_new() {
        ensure!(
            plan.read_original()?.as_deref().map(str::as_bytes) == Some(bytes),
            "certificate target conflicts with prepared material"
        );
        return Ok(());
    }
    let target = plan.materialize()?;
    let mut spool = tempfile::tempfile()?;
    spool.write_all(bytes)?;
    crate::config::atomic_write::hardened_atomic_create_only_at(
        &target,
        &mut spool,
        bytes.len() as u64,
        crate::config::atomic_write::AtomicCreateOnlyAtOpts {
            validator: None,
            mode: Some(0o600),
            owner: None,
            staging: Default::default(),
            #[cfg(test)]
            test_failure: None,
        },
    )?;
    Ok(())
}
fn remove_legacy_token(guard: &MigrationWriteLock) -> anyhow::Result<()> {
    let path = super::secret::cluster_token_path(guard.canonical_master());
    if path.parent() == Some(guard.identity().root.as_path()) {
        let plan = guard
            .tree_io()
            .plan_root_file_no_follow(Path::new("cluster_token"))?;
        if !plan.is_new() {
            plan.materialize()?.unlink()?;
        }
    } else {
        let parent = crate::config::state_dir::open_for_migration(guard)?;
        if let Some(file) =
            crate::config::tree_io::inspect_at(&parent, std::ffi::OsStr::new("cluster_token"))?
        {
            ensure!(
                file.metadata()?.is_file(),
                "legacy credential is not a regular file"
            );
            crate::config::tree_io::unlink_at(&parent, std::ffi::OsStr::new("cluster_token"))?;
            parent.sync_all()?;
        }
    }
    Ok(())
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeMarker {
    preview_id: String,
    #[serde(default = "committed_marker_default")]
    committed: bool,
}
fn committed_marker_default() -> bool {
    true
}

fn write_runtime_marker(
    guard: &MigrationWriteLock,
    id: &str,
    committed: bool,
) -> anyhow::Result<()> {
    let files = PrivateStore::open(guard, PLANS)?;
    if let Some(bytes) = files.read("runtime.lockdata", 512)? {
        let marker: RuntimeMarker = serde_json::from_slice(&bytes)?;
        ensure!(
            marker.preview_id == id,
            "another node transition requires restart"
        );
    }
    // Write ahead of promotion so a crash cannot expose a saved role without its fence.
    files.write(
        "runtime.lockdata",
        &serde_json::to_vec(&RuntimeMarker {
            preview_id: id.into(),
            committed,
        })?,
    )
}

fn replace_runtime_marker(
    guard: &MigrationWriteLock,
    superseded: &str,
    replacement: &str,
) -> anyhow::Result<()> {
    ensure!(
        super::membership::valid_id(superseded)
            && super::membership::valid_id(replacement)
            && superseded != replacement,
        "invalid runtime recovery marker"
    );
    let files = PrivateStore::open(guard, PLANS)?;
    let marker: RuntimeMarker = serde_json::from_slice(
        &files
            .read("runtime.lockdata", 512)?
            .context("primary activation restart fence absent")?,
    )?;
    ensure!(
        marker.committed && (marker.preview_id == superseded || marker.preview_id == replacement),
        "primary activation restart fence changed"
    );
    files.write(
        "runtime.lockdata",
        &serde_json::to_vec(&RuntimeMarker {
            preview_id: replacement.into(),
            committed: true,
        })?,
    )
}

fn remove_runtime_marker(files: &PrivateStore<'_>, id: &str) -> anyhow::Result<()> {
    if let Some(bytes) = files.read("runtime.lockdata", 512)? {
        let marker: RuntimeMarker = serde_json::from_slice(&bytes)?;
        if marker.preview_id == id {
            files.remove("runtime.lockdata")?;
        }
    }
    Ok(())
}

fn remove_pending_marker(files: &PrivateStore<'_>, id: &str) -> anyhow::Result<()> {
    if let Some(bytes) = files.read("pending.lockdata", 512)? {
        let marker: PendingMarker = serde_json::from_slice(&bytes)?;
        if marker.preview_id == id {
            files.remove("pending.lockdata")?;
        }
    }
    Ok(())
}

#[derive(Serialize, Deserialize)]
struct PendingMarker {
    preview_id: String,
    expires_at: u64,
}

/// The caller already owns the configuration writer lock; no recursive flock.
pub(crate) fn policy_edit_allowed_under_guard(
    guard: &crate::config::write_lock::ConfigWriteLock,
) -> anyhow::Result<bool> {
    guard.verify_master(guard.canonical_master())?;
    pending_marker_allows(
        guard.canonical_master(),
        &guard.identity().root,
        guard.tree_io().root,
    )
}

fn pending_marker_allows(
    master: &Path,
    root: &Path,
    root_file: &std::fs::File,
) -> anyhow::Result<bool> {
    use crate::config::write_lock::open_at;
    use std::ffi::OsStr;
    use std::io::Read;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;
    let state = crate::config::state_dir::for_config_parent(root);
    let mut dir = if state == root {
        root_file.try_clone()?
    } else {
        let mut dir = std::fs::File::open("/")?;
        for component in state.components() {
            if let std::path::Component::Normal(part) = component {
                dir = open_at(&dir, part, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
            }
        }
        dir
    };
    let owner = dir.metadata()?;
    use sha2::{Digest, Sha256};
    let namespace = hex::encode(Sha256::digest(master.as_os_str().as_bytes()));
    for name in [PLANS, &namespace] {
        dir = match open_at(
            &dir,
            OsStr::new(name),
            libc::O_RDONLY | libc::O_DIRECTORY,
            0,
        ) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(true),
            Err(error) => return Err(error.into()),
        };
        let meta = dir.metadata()?;
        ensure!(
            meta.uid() == owner.uid() && meta.gid() == owner.gid() && meta.mode() & 0o077 == 0,
            "unsafe pending-membership directory"
        );
    }
    for name in ["runtime.lockdata", "pending.lockdata"] {
        let file = match open_at(&dir, OsStr::new(name), libc::O_RDONLY, 0) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        let meta = file.metadata()?;
        ensure!(
            meta.is_file()
                && meta.nlink() == 1
                && meta.uid() == owner.uid()
                && meta.gid() == owner.gid()
                && meta.mode() & 0o077 == 0
                && meta.len() <= 512,
            "unsafe node-transition marker"
        );
        let mut bytes = Vec::new();
        file.take(513).read_to_end(&mut bytes)?;
        if name == "runtime.lockdata" {
            let marker: RuntimeMarker = serde_json::from_slice(&bytes)?;
            ensure!(
                super::membership::valid_id(&marker.preview_id),
                "invalid transition identity"
            );
            return Ok(false);
        }
        let marker: PendingMarker = serde_json::from_slice(&bytes)?;
        ensure!(
            super::membership::valid_id(&marker.preview_id),
            "invalid pending membership identity"
        );
        if marker.expires_at > super::membership::now()? {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Complete local evidence publication after journal recovery, without networking.
pub(crate) fn recover_before_load(master: &Path) -> anyhow::Result<()> {
    let ids = {
        let guard = acquire_for_migration(master)?;
        let receipts = receipts(&guard)?;
        ensure!(
            policy_transaction::recover_active(&guard, &receipts)?
                != policy_transaction::RecoveryOutcome::LegacyActive,
            "legacy migration recovery required"
        );
        let files = PrivateStore::open(&guard, PLANS)?;
        let mut index = read_index(&files)?;
        retire_history(&files, &mut index, super::membership::now()?)?;
        let full_ids = index
            .entries
            .iter()
            .filter(|(_, entry)| !entry.compact)
            .map(|(id, _)| id.clone())
            .collect::<Vec<_>>();
        let mut ids = Vec::new();
        for id in full_ids {
            let plan: PreparedPlan = serde_json::from_slice(
                &files
                    .read(&plan_name(&id)?, MAX_PLAN)?
                    .context("unfinished lifecycle record missing; preserve recovery evidence")?,
            )?;
            ensure!(plan.preview.id == id, "lifecycle record identity mismatch");
            if plan.committed {
                index.entries.insert(id, PlanEntry::full(&plan));
                write_index(&files, &index)?;
                compact_completed(&files, &mut index, &plan)?;
                continue;
            }
            let actor = plan
                .manifest
                .as_ref()
                .map(|m| format!("cluster:{}", m.primary_lineage))
                .unwrap_or_else(|| format!("nodes:{}", plan.preview.local_node_id));
            if policy_transaction::lookup_receipt(&guard, &receipts, &actor, &plan.preview.id)?
                .is_some_and(|r| r.persistence == Persistence::Committed && !r.rollback_restored)
            {
                ids.push(plan.preview.id);
            }
        }
        ids
    };
    for id in ids {
        apply_local(master, &id)?;
    }
    Ok(())
}

/// Clear restart notices only for the exact membership that reached readiness.
pub(crate) fn acknowledge_runtime_start(
    master: &Path,
    active: &crate::config::schema::ConfigV1,
) -> anyhow::Result<()> {
    let guard = acquire_for_migration(master)?;
    let loaded = load(&guard)?;
    let current = loaded.config.validation_projection()?;
    if current.node != active.node
        || current.cluster != active.cluster
        || (current.api.enabled != active.api.enabled
            || current.api.listen != active.api.listen
            || current.api.tls_cert != active.api.tls_cert
            || current.api.tls_key != active.api.tls_key)
    {
        return Ok(());
    }
    let ids = {
        let files = PrivateStore::open(&guard, PLANS)?;
        let index = read_index(&files)?;
        let marker: Option<RuntimeMarker> = files
            .read("runtime.lockdata", 512)?
            .map(|bytes| serde_json::from_slice(&bytes))
            .transpose()?;
        index
            .entries
            .iter()
            .filter(|(id, entry)| {
                !entry.compact || marker.as_ref().is_some_and(|m| m.preview_id == **id)
            })
            .map(|(id, _)| id.clone())
            .collect::<Vec<_>>()
    };
    for id in ids {
        let mut plan = read_plan(&guard, &id)?;
        if plan.committed {
            if !plan.runtime_acknowledged {
                plan.runtime_acknowledged = true;
                save_plan(&guard, &plan)?;
            }
            let files = PrivateStore::open(&guard, PLANS)?;
            remove_runtime_marker(&files, &plan.preview.id)?;
        }
    }
    Ok(())
}

pub(crate) fn policy_edit_allowed_under_migration_guard(
    guard: &MigrationWriteLock,
) -> anyhow::Result<bool> {
    guard.verify_master(guard.canonical_master())?;
    pending_marker_allows(
        guard.canonical_master(),
        &guard.identity().root,
        guard.tree_io().root,
    )
}

mod plan_bytes {
    use base64::Engine;
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&base64::engine::general_purpose::STANDARD.encode(bytes))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let encoded = String::deserialize(deserializer)?;
        base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(serde::de::Error::custom)
    }
}

pub(crate) fn preview_operation(master: &Path, id: &str) -> anyhow::Result<LifecycleOperation> {
    let guard = acquire_for_migration(master)?;
    Ok(read_plan(&guard, id)?.preview.operation)
}

fn check_leave_active_pair(
    guard: &MigrationWriteLock,
    expected: Option<&(super::dto::ArtifactIdentity, String)>,
) -> anyhow::Result<()> {
    if let Some((policy, corpus)) = expected {
        let ownership = super::ledger::OwnershipStore::open(guard)?;
        let ledger = ownership
            .current()
            .context("active node has no committed ownership ledger")?;
        ensure!(
            super::dto::ArtifactIdentity::from(&ledger.manifest) == *policy,
            "committed policy changed since active leave confirmation"
        );
        let store = super::corpus::CorpusStore::open(guard.canonical_master())?;
        ensure!(
            store.pair_state()?.persisted.as_deref() == Some(corpus),
            "committed corpus changed since active leave confirmation"
        );
        ensure!(
            store.manifest(corpus)?.artifact == *policy,
            "committed corpus and policy identity disagree"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::pem::PemObject;
    fn master(dir: &tempfile::TempDir) -> PathBuf {
        let path = dir.path().join("config.toml");
        std::fs::write(&path,"schema_version = 5\n[server]\ndefault_profile = \"default\"\n[profiles.default]\ndisplay_name = \"Default\"\n[upstream]\nservers = [\"192.0.2.1:53\"]\n").unwrap();
        path
    }
    #[tokio::test]
    async fn rename_preserves_identity_and_rejects_a_changed_preview() {
        let dir = tempfile::tempdir().unwrap();
        let path = master(&dir);
        let p = preview(
            &path,
            LifecycleRequest::Rename {
                name: "desk".into(),
            },
        )
        .await
        .unwrap();
        let before = std::fs::read(&path).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), before);
        apply(&path, &p.id).await.unwrap();
        let status = status(&path).unwrap();
        assert_eq!(status.node_name, "desk");
        assert_eq!(status.node_id, Some(p.local_node_id));
        let p = preview(
            &path,
            LifecycleRequest::Rename {
                name: "kitchen".into(),
            },
        )
        .await
        .unwrap();
        let other = preview(
            &path,
            LifecycleRequest::Rename {
                name: "hall".into(),
            },
        )
        .await
        .unwrap();
        apply(&path, &other.id).await.unwrap();
        assert!(apply(&path, &p.id).await.is_err());
        assert_eq!(status_fn(&path).node_name, "hall");
        let guard = acquire_for_migration(&path).unwrap();
        assert!(policy_edit_allowed_under_migration_guard(&guard).unwrap());
    }
    fn status_fn(path: &Path) -> LifecycleStatus {
        status(path).unwrap()
    }
    #[tokio::test]
    async fn create_without_api_admin_token_and_leave_retains_policy() {
        let dir = tempfile::tempdir().unwrap();
        let path = master(&dir);
        let p = preview(
            &path,
            LifecycleRequest::Create {
                san: vec!["192.0.2.10".into()],
                api_listen: Some("192.0.2.10:8053".parse().unwrap()),
                migrate_legacy: false,
            },
        )
        .await
        .unwrap();
        let result = apply(&path, &p.id).await.unwrap();
        assert_eq!(result.status.saved_role, NodeRole::Primary);
        assert!(result.status.restart_required);
        let guard = acquire_for_migration(&path).unwrap();
        let loaded = load(&guard).unwrap();
        let active = loaded.config.validation_projection().unwrap();
        assert!(loaded
            .config
            .api
            .token_hash
            .as_deref()
            .is_none_or(str::is_empty));
        drop(guard);
        acknowledge_runtime_start(&path, &active).unwrap();
        assert!(!status(&path).unwrap().restart_required);
        let leave = preview(&path, LifecycleRequest::Leave).await.unwrap();
        let result = apply(&path, &leave.id).await.unwrap();
        assert_eq!(result.status.saved_role, NodeRole::Standalone);
        let guard = acquire_for_migration(&path).unwrap();
        let config = load(&guard).unwrap();
        assert_eq!(config.config.upstream.servers, vec!["192.0.2.1:53"]);
        assert!(!policy_edit_allowed_under_migration_guard(&guard).unwrap());
        let standalone = config.config.validation_projection().unwrap();
        drop(guard);
        {
            let writer = crate::config::write_lock::acquire_for_write(&path).unwrap();
            assert!(!policy_edit_allowed_under_guard(&writer).unwrap());
        }
        acknowledge_runtime_start(&path, &active).unwrap();
        assert!(!status(&path).unwrap().can_edit_policy);
        acknowledge_runtime_start(&path, &standalone).unwrap();
        assert!(status(&path).unwrap().can_edit_policy);
        {
            let guard = acquire_for_migration(&path).unwrap();
            write_runtime_marker(&guard, &leave.id, true).unwrap();
        }
        acknowledge_runtime_start(&path, &standalone).unwrap();
        assert!(status(&path).unwrap().can_edit_policy);
    }
    #[tokio::test]
    async fn primary_activation_recovery_preserves_ids_and_rotates_one_consistent_pin() {
        use sha2::{Digest, Sha256};

        let dir = tempfile::tempdir().unwrap();
        let path = master(&dir);
        let create = preview(
            &path,
            LifecycleRequest::Create {
                san: vec!["192.0.2.10".into()],
                api_listen: Some("192.0.2.10:8053".parse().unwrap()),
                migrate_legacy: false,
            },
        )
        .await
        .unwrap();
        apply(&path, &create.id).await.unwrap();
        let before = status(&path).unwrap();
        let before_bytes = std::fs::read(&path).unwrap();
        let recovery =
            preview_primary_activation_recovery(&path, "127.0.0.1:18054".parse().unwrap())
                .await
                .unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), before_bytes);
        {
            let guard = acquire_for_migration(&path).unwrap();
            let files = PrivateStore::open(&guard, PLANS).unwrap();
            let marker: RuntimeMarker =
                serde_json::from_slice(&files.read("runtime.lockdata", 512).unwrap().unwrap())
                    .unwrap();
            assert_eq!(marker.preview_id, create.id);
        }

        let result = apply_primary_activation_recovery(&path, &recovery.id)
            .await
            .unwrap();
        assert!(result.status.restart_required);
        assert_eq!(result.status.node_id, before.node_id);
        assert_eq!(result.status.cluster_id, before.cluster_id);
        let guard = acquire_for_migration(&path).unwrap();
        let loaded = load(&guard).unwrap();
        assert_eq!(
            loaded.config.node.control_listen,
            Some("127.0.0.1:18054".parse().unwrap())
        );
        assert_eq!(loaded.config.api.listen, "127.0.0.1:18054".parse().unwrap());
        let certificate_path = loaded.config.api.tls_cert.as_ref().unwrap();
        let certificate_pem = std::fs::read(certificate_path).unwrap();
        let certificate = rustls::pki_types::CertificateDer::pem_slice_iter(&certificate_pem)
            .next()
            .unwrap()
            .unwrap();
        let fingerprint = hex::encode(Sha256::digest(certificate.as_ref()));
        assert_eq!(
            loaded.config.cluster.primary_cert_fingerprint.as_deref(),
            Some(fingerprint.as_str())
        );
        assert_eq!(
            super::super::membership::MembershipStore::open(&guard)
                .unwrap()
                .primary_fingerprint(),
            fingerprint
        );
        let files = PrivateStore::open(&guard, PLANS).unwrap();
        let marker: RuntimeMarker =
            serde_json::from_slice(&files.read("runtime.lockdata", 512).unwrap().unwrap()).unwrap();
        assert_eq!(marker.preview_id, recovery.id);
        drop(files);
        drop(guard);

        let replay = apply_primary_activation_recovery(&path, &recovery.id)
            .await
            .unwrap();
        assert_eq!(replay.status.node_id, before.node_id);
        assert_eq!(replay.status.cluster_id, before.cluster_id);
    }

    #[tokio::test]
    async fn primary_activation_recovery_rejects_ineligible_or_changed_membership() {
        let standalone = tempfile::tempdir().unwrap();
        let standalone_path = master(&standalone);
        let nonlocal = preview_primary_activation_recovery(
            &standalone_path,
            "192.0.2.254:18054".parse().unwrap(),
        )
        .await
        .unwrap_err();
        assert!(format!("{nonlocal:#}").contains("is not assigned locally"));
        assert!(preview_primary_activation_recovery(
            &standalone_path,
            "127.0.0.1:18054".parse().unwrap()
        )
        .await
        .is_err());

        let dir = tempfile::tempdir().unwrap();
        let path = master(&dir);
        let create = preview(
            &path,
            LifecycleRequest::Create {
                san: vec!["192.0.2.10".into()],
                api_listen: Some("192.0.2.10:8053".parse().unwrap()),
                migrate_legacy: false,
            },
        )
        .await
        .unwrap();
        apply(&path, &create.id).await.unwrap();
        let recovery =
            preview_primary_activation_recovery(&path, "127.0.0.1:18054".parse().unwrap())
                .await
                .unwrap();
        {
            let guard = acquire_for_migration(&path).unwrap();
            let mut members = super::super::membership::MembershipStore::open(&guard).unwrap();
            let now = super::super::membership::now().unwrap();
            let operation_id = super::super::membership::random_id();
            let node_id = super::super::membership::random_id();
            members
                .admit_prepared(
                    &operation_id,
                    &node_id,
                    "peer",
                    "192.0.2.30:8053".parse().unwrap(),
                    &SecretString(crate::auth::token::generate_token().0),
                    now,
                )
                .unwrap();
        }
        assert!(apply_primary_activation_recovery(&path, &recovery.id)
            .await
            .is_err());
        let guard = acquire_for_migration(&path).unwrap();
        let files = PrivateStore::open(&guard, PLANS).unwrap();
        let marker: RuntimeMarker =
            serde_json::from_slice(&files.read("runtime.lockdata", 512).unwrap().unwrap()).unwrap();
        assert_eq!(marker.preview_id, create.id);

        let acknowledged = tempfile::tempdir().unwrap();
        let acknowledged_path = master(&acknowledged);
        let create = preview(
            &acknowledged_path,
            LifecycleRequest::Create {
                san: vec!["192.0.2.10".into()],
                api_listen: Some("192.0.2.10:8053".parse().unwrap()),
                migrate_legacy: false,
            },
        )
        .await
        .unwrap();
        apply(&acknowledged_path, &create.id).await.unwrap();
        let active = load(&acquire_for_migration(&acknowledged_path).unwrap())
            .unwrap()
            .config
            .validation_projection()
            .unwrap();
        acknowledge_runtime_start(&acknowledged_path, &active).unwrap();
        assert!(preview_primary_activation_recovery(
            &acknowledged_path,
            "127.0.0.1:18054".parse().unwrap()
        )
        .await
        .is_err());
    }

    #[tokio::test]
    async fn cancelled_primary_activation_recovery_keeps_original_restart_fence() {
        let dir = tempfile::tempdir().unwrap();
        let path = master(&dir);
        let create = preview(
            &path,
            LifecycleRequest::Create {
                san: vec!["192.0.2.10".into()],
                api_listen: Some("192.0.2.10:8053".parse().unwrap()),
                migrate_legacy: false,
            },
        )
        .await
        .unwrap();
        apply(&path, &create.id).await.unwrap();
        let before = std::fs::read(&path).unwrap();
        let recovery =
            preview_primary_activation_recovery(&path, "127.0.0.1:18054".parse().unwrap())
                .await
                .unwrap();
        cancel(&path, &recovery.id).await.unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), before);
        let guard = acquire_for_migration(&path).unwrap();
        let files = PrivateStore::open(&guard, PLANS).unwrap();
        let marker: RuntimeMarker =
            serde_json::from_slice(&files.read("runtime.lockdata", 512).unwrap().unwrap()).unwrap();
        assert_eq!(marker.preview_id, create.id);
        drop(files);
        drop(guard);

        let ordinary = preview(
            &path,
            LifecycleRequest::Rename {
                name: "ordinary".into(),
            },
        )
        .await
        .unwrap();
        assert!(apply_primary_activation_recovery(&path, &ordinary.id)
            .await
            .is_err());
    }
    #[tokio::test]
    async fn pending_peer_prevents_primary_leave_even_if_added_after_preview() {
        let dir = tempfile::tempdir().unwrap();
        let path = master(&dir);
        let create = preview(
            &path,
            LifecycleRequest::Create {
                san: vec!["192.0.2.10".into()],
                api_listen: Some("192.0.2.10:8053".parse().unwrap()),
                migrate_legacy: false,
            },
        )
        .await
        .unwrap();
        apply(&path, &create.id).await.unwrap();
        let active = {
            let guard = acquire_for_migration(&path).unwrap();
            load(&guard)
                .unwrap()
                .config
                .validation_projection()
                .unwrap()
        };
        acknowledge_runtime_start(&path, &active).unwrap();
        let leave = preview(&path, LifecycleRequest::Leave).await.unwrap();
        {
            let guard = acquire_for_migration(&path).unwrap();
            let mut members = super::super::membership::MembershipStore::open(&guard).unwrap();
            let now = super::super::membership::now().unwrap();
            let invite = members.invite(now).unwrap();
            members
                .enroll(
                    &invite.secret,
                    &super::super::membership::random_id(),
                    "peer",
                    &SecretString(crate::auth::token::generate_token().0),
                    now,
                )
                .unwrap();
        }
        assert!(apply(&path, &leave.id).await.is_err());
        assert_eq!(status(&path).unwrap().saved_role, NodeRole::Primary);
    }
    #[test]
    fn completed_operations_compact_replay_and_progress_past_old_capacity() {
        let dir = tempfile::tempdir().unwrap();
        let path = master(&dir);
        let mut first = None;
        for n in 0..140 {
            let plan = prepare_local(
                &path,
                LifecycleRequest::Rename {
                    name: format!("node-{n}"),
                },
            )
            .unwrap();
            let (result, _) = apply_local(&path, &plan.preview.id).unwrap();
            first.get_or_insert((plan.preview.id, result.backup_id.unwrap()));
        }
        let (first_id, first_backup) = first.unwrap();
        let (replay, _) = apply_local(&path, &first_id).unwrap();
        assert_eq!(replay.backup_id.as_deref(), Some(first_backup.as_str()));
        assert_eq!(
            replay.status.node_name, "node-139",
            "replay must not reapply an older name"
        );
        recover_before_load(&path).unwrap();
        {
            let guard = acquire_for_migration(&path).unwrap();
            let files = PrivateStore::open(&guard, PLANS).unwrap();
            let mut index = read_index(&files).unwrap();
            assert_eq!(index.entries.len(), 140);
            assert!(index.entries.values().all(|entry| entry.compact));
            let compact = read_compact_for_test(&files, &first_id);
            assert!(compact.candidate.is_empty());
            let backup = files
                .read(&format!("backup-{first_id}.data"), MAX_PLAN)
                .unwrap()
                .unwrap();
            let receipts = receipts(&guard).unwrap();
            let receipt = policy_transaction::lookup_receipt(
                &guard,
                &receipts,
                &format!("nodes:{}", compact.preview.local_node_id),
                &first_id,
            )
            .unwrap()
            .unwrap();
            assert_eq!(receipt.transaction_id, first_backup);
            retire_history(
                &files,
                &mut index,
                super::super::membership::now().unwrap() + REPLAY_SECONDS + 1,
            )
            .unwrap();
            assert!(index.entries.is_empty());
            assert_eq!(
                files
                    .read(&format!("backup-{first_id}.data"), MAX_PLAN)
                    .unwrap()
                    .as_deref(),
                Some(backup.as_slice())
            );
            assert!(policy_transaction::lookup_receipt(
                &guard,
                &receipts,
                &receipt.actor,
                &first_id
            )
            .unwrap()
            .is_some());
        }
        let retired = apply_local(&path, &first_id).unwrap_err();
        assert!(
            format!("{retired:#}").contains("unknown or retired preview identity"),
            "{retired:#}"
        );
        let next = prepare_local(
            &path,
            LifecycleRequest::Rename {
                name: "still-usable".into(),
            },
        )
        .unwrap();
        assert_eq!(
            apply_local(&path, &next.preview.id)
                .unwrap()
                .0
                .status
                .node_name,
            "still-usable"
        );
    }
    fn read_compact_for_test(files: &PrivateStore<'_>, id: &str) -> PreparedPlan {
        serde_json::from_slice(
            &files
                .read(&completed_name(id).unwrap(), MAX_PLAN)
                .unwrap()
                .unwrap(),
        )
        .unwrap()
    }
    #[test]
    fn full_active_capacity_still_allows_existing_preview_completion() {
        let dir = tempfile::tempdir().unwrap();
        let path = master(&dir);
        let mut ids = Vec::new();
        for n in 0..MAX_UNRESOLVED_PLANS {
            ids.push(
                prepare_local(
                    &path,
                    LifecycleRequest::Rename {
                        name: format!("pending-{n}"),
                    },
                )
                .unwrap()
                .preview
                .id,
            );
        }
        assert!(prepare_local(
            &path,
            LifecycleRequest::Rename {
                name: "over-capacity".into()
            }
        )
        .is_err());
        assert_eq!(
            apply_local(&path, &ids[0]).unwrap().0.status.node_name,
            "pending-0"
        );
        assert!(prepare_local(
            &path,
            LifecycleRequest::Rename {
                name: "next-slot".into()
            }
        )
        .is_ok());
    }
    #[test]
    fn status_uses_markers_and_retirement_preserves_unacknowledged_recovery_record() {
        let dir = tempfile::tempdir().unwrap();
        let path = master(&dir);
        let create = prepare_local(
            &path,
            LifecycleRequest::Create {
                san: vec!["127.0.0.1".into()],
                api_listen: Some("127.0.0.1:8053".parse().unwrap()),
                migrate_legacy: false,
            },
        )
        .unwrap();
        apply_local(&path, &create.preview.id).unwrap();
        let bytes = {
            let guard = acquire_for_migration(&path).unwrap();
            let files = PrivateStore::open(&guard, PLANS).unwrap();
            let mut index = read_index(&files).unwrap();
            retire_history(
                &files,
                &mut index,
                super::super::membership::now().unwrap() + 2 * REPLAY_SECONDS,
            )
            .unwrap();
            assert!(!index.entries[&create.preview.id].compact);
            let bytes = files
                .read(&plan_name(&create.preview.id).unwrap(), MAX_PLAN)
                .unwrap()
                .unwrap();
            // Status must not parse a candidate; recovery must still reject damaged evidence.
            files
                .write(
                    &plan_name(&create.preview.id).unwrap(),
                    b"damaged candidate",
                )
                .unwrap();
            bytes
        };
        let state = status(&path).unwrap();
        assert!(state.restart_required);
        assert!(!state.can_edit_policy);
        assert!(recover_before_load(&path).is_err());
        let active = {
            let guard = acquire_for_migration(&path).unwrap();
            let files = PrivateStore::open(&guard, PLANS).unwrap();
            files
                .write(&plan_name(&create.preview.id).unwrap(), &bytes)
                .unwrap();
            load(&guard)
                .unwrap()
                .config
                .validation_projection()
                .unwrap()
        };
        acknowledge_runtime_start(&path, &active).unwrap();
        assert!(!status(&path).unwrap().restart_required);
        {
            let guard = acquire_for_migration(&path).unwrap();
            write_runtime_marker(&guard, &create.preview.id, true).unwrap();
            let files = PrivateStore::open(&guard, PLANS).unwrap();
            let mut index = read_index(&files).unwrap();
            retire_history(
                &files,
                &mut index,
                super::super::membership::now().unwrap() + 2 * REPLAY_SECONDS,
            )
            .unwrap();
            assert!(
                index.entries.contains_key(&create.preview.id),
                "marker cleanup is still a recovery root after compaction"
            );
        }
        acknowledge_runtime_start(&path, &active).unwrap();
        let invite = prepare_local(&path, LifecycleRequest::Invite).unwrap();
        let first = apply_local(&path, &invite.preview.id)
            .unwrap()
            .0
            .invitation
            .unwrap();
        let replay = apply_local(&path, &invite.preview.id)
            .unwrap()
            .0
            .invitation
            .unwrap();
        assert_eq!(
            first, replay,
            "explicit invitation replay must not mint another secret"
        );
    }
    #[test]
    fn pending_join_fences_both_writers_without_recursive_lock() {
        let dir = tempfile::tempdir().unwrap();
        let path = master(&dir);
        {
            let guard = acquire_for_migration(&path).unwrap();
            let files = PrivateStore::open(&guard, PLANS).unwrap();
            files
                .write(
                    "pending.lockdata",
                    &serde_json::to_vec(&PendingMarker {
                        preview_id: super::super::membership::random_id(),
                        expires_at: super::super::membership::now().unwrap() + 100,
                    })
                    .unwrap(),
                )
                .unwrap();
        }
        {
            let guard = crate::config::write_lock::acquire_for_write(&path).unwrap();
            assert!(!policy_edit_allowed_under_guard(&guard).unwrap());
        }
        {
            let guard = acquire_for_migration(&path).unwrap();
            assert!(!policy_edit_allowed_under_migration_guard(&guard).unwrap());
        }
    }
}

#[cfg(test)]
mod join_tests {
    use super::*;
    use std::sync::Arc;
    fn fixture() -> (tempfile::TempDir, PathBuf, PreparedPlan) {
        fixture_with_private_corpus(false)
    }
    fn fixture_with_private_corpus(
        private_corpus: bool,
    ) -> (tempfile::TempDir, PathBuf, PreparedPlan) {
        let dir = tempfile::tempdir().unwrap();
        let master = dir.path().join("config.toml");
        std::fs::create_dir(dir.path().join("packs")).unwrap();
        std::fs::write(dir.path().join("packs/shared.txt"), "||old.example^\n").unwrap();
        std::fs::write(&master,"schema_version=5\n[server]\nlisten=\"127.0.0.1:15353\"\ndefault_profile=\"default\"\n[upstream]\nservers=[\"192.0.2.1:53\"]\n[[custom_lists]]\nid=\"shared\"\n[profiles.default]\ncustom_lists=[\"shared\"]\n").unwrap();
        let invite = super::super::membership::Invitation {
            version: 1,
            cluster_id: super::super::membership::random_id(),
            primary_node_id: super::super::membership::random_id(),
            fingerprint: "a".repeat(64),
            expires_at: super::super::membership::now().unwrap()
                + super::super::membership::INVITE_TTL,
            secret: SecretString(crate::auth::token::generate_token().0),
        };
        let mut plan = prepare_local(
            &master,
            LifecycleRequest::Join {
                primary: "https://127.0.0.1:1".into(),
                invitation: invite.encode().unwrap(),
                node_name: Some("desk".into()),
            },
        )
        .unwrap();
        let remote:crate::config::schema::ConfigV5=toml::from_str("schema_version=5\n[server]\ndefault_profile=\"default\"\n[upstream]\nservers=[\"192.0.2.2:53\"]\n[[custom_lists]]\nid=\"shared\"\n[profiles.default]\ncustom_lists=[\"shared\"]\n").unwrap();
        let packs = crate::config::target_v5::PackBodiesV5::new(BTreeMap::from([(
            crate::config::schema::Id::new("shared").unwrap(),
            Arc::from("||new.example^\n"),
        )]));
        let snapshot =
            super::super::artifact::PolicySnapshot::from_target_v5(&remote, &packs, "b".repeat(64))
                .unwrap();
        let publication = snapshot.publication(&"c".repeat(64), 1).unwrap();
        let manifest = super::super::manifest::Manifest::decode(&publication.manifest).unwrap();
        let corpus = super::super::corpus::CorpusManifest::new(
            super::super::dto::ArtifactIdentity::from(&manifest),
            vec![],
            vec![],
        )
        .unwrap();
        let store = super::super::corpus::CorpusStore::open(&master).unwrap();
        if private_corpus {
            store.prepare_manifest_private(&corpus).unwrap();
        } else {
            store.prepare_manifest(&corpus).unwrap();
        }
        plan.corpus_generation = Some(corpus.generation);
        let plan = finish_join(&master, plan, manifest, publication.objects).unwrap();
        (dir, master, plan)
    }
    #[test]
    fn staged_join_validates_a_private_corpus_before_policy_promotion() {
        let (_dir, master, plan) = fixture_with_private_corpus(true);
        let generation = plan.corpus_generation.as_deref().unwrap();
        let store = super::super::corpus::CorpusStore::open(&master).unwrap();
        assert!(store.manifest(generation).is_err());
        assert_eq!(
            store.manifest_metadata(generation).unwrap().generation,
            generation
        );
    }

    #[tokio::test]
    async fn staged_join_publishes_the_verified_review_without_relocking_plans() {
        let (_dir, master, plan) = fixture_with_private_corpus(true);
        let credential = plan.credential.clone().unwrap();
        let review = preview_nodes_staged_join(
            &master,
            NodesStagedJoin {
                cluster_id: credential.cluster_id.clone(),
                primary_node_id: credential.primary_node_id.clone(),
                primary_endpoint: "127.0.0.1:1".parse().unwrap(),
                primary_fingerprint: credential.fingerprint.clone(),
                credential,
                node_name: "desk".into(),
                manifest: plan.manifest.clone().unwrap(),
                objects: BTreeMap::new(),
                corpus_generation: plan.corpus_generation.clone().unwrap(),
                corpus_pin_owner: plan.preview.id.clone(),
                corpus_pin_expires_at: super::super::membership::now().unwrap()
                    + super::super::membership::INVITE_TTL,
            },
        )
        .await
        .unwrap();
        assert_eq!(review.id, plan.preview.id);
        assert!(review.expires_at > super::super::membership::now().unwrap());
    }

    #[test]
    fn populated_join_replaces_policy_with_verified_backup_and_leave_retains_received_policy() {
        let (dir, master, plan) = fixture();
        assert_eq!(
            std::fs::read_to_string(dir.path().join("packs/shared.txt")).unwrap(),
            "||old.example^\n"
        );
        let (joined, _) = apply_local(&master, &plan.preview.id).unwrap();
        assert!(joined.backup_id.is_some());
        assert_eq!(joined.status.saved_role, NodeRole::Secondary);
        assert_eq!(
            std::fs::read_to_string(dir.path().join("packs/shared.txt")).unwrap(),
            "||new.example^\n"
        );
        assert!(super::super::apply::load_persisted(&master)
            .unwrap()
            .is_some());
        {
            let guard = acquire_for_migration(&master).unwrap();
            let config = load(&guard).unwrap();
            assert_eq!(
                config.config.server.listen,
                "127.0.0.1:15353".parse().unwrap()
            );
            assert_eq!(config.config.upstream.servers, vec!["192.0.2.2:53"]);
        }
        let active = {
            let guard = acquire_for_migration(&master).unwrap();
            load(&guard)
                .unwrap()
                .config
                .validation_projection()
                .unwrap()
        };
        acknowledge_runtime_start(&master, &active).unwrap();
        let expected = (
            super::super::dto::ArtifactIdentity::from(plan.manifest.as_ref().unwrap()),
            plan.corpus_generation.clone().unwrap(),
        );
        let wrong = (expected.0.clone(), "0".repeat(64));
        assert!(
            prepare_local_with_active_pair(&master, LifecycleRequest::Leave, Some(&wrong)).is_err()
        );
        let leave =
            prepare_local_with_active_pair(&master, LifecycleRequest::Leave, Some(&expected))
                .unwrap();
        assert!(apply_local_with_active_pair(&master, &leave.preview.id, Some(&wrong)).is_err());
        assert_eq!(status(&master).unwrap().saved_role, NodeRole::Secondary);
        let (left, _) =
            apply_local_with_active_pair(&master, &leave.preview.id, Some(&expected)).unwrap();
        assert_eq!(left.status.saved_role, NodeRole::Standalone);
        assert!(!dir
            .path()
            .join(super::super::transaction::BUNDLE_PATH)
            .exists());
        assert_eq!(
            std::fs::read_to_string(dir.path().join("packs/shared.txt")).unwrap(),
            "||new.example^\n"
        );
        assert!(super::super::pairing::load_secondary_credential(&master).is_err());
        let guard = acquire_for_migration(&master).unwrap();
        assert!(super::super::ledger::OwnershipStore::open(&guard)
            .unwrap()
            .current()
            .is_none());
        assert!(!policy_edit_allowed_under_migration_guard(&guard).unwrap());
        let standalone = load(&guard)
            .unwrap()
            .config
            .validation_projection()
            .unwrap();
        drop(guard);
        acknowledge_runtime_start(&master, &active).unwrap();
        assert!(!status(&master).unwrap().can_edit_policy);
        acknowledge_runtime_start(&master, &standalone).unwrap();
        assert!(status(&master).unwrap().can_edit_policy);
        let (replayed, old_credential) = apply_local(&master, &plan.preview.id).unwrap();
        assert_eq!(replayed.status.saved_role, NodeRole::Standalone);
        assert!(current_activation_credential(&master, old_credential)
            .unwrap()
            .is_none());
        let (_other_dir, other_master, other_plan) = fixture();
        apply_local(&other_master, &other_plan.preview.id).unwrap();
        assert!(
            current_activation_credential(&other_master, plan.credential)
                .unwrap()
                .is_none()
        );
    }
    #[test]
    fn verified_join_restarts_review_window_without_extending_pending_admission() {
        for legacy_deadline in [false, true] {
            let (_dir, master, mut plan) = fixture();
            let now = super::super::membership::now().unwrap();
            plan.preview.expires_at = now - 1;
            if legacy_deadline {
                plan.pending_expires_at = None;
            }
            let deadline = pending_deadline(&plan);
            let manifest = plan.manifest.clone().unwrap();
            let objects = super::super::transaction::expected_objects(&manifest)
                .into_iter()
                .map(|(path, object)| {
                    let bytes = plan
                        .candidate
                        .iter()
                        .find(|member| member.path == Path::new(&path))
                        .unwrap()
                        .bytes
                        .clone();
                    (object.sha256, Arc::<[u8]>::from(bytes))
                })
                .collect();
            {
                let guard = acquire_for_migration(&master).unwrap();
                save_plan(&guard, &plan).unwrap();
                let files = PrivateStore::open(&guard, PLANS).unwrap();
                let mut index = read_index(&files).unwrap();
                retire_history(&files, &mut index, now + 2 * REPLAY_SECONDS).unwrap();
                assert!(
                    index.entries.contains_key(&plan.preview.id),
                    "pending admission is a recovery root"
                );
            }
            let reviewed = finish_join(&master, plan, manifest, objects).unwrap();
            assert!(reviewed.preview.expires_at >= now + super::super::membership::INVITE_TTL);
            assert_eq!(reviewed.pending_expires_at, Some(deadline));
            let guard = acquire_for_migration(&master).unwrap();
            let files = PrivateStore::open(&guard, PLANS).unwrap();
            let marker: PendingMarker =
                serde_json::from_slice(&files.read("pending.lockdata", 512).unwrap().unwrap())
                    .unwrap();
            assert_eq!(marker.expires_at, deadline);
        }
    }

    #[tokio::test]
    async fn staged_join_review_renewal_updates_the_durable_unapplied_plan() {
        let (_dir, master, mut plan) = fixture_with_private_corpus(true);
        let now = super::super::membership::now().unwrap();
        let owner = plan.preview.id.clone();
        plan.private_corpus_pin_owner = Some(owner.clone());
        plan.private_corpus_pin_expires_at = Some(now + 30);
        {
            let guard = acquire_for_migration(&master).unwrap();
            renew_private_corpus_pin(&guard, &plan, now + 30).unwrap();
            save_plan(&guard, &plan).unwrap();
        }

        let renewed = renew_nodes_staged_join_review(&master, &plan.preview.id, &owner, now + 600)
            .await
            .unwrap();
        assert_eq!(renewed.expires_at, now + 600);
        let guard = acquire_for_migration(&master).unwrap();
        let persisted = read_plan(&guard, &plan.preview.id).unwrap();
        assert_eq!(persisted.preview.expires_at, now + 600);
        assert_eq!(persisted.private_corpus_pin_expires_at, Some(now + 600));
        assert_eq!(persisted.pending_expires_at, Some(now + 600));
        drop(guard);
        let (applied, _) = apply_local(&master, &plan.preview.id)
            .expect("the renewed exact private lifecycle preview remains applicable");
        assert_eq!(applied.status.saved_role, NodeRole::Secondary);
    }

    #[tokio::test]
    async fn exact_staged_join_cleanup_cancels_the_retained_pending_marker() {
        let (_dir, master, mut plan) = fixture_with_private_corpus(true);
        let now = super::super::membership::now().unwrap();
        let owner = plan.preview.id.clone();
        plan.private_corpus_pin_owner = Some(owner.clone());
        plan.private_corpus_pin_expires_at = Some(now + 60);
        {
            let guard = acquire_for_migration(&master).unwrap();
            renew_private_corpus_pin(&guard, &plan, now + 60).unwrap();
            save_plan(&guard, &plan).unwrap();
        }
        let active_before = std::fs::read(&master).unwrap();
        assert!(status(&master).unwrap().pending_join);
        assert!(cancel_nodes_staged_join_if_present(
            &master,
            &plan.preview.id,
            &super::super::membership::random_id(),
        )
        .await
        .is_err());
        assert!(status(&master).unwrap().pending_join);
        assert_eq!(std::fs::read(&master).unwrap(), active_before);
        assert!(
            cancel_nodes_staged_join_if_present(&master, &plan.preview.id, &owner)
                .await
                .unwrap()
        );
        assert!(!status(&master).unwrap().pending_join);
        assert_eq!(std::fs::read(&master).unwrap(), active_before);
    }
    #[tokio::test]
    async fn cancelled_join_cannot_be_recreated_by_a_late_transfer_completion() {
        let (dir, master, plan) = fixture();
        let before = std::fs::read(&master).unwrap();
        let manifest = plan.manifest.clone().unwrap();
        let objects = super::super::transaction::expected_objects(&manifest)
            .into_iter()
            .map(|(path, object)| {
                let bytes = plan
                    .candidate
                    .iter()
                    .find(|member| member.path == Path::new(&path))
                    .unwrap()
                    .bytes
                    .clone();
                (object.sha256, Arc::<[u8]>::from(bytes))
            })
            .collect();
        let id = plan.preview.id.clone();
        let cancelled = cancel(&master, &id).await.unwrap();
        assert!(!cancelled.status.pending_join);

        let error = finish_join(&master, plan, manifest, objects)
            .err()
            .expect("a late transfer must not recreate the cancelled join");
        assert!(
            format!("{error:#}").contains("join preview is no longer pending"),
            "{error:#}"
        );
        let state = status(&master).unwrap();
        assert!(!state.pending_join);
        assert!(state.can_edit_policy);
        assert_eq!(state.saved_role, NodeRole::Standalone);
        assert_eq!(std::fs::read(&master).unwrap(), before);
        assert_eq!(
            std::fs::read_to_string(dir.path().join("packs/shared.txt")).unwrap(),
            "||old.example^\n"
        );
        let guard = acquire_for_migration(&master).unwrap();
        assert!(read_plan(&guard, &id).is_err());
        assert!(policy_edit_allowed_under_migration_guard(&guard).unwrap());
    }
    #[tokio::test]
    async fn cancelling_an_expired_join_preserves_the_newer_join_fence() {
        let (_dir, master, mut expired) = fixture();
        let now = super::super::membership::now().unwrap();
        expired.preview.expires_at = now - 1;
        expired.pending_expires_at = Some(now - 1);
        {
            let guard = acquire_for_migration(&master).unwrap();
            save_plan(&guard, &expired).unwrap();
        }
        let invitation = super::super::membership::Invitation {
            version: 1,
            cluster_id: super::super::membership::random_id(),
            primary_node_id: super::super::membership::random_id(),
            fingerprint: "a".repeat(64),
            expires_at: now + super::super::membership::INVITE_TTL,
            secret: SecretString(crate::auth::token::generate_token().0),
        };
        let next = prepare_local(
            &master,
            LifecycleRequest::Join {
                primary: "https://127.0.0.1:1".into(),
                invitation: invitation.encode().unwrap(),
                node_name: None,
            },
        )
        .unwrap();
        let cancelled = cancel(&master, &expired.preview.id).await.unwrap();
        assert!(cancelled.status.pending_join);
        assert_eq!(
            cancelled.status.pending_preview_id.as_deref(),
            Some(next.preview.id.as_str())
        );
        assert!(!cancelled.status.can_edit_policy);
        let guard = acquire_for_migration(&master).unwrap();
        assert!(read_plan(&guard, &expired.preview.id).is_err());
        assert!(read_plan(&guard, &next.preview.id).is_ok());
        assert!(!policy_edit_allowed_under_migration_guard(&guard).unwrap());
    }
    #[test]
    fn join_refuses_changed_reviewed_pack_before_credential_or_policy_promotion() {
        let (dir, master, plan) = fixture();
        std::fs::write(
            dir.path().join("packs/shared.txt"),
            "||concurrent.example^\n",
        )
        .unwrap();
        assert!(apply_local(&master, &plan.preview.id).is_err());
        assert_eq!(
            std::fs::read_to_string(dir.path().join("packs/shared.txt")).unwrap(),
            "||concurrent.example^\n"
        );
        assert!(super::super::pairing::load_secondary_credential(&master).is_err());
    }
    #[tokio::test]
    async fn interrupted_prepared_join_recovers_before_images_and_cancels_pending_admission() {
        let (dir, master, plan) = fixture();
        policy_transaction::fail_after_prepared_for_test();
        let failure = apply_local(&master, &plan.preview.id).unwrap_err();
        assert!(
            format!("{failure:#}").contains("No space left"),
            "{failure:#}"
        );
        recover_before_load(&master).unwrap();
        let result = cancel(&master, &plan.preview.id).await.unwrap();
        assert_eq!(result.status.saved_role, NodeRole::Standalone);
        assert!(!result.status.pending_join);
        assert_eq!(
            std::fs::read_to_string(dir.path().join("packs/shared.txt")).unwrap(),
            "||old.example^\n"
        );
        assert!(super::super::pairing::load_secondary_credential(&master).is_err());
    }
}
