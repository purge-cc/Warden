use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Default)]
struct RecordingListeners {
    prepared: AtomicUsize,
    retired: AtomicUsize,
}

#[async_trait]
impl NodeListenerControl for RecordingListeners {
    async fn prepare(&self, _spec: NodeListenerSpec) -> anyhow::Result<()> {
        self.prepared.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    async fn retire(&self, _endpoint: SocketAddr) -> anyhow::Result<()> {
        self.retired.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

struct BlockingRetireListeners {
    started: tokio::sync::Notify,
    release: tokio::sync::Notify,
}

#[async_trait]
impl NodeListenerControl for BlockingRetireListeners {
    async fn prepare(&self, _spec: NodeListenerSpec) -> anyhow::Result<()> {
        Ok(())
    }

    async fn retire(&self, _endpoint: SocketAddr) -> anyhow::Result<()> {
        self.started.notify_one();
        self.release.notified().await;
        Ok(())
    }
}

struct NoActivePair;

#[async_trait]
impl ActivePairProvider for NoActivePair {
    fn active_pair(&self) -> Option<ActivePolicyCorpus> {
        None
    }

    async fn enrollment_pair(&self) -> anyhow::Result<ActivePolicyCorpus> {
        anyhow::bail!("this fixture has no published pair")
    }

    async fn verified_pair(&self) -> anyhow::Result<Option<ActivePolicyCorpus>> {
        Ok(None)
    }
}

pub(super) struct MutableActivePair(pub(super) std::sync::Mutex<Option<ActivePolicyCorpus>>);

#[async_trait]
impl ActivePairProvider for MutableActivePair {
    fn active_pair(&self) -> Option<ActivePolicyCorpus> {
        self.0.lock().unwrap().clone()
    }

    async fn enrollment_pair(&self) -> anyhow::Result<ActivePolicyCorpus> {
        self.active_pair()
            .context("this fixture has no published pair")
    }

    async fn verified_pair(&self) -> anyhow::Result<Option<ActivePolicyCorpus>> {
        Ok(self.active_pair())
    }
}

fn controller_fixture() -> (
    tempfile::TempDir,
    Arc<NodeController>,
    Arc<RecordingListeners>,
    String,
) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.toml");
    let node_id = crate::cluster::membership::random_id();
    let text = format!(
        "schema_version = 5\n[node]\nid = {node_id:?}\nname = \"Desk\"\n[server]\ndefault_profile = \"default\"\n[profiles.default]\ndisplay_name = \"Default\"\n[upstream]\nservers = [\"192.0.2.1:53\"]\n"
    );
    crate::config::atomic_write::hardened_atomic_write(
        &path,
        text.as_bytes(),
        crate::config::atomic_write::AtomicWriteOpts::default(),
    )
    .unwrap();
    let listeners = Arc::new(RecordingListeners::default());
    let (restart, _receiver) = crate::cluster::managed_restart::channel(1);
    let controller = NodeController::new(path, listeners.clone(), restart, Arc::new(NoActivePair));
    (directory, controller, listeners, node_id)
}

fn persist(controller: &NodeController, state: &ControlState) {
    let guard = acquire_for_migration(&controller.master).unwrap();
    save_state(&guard, state).unwrap();
}

fn pending_peer(node_id: String, credential: &str) -> PeerRecord {
    PeerRecord {
        view: NodePeer {
            node_id,
            name: "Source".into(),
            endpoint: endpoint(),
            role: NodeRole::Primary,
            state: NodePeerState::Pending,
            capabilities: NodeCapabilities::current(),
            last_seen_at: None,
            last_error: None,
        },
        outgoing_credential: SecretString("outgoing-test-credential".into()),
        incoming_credential_hash: hash_token(credential),
        issued_incoming_credential: Some(SecretString(credential.into())),
        source_fingerprint: "a".repeat(64),
    }
}

fn endpoint() -> SocketAddr {
    "192.0.2.10:8053".parse().unwrap()
}

fn operation(phase: NodeOperationPhase, expires_at: u64) -> OperationRecord {
    let source = crate::cluster::membership::random_id();
    let target = crate::cluster::membership::random_id();
    let id = crate::cluster::membership::random_id();
    OperationRecord {
        preview: NodePreview {
            id,
            kind: NodeOperationKind::Add,
            source_node_id: source,
            source_name: "primary".into(),
            source_endpoint: Some(endpoint()),
            target_node_id: target,
            target_name: "secondary".into(),
            target_endpoint: "192.0.2.11:8053".parse().unwrap(),
            target_role: NodeRole::Standalone,
            replacement_summary: vec!["reviewed".into()],
            restart_steps: vec![NodeRestartStep {
                step_id: "primary".into(),
                target: NodeRestartTarget::Primary,
                requested: false,
                acknowledged: false,
            }],
            before_revision: "revision".into(),
            expires_at,
        },
        phase,
        paused_from: None,
        message: "state".into(),
        last_verified_at: None,
        recover_until: Some(expires_at.saturating_add(RECOVERY_TTL)),
        peer_preview_id: None,
        local_preview_id: None,
        staged_pair: None,
        prepared_certificate: None,
        prepared_private_key: None,
        prepared_fingerprint: None,
        cluster_id: None,
        replication_credential: None,
        backup_verified: false,
        cancel_requested: false,
        restart_requested_at: BTreeMap::new(),
    }
}

#[test]
fn staging_add_outlives_the_old_review_deadline_until_verified() {
    let mut state = ControlState::default();
    let staging = operation(NodeOperationPhase::PreparingTarget, 10);
    let id = staging.preview.id.clone();
    state.operations.insert(id.clone(), staging);

    expire_state(&mut state, 10 + PREVIEW_TTL + 1);

    assert_eq!(
        state.operations[&id].phase,
        NodeOperationPhase::PreparingTarget,
        "staging has its own bounded recovery deadline and never becomes a false cancellation"
    );
}

#[tokio::test]
async fn aborted_ipc_waiter_keeps_the_owned_mutation_and_gate_until_completion() {
    let (directory, _unused, _listeners, node_id) = controller_fixture();
    let listeners = Arc::new(BlockingRetireListeners {
        started: tokio::sync::Notify::new(),
        release: tokio::sync::Notify::new(),
    });
    let (restart, _receiver) = crate::cluster::managed_restart::channel(1);
    let controller = NodeController::new(
        directory.path().join("config.toml"),
        listeners.clone(),
        restart,
        Arc::new(NoActivePair),
    );
    let state = ControlState {
        control_endpoint: Some(endpoint()),
        bootstrap: Some(BootstrapAuthorization {
            token_hash: "unused".into(),
            endpoint: endpoint(),
            target_node_id: node_id,
            fingerprint: "a".repeat(64),
            certificate_pem: "certificate".into(),
            private_key_pem: SecretString("key".into()),
            expires_at: crate::cluster::membership::now().unwrap() + PREVIEW_TTL,
            claimed_by: None,
            operation_id: None,
            issued_credential: None,
        }),
        ..ControlState::default()
    };
    persist(&controller, &state);

    let held = controller.transition_gate.lock().await;
    let waiter_controller = controller.clone();
    let waiter = tokio::spawn(async move {
        waiter_controller
            .handle(NodeControlCommand::TokenRevoke)
            .await
    });
    tokio::task::yield_now().await;
    waiter.abort();
    drop(held);
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(20),
            listeners.started.notified(),
        )
        .await
        .is_err(),
        "a waiter cancelled before admission must not leave detached work queued"
    );

    let first_controller = controller.clone();
    let first = tokio::spawn(async move {
        first_controller
            .handle(NodeControlCommand::TokenRevoke)
            .await
    });
    tokio::time::timeout(
        std::time::Duration::from_secs(30),
        listeners.started.notified(),
    )
    .await
    .expect("the admitted controller worker must start");
    first.abort();
    assert!(
        controller.transition_gate.try_lock().is_err(),
        "a second mutation must wait until the detached worker finishes"
    );
    let second_controller = controller.clone();
    let second = tokio::spawn(async move {
        second_controller
            .handle(NodeControlCommand::TokenRevoke)
            .await
    });
    tokio::task::yield_now().await;
    assert!(
        !second.is_finished(),
        "the second mutation must not run while the first owns the transition"
    );

    listeners.release.notify_one();
    let result = tokio::time::timeout(std::time::Duration::from_secs(30), second)
        .await
        .expect("the queued mutation must complete")
        .expect("the task must not panic")
        .expect("the operation must complete");
    assert!(result.message.contains("revoked"));
}

#[test]
fn association_token_is_exactly_bound_and_redacted() {
    let (secret, secret_hash) = crate::auth::token::generate_token();
    let token = BootstrapToken {
        version: PROTOCOL_VERSION,
        target_node_id: crate::cluster::membership::random_id(),
        endpoint: endpoint(),
        fingerprint: "a".repeat(64),
        expires_at: 1_000,
        secret: SecretString(secret.clone()),
    };
    let encoded = token.encode().unwrap();
    assert!(encoded.0.starts_with(BOOTSTRAP_TOKEN_PREFIX));
    assert_eq!(encoded.0.len(), 131);
    let decoded = BootstrapToken::decode(&encoded, 999).unwrap();
    assert_eq!(decoded, token);
    assert!(crate::auth::token::verify_token(
        &decoded.secret.0,
        &secret_hash
    ));
    assert!(BootstrapToken::decode(&encoded, 1_000).is_err());
    assert!(!format!("{token:?}").contains(&secret));
}

#[test]
fn association_token_compact_ipv6_round_trip_has_fixed_length() {
    let (secret, _) = crate::auth::token::generate_token();
    let token = BootstrapToken {
        version: PROTOCOL_VERSION,
        target_node_id: crate::cluster::membership::random_id(),
        endpoint: "[2001:db8::10]:8053".parse().unwrap(),
        fingerprint: "b".repeat(64),
        expires_at: 1_000,
        secret: SecretString(secret),
    };
    let encoded = token.encode().unwrap();
    assert_eq!(encoded.0.len(), 158);
    assert_eq!(BootstrapToken::decode(&encoded, 999).unwrap(), token);
}

#[test]
fn association_token_compact_ipv6_preserves_flowinfo_and_scope() {
    let (secret, _) = crate::auth::token::generate_token();
    let token = BootstrapToken {
        version: PROTOCOL_VERSION,
        target_node_id: crate::cluster::membership::random_id(),
        endpoint: SocketAddr::V6(std::net::SocketAddrV6::new(
            "fe80::10".parse().unwrap(),
            8053,
            0x1020_3040,
            7,
        )),
        fingerprint: "e".repeat(64),
        expires_at: 1_000,
        secret: SecretString(secret),
    };
    let encoded = token.encode().unwrap();
    assert_eq!(encoded.0.len(), 158);
    assert_eq!(BootstrapToken::decode(&encoded, 999).unwrap(), token);
}

#[test]
fn association_token_accepts_legacy_json_encoding() {
    let (secret, _) = crate::auth::token::generate_token();
    let token = BootstrapToken {
        version: PROTOCOL_VERSION,
        target_node_id: crate::cluster::membership::random_id(),
        endpoint: endpoint(),
        fingerprint: "c".repeat(64),
        expires_at: 1_000,
        secret: SecretString(secret),
    };
    let legacy = SecretString(
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&token).unwrap()),
    );
    assert_eq!(BootstrapToken::decode(&legacy, 999).unwrap(), token);
}

#[test]
fn association_token_rejects_invalid_compact_envelopes() {
    let (secret, _) = crate::auth::token::generate_token();
    let token = BootstrapToken {
        version: PROTOCOL_VERSION,
        target_node_id: crate::cluster::membership::random_id(),
        endpoint: endpoint(),
        fingerprint: "d".repeat(64),
        expires_at: 1_000,
        secret: SecretString(secret),
    };
    let encoded = token.encode().unwrap();
    let payload = encoded.0.strip_prefix(BOOTSTRAP_TOKEN_PREFIX).unwrap();
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .unwrap();

    let truncated = SecretString(encoded.0[..encoded.0.len() - 2].into());
    assert!(BootstrapToken::decode(&truncated, 999).is_err());

    let mut trailing = bytes.clone();
    trailing.push(0);
    let trailing = SecretString(format!(
        "{BOOTSTRAP_TOKEN_PREFIX}{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(trailing)
    ));
    assert!(BootstrapToken::decode(&trailing, 999).is_err());

    let mut bad_family = bytes;
    bad_family[0] = 5;
    let bad_family = SecretString(format!(
        "{BOOTSTRAP_TOKEN_PREFIX}{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bad_family)
    ));
    assert!(BootstrapToken::decode(&bad_family, 999).is_err());
    assert!(BootstrapToken::decode(&SecretString("wn3_AA".into()), 999).is_err());
    assert!(BootstrapToken::decode(&SecretString("x".repeat(4_097)), 999).is_err());
}

#[test]
fn expiry_revokes_only_unclaimed_bootstrap_and_never_resets_applied_phase() {
    let mut state = ControlState {
        control_endpoint: Some(endpoint()),
        certificate_pem: Some("certificate".into()),
        private_key_pem: Some(SecretString("key".into())),
        ..ControlState::default()
    };
    let authorization = BootstrapAuthorization {
        token_hash: "a".repeat(64),
        endpoint: endpoint(),
        target_node_id: crate::cluster::membership::random_id(),
        fingerprint: "b".repeat(64),
        certificate_pem: "certificate".into(),
        private_key_pem: SecretString("key".into()),
        expires_at: 10,
        claimed_by: None,
        operation_id: None,
        issued_credential: None,
    };
    state.bootstrap = Some(authorization.clone());
    let prepared = operation(NodeOperationPhase::Prepared, 10);
    let applied = operation(NodeOperationPhase::RestartingPrimary, 10);
    let applied_id = applied.preview.id.clone();
    state
        .operations
        .insert(prepared.preview.id.clone(), prepared);
    state.operations.insert(applied_id.clone(), applied);

    expire_state(&mut state, 10);
    assert!(state.bootstrap.is_none());
    assert!(state
        .operations
        .values()
        .any(|operation| operation.phase == NodeOperationPhase::Paused));
    assert_eq!(
        state.operations[&applied_id].phase,
        NodeOperationPhase::RestartingPrimary
    );

    let mut claimed = authorization;
    claimed.claimed_by = Some(crate::cluster::membership::random_id());
    claimed.operation_id = Some(crate::cluster::membership::random_id());
    claimed.issued_credential = Some(SecretString("ps_claimed".into()));
    state.bootstrap = Some(claimed);
    expire_state(&mut state, 11);
    assert!(state.bootstrap.is_none());

    state.operations.get_mut(&applied_id).unwrap().recover_until = Some(12);
    for now in [12, 13, 14] {
        expire_state(&mut state, now);
        assert_eq!(
            state.operations[&applied_id].phase,
            NodeOperationPhase::Paused
        );
        assert_eq!(
            state.operations[&applied_id].paused_from,
            Some(NodeOperationPhase::RestartingPrimary),
            "repeated reconciliation must preserve the committed recovery step"
        );
    }
}

#[test]
fn listener_restore_requires_live_authorization_or_management_peer() {
    let mut state = ControlState {
        control_endpoint: Some(endpoint()),
        certificate_pem: Some("certificate".into()),
        private_key_pem: Some(SecretString("key".into())),
        ..ControlState::default()
    };
    assert!(listener_specs(&state).is_empty());

    state.bootstrap = Some(BootstrapAuthorization {
        token_hash: "a".repeat(64),
        endpoint: endpoint(),
        target_node_id: crate::cluster::membership::random_id(),
        fingerprint: "b".repeat(64),
        certificate_pem: "certificate".into(),
        private_key_pem: SecretString("key".into()),
        expires_at: u64::MAX,
        claimed_by: None,
        operation_id: None,
        issued_credential: None,
    });
    assert_eq!(listener_specs(&state)[0].scope, ListenerScope::Bootstrap);
}

#[test]
fn public_error_never_copies_an_internal_path() {
    let error = NodeControlError::internal(anyhow::anyhow!(
        "configuration changed at /private/operator/config.toml"
    ));
    assert_eq!(error.code, NodeControlErrorCode::Conflict);
    assert!(!error.message.contains("/private"));
    assert!(format!("{error:?}").contains("/private"));
}

#[tokio::test]
async fn standalone_status_retains_private_review_and_resume_requires_confirmation() {
    let (_directory, controller, _listeners, local_id) = controller_fixture();
    let now = crate::cluster::membership::now().unwrap();
    let mut reviewed = operation(NodeOperationPhase::Prepared, now + PREVIEW_TTL);
    reviewed.preview.source_node_id = local_id.clone();
    reviewed.backup_verified = true;
    let preview = reviewed.preview.clone();
    let mut state = ControlState {
        control_endpoint: Some(endpoint()),
        ..ControlState::default()
    };
    state.operations.insert(preview.id.clone(), reviewed);
    persist(&controller, &state);
    let before = std::fs::read(&controller.master).unwrap();

    let status = controller.handle(NodeControlCommand::Status).await.unwrap();
    assert_eq!(status.status.control_endpoint, Some(endpoint()));
    assert_eq!(status.status.operations.len(), 1);
    assert_eq!(status.status.membership.saved_role, NodeRole::Standalone);
    let resumed = controller
        .handle(NodeControlCommand::Resume {
            operation_id: preview.id.clone(),
        })
        .await
        .unwrap();
    assert_eq!(resumed.preview.unwrap().id, preview.id);
    assert_eq!(
        resumed.status.operations[0].phase,
        NodeOperationPhase::Prepared
    );
    assert_eq!(std::fs::read(&controller.master).unwrap(), before);
    assert_eq!(
        resumed.status.membership.node_id.as_deref(),
        Some(local_id.as_str())
    );
}

#[tokio::test]
async fn requested_restart_reopens_without_rearm_and_requires_exact_ready_proof() {
    let (directory, controller, listeners, local_id) = controller_fixture();
    let master = directory.path().join("config.toml");
    let current_endpoint = endpoint();
    let previous_endpoint: SocketAddr = "192.0.2.9:8053".parse().unwrap();
    let artifact = ArtifactIdentity {
        primary_lineage: "a".repeat(64),
        policy_epoch: 1,
        artifact_hash: "b".repeat(64),
        config_revision: "c".repeat(64),
        operator_policy_hash: "d".repeat(64),
    };
    let manifest =
        super::super::corpus::CorpusManifest::new(artifact.clone(), Vec::new(), Vec::new())
            .unwrap();
    let store = super::super::corpus::CorpusStore::open(&master).unwrap();
    store.install_manifest(&manifest).unwrap();
    store
        .mark_active(&manifest.generation, &manifest.artifact)
        .unwrap();
    let exact_pair = ActivePolicyCorpus {
        policy: artifact,
        corpus_generation: manifest.generation,
    };
    let mut wrong_pair = exact_pair.clone();
    wrong_pair.policy.operator_policy_hash = "e".repeat(64);

    let now = crate::cluster::membership::now().unwrap();
    let mut restarting = operation(NodeOperationPhase::RestartingPrimary, now + RECOVERY_TTL);
    restarting.preview.source_node_id = local_id;
    restarting.preview.restart_steps[0].requested = true;
    restarting
        .restart_requested_at
        .insert("primary".into(), now);
    restarting.staged_pair = Some(exact_pair.clone());
    let operation_id = restarting.preview.id.clone();
    let mut state = ControlState {
        control_endpoint: Some(current_endpoint),
        certificate_pem: Some("current certificate".into()),
        private_key_pem: Some(SecretString("current key".into())),
        certificate_fingerprint: Some("f".repeat(64)),
        previous_listener: Some(ListenerMaterial {
            endpoint: previous_endpoint,
            certificate_pem: "previous certificate".into(),
            private_key_pem: SecretString("previous key".into()),
            fingerprint: "0".repeat(64),
        }),
        ..ControlState::default()
    };
    state.operations.insert(operation_id.clone(), restarting);
    persist(&controller, &state);
    drop(controller);

    let active = Arc::new(MutableActivePair(std::sync::Mutex::new(Some(
        exact_pair.clone(),
    ))));
    let (restart, mut restart_rx) = crate::cluster::managed_restart::channel(1);
    let reopened = NodeController::new(master, listeners, restart, active.clone());
    let runtime = reopened.runtime_start().await.unwrap();
    assert_eq!(runtime.operations_to_resume, vec![operation_id.clone()]);
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(5), restart_rx.recv())
            .await
            .is_err(),
        "reopening durable work must not re-arm its consumed restart step"
    );

    reopened.runtime_ready(previous_endpoint).await.unwrap();
    assert!(
        !load_state(&acquire_for_migration(&reopened.master).unwrap())
            .unwrap()
            .operations[&operation_id]
            .preview
            .restart_steps[0]
            .acknowledged
    );

    *active.0.lock().unwrap() = Some(wrong_pair);
    reopened.runtime_ready(current_endpoint).await.unwrap();
    assert!(
        !load_state(&acquire_for_migration(&reopened.master).unwrap())
            .unwrap()
            .operations[&operation_id]
            .preview
            .restart_steps[0]
            .acknowledged
    );

    *active.0.lock().unwrap() = Some(exact_pair);
    reopened
        .runtime_ready("192.0.2.99:8053".parse().unwrap())
        .await
        .unwrap();
    assert!(
        !load_state(&acquire_for_migration(&reopened.master).unwrap())
            .unwrap()
            .operations[&operation_id]
            .preview
            .restart_steps[0]
            .acknowledged
    );

    reopened.runtime_ready(current_endpoint).await.unwrap();
    let first_ready = load_state(&acquire_for_migration(&reopened.master).unwrap()).unwrap();
    let verified_at = first_ready.operations[&operation_id].last_verified_at;
    assert!(first_ready.operations[&operation_id].preview.restart_steps[0].acknowledged);
    drop(first_ready);

    reopened.runtime_ready(current_endpoint).await.unwrap();
    let replayed = load_state(&acquire_for_migration(&reopened.master).unwrap()).unwrap();
    assert!(replayed.operations[&operation_id].preview.restart_steps[0].acknowledged);
    assert_eq!(
        replayed.operations[&operation_id].last_verified_at,
        verified_at
    );
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(5), restart_rx.recv())
            .await
            .is_err(),
        "readiness replay must not enqueue another restart"
    );
}

#[tokio::test]
async fn standalone_name_edit_never_binds_a_listener_or_requests_a_restart() {
    let (_directory, controller, listeners, local_id) = controller_fixture();
    let prepared = controller
        .handle(NodeControlCommand::PreviewEdit {
            node_id: local_id.clone(),
            name: "Kitchen resolver".into(),
            endpoint: None,
        })
        .await
        .unwrap();
    assert_eq!(listeners.prepared.load(Ordering::SeqCst), 0);
    assert_eq!(prepared.status.control_endpoint, None);
    let applied = controller
        .handle(NodeControlCommand::Apply {
            preview_id: prepared.preview.unwrap().id,
        })
        .await
        .unwrap();
    assert_eq!(applied.status.membership.node_name, "Kitchen resolver");
    assert_eq!(
        applied.status.membership.node_id.as_deref(),
        Some(local_id.as_str())
    );
    assert_eq!(applied.status.membership.saved_role, NodeRole::Standalone);
    assert_eq!(applied.status.control_endpoint, None);
    assert_eq!(listeners.prepared.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn expired_claim_cleanup_is_persistable_and_revokes_management_access() {
    let (_directory, controller, _listeners, local_id) = controller_fixture();
    let now = crate::cluster::membership::now().unwrap();
    let mut review = operation(NodeOperationPhase::Prepared, now - 1);
    review.preview.target_node_id = local_id.clone();
    let source_id = review.preview.source_node_id.clone();
    let operation_id = review.preview.id.clone();
    let (credential, _) = generate_token();
    let mut state = ControlState {
        control_endpoint: Some(endpoint()),
        certificate_pem: Some("certificate".into()),
        private_key_pem: Some(SecretString("key".into())),
        bootstrap: Some(BootstrapAuthorization {
            token_hash: "a".repeat(64),
            endpoint: endpoint(),
            target_node_id: local_id,
            fingerprint: "b".repeat(64),
            certificate_pem: "certificate".into(),
            private_key_pem: SecretString("key".into()),
            expires_at: now - 1,
            claimed_by: Some(source_id.clone()),
            operation_id: Some(operation_id.clone()),
            issued_credential: Some(SecretString(credential.clone())),
        }),
        ..ControlState::default()
    };
    state.peers.insert(
        source_id.clone(),
        pending_peer(source_id.clone(), &credential),
    );
    state.operations.insert(operation_id.clone(), review);
    persist(&controller, &state);
    controller.runtime_tick().await.unwrap();

    let restored = {
        let guard = acquire_for_migration(&controller.master).unwrap();
        load_state(&guard).unwrap()
    };
    assert_eq!(
        restored.operations[&operation_id].phase,
        NodeOperationPhase::Paused
    );
    assert!(restored.bootstrap.is_none());
    assert!(listener_specs(&restored).is_empty());
    assert!(controller.authenticate_peer(&credential).await.is_err());
}

#[tokio::test]
async fn verified_prepared_add_survives_its_original_bootstrap_expiry_until_recovery_expires() {
    let (_directory, controller, _listeners, local_id) = controller_fixture();
    let now = crate::cluster::membership::now().unwrap();
    let mut review = operation(NodeOperationPhase::PreparingTarget, now + RECOVERY_TTL);
    review.preview.target_node_id = local_id.clone();
    review.phase = NodeOperationPhase::Prepared;
    review.preview.expires_at = now + PREVIEW_TTL;
    review.recover_until = Some(now + RECOVERY_TTL);
    review.backup_verified = true;
    let source_id = review.preview.source_node_id.clone();
    let operation_id = review.preview.id.clone();
    let (credential, _) = generate_token();
    let mut state = ControlState {
        bootstrap: Some(BootstrapAuthorization {
            token_hash: "a".repeat(64),
            endpoint: endpoint(),
            target_node_id: local_id,
            fingerprint: "b".repeat(64),
            certificate_pem: "certificate".into(),
            private_key_pem: SecretString("key".into()),
            expires_at: now - 1,
            claimed_by: Some(source_id.clone()),
            operation_id: Some(operation_id.clone()),
            issued_credential: Some(SecretString(credential.clone())),
        }),
        ..ControlState::default()
    };
    let peer = pending_peer(source_id.clone(), &credential);
    state.peers.insert(source_id.clone(), peer.clone());
    state.operations.insert(operation_id.clone(), review);

    expire_state(&mut state, now);
    assert_eq!(
        state.operations[&operation_id].phase,
        NodeOperationPhase::Prepared
    );
    assert!(state.bootstrap.is_some());
    assert_eq!(state.peers[&source_id].view.state, NodePeerState::Pending);

    expire_state(&mut state, now + PREVIEW_TTL + 1);
    assert_eq!(
        state.operations[&operation_id].phase,
        NodeOperationPhase::Paused
    );
    assert!(state.bootstrap.is_some());
    assert_eq!(state.peers[&source_id].view.state, NodePeerState::Pending);
    persist(&controller, &state);
    assert!(controller
        .authorize_pending_request(
            &peer,
            &PeerManagementRequest::Resume {
                operation_id: operation_id.clone(),
            },
        )
        .await
        .is_ok());
}

#[tokio::test]
async fn expiry_is_enforced_at_staging_authorization_without_waiting_for_a_tick() {
    let (_directory, controller, _listeners, local_id) = controller_fixture();
    let now = crate::cluster::membership::now().unwrap();
    let mut review = operation(NodeOperationPhase::Prepared, now + PREVIEW_TTL);
    review.preview.source_node_id = local_id;
    review.staged_pair = Some(ActivePolicyCorpus {
        policy: ArtifactIdentity {
            primary_lineage: "b".repeat(64),
            policy_epoch: 1,
            artifact_hash: "a".repeat(64),
            config_revision: "c".repeat(64),
            operator_policy_hash: "d".repeat(64),
        },
        corpus_generation: "e".repeat(64),
    });
    let target_id = review.preview.target_node_id.clone();
    let operation_id = review.preview.id.clone();
    let (credential, _) = generate_token();
    let mut state = ControlState::default();
    state
        .peers
        .insert(target_id.clone(), pending_peer(target_id, &credential));
    state.operations.insert(review.preview.id.clone(), review);
    persist(&controller, &state);
    let mut headers = HeaderMap::new();
    headers.insert(
        header::AUTHORIZATION,
        format!("Bearer {credential}").parse().unwrap(),
    );
    authorize_staging(
        &controller,
        &headers,
        StagingResource::Artifact("a".repeat(64)),
    )
    .await
    .unwrap();
    state
        .operations
        .get_mut(&operation_id)
        .unwrap()
        .preview
        .expires_at = now - 1;
    persist(&controller, &state);
    assert!(authorize_staging(
        &controller,
        &headers,
        StagingResource::Artifact("a".repeat(64)),
    )
    .await
    .is_err());
}

#[tokio::test]
async fn pending_association_cannot_change_its_primary_endpoint() {
    let (_directory, controller, _listeners, local_id) = controller_fixture();
    let now = crate::cluster::membership::now().unwrap();
    let mut review = operation(NodeOperationPhase::Prepared, now + PREVIEW_TTL);
    review.preview.target_node_id = local_id;
    let operation_id = review.preview.id.clone();
    let source_id = review.preview.source_node_id.clone();
    let (credential, _) = generate_token();
    let peer = pending_peer(source_id.clone(), &credential);
    let mut state = ControlState::default();
    state.peers.insert(source_id.clone(), peer.clone());
    state.operations.insert(operation_id.clone(), review);
    persist(&controller, &state);

    assert!(controller
        .authorize_pending_request(
            &peer,
            &PeerManagementRequest::Resume {
                operation_id: operation_id.clone(),
            }
        )
        .await
        .is_ok());
    let response = controller
        .accept_management(
            &credential,
            PeerManagementRequest::AdoptPrimaryEndpoint {
                operation_id,
                endpoint: "192.0.2.99:8053".parse().unwrap(),
                fingerprint: "b".repeat(64),
            },
        )
        .await;
    assert!(
        response.is_err(),
        "enrollment capability must not authorize endpoint management"
    );
    let guard = acquire_for_migration(&controller.master).unwrap();
    let restored = load_state(&guard).unwrap();
    assert_eq!(restored.peers[&source_id].view.endpoint, peer.view.endpoint);
    assert_eq!(
        restored.peers[&source_id].source_fingerprint,
        peer.source_fingerprint
    );
}

#[tokio::test]
async fn cancelled_add_replays_its_exact_cancel_receipt_but_refuses_apply() {
    let (_directory, controller, _listeners, local_id) = controller_fixture();
    let now = crate::cluster::membership::now().unwrap();
    let mut review = operation(NodeOperationPhase::Cancelled, now + PREVIEW_TTL);
    review.preview.target_node_id = local_id.clone();
    review.peer_preview_id = Some("lifecycle-review".into());
    let operation_id = review.preview.id.clone();
    let source_id = review.preview.source_node_id.clone();
    let (credential, _) = generate_token();
    let peer = pending_peer(source_id.clone(), &credential);
    let mut state = ControlState::default();
    state.peers.insert(source_id, peer);
    state.operations.insert(operation_id.clone(), review);
    state.bootstrap = Some(BootstrapAuthorization {
        token_hash: "unused".into(),
        endpoint: endpoint(),
        target_node_id: local_id,
        fingerprint: "a".repeat(64),
        certificate_pem: "certificate".into(),
        private_key_pem: SecretString("key".into()),
        expires_at: now + PREVIEW_TTL,
        claimed_by: Some(crate::cluster::membership::random_id()),
        operation_id: Some(operation_id.clone()),
        issued_credential: Some(SecretString("peer-credential".into())),
    });
    persist(&controller, &state);

    let replay = controller
        .accept_management(
            &credential,
            PeerManagementRequest::Cancel {
                operation_id: operation_id.clone(),
                preview_id: Some("lifecycle-review".into()),
            },
        )
        .await
        .expect("exact cancelled Add receipt replay");
    assert!(replay.message.contains("already acknowledged"));
    let guard = acquire_for_migration(&controller.master).unwrap();
    let cleaned = load_state(&guard).unwrap();
    assert_eq!(
        cleaned.peers.values().next().unwrap().view.state,
        NodePeerState::Detached
    );
    assert!(cleaned.bootstrap.is_none());
    drop(guard);

    let error = controller
        .accept_management(
            &credential,
            PeerManagementRequest::Apply {
                operation_id: operation_id.clone(),
                preview_id: "lifecycle-review".into(),
            },
        )
        .await
        .expect_err("a cancelled Add must never apply");
    assert!(error.to_string().contains("detached peer credential"));
    assert_eq!(
        controller.operation(&operation_id).await.unwrap().phase,
        NodeOperationPhase::Cancelled
    );
}

#[tokio::test]
async fn cancelled_target_receipt_does_not_cleanup_a_newer_pending_enrollment() {
    let (_directory, controller, listeners, local_id) = controller_fixture();
    let now = crate::cluster::membership::now().unwrap();
    let (credential, _) = generate_token();
    let mut cancelled = operation(NodeOperationPhase::Cancelled, now + PREVIEW_TTL);
    cancelled.preview.target_node_id = local_id.clone();
    cancelled.peer_preview_id = Some("old-lifecycle-review".into());
    cancelled.prepared_certificate = Some("old-certificate".into());
    let cancelled_id = cancelled.preview.id.clone();
    let source_id = cancelled.preview.source_node_id.clone();
    let mut newer = operation(NodeOperationPhase::Prepared, now + PREVIEW_TTL);
    newer.preview.target_node_id = local_id.clone();
    newer.preview.source_node_id = source_id.clone();
    let newer_id = newer.preview.id.clone();
    let state = ControlState {
        bootstrap: Some(BootstrapAuthorization {
            token_hash: "unused".into(),
            endpoint: endpoint(),
            target_node_id: local_id,
            fingerprint: "a".repeat(64),
            certificate_pem: "certificate".into(),
            private_key_pem: SecretString("key".into()),
            expires_at: now + PREVIEW_TTL,
            claimed_by: Some(crate::cluster::membership::random_id()),
            operation_id: Some(newer_id.clone()),
            issued_credential: Some(SecretString("peer-credential".into())),
        }),
        peers: BTreeMap::from([(
            source_id.clone(),
            pending_peer(source_id.clone(), &credential),
        )]),
        operations: BTreeMap::from([(cancelled_id.clone(), cancelled), (newer_id.clone(), newer)]),
        ..ControlState::default()
    };
    persist(&controller, &state);

    let replay = controller
        .accept_management(
            &credential,
            PeerManagementRequest::Cancel {
                operation_id: cancelled_id,
                preview_id: Some("old-lifecycle-review".into()),
            },
        )
        .await
        .expect("a retained receipt must acknowledge without touching a newer enrollment");
    assert!(replay.message.contains("already acknowledged"));
    let guard = acquire_for_migration(&controller.master).unwrap();
    let state = load_state(&guard).unwrap();
    assert_eq!(state.peers[&source_id].view.state, NodePeerState::Pending);
    assert_eq!(
        state.bootstrap.as_ref().unwrap().operation_id.as_deref(),
        Some(newer_id.as_str())
    );
    assert_eq!(
        state.operations[&newer_id].phase,
        NodeOperationPhase::Prepared
    );
    assert_eq!(listeners.retired.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn resume_finishes_a_persisted_source_cancellation_without_removing_a_newer_peer() {
    let (_directory, controller, _listeners, _local_id) = controller_fixture();
    let now = crate::cluster::membership::now().unwrap();
    let (credential, _) = generate_token();
    let mut cancelled = operation(NodeOperationPhase::Cancelled, now + PREVIEW_TTL);
    cancelled.cancel_requested = true;
    let cancelled_id = cancelled.preview.id.clone();
    let target_id = cancelled.preview.target_node_id.clone();
    let state = ControlState {
        peers: BTreeMap::from([(
            target_id.clone(),
            pending_peer(target_id.clone(), &credential),
        )]),
        operations: BTreeMap::from([(cancelled_id.clone(), cancelled.clone())]),
        ..ControlState::default()
    };
    persist(&controller, &state);

    controller.resume(&cancelled_id).await.unwrap();
    let guard = acquire_for_migration(&controller.master).unwrap();
    let state = load_state(&guard).unwrap();
    assert!(!state.peers.contains_key(&target_id));
    drop(guard);

    let mut newer = operation(NodeOperationPhase::Prepared, now + PREVIEW_TTL);
    newer.preview.target_node_id = target_id.clone();
    let newer_id = newer.preview.id.clone();
    let state = ControlState {
        peers: BTreeMap::from([(
            target_id.clone(),
            pending_peer(target_id.clone(), &credential),
        )]),
        operations: BTreeMap::from([(cancelled_id.clone(), cancelled), (newer_id.clone(), newer)]),
        ..ControlState::default()
    };
    persist(&controller, &state);

    controller.resume(&cancelled_id).await.unwrap();
    let guard = acquire_for_migration(&controller.master).unwrap();
    let state = load_state(&guard).unwrap();
    assert_eq!(state.peers[&target_id].view.state, NodePeerState::Pending);
    assert_eq!(
        state.operations[&newer_id].phase,
        NodeOperationPhase::Prepared
    );
}

#[tokio::test]
async fn target_local_abandon_is_exact_and_allows_a_fresh_token() {
    let (_directory, controller, _listeners, local_id) = controller_fixture();
    let now = crate::cluster::membership::now().unwrap();
    let mut pending = operation(NodeOperationPhase::PreparingTarget, now + PREVIEW_TTL);
    pending.preview.target_node_id = local_id.clone();
    let operation_id = pending.preview.id.clone();
    let source_id = pending.preview.source_node_id.clone();
    let (credential, _) = generate_token();
    let mut state = ControlState::default();
    state
        .peers
        .insert(source_id.clone(), pending_peer(source_id, &credential));
    state.operations.insert(operation_id.clone(), pending);
    state.bootstrap = Some(BootstrapAuthorization {
        token_hash: "unused".into(),
        endpoint: endpoint(),
        target_node_id: local_id,
        fingerprint: "a".repeat(64),
        certificate_pem: "certificate".into(),
        private_key_pem: SecretString("key".into()),
        expires_at: now + PREVIEW_TTL,
        claimed_by: Some(crate::cluster::membership::random_id()),
        operation_id: Some(operation_id.clone()),
        issued_credential: Some(SecretString("peer-credential".into())),
    });
    persist(&controller, &state);

    assert!(controller
        .abandon_preparing_add(&crate::cluster::membership::random_id())
        .await
        .is_err());
    let unchanged = controller.operation(&operation_id).await.unwrap();
    assert_eq!(unchanged.phase, NodeOperationPhase::PreparingTarget);
    assert!(!unchanged.cancel_requested);

    controller
        .abandon_preparing_add(&operation_id)
        .await
        .unwrap();
    let guard = acquire_for_migration(&controller.master).unwrap();
    let state = load_state(&guard).unwrap();
    assert_eq!(
        state.operations[&operation_id].phase,
        NodeOperationPhase::Cancelled
    );
    assert_eq!(
        state.peers.values().next().unwrap().view.state,
        NodePeerState::Detached
    );
    assert!(state.bootstrap.is_none());
    drop(guard);
    assert!(controller
        .handle(NodeControlCommand::TokenPrepare {
            listen: Some("127.0.0.1:19300".parse().unwrap()),
        })
        .await
        .unwrap()
        .token
        .is_some());
}

#[tokio::test]
async fn token_refused_for_an_active_peer_preserves_saved_endpoint() {
    let (_directory, controller, listeners, _local_id) = controller_fixture();
    let source_id = crate::cluster::membership::random_id();
    let (credential, _) = generate_token();
    let mut peer = pending_peer(source_id.clone(), &credential);
    peer.view.state = NodePeerState::Active;
    let mut state = ControlState {
        control_endpoint: Some(endpoint()),
        certificate_pem: Some("certificate".into()),
        private_key_pem: Some(SecretString("key".into())),
        certificate_fingerprint: Some("a".repeat(64)),
        ..ControlState::default()
    };
    state.peers.insert(source_id, peer);
    persist(&controller, &state);
    let before = std::fs::read(&controller.master).unwrap();
    let response = controller
        .handle(NodeControlCommand::TokenPrepare {
            listen: Some("127.0.0.2:18053".parse().unwrap()),
        })
        .await;
    assert!(response.is_err());
    assert_eq!(std::fs::read(&controller.master).unwrap(), before);
    assert_eq!(listeners.prepared.load(Ordering::SeqCst), 0);
    let guard = acquire_for_migration(&controller.master).unwrap();
    let restored = load_state(&guard).unwrap();
    assert_eq!(restored.control_endpoint, state.control_endpoint);
    assert_eq!(
        restored.certificate_fingerprint,
        state.certificate_fingerprint
    );
    assert!(restored.bootstrap.is_none());
}

#[test]
fn an_open_node_operation_refuses_relocate_until_it_is_terminal() {
    use crate::cli::commands::config::relocate::{self, tests::layout_for_test, Options};
    let directory = tempfile::tempdir().unwrap();
    let base = std::fs::canonicalize(directory.path()).unwrap();
    let (layout, _mapping) = layout_for_test(&base);
    let master = layout.legacy.join("config.toml");
    std::fs::write(
        &master,
        format!(
            "schema_version = 5\n[backup]\ndir = {:?}\n[server]\ndefault_profile = \"default\"\n[profiles.default]\ndisplay_name = \"Default\"\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
            layout.legacy.join("backups").display().to_string()
        ),
    )
    .unwrap();
    let record = operation(NodeOperationPhase::ApplyingPrimary, 10);
    let id = record.preview.id.clone();
    let mut state = ControlState::default();
    state.operations.insert(id.clone(), record);
    save_state(&acquire_for_migration(&master).unwrap(), &state).unwrap();
    let options = Options {
        dry_run: false,
        reverse: false,
    };

    let outcome = relocate::relocate(&layout, options).unwrap();
    assert_ne!(outcome.code, 0, "{outcome:?}");
    assert!(
        outcome.err[0].starts_with("refused (recovery-required): .warden-node-control")
            && outcome.err[0].contains(&id)
            && outcome.err[0].contains("`warden node status`"),
        "{outcome:?}"
    );
    assert!(master.is_file());

    state.operations.get_mut(&id).unwrap().phase = NodeOperationPhase::Complete;
    save_state(&acquire_for_migration(&master).unwrap(), &state).unwrap();
    let outcome = relocate::relocate(&layout, options).unwrap();
    assert_eq!(outcome.code, 0, "{outcome:?}");
}

#[tokio::test]
async fn status_reports_runtime_problems() {
    let (_directory, controller, _listeners, _local_id) = controller_fixture();
    let problem = "Nodes listener 192.0.2.10:8053 not restored: test".to_string();
    controller.set_runtime_problems(vec![problem.clone()]);
    let status = controller
        .handle(NodeControlCommand::Status)
        .await
        .unwrap()
        .status;
    assert_eq!(status.runtime_problems, vec![problem]);

    // An older daemon sends no runtime_problems key.
    let mut wire = serde_json::to_value(&status).unwrap();
    wire.as_object_mut().unwrap().remove("runtime_problems");
    let older: NodeControlStatus = serde_json::from_value(wire).unwrap();
    assert!(older.runtime_problems.is_empty());
}

/// One config revision whose replicated policy serializes as `extra` adds.
fn same_revision_snapshot(extra: &str) -> Arc<crate::cluster::artifact::PolicySnapshot> {
    let config: crate::config::schema::ConfigV5 = toml::from_str(&format!(
        "schema_version = 5\n[server]\ndefault_profile = \"default\"\n[profiles.default]\ndisplay_name = \"Default\"\n[upstream]\nservers = [\"192.0.2.1:53\"]\n{extra}"
    ))
    .unwrap();
    Arc::new(
        crate::cluster::artifact::PolicySnapshot::from_target_v5(
            &config,
            &crate::config::target_v5::PackBodiesV5::new(BTreeMap::new()),
            "b".repeat(64),
        )
        .unwrap(),
    )
}

#[test]
fn enrollment_capture_republishes_a_revision_an_older_version_serialized_differently() {
    // An older version published these config bytes with another default.
    let directory = tempfile::tempdir().unwrap();
    let master = directory.path().join("config.toml");
    let older = same_revision_snapshot("[anti_bypass]\nenabled = true\n");
    let current = same_revision_snapshot("");
    assert_ne!(older.toml(), current.toml());
    let published = capture_enrollment_policy(&master, older).unwrap();

    let captured = capture_enrollment_policy(&master, Arc::clone(&current)).unwrap();
    assert_eq!(captured.config_revision, published.config_revision);
    assert!(captured.policy_epoch > published.policy_epoch);
    assert_eq!(
        captured.operator_policy_hash,
        current.operator_policy_hash()
    );
    assert_eq!(
        capture_enrollment_policy(&master, current).unwrap(),
        captured
    );
}

#[test]
fn enrollment_capture_refuses_a_revision_with_an_unresolved_publication() {
    let directory = tempfile::tempdir().unwrap();
    let master = directory.path().join("config.toml");
    let older = same_revision_snapshot("[anti_bypass]\nenabled = true\n");
    capture_enrollment_policy(&master, Arc::clone(&older)).unwrap();
    {
        let guard = acquire_for_migration(&master).unwrap();
        let mut store = crate::cluster::publication::PublicationStore::open(&guard).unwrap();
        let pending = store
            .reserve(|lineage, epoch| older.publication(lineage, epoch))
            .unwrap();
        store
            .bind_intent(
                &pending,
                serde_json::json!({
                    "actor": "cluster-publisher",
                    "request_id": "publication-request",
                    "primary_lineage": pending.primary_lineage,
                    "policy_epoch": pending.policy_epoch,
                    "artifact_hash": pending.artifact_hash,
                    "expected_after_revision": pending.config_revision,
                }),
            )
            .unwrap();
    }

    let error = capture_enrollment_policy(&master, same_revision_snapshot("")).unwrap_err();
    assert!(
        error.to_string().contains("unresolved publication"),
        "{error:#}"
    );
}

fn stored_state(controller: &NodeController) -> ControlState {
    load_state(&acquire_for_migration(&controller.master).unwrap()).unwrap()
}

async fn expired_review_frees_the_node(kind: NodeOperationKind) {
    let (_directory, controller, _listeners, _local_id) = controller_fixture();
    let now = crate::cluster::membership::now().unwrap();
    let mut review = operation(NodeOperationPhase::Prepared, now - 1);
    review.preview.kind = kind;
    let operation_id = review.preview.id.clone();
    let mut next = operation(NodeOperationPhase::Prepared, now + PREVIEW_TTL);
    next.preview.kind = kind;
    next.preview.target_node_id = review.preview.target_node_id.clone();
    let mut state = ControlState::default();
    state.operations.insert(operation_id.clone(), review);
    persist(&controller, &state);

    controller.runtime_tick().await.unwrap();

    let operation = &stored_state(&controller).operations[&operation_id];
    assert_eq!(operation.phase, NodeOperationPhase::Cancelled);
    assert_eq!(operation.message, REVIEW_EXPIRED_MESSAGE);
    controller.insert_operation(next).await.unwrap();
}

#[tokio::test]
async fn expired_edit_review_is_cancelled_and_frees_the_node() {
    expired_review_frees_the_node(NodeOperationKind::Edit).await;
}

#[tokio::test]
async fn expired_remove_review_is_cancelled_and_frees_the_node() {
    expired_review_frees_the_node(NodeOperationKind::Remove).await;
}

#[test]
fn legacy_paused_edit_or_remove_review_becomes_cancelled() {
    let mut state = ControlState::default();
    let mut legacy = Vec::new();
    for kind in [NodeOperationKind::Edit, NodeOperationKind::Remove] {
        let mut review = operation(NodeOperationPhase::Paused, 10);
        review.preview.kind = kind;
        legacy.push(review.preview.id.clone());
        state.operations.insert(review.preview.id.clone(), review);
    }
    let mut add = operation(NodeOperationPhase::Paused, 10);
    add.paused_from = Some(NodeOperationPhase::Prepared);
    let add_id = add.preview.id.clone();
    state.operations.insert(add_id.clone(), add);

    expire_state(&mut state, 11);

    for id in legacy {
        assert_eq!(state.operations[&id].phase, NodeOperationPhase::Cancelled);
        assert_eq!(state.operations[&id].message, REVIEW_EXPIRED_MESSAGE);
    }
    assert_eq!(state.operations[&add_id].phase, NodeOperationPhase::Paused);
    assert_eq!(
        state.operations[&add_id].paused_from,
        Some(NodeOperationPhase::Prepared)
    );
}

#[tokio::test]
async fn expired_local_edit_review_releases_its_rename_plan() {
    let (_directory, controller, _listeners, local_id) = controller_fixture();
    let edit = || NodeControlCommand::PreviewEdit {
        node_id: local_id.clone(),
        name: "Kitchen resolver".into(),
        endpoint: None,
    };
    let operation_id = controller.handle(edit()).await.unwrap().preview.unwrap().id;
    let mut state = stored_state(&controller);
    let operation = state.operations.get_mut(&operation_id).unwrap();
    let plan_id = operation.peer_preview_id.clone().unwrap();
    operation.preview.expires_at = crate::cluster::membership::now().unwrap() - 1;
    persist(&controller, &state);
    assert!(
        crate::cluster::lifecycle::preview_exists(&controller.master, &plan_id)
            .await
            .unwrap()
    );

    controller.runtime_tick().await.unwrap();

    let operation = &stored_state(&controller).operations[&operation_id];
    assert_eq!(operation.phase, NodeOperationPhase::Cancelled);
    assert!(
        !crate::cluster::lifecycle::preview_exists(&controller.master, &plan_id)
            .await
            .unwrap()
    );
    controller.handle(edit()).await.unwrap();
}

#[tokio::test]
async fn cancel_of_a_remove_the_peer_never_prepared_completes_locally() {
    let (_directory, controller, _listeners, local_id) = controller_fixture();
    let now = crate::cluster::membership::now().unwrap();
    let mut review = operation(NodeOperationPhase::Prepared, now + PREVIEW_TTL);
    review.preview.kind = NodeOperationKind::Remove;
    review.preview.source_node_id = local_id;
    let operation_id = review.preview.id.clone();
    let mut state = ControlState::default();
    state.operations.insert(operation_id.clone(), review);
    persist(&controller, &state);

    let reply = controller
        .handle(NodeControlCommand::Cancel {
            preview_id: operation_id.clone(),
        })
        .await
        .unwrap();

    assert_eq!(reply.message, "Preview cancelled.");
    assert_eq!(
        stored_state(&controller).operations[&operation_id].phase,
        NodeOperationPhase::Cancelled
    );
    let replay = controller
        .handle(NodeControlCommand::Cancel {
            preview_id: operation_id,
        })
        .await
        .unwrap();
    assert_eq!(replay.message, "Preview cancelled.");
}

#[tokio::test]
async fn apply_of_a_cancelled_review_says_it_expired() {
    let (_directory, controller, _listeners, _local_id) = controller_fixture();
    let mut review = operation(NodeOperationPhase::Cancelled, u64::MAX);
    review.preview.kind = NodeOperationKind::Edit;
    let operation_id = review.preview.id.clone();
    let mut state = ControlState::default();
    state.operations.insert(operation_id.clone(), review);
    persist(&controller, &state);

    let error = controller
        .handle(NodeControlCommand::Apply {
            preview_id: operation_id,
        })
        .await
        .unwrap_err();

    assert_eq!(error.code, NodeControlErrorCode::AuthorizationExpired);
    assert!(
        format!("{:?}", error.source).contains("review expired or was cancelled"),
        "{error:?}"
    );
}

fn corpus_artifact() -> ArtifactIdentity {
    ArtifactIdentity {
        primary_lineage: "a".repeat(64),
        policy_epoch: 1,
        artifact_hash: "b".repeat(64),
        config_revision: "c".repeat(64),
        operator_policy_hash: "d".repeat(64),
    }
}

/// Install and activate a one-list corpus for `artifact`, as a list refresh
/// does. Older generations stay only while something pins them.
pub(super) fn refresh_corpus(
    store: &super::super::corpus::CorpusStore,
    artifact: &ArtifactIdentity,
    body: &[u8],
    fetched_at: i64,
) -> ActivePolicyCorpus {
    let object = super::super::manifest::ObjectRef::of(body);
    if !store.has_object(&object) {
        let mut stage = store.stage(&object).unwrap();
        stage.write_chunk(body).unwrap();
        stage.finish(store).unwrap();
    }
    let url = "https://lists.example.com/rules".to_owned();
    let manifest = super::super::corpus::CorpusManifest::new(
        artifact.clone(),
        vec![super::super::corpus::CorpusSource {
            source: super::super::corpus::SourceIdentity {
                representative: url.clone(),
                fetch_url: url.clone(),
                canonical_url: url,
                aliases: Vec::new(),
                ids: Vec::new(),
                max_entries: 100,
                update_interval_secs: 60,
                format: "Domains".into(),
                trust: "RemoteUnsigned".into(),
            },
            body: object,
            fetched_at,
        }],
        Vec::new(),
    )
    .unwrap();
    store.install_manifest(&manifest).unwrap();
    store.mark_active(&manifest.generation, artifact).unwrap();
    ActivePolicyCorpus {
        policy: artifact.clone(),
        corpus_generation: manifest.generation,
    }
}

#[test]
fn reviewed_corpus_survives_a_list_refresh_that_keeps_its_bodies() {
    let directory = tempfile::tempdir().unwrap();
    let master = directory.path().join("config.toml");
    let store = super::super::corpus::CorpusStore::open(&master).unwrap();
    let artifact = corpus_artifact();
    let reviewed = refresh_corpus(&store, &artifact, b"blocked.example.com\n", 1_800_000_000);
    let owner = crate::cluster::membership::random_id();
    let now = crate::cluster::membership::now().unwrap();
    pin_reviewed_corpus(&master, &reviewed, &owner, now + RECOVERY_TTL).unwrap();

    let revalidated = refresh_corpus(&store, &artifact, b"blocked.example.com\n", 1_800_000_060);
    assert_ne!(revalidated.corpus_generation, reviewed.corpus_generation);
    assert!(reviewed_pair_matches(&master, &reviewed, &revalidated).unwrap());

    let changed = refresh_corpus(&store, &artifact, b"other.example.com\n", 1_800_000_120);
    assert!(!reviewed_pair_matches(&master, &reviewed, &changed).unwrap());

    store.release_private_manifest_pin(&owner).unwrap();
    let gone = reviewed_pair_matches(&master, &reviewed, &changed).unwrap_err();
    assert!(
        format!("{gone:#}").contains(REVIEWED_CORPUS_GONE),
        "{gone:#}"
    );
}

#[tokio::test]
async fn add_apply_refuses_a_changed_corpus_before_the_primary_admits_anything() {
    let (directory, controller, listeners, local_id) = controller_fixture();
    let master = directory.path().join("config.toml");
    let store = super::super::corpus::CorpusStore::open(&master).unwrap();
    let artifact = corpus_artifact();
    let reviewed = refresh_corpus(&store, &artifact, b"blocked.example.com\n", 1_800_000_000);
    let now = crate::cluster::membership::now().unwrap();
    let mut prepared = operation(NodeOperationPhase::Prepared, now + PREVIEW_TTL);
    pin_reviewed_corpus(&master, &reviewed, &prepared.preview.id, now + RECOVERY_TTL).unwrap();
    let changed = refresh_corpus(&store, &artifact, b"other.example.com\n", 1_800_000_060);
    prepared.preview.source_node_id = local_id;
    prepared.preview.before_revision = local_revision(&master).await.unwrap();
    prepared.staged_pair = Some(reviewed);
    prepared.backup_verified = true;
    prepared.peer_preview_id = Some(crate::cluster::membership::random_id());
    let operation_id = prepared.preview.id.clone();
    let mut state = ControlState::default();
    state.operations.insert(operation_id.clone(), prepared);
    persist(&controller, &state);
    drop(controller);
    let (restart, mut restart_rx) = crate::cluster::managed_restart::supervised_channel();
    let controller = NodeController::new(
        master.clone(),
        listeners,
        restart,
        Arc::new(MutableActivePair(std::sync::Mutex::new(Some(changed)))),
    );

    let error = controller
        .handle(NodeControlCommand::Apply {
            preview_id: operation_id.clone(),
        })
        .await
        .unwrap_err();

    assert_eq!(error.code, NodeControlErrorCode::Conflict, "{error:?}");
    assert_eq!(
        load_state(&acquire_for_migration(&master).unwrap())
            .unwrap()
            .operations[&operation_id]
            .phase,
        NodeOperationPhase::Prepared
    );
    assert_eq!(
        super::super::lifecycle::status(&master).unwrap().saved_role,
        NodeRole::Standalone
    );
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(50), restart_rx.recv())
            .await
            .is_err(),
        "a refused Add requested a restart"
    );
    // The operator's way out: the cancel is accepted and waits for the peer.
    controller
        .handle(NodeControlCommand::Cancel {
            preview_id: operation_id.clone(),
        })
        .await
        .unwrap();
    assert!(
        load_state(&acquire_for_migration(&master).unwrap())
            .unwrap()
            .operations[&operation_id]
            .cancel_requested
    );
}

#[tokio::test]
async fn staging_serves_the_reviewed_corpus_after_a_list_refresh() {
    let (directory, controller, _listeners, _local_id) = controller_fixture();
    let master = directory.path().join("config.toml");
    let store = super::super::corpus::CorpusStore::open(&master).unwrap();
    let artifact = corpus_artifact();
    let reviewed = refresh_corpus(&store, &artifact, b"blocked.example.com\n", 1_800_000_000);
    let now = crate::cluster::membership::now().unwrap();
    let mut staging = operation(NodeOperationPhase::PreparingTarget, now + RECOVERY_TTL);
    pin_reviewed_corpus(&master, &reviewed, &staging.preview.id, now + RECOVERY_TTL).unwrap();
    let refreshed = refresh_corpus(&store, &artifact, b"blocked.example.com\n", 1_800_000_060);
    staging.staged_pair = Some(reviewed.clone());
    let target_id = staging.preview.target_node_id.clone();
    let (credential, _) = generate_token();
    let mut state = ControlState::default();
    state
        .peers
        .insert(target_id.clone(), pending_peer(target_id, &credential));
    state.operations.insert(staging.preview.id.clone(), staging);
    persist(&controller, &state);
    let mut headers = HeaderMap::new();
    headers.insert(
        header::AUTHORIZATION,
        format!("Bearer {credential}").parse().unwrap(),
    );

    let response = staged_corpus_manifest(
        State(controller),
        headers,
        RoutePath(artifact.artifact_hash.clone()),
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let served: super::super::corpus::CorpusManifest = serde_json::from_slice(&body).unwrap();
    assert_eq!(served.generation, reviewed.corpus_generation);
    assert_ne!(served.generation, refreshed.corpus_generation);
}

/// Status may read the active pair, but never prove it by hashing the corpus.
struct IdentityOnlyPair(ActivePolicyCorpus);

#[async_trait]
impl ActivePairProvider for IdentityOnlyPair {
    fn active_pair(&self) -> Option<ActivePolicyCorpus> {
        panic!("status hashed the whole corpus")
    }

    async fn enrollment_pair(&self) -> anyhow::Result<ActivePolicyCorpus> {
        anyhow::bail!("status needs no enrollment pair")
    }

    async fn verified_pair(&self) -> anyhow::Result<Option<ActivePolicyCorpus>> {
        anyhow::bail!("status needs no verified pair")
    }

    fn active_identity(&self) -> Option<ActivePolicyCorpus> {
        Some(self.0.clone())
    }
}

#[tokio::test]
async fn status_reports_the_active_pair_without_proving_the_corpus() {
    let (directory, controller, listeners, _local_id) = controller_fixture();
    drop(controller);
    let pair = ActivePolicyCorpus {
        policy: corpus_artifact(),
        corpus_generation: "e".repeat(64),
    };
    let (restart, _receiver) = crate::cluster::managed_restart::channel(1);
    let controller = NodeController::new(
        directory.path().join("config.toml"),
        listeners,
        restart,
        Arc::new(IdentityOnlyPair(pair.clone())),
    );

    let status = controller
        .handle(NodeControlCommand::Status)
        .await
        .unwrap()
        .status
        .membership;

    assert_eq!(status.active_policy, Some(pair.policy));
    assert_eq!(status.active_corpus, Some(pair.corpus_generation));
}

const MANAGE: &str = "/api/nodes/v2/manage";

fn nodes_router(controller: &Arc<NodeController>, client: &str) -> Router {
    node_router(controller.clone()).layer(axum::extract::connect_info::MockConnectInfo(
        client.parse::<SocketAddr>().unwrap(),
    ))
}

fn nodes_request(method: &str, path: &str, bearer: Option<&str>) -> axum::http::Request<Body> {
    let mut request = axum::http::Request::builder()
        .method(method)
        .uri(path)
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(bearer) = bearer {
        request = request.header(header::AUTHORIZATION, format!("Bearer {bearer}"));
    }
    // A well-formed body, so only the credential can refuse it.
    let body = serde_json::to_vec(&PeerManagementRequest::Cancel {
        operation_id: crate::cluster::membership::random_id(),
        preview_id: None,
    })
    .unwrap();
    request.body(Body::from(body)).unwrap()
}

#[tokio::test]
async fn refused_bearers_lock_the_address_out_of_the_nodes_port() {
    use tower::ServiceExt;
    let (_directory, controller, _listeners, _local_id) = controller_fixture();
    let router = nodes_router(&controller, "192.0.2.7:40000");

    for attempt in 1..=10 {
        let response = router
            .clone()
            .oneshot(nodes_request("POST", MANAGE, Some("wrong")))
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "attempt {attempt}"
        );
    }
    let locked = router
        .clone()
        .oneshot(nodes_request("POST", MANAGE, Some("wrong")))
        .await
        .unwrap();
    assert_eq!(locked.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(locked.headers()[header::RETRY_AFTER], "300");

    let health = router
        .oneshot(nodes_request("GET", "/api/nodes/v2/health", None))
        .await
        .unwrap();
    assert_eq!(health.status(), StatusCode::NO_CONTENT);
    let other = nodes_router(&controller, "192.0.2.8:40000")
        .oneshot(nodes_request("POST", MANAGE, None))
        .await
        .unwrap();
    assert_eq!(other.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn refused_bearers_never_wait_for_the_transition_gate() {
    use tower::ServiceExt;
    let (_directory, controller, _listeners, _local_id) = controller_fixture();
    let operation = controller.transition_gate.clone().lock_owned().await;

    let mut flood = tokio::task::JoinSet::new();
    for host in 1..=20 {
        let router = nodes_router(&controller, &format!("192.0.2.{host}:40000"));
        flood.spawn(router.oneshot(nodes_request("POST", MANAGE, Some("wrong"))));
    }
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        controller.handle(NodeControlCommand::Status),
    )
    .await
    .expect("status waited behind the flood")
    .unwrap();
    while let Some(response) = flood.join_next().await {
        assert_eq!(
            response.unwrap().unwrap().status(),
            StatusCode::UNAUTHORIZED
        );
    }
    drop(operation);
}

#[tokio::test]
async fn nodes_port_refuses_at_once_when_its_permits_are_taken() {
    use tower::ServiceExt;
    let (_directory, controller, _listeners, _local_id) = controller_fixture();
    let router = nodes_router(&controller, "192.0.2.7:40000");
    let requests = controller
        .request_permits
        .clone()
        .try_acquire_many_owned(REQUEST_PERMITS as u32)
        .unwrap();
    let busy = router
        .clone()
        .oneshot(nodes_request("POST", MANAGE, Some("wrong")))
        .await
        .unwrap();
    assert_eq!(busy.status(), StatusCode::SERVICE_UNAVAILABLE);
    // Claims keep their own permits while peers are busy.
    let claim = router
        .clone()
        .oneshot(nodes_request("POST", "/api/nodes/v2/bootstrap/claim", None))
        .await
        .unwrap();
    assert_ne!(claim.status(), StatusCode::SERVICE_UNAVAILABLE);
    drop(requests);

    let _claims = controller
        .claim_permits
        .clone()
        .try_acquire_many_owned(CLAIM_PERMITS as u32)
        .unwrap();
    let busy = router
        .oneshot(nodes_request("POST", "/api/nodes/v2/bootstrap/claim", None))
        .await
        .unwrap();
    assert_eq!(busy.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn a_refused_claim_never_loads_the_configuration() {
    let (directory, controller, _listeners, local_id) = controller_fixture();
    let now = crate::cluster::membership::now().unwrap();
    let (token, token_hash) = generate_token();
    let mut state = ControlState {
        bootstrap: Some(BootstrapAuthorization {
            token_hash,
            endpoint: endpoint(),
            target_node_id: local_id,
            fingerprint: "a".repeat(64),
            certificate_pem: "certificate".into(),
            private_key_pem: SecretString("key".into()),
            expires_at: now + PREVIEW_TTL,
            claimed_by: None,
            operation_id: None,
            issued_credential: None,
        }),
        ..ControlState::default()
    };
    persist(&controller, &state);
    crate::config::atomic_write::hardened_atomic_write(
        &directory.path().join("config.toml"),
        b"schema_version = [",
        crate::config::atomic_write::AtomicWriteOpts::default(),
    )
    .unwrap();
    let claim = |token: String| BootstrapClaimRequest {
        token: SecretString(token),
        operation_id: crate::cluster::membership::random_id(),
        source_node_id: crate::cluster::membership::random_id(),
        source_name: "Office resolver".into(),
        source_endpoint: endpoint(),
        source_fingerprint: "b".repeat(64),
        source_credential: SecretString("source-credential".into()),
    };

    let refused = controller
        .accept_bootstrap(claim("wrong".into()))
        .await
        .unwrap_err();
    assert!(refused.is::<CredentialRefused>(), "{refused:#}");
    let unreadable = controller
        .accept_bootstrap(claim(token.clone()))
        .await
        .unwrap_err();
    assert!(!unreadable.is::<CredentialRefused>(), "{unreadable:#}");
    // The right token after its expiry is a plain refusal: no lockout count.
    state.bootstrap.as_mut().unwrap().expires_at = now - 1;
    persist(&controller, &state);
    let expired = controller.accept_bootstrap(claim(token)).await.unwrap_err();
    assert!(!expired.is::<CredentialRefused>(), "{expired:#}");
    assert!(
        expired.to_string().starts_with("association token expired"),
        "{expired:#}"
    );
}

/// The fixture's configuration with `node_extra` under `[node]` and `tail`
/// appended.
fn rewrite_config(master: &Path, node_id: &str, node_extra: &str, tail: &str) {
    let text = format!(
        "schema_version = 5\n[node]\nid = {node_id:?}\nname = \"Desk\"\n{node_extra}[server]\ndefault_profile = \"default\"\n[profiles.default]\ndisplay_name = \"Default\"\n[upstream]\nservers = [\"192.0.2.1:53\"]\n{tail}"
    );
    crate::config::atomic_write::hardened_atomic_write(
        master,
        text.as_bytes(),
        crate::config::atomic_write::AtomicWriteOpts::default(),
    )
    .unwrap();
}

#[tokio::test]
async fn token_never_guesses_a_loopback_nodes_endpoint() {
    let (directory, controller, _listeners, local_id) = controller_fixture();
    let master = directory.path().join("config.toml");
    let refused = |error: NodeControlError| {
        assert_eq!(
            error.code,
            NodeControlErrorCode::ListenRequired,
            "{error:?}"
        );
    };

    // Defaults: the API is off and listens on loopback.
    refused(
        controller
            .handle(NodeControlCommand::TokenPrepare { listen: None })
            .await
            .unwrap_err(),
    );
    for stored in ["127.0.0.1:19400", "[::ffff:127.0.0.1]:19400"] {
        rewrite_config(
            &master,
            &local_id,
            &format!("control_listen = {stored:?}\n"),
            "",
        );
        refused(
            controller
                .handle(NodeControlCommand::TokenPrepare { listen: None })
                .await
                .unwrap_err(),
        );
    }

    rewrite_config(&master, &local_id, "", "");
    let explicit: SocketAddr = "127.0.0.1:19401".parse().unwrap();
    assert_eq!(
        preferred_endpoint(&master, Some(explicit)).unwrap(),
        explicit
    );
    let tls = [
        directory.path().join("api.crt"),
        directory.path().join("api.key"),
    ];
    for path in &tls {
        std::fs::write(path, "").unwrap();
    }
    rewrite_config(
        &master,
        &local_id,
        "",
        &format!(
            "[api]\nenabled = true\nlisten = \"192.0.2.10:8053\"\ntoken_hash = {:?}\ntls_cert = {:?}\ntls_key = {:?}\n",
            "a".repeat(64),
            tls[0],
            tls[1]
        ),
    );
    assert_eq!(
        preferred_endpoint(&master, None).unwrap(),
        "192.0.2.10:8053".parse().unwrap()
    );
    rewrite_config(
        &master,
        &local_id,
        "",
        "[api]\nenabled = false\nlisten = \"192.0.2.10:8053\"\n",
    );
    assert!(preferred_endpoint(&master, None).is_err());
}

#[test]
fn source_endpoint_refuses_a_stored_loopback_for_a_remote_destination() {
    let (directory, _controller, _listeners, local_id) = controller_fixture();
    let master = directory.path().join("config.toml");
    rewrite_config(
        &master,
        &local_id,
        "control_listen = \"127.0.0.1:19402\"\n",
        "",
    );

    let error = preferred_source_endpoint(&master, "192.0.2.20:8053".parse().unwrap())
        .unwrap_err()
        .to_string();
    assert!(error.starts_with("choose --listen"), "{error}");
    assert_eq!(
        preferred_source_endpoint(&master, "127.0.0.1:8053".parse().unwrap()).unwrap(),
        "127.0.0.1:19402".parse().unwrap()
    );
}

#[tokio::test]
async fn source_listener_refuses_a_saved_loopback_endpoint_for_a_remote_destination() {
    let (_directory, controller, listeners, _local_id) = controller_fixture();
    // What `node token` without --listen saved before it stopped guessing.
    let saved: SocketAddr = "127.0.0.1:8053".parse().unwrap();
    persist(
        &controller,
        &ControlState {
            control_endpoint: Some(saved),
            certificate_pem: Some("certificate".into()),
            private_key_pem: Some(SecretString("key".into())),
            certificate_fingerprint: Some("a".repeat(64)),
            ..ControlState::default()
        },
    );

    let error = controller
        .ensure_source_listener("192.0.2.20:8053".parse().unwrap())
        .await
        .unwrap_err()
        .to_string();
    assert!(error.starts_with("choose --listen"), "{error}");
    assert_eq!(listeners.prepared.load(Ordering::SeqCst), 0);
    let (endpoint, _) = controller
        .ensure_source_listener("127.0.0.1:19403".parse().unwrap())
        .await
        .unwrap();
    assert_eq!(endpoint, saved);
}

const CLAIM: &str = "/api/nodes/v2/bootstrap/claim";

#[tokio::test(start_paused = true)]
async fn stalled_claim_bodies_lock_the_address_out() {
    use tower::ServiceExt;
    let (_directory, controller, _listeners, _local_id) = controller_fixture();
    let router = nodes_router(&controller, "192.0.2.7:40000");
    // The writer stays open and silent, so the body never ends.
    let stalled = || {
        let (writer, reader) = tokio::io::duplex(64);
        let request = axum::http::Request::builder()
            .method("POST")
            .uri(CLAIM)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from_stream(tokio_util::io::ReaderStream::new(reader)))
            .unwrap();
        (writer, request)
    };

    for attempt in 1..=10 {
        let (_writer, request) = stalled();
        let response = router.clone().oneshot(request).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::REQUEST_TIMEOUT,
            "attempt {attempt}"
        );
    }
    let (_writer, request) = stalled();
    let locked = router.oneshot(request).await.unwrap();
    assert_eq!(locked.status(), StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test(start_paused = true)]
async fn a_claim_that_waits_for_the_lock_still_answers() {
    use tower::ServiceExt;
    let (_directory, controller, _listeners, local_id) = controller_fixture();
    let (token, token_hash) = generate_token();
    persist(
        &controller,
        &ControlState {
            bootstrap: Some(BootstrapAuthorization {
                token_hash,
                endpoint: endpoint(),
                target_node_id: local_id,
                fingerprint: "a".repeat(64),
                certificate_pem: "certificate".into(),
                private_key_pem: SecretString("key".into()),
                expires_at: crate::cluster::membership::now().unwrap() + PREVIEW_TTL,
                claimed_by: None,
                operation_id: None,
                issued_credential: None,
            }),
            ..ControlState::default()
        },
    );
    let body = serde_json::to_vec(&BootstrapClaimRequest {
        token: SecretString(token),
        operation_id: crate::cluster::membership::random_id(),
        source_node_id: crate::cluster::membership::random_id(),
        source_name: "Office resolver".into(),
        source_endpoint: endpoint(),
        source_fingerprint: "b".repeat(64),
        source_credential: SecretString("source-credential".into()),
    })
    .unwrap();
    let request = axum::http::Request::builder()
        .method("POST")
        .uri(CLAIM)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .unwrap();
    let held = acquire_for_migration(&controller.master).unwrap();
    let claim = tokio::spawn(nodes_router(&controller, "192.0.2.7:40000").oneshot(request));
    for _ in 0..100 {
        tokio::task::yield_now().await;
    }

    // The claim waits for the lock past any request bound; it must not be
    // cut off while it may still spend the token.
    tokio::time::advance(std::time::Duration::from_secs(60)).await;
    drop(held);

    assert_eq!(claim.await.unwrap().unwrap().status(), StatusCode::OK);
    let state = load_state(&acquire_for_migration(&controller.master).unwrap()).unwrap();
    assert!(state.bootstrap.unwrap().claimed_by.is_some());
}
