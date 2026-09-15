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
}

struct MutableActivePair(std::sync::Mutex<Option<ActivePolicyCorpus>>);

#[async_trait]
impl ActivePairProvider for MutableActivePair {
    fn active_pair(&self) -> Option<ActivePolicyCorpus> {
        self.0.lock().unwrap().clone()
    }

    async fn enrollment_pair(&self) -> anyhow::Result<ActivePolicyCorpus> {
        self.active_pair()
            .context("this fixture has no published pair")
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
        std::time::Duration::from_secs(1),
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
    let result = tokio::time::timeout(std::time::Duration::from_secs(1), second)
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
    assert!(reopened
        .runtime_ready("192.0.2.99:8053".parse().unwrap())
        .await
        .is_err());
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
