use super::*;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

async fn serve_node_controller(
    listener: std::net::TcpListener,
    directory: &tempfile::TempDir,
    certificate: &str,
    private_key: &str,
    controller: Arc<NodeController>,
) -> tokio::task::JoinHandle<()> {
    let certificate_path = directory.path().join("node-test.crt");
    let private_key_path = directory.path().join("node-test.key");
    std::fs::write(&certificate_path, certificate).unwrap();
    std::fs::write(&private_key_path, private_key).unwrap();
    let tls =
        axum_server::tls_rustls::RustlsConfig::from_pem_file(certificate_path, private_key_path)
            .await
            .unwrap();
    listener.set_nonblocking(true).unwrap();
    tokio::spawn(async move {
        let _ = axum_server::from_tcp_rustls(listener, tls)
            .unwrap()
            .serve(node_router(controller).into_make_service())
            .await;
    })
}

async fn serve_delayed_prepare_reply(
    listener: std::net::TcpListener,
    directory: &tempfile::TempDir,
    certificate: &str,
    private_key: &str,
    reply: PeerManagementReply,
) -> tokio::task::JoinHandle<()> {
    let certificate_path = directory.path().join("delayed-node-test.crt");
    let private_key_path = directory.path().join("delayed-node-test.key");
    std::fs::write(&certificate_path, certificate).unwrap();
    std::fs::write(&private_key_path, private_key).unwrap();
    let tls =
        axum_server::tls_rustls::RustlsConfig::from_pem_file(certificate_path, private_key_path)
            .await
            .unwrap();
    listener.set_nonblocking(true).unwrap();
    let router = Router::new().route(
        "/api/nodes/v2/manage",
        post(move || {
            let reply = reply.clone();
            async move {
                tokio::time::sleep(std::time::Duration::from_secs(31)).await;
                (StatusCode::OK, Json(reply))
            }
        }),
    );
    tokio::spawn(async move {
        let _ = axum_server::from_tcp_rustls(listener, tls)
            .unwrap()
            .serve(router.into_make_service())
            .await;
    })
}

struct TestPairProvider;

#[async_trait]
impl ActivePairProvider for TestPairProvider {
    fn active_pair(&self) -> Option<ActivePolicyCorpus> {
        None
    }

    async fn enrollment_pair(&self) -> anyhow::Result<ActivePolicyCorpus> {
        anyhow::bail!("test has no active enrollment pair")
    }
}

struct MaterialListener {
    material: NodeListenerSpec,
    fail_prepare: AtomicBool,
    prepared: Mutex<Vec<NodeListenerSpec>>,
    retired: Mutex<Vec<SocketAddr>>,
}

#[async_trait]
impl NodeListenerControl for MaterialListener {
    async fn existing_material(
        &self,
        endpoint: SocketAddr,
    ) -> anyhow::Result<Option<NodeListenerSpec>> {
        Ok((self.material.endpoint == endpoint).then(|| self.material.clone()))
    }

    async fn prepare(&self, spec: NodeListenerSpec) -> anyhow::Result<()> {
        if self.fail_prepare.load(Ordering::SeqCst) {
            anyhow::bail!("listener preparation fault")
        }
        self.prepared.lock().unwrap().push(spec);
        Ok(())
    }

    async fn retire(&self, endpoint: SocketAddr) -> anyhow::Result<()> {
        self.retired.lock().unwrap().push(endpoint);
        Ok(())
    }
}

fn controller_with_listener(
    directory: &tempfile::TempDir,
    node_id: &str,
    listener: Arc<dyn NodeListenerControl>,
    control_endpoint: Option<SocketAddr>,
) -> Arc<NodeController> {
    let master = directory.path().join("config.toml");
    let control = control_endpoint
        .map(|endpoint| format!("control_listen = \"{endpoint}\"\n"))
        .unwrap_or_default();
    let config = format!(
        "schema_version = 5\n[node]\nid = {node_id:?}\nname = \"Desk\"\n{control}[server]\ndefault_profile = \"default\"\n[profiles.default]\ndisplay_name = \"Default\"\n[upstream]\nservers = [\"192.0.2.1:53\"]\n"
    );
    crate::config::atomic_write::hardened_atomic_write(
        &master,
        config.as_bytes(),
        crate::config::atomic_write::AtomicWriteOpts::default(),
    )
    .unwrap();
    let (restart, _receiver) = crate::cluster::managed_restart::channel(1);
    NodeController::new(master, listener, restart, Arc::new(TestPairProvider))
}

fn identity(byte: char) -> ArtifactIdentity {
    ArtifactIdentity {
        primary_lineage: byte.to_string().repeat(64),
        policy_epoch: 1,
        artifact_hash: byte.to_string().repeat(64),
        config_revision: byte.to_string().repeat(64),
        operator_policy_hash: byte.to_string().repeat(64),
    }
}

fn test_peer(
    node_id: String,
    name: &str,
    endpoint: SocketAddr,
    role: NodeRole,
    outgoing_credential: SecretString,
    incoming_credential: &SecretString,
    fingerprint: String,
) -> PeerRecord {
    PeerRecord {
        view: NodePeer {
            node_id,
            name: name.into(),
            endpoint,
            role,
            state: NodePeerState::Active,
            capabilities: NodeCapabilities::current(),
            last_seen_at: None,
            last_error: None,
        },
        outgoing_credential,
        incoming_credential_hash: hash_token(&incoming_credential.0),
        issued_incoming_credential: None,
        source_fingerprint: fingerprint,
    }
}

fn test_operation(
    operation_id: String,
    source_id: String,
    target_id: String,
    target_endpoint: SocketAddr,
    kind: NodeOperationKind,
    phase: NodeOperationPhase,
) -> OperationRecord {
    OperationRecord {
        preview: NodePreview {
            id: operation_id.clone(),
            kind,
            source_node_id: source_id,
            source_name: "Primary".into(),
            source_endpoint: Some("127.0.0.1:19001".parse().unwrap()),
            target_node_id: target_id,
            target_name: "Office resolver".into(),
            target_endpoint,
            target_role: NodeRole::Secondary,
            replacement_summary: Vec::new(),
            restart_steps: vec![NodeRestartStep {
                step_id: "secondary".into(),
                target: NodeRestartTarget::Secondary,
                requested: true,
                acknowledged: true,
            }],
            before_revision: "revision".into(),
            expires_at: u64::MAX,
        },
        phase,
        paused_from: None,
        message: "test recovery boundary".into(),
        last_verified_at: None,
        recover_until: Some(u64::MAX),
        peer_preview_id: Some(operation_id),
        local_preview_id: None,
        staged_pair: Some(ActivePolicyCorpus {
            policy: identity('a'),
            corpus_generation: "b".repeat(64),
        }),
        prepared_certificate: None,
        prepared_private_key: None,
        prepared_fingerprint: None,
        cluster_id: None,
        replication_credential: None,
        backup_verified: true,
        cancel_requested: false,
        restart_requested_at: BTreeMap::new(),
    }
}

#[tokio::test]
async fn prepare_add_uses_the_staging_transport_budget_without_extending_other_verbs() {
    let directory = tempfile::tempdir().unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = listener.local_addr().unwrap();
    let certificate = crate::cluster::certgen::generate_self_signed(
        &[crate::cluster::certgen::San::Ip(endpoint.ip())],
        30,
        time::OffsetDateTime::now_utc(),
    )
    .unwrap();
    let reply = PeerManagementReply {
        node_id: crate::cluster::membership::random_id(),
        status: LifecycleStatus::default(),
        preview_id: Some(crate::cluster::membership::random_id()),
        operation: None,
        capabilities: NodeCapabilities::current(),
        backup_verified: true,
        control_endpoint: Some(endpoint),
        control_fingerprint: Some(certificate.fingerprint_sha256.clone()),
        transition_acknowledged: false,
        message: "verified staging reply".into(),
    };
    let server = serve_delayed_prepare_reply(
        listener,
        &directory,
        &certificate.cert_pem,
        &certificate.key_pem,
        reply.clone(),
    )
    .await;
    let source_id = crate::cluster::membership::random_id();
    let target_id = crate::cluster::membership::random_id();
    let credential = SecretString(crate::auth::token::generate_token().0);
    let peer = test_peer(
        target_id,
        "Delayed target",
        endpoint,
        NodeRole::Secondary,
        credential.clone(),
        &credential,
        certificate.fingerprint_sha256.clone(),
    );
    let request = PeerManagementRequest::PrepareAdd {
        operation_id: crate::cluster::membership::random_id(),
        name: "Delayed target".into(),
        cluster_id: crate::cluster::membership::random_id(),
        primary_node_id: source_id,
        primary_endpoint: "127.0.0.1:19001".parse().unwrap(),
        primary_fingerprint: "a".repeat(64),
        staged_pair: Box::new(ActivePolicyCorpus {
            policy: identity('a'),
            corpus_generation: "b".repeat(64),
        }),
        replication_credential: SecretString(crate::auth::token::generate_token().0),
    };
    let (short_budget, staging_budget) =
        tokio::time::timeout(std::time::Duration::from_secs(40), async {
            tokio::join!(
                post_pinned::<_, PeerManagementReply>(
                    endpoint,
                    &certificate.fingerprint_sha256,
                    "/api/nodes/v2/manage",
                    Some(&credential.0),
                    &request,
                ),
                send_management(&peer, &request),
            )
        })
        .await
        .expect("both bounded HTTPS attempts must finish within 40 seconds");
    assert!(
        short_budget.is_err(),
        "the ordinary 30-second request must time out"
    );
    assert_eq!(staging_budget.unwrap().message, reply.message);
    server.abort();
}

#[test]
fn management_grant_requires_membership_still_active_under_guard() {
    let directory = tempfile::tempdir().unwrap();
    let master = directory.path().join("config.toml");
    let guard = acquire_for_migration(&master).unwrap();
    let cluster_id = crate::cluster::membership::random_id();
    let primary_id = crate::cluster::membership::random_id();
    let secondary_id = crate::cluster::membership::random_id();
    let operation_id = crate::cluster::membership::random_id();
    let credential = SecretString(crate::auth::token::generate_token().0);
    let now = crate::cluster::membership::now().unwrap();
    let mut membership = super::super::membership::MembershipStore::initialize(
        &guard,
        &cluster_id,
        &primary_id,
        &"a".repeat(64),
    )
    .unwrap();
    membership
        .admit_prepared(
            &operation_id,
            &secondary_id,
            "Secondary",
            "192.0.2.20:8053".parse().unwrap(),
            &credential,
            now,
        )
        .unwrap();
    let principal = membership.authenticate(&credential.0, now).unwrap();
    membership.activate(&principal, now).unwrap();
    drop(membership);
    assert!(require_active_management_member(&guard, &secondary_id, "Secondary").is_ok());

    {
        let mut membership = super::super::membership::MembershipStore::open(&guard).unwrap();
        membership.revoke(&secondary_id).unwrap();
    }
    assert!(require_active_management_member(&guard, &secondary_id, "Secondary").is_err());
}

#[test]
fn staged_artifact_authorization_is_bound_to_exact_reviewed_pair() {
    let directory = tempfile::tempdir().unwrap();
    let master = directory.path().join("config.toml");
    let guard = acquire_for_migration(&master).unwrap();
    let reviewed = ActivePolicyCorpus {
        policy: identity('a'),
        corpus_generation: "c".repeat(64),
    };

    assert!(authorize_reviewed_resource(
        &guard,
        &master,
        &reviewed,
        StagingResource::Artifact("a".repeat(64)),
    )
    .is_ok());
    assert!(authorize_reviewed_resource(
        &guard,
        &master,
        &reviewed,
        StagingResource::Artifact("b".repeat(64)),
    )
    .is_err());
    assert!(authorize_reviewed_resource(
        &guard,
        &master,
        &reviewed,
        StagingResource::Corpus("b".repeat(64)),
    )
    .is_err());
}

#[test]
fn pending_management_scope_accepts_only_enrollment_verbs() {
    let operation_id = crate::cluster::membership::random_id();
    assert!(pending_enrollment_verb(&PeerManagementRequest::Resume {
        operation_id: operation_id.clone(),
    }));
    assert!(pending_enrollment_verb(
        &PeerManagementRequest::ArmAddRecovery {
            operation_id: operation_id.clone(),
            preview_id: operation_id.clone(),
        }
    ));
    assert!(!pending_enrollment_verb(&PeerManagementRequest::Status));
    assert!(!pending_enrollment_verb(
        &PeerManagementRequest::AdoptPrimaryEndpoint {
            operation_id,
            endpoint: "192.0.2.30:8053".parse().unwrap(),
            fingerprint: "d".repeat(64),
        }
    ));
}

#[test]
fn completed_target_detach_outbox_survives_store_reopen_until_source_receipt() {
    let directory = tempfile::tempdir().unwrap();
    let master = directory.path().join("config.toml");
    let local_id = crate::cluster::membership::random_id();
    let source_id = crate::cluster::membership::random_id();
    let operation_id = crate::cluster::membership::random_id();
    let operation = OperationRecord {
        preview: NodePreview {
            id: operation_id.clone(),
            kind: NodeOperationKind::Remove,
            source_node_id: source_id,
            source_name: "Primary".into(),
            source_endpoint: Some("192.0.2.10:8053".parse().unwrap()),
            target_node_id: local_id.clone(),
            target_name: "Secondary".into(),
            target_endpoint: "192.0.2.20:8053".parse().unwrap(),
            target_role: NodeRole::Secondary,
            replacement_summary: Vec::new(),
            restart_steps: Vec::new(),
            before_revision: "a".repeat(64),
            expires_at: u64::MAX,
        },
        phase: NodeOperationPhase::Complete,
        paused_from: None,
        message: "standalone complete".into(),
        last_verified_at: Some(100),
        recover_until: None,
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
    };
    let guard = acquire_for_migration(&master).unwrap();
    let mut state = ControlState::default();
    state.operations.insert(operation_id.clone(), operation);
    save_state(&guard, &state).unwrap();
    drop(guard);

    let guard = acquire_for_migration(&master).unwrap();
    let mut reopened = load_state(&guard).unwrap();
    let after_normal_retention = 100 + OPERATION_RETENTION + 1;
    expire_state(&mut reopened, after_normal_retention);
    assert_eq!(
        detach_outbox_ids(&reopened, &local_id, after_normal_retention).as_slice(),
        std::slice::from_ref(&operation_id)
    );
    reopened
        .detach_receipts
        .insert(operation_id.clone(), after_normal_retention);
    expire_state(
        &mut reopened,
        after_normal_retention + DETACH_RECEIPT_TTL + 1,
    );
    assert!(reopened.operations.contains_key(&operation_id));
    save_state(&guard, &reopened).unwrap();
    drop(guard);

    let guard = acquire_for_migration(&master).unwrap();
    let mut reopened = load_state(&guard).unwrap();
    assert!(detach_outbox_ids(
        &reopened,
        &local_id,
        after_normal_retention + DETACH_RECEIPT_TTL + 1
    )
    .is_empty());
    expire_state(
        &mut reopened,
        after_normal_retention + OPERATION_RETENTION + 1,
    );
    assert!(!reopened.operations.contains_key(&operation_id));
}

#[tokio::test]
async fn source_listener_reuses_transport_tls_and_does_not_persist_prepare_failure() {
    let endpoint: SocketAddr = "127.0.0.1:18443".parse().unwrap();
    let certificate = crate::cluster::certgen::generate_self_signed(
        &[crate::cluster::certgen::San::Ip(endpoint.ip())],
        30,
        time::OffsetDateTime::now_utc(),
    )
    .unwrap();
    let material = NodeListenerSpec {
        endpoint,
        certificate_pem: certificate.cert_pem,
        private_key_pem: SecretString(certificate.key_pem),
        scope: ListenerScope::Management,
    };
    let expected = listener_material_from_spec(material.clone()).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let listener = Arc::new(MaterialListener {
        material: material.clone(),
        fail_prepare: AtomicBool::new(false),
        prepared: Mutex::new(Vec::new()),
        retired: Mutex::new(Vec::new()),
    });
    let controller = controller_with_listener(
        &directory,
        &crate::cluster::membership::random_id(),
        listener.clone(),
        Some(endpoint),
    );
    let selected = controller
        .ensure_source_listener("192.0.2.30:8053".parse().unwrap())
        .await
        .unwrap();
    assert_eq!(selected, (endpoint, expected.fingerprint.clone()));
    {
        let prepared = listener.prepared.lock().unwrap();
        assert_eq!(prepared.len(), 1);
        assert_eq!(prepared[0].endpoint, material.endpoint);
        assert_eq!(prepared[0].certificate_pem, material.certificate_pem);
        assert_eq!(prepared[0].private_key_pem, material.private_key_pem);
        assert_eq!(prepared[0].scope, material.scope);
    }
    let guard = acquire_for_migration(&controller.master).unwrap();
    let state = load_state(&guard).unwrap();
    assert_eq!(
        state.certificate_pem.as_deref(),
        Some(material.certificate_pem.as_str())
    );
    assert_eq!(
        state.certificate_fingerprint.as_deref(),
        Some(expected.fingerprint.as_str())
    );
    drop(guard);

    let failed_directory = tempfile::tempdir().unwrap();
    let failed_listener = Arc::new(MaterialListener {
        material,
        fail_prepare: AtomicBool::new(true),
        prepared: Mutex::new(Vec::new()),
        retired: Mutex::new(Vec::new()),
    });
    let failed = controller_with_listener(
        &failed_directory,
        &crate::cluster::membership::random_id(),
        failed_listener,
        Some(endpoint),
    );
    assert!(failed
        .ensure_source_listener("192.0.2.30:8053".parse().unwrap())
        .await
        .is_err());
    let guard = acquire_for_migration(&failed.master).unwrap();
    let state = load_state(&guard).unwrap();
    assert!(state.control_endpoint.is_none());
    assert!(state.certificate_pem.is_none());
    assert!(state.certificate_fingerprint.is_none());
}

#[tokio::test]
async fn failed_endpoint_ack_keeps_the_new_source_mapping_for_recovery() {
    let directory = tempfile::tempdir().unwrap();
    let local_id = crate::cluster::membership::random_id();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let new_endpoint = listener.local_addr().unwrap();
    let listener_task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        drop(stream);
    });
    let material = crate::cluster::certgen::generate_self_signed(
        &[crate::cluster::certgen::San::Ip(new_endpoint.ip())],
        30,
        time::OffsetDateTime::now_utc(),
    )
    .unwrap();
    let listeners = Arc::new(MaterialListener {
        material: NodeListenerSpec {
            endpoint: new_endpoint,
            certificate_pem: material.cert_pem,
            private_key_pem: SecretString(material.key_pem),
            scope: ListenerScope::Management,
        },
        fail_prepare: AtomicBool::new(false),
        prepared: Mutex::new(Vec::new()),
        retired: Mutex::new(Vec::new()),
    });
    let controller = controller_with_listener(&directory, &local_id, listeners, None);
    let target_id = crate::cluster::membership::random_id();
    let operation_id = crate::cluster::membership::random_id();
    let new_fingerprint = "b".repeat(64);
    let peer = PeerRecord {
        view: NodePeer {
            node_id: target_id.clone(),
            name: "Secondary".into(),
            endpoint: "127.0.0.1:18444".parse().unwrap(),
            role: NodeRole::Secondary,
            state: NodePeerState::Active,
            capabilities: NodeCapabilities::current(),
            last_seen_at: None,
            last_error: None,
        },
        outgoing_credential: SecretString(crate::auth::token::generate_token().0),
        incoming_credential_hash: "c".repeat(64),
        issued_incoming_credential: None,
        source_fingerprint: "d".repeat(64),
    };
    let operation = OperationRecord {
        preview: NodePreview {
            id: operation_id.clone(),
            kind: NodeOperationKind::Edit,
            source_node_id: local_id,
            source_name: "Primary".into(),
            source_endpoint: None,
            target_node_id: target_id.clone(),
            target_name: "Secondary".into(),
            target_endpoint: new_endpoint,
            target_role: NodeRole::Secondary,
            replacement_summary: Vec::new(),
            restart_steps: Vec::new(),
            before_revision: "revision".into(),
            expires_at: u64::MAX,
        },
        phase: NodeOperationPhase::RestartingTarget,
        paused_from: None,
        message: "awaiting endpoint proof".into(),
        last_verified_at: None,
        recover_until: Some(u64::MAX),
        peer_preview_id: Some(crate::cluster::membership::random_id()),
        local_preview_id: None,
        staged_pair: None,
        prepared_certificate: None,
        prepared_private_key: None,
        prepared_fingerprint: Some(new_fingerprint.clone()),
        cluster_id: None,
        replication_credential: None,
        backup_verified: false,
        cancel_requested: false,
        restart_requested_at: BTreeMap::new(),
    };
    let mut state = ControlState::default();
    state.peers.insert(target_id.clone(), peer);
    let mut stored_operation = operation.clone();
    stored_operation.prepared_fingerprint = None;
    state
        .operations
        .insert(operation_id.clone(), stored_operation);
    let guard = acquire_for_migration(&controller.master).unwrap();
    save_state(&guard, &state).unwrap();
    drop(guard);

    assert!(controller
        .complete_peer_endpoint_transition(operation)
        .await
        .is_err());
    listener_task.await.unwrap();
    drop(controller);

    let master = directory.path().join("config.toml");
    let guard = acquire_for_migration(&master).unwrap();
    let reopened = load_state(&guard).unwrap();
    assert_eq!(reopened.peers[&target_id].view.endpoint, new_endpoint);
    assert_eq!(
        reopened.peers[&target_id].source_fingerprint,
        new_fingerprint
    );
    assert_eq!(
        reopened.operations[&operation_id].phase,
        NodeOperationPhase::RestartingTarget
    );
    assert_eq!(
        reopened.operations[&operation_id]
            .prepared_fingerprint
            .as_deref(),
        Some(new_fingerprint.as_str())
    );
}

#[tokio::test]
async fn expired_prepared_edit_retires_its_unpromoted_listener() {
    let directory = tempfile::tempdir().unwrap();
    let local_id = crate::cluster::membership::random_id();
    let endpoint: SocketAddr = "127.0.0.1:18445".parse().unwrap();
    let certificate = crate::cluster::certgen::generate_self_signed(
        &[crate::cluster::certgen::San::Ip(endpoint.ip())],
        30,
        time::OffsetDateTime::now_utc(),
    )
    .unwrap();
    let listeners = Arc::new(MaterialListener {
        material: NodeListenerSpec {
            endpoint,
            certificate_pem: certificate.cert_pem.clone(),
            private_key_pem: SecretString(certificate.key_pem.clone()),
            scope: ListenerScope::Management,
        },
        fail_prepare: AtomicBool::new(false),
        prepared: Mutex::new(Vec::new()),
        retired: Mutex::new(Vec::new()),
    });
    let controller = controller_with_listener(&directory, &local_id, listeners.clone(), None);
    let now = crate::cluster::membership::now().unwrap();
    let operation_id = crate::cluster::membership::random_id();
    let operation = OperationRecord {
        preview: NodePreview {
            id: operation_id.clone(),
            kind: NodeOperationKind::Edit,
            source_node_id: crate::cluster::membership::random_id(),
            source_name: "Primary".into(),
            source_endpoint: Some("127.0.0.1:18444".parse().unwrap()),
            target_node_id: local_id,
            target_name: "Secondary".into(),
            target_endpoint: endpoint,
            target_role: NodeRole::Secondary,
            replacement_summary: Vec::new(),
            restart_steps: Vec::new(),
            before_revision: "revision".into(),
            expires_at: now - 1,
        },
        phase: NodeOperationPhase::Prepared,
        paused_from: None,
        message: "prepared".into(),
        last_verified_at: Some(now - 1),
        recover_until: Some(now + RECOVERY_TTL),
        peer_preview_id: Some(crate::cluster::membership::random_id()),
        local_preview_id: None,
        staged_pair: None,
        prepared_certificate: Some(certificate.cert_pem),
        prepared_private_key: Some(SecretString(certificate.key_pem)),
        prepared_fingerprint: Some(certificate.fingerprint_sha256),
        cluster_id: None,
        replication_credential: None,
        backup_verified: false,
        cancel_requested: false,
        restart_requested_at: BTreeMap::new(),
    };
    let mut state = ControlState::default();
    state.operations.insert(operation_id.clone(), operation);
    let guard = acquire_for_migration(&controller.master).unwrap();
    save_state(&guard, &state).unwrap();
    drop(guard);

    assert_eq!(controller.runtime_tick().await.unwrap(), 1);
    assert_eq!(listeners.retired.lock().unwrap().as_slice(), &[endpoint]);
    let guard = acquire_for_migration(&controller.master).unwrap();
    let state = load_state(&guard).unwrap();
    let operation = &state.operations[&operation_id];
    assert_eq!(operation.phase, NodeOperationPhase::Paused);
    assert!(operation.prepared_certificate.is_none());
    assert!(operation.prepared_private_key.is_none());
    assert!(operation.prepared_fingerprint.is_none());
}

#[tokio::test]
async fn lost_target_apply_reply_reconciles_from_persisted_complete_state() {
    let source_directory = tempfile::tempdir().unwrap();
    let target_directory = tempfile::tempdir().unwrap();
    let source_id = crate::cluster::membership::random_id();
    let target_id = crate::cluster::membership::random_id();
    let operation_id = crate::cluster::membership::random_id();
    let socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let target_endpoint = socket.local_addr().unwrap();
    let certificate = crate::cluster::certgen::generate_self_signed(
        &[crate::cluster::certgen::San::Ip(target_endpoint.ip())],
        30,
        time::OffsetDateTime::now_utc(),
    )
    .unwrap();
    let target_material = NodeListenerSpec {
        endpoint: target_endpoint,
        certificate_pem: certificate.cert_pem.clone(),
        private_key_pem: SecretString(certificate.key_pem.clone()),
        scope: ListenerScope::Management,
    };
    let target_fingerprint = certificate.fingerprint_sha256.clone();
    let source_to_target = SecretString(crate::auth::token::generate_token().0);
    let target_to_source = SecretString(crate::auth::token::generate_token().0);
    let target_listeners = Arc::new(MaterialListener {
        material: target_material.clone(),
        fail_prepare: AtomicBool::new(false),
        prepared: Mutex::new(Vec::new()),
        retired: Mutex::new(Vec::new()),
    });
    let target = controller_with_listener(
        &target_directory,
        &target_id,
        target_listeners,
        Some(target_endpoint),
    );
    let target_operation = test_operation(
        operation_id.clone(),
        source_id.clone(),
        target_id.clone(),
        target_endpoint,
        NodeOperationKind::Add,
        NodeOperationPhase::Complete,
    );
    let mut target_state = ControlState {
        control_endpoint: Some(target_endpoint),
        certificate_pem: Some(certificate.cert_pem.clone()),
        private_key_pem: Some(SecretString(certificate.key_pem.clone())),
        certificate_fingerprint: Some(target_fingerprint.clone()),
        ..ControlState::default()
    };
    target_state.peers.insert(
        source_id.clone(),
        test_peer(
            source_id.clone(),
            "Primary",
            "127.0.0.1:19001".parse().unwrap(),
            NodeRole::Primary,
            target_to_source.clone(),
            &source_to_target,
            "c".repeat(64),
        ),
    );
    target_state
        .operations
        .insert(operation_id.clone(), target_operation);
    let guard = acquire_for_migration(&target.master).unwrap();
    save_state(&guard, &target_state).unwrap();
    drop(guard);
    let server = serve_node_controller(
        socket,
        &target_directory,
        &certificate.cert_pem,
        &certificate.key_pem,
        target,
    )
    .await;

    let source_material = crate::cluster::certgen::generate_self_signed(
        &[crate::cluster::certgen::San::Ip(
            "127.0.0.1".parse().unwrap(),
        )],
        30,
        time::OffsetDateTime::now_utc(),
    )
    .unwrap();
    let source_listeners = Arc::new(MaterialListener {
        material: NodeListenerSpec {
            endpoint: "127.0.0.1:19001".parse().unwrap(),
            certificate_pem: source_material.cert_pem,
            private_key_pem: SecretString(source_material.key_pem),
            scope: ListenerScope::Management,
        },
        fail_prepare: AtomicBool::new(false),
        prepared: Mutex::new(Vec::new()),
        retired: Mutex::new(Vec::new()),
    });
    let source = controller_with_listener(
        &source_directory,
        &source_id,
        source_listeners.clone(),
        Some("127.0.0.1:19001".parse().unwrap()),
    );
    let source_operation = test_operation(
        operation_id.clone(),
        source_id.clone(),
        target_id.clone(),
        target_endpoint,
        NodeOperationKind::Add,
        NodeOperationPhase::ApplyingTarget,
    );
    let mut source_peer = test_peer(
        target_id.clone(),
        "Office resolver",
        target_endpoint,
        NodeRole::Standalone,
        source_to_target,
        &target_to_source,
        target_fingerprint,
    );
    source_peer.view.state = NodePeerState::Pending;
    let mut source_state = ControlState::default();
    source_state.peers.insert(target_id.clone(), source_peer);
    source_state
        .operations
        .insert(operation_id.clone(), source_operation);
    let guard = acquire_for_migration(&source.master).unwrap();
    save_state(&guard, &source_state).unwrap();
    drop(guard);
    drop(source);

    let reopened = controller_with_listener(
        &source_directory,
        &source_id,
        source_listeners,
        Some("127.0.0.1:19001".parse().unwrap()),
    );
    assert_eq!(reopened.runtime_tick().await.unwrap(), 1);
    let guard = acquire_for_migration(&reopened.master).unwrap();
    let recovered = load_state(&guard).unwrap();
    assert_eq!(
        recovered.operations[&operation_id].phase,
        NodeOperationPhase::Complete
    );
    assert_eq!(
        recovered.peers[&target_id].view.state,
        NodePeerState::Active
    );
    server.abort();
}

#[tokio::test]
async fn lost_endpoint_ack_reply_replays_without_retiring_the_old_listener_twice() {
    let source_directory = tempfile::tempdir().unwrap();
    let target_directory = tempfile::tempdir().unwrap();
    let source_id = crate::cluster::membership::random_id();
    let target_id = crate::cluster::membership::random_id();
    let operation_id = crate::cluster::membership::random_id();
    let socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let new_endpoint = socket.local_addr().unwrap();
    let old_endpoint: SocketAddr = "127.0.0.1:19002".parse().unwrap();
    let certificate = crate::cluster::certgen::generate_self_signed(
        &[crate::cluster::certgen::San::Ip(new_endpoint.ip())],
        30,
        time::OffsetDateTime::now_utc(),
    )
    .unwrap();
    let target_fingerprint = certificate.fingerprint_sha256.clone();
    let source_to_target = SecretString(crate::auth::token::generate_token().0);
    let target_to_source = SecretString(crate::auth::token::generate_token().0);
    let target_listeners = Arc::new(MaterialListener {
        material: NodeListenerSpec {
            endpoint: new_endpoint,
            certificate_pem: certificate.cert_pem.clone(),
            private_key_pem: SecretString(certificate.key_pem.clone()),
            scope: ListenerScope::Management,
        },
        fail_prepare: AtomicBool::new(false),
        prepared: Mutex::new(Vec::new()),
        retired: Mutex::new(Vec::new()),
    });
    let target = controller_with_listener(
        &target_directory,
        &target_id,
        target_listeners.clone(),
        Some(new_endpoint),
    );
    let target_source_peer = test_peer(
        source_id.clone(),
        "Primary",
        "127.0.0.1:19001".parse().unwrap(),
        NodeRole::Primary,
        target_to_source.clone(),
        &source_to_target,
        "c".repeat(64),
    );
    let target_operation = test_operation(
        operation_id.clone(),
        source_id.clone(),
        target_id.clone(),
        new_endpoint,
        NodeOperationKind::Edit,
        NodeOperationPhase::Complete,
    );
    let mut target_state = ControlState {
        control_endpoint: Some(new_endpoint),
        certificate_pem: Some(certificate.cert_pem.clone()),
        private_key_pem: Some(SecretString(certificate.key_pem.clone())),
        certificate_fingerprint: Some(target_fingerprint.clone()),
        previous_listener: Some(ListenerMaterial {
            endpoint: old_endpoint,
            certificate_pem: "old certificate".into(),
            private_key_pem: SecretString("old private key".into()),
            fingerprint: "d".repeat(64),
        }),
        ..ControlState::default()
    };
    target_state
        .peers
        .insert(source_id.clone(), target_source_peer.clone());
    target_state
        .operations
        .insert(operation_id.clone(), target_operation);
    let guard = acquire_for_migration(&target.master).unwrap();
    save_state(&guard, &target_state).unwrap();
    drop(guard);

    let _lost_reply = target
        .accept_endpoint_ack(&target_source_peer, operation_id.clone())
        .await
        .unwrap();
    assert_eq!(
        target_listeners.retired.lock().unwrap().as_slice(),
        &[old_endpoint]
    );
    let guard = acquire_for_migration(&target.master).unwrap();
    assert!(load_state(&guard).unwrap().previous_listener.is_none());
    drop(guard);
    let server = serve_node_controller(
        socket,
        &target_directory,
        &certificate.cert_pem,
        &certificate.key_pem,
        target.clone(),
    )
    .await;

    let source_listeners = Arc::new(MaterialListener {
        material: NodeListenerSpec {
            endpoint: "127.0.0.1:19001".parse().unwrap(),
            certificate_pem: certificate.cert_pem.clone(),
            private_key_pem: SecretString(certificate.key_pem.clone()),
            scope: ListenerScope::Management,
        },
        fail_prepare: AtomicBool::new(false),
        prepared: Mutex::new(Vec::new()),
        retired: Mutex::new(Vec::new()),
    });
    let source = controller_with_listener(
        &source_directory,
        &source_id,
        source_listeners.clone(),
        Some("127.0.0.1:19001".parse().unwrap()),
    );
    let membership_credential = SecretString(crate::auth::token::generate_token().0);
    {
        let guard = acquire_for_migration(&source.master).unwrap();
        let mut membership = super::super::membership::MembershipStore::initialize(
            &guard,
            &crate::cluster::membership::random_id(),
            &source_id,
            &"e".repeat(64),
        )
        .unwrap();
        membership
            .admit_prepared(
                &crate::cluster::membership::random_id(),
                &target_id,
                "Old name",
                new_endpoint,
                &membership_credential,
                crate::cluster::membership::now().unwrap(),
            )
            .unwrap();
        let principal = membership
            .authenticate(
                &membership_credential.0,
                crate::cluster::membership::now().unwrap(),
            )
            .unwrap();
        membership
            .activate(&principal, crate::cluster::membership::now().unwrap())
            .unwrap();
    }
    let mut source_operation = test_operation(
        operation_id.clone(),
        source_id.clone(),
        target_id.clone(),
        new_endpoint,
        NodeOperationKind::Edit,
        NodeOperationPhase::RestartingTarget,
    );
    source_operation.prepared_fingerprint = Some(target_fingerprint.clone());
    let source_peer = test_peer(
        target_id.clone(),
        "Old name",
        old_endpoint,
        NodeRole::Secondary,
        source_to_target,
        &target_to_source,
        "f".repeat(64),
    );
    let mut source_state = ControlState::default();
    source_state.peers.insert(target_id.clone(), source_peer);
    source_state
        .operations
        .insert(operation_id.clone(), source_operation.clone());
    let guard = acquire_for_migration(&source.master).unwrap();
    save_state(&guard, &source_state).unwrap();
    drop(guard);
    drop(source);

    let reopened = controller_with_listener(
        &source_directory,
        &source_id,
        source_listeners,
        Some("127.0.0.1:19001".parse().unwrap()),
    );
    reopened
        .complete_peer_endpoint_transition(source_operation)
        .await
        .unwrap();
    let guard = acquire_for_migration(&reopened.master).unwrap();
    let recovered = load_state(&guard).unwrap();
    assert_eq!(
        recovered.operations[&operation_id].phase,
        NodeOperationPhase::Complete
    );
    assert_eq!(recovered.peers[&target_id].view.endpoint, new_endpoint);
    assert_eq!(recovered.peers[&target_id].view.name, "Office resolver");
    assert_eq!(
        target_listeners.retired.lock().unwrap().as_slice(),
        &[old_endpoint]
    );
    server.abort();
}

#[tokio::test]
async fn offline_remove_prepares_same_operation_on_return_and_completes_idempotently() {
    let source_directory = tempfile::tempdir().unwrap();
    let target_directory = tempfile::tempdir().unwrap();
    let source_id = crate::cluster::membership::random_id();
    let target_id = crate::cluster::membership::random_id();
    let operation_id = crate::cluster::membership::random_id();
    let socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let target_endpoint = socket.local_addr().unwrap();
    let certificate = crate::cluster::certgen::generate_self_signed(
        &[crate::cluster::certgen::San::Ip(target_endpoint.ip())],
        30,
        time::OffsetDateTime::now_utc(),
    )
    .unwrap();
    let target_fingerprint = certificate.fingerprint_sha256.clone();
    let source_to_target = SecretString(crate::auth::token::generate_token().0);
    let target_to_source = SecretString(crate::auth::token::generate_token().0);

    let target_listeners = Arc::new(MaterialListener {
        material: NodeListenerSpec {
            endpoint: target_endpoint,
            certificate_pem: certificate.cert_pem.clone(),
            private_key_pem: SecretString(certificate.key_pem.clone()),
            scope: ListenerScope::Management,
        },
        fail_prepare: AtomicBool::new(false),
        prepared: Mutex::new(Vec::new()),
        retired: Mutex::new(Vec::new()),
    });
    let target = controller_with_listener(
        &target_directory,
        &target_id,
        target_listeners,
        Some(target_endpoint),
    );
    let mut target_source_peer = test_peer(
        source_id.clone(),
        "Primary",
        "127.0.0.1:19001".parse().unwrap(),
        NodeRole::Primary,
        target_to_source.clone(),
        &source_to_target,
        "c".repeat(64),
    );
    target_source_peer.view.state = NodePeerState::PendingDetach;
    let target_operation = test_operation(
        operation_id.clone(),
        source_id.clone(),
        target_id.clone(),
        target_endpoint,
        NodeOperationKind::Remove,
        NodeOperationPhase::Complete,
    );
    let mut target_state = ControlState {
        control_endpoint: Some(target_endpoint),
        certificate_pem: Some(certificate.cert_pem.clone()),
        private_key_pem: Some(SecretString(certificate.key_pem.clone())),
        certificate_fingerprint: Some(target_fingerprint.clone()),
        ..ControlState::default()
    };
    target_state
        .peers
        .insert(source_id.clone(), target_source_peer);
    target_state
        .operations
        .insert(operation_id.clone(), target_operation);
    let guard = acquire_for_migration(&target.master).unwrap();
    save_state(&guard, &target_state).unwrap();
    drop(guard);
    let server = serve_node_controller(
        socket,
        &target_directory,
        &certificate.cert_pem,
        &certificate.key_pem,
        target.clone(),
    )
    .await;

    let source_listeners = Arc::new(MaterialListener {
        material: NodeListenerSpec {
            endpoint: "127.0.0.1:19001".parse().unwrap(),
            certificate_pem: certificate.cert_pem.clone(),
            private_key_pem: SecretString(certificate.key_pem.clone()),
            scope: ListenerScope::Management,
        },
        fail_prepare: AtomicBool::new(false),
        prepared: Mutex::new(Vec::new()),
        retired: Mutex::new(Vec::new()),
    });
    let source = controller_with_listener(
        &source_directory,
        &source_id,
        source_listeners,
        Some("127.0.0.1:19001".parse().unwrap()),
    );
    let create = super::super::lifecycle::preview(
        &source.master,
        super::super::lifecycle::LifecycleRequest::Create {
            san: vec!["127.0.0.1".into()],
            api_listen: Some("127.0.0.1:19001".parse().unwrap()),
            migrate_legacy: false,
        },
    )
    .await
    .unwrap();
    super::super::lifecycle::apply(&source.master, &create.id)
        .await
        .unwrap();
    let membership_credential = SecretString(crate::auth::token::generate_token().0);
    {
        let guard = acquire_for_migration(&source.master).unwrap();
        let mut membership = super::super::membership::MembershipStore::open(&guard).unwrap();
        membership
            .admit_prepared(
                &crate::cluster::membership::random_id(),
                &target_id,
                "Secondary",
                target_endpoint,
                &membership_credential,
                crate::cluster::membership::now().unwrap(),
            )
            .unwrap();
        let principal = membership
            .authenticate(
                &membership_credential.0,
                crate::cluster::membership::now().unwrap(),
            )
            .unwrap();
        membership
            .activate(&principal, crate::cluster::membership::now().unwrap())
            .unwrap();
    }
    let mut source_operation = test_operation(
        operation_id.clone(),
        source_id.clone(),
        target_id.clone(),
        target_endpoint,
        NodeOperationKind::Remove,
        NodeOperationPhase::AwaitingDetach,
    );
    source_operation.peer_preview_id = None;
    let source_peer = test_peer(
        target_id.clone(),
        "Secondary",
        target_endpoint,
        NodeRole::Secondary,
        source_to_target,
        &target_to_source,
        target_fingerprint,
    );
    let mut source_state = ControlState::default();
    source_state.peers.insert(target_id.clone(), source_peer);
    source_state
        .operations
        .insert(operation_id.clone(), source_operation);
    let guard = acquire_for_migration(&source.master).unwrap();
    save_state(&guard, &source_state).unwrap();
    drop(guard);

    assert_eq!(source.runtime_tick().await.unwrap(), 1);
    let guard = acquire_for_migration(&source.master).unwrap();
    let recovered = load_state(&guard).unwrap();
    assert_eq!(
        recovered.operations[&operation_id].phase,
        NodeOperationPhase::Complete
    );
    assert!(recovered.operations[&operation_id]
        .peer_preview_id
        .is_some());
    assert_eq!(
        recovered.peers[&target_id].view.state,
        NodePeerState::Detached
    );
    drop(guard);
    let guard = acquire_for_migration(&target.master).unwrap();
    let recovered_target = load_state(&guard).unwrap();
    assert_eq!(
        recovered_target.peers[&source_id].view.state,
        NodePeerState::Detached
    );
    assert!(recovered_target.detach_receipts.contains_key(&operation_id));
    server.abort();
}

#[tokio::test]
async fn acknowledged_detach_can_reassociate_same_stable_target_with_fresh_credentials() {
    let directory = tempfile::tempdir().unwrap();
    let local_id = crate::cluster::membership::random_id();
    let source_id = crate::cluster::membership::random_id();
    let add_operation_id = crate::cluster::membership::random_id();
    let remove_operation_id = crate::cluster::membership::random_id();
    let endpoint: SocketAddr = "127.0.0.1:19003".parse().unwrap();
    let certificate = crate::cluster::certgen::generate_self_signed(
        &[crate::cluster::certgen::San::Ip(endpoint.ip())],
        30,
        time::OffsetDateTime::now_utc(),
    )
    .unwrap();
    let listeners = Arc::new(MaterialListener {
        material: NodeListenerSpec {
            endpoint,
            certificate_pem: certificate.cert_pem.clone(),
            private_key_pem: SecretString(certificate.key_pem.clone()),
            scope: ListenerScope::Management,
        },
        fail_prepare: AtomicBool::new(false),
        prepared: Mutex::new(Vec::new()),
        retired: Mutex::new(Vec::new()),
    });
    let controller = controller_with_listener(&directory, &local_id, listeners, Some(endpoint));
    let original = controller.prepare_token(Some(endpoint)).await.unwrap();
    let original = BootstrapToken::decode(
        &original.token.unwrap(),
        crate::cluster::membership::now().unwrap(),
    )
    .unwrap();
    let old_source_credential = SecretString(crate::auth::token::generate_token().0);
    let first_claim = controller
        .accept_bootstrap(BootstrapClaimRequest {
            token: original.secret.clone(),
            operation_id: add_operation_id.clone(),
            source_node_id: source_id.clone(),
            source_name: "Primary".into(),
            source_endpoint: "127.0.0.1:19001".parse().unwrap(),
            source_fingerprint: "d".repeat(64),
            source_credential: old_source_credential,
        })
        .await
        .unwrap();
    let add = test_operation(
        add_operation_id.clone(),
        source_id.clone(),
        local_id.clone(),
        endpoint,
        NodeOperationKind::Add,
        NodeOperationPhase::Complete,
    );
    let remove = test_operation(
        remove_operation_id.clone(),
        source_id.clone(),
        local_id.clone(),
        endpoint,
        NodeOperationKind::Remove,
        NodeOperationPhase::Complete,
    );
    let guard = acquire_for_migration(&controller.master).unwrap();
    let mut state = load_state(&guard).unwrap();
    state.peers.get_mut(&source_id).unwrap().view.state = NodePeerState::PendingDetach;
    state.operations.insert(add_operation_id.clone(), add);
    state.operations.insert(remove_operation_id.clone(), remove);
    save_state(&guard, &state).unwrap();
    drop(guard);

    let source_peer = controller.peer(&source_id).await.unwrap();
    controller
        .accept_detach_ack(&source_peer, remove_operation_id.clone())
        .await
        .unwrap();
    assert!(controller
        .accept_bootstrap(BootstrapClaimRequest {
            token: original.secret,
            operation_id: add_operation_id,
            source_node_id: source_id.clone(),
            source_name: "Primary".into(),
            source_endpoint: "127.0.0.1:19001".parse().unwrap(),
            source_fingerprint: "d".repeat(64),
            source_credential: SecretString(crate::auth::token::generate_token().0),
        })
        .await
        .is_err());
    let prepared = controller.prepare_token(Some(endpoint)).await.unwrap();
    let encoded = prepared.token.unwrap();
    let token =
        BootstrapToken::decode(&encoded, crate::cluster::membership::now().unwrap()).unwrap();
    let new_operation_id = crate::cluster::membership::random_id();
    let new_source_credential = SecretString(crate::auth::token::generate_token().0);
    let response = controller
        .accept_bootstrap(BootstrapClaimRequest {
            token: token.secret,
            operation_id: new_operation_id,
            source_node_id: source_id.clone(),
            source_name: "Primary".into(),
            source_endpoint: "127.0.0.1:19001".parse().unwrap(),
            source_fingerprint: "e".repeat(64),
            source_credential: new_source_credential.clone(),
        })
        .await
        .unwrap();
    assert_eq!(response.target_node_id, local_id);
    assert!(controller
        .authenticate_peer(&first_claim.target_credential.0)
        .await
        .is_err());
    assert!(controller
        .authenticate_peer(&response.target_credential.0)
        .await
        .is_ok());
    let guard = acquire_for_migration(&controller.master).unwrap();
    let rebound = load_state(&guard).unwrap();
    assert_eq!(rebound.peers[&source_id].view.state, NodePeerState::Pending);
    assert_eq!(
        rebound.peers[&source_id].outgoing_credential.0,
        new_source_credential.0
    );
    assert!(rebound.detach_receipts.contains_key(&remove_operation_id));
}

#[tokio::test]
async fn acknowledged_outbox_receipt_retires_the_claimed_bootstrap() {
    let source_directory = tempfile::tempdir().unwrap();
    let target_directory = tempfile::tempdir().unwrap();
    let source_id = crate::cluster::membership::random_id();
    let target_id = crate::cluster::membership::random_id();
    let add_operation_id = crate::cluster::membership::random_id();
    let remove_operation_id = crate::cluster::membership::random_id();
    let socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let source_endpoint = socket.local_addr().unwrap();
    let target_endpoint: SocketAddr = "127.0.0.1:19004".parse().unwrap();
    let certificate = crate::cluster::certgen::generate_self_signed(
        &[crate::cluster::certgen::San::Ip(source_endpoint.ip())],
        30,
        time::OffsetDateTime::now_utc(),
    )
    .unwrap();
    let source_to_target = SecretString(crate::auth::token::generate_token().0);
    let target_to_source = SecretString(crate::auth::token::generate_token().0);

    let source = controller_with_listener(
        &source_directory,
        &source_id,
        Arc::new(MaterialListener {
            material: NodeListenerSpec {
                endpoint: source_endpoint,
                certificate_pem: certificate.cert_pem.clone(),
                private_key_pem: SecretString(certificate.key_pem.clone()),
                scope: ListenerScope::Management,
            },
            fail_prepare: AtomicBool::new(false),
            prepared: Mutex::new(Vec::new()),
            retired: Mutex::new(Vec::new()),
        }),
        Some(source_endpoint),
    );
    let mut target_peer = test_peer(
        target_id.clone(),
        "Secondary",
        target_endpoint,
        NodeRole::Secondary,
        source_to_target.clone(),
        &target_to_source,
        "e".repeat(64),
    );
    target_peer.view.state = NodePeerState::PendingDetach;
    let source_remove = test_operation(
        remove_operation_id.clone(),
        source_id.clone(),
        target_id.clone(),
        target_endpoint,
        NodeOperationKind::Remove,
        NodeOperationPhase::Complete,
    );
    let mut source_state = ControlState::default();
    source_state.peers.insert(target_id.clone(), target_peer);
    source_state
        .operations
        .insert(remove_operation_id.clone(), source_remove);
    let guard = acquire_for_migration(&source.master).unwrap();
    save_state(&guard, &source_state).unwrap();
    drop(guard);
    let server = serve_node_controller(
        socket,
        &source_directory,
        &certificate.cert_pem,
        &certificate.key_pem,
        source,
    )
    .await;

    let target = controller_with_listener(
        &target_directory,
        &target_id,
        Arc::new(MaterialListener {
            material: NodeListenerSpec {
                endpoint: target_endpoint,
                certificate_pem: certificate.cert_pem.clone(),
                private_key_pem: SecretString(certificate.key_pem.clone()),
                scope: ListenerScope::Management,
            },
            fail_prepare: AtomicBool::new(false),
            prepared: Mutex::new(Vec::new()),
            retired: Mutex::new(Vec::new()),
        }),
        Some(target_endpoint),
    );
    let mut source_peer = test_peer(
        source_id.clone(),
        "Primary",
        source_endpoint,
        NodeRole::Primary,
        target_to_source,
        &source_to_target,
        certificate.fingerprint_sha256.clone(),
    );
    source_peer.view.state = NodePeerState::PendingDetach;
    let add = test_operation(
        add_operation_id.clone(),
        source_id.clone(),
        target_id.clone(),
        target_endpoint,
        NodeOperationKind::Add,
        NodeOperationPhase::Complete,
    );
    let remove = test_operation(
        remove_operation_id.clone(),
        source_id.clone(),
        target_id.clone(),
        target_endpoint,
        NodeOperationKind::Remove,
        NodeOperationPhase::Complete,
    );
    let (_, bootstrap_hash) = generate_token();
    let mut target_state = ControlState {
        bootstrap: Some(BootstrapAuthorization {
            token_hash: bootstrap_hash,
            endpoint: target_endpoint,
            target_node_id: target_id.clone(),
            fingerprint: certificate.fingerprint_sha256.clone(),
            certificate_pem: certificate.cert_pem.clone(),
            private_key_pem: SecretString(certificate.key_pem.clone()),
            expires_at: u64::MAX,
            claimed_by: Some(source_id.clone()),
            operation_id: Some(add_operation_id.clone()),
            issued_credential: Some(source_to_target),
        }),
        control_endpoint: Some(target_endpoint),
        certificate_pem: Some(certificate.cert_pem),
        private_key_pem: Some(SecretString(certificate.key_pem)),
        certificate_fingerprint: Some(certificate.fingerprint_sha256),
        ..ControlState::default()
    };
    target_state.peers.insert(source_id.clone(), source_peer);
    target_state.operations.insert(add_operation_id, add);
    target_state
        .operations
        .insert(remove_operation_id.clone(), remove);
    let guard = acquire_for_migration(&target.master).unwrap();
    save_state(&guard, &target_state).unwrap();
    drop(guard);

    target
        .push_detach_receipt(&remove_operation_id)
        .await
        .unwrap();
    let guard = acquire_for_migration(&target.master).unwrap();
    let detached = load_state(&guard).unwrap();
    assert!(detached.bootstrap.is_none());
    assert_eq!(
        detached.peers[&source_id].view.state,
        NodePeerState::Detached
    );
    assert!(detached.detach_receipts.contains_key(&remove_operation_id));
    server.abort();
}
