use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::body::Body;
use axum::extract::State;
use axum::http::{Request, Response, StatusCode};
use axum::Router;
use tokio::sync::mpsc;

use crate::cluster::dto::{
    ActiveArtifactAck, ArtifactIdentity, HeartbeatV2Response, ManifestResponse,
};
use crate::cluster::manifest::{Manifest, ObjectRef, Requirements, RuleRequirements};
use crate::config::atomic_write::{hardened_atomic_write, AtomicWriteOpts};

const HEARTBEAT: &str = "/api/cluster/v2/heartbeat";
const MASTER: &str = r#"schema_version = 5
includes = ["cluster.d/*.toml"]
[server]
listen = "127.0.0.1:15354"
[upstream]
servers = ["192.0.2.1:53"]
[cluster]
enabled = true
role = "secondary"
peer = "https://192.0.2.2"
token_hash = "fixture-token-hash"
"#;
const POLICY: &[u8] = b"schema_version = 5\n[server]\ndefault_profile = \"default\"\n[profiles.default]\ndisplay_name = \"Default\"\n[upstream]\nservers = [\"192.0.2.1:53\"]\n";

#[derive(Clone)]
struct Replies {
    heartbeat_status: StatusCode,
    heartbeat: Vec<u8>,
    manifest: Vec<u8>,
    object: Vec<u8>,
    requests: Arc<Mutex<Vec<String>>>,
}

impl Replies {
    fn for_manifest(manifest: &Manifest) -> Self {
        Self {
            heartbeat_status: StatusCode::OK,
            heartbeat: serde_json::to_vec(&HeartbeatV2Response {
                desired: ArtifactIdentity::from(manifest),
                active_acknowledged: false,
                desired_corpus: None,
                corpus_acknowledged: false,
            })
            .unwrap(),
            manifest: manifest_delivery(manifest),
            object: POLICY.to_vec(),
            requests: Arc::default(),
        }
    }
}

async fn respond(State(replies): State<Replies>, request: Request<Body>) -> Response<Body> {
    let path = request.uri().path();
    replies
        .requests
        .lock()
        .unwrap()
        .push(format!("{} {path}", request.method()));
    let (status, body) = if path == HEARTBEAT {
        (replies.heartbeat_status, replies.heartbeat)
    } else if path.ends_with("/manifest") {
        (StatusCode::OK, replies.manifest)
    } else if path.contains("/objects/") {
        (StatusCode::OK, replies.object)
    } else {
        (StatusCode::NOT_FOUND, Vec::new())
    };
    Response::builder()
        .status(status)
        .body(Body::from(body))
        .unwrap()
}

struct Peer {
    url: String,
    task: tokio::task::JoinHandle<()>,
}

impl Peer {
    async fn start(replies: Replies) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let router = Router::new().fallback(respond).with_state(replies);
        let task = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        Self { url, task }
    }
}

impl Drop for Peer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn manifest() -> Manifest {
    let mut manifest = Manifest {
        artifact_format: 2,
        schema_version: 5,
        operator_rule_grammar: "1".into(),
        compiled_cost_version: crate::filter::operator_rules::CompiledCostV1::VERSION,
        primary_lineage: "1".repeat(64),
        policy_epoch: 1,
        config_revision: "2".repeat(64),
        operator_policy_hash: "3".repeat(64),
        policy_toml: ObjectRef::of(POLICY),
        packs: Vec::new(),
        mounts: BTreeMap::from([("default".into(), Vec::new())]),
        requirements: Requirements {
            version: 1,
            compiler_version: 1,
            pack_bytes: 0,
            store: RuleRequirements::default(),
            profiles: BTreeMap::from([("default".into(), RuleRequirements::default())]),
            packs: BTreeMap::new(),
        },
        artifact_hash: String::new(),
    };
    manifest.artifact_hash = manifest.canonical_hash().unwrap();
    manifest.validate().unwrap();
    manifest
}

fn manifest_delivery(manifest: &Manifest) -> Vec<u8> {
    serde_json::to_vec(&ManifestResponse {
        manifest: manifest.clone(),
        available_until: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600,
    })
    .unwrap()
}

fn applicable_artifact() -> (Manifest, BTreeMap<String, Arc<[u8]>>) {
    let config: crate::config::schema::ConfigV5 =
        toml::from_str(std::str::from_utf8(POLICY).unwrap()).unwrap();
    let snapshot = crate::cluster::artifact::PolicySnapshot::from_target_v5(
        &config,
        &crate::config::target_v5::PackBodiesV5::new(BTreeMap::new()),
        "2".repeat(64),
    )
    .unwrap();
    let publication = snapshot.publication(&"1".repeat(64), 1).unwrap();
    (
        Manifest::decode(&publication.manifest).unwrap(),
        publication.objects,
    )
}

fn receiver() -> (tempfile::TempDir, PathBuf) {
    let root = tempfile::tempdir().unwrap();
    let master = root.path().join("config.toml");
    hardened_atomic_write(&master, MASTER.as_bytes(), AtomicWriteOpts::default()).unwrap();
    (root, master)
}

fn candidate_runtime() -> Arc<crate::operator_rules::PolicyCandidateRuntime> {
    let limits = crate::filter::operator_rules::RuleCompileLimits::default();
    Arc::new(crate::operator_rules::PolicyCandidateRuntime::new(
        crate::filter::operator_rules::CompileAdmission::new(limits.max_compiled_bytes_total, 1)
            .unwrap(),
    ))
}

async fn rejected_without_policy_change(replies: Replies, expected_error: &str) -> Vec<String> {
    let requests = Arc::clone(&replies.requests);
    let peer = Peer::start(replies).await;
    let (root, master) = receiver();
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let (reload_tx, mut reload_rx) = mpsc::channel(1);
    let previous_hash = Some("4".repeat(64));
    let mut last_config_hash = previous_hash.clone();
    let runtime = candidate_runtime();
    let error = super::poll_once_v2(
        &client,
        &peer.url,
        "fixture-token",
        &master,
        &reload_tx,
        &mut last_config_hash,
        None,
        Some("secondary.test"),
        None,
        &runtime,
    )
    .await
    .unwrap_err();
    assert!(
        error.to_string().contains(expected_error),
        "expected {expected_error:?}, got {error:#}"
    );
    assert_eq!(last_config_hash, previous_hash);
    assert_eq!(std::fs::read(&master).unwrap(), MASTER.as_bytes());
    assert!(!root
        .path()
        .join(crate::cluster::transaction::BUNDLE_PATH)
        .exists());
    assert!(!root.path().join("packs").exists());
    assert!(crate::cluster::apply::load_persisted(&master)
        .unwrap()
        .is_none());
    assert!(matches!(
        reload_rx.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));
    let recorded = requests.lock().unwrap().clone();
    recorded
}

#[tokio::test]
async fn capability_rejection_does_not_fall_back_to_legacy_or_change_policy() {
    let mut replies = Replies::for_manifest(&manifest());
    replies.heartbeat_status = StatusCode::UPGRADE_REQUIRED;
    replies.heartbeat = b"ArtifactCapabilityMismatch".to_vec();
    let requests = rejected_without_policy_change(replies, "artifact heartbeat HTTP 426").await;
    assert_eq!(requests, [format!("POST {HEARTBEAT}")]);
}

#[tokio::test]
async fn oversized_heartbeat_stops_before_manifest_and_policy_writes() {
    let mut replies = Replies::for_manifest(&manifest());
    replies.heartbeat.resize(16 * 1024 + 1, b' ');
    let requests =
        rejected_without_policy_change(replies, "heartbeat response exceeds the 16384-byte cap")
            .await;
    assert_eq!(requests, [format!("POST {HEARTBEAT}")]);
}

#[tokio::test]
async fn heartbeat_manifest_disagreement_stops_before_object_downloads() {
    let desired = manifest();
    let mut replies = Replies::for_manifest(&desired);
    let mut different = desired.clone();
    different.policy_epoch += 1;
    different.artifact_hash = different.canonical_hash().unwrap();
    different.validate().unwrap();
    replies.manifest = manifest_delivery(&different);
    let requests =
        rejected_without_policy_change(replies, "ArtifactIdentityMismatch: heartbeat and manifest")
            .await;
    assert_eq!(
        requests,
        [
            format!("POST {HEARTBEAT}"),
            format!(
                "GET /api/cluster/v2/artifacts/{}/manifest",
                desired.artifact_hash
            ),
        ]
    );
}

#[tokio::test]
async fn object_size_and_digest_failures_leave_policy_unmodified() {
    let desired = manifest();
    let mut oversized = POLICY.to_vec();
    oversized.push(b'\n');
    let mut wrong_digest = POLICY.to_vec();
    wrong_digest[0] = b'#';
    let cases = [
        (
            oversized,
            format!(
                "artifact object response exceeds the {}-byte cap",
                POLICY.len()
            ),
        ),
        (
            wrong_digest,
            "ArtifactObjectMismatch: size or digest".into(),
        ),
    ];
    for (object, error) in cases {
        let mut replies = Replies::for_manifest(&desired);
        replies.object = object;
        let requests = rejected_without_policy_change(replies, &error).await;
        assert_eq!(
            requests,
            [
                format!("POST {HEARTBEAT}"),
                format!(
                    "GET /api/cluster/v2/artifacts/{}/manifest",
                    desired.artifact_hash
                ),
                format!(
                    "GET /api/cluster/v2/artifacts/{}/objects/{}",
                    desired.artifact_hash, desired.policy_toml.sha256
                ),
            ]
        );
    }
}

#[test]
fn persisted_artifact_retries_activation_after_a_rejected_reload_without_reapplying() {
    let desired = ArtifactIdentity::from(&manifest());
    let (reload_tx, mut reload_rx) = mpsc::channel(1);

    // First cycle: the durable artifact already matches, but the resolver has
    // no fresh acknowledgement. The reload handler consumes and rejects this
    // request; no artifact endpoint is involved in either activation retry.
    let first = super::ensure_active_convergence(Some(&desired), None, &desired, false, &reload_tx)
        .unwrap_err();
    assert!(first.to_string().contains("ArtifactActivationPending"));
    assert_eq!(reload_rx.try_recv().unwrap(), None);

    // A later poll must retry after that rejection, rather than treating the
    // persisted ledger as convergence or attempting a second artifact apply.
    let second =
        super::ensure_active_convergence(Some(&desired), None, &desired, false, &reload_tx)
            .unwrap_err();
    assert!(second.to_string().contains("ArtifactActivationPending"));
    assert_eq!(reload_rx.try_recv().unwrap(), None);
    assert!(matches!(
        reload_rx.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));

    // Even a local matching identity cannot converge until the primary has
    // observed and acknowledged that exact active resolver generation.
    let active = ActiveArtifactAck {
        artifact: desired.clone(),
        local_config_revision: desired.config_revision.clone(),
        daemon_instance_id: "secondary-instance".into(),
        resolver_generation: 17,
    };
    assert!(super::ensure_active_convergence(
        Some(&desired),
        Some(&active),
        &desired,
        false,
        &reload_tx,
    )
    .is_err());
    assert!(super::ensure_active_convergence(
        Some(&desired),
        Some(&active),
        &desired,
        true,
        &reload_tx,
    )
    .is_ok());
}

#[test]
fn active_ack_keeps_source_and_receiver_revisions_distinct_and_requires_corpus_proof() {
    let (_root, master) = receiver();
    let mut receiver_local: toml::Table = toml::from_str(MASTER).unwrap();
    receiver_local.remove("upstream").unwrap();
    hardened_atomic_write(
        &master,
        toml::to_string(&receiver_local).unwrap().as_bytes(),
        AtomicWriteOpts::default(),
    )
    .unwrap();
    let (manifest, objects) = applicable_artifact();
    let ledger = crate::cluster::artifact_apply::apply_with_resolver(
        &master,
        &manifest,
        &objects,
        &crate::cluster::transaction::ExistingReceiptAdapter,
    )
    .unwrap();
    let active = crate::operator_rules::activation::ActivePolicyIdentity {
        daemon_instance_id: "receiver-instance".into(),
        config_revision: "9".repeat(64),
        operator_policy_hash: manifest.operator_policy_hash.clone(),
        resolver_generation: 17,
    };

    let ack = super::active_artifact_ack(Some(&ledger), Some(&active), true, true).unwrap();
    assert_eq!(ack.artifact, ArtifactIdentity::from(&manifest));
    assert_eq!(ack.local_config_revision, active.config_revision);
    assert_ne!(ack.local_config_revision, manifest.config_revision);
    assert!(super::active_artifact_ack(Some(&ledger), Some(&active), true, false).is_none());
    assert!(super::active_artifact_ack(Some(&ledger), Some(&active), false, true).is_none());
}

#[test]
fn pinned_primary_origin_accepts_only_literal_ip_https_origins() {
    assert_eq!(
        super::pinned_primary_endpoint("https://127.0.0.1:8443").unwrap(),
        "127.0.0.1:8443".parse().unwrap()
    );
    assert_eq!(
        super::pinned_primary_endpoint("https://[::1]:9443/").unwrap(),
        "[::1]:9443".parse().unwrap()
    );
    for invalid in [
        "http://127.0.0.1:8443",
        "https://primary.local:8443",
        "https://user@127.0.0.1:8443",
        "https://127.0.0.1:8443/path",
        "https://127.0.0.1:8443/?query=1",
    ] {
        assert!(
            super::pinned_primary_endpoint(invalid).is_err(),
            "{invalid}"
        );
    }
}
