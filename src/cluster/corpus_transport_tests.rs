use super::*;
use crate::cluster::corpus::{CorpusManifest, CorpusSource, CorpusStore, SourceIdentity};
use crate::cluster::dto::ArtifactIdentity;
use crate::cluster::manifest::ObjectRef;
use std::sync::atomic::AtomicUsize;

#[tokio::test]
async fn list_only_guarded_commit_finishes_promptly_and_delivers_reload() {
    use crate::config::atomic_write::{hardened_atomic_write, AtomicWriteOpts};
    use std::collections::BTreeMap;

    let root = tempfile::tempdir().unwrap();
    let master = root.path().join("config.toml");
    let legacy = "schema_version = 5\nincludes = [\"cluster.d/*.toml\"]\n[server]\nlisten = \"127.0.0.1:15354\"\n[cluster]\nenabled = true\nrole = \"secondary\"\npeer = \"https://192.0.2.1\"\ntoken_hash = \"fixture-token-hash\"\n";
    hardened_atomic_write(&master, legacy.as_bytes(), AtomicWriteOpts::default()).unwrap();
    let config = toml::from_str::<crate::config::schema::ConfigV5>(
        "schema_version = 5\n[server]\ndefault_profile = \"default\"\n[upstream]\nservers = [\"192.0.2.1:53\"]\n[profiles.default]\n",
    )
    .unwrap();
    let snapshot = crate::cluster::artifact::PolicySnapshot::from_target_v5(
        &config,
        &crate::config::target_v5::PackBodiesV5::new(BTreeMap::new()),
        "b".repeat(64),
    )
    .unwrap();
    let publication = snapshot.publication(&"a".repeat(64), 1).unwrap();
    let policy = crate::cluster::manifest::Manifest::decode(&publication.manifest).unwrap();
    let runtime = Arc::new(crate::operator_rules::PolicyCandidateRuntime::new(
        crate::filter::operator_rules::CompileAdmission::new(
            crate::filter::operator_rules::RuleCompileLimits::default().max_compiled_bytes_total,
            1,
        )
        .unwrap(),
    ));
    let (reload_tx, mut reload_rx) = mpsc::channel(1);
    crate::cluster::apply::apply_artifact(
        &master,
        policy.clone(),
        publication.objects,
        &reload_tx,
        runtime,
    )
    .await
    .unwrap();
    assert_eq!(reload_rx.try_recv().unwrap(), None);
    let modern = format!(
        "{legacy}membership_version = 1\ncluster_id = \"11111111-1111-4111-8111-111111111111\"\nprimary_node_id = \"22222222-2222-4222-8222-222222222222\"\nprimary_cert_fingerprint = \"{}\"\n[node]\nid = \"33333333-3333-4333-8333-333333333333\"\n",
        "a".repeat(64)
    );
    hardened_atomic_write(&master, modern.as_bytes(), AtomicWriteOpts::default()).unwrap();

    let artifact = ArtifactIdentity::from(&policy);
    let store = CorpusStore::open(&master).unwrap();
    let old = CorpusManifest::new(artifact.clone(), vec![], vec![]).unwrap();
    store.install_manifest(&old).unwrap();
    store.mark_active(&old.generation, &artifact).unwrap();
    let bytes = b"blocked.example\n";
    let source = manifest(bytes, 1_800_000_000).sources.remove(0);
    let mut stage = store.stage(&source.body).unwrap();
    stage.write_chunk(bytes).unwrap();
    stage.finish(&store).unwrap();
    let next = CorpusManifest::new(artifact, vec![source], vec![]).unwrap();
    store.prepare_manifest(&next).unwrap();

    let pending = tokio::time::timeout(
        Duration::from_secs(2),
        commit_received_corpus(&master, &next, &reload_tx),
    )
    .await
    .expect("list-only commit must not recursively acquire the configuration lock")
    .unwrap();
    assert!(pending);
    assert_eq!(reload_rx.try_recv().unwrap(), None);
    let pair = store.pair_state().unwrap();
    assert_eq!(pair.persisted, Some(next.generation.clone()));
    assert_eq!(pair.active, Some(old.generation));
    store.mark_active(&next.generation, &next.artifact).unwrap();
    assert!(!tokio::time::timeout(
        Duration::from_secs(2),
        commit_received_corpus(&master, &next, &reload_tx),
    )
    .await
    .unwrap()
    .unwrap());
    assert!(reload_rx.try_recv().is_err());
}

#[test]
fn modern_heartbeat_requires_live_pair_after_restart_and_during_activation() {
    let manifest = manifest(b"blocked.example\n", 1_800_000_000);
    let mut pair = crate::cluster::corpus::PairState {
        active: Some(manifest.generation.clone()),
        persisted: Some(manifest.generation.clone()),
        desired: Some(manifest.generation.clone()),
    };
    let observe = ClusterObserve::new_secondary(None, "https://primary.example.test".into(), 45);
    let ready = |pair: &crate::cluster::corpus::PairState| {
        corpus_ack_ready(true, Some(&observe), Some(&manifest.artifact), pair)
    };
    assert!(!corpus_ack_ready(
        true,
        None,
        Some(&manifest.artifact),
        &pair
    ));
    assert!(!ready(&pair));
    observe.record_active_pair(manifest.artifact.clone(), manifest.generation.clone());
    assert!(ready(&pair));
    observe.clear_active_pair();
    assert!(!ready(&pair));
    let mut other_policy = manifest.artifact.clone();
    other_policy.policy_epoch += 1;
    observe.record_active_pair(other_policy, manifest.generation.clone());
    assert!(!ready(&pair));
    observe.record_active_pair(manifest.artifact.clone(), "e".repeat(64));
    assert!(!ready(&pair));
    observe.record_active_pair(manifest.artifact.clone(), manifest.generation.clone());
    pair.desired = Some("e".repeat(64));
    assert!(!ready(&pair));
    assert!(corpus_ack_ready(false, None, None, &Default::default()));
}

fn manifest(bytes: &[u8], freshness: i64) -> CorpusManifest {
    CorpusManifest::new(
        ArtifactIdentity {
            primary_lineage: "a".repeat(64),
            policy_epoch: 1,
            artifact_hash: "b".repeat(64),
            config_revision: "c".repeat(64),
            operator_policy_hash: "d".repeat(64),
        },
        vec![CorpusSource {
            source: SourceIdentity {
                representative: "https://origin.example.test/rules".into(),
                fetch_url: "https://origin.example.test/rules".into(),
                canonical_url: "https://origin.example.test/rules".into(),
                aliases: vec![],
                ids: vec![],
                max_entries: 100,
                update_interval_secs: 60,
                format: "Domains".into(),
                trust: "RemoteUnsigned".into(),
            },
            body: ObjectRef::of(bytes),
            fetched_at: freshness,
        }],
        vec![],
    )
    .unwrap()
}

async fn server(
    manifest: CorpusManifest,
    wire: &'static [u8],
    hits: Arc<AtomicUsize>,
) -> (String, tokio::task::JoinHandle<()>) {
    let app = axum::Router::new()
        .route(
            "/api/cluster/v2/corpus/manifest",
            axum::routing::get(move || {
                let manifest = manifest.clone();
                async move { axum::Json(manifest) }
            }),
        )
        .route(
            "/api/cluster/v2/corpus/objects/{hash}",
            axum::routing::get(move || {
                let hits = Arc::clone(&hits);
                async move {
                    hits.fetch_add(1, Ordering::SeqCst);
                    wire
                }
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{address}"), task)
}

#[tokio::test]
async fn corpus_transport_reuses_hash_when_only_freshness_generation_changes() {
    let root = tempfile::tempdir().unwrap();
    let master = root.path().join("config.toml");
    let body = b"blocked.example\n";
    let first = manifest(body, 1_800_000_000);
    let hits = Arc::new(AtomicUsize::new(0));
    let (peer, task) = server(first.clone(), body, Arc::clone(&hits)).await;
    fetch_corpus(
        &reqwest::Client::new(),
        &peer,
        "test",
        &master,
        &first.artifact,
        &first.generation,
    )
    .await
    .unwrap();
    fetch_corpus(
        &reqwest::Client::new(),
        &peer,
        "test",
        &master,
        &first.artifact,
        &first.generation,
    )
    .await
    .unwrap();
    assert_eq!(hits.load(Ordering::SeqCst), 1);
    task.abort();
    let next = manifest(body, 1_800_000_060);
    let (peer, task) = server(next.clone(), body, Arc::clone(&hits)).await;
    fetch_corpus(
        &reqwest::Client::new(),
        &peer,
        "test",
        &master,
        &next.artifact,
        &next.generation,
    )
    .await
    .unwrap();
    assert_eq!(hits.load(Ordering::SeqCst), 1);
    let pair = CorpusStore::open(&master).unwrap().pair_state().unwrap();
    assert!(pair.persisted.is_none());
    assert!(pair.active.is_none());
    assert_eq!(pair.desired, Some(next.generation));
    task.abort();
}

#[tokio::test]
async fn corrupt_primary_body_keeps_last_committed_pair() {
    let root = tempfile::tempdir().unwrap();
    let master = root.path().join("config.toml");
    let old = manifest(b"old.example\n", 1_800_000_000);
    let store = CorpusStore::open(&master).unwrap();
    let mut stage = store.stage(&old.sources[0].body).unwrap();
    stage.write_chunk(b"old.example\n").unwrap();
    stage.finish(&store).unwrap();
    store.install_manifest(&old).unwrap();
    store.mark_active(&old.generation, &old.artifact).unwrap();
    let candidate = manifest(b"new.example\n", 1_800_000_060);
    let (peer, task) = server(
        candidate.clone(),
        b"bad.example\n",
        Arc::new(AtomicUsize::new(0)),
    )
    .await;
    assert!(fetch_corpus(
        &reqwest::Client::new(),
        &peer,
        "test",
        &master,
        &candidate.artifact,
        &candidate.generation
    )
    .await
    .is_err());
    let pair = store.pair_state().unwrap();
    assert_eq!(pair.persisted, Some(old.generation.clone()));
    assert_eq!(pair.active, Some(old.generation));
    assert_eq!(pair.desired, Some(candidate.generation));
    task.abort();
}

#[tokio::test]
async fn concurrently_changed_generation_is_refused_before_object_transfer() {
    let root = tempfile::tempdir().unwrap();
    let manifest = manifest(b"blocked.example\n", 1_800_000_000);
    let hits = Arc::new(AtomicUsize::new(0));
    let (peer, task) = server(manifest.clone(), b"blocked.example\n", Arc::clone(&hits)).await;
    assert!(fetch_corpus(
        &reqwest::Client::new(),
        &peer,
        "test",
        &root.path().join("config.toml"),
        &manifest.artifact,
        &"e".repeat(64)
    )
    .await
    .is_err());
    assert_eq!(hits.load(Ordering::SeqCst), 0);
    task.abort();
}
