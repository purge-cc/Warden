use super::*;
use crate::cluster::corpus::{source_inventory, CorpusManifest, CorpusSource, CorpusStore};
use crate::cluster::dto::ArtifactIdentity;
use crate::cluster::manifest::ObjectRef;
use std::collections::BTreeMap;

fn artifact() -> ArtifactIdentity {
    ArtifactIdentity {
        primary_lineage: "a".repeat(64),
        policy_epoch: 1,
        artifact_hash: "b".repeat(64),
        config_revision: "c".repeat(64),
        operator_policy_hash: "d".repeat(64),
    }
}

fn plan(urls: &[&str]) -> ResolvedSourcePlan {
    ResolvedSourcePlan::build_for_schema(
        &Catalog::from_entries(vec![]),
        &urls.iter().map(|url| (*url).to_owned()).collect::<Vec<_>>(),
        &[],
        &BTreeMap::new(),
        Default::default(),
        5,
    )
    .unwrap()
}

fn manifest(store: &CorpusStore, plan: &ResolvedSourcePlan, bodies: &[&[u8]]) -> CorpusManifest {
    let sources = source_inventory(plan)
        .into_iter()
        .zip(bodies)
        .map(|(source, bytes)| {
            let body = ObjectRef::of(bytes);
            let mut stage = store.stage(&body).unwrap();
            stage.write_chunk(bytes).unwrap();
            stage.finish(store).unwrap();
            CorpusSource {
                source,
                body,
                fetched_at: 1_800_000_000,
            }
        })
        .collect();
    let manifest = CorpusManifest::new(artifact(), sources, vec![]).unwrap();
    store.install_manifest(&manifest).unwrap();
    manifest
}

fn manager(plan: ResolvedSourcePlan, filter: Arc<FilterEngine>) -> ListManager {
    let bits = SourceBitMap::from_plan(&plan).unwrap();
    ListManager::with_plan_and_tokens(
        reqwest::Client::new(),
        filter,
        plan,
        Duration::from_secs(60),
        bits,
        SourceTokenMap::default(),
        1024 * 1024,
        100_000,
        None,
    )
}

#[tokio::test]
async fn secondary_force_and_scheduled_refresh_use_only_pinned_body_and_private_spill() {
    let root = tempfile::tempdir().unwrap();
    let store = Arc::new(CorpusStore::open(&root.path().join("config.toml")).unwrap());
    let url = "https://origin.example.test/rules";
    let plan = plan(&[url]);
    let manifest = manifest(&store, &plan, &[b"blocked.example\n"]);
    let filter = Arc::new(FilterEngine::new());
    let mut manager = manager(plan, Arc::clone(&filter));
    manager
        .set_node_corpus_secondary(Arc::clone(&store), manifest)
        .unwrap();
    for mode in [
        RefreshMode::CacheOnly,
        RefreshMode::Force,
        RefreshMode::Scheduled,
    ] {
        assert_eq!(manager.refresh_with_mode(mode).await, 1);
        manager.verify_node_corpus().unwrap();
    }
    assert!(manager
        .download_list(url, url)
        .await
        .err()
        .unwrap()
        .to_string()
        .contains("only from its primary corpus"));
    assert!(manager.cache.is_empty());
    assert!(std::fs::read_dir(manager.cache_dir.as_ref().unwrap())
        .unwrap()
        .next()
        .is_none());
}

#[tokio::test]
async fn corrupt_one_source_preserves_complete_live_generation_without_origin_fallback() {
    let root = tempfile::tempdir().unwrap();
    let store = Arc::new(CorpusStore::open(&root.path().join("config.toml")).unwrap());
    let plan = plan(&[
        "https://origin.example.test/a",
        "https://origin.example.test/b",
    ]);
    let manifest = manifest(&store, &plan, &[b"first.example\n", b"second.example\n"]);
    let damaged = store.object_path(&manifest.sources[1].body.sha256).unwrap();
    let filter = Arc::new(FilterEngine::new());
    let mut manager = manager(plan, Arc::clone(&filter));
    manager.set_node_corpus_secondary(store, manifest).unwrap();
    assert_eq!(manager.refresh_with_mode(RefreshMode::Force).await, 2);
    std::fs::write(damaged, b"corrupted").unwrap();
    assert_eq!(manager.refresh_with_mode(RefreshMode::Force).await, 2);
    assert_eq!(filter.domain_count(), 2);
    assert!(manager.verify_node_corpus().is_err());
}

#[tokio::test]
async fn detached_secondary_quota_does_not_use_cold_start_exception() {
    let root = tempfile::tempdir().unwrap();
    let store = Arc::new(CorpusStore::open(&root.path().join("config.toml")).unwrap());
    let plan = plan(&["https://origin.example.test/a"]);
    let manifest = manifest(&store, &plan, &[b"first.example\nsecond.example\n"]);
    let filter = Arc::new(FilterEngine::new());
    let mut manager = manager(plan, Arc::clone(&filter));
    manager.set_max_total_domains(1);
    manager.set_node_corpus_secondary(store, manifest).unwrap();
    manager.refresh_with_mode(RefreshMode::CacheOnly).await;
    assert!(manager.verify_node_corpus().is_err());
    assert_eq!(filter.domain_count(), 0);
}

#[tokio::test]
async fn empty_inventory_is_valid_and_removal_contributes_no_old_domains() {
    let root = tempfile::tempdir().unwrap();
    let store = Arc::new(CorpusStore::open(&root.path().join("config.toml")).unwrap());
    let filter = Arc::new(FilterEngine::new());
    let full_plan = plan(&["https://origin.example.test/a"]);
    let full = manifest(&store, &full_plan, &[b"first.example\n"]);
    let mut old = manager(full_plan, Arc::clone(&filter));
    old.set_node_corpus_secondary(Arc::clone(&store), full)
        .unwrap();
    old.refresh_with_mode(RefreshMode::Force).await;
    assert_eq!(filter.domain_count(), 1);
    let empty_plan = plan(&[]);
    let empty = manifest(&store, &empty_plan, &[]);
    let mut replacement = manager(empty_plan, Arc::clone(&filter));
    replacement.set_node_corpus_secondary(store, empty).unwrap();
    replacement.refresh_with_mode(RefreshMode::Force).await;
    replacement.verify_node_corpus().unwrap();
    assert_eq!(filter.domain_count(), 0);
}

#[tokio::test]
async fn primary_publishes_installed_durable_inputs_and_refuses_missing_selected_body() {
    let root = tempfile::tempdir().unwrap();
    let cache = tempfile::tempdir().unwrap();
    let store = Arc::new(CorpusStore::open(&root.path().join("config.toml")).unwrap());
    let url = "https://origin.example.test/a";
    let body_path = write_cache_to_disk(
        cache.path(),
        url,
        url,
        "blocked.example\n",
        None,
        None,
        OffsetDateTime::now_utc(),
    )
    .unwrap();
    let mut manager = manager(plan(&[url]), Arc::new(FilterEngine::new()));
    manager.cache_dir = Some(cache.path().to_owned());
    manager
        .set_node_corpus_primary(Arc::clone(&store), artifact(), vec![])
        .unwrap();
    assert!(store
        .manifest_for_artifact(&artifact().artifact_hash)
        .is_err());
    manager.load_disk_cache();
    manager.refresh_with_mode(RefreshMode::CacheOnly).await;
    let published = store
        .manifest_for_artifact(&artifact().artifact_hash)
        .unwrap();
    assert_eq!(
        published.sources[0].body,
        ObjectRef::of(b"blocked.example\n")
    );
    assert_eq!(
        store.pair_state().unwrap().active,
        Some(published.generation.clone())
    );
    std::fs::remove_file(body_path).unwrap();
    assert!(manager.publish_node_corpus().is_err());
    assert_eq!(
        store
            .manifest_for_artifact(&artifact().artifact_hash)
            .unwrap(),
        published
    );
}

#[tokio::test]
async fn primary_candidate_cache_isolated_then_recovered_after_publication() {
    let root = tempfile::tempdir().unwrap();
    let cache = tempfile::tempdir().unwrap();
    let master = root.path().join("config.toml");
    let store = Arc::new(CorpusStore::open(&master).unwrap());
    let url = "https://origin.example.test/a";
    write_cache_to_disk(
        cache.path(),
        url,
        url,
        "blocked.example\n",
        None,
        None,
        OffsetDateTime::now_utc(),
    )
    .unwrap();
    let meta = cache
        .path()
        .join(format!("{}.meta", source_to_cache_stem(url)));
    let original = std::fs::read(&meta).unwrap();
    let mut candidate = manager(plan(&[url]), Arc::new(FilterEngine::new()));
    candidate.cache_dir = Some(cache.path().to_owned());
    candidate.isolate_candidate_cache(&store).unwrap();
    let private = candidate.cache_dir.clone().unwrap();
    assert_ne!(private, cache.path());
    candidate.load_disk_cache();
    candidate.refresh_with_mode(RefreshMode::CacheOnly).await;
    candidate.verify_node_corpus().unwrap();
    assert_eq!(std::fs::read(&meta).unwrap(), original);
    candidate
        .set_node_corpus_primary(Arc::clone(&store), artifact(), vec![])
        .unwrap();
    drop(candidate);
    assert!(private.is_dir());
    let reopened = Arc::new(CorpusStore::open(&master).unwrap());
    let mut restarted = manager(plan(&[url]), Arc::new(FilterEngine::new()));
    restarted
        .set_node_corpus_primary(reopened, artifact(), vec![])
        .unwrap();
    assert_eq!(restarted.cache_dir, Some(private));
    restarted.load_disk_cache();
    restarted.refresh_with_mode(RefreshMode::CacheOnly).await;
    restarted.verify_node_corpus().unwrap();
}

#[tokio::test]
async fn repeated_primary_cache_publications_bound_retention_and_preserve_live_owners() {
    let root = tempfile::tempdir().unwrap();
    let original = tempfile::tempdir().unwrap();
    let master = root.path().join("config.toml");
    let store = Arc::new(CorpusStore::open(&master).unwrap());
    let url = "https://origin.example.test/a";
    write_cache_to_disk(
        original.path(),
        url,
        url,
        "blocked.example\n",
        None,
        None,
        OffsetDateTime::now_utc(),
    )
    .unwrap();
    let mut live: Option<ListManager> = None;
    let mut abandoned = manager(plan(&[url]), Arc::new(FilterEngine::new()));
    abandoned.cache_dir = Some(original.path().to_owned());
    abandoned.isolate_candidate_cache(&store).unwrap();
    let pending_path = abandoned.cache_dir.clone().unwrap();
    for _ in 0..8 {
        let mut next = manager(plan(&[url]), Arc::new(FilterEngine::new()));
        next.cache_dir = Some(original.path().to_owned());
        next.isolate_candidate_cache(&store).unwrap();
        next.load_disk_cache();
        next.refresh_with_mode(RefreshMode::CacheOnly).await;
        next.verify_node_corpus().unwrap();
        next.set_node_corpus_primary(Arc::clone(&store), artifact(), vec![])
            .unwrap();
        if let Some(previous) = &live {
            assert!(previous.cache_dir.as_ref().unwrap().is_dir());
        }
        assert!(pending_path.is_dir());
        let previous_path = live.as_ref().and_then(|manager| manager.cache_dir.clone());
        drop(live.take());
        CorpusStore::open(&master).unwrap();
        if let Some(path) = previous_path {
            assert!(!path.exists());
        }
        let count = std::fs::read_dir(root.path().join(".warden-node-corpus"))
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().starts_with("parser-"))
            .count();
        assert_eq!(
            count, 2,
            "only the selected and live detached candidate remain"
        );
        live = Some(next);
    }
    let selected_before_failure = store.primary_cache_dir().unwrap().unwrap();
    abandoned.load_disk_cache();
    abandoned.refresh_with_mode(RefreshMode::CacheOnly).await;
    abandoned.verify_node_corpus().unwrap();
    let stem = source_to_cache_stem(url);
    let meta = load_meta_file(&pending_path.join(format!("{stem}.meta")));
    let missing = manifest_from_meta(&stem, &meta).unwrap();
    std::fs::remove_file(pending_path.join(missing.body)).unwrap();
    assert!(abandoned
        .set_node_corpus_primary(Arc::clone(&store), artifact(), vec![])
        .is_err());
    assert_eq!(
        store.primary_cache_dir().unwrap(),
        Some(selected_before_failure.clone())
    );
    assert!(selected_before_failure.is_dir());
    drop(abandoned);
    drop(live);
    let reopened = Arc::new(CorpusStore::open(&master).unwrap());
    let selected = reopened.primary_cache_dir().unwrap().unwrap();
    let mut restarted = manager(plan(&[url]), Arc::new(FilterEngine::new()));
    restarted
        .set_node_corpus_primary(reopened, artifact(), vec![])
        .unwrap();
    assert_eq!(restarted.cache_dir, Some(selected));
    restarted.load_disk_cache();
    restarted.refresh_with_mode(RefreshMode::CacheOnly).await;
    restarted.verify_node_corpus().unwrap();
    assert!(original.path().is_dir());
    assert!(!pending_path.exists());
}

#[tokio::test]
async fn periodic_auxiliary_change_publishes_only_after_complete_domain_cycle() {
    let root = tempfile::tempdir().unwrap();
    let cache = tempfile::tempdir().unwrap();
    let store = Arc::new(CorpusStore::open(&root.path().join("config.toml")).unwrap());
    let mut manager = manager(plan(&[]), Arc::new(FilterEngine::new()));
    manager.cache_dir = Some(cache.path().to_owned());
    manager
        .set_node_corpus_primary(Arc::clone(&store), artifact(), vec![])
        .unwrap();
    manager.refresh_with_mode(RefreshMode::CacheOnly).await;
    let before = store.pair_state().unwrap().active;
    let activated = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let activate_flag = Arc::clone(&activated);
    manager.set_node_auxiliary_refresh(Arc::new(move |store, _client| {
        let activated = Arc::clone(&activate_flag);
        Box::pin(async move {
            let body = ObjectRef::of(b"192.0.2.1\n");
            let mut input = tempfile::tempfile()?;
            input.write_all(b"192.0.2.1\n")?;
            store.import_file(&body, &mut input)?;
            Ok(crate::cluster::corpus::PreparedAuxiliary {
                sources: vec![crate::cluster::corpus::CorpusAuxSource {
                    url: "https://origin.example.test/ip".into(),
                    body,
                    fetched_at: 1_800_000_000,
                }],
                activate: Box::new(move || {
                    activated.store(true, std::sync::atomic::Ordering::SeqCst)
                }),
            })
        })
    }));
    manager.refresh_with_mode(RefreshMode::Force).await;
    assert!(activated.load(std::sync::atomic::Ordering::SeqCst));
    let published = store
        .manifest_for_artifact(&artifact().artifact_hash)
        .unwrap();
    assert_eq!(published.auxiliary.len(), 1);
    assert_ne!(store.pair_state().unwrap().active, before);
    let complete = store.pair_state().unwrap().active;
    manager.set_node_auxiliary_refresh(Arc::new(|_, _| {
        Box::pin(async { anyhow::bail!("origin unavailable") })
    }));
    manager.refresh_with_mode(RefreshMode::Force).await;
    assert_eq!(store.pair_state().unwrap().active, complete);
    assert!(manager.verify_node_corpus().is_err());
}

#[tokio::test]
async fn refused_domain_refresh_never_activates_prepared_auxiliary_inputs() {
    let root = tempfile::tempdir().unwrap();
    let cache = tempfile::tempdir().unwrap();
    let store = Arc::new(CorpusStore::open(&root.path().join("config.toml")).unwrap());
    let url = "http://origin.example.test/a";
    let selected = write_cache_to_disk(
        cache.path(),
        url,
        url,
        "blocked.example\n",
        None,
        None,
        OffsetDateTime::now_utc(),
    )
    .unwrap();
    let mut manager = manager(plan(&[url]), Arc::new(FilterEngine::new()));
    manager.cache_dir = Some(cache.path().to_owned());
    manager
        .set_node_corpus_primary(Arc::clone(&store), artifact(), vec![])
        .unwrap();
    manager.load_disk_cache();
    manager.refresh_with_mode(RefreshMode::CacheOnly).await;
    let before = store.pair_state().unwrap().active;
    let activated = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let activate_flag = Arc::clone(&activated);
    manager.set_node_auxiliary_refresh(Arc::new(move |_, _| {
        let activated = Arc::clone(&activate_flag);
        Box::pin(async move {
            Ok(crate::cluster::corpus::PreparedAuxiliary {
                sources: vec![],
                activate: Box::new(move || {
                    activated.store(true, std::sync::atomic::Ordering::SeqCst)
                }),
            })
        })
    }));
    std::fs::remove_file(selected).unwrap();
    manager.refresh_with_mode(RefreshMode::Force).await;
    assert!(!activated.load(std::sync::atomic::Ordering::SeqCst));
    assert_eq!(store.pair_state().unwrap().active, before);
    assert_eq!(manager.filter.domain_count(), 1);
}

#[tokio::test]
async fn prepared_status_install_preserves_success_and_live_sequence_waiters() {
    let root = tempfile::tempdir().unwrap();
    let store = Arc::new(CorpusStore::open(&root.path().join("config.toml")).unwrap());
    let empty_plan = plan(&[]);
    let manifest = manifest(&store, &empty_plan, &[]);
    let mut candidate = manager(empty_plan, Arc::new(FilterEngine::new()));
    candidate
        .set_node_corpus_secondary(store, manifest)
        .unwrap();
    candidate.refresh_with_mode(RefreshMode::CacheOnly).await;
    candidate.verify_node_corpus().unwrap();
    let live = Arc::new(ListStatusRegistry::new(&[]));
    for _ in 0..5 {
        live.record_cycle(CycleOutcome::Refused);
    }
    let previous = live.cycle().seq;
    candidate.install_prepared_status_registry(Arc::clone(&live));
    candidate.verify_node_corpus().unwrap();
    assert_eq!(live.cycle().seq, previous + 1);
    assert_eq!(live.cycle().served_state, ServedState::IntentionalEmpty);
    assert!(Arc::ptr_eq(&candidate.status_registry, &live));
}

#[tokio::test]
async fn failed_primary_refresh_clears_live_pair_proof_until_successful_publication() {
    let root = tempfile::tempdir().unwrap();
    let cache = tempfile::tempdir().unwrap();
    let store = Arc::new(CorpusStore::open(&root.path().join("config.toml")).unwrap());
    let url = "https://origin.example.test/a";
    let selected = write_cache_to_disk(
        cache.path(),
        url,
        url,
        "blocked.example\n",
        None,
        None,
        OffsetDateTime::now_utc(),
    )
    .unwrap();
    let mut manager = manager(plan(&[url]), Arc::new(FilterEngine::new()));
    manager.cache_dir = Some(cache.path().to_owned());
    manager
        .set_node_corpus_primary(store, artifact(), vec![])
        .unwrap();
    let events = Arc::new(std::sync::Mutex::new(Vec::new()));
    let unknown = Arc::clone(&events);
    manager
        .set_node_pair_unconfirmed_hook(Arc::new(move || unknown.lock().unwrap().push("unknown")));
    let confirmed = Arc::clone(&events);
    manager.set_node_active_pair_hook(Arc::new(move |_, _| {
        confirmed.lock().unwrap().push("active")
    }));
    manager.load_disk_cache();
    manager.refresh_with_mode(RefreshMode::CacheOnly).await;
    std::fs::remove_file(selected).unwrap();
    manager.refresh_with_mode(RefreshMode::CacheOnly).await;
    assert_eq!(
        *events.lock().unwrap(),
        vec!["unknown", "active", "unknown"]
    );
    assert_eq!(manager.filter.domain_count(), 1);
}
