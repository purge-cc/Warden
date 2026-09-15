use super::*;

fn identity() -> ArtifactIdentity {
    ArtifactIdentity {
        primary_lineage: "a".repeat(64),
        policy_epoch: 1,
        artifact_hash: "b".repeat(64),
        config_revision: "c".repeat(64),
        operator_policy_hash: "d".repeat(64),
    }
}

fn source(bytes: &[u8]) -> CorpusSource {
    CorpusSource {
        source: SourceIdentity {
            representative: "https://lists.example.test/rules".into(),
            fetch_url: "https://lists.example.test/rules".into(),
            canonical_url: "https://lists.example.test/rules".into(),
            aliases: vec![],
            ids: vec![],
            max_entries: 100,
            update_interval_secs: 60,
            format: "Domains".into(),
            trust: "RemoteUnsigned".into(),
        },
        body: ObjectRef::of(bytes),
        fetched_at: 1_800_000_000,
    }
}

fn put(store: &CorpusStore, bytes: &[u8]) {
    let mut stage = store.stage(&ObjectRef::of(bytes)).unwrap();
    for chunk in bytes.chunks(3) {
        stage.write_chunk(chunk).unwrap();
    }
    stage.finish(store).unwrap();
}

#[test]
fn corrupt_truncated_and_oversize_objects_never_become_owned() {
    let root = tempfile::tempdir().unwrap();
    let store = CorpusStore::open(&root.path().join("config.toml")).unwrap();
    let expected = ObjectRef::of(b"blocked.example\n");
    let mut stage = store.stage(&expected).unwrap();
    stage.write_chunk(b"truncated").unwrap();
    assert!(stage.finish(&store).is_err());
    assert!(!store.has_object(&expected));
    let mut stage = store.stage(&expected).unwrap();
    assert!(stage
        .write_chunk(b"too many bytes for the reservation")
        .is_err());
    drop(stage);
    let mut stage = store.stage(&expected).unwrap();
    stage.write_chunk(b"another.example\n").unwrap();
    assert!(stage.finish(&store).is_err());
    assert_eq!(
        std::fs::read_dir(store.root.join("objects"))
            .unwrap()
            .count(),
        0
    );
}

#[test]
fn candidate_missing_body_keeps_persisted_and_active_pair_across_reopen() {
    let root = tempfile::tempdir().unwrap();
    let master = root.path().join("config.toml");
    let store = CorpusStore::open(&master).unwrap();
    let bytes = b"old.example\n";
    put(&store, bytes);
    let old = CorpusManifest::new(identity(), vec![source(bytes)], vec![]).unwrap();
    store.install_manifest(&old).unwrap();
    store.mark_active(&old.generation, &old.artifact).unwrap();
    let candidate =
        CorpusManifest::new(identity(), vec![source(b"new.example\n")], vec![]).unwrap();
    store.record_desired(&candidate).unwrap();
    assert!(store.install_manifest(&candidate).is_err());
    let reopened = CorpusStore::open(&master).unwrap();
    assert!(reopened.manifest(&candidate.generation).is_err());
    assert_eq!(
        reopened
            .manifest_metadata(&candidate.generation)
            .unwrap()
            .artifact,
        candidate.artifact
    );
    assert!(reopened.verify_manifest_objects(&candidate).is_err());
    assert_eq!(
        reopened.pair_state().unwrap().persisted,
        Some(old.generation.clone())
    );
    assert_eq!(reopened.pair_state().unwrap().active, Some(old.generation));
    assert_eq!(
        reopened.pair_state().unwrap().desired,
        Some(candidate.generation)
    );
}

#[test]
fn desired_metadata_refuses_substitution_and_does_not_mask_corrupt_installed_manifest() {
    let root = tempfile::tempdir().unwrap();
    let store = CorpusStore::open(&root.path().join("config.toml")).unwrap();
    let candidate = CorpusManifest::new(identity(), vec![], vec![]).unwrap();
    store.record_desired(&candidate).unwrap();
    let substitute = "e".repeat(64);
    std::fs::copy(
        store.root.join("candidates").join(&candidate.generation),
        store.root.join("candidates").join(&substitute),
    )
    .unwrap();
    assert!(store.manifest_metadata(&substitute).is_err());
    assert!(store.manifest_metadata("../pair.json").is_err());
    std::fs::write(
        store.root.join("manifests").join(&candidate.generation),
        b"invalid manifest",
    )
    .unwrap();
    assert!(store.manifest_metadata(&candidate.generation).is_err());
}

#[test]
fn list_only_change_requires_separate_runtime_activation_and_reuses_objects() {
    let root = tempfile::tempdir().unwrap();
    let store = CorpusStore::open(&root.path().join("config.toml")).unwrap();
    let bytes = b"blocked.example\n";
    put(&store, bytes);
    let first = CorpusManifest::new(identity(), vec![source(bytes)], vec![]).unwrap();
    store.install_manifest(&first).unwrap();
    store
        .mark_active(&first.generation, &first.artifact)
        .unwrap();
    let mut refreshed = source(bytes);
    refreshed.fetched_at += 60;
    let second = CorpusManifest::new(identity(), vec![refreshed], vec![]).unwrap();
    assert_ne!(first.generation, second.generation);
    store.install_manifest(&second).unwrap();
    assert_eq!(store.pair_state().unwrap().active, Some(first.generation));
    assert_eq!(
        std::fs::read_dir(store.root.join("objects"))
            .unwrap()
            .count(),
        1
    );
    store
        .mark_active(&second.generation, &second.artifact)
        .unwrap();
    assert_eq!(store.pair_state().unwrap().active, Some(second.generation));
}

#[test]
fn intentional_empty_removes_inventory_and_gc_requires_released_ownership() {
    let root = tempfile::tempdir().unwrap();
    let store = CorpusStore::open(&root.path().join("config.toml")).unwrap();
    put(&store, b"old.example\n");
    let old = CorpusManifest::new(identity(), vec![source(b"old.example\n")], vec![]).unwrap();
    store.install_manifest(&old).unwrap();
    store.mark_active(&old.generation, &old.artifact).unwrap();
    let empty = CorpusManifest::new(identity(), vec![], vec![]).unwrap();
    store.install_manifest(&empty).unwrap();
    assert_eq!(store.collect_unreferenced().unwrap(), 0);
    assert!(store.has_object(&old.sources[0].body));
    store
        .mark_active(&empty.generation, &empty.artifact)
        .unwrap();
    put(&store, b"unselected.example\n");
    assert_eq!(store.collect_unreferenced().unwrap(), 2);
    assert!(!store.has_object(&old.sources[0].body));
    assert!(store
        .manifest_for_artifact(&empty.artifact.artifact_hash)
        .unwrap()
        .sources
        .is_empty());
}

#[test]
fn manifest_tamper_policy_binding_auxiliary_and_quotas_fail_closed() {
    let mut manifest = CorpusManifest::new(identity(), vec![source(b"x")], vec![]).unwrap();
    manifest.artifact.policy_epoch += 1;
    assert!(manifest.validate().is_err());
    let mut oversized = source(b"x");
    oversized.body.bytes = MAX_OBJECT_BYTES + 1;
    assert!(CorpusManifest::new(identity(), vec![oversized], vec![]).is_err());
    let manifest = CorpusManifest::new(identity(), vec![], vec![]).unwrap();
    assert!(manifest
        .verify_auxiliary(&["https://lists.example.test/ip".into()])
        .is_err());
    assert!(CorpusManifest::new(identity(), vec![source(b"x"), source(b"x")], vec![]).is_err());
}

#[cfg(unix)]
#[test]
fn object_symlink_and_path_escape_are_rejected() {
    let root = tempfile::tempdir().unwrap();
    let store = CorpusStore::open(&root.path().join("config.toml")).unwrap();
    let object = ObjectRef::of(b"body");
    let outside = root.path().join("outside");
    std::fs::write(&outside, b"body").unwrap();
    std::os::unix::fs::symlink(&outside, store.object_path(&object.sha256).unwrap()).unwrap();
    assert!(store.verified_object(&object).is_err());
    assert!(store.open_object("../../outside").is_err());
}

#[test]
fn prepared_list_only_candidate_does_not_replace_recovered_committed_pair() {
    let root = tempfile::tempdir().unwrap();
    let master = root.path().join("config.toml");
    let store = CorpusStore::open(&master).unwrap();
    put(&store, b"old.example\n");
    let old = CorpusManifest::new(identity(), vec![source(b"old.example\n")], vec![]).unwrap();
    store.install_manifest(&old).unwrap();
    store.mark_active(&old.generation, &old.artifact).unwrap();
    let candidate =
        CorpusManifest::new(identity(), vec![source(b"candidate.example\n")], vec![]).unwrap();
    store.record_desired(&candidate).unwrap();
    put(&store, b"candidate.example\n");
    store.prepare_manifest(&candidate).unwrap();
    assert_eq!(
        store.pair_state().unwrap().persisted,
        Some(old.generation.clone())
    );
    let recovered = CorpusStore::open(&master)
        .unwrap()
        .recover_committed_pair(&identity())
        .unwrap();
    assert_eq!(recovered, old);
    assert_eq!(
        store
            .manifest_for_artifact(&identity().artifact_hash)
            .unwrap(),
        old
    );
    assert_eq!(
        store.pair_state().unwrap().desired,
        Some(candidate.generation)
    );
}

#[test]
fn independent_store_handles_serialize_pair_updates_without_lost_fields() {
    let root = tempfile::tempdir().unwrap();
    let master = root.path().join("config.toml");
    let store = CorpusStore::open(&master).unwrap();
    let old = CorpusManifest::new(identity(), vec![], vec![]).unwrap();
    store.install_manifest(&old).unwrap();
    let mut next_identity = identity();
    next_identity.policy_epoch += 1;
    let next = CorpusManifest::new(next_identity, vec![], vec![]).unwrap();
    let a = CorpusStore::open(&master).unwrap();
    let b = CorpusStore::open(&master).unwrap();
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    std::thread::scope(|scope| {
        let barrier_a = std::sync::Arc::clone(&barrier);
        let old_ref = &old;
        scope.spawn(move || {
            barrier_a.wait();
            a.mark_active(&old_ref.generation, &old_ref.artifact)
                .unwrap();
        });
        let next_ref = &next;
        scope.spawn(move || {
            barrier.wait();
            b.record_desired(next_ref).unwrap();
        });
    });
    let state = store.pair_state().unwrap();
    assert_eq!(state.active, Some(old.generation));
    assert_eq!(state.desired, Some(next.generation));
}

#[test]
fn list_only_refreshes_do_not_exhaust_manifest_quota() {
    let root = tempfile::tempdir().unwrap();
    let store = CorpusStore::open(&root.path().join("config.toml")).unwrap();
    put(&store, b"blocked.example\n");
    for generation in 0..257 {
        let mut item = source(b"blocked.example\n");
        item.fetched_at += generation as i64;
        let manifest = CorpusManifest::new(identity(), vec![item], vec![]).unwrap();
        store.install_manifest(&manifest).unwrap();
        store
            .mark_active(&manifest.generation, &manifest.artifact)
            .unwrap();
    }
    assert_eq!(
        std::fs::read_dir(store.root.join("manifests"))
            .unwrap()
            .count(),
        1
    );
    assert_eq!(
        std::fs::read_dir(store.root.join("objects"))
            .unwrap()
            .count(),
        1
    );
}

#[test]
fn gc_keeps_pending_transfer_objects_until_candidate_ownership_is_released() {
    let root = tempfile::tempdir().unwrap();
    let store = CorpusStore::open(&root.path().join("config.toml")).unwrap();
    let pending =
        CorpusManifest::new(identity(), vec![source(b"pending.example\n")], vec![]).unwrap();
    store.record_desired(&pending).unwrap();
    put(&store, b"pending.example\n");
    assert_eq!(store.collect_unreferenced().unwrap(), 0);
    assert!(store.has_object(&pending.sources[0].body));
}

#[test]
fn read_only_open_never_creates_corpus_state() {
    let root = tempfile::tempdir().unwrap();
    assert!(CorpusStore::open_existing(&root.path().join("config.toml"))
        .unwrap()
        .is_none());
    assert!(!root.path().join(".warden-node-corpus").exists());
}

#[test]
fn orphan_parser_cache_recovery_requires_receipt_and_released_directory_lease() {
    use std::os::unix::fs::PermissionsExt;
    let root = tempfile::tempdir().unwrap();
    let master = root.path().join("config.toml");
    let store = CorpusStore::open(&master).unwrap();
    let (workspace, lease) = store.parser_workspace().unwrap();
    assert_eq!(
        std::fs::metadata(workspace.path())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    std::fs::write(workspace.path().join("spill.bin"), b"parser spill").unwrap();
    let orphan = workspace.keep();
    let unowned = tempfile::Builder::new()
        .prefix("parser-")
        .tempdir_in(&store.root)
        .unwrap();
    CorpusStore::open(&master).unwrap();
    assert!(orphan.is_dir());
    drop(lease);
    CorpusStore::open(&master).unwrap();
    assert!(!orphan.exists());
    assert!(unowned.path().is_dir());
}

#[test]
fn superseded_transfer_ownership_expires_only_after_its_live_lease() {
    let root = tempfile::tempdir().unwrap();
    let master = root.path().join("config.toml");
    let receiver = CorpusStore::open(&master).unwrap();
    let collector = CorpusStore::open(&master).unwrap();
    let abandoned =
        CorpusManifest::new(identity(), vec![source(b"old.example\n")], vec![]).unwrap();
    let lease = receiver.record_desired(&abandoned).unwrap();
    put(&receiver, b"old.example\n");
    let current = CorpusManifest::new(identity(), vec![source(b"new.example\n")], vec![]).unwrap();
    collector.record_desired(&current).unwrap();
    assert_eq!(collector.collect_unreferenced().unwrap(), 0);
    assert!(collector.has_object(&abandoned.sources[0].body));
    drop(lease);
    assert_eq!(collector.collect_unreferenced().unwrap(), 1);
    assert!(!collector.has_object(&abandoned.sources[0].body));
    assert_eq!(
        std::fs::read_dir(collector.root.join("candidates"))
            .unwrap()
            .count(),
        1
    );
    assert_eq!(
        collector.pair_state().unwrap().desired,
        Some(current.generation)
    );
}

#[test]
fn verified_retransmission_repairs_corrupt_owned_digest_atomically() {
    let root = tempfile::tempdir().unwrap();
    let store = CorpusStore::open(&root.path().join("config.toml")).unwrap();
    let bytes = b"correct.example\n";
    put(&store, bytes);
    let object = ObjectRef::of(bytes);
    std::fs::write(store.object_path(&object.sha256).unwrap(), b"corrupt").unwrap();
    assert!(!store.has_object(&object));
    put(&store, bytes);
    let mut file = store.verified_object(&object).unwrap();
    let mut actual = Vec::new();
    file.read_to_end(&mut actual).unwrap();
    assert_eq!(actual, bytes);
}

#[test]
fn primary_import_is_pinned_against_another_manager_gc_until_capture_or_drop() {
    let root = tempfile::tempdir().unwrap();
    let master = root.path().join("config.toml");
    let collector = CorpusStore::open(&master).unwrap();
    let incoming = CorpusStore::open(&master).unwrap();
    let bytes = b"incoming.example\n";
    let mut input = tempfile::tempfile().unwrap();
    input.write_all(bytes).unwrap();
    incoming
        .import_file(&ObjectRef::of(bytes), &mut input)
        .unwrap();
    assert_eq!(collector.collect_unreferenced().unwrap(), 0);
    drop(incoming);
    assert_eq!(collector.collect_unreferenced().unwrap(), 1);
}

#[test]
fn authoritative_policy_retirement_preserves_runtime_and_pending_ownership() {
    let root = tempfile::tempdir().unwrap();
    let store = CorpusStore::open(&root.path().join("config.toml")).unwrap();
    let old = CorpusManifest::new(identity(), vec![], vec![]).unwrap();
    store.install_manifest(&old).unwrap();
    store.mark_active(&old.generation, &old.artifact).unwrap();
    let mut next_identity = identity();
    next_identity.artifact_hash = "e".repeat(64);
    next_identity.policy_epoch += 1;
    let next = CorpusManifest::new(next_identity, vec![], vec![]).unwrap();
    store.install_manifest(&next).unwrap();
    let retained = BTreeSet::from([next.artifact.artifact_hash.clone()]);
    store.retain_policy_artifacts(&retained).unwrap();
    assert!(store
        .manifest_for_artifact(&old.artifact.artifact_hash)
        .is_ok());
    store.mark_active(&next.generation, &next.artifact).unwrap();
    store.retain_policy_artifacts(&retained).unwrap();
    assert!(store
        .manifest_for_artifact(&old.artifact.artifact_hash)
        .is_err());
    assert!(store
        .manifest_for_artifact(&next.artifact.artifact_hash)
        .is_ok());
}
