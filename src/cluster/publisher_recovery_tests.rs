use super::*;
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use std::sync::Arc;

use crate::config::policy_revision::{
    PolicyMemberKind, PolicyMemberState, PolicyRevisionInventory, PolicyRevisionMember,
};
use crate::config::schema::{ConfigV5, Id};
use crate::config::target_v5::PackBodiesV5;
use crate::config::write_lock::acquire_for_migration;

struct Candidate {
    before: PolicyRevisionInventory,
    after: PolicyRevisionInventory,
    snapshot: PolicySnapshot,
}

impl Candidate {
    fn new() -> Self {
        let master = concat!(
            "schema_version = 5\n",
            "[server]\ndefault_profile = 'default'\n",
            "[profiles.default]\ncustom_lists = ['policy']\n",
            "[upstream]\nservers = ['192.0.2.1:53']\n",
            "[[custom_lists]]\nid = 'policy'\n",
        );
        let after_master = format!("{master}[[custom_lists]]\nid = 'new'\n");
        let member = |kind, path: &str, bytes: &[u8]| {
            PolicyRevisionMember::present(kind, path.into(), bytes.to_vec()).unwrap()
        };
        let before = PolicyRevisionInventory::new(vec![
            member(PolicyMemberKind::Master, "config.toml", master.as_bytes()),
            member(
                PolicyMemberKind::Pack,
                "packs/policy.txt",
                b"||before.example^\n",
            ),
        ])
        .unwrap();
        let after = PolicyRevisionInventory::new(vec![
            member(
                PolicyMemberKind::Master,
                "config.toml",
                after_master.as_bytes(),
            ),
            member(
                PolicyMemberKind::Pack,
                "packs/policy.txt",
                b"||after.example^\n",
            ),
            member(PolicyMemberKind::Pack, "packs/new.txt", b"||new.example^\n"),
        ])
        .unwrap();
        let config: ConfigV5 = toml::from_str(&after_master).unwrap();
        let bodies = PackBodiesV5::new(BTreeMap::from([
            (Id::new("policy").unwrap(), Arc::from("||after.example^\n")),
            (Id::new("new").unwrap(), Arc::from("||new.example^\n")),
        ]));
        let snapshot =
            PolicySnapshot::from_target_v5(&config, &bodies, after.revision().to_string()).unwrap();
        Self {
            before,
            after,
            snapshot,
        }
    }

    fn initialize(&self, root: &Path) {
        fs::create_dir(root.join("packs")).unwrap();
        for member in self.before.members() {
            let PolicyMemberState::Present(bytes) = member.state() else {
                unreachable!()
            };
            fs::write(root.join(member.path()), bytes).unwrap();
            fs::set_permissions(root.join(member.path()), fs::Permissions::from_mode(0o640))
                .unwrap();
        }
    }

    fn request(&self) -> TransactionRequest {
        TransactionRequest {
            actor: "publisher-recovery-test".into(),
            request_id: "reserved-before-prepare".into(),
            origin: "rest".into(),
            operation: "operator_rules.batch.v1".into(),
            payload: b"original request".to_vec(),
            expected_revision: self.before.revision(),
            source_schema: 5,
            target_schema: 5,
        }
    }
}

fn receipts_for(guard: &MigrationWriteLock) -> ReceiptStore {
    ReceiptStore::open(
        &crate::config::state_dir::open_for_migration(guard).unwrap(),
        guard,
    )
    .unwrap()
}

#[test]
fn publication_before_prepare_crash_child() {
    let Some(root) = std::env::var_os("WARDEN_PUBLICATION_BEFORE_PREPARE_ROOT") else {
        return;
    };
    let candidate = Candidate::new();
    let guard = acquire_for_migration(&Path::new(&root).join("config.toml")).unwrap();
    if let Ok(boundary) = std::env::var("WARDEN_BOUND_RESERVATION_CRASH_BOUNDARY") {
        crate::cluster::publication::kill_at_reservation_boundary(&boundary);
    }
    reserve(
        &guard,
        &receipts_for(&guard),
        &candidate.snapshot,
        &candidate.request(),
        &candidate.before,
        &candidate.after,
    )
    .unwrap();
    unsafe { libc::_exit(94) };
}

#[test]
fn crash_after_binding_before_prepare_aborts_durably_without_reusing_the_epoch() {
    let root = tempfile::tempdir().unwrap();
    let candidate = Candidate::new();
    candidate.initialize(root.path());
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "cluster::publisher::recovery_tests::publication_before_prepare_crash_child",
        ])
        .env("WARDEN_PUBLICATION_BEFORE_PREPARE_ROOT", root.path())
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(94));
    let guard = acquire_for_migration(&root.path().join("config.toml")).unwrap();
    let receipts = receipts_for(&guard);
    let previous_epoch = {
        let mut store = PublicationStore::open(&guard).unwrap();
        let pending = store.pending_intents().unwrap();
        assert_eq!(pending.len(), 1);
        let epoch = pending[0].0.policy_epoch;
        recover(&guard, &receipts, &mut store).unwrap();
        assert!(store.pending_intents().unwrap().is_empty());
        assert!(store.current().unwrap().is_none());
        epoch
    };
    {
        let mut store = PublicationStore::open(&guard).unwrap();
        recover(&guard, &receipts, &mut store).unwrap();
        assert!(store.pending_intents().unwrap().is_empty());
    }
    assert_eq!(
        fs::read(root.path().join("packs/policy.txt")).unwrap(),
        b"||before.example^\n"
    );
    assert!(!root.path().join("packs/new.txt").exists());
    let next = reserve(
        &guard,
        &receipts,
        &candidate.snapshot,
        &candidate.request(),
        &candidate.before,
        &candidate.after,
    )
    .unwrap();
    assert!(next.reservation.policy_epoch > previous_epoch);
}

#[test]
fn bound_reservation_crashes_never_leave_an_unbound_pending_epoch() {
    for boundary in ["epoch", "candidate", "reservation"] {
        let root = tempfile::tempdir().unwrap();
        let candidate = Candidate::new();
        candidate.initialize(root.path());
        let metadata: Vec<_> = candidate
            .before
            .members()
            .iter()
            .map(|member| fs::metadata(root.path().join(member.path())).unwrap())
            .collect();
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "cluster::publisher::recovery_tests::publication_before_prepare_crash_child",
            ])
            .env("WARDEN_PUBLICATION_BEFORE_PREPARE_ROOT", root.path())
            .env("WARDEN_BOUND_RESERVATION_CRASH_BOUNDARY", boundary)
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(77), "{boundary}");
        let guard = acquire_for_migration(&root.path().join("config.toml")).unwrap();
        let receipts = receipts_for(&guard);
        {
            let mut store = PublicationStore::open(&guard).unwrap();
            let pending = store.pending_intents().unwrap();
            assert_eq!(pending.len(), usize::from(boundary == "reservation"));
            if let Some((reservation, envelope)) = pending.first() {
                assert_eq!(reservation.policy_epoch, 1);
                assert_eq!(
                    store.bound_intent(reservation).unwrap().as_ref(),
                    Some(envelope)
                );
                assert!(store.preparation_proof(reservation).unwrap().is_some());
            }
            assert!(store.current().unwrap().is_none());
            recover(&guard, &receipts, &mut store).unwrap();
            assert!(store.pending_intents().unwrap().is_empty());
            assert!(store.current().unwrap().is_none());
        }
        {
            let mut store = PublicationStore::open(&guard).unwrap();
            recover(&guard, &receipts, &mut store).unwrap();
            assert!(store.pending_intents().unwrap().is_empty());
            assert!(store.current().unwrap().is_none());
        }
        for (member, before) in candidate.before.members().iter().zip(&metadata) {
            let PolicyMemberState::Present(bytes) = member.state() else {
                unreachable!()
            };
            let path = root.path().join(member.path());
            assert_eq!(fs::read(&path).unwrap(), *bytes, "{boundary}");
            let after = fs::metadata(path).unwrap();
            assert_eq!(
                (
                    after.dev(),
                    after.ino(),
                    after.uid(),
                    after.gid(),
                    after.mode()
                ),
                (
                    before.dev(),
                    before.ino(),
                    before.uid(),
                    before.gid(),
                    before.mode()
                ),
                "{boundary}"
            );
        }
        assert!(!root.path().join("packs/new.txt").exists());
        let next = reserve(
            &guard,
            &receipts,
            &candidate.snapshot,
            &candidate.request(),
            &candidate.before,
            &candidate.after,
        )
        .unwrap();
        assert_eq!(next.reservation.policy_epoch, 2, "{boundary}");
    }
}

#[test]
fn absent_receipt_with_before_drift_or_occupied_new_target_preserves_the_intent() {
    for drift in [
        "master",
        "pack-bytes",
        "pack-inode",
        "pack-mode",
        "new-target",
    ] {
        let root = tempfile::tempdir().unwrap();
        let candidate = Candidate::new();
        candidate.initialize(root.path());
        let guard = acquire_for_migration(&root.path().join("config.toml")).unwrap();
        let receipts = receipts_for(&guard);
        let intent = reserve(
            &guard,
            &receipts,
            &candidate.snapshot,
            &candidate.request(),
            &candidate.before,
            &candidate.after,
        )
        .unwrap();
        let path = root.path().join(match drift {
            "master" => "config.toml",
            "new-target" => "packs/new.txt",
            _ => "packs/policy.txt",
        });
        match drift {
            "pack-inode" => {
                let body = fs::read(&path).unwrap();
                fs::rename(&path, root.path().join("original-pack")).unwrap();
                fs::write(&path, body).unwrap();
                fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
            }
            "pack-mode" => fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap(),
            _ => fs::write(&path, b"foreign bytes\n").unwrap(),
        }
        let foreign = fs::read(&path).unwrap();
        for _ in 0..2 {
            let mut store = PublicationStore::open(&guard).unwrap();
            assert!(recover(&guard, &receipts, &mut store).is_err(), "{drift}");
            assert_eq!(store.pending_intents().unwrap()[0].0, intent.reservation);
            assert!(store.current().unwrap().is_none());
            assert_eq!(fs::read(&path).unwrap(), foreign);
        }
    }
}

#[test]
fn legacy_binding_without_a_preparation_proof_is_not_cancellation_evidence() {
    let root = tempfile::tempdir().unwrap();
    let candidate = Candidate::new();
    candidate.initialize(root.path());
    let guard = acquire_for_migration(&root.path().join("config.toml")).unwrap();
    let receipts = receipts_for(&guard);
    let reservation = {
        let mut store = PublicationStore::open(&guard).unwrap();
        let intent = PublicationIntent::reserve_for_request(
            &mut store,
            &candidate.snapshot,
            &candidate.request(),
        )
        .unwrap();
        store
            .bind_intent(
                &intent.reservation,
                intent.binding.operation_manifest().unwrap(),
            )
            .unwrap();
        intent.reservation
    };
    let mut store = PublicationStore::open(&guard).unwrap();
    assert!(recover(&guard, &receipts, &mut store).is_err());
    assert_eq!(store.pending_intents().unwrap()[0].0, reservation);
    assert!(store.current().unwrap().is_none());
    assert_eq!(
        fs::read(root.path().join("packs/policy.txt")).unwrap(),
        b"||before.example^\n"
    );
}
