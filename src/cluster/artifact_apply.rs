//! Apply a verified artifact through one guarded policy transaction.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{ensure, Context};
use rand_core::RngCore;
use tokio::sync::mpsc;

use super::artifact::verify_objects;
use super::ledger::{OwnershipLedger, OwnershipStore, RecoveryStatus};
use super::manifest::{Manifest, MAX_APPLY_BYTES, MAX_APPLY_FILES};
use super::transaction::{
    expected_objects, prepare_apply_verified, EvidenceResolver, ExistingReceiptAdapter, BUNDLE_PATH,
};
use crate::config::custom_list::PackOverlay;
use crate::config::loader::{self, LoadedConfigV5, LoaderOverlay};
use crate::config::policy_revision::{
    self, PolicyMemberKind, PolicyMemberState, PolicyRevisionInventory, PolicyRevisionMember,
};
use crate::config::policy_transaction::{
    self, Persistence, PrepareOutcome, ReceiptStore, RecoveryOutcome,
};
use crate::config::schema::{ClusterRole, Id};
use crate::config::write_lock::{acquire_for_migration, MigrationWriteLock};

pub(crate) async fn apply_artifact(
    config_path: &Path,
    manifest: Manifest,
    objects: BTreeMap<String, Arc<[u8]>>,
    reload_tx: &mpsc::Sender<Option<u32>>,
    candidate_runtime: Arc<crate::operator_rules::PolicyCandidateRuntime>,
) -> anyhow::Result<OwnershipLedger> {
    let path = config_path.to_path_buf();
    let ledger = tokio::task::spawn_blocking(move || {
        apply_with_runtime(
            &path,
            &manifest,
            &objects,
            &ExistingReceiptAdapter,
            &candidate_runtime,
            None,
        )
    })
    .await
    .context("artifact apply task panicked")??;
    reload_tx
        .send(None)
        .await
        .context("reload channel closed after artifact persisted")?;
    Ok(ledger)
}

pub(crate) fn load_persisted(config_path: &Path) -> anyhow::Result<Option<OwnershipLedger>> {
    load_with_resolver(config_path, &ExistingReceiptAdapter)
}

pub(crate) fn load_persisted_with_active(
    config_path: &Path,
    active: &crate::operator_rules::activation::ActivePolicyIdentity,
) -> anyhow::Result<(Option<OwnershipLedger>, bool)> {
    load_with_resolver_and_active(config_path, &ExistingReceiptAdapter, Some(active))
}

fn load_with_resolver(
    config_path: &Path,
    resolver: &impl EvidenceResolver,
) -> anyhow::Result<Option<OwnershipLedger>> {
    Ok(load_with_resolver_and_active(config_path, resolver, None)?.0)
}

fn load_with_resolver_and_active(
    config_path: &Path,
    resolver: &impl EvidenceResolver,
    active: Option<&crate::operator_rules::activation::ActivePolicyIdentity>,
) -> anyhow::Result<(Option<OwnershipLedger>, bool)> {
    let guard = acquire_for_migration(config_path)?;
    let receipts = open_receipts(&guard)?;
    recover_policy(&guard, &receipts)?;
    let mut ownership = OwnershipStore::open(&guard)?;
    settle_pending(&mut ownership, &receipts, resolver)?;
    let current = ownership.current().cloned();
    let mut active_revision_attested = false;
    if let Some(ledger) = &current {
        let loaded = load_current(&guard)?;
        ownership.preflight(
            &ledger.manifest,
            &local_declarations(&guard, &loaded)?,
            true,
        )?;
        if let Some(active) = active {
            active_revision_attested = if active.config_revision == ledger.config_revision {
                true
            } else {
                let (snapshot, loaded) =
                    policy_revision::capture_coherent_loaded_v5_under_migration_guard(
                        &guard,
                        &loaded,
                        time::OffsetDateTime::now_utc(),
                    )?;
                snapshot.revision().to_string() == active.config_revision
                    && super::artifact::replicated_policy_object(&loaded.config)?
                        == ledger.manifest.policy_toml
            };
        }
    } else {
        ensure!(
            guard
                .tree_io()
                .plan_root_file_no_follow(Path::new(BUNDLE_PATH))?
                .is_new(),
            "ArtifactEnrollmentRequired: existing policy has no ownership ledger"
        );
    }
    Ok((current, active_revision_attested))
}

/// A resolver must return verified transaction member evidence. Aggregate-only
/// adapters are refused before admission or policy mutation.
#[cfg(test)]
pub(crate) fn apply_with_resolver(
    config_path: &Path,
    manifest: &Manifest,
    objects: &BTreeMap<String, Arc<[u8]>>,
    resolver: &impl EvidenceResolver,
) -> anyhow::Result<OwnershipLedger> {
    let admission = crate::filter::operator_rules::CompileAdmission::new(
        crate::filter::operator_rules::RuleCompileLimits::HARD_CEILINGS
            .max_compiled_bytes_total
            .checked_mul(2)
            .context("test admission ceiling overflow")?,
        1,
    )?;
    let runtime = crate::operator_rules::PolicyCandidateRuntime::new(admission);
    apply_with_runtime(config_path, manifest, objects, resolver, &runtime, None)
}

#[cfg(test)]
fn apply_with_resolver_limits(
    config_path: &Path,
    manifest: &Manifest,
    objects: &BTreeMap<String, Arc<[u8]>>,
    resolver: &impl EvidenceResolver,
    receiver_limits: Option<crate::filter::operator_rules::RuleCompileLimits>,
) -> anyhow::Result<OwnershipLedger> {
    let limit = receiver_limits
        .as_ref()
        .map_or(
            crate::filter::operator_rules::RuleCompileLimits::HARD_CEILINGS
                .max_compiled_bytes_total,
            |limits| limits.max_compiled_bytes_total,
        )
        .checked_mul(2)
        .context("test admission ceiling overflow")?;
    let admission = crate::filter::operator_rules::CompileAdmission::new(limit, 1)?;
    let runtime = crate::operator_rules::PolicyCandidateRuntime::new(admission);
    apply_with_runtime(
        config_path,
        manifest,
        objects,
        resolver,
        &runtime,
        receiver_limits,
    )
}

fn apply_with_runtime(
    config_path: &Path,
    manifest: &Manifest,
    objects: &BTreeMap<String, Arc<[u8]>>,
    resolver: &impl EvidenceResolver,
    candidate_runtime: &crate::operator_rules::PolicyCandidateRuntime,
    injected_limits: Option<crate::filter::operator_rules::RuleCompileLimits>,
) -> anyhow::Result<OwnershipLedger> {
    verify_objects(manifest, objects)?;
    ensure!(
        resolver.supports_member_evidence(),
        "TransactionMemberEvidenceUnavailable: artifact apply requires verified member evidence"
    );
    let guard = acquire_for_migration(config_path)?;
    let receipts = open_receipts(&guard)?;
    recover_policy(&guard, &receipts)?;
    let mut ownership = OwnershipStore::open(&guard)?;
    settle_pending(&mut ownership, &receipts, resolver)?;
    let now = time::OffsetDateTime::now_utc();
    let loaded = load_current(&guard)?;
    ensure!(
        loaded.config.cluster.enabled && loaded.config.cluster.role == ClusterRole::Secondary,
        "ArtifactEnrollmentRequired: artifact receiver must be an enabled secondary"
    );
    let (snapshot, loaded) =
        policy_revision::capture_coherent_loaded_v5_under_migration_guard(&guard, &loaded, now)?;
    let bundle_exists = !guard
        .tree_io()
        .plan_root_file_no_follow(Path::new(BUNDLE_PATH))?
        .is_new();
    let local = local_declarations(&guard, &loaded)?;
    let plan = ownership.preflight(manifest, &local, bundle_exists)?;
    if plan.replay {
        return ownership
            .current()
            .cloned()
            .context("ArtifactOwnershipConflict: replay without ledger");
    }
    let before = snapshot.inventory();
    let after = candidate_inventory(before, manifest, objects, &plan.delete_paths)?;
    let limits = match injected_limits {
        Some(limits) => {
            limits.validate()?;
            limits
        }
        None => production_receiver_limits(&loaded.config.custom_list_limits)?,
    };
    super::admission::verify_for_receiver(manifest, objects, &limits)?;
    let (toml, packs) = candidate_overlays(&guard, before, &after)?;
    let validated = validate_candidate(&guard, &after, &toml, &packs, now)?;
    let semantic_packs = validated
        .pack_bodies
        .iter()
        .map(|(id, body)| crate::operator_rules::SemanticPack {
            id: id.as_str(),
            body: body.as_ref(),
        })
        .collect::<Vec<_>>();
    ensure!(
        crate::operator_rules::hash_policy_candidate(&validated.config, &semantic_packs)?
            .to_string()
            == manifest.operator_policy_hash,
        "ArtifactPolicyHashMismatch: local candidate changed replicated semantics"
    );
    let verified = candidate_runtime.compile(
        after.revision().to_string(),
        manifest.operator_policy_hash.clone(),
        &validated.config,
        &validated.pack_bodies,
    )?;
    if validated.config.cluster.membership_version == Some(1) {
        crate::cli::commands::start::preflight_received_corpus(
            config_path,
            &validated.config.validation_projection()?,
            &super::dto::ArtifactIdentity::from(manifest),
        )?;
    }
    let mut attempt = [0_u8; 16];
    rand_core::OsRng
        .try_fill_bytes(&mut attempt)
        .map_err(|error| anyhow::anyhow!("artifact request identity entropy: {error}"))?;
    let request_id = format!(
        "artifact:{}:{}:{}",
        manifest.policy_epoch,
        manifest.artifact_hash,
        hex::encode(attempt)
    );
    let actor = format!("cluster:{}", manifest.primary_lineage);
    let pending = ownership.begin(
        plan,
        manifest,
        before,
        &after.revision().to_string(),
        &actor,
        &request_id,
    )?;
    let prepared = prepare_apply_verified(
        &guard,
        &receipts,
        &pending,
        before,
        &after,
        Some(&verified),
        || Ok(()),
    );
    let receipt = match prepared {
        Ok(PrepareOutcome::Prepared(transaction)) => {
            ownership.bind_prepared(&transaction.receipt())?;
            transaction.commit()?
        }
        Ok(PrepareOutcome::Replay(receipt)) => *receipt,
        Err(error) => {
            // Recovery may settle a failure after Prepared. Its failure retains
            // the intent so another admission cannot prune the needed receipt.
            recover_policy(&guard, &receipts)?;
            settle_pending(&mut ownership, &receipts, resolver)?;
            return Err(error);
        }
    };
    ensure!(
        receipt.persistence == Persistence::Committed && !receipt.rollback_restored,
        "ArtifactRecoveryRequired: policy transaction has not committed"
    );
    let evidence = resolver
        .lookup(&guard, &receipts, &actor, &request_id)?
        .context("ArtifactRecoveryRequired: committed member evidence is unavailable")?;
    ensure!(
        evidence.receipt == receipt,
        "ArtifactIntentMismatch: receipt changed before ownership completion"
    );
    let ledger = ownership.complete(&evidence)?;
    if validated.config.cluster.membership_version == Some(1) {
        let store = super::corpus::CorpusStore::open(config_path)?;
        let corpus = store.manifest_for_artifact(&ledger.manifest.artifact_hash)?;
        store.install_manifest(&corpus)?;
        let retained = std::iter::once(ledger.manifest.artifact_hash.clone())
            .chain(
                ledger
                    .rollback_proofs
                    .iter()
                    .map(|proof| proof.manifest.artifact_hash.clone()),
            )
            .collect();
        store.retain_policy_artifacts(&retained)?;
    }
    candidate_runtime.remember_candidate(verified)?;
    Ok(ledger)
}

fn production_receiver_limits(
    limits: &crate::config::schema::CustomListLimitsV5,
) -> anyhow::Result<crate::filter::operator_rules::RuleCompileLimits> {
    Ok(crate::filter::operator_rules::RuleCompileLimits::try_from(
        limits,
    )?)
}

fn open_receipts(guard: &MigrationWriteLock) -> anyhow::Result<ReceiptStore> {
    ReceiptStore::open(&crate::config::state_dir::open_for_migration(guard)?, guard)
}

fn recover_policy(guard: &MigrationWriteLock, receipts: &ReceiptStore) -> anyhow::Result<()> {
    ensure!(
        policy_transaction::recover_active(guard, receipts)? != RecoveryOutcome::LegacyActive,
        "ArtifactRecoveryRequired: legacy migration is active"
    );
    Ok(())
}

fn settle_pending(
    ownership: &mut OwnershipStore<'_>,
    receipts: &ReceiptStore,
    resolver: &impl EvidenceResolver,
) -> anyhow::Result<()> {
    if ownership.pending().is_none() {
        return Ok(());
    }
    ensure!(
        !matches!(
            ownership.recover(receipts, resolver)?,
            RecoveryStatus::AwaitingReceipt
        ),
        "ArtifactRecoveryRequired: ownership intent lacks terminal evidence"
    );
    Ok(())
}

fn load_current(guard: &MigrationWriteLock) -> anyhow::Result<LoadedConfigV5> {
    loader::load_config_v5_with_policy_overlays_under_service_migration_guard(
        guard,
        guard.canonical_master(),
        time::OffsetDateTime::now_utc(),
        None,
        None,
    )
    .map_err(|error| anyhow::anyhow!("ArtifactValidationFailed: {error:?}"))
}

fn local_declarations(
    guard: &MigrationWriteLock,
    loaded: &LoadedConfigV5,
) -> anyhow::Result<Vec<Id>> {
    let bundle = guard.identity().root.join(BUNDLE_PATH);
    let mut local = Vec::new();
    for list in &loaded.config.custom_lists {
        let (path, _) = loaded
            .provenance
            .get(&format!("custom_lists.{}", list.id))
            .context("ArtifactEnrollmentRequired: Custom List provenance is missing")?;
        if path != &bundle {
            local.push(list.id.clone());
        }
    }
    Ok(local)
}

fn candidate_inventory(
    before: &PolicyRevisionInventory,
    manifest: &Manifest,
    objects: &BTreeMap<String, Arc<[u8]>>,
    delete_paths: &[String],
) -> anyhow::Result<PolicyRevisionInventory> {
    let expected = expected_objects(manifest);
    let changed: BTreeSet<_> = expected.keys().chain(delete_paths.iter()).collect();
    ensure!(
        changed.len() <= MAX_APPLY_FILES,
        "ArtifactLimitExceeded: apply member count"
    );
    let total = expected.values().try_fold(0_u64, |sum, object| {
        sum.checked_add(object.bytes)
            .context("ArtifactLimitExceeded: apply bytes overflow")
    })?;
    ensure!(
        total <= MAX_APPLY_BYTES as u64,
        "ArtifactLimitExceeded: apply bytes"
    );
    let mut members: Vec<_> = before
        .members()
        .iter()
        .filter(|member| {
            !expected.contains_key(&member.path().to_string_lossy().into_owned())
                && !delete_paths
                    .iter()
                    .any(|path| member.path() == Path::new(path))
        })
        .cloned()
        .collect();
    for (path, object) in expected {
        let kind = if path == BUNDLE_PATH {
            PolicyMemberKind::Include
        } else {
            PolicyMemberKind::Pack
        };
        members.push(PolicyRevisionMember::present(
            kind,
            PathBuf::from(path),
            objects
                .get(&object.sha256)
                .context("ArtifactInventoryMismatch: candidate object")?
                .to_vec(),
        )?);
    }
    Ok(PolicyRevisionInventory::new(members)?)
}

fn candidate_overlays(
    guard: &MigrationWriteLock,
    before: &PolicyRevisionInventory,
    after: &PolicyRevisionInventory,
) -> anyhow::Result<(LoaderOverlay, PackOverlay)> {
    let mut toml = LoaderOverlay::default();
    let mut packs = PackOverlay::default();
    for member in after.members() {
        let PolicyMemberState::Present(bytes) = member.state() else {
            anyhow::bail!("ArtifactInventoryMismatch: absent candidate member");
        };
        if member.kind() == PolicyMemberKind::Pack {
            packs.stage(pack_id(member.path())?, bytes.clone());
        } else {
            let plan = guard.tree_io().plan_root_file_no_follow(member.path())?;
            toml.stage_plan_reachable_only(&plan, String::from_utf8(bytes.clone())?)?;
        }
    }
    for member in before.members().iter().filter(|member| {
        !after
            .members()
            .iter()
            .any(|next| next.path() == member.path())
    }) {
        if member.kind() == PolicyMemberKind::Pack {
            packs.omit(pack_id(member.path())?);
        } else {
            toml.omit_plan(&guard.tree_io().plan_root_file_no_follow(member.path())?)?;
        }
    }
    Ok((toml, packs))
}

fn pack_id(path: &Path) -> anyhow::Result<Id> {
    Ok(Id::new(
        path.file_stem()
            .and_then(|part| part.to_str())
            .context("invalid pack path")?,
    )?)
}

fn validate_candidate(
    guard: &MigrationWriteLock,
    after: &PolicyRevisionInventory,
    toml: &LoaderOverlay,
    packs: &PackOverlay,
    now: time::OffsetDateTime,
) -> anyhow::Result<LoadedConfigV5> {
    let loaded = loader::load_config_v5_with_policy_overlays_under_service_migration_guard(
        guard,
        guard.canonical_master(),
        now,
        Some(toml),
        Some(packs),
    )
    .map_err(|error| anyhow::anyhow!("ArtifactValidationFailed: {error:?}"))?;
    let expected_files: BTreeSet<_> = after
        .members()
        .iter()
        .filter(|member| member.kind() != PolicyMemberKind::Pack)
        .map(|member| guard.identity().root.join(member.path()))
        .collect();
    let expected_packs: BTreeSet<_> = after
        .members()
        .iter()
        .filter(|member| member.kind() == PolicyMemberKind::Pack)
        .map(|member| pack_id(member.path()))
        .collect::<anyhow::Result<_>>()?;
    ensure!(
        loaded.files_loaded.iter().cloned().collect::<BTreeSet<_>>() == expected_files
            && loaded
                .config
                .custom_lists
                .iter()
                .map(|list| list.id.clone())
                .collect::<BTreeSet<_>>()
                == expected_packs,
        "ArtifactInventoryMismatch: candidate resolves a different inventory"
    );
    ensure!(
        local_declarations(guard, &loaded)?.is_empty(),
        "ArtifactEnrollmentRequired: candidate contains local Custom List declarations"
    );
    Ok(loaded)
}

#[cfg(test)]
mod tests {
    use super::super::transaction::{
        test_support::*, MemberEvidence, OperationBinding, OperationEvidence,
    };
    use super::*;
    use crate::config::policy_transaction::{MemberOperation, MemberRole};
    use std::cell::{Cell, RefCell};
    use std::fs;

    const MASTER: &str = "schema_version = 5\nincludes = [\"cluster.d/*.toml\"]\n[server]\nlisten = \"127.0.0.1:15354\"\nlog_level = \"trace\"\ntcp_timeout_secs = 37\n[cluster]\nenabled = true\nrole = \"secondary\"\npeer = \"https://192.0.2.1\"\ntoken_hash = \"fixture-token-hash\"\n";

    // This fixture supplies a test oracle at the transaction boundary. The
    // production adapter must supply the same DTO from verified journal data.
    struct FixtureResolver {
        manifest: RefCell<Manifest>,
        previous_paths: RefCell<BTreeSet<String>>,
        recorded: RefCell<BTreeMap<String, OperationEvidence>>,
        hide_once: Cell<bool>,
    }

    impl FixtureResolver {
        fn new(manifest: &Manifest) -> Self {
            Self {
                manifest: RefCell::new(manifest.clone()),
                previous_paths: RefCell::new(BTreeSet::new()),
                recorded: RefCell::new(BTreeMap::new()),
                hide_once: Cell::new(false),
            }
        }
    }

    impl EvidenceResolver for FixtureResolver {
        fn lookup(
            &self,
            guard: &MigrationWriteLock,
            receipts: &ReceiptStore,
            actor: &str,
            request_id: &str,
        ) -> anyhow::Result<Option<OperationEvidence>> {
            if let Some(evidence) = self.recorded.borrow().get(request_id) {
                return Ok(Some(evidence.clone()));
            }
            let Some(receipt) =
                policy_transaction::lookup_receipt(guard, receipts, actor, request_id)?
            else {
                return Ok(None);
            };
            let manifest = self.manifest.borrow();
            let binding =
                OperationBinding::for_apply(&manifest, &receipt.after_revision, actor, request_id)?;
            let mut members = Vec::new();
            if receipt.persistence == Persistence::Committed {
                members = fixture_members(&guard.identity().root, &manifest);
                let next: BTreeSet<_> = binding.objects.keys().cloned().collect();
                for path in self.previous_paths.borrow().difference(&next) {
                    members.push(MemberEvidence {
                        path: path.clone(),
                        role: MemberRole::Pack,
                        operation: Some(MemberOperation::Delete),
                        before: None,
                        after: None,
                        restored: None,
                    });
                }
                *self.previous_paths.borrow_mut() = next;
            }
            let evidence = OperationEvidence {
                receipt,
                operation_manifest: binding.operation_manifest()?,
                members,
            };
            self.recorded
                .borrow_mut()
                .insert(request_id.into(), evidence.clone());
            if self.hide_once.replace(false) {
                return Ok(None);
            }
            Ok(Some(evidence))
        }
    }

    fn receiver() -> (tempfile::TempDir, PathBuf) {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("config.toml");
        fs::write(&path, MASTER).unwrap();
        (root, path)
    }

    fn candidate_runtime() -> Arc<crate::operator_rules::PolicyCandidateRuntime> {
        Arc::new(crate::operator_rules::PolicyCandidateRuntime::new(
            crate::filter::operator_rules::CompileAdmission::new(
                crate::filter::operator_rules::RuleCompileLimits::HARD_CEILINGS
                    .max_compiled_bytes_total
                    * 2,
                1,
            )
            .unwrap(),
        ))
    }

    fn current_active_identity(
        path: &Path,
    ) -> crate::operator_rules::activation::ActivePolicyIdentity {
        let guard = acquire_for_migration(path).unwrap();
        let loaded = load_current(&guard).unwrap();
        let (snapshot, loaded) = policy_revision::capture_coherent_loaded_v5_under_migration_guard(
            &guard,
            &loaded,
            time::OffsetDateTime::now_utc(),
        )
        .unwrap();
        let packs = loaded
            .pack_bodies
            .iter()
            .map(|(id, body)| crate::operator_rules::SemanticPack {
                id: id.as_str(),
                body: body.as_ref(),
            })
            .collect::<Vec<_>>();
        crate::operator_rules::activation::ActivePolicyIdentity {
            daemon_instance_id: "receiver-daemon".into(),
            config_revision: snapshot.revision().to_string(),
            operator_policy_hash: crate::operator_rules::hash_policy_candidate(
                &loaded.config,
                &packs,
            )
            .unwrap()
            .to_string(),
            resolver_generation: 7,
        }
    }

    fn mounted_artifact(body: &str) -> (Manifest, BTreeMap<String, Arc<[u8]>>) {
        let id = Id::new("list").unwrap();
        let mut config = crate::config::schema::ConfigV5::default();
        config.upstream.servers = vec!["192.0.2.1:53".into()];
        config.server.default_profile = Some(Id::new("default").unwrap());
        config.custom_lists.push(crate::config::schema::CustomList {
            id: id.clone(),
            display_name: String::new(),
            description: String::new(),
        });
        config.profiles.insert(
            "default".into(),
            crate::config::schema::ProfileV5 {
                custom_lists: vec![id.clone()],
                ..Default::default()
            },
        );
        let snapshot = super::super::artifact::PolicySnapshot::from_target_v5(
            &config,
            &crate::config::target_v5::PackBodiesV5::new(BTreeMap::from([(id, Arc::from(body))])),
            "b".repeat(64),
        )
        .unwrap();
        let publication = snapshot.publication(&"a".repeat(64), 1).unwrap();
        (
            Manifest::decode(&publication.manifest).unwrap(),
            publication.objects,
        )
    }

    #[test]
    fn production_receiver_derives_every_compile_limit_from_node_local_config() {
        let local = crate::config::schema::CustomListLimitsV5 {
            max_lists: 11,
            max_file_bytes: 12,
            max_total_bytes: 13,
            max_rules_per_list: 14,
            max_indexed_rules_per_profile: 15,
            max_indexed_rules_total: 16,
            max_advanced_rules_per_profile: 17,
            max_advanced_rules_total: 18,
            max_regex_rules_per_profile: 19,
            max_regex_rules_total: 20,
            max_store_indexed_rules: 21,
            max_store_advanced_rules: 22,
            max_store_regex_rules: 23,
            max_rule_bytes: 24,
            max_regex_program_bytes: 25,
            max_store_compiled_bytes: 26,
            max_compiled_bytes_per_profile: 27,
            max_compiled_bytes_total: 28,
        };
        assert_eq!(
            production_receiver_limits(&local).unwrap(),
            crate::filter::operator_rules::RuleCompileLimits {
                max_lists: 11,
                max_file_bytes: 12,
                max_total_bytes: 13,
                max_rules_per_list: 14,
                max_indexed_rules_per_profile: 15,
                max_indexed_rules_total: 16,
                max_advanced_rules_per_profile: 17,
                max_advanced_rules_total: 18,
                max_regex_rules_per_profile: 19,
                max_regex_rules_total: 20,
                max_store_indexed_rules: 21,
                max_store_advanced_rules: 22,
                max_store_regex_rules: 23,
                max_rule_bytes: 24,
                max_regex_program_bytes: 25,
                max_store_compiled_bytes: 26,
                max_compiled_bytes_per_profile: 27,
                max_compiled_bytes_total: 28,
            }
        );
    }

    #[test]
    fn receiver_preserves_local_server_identity_fields() {
        let (root, path) = receiver();
        let (manifest, objects) = mounted_artifact("||one.example^\n");
        let resolver = FixtureResolver::new(&manifest);

        apply_with_resolver(&path, &manifest, &objects, &resolver).unwrap();

        let guard = acquire_for_migration(&path).unwrap();
        let loaded = load_current(&guard).unwrap();
        assert_eq!(
            loaded.config.server.listen,
            "127.0.0.1:15354".parse().unwrap()
        );
        assert_eq!(loaded.config.server.log_level, "trace");
        assert_eq!(loaded.config.server.tcp_timeout_secs, 37);
        assert!(root.path().join(BUNDLE_PATH).exists());
    }

    #[test]
    fn receiver_attests_a_node_local_revision_against_the_exact_replicated_policy() {
        let (_root, path) = receiver();
        let (manifest, objects) = mounted_artifact("||one.example^\n");
        let resolver = FixtureResolver::new(&manifest);
        let ledger = apply_with_resolver(&path, &manifest, &objects, &resolver).unwrap();
        fs::write(
            &path,
            format!("{MASTER}\n[node]\ncontrol_listen = \"127.0.0.2:8053\"\n"),
        )
        .unwrap();
        let active = current_active_identity(&path);

        assert_ne!(manifest.config_revision, ledger.config_revision);
        assert_ne!(active.config_revision, ledger.config_revision);
        assert_eq!(active.operator_policy_hash, manifest.operator_policy_hash);
        let (persisted, attested) = load_persisted_with_active(&path, &active).unwrap();
        assert_eq!(persisted.unwrap(), ledger);
        assert!(attested);
    }

    #[test]
    fn receiver_refuses_a_stale_local_revision_after_another_node_local_change() {
        let (_root, path) = receiver();
        let (manifest, objects) = mounted_artifact("||one.example^\n");
        let resolver = FixtureResolver::new(&manifest);
        apply_with_resolver(&path, &manifest, &objects, &resolver).unwrap();
        fs::write(
            &path,
            format!("{MASTER}\n[node]\ncontrol_listen = \"127.0.0.2:8053\"\n"),
        )
        .unwrap();
        let stale = current_active_identity(&path);
        fs::write(
            &path,
            format!("{MASTER}\n[node]\ncontrol_listen = \"127.0.0.2:8054\"\n"),
        )
        .unwrap();

        let (_, attested) = load_persisted_with_active(&path, &stale).unwrap();
        assert!(!attested);
    }

    #[test]
    fn receiver_refuses_owned_replicated_drift_even_when_the_semantic_hash_matches() {
        let (root, path) = receiver();
        let (manifest, objects) = mounted_artifact("||one.example^\n");
        let resolver = FixtureResolver::new(&manifest);
        apply_with_resolver(&path, &manifest, &objects, &resolver).unwrap();
        let bundle = root.path().join(BUNDLE_PATH);
        let changed = fs::read_to_string(&bundle)
            .unwrap()
            .replace("192.0.2.1:53", "192.0.2.9:53");
        fs::write(&bundle, changed).unwrap();
        let active = current_active_identity(&path);

        assert_eq!(active.operator_policy_hash, manifest.operator_policy_hash);
        assert!(load_persisted_with_active(&path, &active).is_err());
    }

    #[test]
    fn receiver_refuses_pack_drift_before_local_revision_attestation() {
        let (root, path) = receiver();
        let (manifest, objects) = mounted_artifact("||one.example^\n");
        let resolver = FixtureResolver::new(&manifest);
        let ledger = apply_with_resolver(&path, &manifest, &objects, &resolver).unwrap();
        fs::write(root.path().join("packs/list.txt"), "||other.example^\n").unwrap();
        let active = crate::operator_rules::activation::ActivePolicyIdentity {
            daemon_instance_id: "receiver-daemon".into(),
            config_revision: ledger.config_revision.clone(),
            operator_policy_hash: manifest.operator_policy_hash.clone(),
            resolver_generation: 7,
        };

        assert!(load_persisted_with_active(&path, &active).is_err());
    }

    #[test]
    fn receiver_rejects_a_local_redefinition_of_a_replicated_policy_field() {
        let (root, path) = receiver();
        fs::write(
            &path,
            format!(
                "{}\n[profiles.local]\n",
                MASTER.replace(
                    "tcp_timeout_secs = 37\n",
                    "tcp_timeout_secs = 37\ndefault_profile = \"local\"\n",
                )
            ),
        )
        .unwrap();
        let (manifest, objects) = mounted_artifact("||one.example^\n");
        let resolver = FixtureResolver::new(&manifest);

        let error = apply_with_resolver(&path, &manifest, &objects, &resolver).unwrap_err();

        let message = format!("{error:#}");
        assert!(message.contains("DuplicateId"), "{message}");
        assert!(message.contains("server.default_profile"), "{message}");
        assert!(!root.path().join(BUNDLE_PATH).exists());
    }

    #[test]
    fn production_receiver_enforces_local_source_projection_regex_and_compiled_caps() {
        const BODY: &str = "||one.example^\n||two.example^\n/first/\n/second/\n";
        for (field, lower) in [
            ("max_file_bytes", 1),
            ("max_total_bytes", 1),
            ("max_rules_per_list", 1),
            ("max_indexed_rules_per_profile", 1),
            ("max_store_indexed_rules", 1),
            ("max_regex_rules_per_profile", 1),
            ("max_store_regex_rules", 1),
            ("max_store_compiled_bytes", 1),
            ("max_compiled_bytes_per_profile", 1),
            ("max_compiled_bytes_total", 1),
        ] {
            let (root, path) = receiver();
            let (manifest, objects) = mounted_artifact(BODY);
            let resolver = FixtureResolver::new(&manifest);
            fs::write(
                &path,
                format!("{MASTER}\n[custom_list_limits]\n{field} = {lower}\n"),
            )
            .unwrap();
            let error = apply_with_resolver(&path, &manifest, &objects, &resolver).unwrap_err();
            assert!(
                format!("{error:#}").contains(field),
                "{field} was not enforced by production receiver: {error:#}"
            );
            assert!(!root.path().join(BUNDLE_PATH).exists(), "{field}");
            assert!(!root.path().join("packs").exists(), "{field}");
        }
    }

    #[tokio::test]
    async fn async_receiver_installs_complete_artifact_and_signals_reload() {
        const POLICY: &str = r#"schema_version = 5
[server]
default_profile = "default"
[profiles.default]
display_name = "Default"
custom_lists = ["streaming"]
[upstream]
servers = ["192.0.2.1:53"]
[[custom_lists]]
id = "streaming"
display_name = "Streaming"
[[devices]]
id = "tablet"
display_name = "Tablet"
ip = "192.0.2.50"
profile = "default"
"#;
        const PACK: &[u8] = b"||video.example^\n";

        let (root, path) = receiver();
        let original_master = fs::read(&path).unwrap();
        let config: crate::config::schema::ConfigV5 = toml::from_str(POLICY).unwrap();
        let snapshot = super::super::artifact::PolicySnapshot::from_target_v5(
            &config,
            &crate::config::target_v5::PackBodiesV5::new(BTreeMap::from([(
                Id::new("streaming").unwrap(),
                Arc::from(std::str::from_utf8(PACK).unwrap()),
            )])),
            "b".repeat(64),
        )
        .unwrap();
        let publication = snapshot.publication(&"a".repeat(64), 1).unwrap();
        let manifest = Manifest::decode(&publication.manifest).unwrap();
        let (reload_tx, mut reload_rx) = mpsc::channel(1);

        let runtime = candidate_runtime();
        let ledger = apply_artifact(
            &path,
            manifest.clone(),
            publication.objects,
            &reload_tx,
            Arc::clone(&runtime),
        )
        .await
        .unwrap();

        assert_eq!(reload_rx.try_recv().unwrap(), None);
        assert_eq!(fs::read(&path).unwrap(), original_master);
        let installed = fs::read_to_string(root.path().join(BUNDLE_PATH)).unwrap();
        assert!(installed.contains("tablet"));
        assert!(installed.contains("streaming"));
        assert_eq!(
            fs::read(root.path().join("packs/streaming.txt")).unwrap(),
            PACK
        );
        assert_eq!(ledger.manifest, manifest);
        assert!(runtime
            .matching(
                &ledger.config_revision,
                &ledger.manifest.operator_policy_hash
            )
            .unwrap()
            .is_some());
        assert_eq!(ledger, load_persisted(&path).unwrap().unwrap());
    }

    #[test]
    fn production_adapter_applies_replays_replaces_and_deletes_owned_members() {
        let (root, path) = receiver();
        let (first, objects) = artifact(1, &[("list", "example.org\n")]);
        let ledger = apply_with_resolver(&path, &first, &objects, &ExistingReceiptAdapter).unwrap();
        assert_eq!(ledger, load_persisted(&path).unwrap().unwrap());
        assert_eq!(
            ledger,
            apply_with_resolver(&path, &first, &objects, &ExistingReceiptAdapter).unwrap()
        );
        let (next, objects) = artifact(2, &[("list", "changed.example\n")]);
        let replaced =
            apply_with_resolver(&path, &next, &objects, &ExistingReceiptAdapter).unwrap();
        assert_ne!(ledger.transaction_id, replaced.transaction_id);
        assert_eq!(
            replaced.entries[BUNDLE_PATH].identity,
            ledger.entries[BUNDLE_PATH].identity
        );
        assert_eq!(
            replaced.entries["packs/list.txt"].transaction_id,
            replaced.transaction_id
        );
        assert_eq!(replaced, load_persisted(&path).unwrap().unwrap());
        let (unchanged, objects) = artifact(3, &[("list", "changed.example\n")]);
        let carried =
            apply_with_resolver(&path, &unchanged, &objects, &ExistingReceiptAdapter).unwrap();
        for (path, member) in &carried.entries {
            assert_eq!(member.identity, replaced.entries[path].identity);
            assert_eq!(member.transaction_id, carried.transaction_id);
        }
        assert_eq!(carried.receipt.changed_members, 0);
        {
            let guard = acquire_for_migration(&path).unwrap();
            let evidence = ExistingReceiptAdapter
                .lookup(
                    &guard,
                    &open_receipts(&guard).unwrap(),
                    &carried.receipt.actor,
                    &carried.receipt.request_id,
                )
                .unwrap()
                .unwrap();
            assert_eq!(evidence.members.len(), carried.entries.len() + 1);
            assert!(evidence
                .members
                .iter()
                .all(|member| member.operation.is_none()
                    && member
                        .after
                        .as_ref()
                        .map(super::super::transaction::MemberBeforeState::from)
                        == member.before));
        }
        assert_eq!(carried, load_persisted(&path).unwrap().unwrap());
        let (last, objects) = artifact(4, &[]);
        apply_with_resolver(&path, &last, &objects, &ExistingReceiptAdapter).unwrap();
        assert!(!root.path().join("packs/list.txt").exists());
        assert_eq!(fs::read_to_string(&path).unwrap(), MASTER);
    }

    #[test]
    fn production_adapter_recovers_abort_before_promotion() {
        let (root, path) = receiver();
        let (manifest, objects) = artifact(1, &[("list", "example.org\n")]);
        policy_transaction::fail_after_prepared_for_test();
        assert!(apply_with_resolver(&path, &manifest, &objects, &ExistingReceiptAdapter).is_err());
        assert!(load_persisted(&path).unwrap().is_none());
        assert!(!root.path().join(BUNDLE_PATH).exists());
        assert!(!root.path().join("packs/list.txt").exists());
        apply_with_resolver(&path, &manifest, &objects, &ExistingReceiptAdapter).unwrap();
    }

    #[test]
    fn production_adapter_retains_recorded_identity_after_live_path_replacement() {
        let (root, path) = receiver();
        let (manifest, objects) = artifact(1, &[("list", "example.org\n")]);
        let ledger =
            apply_with_resolver(&path, &manifest, &objects, &ExistingReceiptAdapter).unwrap();
        let pack = root.path().join("packs/list.txt");
        let old = fs::File::open(&pack).unwrap();
        fs::remove_file(&pack).unwrap();
        fs::write(&pack, b"example.org\n").unwrap();
        let guard = acquire_for_migration(&path).unwrap();
        let evidence = ExistingReceiptAdapter
            .lookup(
                &guard,
                &open_receipts(&guard).unwrap(),
                &ledger.receipt.actor,
                &ledger.receipt.request_id,
            )
            .unwrap()
            .unwrap();
        assert_eq!(
            evidence
                .members
                .iter()
                .find(|member| member.path == "packs/list.txt")
                .unwrap()
                .after
                .as_ref(),
            Some(&ledger.entries["packs/list.txt"].identity)
        );
        drop(guard);
        assert!(load_persisted(&path).is_err());
        drop(old);
    }

    #[test]
    fn apply_replay_and_owned_removal_preserve_unowned_files() {
        let (root, path) = receiver();
        let (first, objects) = artifact(1, &[("list", "example.org\n")]);
        let resolver = FixtureResolver::new(&first);
        let ledger = apply_with_resolver(&path, &first, &objects, &resolver).unwrap();
        assert_eq!(ledger.manifest.artifact_hash, first.artifact_hash);
        assert_eq!(fs::read_to_string(&path).unwrap(), MASTER);
        let replay = apply_with_resolver(&path, &first, &objects, &resolver).unwrap();
        assert_eq!(replay.transaction_id, ledger.transaction_id);
        fs::write(root.path().join("packs/stray.txt"), b"stray.example\n").unwrap();
        fs::write(root.path().join("cluster.d/extra.toml"), b"# unmanaged\n").unwrap();
        let (second, objects) = artifact(2, &[]);
        *resolver.manifest.borrow_mut() = second.clone();
        let ledger = apply_with_resolver(&path, &second, &objects, &resolver).unwrap();
        assert_eq!(ledger.entries.len(), 1);
        assert!(!root.path().join("packs/list.txt").exists());
        assert_eq!(
            fs::read(root.path().join("packs/stray.txt")).unwrap(),
            b"stray.example\n"
        );
        assert_eq!(
            fs::read(root.path().join("cluster.d/extra.toml")).unwrap(),
            b"# unmanaged\n"
        );
    }

    #[test]
    fn committed_policy_waits_for_exact_evidence_then_recovers_pending() {
        let (root, path) = receiver();
        let (manifest, objects) = artifact(1, &[("list", "example.org\n")]);
        let resolver = FixtureResolver::new(&manifest);
        resolver.hide_once.set(true);
        assert!(apply_with_resolver(&path, &manifest, &objects, &resolver).is_err());
        assert!(root.path().join(BUNDLE_PATH).exists());
        assert!(load_persisted(&path).unwrap().is_some());
        let recovered = load_with_resolver(&path, &resolver).unwrap().unwrap();
        assert_eq!(recovered.manifest, manifest);
        assert_eq!(load_persisted(&path).unwrap().unwrap(), recovered);
    }

    #[test]
    fn failed_prepared_transaction_recovers_without_installing_policy() {
        let (root, path) = receiver();
        let (manifest, objects) = artifact(1, &[]);
        let resolver = FixtureResolver::new(&manifest);
        policy_transaction::fail_after_prepared_for_test();
        assert!(apply_with_resolver(&path, &manifest, &objects, &resolver).is_err());
        assert!(!root.path().join(BUNDLE_PATH).exists());
        assert!(load_with_resolver(&path, &resolver).unwrap().is_none());
        assert_eq!(fs::read_to_string(&path).unwrap(), MASTER);
        apply_with_resolver(&path, &manifest, &objects, &resolver).unwrap();
    }

    #[test]
    fn unsupported_adapter_and_invalid_objects_do_not_mutate_policy() {
        struct Unsupported;
        impl EvidenceResolver for Unsupported {
            fn lookup(
                &self,
                _: &MigrationWriteLock,
                _: &ReceiptStore,
                _: &str,
                _: &str,
            ) -> anyhow::Result<Option<OperationEvidence>> {
                panic!("unsupported adapter must be rejected before lookup")
            }
            fn supports_member_evidence(&self) -> bool {
                false
            }
        }
        let (root, path) = receiver();
        let (manifest, mut objects) = artifact(1, &[]);
        let error = apply_with_resolver(&path, &manifest, &objects, &Unsupported).unwrap_err();
        assert!(error
            .to_string()
            .contains("TransactionMemberEvidenceUnavailable"));
        let resolver = FixtureResolver::new(&manifest);
        objects.insert(
            manifest.policy_toml.sha256.clone(),
            Arc::from(b"changed".as_slice()),
        );
        assert!(apply_with_resolver(&path, &manifest, &objects, &resolver).is_err());
        assert!(!root.path().join("cluster.d").exists());
        assert_eq!(fs::read_to_string(path).unwrap(), MASTER);
    }

    #[test]
    fn receiver_recounts_and_admits_before_preparing_or_promoting() {
        let (root, path) = receiver();
        let (manifest, objects) = artifact(1, &[("list", "||one.example^\n||two.example^\n")]);
        assert_eq!(manifest.requirements.store.indexed, 2);
        let resolver = FixtureResolver::new(&manifest);
        let mut forged = manifest.clone();
        forged.requirements.store.indexed = 1;
        forged.artifact_hash = forged.canonical_hash().unwrap();
        assert!(apply_with_resolver(&path, &forged, &objects, &resolver)
            .unwrap_err()
            .to_string()
            .contains("ArtifactRequirementsMismatch"));
        let limits = crate::filter::operator_rules::RuleCompileLimits {
            max_store_indexed_rules: 1,
            ..Default::default()
        };
        assert!(
            apply_with_resolver_limits(&path, &manifest, &objects, &resolver, Some(limits))
                .unwrap_err()
                .to_string()
                .contains("max_store_indexed_rules")
        );
        assert!(!root.path().join(BUNDLE_PATH).exists());
        assert!(!root.path().join("packs").exists());
        assert_eq!(fs::read_to_string(&path).unwrap(), MASTER);
        let guard = acquire_for_migration(&path).unwrap();
        let ownership = OwnershipStore::open(&guard).unwrap();
        assert!(ownership.current().is_none());
        assert!(ownership.pending().is_none());
        drop(ownership);
        drop(guard);
        apply_with_resolver(&path, &manifest, &objects, &resolver).unwrap();
    }

    #[test]
    fn schema5_receiver_compiles_advanced_rows_and_enforces_the_local_file_limit() {
        let (root, path) = receiver();
        let body = "||one.example^\n||*.advanced.example^\n/regex/\n";
        let (manifest, objects) = artifact(1, &[("list", body)]);
        assert_eq!(manifest.requirements.store.indexed, 2);
        assert_eq!(manifest.requirements.store.advanced, 2);
        assert_eq!(manifest.requirements.store.regex, 1);
        assert_eq!(manifest.requirements.store.skipped_rows, 0);
        let resolver = FixtureResolver::new(&manifest);
        fs::write(
            &path,
            format!("{MASTER}\n[custom_list_limits]\nmax_file_bytes = 1\n"),
        )
        .unwrap();
        assert!(apply_with_resolver(&path, &manifest, &objects, &resolver).is_err());
        assert!(!root.path().join(BUNDLE_PATH).exists());
        assert!(!root.path().join("packs").exists());
        fs::write(&path, MASTER).unwrap();
        apply_with_resolver(&path, &manifest, &objects, &resolver).unwrap();
        assert_eq!(
            fs::read_to_string(root.path().join("packs/list.txt")).unwrap(),
            body.trim_end()
        );
    }

    #[test]
    fn existing_bundle_without_ledger_and_noncolliding_local_declarations_refuse_enrollment() {
        let (root, path) = receiver();
        let (manifest, objects) = artifact(1, &[("remote", "remote.example\n")]);
        let resolver = FixtureResolver::new(&manifest);
        fs::create_dir(root.path().join("packs")).unwrap();
        fs::write(root.path().join("packs/local.txt"), b"local.example\n").unwrap();
        fs::write(
            &path,
            format!("{MASTER}\n[[custom_lists]]\nid = \"local\"\n"),
        )
        .unwrap();
        assert!(apply_with_resolver(&path, &manifest, &objects, &resolver).is_err());
        assert!(!root.path().join(BUNDLE_PATH).exists());
        fs::write(&path, MASTER).unwrap();
        install(root.path(), &manifest, &objects);
        assert!(apply_with_resolver(&path, &manifest, &objects, &resolver).is_err());
    }
}
