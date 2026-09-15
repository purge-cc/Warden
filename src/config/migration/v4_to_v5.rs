use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::Arc;

use anyhow::{bail, ensure, Context};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

use super::choices::{
    hex, row_digest, FindingDecisionV1, MigrationChoicesV1, MigrationDecisionV1,
    MigrationMappingKindV1, PLANNER_VERSION,
};
use super::v4::{HistoricalConfigV4, ResolverSourceV4};
use crate::config::custom_list::{pack_path, parse_pack_line, PackOverlay};
use crate::config::loader::{self, LoadedConfig, LoaderOverlay};
use crate::config::policy_revision::{
    self, PolicyMemberKind, PolicyMemberState, PolicyRevisionInventory, PolicyRevisionMember,
    PolicyRevisionSnapshot,
};
use crate::config::policy_transaction::{
    self, FinalizeOutcome, Persistence, PrepareOutcome, ReceiptPreparationContext,
    ReceiptSemanticContext, ReceiptStore, RollbackOutcome, TransactionRequest,
};
use crate::config::schema::{
    ClusterRole, ConfigV5, CustomList, CustomListLimitsV5, DeviceV5, Id, MigrationOriginV1,
    Profile, ProfileV5, ScheduleTargetType, TARGET_SCHEMA_VERSION_V5,
};
use crate::config::target_v5::{self, PackBodiesV5};
use crate::config::write_lock;
use crate::filter::operator_rules::{
    parse_rule_ast, CompileAdmission, OperatorPattern, OperatorRuleAst, RuleTier,
};
use crate::operator_rules::{
    hash_policy_candidate, hash_profile_policy_candidate, hash_schema4_migration_snapshot,
    SemanticPack,
};

const SOURCE_SCHEMA: u32 = 4;
const ACTOR: &str = "migration-v4-to-v5";
const OPERATION: &str = "config.migrate.v4-to-v5.v1";
const BOOTSTRAP_AUTHORIZATION: &str = "offline_v4_to_v5_executable_v1";
const PLAN_HASH_DOMAIN: &[u8] = b"warden/uor/v4-to-v5/plan/v1\0";
const MAX_MIGRATION_FINDINGS: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingCodeV1 {
    LatticeVerdictChanges,
    AllowGrantChanges,
    ResponseAuthorityChanges,
    DynamicProfileSource,
    OverlayPrecedenceNotRepresentable,
    AdvancedEquivalenceUnsupported,
    LegacyInactiveRule,
    InvalidLegacyGraph,
    TargetBudgetExceeded,
    DestinationCollision,
    ClusterLocalPolicyConflict,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EquivalenceV1 {
    Changed,
    Unproven,
    ChangedAccepted,
    UnprovenAccepted,
    Resolved,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationFindingV1 {
    pub finding_id: String,
    pub code: FindingCodeV1,
    pub scope: String,
    pub cause: String,
    pub equivalence: EquivalenceV1,
    pub blocking: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub before: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub witness: Option<String>,
    pub allowed_remedies: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationMappingV1 {
    pub kind: MigrationMappingKindV1,
    pub source_id: String,
    pub target_id: String,
    #[serde(default)]
    pub rule_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileCloneV1 {
    pub device_id: String,
    pub source_profile: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_group: Option<String>,
    pub target_profile: String,
    pub added_custom_list: String,
    pub source_policy_hash: String,
    pub resolver_source_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InventoryMemberV1 {
    pub path: String,
    pub role: String,
    pub digest: String,
    pub length: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FilesystemOperationKindV1 {
    Create,
    Replace,
    Delete,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FilesystemOperationV1 {
    pub path: String,
    pub operation: FilesystemOperationKindV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after_length: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationPlanV1 {
    pub planner_version: u32,
    pub plan_hash: String,
    pub source_schema: u32,
    pub target_schema: u32,
    pub source_config_revision: String,
    pub source_digest: String,
    pub source_operator_policy_hash: String,
    pub choices_digest: String,
    pub choices: MigrationChoicesV1,
    pub required_capabilities: Vec<String>,
    pub source_inventory: Vec<InventoryMemberV1>,
    pub candidate_inventory: Vec<InventoryMemberV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub candidate_config_revision: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub candidate_operator_policy_hash: Option<String>,
    pub mappings: Vec<MigrationMappingV1>,
    pub clones: Vec<ProfileCloneV1>,
    pub findings: Vec<MigrationFindingV1>,
    pub filesystem_operations: Vec<FilesystemOperationV1>,
    pub backup_bytes: u64,
    pub required_free_bytes: u64,
    pub blocked: bool,
}

impl MigrationPlanV1 {
    pub fn verify_hash(&self) -> anyhow::Result<()> {
        ensure!(
            self.plan_hash == compute_plan_hash(self)?,
            "plan hash does not match its content"
        );
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplyReceiptV1 {
    pub receipt_id: String,
    pub plan_hash: String,
    pub source_config_revision: String,
    pub candidate_config_revision: String,
    pub persistence: String,
    pub changed_members: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RollbackResultV1 {
    Restored {
        receipt_id: String,
        revision: String,
    },
    AlreadyRestored {
        receipt_id: String,
        revision: String,
    },
    NotApplicable,
    NotFound,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FinalizeResultV1 {
    Finalized { receipt_id: String },
    AlreadyFinalized { receipt_id: String },
    NotFound,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationLintFindingV1 {
    pub profile_id: String,
    pub code: String,
    pub detail: String,
}

struct BuiltCandidate {
    plan: MigrationPlanV1,
    inventory: Option<PolicyRevisionInventory>,
}

pub fn check(master: &Path) -> anyhow::Result<MigrationPlanV1> {
    plan(master, None)
}

pub fn plan(master: &Path, choices: Option<MigrationChoicesV1>) -> anyhow::Result<MigrationPlanV1> {
    let guard = write_lock::acquire_for_read(master)?;
    let now = OffsetDateTime::now_utc();
    let loaded =
        loader::load_config_for_schema_under_read_guard(&guard, master, SOURCE_SCHEMA, now)
            .map_err(load_errors)?;
    let (snapshot, loaded) = policy_revision::capture_coherent_loaded_under_read_guard(
        &guard,
        &loaded,
        SOURCE_SCHEMA,
        now,
    )?;
    Ok(build(&snapshot, &loaded, choices)?.plan)
}

pub fn apply(
    master: &Path,
    supplied_plan: &MigrationPlanV1,
    expected_plan_hash: &str,
) -> anyhow::Result<ApplyReceiptV1> {
    let pid_file = crate::cli::config_discovery::resolve_pid_file(None, master);
    apply_with_pid_file(master, &pid_file, supplied_plan, expected_plan_hash)
}

pub fn apply_with_pid_file(
    master: &Path,
    pid_file: &Path,
    supplied_plan: &MigrationPlanV1,
    expected_plan_hash: &str,
) -> anyhow::Result<ApplyReceiptV1> {
    supplied_plan.verify_hash()?;
    ensure!(
        expected_plan_hash == supplied_plan.plan_hash,
        "ExpectedPlanHashMismatch: explicit hash does not match the supplied plan"
    );
    let offline_lease = crate::config::runtime_lease::acquire_for_migration(master, pid_file)?;
    let guard = write_lock::acquire_for_migration(master)?;
    offline_lease.verify_migration_tree(&guard)?;
    let data = crate::config::state_dir::open_for_migration(&guard)?;
    let receipts = ReceiptStore::open(&data, &guard)?;
    if offline_lease.requires_migration_bootstrap() {
        policy_transaction::recover_bootstrap_migration(&guard, &receipts, |receipt| {
            verify_bootstrap_receipt(receipt)?;
            ensure!(
                receipt.operator_plan_hash.as_deref() == Some(expected_plan_hash)
                    && receipt.before_revision == supplied_plan.source_config_revision
                    && Some(&receipt.after_revision)
                        == supplied_plan.candidate_config_revision.as_ref(),
                "BootstrapRecoveryMismatch: active migration belongs to another approved plan"
            );
            Ok(())
        })?;
    } else {
        policy_transaction::recover_active(&guard, &receipts)?;
    }
    let base_request_id = format!("v4-to-v5-{}", &supplied_plan.plan_hash[..32]);
    let mut request_id = base_request_id.clone();
    let mut attempts = 0;
    while let Some(receipt) =
        policy_transaction::lookup_receipt_after_recovery(&guard, &receipts, ACTOR, &request_id)?
    {
        attempts += 1;
        ensure!(
            attempts < policy_transaction::MAX_RECEIPTS,
            "migration retry budget exceeded"
        );
        ensure!(
            receipt.operator_plan_hash.as_deref() == Some(expected_plan_hash)
                && receipt.before_revision == supplied_plan.source_config_revision
                && Some(&receipt.after_revision)
                    == supplied_plan.candidate_config_revision.as_ref(),
            "BootstrapRecoveryMismatch: receipt belongs to another approved plan"
        );
        if offline_lease.requires_migration_bootstrap() {
            verify_bootstrap_receipt(&receipt)?;
        }
        match receipt.persistence {
            Persistence::Committed if !receipt.rollback_restored => {
                return Ok(apply_receipt(receipt, expected_plan_hash));
            }
            Persistence::Aborted | Persistence::Committed => {
                request_id = format!("{base_request_id}-retry-{}", receipt.transaction_id);
            }
            Persistence::Prepared | Persistence::DurabilityUncertain => {
                bail!("MigrationRecoveryRequired: the previous attempt is not terminal");
            }
        }
    }
    let now = OffsetDateTime::now_utc();
    let loaded = loader::load_config_for_schema_under_migration_guard(
        &guard,
        guard.canonical_master(),
        SOURCE_SCHEMA,
        now,
    )
    .map_err(load_errors)?;
    let (snapshot, loaded) = policy_revision::capture_coherent_loaded_under_migration_guard(
        &guard,
        &loaded,
        SOURCE_SCHEMA,
        now,
    )?;
    let candidate = build(&snapshot, &loaded, Some(supplied_plan.choices.clone()))?;
    ensure!(
        candidate.plan.plan_hash == supplied_plan.plan_hash,
        "StalePlan: source tree or planner result changed; re-plan is required"
    );
    ensure!(
        !candidate.plan.blocked,
        "migration plan has unresolved findings"
    );
    ensure!(
        !(loaded.config.cluster.enabled && loaded.config.cluster.role == ClusterRole::Secondary),
        "ClusterLocalPolicyConflict: migrate a secondary only through an isolated deployment workflow"
    );
    let after = candidate
        .inventory
        .as_ref()
        .context("blocked plan has no candidate inventory")?;
    validate_candidate_under_guard(&guard, snapshot.inventory(), after, now)?;
    let mut manifest = receipt_manifest(&candidate.plan)?;
    if offline_lease.requires_migration_bootstrap() {
        manifest["bootstrap_authorization"] = BOOTSTRAP_AUTHORIZATION.into();
    }
    let request = TransactionRequest {
        request_id,
        actor: ACTOR.into(),
        origin: "migration".into(),
        operation: OPERATION.into(),
        payload: format!("warden/uor/v4-to-v5/apply/v1\0{}", candidate.plan.plan_hash).into_bytes(),
        expected_revision: snapshot.revision(),
        source_schema: SOURCE_SCHEMA as u64,
        target_schema: TARGET_SCHEMA_VERSION_V5 as u64,
    };
    let outcome = policy_transaction::prepare_with_hook_after_recovery(
        &guard,
        &receipts,
        &request,
        policy_transaction::PolicyRevisionTransition::new(snapshot.inventory(), after),
        ReceiptPreparationContext {
            operator_plan_hash: Some(&candidate.plan.plan_hash),
            semantic: ReceiptSemanticContext {
                before_policy_hash: Some(candidate.plan.source_operator_policy_hash.clone()),
                after_policy_hash: candidate.plan.candidate_operator_policy_hash.clone(),
                audit: migration_audit(&candidate.plan),
            },
            operation_manifest: Some(manifest),
        },
        || validate_candidate_under_guard(&guard, snapshot.inventory(), after, now),
        |_| {},
    )?;
    let receipt = match outcome {
        PrepareOutcome::Replay(receipt) => *receipt,
        PrepareOutcome::Prepared(transaction) => transaction.commit()?,
    };
    ensure!(
        receipt.persistence == Persistence::Committed,
        "MigrationRecoveryRequired: migration did not reach committed persistence"
    );
    Ok(apply_receipt(receipt, &candidate.plan.plan_hash))
}

fn apply_receipt(receipt: policy_transaction::BaseReceipt, plan_hash: &str) -> ApplyReceiptV1 {
    ApplyReceiptV1 {
        receipt_id: receipt.transaction_id,
        plan_hash: plan_hash.into(),
        source_config_revision: receipt.before_revision,
        candidate_config_revision: receipt.after_revision,
        persistence: persistence_name(receipt.persistence).into(),
        changed_members: receipt.changed_members,
    }
}

pub fn rollback(
    master: &Path,
    receipt_id: &str,
    expected_revision: &str,
) -> anyhow::Result<RollbackResultV1> {
    let pid_file = crate::cli::config_discovery::resolve_pid_file(None, master);
    rollback_with_pid_file(master, &pid_file, receipt_id, expected_revision)
}

pub fn rollback_with_pid_file(
    master: &Path,
    pid_file: &Path,
    receipt_id: &str,
    expected_revision: &str,
) -> anyhow::Result<RollbackResultV1> {
    let offline_lease = crate::config::runtime_lease::acquire_for_migration(master, pid_file)?;
    let guard = write_lock::acquire_for_migration(master)?;
    offline_lease.verify_migration_tree(&guard)?;
    let data = crate::config::state_dir::open_for_migration(&guard)?;
    let receipts = ReceiptStore::open(&data, &guard)?;
    if offline_lease.requires_migration_bootstrap() {
        policy_transaction::recover_bootstrap_migration(&guard, &receipts, |receipt| {
            verify_bootstrap_receipt(receipt)?;
            ensure!(
                receipt.transaction_id == receipt_id && receipt.after_revision == expected_revision,
                "BootstrapRecoveryMismatch: active migration belongs to another receipt"
            );
            Ok(())
        })?;
    } else {
        policy_transaction::recover_active(&guard, &receipts)?;
    }
    let Some(receipt) = policy_transaction::lookup_operation_receipt_after_recovery(
        &guard, &receipts, ACTOR, receipt_id,
    )?
    else {
        return Ok(RollbackResultV1::NotFound);
    };
    ensure!(
        receipt.after_revision == expected_revision,
        "RevisionConflict: --expect-revision does not match the migration receipt"
    );
    if offline_lease.requires_migration_bootstrap() {
        verify_bootstrap_receipt(&receipt)?;
    }
    let request_id = receipt.request_id.clone();
    match policy_transaction::rollback_migration_after_recovery(
        &guard,
        &receipts,
        ACTOR,
        &request_id,
        |recorded| {
            ensure!(
                recorded.transaction_id == receipt.transaction_id
                    && recorded.actor == receipt.actor
                    && recorded.request_id == receipt.request_id
                    && recorded.origin == receipt.origin
                    && recorded.operation == receipt.operation
                    && recorded.operator_plan_hash == receipt.operator_plan_hash
                    && recorded.before_revision == receipt.before_revision
                    && recorded.after_revision == receipt.after_revision
                    && recorded.operation_manifest == receipt.operation_manifest,
                "BootstrapAuthorizationMismatch: undo journal differs from the approved receipt"
            );
            if offline_lease.requires_migration_bootstrap() {
                verify_bootstrap_receipt(recorded)?;
            }
            Ok(())
        },
    )? {
        RollbackOutcome::NoReceipt => Ok(RollbackResultV1::NotFound),
        RollbackOutcome::RollbackNotApplicable => Ok(RollbackResultV1::NotApplicable),
        RollbackOutcome::Restored(restored) if receipt.rollback_restored => {
            Ok(RollbackResultV1::AlreadyRestored {
                receipt_id: restored.transaction_id,
                revision: restored.before_revision,
            })
        }
        RollbackOutcome::Restored(restored) => Ok(RollbackResultV1::Restored {
            receipt_id: restored.transaction_id,
            revision: restored.before_revision,
        }),
    }
}

fn verify_bootstrap_receipt(receipt: &policy_transaction::BaseReceipt) -> anyhow::Result<()> {
    let manifest = receipt
        .operation_manifest
        .as_ref()
        .context("BootstrapAuthorizationMissing: migration receipt has no manifest")?;
    let plan_hash = receipt
        .operator_plan_hash
        .as_deref()
        .context("BootstrapAuthorizationMissing: migration receipt has no approved plan hash")?;
    let base_request_id = format!("v4-to-v5-{}", plan_hash.get(..32).unwrap_or_default());
    let retry_request = receipt
        .request_id
        .strip_prefix(&format!("{base_request_id}-retry-"))
        .is_some_and(|id| id.len() == 32 && id.bytes().all(|byte| byte.is_ascii_hexdigit()));
    ensure!(
        receipt.actor == ACTOR
            && receipt.operation == OPERATION
            && receipt.origin == "migration"
            && plan_hash.len() == 64
            && (receipt.request_id == base_request_id || retry_request)
            && manifest["manifest_version"] == 1
            && manifest["kind"] == "v4_to_v5_migration"
            && manifest["bootstrap_authorization"] == BOOTSTRAP_AUTHORIZATION
            && manifest["plan_hash"] == plan_hash
            && manifest["source_config_revision"] == receipt.before_revision
            && manifest["candidate_config_revision"] == receipt.after_revision,
        "BootstrapAuthorizationMismatch: receipt does not authorize this first migration"
    );
    Ok(())
}

pub fn finalize(master: &Path, receipt_id: &str) -> anyhow::Result<FinalizeResultV1> {
    let pid_file = crate::cli::config_discovery::resolve_pid_file(None, master);
    finalize_with_pid_file(master, &pid_file, receipt_id)
}

pub fn finalize_with_pid_file(
    master: &Path,
    pid_file: &Path,
    receipt_id: &str,
) -> anyhow::Result<FinalizeResultV1> {
    let offline_lease = crate::config::runtime_lease::acquire_for_migration(master, pid_file)?;
    let guard = write_lock::acquire_for_migration(master)?;
    offline_lease.verify_migration_tree(&guard)?;
    ensure!(
        crate::config::migration_journal::inspect(guard.tree_io())?
            == crate::config::migration_journal::FenceState::Absent,
        "MigrationRecoveryRequired: finalize cannot recover an active journal"
    );
    let data = crate::config::state_dir::open_for_migration(&guard)?;
    let receipts = ReceiptStore::open(&data, &guard)?;
    match policy_transaction::finalize_after_recovery(&guard, &receipts, ACTOR, receipt_id)? {
        FinalizeOutcome::NoReceipt => Ok(FinalizeResultV1::NotFound),
        FinalizeOutcome::AlreadyFinalized(receipt) => Ok(FinalizeResultV1::AlreadyFinalized {
            receipt_id: receipt.transaction_id,
        }),
        FinalizeOutcome::Finalized(receipt) => Ok(FinalizeResultV1::Finalized {
            receipt_id: receipt.transaction_id,
        }),
    }
}

fn build(
    snapshot: &PolicyRevisionSnapshot,
    loaded: &LoadedConfig,
    choices: Option<MigrationChoicesV1>,
) -> anyhow::Result<BuiltCandidate> {
    let source_revision = snapshot.revision().to_string();
    let source_operator_policy_hash =
        hash_schema4_migration_snapshot(snapshot, &loaded.config)?.to_string();
    let choices = choices.unwrap_or_else(|| MigrationChoicesV1::empty(&source_revision));
    choices.validate(&source_revision)?;
    let choices_digest = choices.digest()?;
    let source_digest = migration_source_digest(&source_revision);
    let historical = HistoricalConfigV4::decode(loaded)?;
    let source_packs = source_pack_bodies(snapshot)?;
    let mut findings = Vec::new();
    let mut mappings = Vec::new();
    let mut clones = Vec::new();
    let mut target_packs = source_packs.clone();
    let mut target = target_config(&historical.config)?;

    find_existing_inactive_rows(
        &source_packs,
        &choices,
        &source_digest,
        &mut findings,
        &mut target_packs,
    )?;
    analyse_profiles(&historical, &source_packs, &source_digest, &mut findings)?;

    let mut occupied = all_ids(&historical.config);
    occupied.extend(snapshot.orphan_packs().iter().filter_map(|path| {
        path.file_stem()
            .and_then(|stem| stem.to_str())
            .map(str::to_owned)
    }));
    let mut proposed = BTreeMap::new();
    for (profile_id, profile) in &historical.config.profiles {
        if !profile.admin_rules.is_empty() {
            let target_id = choose_id(
                &choices,
                MigrationMappingKindV1::ProfileList,
                profile_id,
                &source_digest,
                &choices_digest,
            )?;
            proposed.insert(
                (MigrationMappingKindV1::ProfileList, profile_id.clone()),
                target_id,
            );
        }
    }

    let mut consumed_rules = BTreeSet::new();
    for profile in historical.config.profiles.values() {
        consumed_rules.extend(profile.admin_rules.iter().cloned());
    }

    for device in &historical.config.devices {
        let active = active_device_rules(&historical, device, &source_digest, &mut findings)?;
        consumed_rules.extend(active.iter().map(|rule| rule.0.clone()));
        if active.is_empty() {
            continue;
        }
        let list_id = choose_id(
            &choices,
            MigrationMappingKindV1::DeviceList,
            device.id.as_str(),
            &source_digest,
            &choices_digest,
        )?;
        let clone_id = choose_id(
            &choices,
            MigrationMappingKindV1::DeviceClone,
            device.id.as_str(),
            &source_digest,
            &choices_digest,
        )?;
        proposed.insert(
            (MigrationMappingKindV1::DeviceList, device.id.to_string()),
            list_id,
        );
        proposed.insert(
            (MigrationMappingKindV1::DeviceClone, device.id.to_string()),
            clone_id,
        );
    }
    let unmounted: Vec<_> = historical
        .config
        .admin_rules
        .iter()
        .filter(|rule| !consumed_rules.contains(&rule.id))
        .collect();
    if !unmounted.is_empty() {
        let source_id = "unmounted";
        let target_id = choose_id(
            &choices,
            MigrationMappingKindV1::UnmountedArchive,
            source_id,
            &source_digest,
            &choices_digest,
        )?;
        proposed.insert(
            (MigrationMappingKindV1::UnmountedArchive, source_id.into()),
            target_id,
        );
    }

    let base_collisions = collision_findings(&proposed, &occupied, &source_digest)?;
    apply_replacement_decisions(&choices, &base_collisions, &mut proposed)?;
    for mut finding in base_collisions {
        if choices.finding_decisions.iter().any(|decision| {
            decision.finding_id == finding.finding_id
                && matches!(
                    decision.decision,
                    MigrationDecisionV1::ReplaceMapping { .. }
                )
        }) {
            finding.equivalence = EquivalenceV1::Resolved;
            finding.blocking = false;
            record_finding(&mut findings, finding)?;
        }
    }
    append_findings(
        &mut findings,
        collision_findings(&proposed, &occupied, &source_digest)?,
    )?;

    let mut generated_ids = BTreeSet::new();
    let mut duplicate_targets = BTreeSet::new();
    for ((kind, source_id), target_id) in &proposed {
        if !generated_ids.insert(target_id.clone()) {
            duplicate_targets.insert(target_id.clone());
            record_finding(
                &mut findings,
                finding(
                    FindingCodeV1::DestinationCollision,
                    format!("mapping:{source_id}"),
                    format!("multiple generated destinations use {target_id}"),
                    EquivalenceV1::Unproven,
                    None,
                    None,
                    None,
                    vec!["replace_mapping"],
                    &source_digest,
                ),
            )?;
        }
        ensure!(
            Id::new(target_id.clone()).is_ok(),
            "planner produced an invalid target id"
        );
        let _ = kind;
    }

    for (profile_id, profile) in &historical.config.profiles {
        let Some(target_id) =
            proposed.get(&(MigrationMappingKindV1::ProfileList, profile_id.clone()))
        else {
            continue;
        };
        let rules = rules_for_refs(&historical, &profile.admin_rules)?;
        if !occupied.contains(target_id) && !duplicate_targets.contains(target_id) {
            add_generated_list(
                &mut target,
                &mut target_packs,
                target_id,
                &rules,
                "Migrated profile rules",
            )?;
            target
                .profiles
                .get_mut(profile_id)
                .context("target profile disappeared")?
                .custom_lists
                .push(Id::new(target_id.clone())?);
        }
        mappings.push(MigrationMappingV1 {
            kind: MigrationMappingKindV1::ProfileList,
            source_id: profile_id.clone(),
            target_id: target_id.clone(),
            rule_ids: profile
                .admin_rules
                .iter()
                .map(ToString::to_string)
                .collect(),
        });
    }

    for device in &historical.config.devices {
        let Some(list_id) =
            proposed.get(&(MigrationMappingKindV1::DeviceList, device.id.to_string()))
        else {
            continue;
        };
        let clone_id = proposed
            .get(&(MigrationMappingKindV1::DeviceClone, device.id.to_string()))
            .context("device list has no clone mapping")?;
        let active = active_device_rules_without_findings(&historical, device)?;
        let rules: Vec<_> = active.iter().map(|(_, rule)| rule.rule.as_str()).collect();
        if !occupied.contains(list_id) && !duplicate_targets.contains(list_id) {
            add_generated_list(
                &mut target,
                &mut target_packs,
                list_id,
                &rules,
                "Migrated device overlay",
            )?;
        }
        let source = selected_source(&historical, device, &choices)?;
        if historical.applicable_schedule_exists(device) {
            record_finding(
                &mut findings,
                finding(
                    FindingCodeV1::DynamicProfileSource,
                    format!("device:{}", device.id),
                    "a schedule can change the source profile represented by a static clone".into(),
                    EquivalenceV1::Unproven,
                    None,
                    None,
                    Some(
                        "an applicable schedule exists even when its window is currently inactive"
                            .into(),
                    ),
                    vec!["accept_v5_semantics", "replace_mapping", "defer"],
                    &source_digest,
                ),
            )?;
        }
        let Some(source) = source else {
            record_finding(
                &mut findings,
                finding(
                    FindingCodeV1::DynamicProfileSource,
                    format!("device:{}", device.id),
                    "the overlay source falls through subnet or global resolution".into(),
                    EquivalenceV1::Unproven,
                    None,
                    None,
                    None,
                    vec!["replace_mapping", "accept_v5_semantics", "defer"],
                    &source_digest,
                ),
            )?;
            continue;
        };
        analyse_overlay_precedence(
            &historical,
            &source_packs,
            device,
            &source,
            &active,
            &source_digest,
            &mut findings,
        )?;
        let source_profile = target
            .profiles
            .get(source.profile_id.as_str())
            .context("target source profile disappeared")?
            .clone();
        let source_policy_hash = target_profile_policy_hash(&source_profile, &[], &target_packs)?;
        let source_pack_digests = profile_pack_digests(&source_profile, &[], &target_packs)?;
        let resolver_source_hash = resolver_source_hash_v4(&historical, device)?;
        let list = Id::new(list_id.clone())?;
        let mut clone = source_profile;
        clone.display_name = if clone.display_name.is_empty() {
            format!("{} migration snapshot", device.id)
        } else {
            format!("{} — {}", clone.display_name, device.id)
        };
        if !clone.custom_lists.contains(&list) {
            clone.custom_lists.push(list.clone());
        }
        clone.migration_origin = Some(MigrationOriginV1 {
            source_profile: source.profile_id.clone(),
            source_group: source.group_id.clone(),
            device_id: device.id.clone(),
            source_policy_hash: source_policy_hash.clone(),
            source_pack_digests,
            resolver_source_hash: resolver_source_hash.clone(),
            added_custom_lists: vec![list],
        });
        if !occupied.contains(clone_id)
            && !occupied.contains(list_id)
            && !duplicate_targets.contains(clone_id)
            && !duplicate_targets.contains(list_id)
        {
            target.profiles.insert(clone_id.clone(), clone);
            target
                .devices
                .iter_mut()
                .find(|candidate| candidate.id == device.id)
                .context("target device disappeared")?
                .profile = Some(Id::new(clone_id.clone())?);
        }
        mappings.push(MigrationMappingV1 {
            kind: MigrationMappingKindV1::DeviceList,
            source_id: device.id.to_string(),
            target_id: list_id.clone(),
            rule_ids: active.iter().map(|(id, _)| id.to_string()).collect(),
        });
        mappings.push(MigrationMappingV1 {
            kind: MigrationMappingKindV1::DeviceClone,
            source_id: device.id.to_string(),
            target_id: clone_id.clone(),
            rule_ids: Vec::new(),
        });
        clones.push(ProfileCloneV1 {
            device_id: device.id.to_string(),
            source_profile: source.profile_id.to_string(),
            source_group: source.group_id.as_ref().map(ToString::to_string),
            target_profile: clone_id.clone(),
            added_custom_list: list_id.clone(),
            source_policy_hash,
            resolver_source_hash,
        });
    }

    if let Some(target_id) = proposed.get(&(
        MigrationMappingKindV1::UnmountedArchive,
        "unmounted".to_string(),
    )) {
        let rules: Vec<_> = unmounted.iter().map(|rule| rule.rule.as_str()).collect();
        if !occupied.contains(target_id) && !duplicate_targets.contains(target_id) {
            add_generated_list(
                &mut target,
                &mut target_packs,
                target_id,
                &rules,
                "Unreferenced schema-4 rules",
            )?;
        }
        mappings.push(MigrationMappingV1 {
            kind: MigrationMappingKindV1::UnmountedArchive,
            source_id: "unmounted".into(),
            target_id: target_id.clone(),
            rule_ids: unmounted.iter().map(|rule| rule.id.to_string()).collect(),
        });
    }

    if historical.config.cluster.enabled && historical.config.cluster.role == ClusterRole::Secondary
    {
        record_finding(&mut findings, finding(
            FindingCodeV1::ClusterLocalPolicyConflict,
            "cluster:secondary".into(),
            "a secondary migration requires an isolated deployment and replication reconciliation"
                .into(),
            EquivalenceV1::Unproven,
            None,
            None,
            None,
            vec!["defer"],
            &source_digest,
        ))?;
    }
    let structural_block = findings.iter().any(|finding| {
        finding.blocking
            && matches!(
                finding.code,
                FindingCodeV1::DestinationCollision | FindingCodeV1::LegacyInactiveRule
            )
    });
    if !structural_block {
        if let Err(error) =
            validate_target_in_memory(&target, &target_packs, OffsetDateTime::UNIX_EPOCH)
        {
            record_finding(
                &mut findings,
                finding(
                    FindingCodeV1::TargetBudgetExceeded,
                    "target:policy".into(),
                    format!("schema-5 validation or compilation failed: {error:#}"),
                    EquivalenceV1::Unproven,
                    None,
                    None,
                    None,
                    vec!["defer"],
                    &source_digest,
                ),
            )?;
        }
    }

    apply_finding_decisions(&choices, &mut findings)?;
    findings.sort_by(|left, right| left.finding_id.cmp(&right.finding_id));
    mappings.sort_by(|left, right| {
        (left.kind, left.source_id.as_str()).cmp(&(right.kind, right.source_id.as_str()))
    });
    clones.sort_by(|left, right| left.device_id.cmp(&right.device_id));
    let blocked = findings.iter().any(|finding| finding.blocking);

    let source_inventory = inventory_summary(snapshot.inventory())?;
    let backup_bytes: u64 = source_inventory.iter().map(|entry| entry.length).sum();
    let mut inventory = None;
    let mut candidate_inventory = Vec::new();
    let mut candidate_config_revision = None;
    let mut candidate_operator_policy_hash = None;
    let mut filesystem_operations = Vec::new();
    if !findings
        .iter()
        .any(|finding| finding.blocking && finding.code == FindingCodeV1::DestinationCollision)
    {
        let built = candidate_inventory_for(snapshot.inventory(), &target, &target_packs)?;
        candidate_inventory = inventory_summary(&built)?;
        candidate_config_revision = Some(built.revision().to_string());
        let semantic_packs = target_packs
            .iter()
            .map(|(id, body)| {
                Ok(SemanticPack {
                    id: id.as_str(),
                    body: std::str::from_utf8(body)
                        .with_context(|| format!("candidate pack {id} is not UTF-8"))?,
                })
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        candidate_operator_policy_hash = Some(
            hash_policy_candidate(&target, &semantic_packs)
                .context("candidate operator policy semantic hash failed")?
                .to_string(),
        );
        filesystem_operations = filesystem_diff(snapshot.inventory(), &built)?;
        inventory = Some(built);
    }
    let required_free_bytes = backup_bytes.saturating_mul(2).saturating_add(
        candidate_inventory
            .iter()
            .map(|entry| entry.length)
            .sum::<u64>(),
    );
    let mut plan = MigrationPlanV1 {
        planner_version: PLANNER_VERSION,
        plan_hash: String::new(),
        source_schema: SOURCE_SCHEMA,
        target_schema: TARGET_SCHEMA_VERSION_V5,
        source_config_revision: source_revision,
        source_digest,
        source_operator_policy_hash,
        choices_digest,
        choices,
        required_capabilities: vec![
            "schema-v5-runtime".into(),
            "operator-rules-v1".into(),
            "offline-node".into(),
            "schema5-dns-ready-runtime-lease-v2".into(),
            "policy-transaction-format2".into(),
        ],
        source_inventory,
        candidate_inventory,
        candidate_config_revision,
        candidate_operator_policy_hash,
        mappings,
        clones,
        findings,
        filesystem_operations,
        backup_bytes,
        required_free_bytes,
        blocked,
    };
    plan.plan_hash = compute_plan_hash(&plan)?;
    Ok(BuiltCandidate { plan, inventory })
}

fn target_config(source: &crate::config::schema::ConfigV1) -> anyhow::Result<ConfigV5> {
    let max_file_bytes = usize::try_from(source.custom_list_limits.max_file_bytes)
        .context("custom-list max_file_bytes is not representable by schema 5")?;
    Ok(ConfigV5 {
        schema_version: TARGET_SCHEMA_VERSION_V5,
        includes: Vec::new(),
        server: source.server.clone(),
        retired: source.retired.clone(),
        blocklists: source.blocklists.clone(),
        profiles: source
            .profiles
            .iter()
            .map(|(id, profile)| (id.clone(), profile_to_v5(profile)))
            .collect(),
        devices: source.devices.iter().map(device_to_v5).collect(),
        groups: source.groups.clone(),
        subnets: source.subnets.clone(),
        schedules: source.schedules.clone(),
        custom_lists: source.custom_lists.clone(),
        custom_list_limits: CustomListLimitsV5 {
            max_file_bytes,
            ..CustomListLimitsV5::default()
        },
        labels: source.labels.clone(),
        upstream: source.upstream.clone(),
        dnssec: source.dnssec.clone(),
        cache: source.cache.clone(),
        tracking: source.tracking.clone(),
        security: source.security.clone(),
        anti_bypass: source.anti_bypass.clone(),
        socket: source.socket.clone(),
        api: source.api.clone(),
        forwarding: source.forwarding.clone(),
        local_dns: source.local_dns.clone(),
        ip_blocklists: source.ip_blocklists.clone(),
        lists: source.lists.clone(),
        resource_budget: source.resource_budget.clone(),
        backup: source.backup.clone(),
        cluster: source.cluster.clone(),
        node: source.node.clone(),
    })
}

fn profile_to_v5(profile: &Profile) -> ProfileV5 {
    ProfileV5 {
        display_name: profile.display_name.clone(),
        block_response: profile.block_response,
        blocked_ttl_secs: profile.blocked_ttl_secs,
        block_all: profile.block_all,
        local_records: profile.local_records.clone(),
        ecs: profile.ecs.clone(),
        rewrite_rules: profile.rewrite_rules.clone(),
        safe_search: profile.safe_search,
        custom_lists: profile.custom_lists.clone(),
        lists: profile.lists.clone(),
        migration_origin: None,
    }
}

fn device_to_v5(device: &crate::config::schema::Device) -> DeviceV5 {
    DeviceV5 {
        id: device.id.clone(),
        display_name: device.display_name.clone(),
        ip: device.ip,
        mac: device.mac.clone(),
        mac_aliases: device.mac_aliases.clone(),
        profile: device.profile.clone(),
        groups: device.groups.clone(),
        owner: device.owner.clone(),
        device_type: device.device_type.clone(),
        department: device.department.clone(),
        notes: device.notes.clone(),
        unfiltered: device.unfiltered,
        network_name: device.network_name.clone(),
        network_name_wildcard: device.network_name_wildcard,
    }
}

fn add_generated_list(
    config: &mut ConfigV5,
    packs: &mut BTreeMap<Id, Vec<u8>>,
    target_id: &str,
    rules: &[&str],
    description: &str,
) -> anyhow::Result<()> {
    let id = Id::new(target_id.to_string())?;
    ensure!(
        !config.custom_lists.iter().any(|list| list.id == id) && !packs.contains_key(&id),
        "DestinationCollision: generated custom list {id} already exists"
    );
    let mut body = rules.join("\n");
    if !body.is_empty() {
        body.push('\n');
    }
    config.custom_lists.push(CustomList {
        id: id.clone(),
        display_name: target_id.to_string(),
        description: description.into(),
    });
    packs.insert(id, body.into_bytes());
    Ok(())
}

fn rules_for_refs<'a>(
    historical: &'a HistoricalConfigV4,
    refs: &[Id],
) -> anyhow::Result<Vec<&'a str>> {
    refs.iter()
        .map(|id| historical.rule(id).map(|rule| rule.rule.as_str()))
        .collect()
}

fn active_device_rules<'a>(
    historical: &'a HistoricalConfigV4,
    device: &crate::config::schema::Device,
    source_digest: &str,
    findings: &mut Vec<MigrationFindingV1>,
) -> anyhow::Result<Vec<(Id, &'a crate::config::schema::AdminRule)>> {
    let mut active = Vec::new();
    for (expected_allow, refs) in [(true, &device.allow_rules), (false, &device.deny_rules)] {
        for id in refs {
            let rule = historical.rule(id)?;
            let ast = parse_rule_ast(&rule.rule)?;
            let active_here = matches!(ast.pattern(), OperatorPattern::Exact(_))
                && !ast.tier().is_important()
                && ast.tier().is_allow() == expected_allow;
            if active_here {
                active.push((id.clone(), rule));
            } else {
                record_finding(
                    findings,
                    finding(
                        FindingCodeV1::LegacyInactiveRule,
                        format!("device:{}:rule:{id}", device.id),
                        "the schema-4 overlay ignores this action or advanced rule shape".into(),
                        EquivalenceV1::Unproven,
                        Some("inactive in the device overlay".into()),
                        Some("omitted from the generated device pack".into()),
                        Some(rule.rule.clone()),
                        vec!["accept_v5_semantics", "defer"],
                        source_digest,
                    ),
                )?;
            }
        }
    }
    Ok(active)
}

fn active_device_rules_without_findings<'a>(
    historical: &'a HistoricalConfigV4,
    device: &crate::config::schema::Device,
) -> anyhow::Result<Vec<(Id, &'a crate::config::schema::AdminRule)>> {
    let mut ignored = Vec::new();
    active_device_rules(historical, device, "", &mut ignored)
}

fn analyse_profiles(
    historical: &HistoricalConfigV4,
    packs: &BTreeMap<Id, Vec<u8>>,
    source_digest: &str,
    findings: &mut Vec<MigrationFindingV1>,
) -> anyhow::Result<()> {
    for (profile_id, profile) in &historical.config.profiles {
        let parsed = effective_profile_rules(historical, packs, profile)?;
        for rule in &parsed {
            let ast = &rule.ast;
            if !matches!(ast.pattern(), OperatorPattern::Exact(_)) {
                record_finding(
                    findings,
                    finding(
                        FindingCodeV1::AdvancedEquivalenceUnsupported,
                        format!("profile:{profile_id}:{}", rule.origin),
                        "wildcard or regular-expression equivalence is not proven structurally"
                            .into(),
                        EquivalenceV1::Unproven,
                        None,
                        None,
                        Some(rule.text.clone()),
                        vec!["accept_v5_semantics", "defer"],
                        source_digest,
                    ),
                )?;
            }
            if ast.tier().is_allow()
                && (ast.tier() != RuleTier::OrdinaryAllow
                    || !matches!(ast.pattern(), OperatorPattern::Exact(_)))
            {
                record_finding(findings, finding(
                    FindingCodeV1::AllowGrantChanges,
                    format!("profile:{profile_id}:{}", rule.origin),
                    "an allow outside the schema-4 simple allow set becomes a v5 response/IP grant"
                        .into(),
                    EquivalenceV1::Changed,
                    Some("schema 4 grants only the matching query name".into()),
                    Some(
                        "schema 5 retains the winning grant through CNAME and IP evaluation".into(),
                    ),
                    Some(rule.text.clone()),
                    vec!["accept_v5_semantics", "defer"],
                    source_digest,
                ))?;
            }
        }
        let ordinary_allows: Vec<_> = parsed
            .iter()
            .filter(|rule| {
                rule.ast.tier() == RuleTier::OrdinaryAllow
                    && matches!(rule.ast.pattern(), OperatorPattern::Exact(_))
            })
            .collect();
        let important_denies: Vec<_> = parsed
            .iter()
            .filter(|rule| rule.ast.tier() == RuleTier::ImportantDeny)
            .collect();
        for allow in &ordinary_allows {
            for deny in &important_denies {
                let response_witness = response_witness(&allow.ast, &deny.ast);
                record_finding(findings, finding(
                    FindingCodeV1::ResponseAuthorityChanges,
                    format!(
                        "profile:{profile_id}:allow:{}:deny:{}",
                        allow.origin, deny.origin
                    ),
                    "an ordinary query grant cannot overrule an important CNAME-target deny in v5"
                        .into(),
                    EquivalenceV1::Changed,
                    Some("the schema-4 query allow can bypass later response filtering".into()),
                    Some("the important deny has higher authority".into()),
                    Some(response_witness),
                    vec!["accept_v5_semantics", "defer"],
                    source_digest,
                ))?;
                if profile.block_all {
                    if let Some(witness) = overlap_witness(&allow.ast, &deny.ast) {
                        record_finding(findings, finding(
                            FindingCodeV1::LatticeVerdictChanges,
                            format!(
                                "profile:{profile_id}:allow:{}:deny:{}",
                                allow.origin, deny.origin
                            ),
                            "block_all checks an ordinary exact allow before an important deny in schema 4".into(),
                            EquivalenceV1::Changed,
                            Some("forward".into()),
                            Some("block".into()),
                            Some(witness),
                            vec!["accept_v5_semantics", "defer"],
                            source_digest,
                        ))?;
                    }
                }
            }
        }
    }
    Ok(())
}

fn analyse_overlay_precedence(
    historical: &HistoricalConfigV4,
    packs: &BTreeMap<Id, Vec<u8>>,
    device: &crate::config::schema::Device,
    source: &ResolverSourceV4,
    active: &[(Id, &crate::config::schema::AdminRule)],
    source_digest: &str,
    findings: &mut Vec<MigrationFindingV1>,
) -> anyhow::Result<()> {
    let profile = historical.profile(&source.profile_id)?;
    let profile_rules = effective_profile_rules(historical, packs, profile)?;
    for (device_id, device_rule) in active {
        let device_ast = parse_rule_ast(&device_rule.rule)?;
        for profile_rule in &profile_rules {
            let profile_ast = &profile_rule.ast;
            if let Some(witness) = overlap_witness(&device_ast, profile_ast) {
                let changed = (device_ast.tier() == RuleTier::OrdinaryAllow
                    && ((profile_ast.tier() == RuleTier::OrdinaryDeny
                        && !device.override_profile_deny)
                        || profile_ast.tier() == RuleTier::ImportantDeny))
                    || (device_ast.tier() == RuleTier::OrdinaryDeny
                        && profile_ast.tier().is_allow());
                if changed {
                    record_finding(findings, finding(
                        FindingCodeV1::OverlayPrecedenceNotRepresentable,
                        format!(
                            "device:{}:rule:{device_id}:profile-rule:{}",
                            device.id, profile_rule.origin
                        ),
                        "the schema-4 device/profile ordering differs from the unified authority lattice"
                            .into(),
                        EquivalenceV1::Changed,
                        Some("device overlay ordering".into()),
                        Some("important/allow authority ordering".into()),
                        Some(witness),
                        vec!["accept_v5_semantics", "defer"],
                        source_digest,
                    ))?;
                }
            }
            let response_changed = device_ast.tier() == RuleTier::OrdinaryAllow
                && ((profile_ast.tier() == RuleTier::OrdinaryDeny
                    && !device.override_profile_deny)
                    || (profile_ast.tier() == RuleTier::ImportantDeny
                        && device.override_profile_deny));
            if response_changed {
                record_finding(findings, finding(
                    FindingCodeV1::ResponseAuthorityChanges,
                    format!(
                        "device:{}:rule:{device_id}:response-profile-rule:{}",
                        device.id, profile_rule.origin
                    ),
                    "the device query allow and profile CNAME-target deny have different response authority in v5"
                        .into(),
                    EquivalenceV1::Changed,
                    Some("schema-4 device response authority".into()),
                    Some("the unified grant competes at its operator tier".into()),
                    Some(response_witness(&device_ast, profile_ast)),
                    vec!["accept_v5_semantics", "defer"],
                    source_digest,
                ))?;
            }
        }
    }
    let allows: Vec<_> = active
        .iter()
        .filter(|(_, rule)| parse_rule_ast(&rule.rule).is_ok_and(|ast| ast.tier().is_allow()))
        .collect();
    let denies: Vec<_> = active
        .iter()
        .filter(|(_, rule)| parse_rule_ast(&rule.rule).is_ok_and(|ast| !ast.tier().is_allow()))
        .collect();
    for (allow_id, allow) in allows {
        let allow_ast = parse_rule_ast(&allow.rule)?;
        for (deny_id, deny) in &denies {
            let deny_ast = parse_rule_ast(&deny.rule)?;
            let Some(witness) = overlap_witness(&allow_ast, &deny_ast) else {
                continue;
            };
            let simple_profile_deny_hits = profile_rules.iter().any(|rule| {
                rule.ast.tier() == RuleTier::OrdinaryDeny
                    && overlap_witness(&allow_ast, &rule.ast).is_some()
            });
            if device.override_profile_deny && simple_profile_deny_hits {
                continue;
            }
            record_finding(findings, finding(
                FindingCodeV1::OverlayPrecedenceNotRepresentable,
                format!("device:{}:allow:{allow_id}:deny:{deny_id}", device.id),
                "schema 4 can give a device deny or a non-overridden profile deny precedence over a same-name device allow"
                    .into(),
                EquivalenceV1::Changed,
                Some("block".into()),
                Some("ordinary allow".into()),
                Some(witness),
                vec!["accept_v5_semantics", "defer"],
                source_digest,
            ))?;
        }
    }
    Ok(())
}

#[derive(Debug)]
struct EffectiveProfileRuleV4 {
    origin: String,
    text: String,
    ast: OperatorRuleAst,
}

fn effective_profile_rules(
    historical: &HistoricalConfigV4,
    packs: &BTreeMap<Id, Vec<u8>>,
    profile: &Profile,
) -> anyhow::Result<Vec<EffectiveProfileRuleV4>> {
    let mut rules = Vec::new();
    for id in &profile.admin_rules {
        let rule = historical.rule(id)?;
        rules.push(EffectiveProfileRuleV4 {
            origin: format!("admin:{id}"),
            text: rule.rule.clone(),
            ast: parse_rule_ast(&rule.rule)?,
        });
    }
    for list_id in &profile.custom_lists {
        let body = packs
            .get(list_id)
            .with_context(|| format!("mounted custom list {list_id} has no captured body"))?;
        let text = std::str::from_utf8(body)
            .with_context(|| format!("mounted custom list {list_id} is not UTF-8"))?;
        for (index, row) in text.lines().enumerate() {
            let normalized = match parse_pack_line(row) {
                Ok(crate::config::custom_list::PackLine::Blank) | Err(_) => continue,
                Ok(crate::config::custom_list::PackLine::Allow(domain)) => {
                    format!("@@||{domain}^")
                }
                Ok(crate::config::custom_list::PackLine::Deny(domain)) => {
                    format!("||{domain}^")
                }
            };
            rules.push(EffectiveProfileRuleV4 {
                origin: format!("custom-list:{list_id}:row:{}", index + 1),
                ast: parse_rule_ast(&normalized)?,
                text: normalized,
            });
        }
    }
    Ok(rules)
}

fn response_witness(allow: &OperatorRuleAst, deny: &OperatorRuleAst) -> String {
    fn label(ast: &OperatorRuleAst) -> String {
        match ast.pattern() {
            OperatorPattern::Exact(domain) => domain.to_string(),
            OperatorPattern::Wildcard(domain) => format!("a.{domain}"),
            OperatorPattern::Regex { source, .. } => format!("a name matching /{source}/"),
        }
    }
    format!(
        "QNAME {} is allowed, then its response names CNAME target {}",
        label(allow),
        label(deny)
    )
}

fn overlap_witness(left: &OperatorRuleAst, right: &OperatorRuleAst) -> Option<String> {
    fn domain(ast: &OperatorRuleAst) -> Option<&str> {
        match ast.pattern() {
            OperatorPattern::Exact(domain) | OperatorPattern::Wildcard(domain) => {
                Some(domain.as_str())
            }
            OperatorPattern::Regex { .. } => None,
        }
    }
    let left = domain(left)?;
    let right = domain(right)?;
    if left == right || left.ends_with(&format!(".{right}")) {
        Some(left.into())
    } else if right.ends_with(&format!(".{left}")) {
        Some(right.into())
    } else {
        None
    }
}

fn selected_source(
    historical: &HistoricalConfigV4,
    device: &crate::config::schema::Device,
    choices: &MigrationChoicesV1,
) -> anyhow::Result<Option<ResolverSourceV4>> {
    if let Some(mapping) = choices
        .destination_mappings
        .iter()
        .find(|mapping| mapping.source_id == device.id.as_str())
    {
        ensure!(
            historical.config.profiles.contains_key(&mapping.target_id),
            "destination mapping names an unknown source profile"
        );
        return Ok(Some(ResolverSourceV4 {
            profile_id: Id::new(mapping.target_id.clone())?,
            group_id: None,
        }));
    }
    Ok(historical.resolver_source(device))
}

fn choose_id(
    choices: &MigrationChoicesV1,
    kind: MigrationMappingKindV1,
    source_id: &str,
    source_digest: &str,
    choices_digest: &str,
) -> anyhow::Result<String> {
    let category = match kind {
        MigrationMappingKindV1::ProfileList
        | MigrationMappingKindV1::DeviceList
        | MigrationMappingKindV1::UnmountedArchive => &choices.list_mappings,
        MigrationMappingKindV1::DeviceClone => &choices.profile_mappings,
    };
    let explicit = category
        .iter()
        .find(|mapping| mapping.source_id == source_id)
        .map(|mapping| mapping.target_id.clone())
        .or_else(|| {
            choices
                .collision_resolutions
                .iter()
                .find(|mapping| mapping.kind == kind && mapping.source_id == source_id)
                .map(|mapping| mapping.target_id.clone())
        });
    if let Some(explicit) = explicit {
        Id::new(explicit.clone())?;
        return Ok(explicit);
    }
    migration_id(kind, source_id, source_digest, choices_digest)
}

pub fn migration_id(
    kind: MigrationMappingKindV1,
    source_id: &str,
    source_digest: &str,
    choices_digest: &str,
) -> anyhow::Result<String> {
    ensure!(
        source_digest.len() == 64 && choices_digest.len() == 64,
        "invalid migration digest"
    );
    let source_bytes = decode_hex(source_digest)?;
    let choices_bytes = decode_hex(choices_digest)?;
    let mut hash = Sha256::new();
    hash.update(b"warden/uor/v4-to-v5/id/v1\0");
    update_lp(&mut hash, kind.tag().as_bytes());
    update_lp(&mut hash, source_id.as_bytes());
    hash.update(source_bytes);
    hash.update(choices_bytes);
    let suffix = &hex(&hash.finalize())[..16];
    let prefix = format!("uor-{}-", kind.tag());
    let slug_budget = Id::MAX_LEN - prefix.len() - 1 - suffix.len();
    let mut slug = source_id
        .bytes()
        .map(|byte| {
            if byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-' {
                byte as char
            } else {
                '-'
            }
        })
        .collect::<String>();
    slug.truncate(slug_budget);
    while slug.ends_with('-') {
        slug.pop();
    }
    if slug.is_empty() {
        slug.push_str("rules");
    }
    let id = format!("{prefix}{slug}-{suffix}");
    Id::new(id.clone())?;
    Ok(id)
}

fn migration_source_digest(revision: &str) -> String {
    let mut hash = Sha256::new();
    hash.update(b"warden/uor/migration-input/v1\0");
    update_lp(&mut hash, revision.as_bytes());
    hex(&hash.finalize())
}

fn update_lp(hash: &mut Sha256, bytes: &[u8]) {
    hash.update((bytes.len() as u64).to_be_bytes());
    hash.update(bytes);
}

fn decode_hex(value: &str) -> anyhow::Result<Vec<u8>> {
    ensure!(value.len().is_multiple_of(2), "invalid hex digest");
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair)?;
            Ok(u8::from_str_radix(text, 16)?)
        })
        .collect()
}

fn all_ids(config: &crate::config::schema::ConfigV1) -> BTreeSet<String> {
    let mut ids = BTreeSet::new();
    ids.extend(config.profiles.keys().cloned());
    ids.extend(config.devices.iter().map(|entry| entry.id.to_string()));
    ids.extend(config.groups.iter().map(|entry| entry.id.to_string()));
    ids.extend(config.subnets.iter().map(|entry| entry.id.to_string()));
    ids.extend(config.schedules.iter().map(|entry| entry.id.to_string()));
    ids.extend(config.admin_rules.iter().map(|entry| entry.id.to_string()));
    ids.extend(config.custom_lists.iter().map(|entry| entry.id.to_string()));
    ids.extend(config.blocklists.iter().map(|entry| entry.id.to_string()));
    ids
}

fn collision_findings(
    proposed: &BTreeMap<(MigrationMappingKindV1, String), String>,
    occupied: &BTreeSet<String>,
    source_digest: &str,
) -> anyhow::Result<Vec<MigrationFindingV1>> {
    let mut findings = Vec::new();
    for ((kind, source), target) in proposed
        .iter()
        .filter(|(_, target)| occupied.contains(*target))
    {
        record_finding(
            &mut findings,
            finding(
                FindingCodeV1::DestinationCollision,
                format!("mapping:{}:{source}", kind.tag()),
                format!("destination id or pack path {target} is already occupied"),
                EquivalenceV1::Unproven,
                None,
                None,
                Some(target.clone()),
                vec!["replace_mapping", "defer"],
                source_digest,
            ),
        )?;
    }
    Ok(findings)
}

fn apply_replacement_decisions(
    choices: &MigrationChoicesV1,
    base_collisions: &[MigrationFindingV1],
    proposed: &mut BTreeMap<(MigrationMappingKindV1, String), String>,
) -> anyhow::Result<()> {
    for FindingDecisionV1 {
        finding_id,
        decision,
    } in &choices.finding_decisions
    {
        let MigrationDecisionV1::ReplaceMapping {
            kind,
            source_id,
            target_id,
        } = decision
        else {
            continue;
        };
        ensure!(
            base_collisions
                .iter()
                .any(|finding| &finding.finding_id == finding_id),
            "replace_mapping refers to a finding that is not a current collision"
        );
        let value = proposed
            .get_mut(&(*kind, source_id.clone()))
            .context("replace_mapping does not match the collided mapping")?;
        *value = target_id.clone();
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn finding(
    code: FindingCodeV1,
    scope: String,
    cause: String,
    equivalence: EquivalenceV1,
    before: Option<String>,
    after: Option<String>,
    witness: Option<String>,
    allowed_remedies: Vec<&str>,
    source_digest: &str,
) -> MigrationFindingV1 {
    let mut hash = Sha256::new();
    hash.update(b"warden/uor/v4-to-v5/finding/v1\0");
    update_lp(&mut hash, format!("{code:?}").as_bytes());
    update_lp(&mut hash, scope.as_bytes());
    update_lp(&mut hash, cause.as_bytes());
    update_lp(&mut hash, witness.as_deref().unwrap_or_default().as_bytes());
    update_lp(&mut hash, source_digest.as_bytes());
    MigrationFindingV1 {
        finding_id: format!("finding-{}", &hex(&hash.finalize())[..20]),
        code,
        scope,
        cause,
        equivalence,
        blocking: true,
        before,
        after,
        witness,
        allowed_remedies: allowed_remedies.into_iter().map(str::to_owned).collect(),
    }
}

fn record_finding(
    findings: &mut Vec<MigrationFindingV1>,
    finding: MigrationFindingV1,
) -> anyhow::Result<()> {
    ensure!(
        findings.len() < MAX_MIGRATION_FINDINGS,
        "migration finding budget exceeded ({MAX_MIGRATION_FINDINGS})"
    );
    findings.push(finding);
    Ok(())
}

fn append_findings(
    findings: &mut Vec<MigrationFindingV1>,
    additions: Vec<MigrationFindingV1>,
) -> anyhow::Result<()> {
    ensure!(
        findings.len().saturating_add(additions.len()) <= MAX_MIGRATION_FINDINGS,
        "migration finding budget exceeded ({MAX_MIGRATION_FINDINGS})"
    );
    findings.extend(additions);
    Ok(())
}

fn apply_finding_decisions(
    choices: &MigrationChoicesV1,
    findings: &mut [MigrationFindingV1],
) -> anyhow::Result<()> {
    for decision in &choices.finding_decisions {
        if matches!(
            decision.decision,
            MigrationDecisionV1::ReplaceMapping { .. }
        ) {
            continue;
        }
        let finding = findings
            .iter_mut()
            .find(|finding| finding.finding_id == decision.finding_id)
            .context("finding decision is stale or names an unknown finding")?;
        match &decision.decision {
            MigrationDecisionV1::AcceptV5Semantics => {
                ensure!(
                    finding
                        .allowed_remedies
                        .iter()
                        .any(|remedy| remedy == "accept_v5_semantics"),
                    "finding cannot be accepted without its required repair"
                );
                finding.equivalence = match finding.equivalence {
                    EquivalenceV1::Changed => EquivalenceV1::ChangedAccepted,
                    EquivalenceV1::Unproven => EquivalenceV1::UnprovenAccepted,
                    accepted => accepted,
                };
                finding.blocking = false;
            }
            MigrationDecisionV1::RepairInactiveRows { .. } => {
                ensure!(
                    finding.code == FindingCodeV1::LegacyInactiveRule
                        && finding.equivalence == EquivalenceV1::Resolved,
                    "repair decision does not match a repaired inactive row"
                );
                finding.blocking = false;
            }
            MigrationDecisionV1::Defer => {}
            MigrationDecisionV1::ReplaceMapping { .. } => unreachable!(),
        }
    }
    Ok(())
}

fn find_existing_inactive_rows(
    source_packs: &BTreeMap<Id, Vec<u8>>,
    choices: &MigrationChoicesV1,
    source_digest: &str,
    findings: &mut Vec<MigrationFindingV1>,
    target_packs: &mut BTreeMap<Id, Vec<u8>>,
) -> anyhow::Result<()> {
    let mut repairs = BTreeMap::new();
    for decision in &choices.finding_decisions {
        if let MigrationDecisionV1::RepairInactiveRows { repairs: rows } = &decision.decision {
            for row in rows {
                ensure!(
                    repairs
                        .insert(
                            (row.list_id.clone(), row.line),
                            (decision.finding_id.as_str(), row)
                        )
                        .is_none(),
                    "an inactive row is repaired more than once"
                );
            }
        }
    }
    let mut used_repairs = BTreeSet::new();
    for (list_id, bytes) in source_packs {
        let text = std::str::from_utf8(bytes).context("captured pack is not UTF-8")?;
        let had_final_newline = text.ends_with('\n');
        let mut rows = Vec::new();
        let mut modified = false;
        for (index, raw) in text.lines().enumerate() {
            let line = index + 1;
            if parse_pack_line(raw).is_ok() {
                rows.push(raw.to_string());
                continue;
            }
            let digest = row_digest(raw);
            let scope = format!("custom-list:{list_id}:line:{line}");
            let mut inactive = finding(
                FindingCodeV1::LegacyInactiveRule,
                scope,
                "schema 4 skipped this custom-list row".into(),
                EquivalenceV1::Unproven,
                Some("skipped".into()),
                Some("must remain inactive unless repaired explicitly".into()),
                Some(raw.into()),
                vec!["repair_inactive_rows", "defer"],
                source_digest,
            );
            if let Some((decision_id, repair)) = repairs.get(&(list_id.to_string(), line)) {
                ensure!(
                    repair.row_digest == digest,
                    "StaleChoices: repaired row digest changed"
                );
                ensure!(
                    *decision_id == inactive.finding_id,
                    "repair row is attached to a different finding"
                );
                if let Some(replacement) = &repair.replacement {
                    if !replacement.trim().is_empty() && !replacement.trim_start().starts_with('#')
                    {
                        parse_rule_ast(replacement)
                            .context("replacement row is not valid v5 grammar")?;
                    }
                    rows.push(replacement.clone());
                }
                modified = true;
                inactive.equivalence = EquivalenceV1::Resolved;
                inactive.blocking = false;
                used_repairs.insert((list_id.to_string(), line));
            } else {
                rows.push(raw.to_string());
            }
            record_finding(findings, inactive)?;
        }
        if modified {
            let mut body = rows.join("\n");
            if had_final_newline {
                body.push('\n');
            }
            target_packs.insert(list_id.clone(), body.into_bytes());
        }
    }
    ensure!(
        used_repairs.len() == repairs.len(),
        "repair_inactive_rows names a row that is absent or active"
    );
    Ok(())
}

fn source_pack_bodies(snapshot: &PolicyRevisionSnapshot) -> anyhow::Result<BTreeMap<Id, Vec<u8>>> {
    snapshot
        .inventory()
        .members()
        .iter()
        .filter(|member| member.kind() == PolicyMemberKind::Pack)
        .map(|member| {
            let id = Id::new(
                member
                    .path()
                    .file_stem()
                    .and_then(|name| name.to_str())
                    .context("pack path is not UTF-8")?
                    .to_string(),
            )?;
            let PolicyMemberState::Present(bytes) = member.state() else {
                bail!("live source pack is absent")
            };
            Ok((id, bytes.clone()))
        })
        .collect()
}

fn candidate_inventory_for(
    source: &PolicyRevisionInventory,
    target: &ConfigV5,
    packs: &BTreeMap<Id, Vec<u8>>,
) -> anyhow::Result<PolicyRevisionInventory> {
    let master = source
        .members()
        .iter()
        .find(|member| member.kind() == PolicyMemberKind::Master)
        .context("source inventory has no master")?;
    let master_bytes = toml::to_string_pretty(target)?.into_bytes();
    let mut members = vec![PolicyRevisionMember::present(
        PolicyMemberKind::Master,
        master.path().to_path_buf(),
        master_bytes,
    )?];
    for (id, body) in packs {
        members.push(PolicyRevisionMember::present(
            PolicyMemberKind::Pack,
            pack_path(Path::new(""), id),
            body.clone(),
        )?);
    }
    Ok(PolicyRevisionInventory::new(members)?)
}

fn inventory_summary(
    inventory: &PolicyRevisionInventory,
) -> anyhow::Result<Vec<InventoryMemberV1>> {
    inventory
        .members()
        .iter()
        .map(|member| {
            let PolicyMemberState::Present(bytes) = member.state() else {
                bail!("plan inventory cannot summarize an absent member")
            };
            Ok(InventoryMemberV1 {
                path: member.path().to_string_lossy().into_owned(),
                role: match member.kind() {
                    PolicyMemberKind::Master => "master",
                    PolicyMemberKind::Include => "include",
                    PolicyMemberKind::Pack => "pack",
                }
                .into(),
                digest: digest(bytes),
                length: bytes.len() as u64,
            })
        })
        .collect()
}

fn filesystem_diff(
    before: &PolicyRevisionInventory,
    after: &PolicyRevisionInventory,
) -> anyhow::Result<Vec<FilesystemOperationV1>> {
    let before: BTreeMap<_, _> = before.members().iter().map(|m| (m.path(), m)).collect();
    let after: BTreeMap<_, _> = after.members().iter().map(|m| (m.path(), m)).collect();
    let paths: BTreeSet<_> = before.keys().chain(after.keys()).copied().collect();
    let mut operations = Vec::new();
    for path in &paths {
        let old = before.get(path).copied();
        let new = after.get(path).copied();
        let old_bytes = old.map(present_bytes).transpose()?;
        let new_bytes = new.map(present_bytes).transpose()?;
        if old_bytes == new_bytes {
            continue;
        }
        operations.push(FilesystemOperationV1 {
            path: path.to_string_lossy().into_owned(),
            operation: match (old, new) {
                (None, Some(_)) => FilesystemOperationKindV1::Create,
                (Some(_), None) => FilesystemOperationKindV1::Delete,
                (Some(_), Some(_)) => FilesystemOperationKindV1::Replace,
                (None, None) => unreachable!(),
            },
            after_digest: new_bytes.map(digest),
            after_length: new_bytes.map(|bytes| bytes.len() as u64),
        });
    }
    Ok(operations)
}

fn present_bytes(member: &PolicyRevisionMember) -> anyhow::Result<&[u8]> {
    match member.state() {
        PolicyMemberState::Present(bytes) => Ok(bytes),
        PolicyMemberState::Absent => bail!("candidate inventory contains an absent state"),
    }
}

fn validate_candidate_under_guard(
    guard: &write_lock::MigrationWriteLock,
    before: &PolicyRevisionInventory,
    after: &PolicyRevisionInventory,
    now: OffsetDateTime,
) -> anyhow::Result<()> {
    let (toml, packs) = candidate_overlays(guard, before, after)?;
    let loaded = loader::load_config_v5_executable_with_policy_overlays_under_migration_guard(
        guard,
        guard.canonical_master(),
        now,
        Some(&toml),
        Some(&packs),
    )
    .map_err(|error| match error {
        loader::GuardedLoadFailure::Diagnostics(errors) => load_errors(errors),
        loader::GuardedLoadFailure::UnsafePath(error)
        | loader::GuardedLoadFailure::BudgetExceeded(error)
        | loader::GuardedLoadFailure::TreeChanged(error)
        | loader::GuardedLoadFailure::RecoveryRequired(error)
        | loader::GuardedLoadFailure::Storage(error) => error,
    })?;
    let expected_toml: BTreeSet<_> = after
        .members()
        .iter()
        .filter(|member| member.kind() != PolicyMemberKind::Pack)
        .map(|member| guard.tree_io().identity.root.join(member.path()))
        .collect();
    ensure!(
        loaded.files_loaded.into_iter().collect::<BTreeSet<_>>() == expected_toml,
        "candidate loader selected a different TOML inventory"
    );
    Ok(())
}

fn candidate_overlays(
    guard: &write_lock::MigrationWriteLock,
    before: &PolicyRevisionInventory,
    after: &PolicyRevisionInventory,
) -> anyhow::Result<(LoaderOverlay, PackOverlay)> {
    let mut toml = LoaderOverlay::default();
    let mut packs = PackOverlay::default();
    for member in after.members() {
        let bytes = present_bytes(member)?;
        if member.kind() == PolicyMemberKind::Pack {
            let id = Id::new(
                member
                    .path()
                    .file_stem()
                    .and_then(|name| name.to_str())
                    .context("pack path is not UTF-8")?
                    .to_string(),
            )?;
            packs.stage(id, bytes.to_vec());
        } else {
            let target = guard
                .tree_io()
                .plan_target(&guard.tree_io().identity.root.join(member.path()))?;
            ensure!(
                before
                    .members()
                    .iter()
                    .any(|old| old.path() == member.path())
                    || target.is_new(),
                "candidate TOML destination is occupied outside the source inventory"
            );
            toml.stage_plan_reachable_only(&target, String::from_utf8(bytes.to_vec())?)?;
        }
    }
    for old in before.members().iter().filter(|member| {
        member.kind() == PolicyMemberKind::Pack
            && !after
                .members()
                .iter()
                .any(|new| new.path() == member.path())
    }) {
        let id = Id::new(
            old.path()
                .file_stem()
                .unwrap()
                .to_str()
                .unwrap()
                .to_string(),
        )?;
        packs.omit(id);
    }
    Ok((toml, packs))
}

fn validate_target_in_memory(
    config: &ConfigV5,
    packs: &BTreeMap<Id, Vec<u8>>,
    now: OffsetDateTime,
) -> anyhow::Result<()> {
    let bodies = PackBodiesV5::new(
        packs
            .iter()
            .map(|(id, body)| {
                Ok((
                    id.clone(),
                    Arc::<str>::from(std::str::from_utf8(body).context("pack is not UTF-8")?),
                ))
            })
            .collect::<anyhow::Result<_>>()?,
    );
    let mut warnings = crate::config::schema::validator::AuditWarnings::emitting();
    target_v5::validate_v5_collect_with_bodies(config, &bodies, now, &mut warnings, None)?;
    let admission =
        CompileAdmission::new(config.custom_list_limits.max_compiled_bytes_total.max(1), 1)?;
    target_v5::compile_v5_operator_rules(config, &bodies, &admission)?;
    Ok(())
}

fn target_profile_policy_hash(
    profile: &ProfileV5,
    added: &[Id],
    bodies: &BTreeMap<Id, Vec<u8>>,
) -> anyhow::Result<String> {
    target_profile_policy_hash_with(profile, added, |id| {
        bodies
            .get(id)
            .map(|body| std::str::from_utf8(body).context("pack is not UTF-8"))
            .transpose()?
            .with_context(|| format!("missing source profile pack body {id}"))
    })
}

fn target_profile_policy_hash_from_bodies(
    profile: &ProfileV5,
    added: &[Id],
    bodies: &PackBodiesV5,
) -> anyhow::Result<String> {
    target_profile_policy_hash_with(profile, added, |id| {
        bodies
            .get(id)
            .map(|body| body.as_ref())
            .with_context(|| format!("missing source profile pack body {id}"))
    })
}

fn target_profile_policy_hash_with<'a>(
    profile: &ProfileV5,
    added: &[Id],
    mut pack_body: impl FnMut(&Id) -> anyhow::Result<&'a str>,
) -> anyhow::Result<String> {
    let mut projected = profile.clone();
    projected.custom_lists = profile
        .custom_lists
        .iter()
        .filter(|id| !added.contains(id))
        .cloned()
        .collect();
    projected.custom_lists.sort();
    let packs = projected
        .custom_lists
        .iter()
        .map(|id| {
            Ok(SemanticPack {
                id: id.as_str(),
                body: pack_body(id)?,
            })
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    Ok(hash_profile_policy_candidate(&projected, &packs)?.to_string())
}

fn resolver_source_hash_v4(
    historical: &HistoricalConfigV4,
    device: &crate::config::schema::Device,
) -> anyhow::Result<String> {
    resolver_source_hash_parts(
        &device.id,
        &device.groups,
        historical.groups(),
        &historical.config.schedules,
    )
}

fn resolver_source_hash_v5(config: &ConfigV5, device: &DeviceV5) -> anyhow::Result<String> {
    resolver_source_hash_parts(
        &device.id,
        &device.groups,
        &config.groups,
        &config.schedules,
    )
}

fn resolver_source_hash_parts(
    device_id: &Id,
    device_groups: &[Id],
    groups: &[crate::config::schema::Group],
    schedules: &[crate::config::schema::Schedule],
) -> anyhow::Result<String> {
    #[derive(Serialize)]
    struct Membership<'a> {
        group_id: &'a Id,
        profile: &'a Id,
        priority: i32,
        device_declared: bool,
        group_declared: bool,
    }
    #[derive(Serialize)]
    struct ApplicableSchedule<'a> {
        id: &'a Id,
        target_type: ScheduleTargetType,
        target_id: &'a Id,
        profile: &'a Id,
        days: &'a [String],
        hours: &'a str,
        expires_at: &'a Option<OffsetDateTime>,
    }
    #[derive(Serialize)]
    struct ResolverSource<'a> {
        device_id: &'a Id,
        memberships: Vec<Membership<'a>>,
        schedules: Vec<ApplicableSchedule<'a>>,
    }
    let direct: BTreeSet<_> = device_groups.iter().collect();
    let mut membership_groups: Vec<_> = groups
        .iter()
        .filter(|group| direct.contains(&group.id) || group.devices.contains(device_id))
        .collect();
    membership_groups.sort_by(|left, right| left.id.cmp(&right.id));
    let membership_ids: BTreeSet<_> = membership_groups.iter().map(|group| &group.id).collect();
    let memberships = membership_groups
        .into_iter()
        .map(|group| Membership {
            group_id: &group.id,
            profile: &group.profile,
            priority: group.priority,
            device_declared: direct.contains(&group.id),
            group_declared: group.devices.contains(device_id),
        })
        .collect();
    let mut applicable_schedules: Vec<_> = schedules
        .iter()
        .filter(|schedule| match schedule.target_type {
            ScheduleTargetType::Device => schedule.target_id == *device_id,
            ScheduleTargetType::Group => membership_ids.contains(&schedule.target_id),
        })
        .collect();
    applicable_schedules.sort_by(|left, right| left.id.cmp(&right.id));
    let schedules = applicable_schedules
        .into_iter()
        .map(|schedule| ApplicableSchedule {
            id: &schedule.id,
            target_type: schedule.target_type,
            target_id: &schedule.target_id,
            profile: &schedule.profile,
            days: &schedule.days,
            hours: &schedule.hours,
            expires_at: &schedule.expires_at,
        })
        .collect();
    digest_serialized(
        b"warden/uor/migration-resolver-source/v1\0",
        &ResolverSource {
            device_id,
            memberships,
            schedules,
        },
    )
}

pub fn lint_migration_origins(config: &ConfigV5) -> Vec<MigrationLintFindingV1> {
    lint_migration_origins_inner(config, None)
}

pub fn lint_migration_origins_with_bodies(
    config: &ConfigV5,
    bodies: &PackBodiesV5,
) -> Vec<MigrationLintFindingV1> {
    lint_migration_origins_inner(config, Some(bodies))
}

fn lint_migration_origins_inner(
    config: &ConfigV5,
    bodies: Option<&PackBodiesV5>,
) -> Vec<MigrationLintFindingV1> {
    let mut findings = Vec::new();
    for (profile_id, clone) in &config.profiles {
        let Some(origin) = clone.migration_origin.as_ref() else {
            continue;
        };
        let Some(source) = config.profiles.get(origin.source_profile.as_str()) else {
            findings.push(MigrationLintFindingV1 {
                profile_id: profile_id.clone(),
                code: "migration_source_missing".into(),
                detail: format!("source profile {} no longer exists", origin.source_profile),
            });
            continue;
        };
        match bodies {
            Some(bodies) => {
                let source_policy_hash =
                    target_profile_policy_hash_from_bodies(source, &[], bodies);
                let clone_policy_hash = target_profile_policy_hash_from_bodies(
                    clone,
                    &origin.added_custom_lists,
                    bodies,
                );
                if !matches!(source_policy_hash.as_deref(), Ok(value) if value == origin.source_policy_hash)
                    || !matches!(clone_policy_hash.as_deref(), Ok(value) if value == origin.source_policy_hash)
                {
                    findings.push(MigrationLintFindingV1 {
                        profile_id: profile_id.clone(),
                        code: "migration_clone_drift".into(),
                        detail: "the source or clone policy changed after the migration snapshot"
                            .into(),
                    });
                }
                let source_digests = profile_pack_digests_from_bodies(source, &[], bodies);
                let clone_digests =
                    profile_pack_digests_from_bodies(clone, &origin.added_custom_lists, bodies);
                if !matches!(source_digests.as_ref(), Ok(value) if value == &origin.source_pack_digests)
                    || !matches!(clone_digests.as_ref(), Ok(value) if value == &origin.source_pack_digests)
                {
                    findings.push(MigrationLintFindingV1 {
                        profile_id: profile_id.clone(),
                        code: "migration_pack_bytes_changed_unclassified".into(),
                        detail: "a source-profile pack body is absent or byte-different; this byte-level diagnostic does not determine semantic drift".into(),
                    });
                }
            }
            None if source_has_packs(source, &[])
                || source_has_packs(clone, &origin.added_custom_lists) =>
            {
                findings.push(MigrationLintFindingV1 {
                    profile_id: profile_id.clone(),
                    code: "migration_pack_policy_unverified".into(),
                    detail: "pack bodies were not supplied; migration origin policy reassessment is incomplete".into(),
                });
            }
            None => {
                let no_bodies = BTreeMap::new();
                if target_profile_policy_hash(source, &[], &no_bodies)
                    .ok()
                    .as_deref()
                    != Some(origin.source_policy_hash.as_str())
                    || target_profile_policy_hash(clone, &origin.added_custom_lists, &no_bodies)
                        .ok()
                        .as_deref()
                        != Some(origin.source_policy_hash.as_str())
                {
                    findings.push(MigrationLintFindingV1 {
                        profile_id: profile_id.clone(),
                        code: "migration_clone_drift".into(),
                        detail: "the source or clone policy changed after the migration snapshot"
                            .into(),
                    });
                }
            }
        }
        match config
            .devices
            .iter()
            .find(|device| device.id == origin.device_id)
        {
            Some(device)
                if resolver_source_hash_v5(config, device).ok().as_deref()
                    == Some(origin.resolver_source_hash.as_str()) => {}
            Some(_) => findings.push(MigrationLintFindingV1 {
                profile_id: profile_id.clone(),
                code: "migration_resolver_reassessment".into(),
                detail: "group membership, priority, or an applicable schedule changed".into(),
            }),
            None => findings.push(MigrationLintFindingV1 {
                profile_id: profile_id.clone(),
                code: "migration_device_missing".into(),
                detail: format!("source device {} no longer exists", origin.device_id),
            }),
        }
    }
    findings.sort_by(|left, right| {
        (left.profile_id.as_str(), left.code.as_str())
            .cmp(&(right.profile_id.as_str(), right.code.as_str()))
    });
    findings
}

fn source_has_packs(profile: &ProfileV5, excluded: &[Id]) -> bool {
    profile.custom_lists.iter().any(|id| !excluded.contains(id))
}

fn profile_pack_digests(
    profile: &ProfileV5,
    excluded: &[Id],
    bodies: &BTreeMap<Id, Vec<u8>>,
) -> anyhow::Result<BTreeMap<Id, String>> {
    profile
        .custom_lists
        .iter()
        .filter(|id| !excluded.contains(id))
        .map(|id| {
            Ok((
                id.clone(),
                digest(
                    bodies
                        .get(id)
                        .with_context(|| format!("missing source profile pack body {id}"))?,
                ),
            ))
        })
        .collect()
}

fn profile_pack_digests_from_bodies(
    profile: &ProfileV5,
    excluded: &[Id],
    bodies: &PackBodiesV5,
) -> anyhow::Result<BTreeMap<Id, String>> {
    profile
        .custom_lists
        .iter()
        .filter(|id| !excluded.contains(id))
        .map(|id| {
            Ok((
                id.clone(),
                digest(
                    bodies
                        .get(id)
                        .with_context(|| format!("missing source profile pack body {id}"))?
                        .as_bytes(),
                ),
            ))
        })
        .collect()
}

fn digest_serialized(domain: &[u8], value: &impl Serialize) -> anyhow::Result<String> {
    let bytes = serde_json::to_vec(value)?;
    let mut hash = Sha256::new();
    hash.update(domain);
    update_lp(&mut hash, &bytes);
    Ok(hex(&hash.finalize()))
}

fn digest(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

fn compute_plan_hash(plan: &MigrationPlanV1) -> anyhow::Result<String> {
    let mut unsigned = plan.clone();
    unsigned.plan_hash.clear();
    digest_serialized(PLAN_HASH_DOMAIN, &unsigned)
}

fn receipt_manifest(plan: &MigrationPlanV1) -> anyhow::Result<serde_json::Value> {
    Ok(serde_json::json!({
        "manifest_version": 1,
        "kind": "v4_to_v5_migration",
        "planner_version": plan.planner_version,
        "plan_hash": plan.plan_hash,
        "source_config_revision": plan.source_config_revision,
        "source_operator_policy_hash": plan.source_operator_policy_hash,
        "candidate_config_revision": plan.candidate_config_revision,
        "candidate_operator_policy_hash": plan.candidate_operator_policy_hash,
        "choices_digest": plan.choices_digest,
        "mappings": plan.mappings,
        "clones": plan.clones,
        "source_inventory": plan.source_inventory,
        "candidate_inventory": plan.candidate_inventory,
        "filesystem_operations": plan.filesystem_operations,
        "findings": plan.findings,
    }))
}

fn migration_audit(plan: &MigrationPlanV1) -> policy_transaction::ReceiptAuditContext {
    let mut list_ids = Vec::new();
    let mut profile_ids = Vec::new();
    for mapping in &plan.mappings {
        match mapping.kind {
            MigrationMappingKindV1::ProfileList
            | MigrationMappingKindV1::DeviceList
            | MigrationMappingKindV1::UnmountedArchive => list_ids.push(mapping.target_id.clone()),
            MigrationMappingKindV1::DeviceClone => profile_ids.push(mapping.target_id.clone()),
        }
    }
    list_ids.sort();
    list_ids.dedup();
    profile_ids.sort();
    profile_ids.dedup();
    let truncated = list_ids.len() > 64 || profile_ids.len() > 64;
    list_ids.truncate(64);
    profile_ids.truncate(64);
    policy_transaction::ReceiptAuditContext {
        list_ids,
        profile_ids,
        operations: plan
            .filesystem_operations
            .len()
            .try_into()
            .unwrap_or(u32::MAX),
        rules_added: plan
            .mappings
            .iter()
            .map(|mapping| mapping.rule_ids.len())
            .sum::<usize>()
            .try_into()
            .unwrap_or(u32::MAX),
        mounts_added: plan.mappings.len().try_into().unwrap_or(u32::MAX),
        affected_profiles: plan.clones.len().try_into().unwrap_or(u32::MAX),
        affected_destinations: plan.clones.len().try_into().unwrap_or(u32::MAX),
        truncated,
        ..policy_transaction::ReceiptAuditContext::default()
    }
}

fn persistence_name(persistence: Persistence) -> &'static str {
    match persistence {
        Persistence::Prepared => "prepared",
        Persistence::Committed => "committed",
        Persistence::Aborted => "aborted",
        Persistence::DurabilityUncertain => "durability_uncertain",
    }
}

fn load_errors(errors: Vec<crate::config::error::ConfigError>) -> anyhow::Error {
    anyhow::anyhow!(
        "configuration load failed: {}",
        errors
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("; ")
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    fn apply(
        master: &Path,
        supplied_plan: &MigrationPlanV1,
        expected_plan_hash: &str,
    ) -> anyhow::Result<ApplyReceiptV1> {
        super::apply_with_pid_file(
            master,
            &master.with_extension("test.pid"),
            supplied_plan,
            expected_plan_hash,
        )
    }

    fn rollback(
        master: &Path,
        receipt_id: &str,
        expected_revision: &str,
    ) -> anyhow::Result<RollbackResultV1> {
        super::rollback_with_pid_file(
            master,
            &master.with_extension("test.pid"),
            receipt_id,
            expected_revision,
        )
    }

    fn finalize(master: &Path, receipt_id: &str) -> anyhow::Result<FinalizeResultV1> {
        super::finalize_with_pid_file(master, &master.with_extension("test.pid"), receipt_id)
    }

    fn fixture(body: &str) -> (tempfile::TempDir, PathBuf) {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join("packs")).unwrap();
        let master = root.path().join("config.toml");
        fs::write(&master, body).unwrap();
        (root, master)
    }

    fn simple() -> &'static str {
        r#"schema_version = 4

[server]
default_profile = "base"

[profiles.base]
display_name = "Base"
admin_rules = ["deny-example"]

[[admin_rules]]
id = "deny-example"
rule = "||example.test^"

[upstream]
servers = ["192.0.2.1:53"]
"#
    }

    fn tree_bytes(root: &Path) -> Vec<(PathBuf, Vec<u8>)> {
        fn walk(root: &Path, current: &Path, out: &mut Vec<(PathBuf, Vec<u8>)>) {
            let mut entries: Vec<_> = fs::read_dir(current).unwrap().map(Result::unwrap).collect();
            entries.sort_by_key(|entry| entry.file_name());
            for entry in entries {
                let path = entry.path();
                if entry.file_type().unwrap().is_dir() {
                    walk(root, &path, out);
                } else {
                    out.push((
                        path.strip_prefix(root).unwrap().to_path_buf(),
                        fs::read(path).unwrap(),
                    ));
                }
            }
        }
        let mut out = Vec::new();
        walk(root, root, &mut out);
        out
    }

    fn mark_lease_aware(master: &Path) {
        let lease = crate::config::runtime_lease::acquire_for_daemon(master).unwrap();
        lease.attest_schema5_runtime(5).unwrap();
    }

    #[test]
    fn planning_is_pure_deterministic_and_choice_sensitive() {
        let (root, master) = fixture(simple());
        let before = tree_bytes(root.path());
        let first = plan(&master, None).unwrap();
        let second = plan(&master, None).unwrap();
        assert_eq!(first, second);
        assert_eq!(tree_bytes(root.path()), before);
        assert!(!first.blocked);
        assert!(first.verify_hash().is_ok());

        let mut choices = MigrationChoicesV1::empty(&first.source_config_revision);
        choices
            .list_mappings
            .push(super::super::choices::MappingChoiceV1 {
                source_id: "base".into(),
                target_id: "chosen-profile-rules".into(),
            });
        let revised = plan(&master, Some(choices)).unwrap();
        assert_ne!(first.plan_hash, revised.plan_hash);
        assert_ne!(first.mappings, revised.mappings);
        assert_eq!(tree_bytes(root.path()), before);
    }

    #[test]
    fn finding_collection_refuses_to_exceed_its_explicit_budget() {
        let mut findings = Vec::new();
        for index in 0..MAX_MIGRATION_FINDINGS {
            record_finding(
                &mut findings,
                finding(
                    FindingCodeV1::AdvancedEquivalenceUnsupported,
                    format!("profile:p:rule:{index}"),
                    "bounded test".into(),
                    EquivalenceV1::Unproven,
                    None,
                    None,
                    None,
                    vec!["defer"],
                    &"0".repeat(64),
                ),
            )
            .unwrap();
        }
        let error = record_finding(
            &mut findings,
            finding(
                FindingCodeV1::AdvancedEquivalenceUnsupported,
                "profile:p:overflow".into(),
                "bounded test".into(),
                EquivalenceV1::Unproven,
                None,
                None,
                None,
                vec!["defer"],
                &"0".repeat(64),
            ),
        )
        .unwrap_err();
        assert!(error.to_string().contains("finding budget exceeded"));
        assert_eq!(findings.len(), MAX_MIGRATION_FINDINGS);
    }

    #[test]
    fn candidate_operator_policy_hash_uses_shared_target_hasher() {
        let (_root, master) = fixture(simple());
        let guard = write_lock::acquire_for_read(&master).unwrap();
        let loaded = loader::load_config_for_schema_under_read_guard(
            &guard,
            &master,
            SOURCE_SCHEMA,
            OffsetDateTime::UNIX_EPOCH,
        )
        .unwrap();
        let (snapshot, loaded) = policy_revision::capture_coherent_loaded_under_read_guard(
            &guard,
            &loaded,
            SOURCE_SCHEMA,
            OffsetDateTime::UNIX_EPOCH,
        )
        .unwrap();
        let candidate = build(&snapshot, &loaded, None).unwrap();
        let inventory = candidate.inventory.as_ref().unwrap();
        let config: ConfigV5 = inventory
            .members()
            .iter()
            .find(|member| member.kind() == PolicyMemberKind::Master)
            .and_then(|member| match member.state() {
                PolicyMemberState::Present(bytes) => Some(bytes),
                PolicyMemberState::Absent => None,
            })
            .map(|bytes| toml::from_str(std::str::from_utf8(bytes).unwrap()).unwrap())
            .unwrap();
        let packs = inventory
            .members()
            .iter()
            .filter(|member| member.kind() == PolicyMemberKind::Pack)
            .map(|member| {
                let id = Id::new(
                    member
                        .path()
                        .file_stem()
                        .unwrap()
                        .to_str()
                        .unwrap()
                        .to_string(),
                )
                .unwrap();
                let PolicyMemberState::Present(body) = member.state() else {
                    panic!("candidate pack must be present");
                };
                (id, body.clone())
            })
            .collect::<BTreeMap<_, _>>();
        let semantic_packs = packs
            .iter()
            .map(|(id, body)| SemanticPack {
                id: id.as_str(),
                body: std::str::from_utf8(body).unwrap(),
            })
            .collect::<Vec<_>>();
        let expected = hash_policy_candidate(&config, &semantic_packs)
            .unwrap()
            .to_string();
        assert_eq!(
            candidate.plan.candidate_operator_policy_hash.as_deref(),
            Some(expected.as_str())
        );
    }

    #[test]
    fn every_profile_reports_lattice_grant_and_cname_changes() {
        let (_root, master) = fixture(
            r#"schema_version = 4
[server]
default_profile = "base"
[profiles.base]
block_all = true
admin_rules = ["allow", "deny-important", "allow-advanced"]
[[admin_rules]]
id = "allow"
rule = "@@||example.test^"
[[admin_rules]]
id = "deny-important"
rule = "||example.test^$important"
[[admin_rules]]
id = "allow-advanced"
rule = "@@||*.advanced.test^"
[upstream]
servers = ["192.0.2.1:53"]
"#,
        );
        let plan = plan(&master, None).unwrap();
        let codes: Vec<_> = plan.findings.iter().map(|finding| &finding.code).collect();
        assert!(codes.contains(&&FindingCodeV1::LatticeVerdictChanges));
        assert!(codes.contains(&&FindingCodeV1::ResponseAuthorityChanges));
        assert!(codes.contains(&&FindingCodeV1::AllowGrantChanges));
        assert!(codes.contains(&&FindingCodeV1::AdvancedEquivalenceUnsupported));
        assert!(plan.blocked);
    }

    #[test]
    fn mounted_pack_and_disjoint_response_targets_are_part_of_profile_analysis() {
        let (root, master) = fixture(
            r#"schema_version = 4
[server]
default_profile = "base"
[profiles.base]
custom_lists = ["mounted"]
admin_rules = ["deny-important", "allow-important-exact"]
[[custom_lists]]
id = "mounted"
display_name = "Mounted"
[[admin_rules]]
id = "deny-important"
rule = "||blocked.test^$important"
[[admin_rules]]
id = "allow-important-exact"
rule = "@@||important.test^$important"
[upstream]
servers = ["192.0.2.1:53"]
"#,
        );
        fs::write(root.path().join("packs/mounted.txt"), "@@||allowed.test^\n").unwrap();

        let plan = plan(&master, None).unwrap();
        let response = plan
            .findings
            .iter()
            .find(|finding| {
                finding.code == FindingCodeV1::ResponseAuthorityChanges
                    && finding.scope.contains("custom-list:mounted:row:1")
            })
            .expect("mounted ordinary allow must be analyzed");
        let witness = response.witness.as_deref().unwrap();
        assert!(witness.contains("allowed.test"));
        assert!(witness.contains("blocked.test"));
        assert!(plan.findings.iter().any(|finding| {
            finding.code == FindingCodeV1::AllowGrantChanges
                && finding.scope.contains("admin:allow-important-exact")
        }));
    }

    #[test]
    fn overlay_analysis_covers_the_ordered_oracle_and_response_grants() {
        let (_root, master) = fixture(
            r#"schema_version = 4
[server]
default_profile = "base"
[profiles.base]
admin_rules = ["pa-ordinary", "pa-important", "pd-ordinary", "pd-important"]
[[admin_rules]]
id = "pa-ordinary"
rule = "@@||ordinary-allow.test^"
[[admin_rules]]
id = "pa-important"
rule = "@@||important-allow.test^$important"
[[admin_rules]]
id = "pd-ordinary"
rule = "||ordinary-deny.test^"
[[admin_rules]]
id = "pd-important"
rule = "||important-deny.test^$important"
[[admin_rules]]
id = "da-vs-ordinary"
rule = "@@||ordinary-deny.test^"
[[admin_rules]]
id = "da-vs-important"
rule = "@@||important-deny.test^"
[[admin_rules]]
id = "dd-vs-ordinary"
rule = "||ordinary-allow.test^"
[[admin_rules]]
id = "dd-vs-important"
rule = "||important-allow.test^"
[[admin_rules]]
id = "both-allow"
rule = "@@||both.test^"
[[admin_rules]]
id = "both-deny"
rule = "||both.test^"
[[admin_rules]]
id = "qname-allow"
rule = "@@||qname-only.test^"
[[devices]]
id = "screen"
display_name = "Screen"
ip = "192.0.2.20"
profile = "base"
allow_rules = ["da-vs-ordinary", "da-vs-important", "both-allow", "qname-allow"]
deny_rules = ["dd-vs-ordinary", "dd-vs-important", "both-deny"]
override_profile_deny = false
[upstream]
servers = ["192.0.2.1:53"]
"#,
        );

        let plan = plan(&master, None).unwrap();
        for fragment in [
            "rule:da-vs-ordinary:profile-rule:admin:pd-ordinary",
            "rule:da-vs-important:profile-rule:admin:pd-important",
            "rule:dd-vs-ordinary:profile-rule:admin:pa-ordinary",
            "rule:dd-vs-important:profile-rule:admin:pa-important",
            "allow:both-allow:deny:both-deny",
        ] {
            assert!(
                plan.findings.iter().any(|finding| {
                    finding.code == FindingCodeV1::OverlayPrecedenceNotRepresentable
                        && finding.scope.contains(fragment)
                }),
                "missing overlay finding for {fragment}"
            );
        }
        let response = plan
            .findings
            .iter()
            .find(|finding| {
                finding.code == FindingCodeV1::ResponseAuthorityChanges
                    && finding
                        .scope
                        .contains("rule:qname-allow:response-profile-rule:admin:pd-ordinary")
            })
            .expect("device query allow versus a disjoint ordinary CNAME deny must be analyzed");
        let witness = response.witness.as_deref().unwrap();
        assert!(witness.contains("qname-only.test"));
        assert!(witness.contains("ordinary-deny.test"));
    }

    #[test]
    fn target_validation_surfaces_migration_origin_reassessment() {
        let (_root, master) = fixture(simple());
        let loaded = loader::load_config(&master, OffsetDateTime::UNIX_EPOCH).unwrap();
        let mut target = target_config(&loaded.config).unwrap();
        target.profiles.get_mut("base").unwrap().migration_origin = Some(MigrationOriginV1 {
            source_profile: Id::new("missing-source").unwrap(),
            source_group: None,
            device_id: Id::new("missing-device").unwrap(),
            source_policy_hash: "0".repeat(64),
            source_pack_digests: BTreeMap::new(),
            resolver_source_hash: "1".repeat(64),
            added_custom_lists: Vec::new(),
        });
        let mut warnings = crate::config::schema::validator::AuditWarnings::silent();
        target_v5::validate_v5_collect(&target, OffsetDateTime::UNIX_EPOCH, &mut warnings, None)
            .unwrap();
        assert!(warnings
            .into_messages()
            .iter()
            .any(|message| message.contains("migration_source_missing")));
    }

    #[test]
    fn migration_origin_lint_reassesses_group_and_schedule_drift() {
        let (_root, master) = fixture(
            r#"schema_version = 4
[server]
default_profile = "base"
[profiles.base]
[[devices]]
id = "screen"
display_name = "Screen"
ip = "192.0.2.20"
groups = ["room"]
[[groups]]
id = "room"
display_name = "Room"
profile = "base"
priority = 10
[[schedules]]
id = "night"
display_name = "Night"
target_type = "group"
target_id = "room"
profile = "base"
days = ["all"]
hours = "23:00-23:01"
[upstream]
servers = ["192.0.2.1:53"]
"#,
        );
        let loaded = loader::load_config(&master, OffsetDateTime::UNIX_EPOCH).unwrap();
        let mut target = target_config(&loaded.config).unwrap();
        let source = target.profiles.get("base").unwrap().clone();
        let source_policy_hash =
            target_profile_policy_hash(&source, &[], &BTreeMap::new()).unwrap();
        let resolver_source_hash = resolver_source_hash_v5(&target, &target.devices[0]).unwrap();
        let mut clone = source;
        clone.display_name = "Screen snapshot".into();
        clone.migration_origin = Some(MigrationOriginV1 {
            source_profile: Id::new("base").unwrap(),
            source_group: Some(Id::new("room").unwrap()),
            device_id: Id::new("screen").unwrap(),
            source_policy_hash,
            source_pack_digests: BTreeMap::new(),
            resolver_source_hash,
            added_custom_lists: Vec::new(),
        });
        target.profiles.insert("screen-snapshot".into(), clone);
        target.devices[0].profile = Some(Id::new("screen-snapshot").unwrap());
        assert!(lint_migration_origins(&target).is_empty());

        let mut descriptive_edit = target.clone();
        descriptive_edit.groups[0].display_name = "Renamed room".into();
        descriptive_edit.schedules[0].display_name = "Renamed night".into();
        assert!(lint_migration_origins(&descriptive_edit).is_empty());

        let mut membership_direction_drift = target.clone();
        membership_direction_drift.devices[0].groups.clear();
        membership_direction_drift.groups[0]
            .devices
            .push(Id::new("screen").unwrap());
        assert!(lint_migration_origins(&membership_direction_drift)
            .iter()
            .any(|finding| finding.code == "migration_resolver_reassessment"));

        let mut group_drift = target.clone();
        group_drift.groups[0].priority += 1;
        assert!(lint_migration_origins(&group_drift)
            .iter()
            .any(|finding| finding.code == "migration_resolver_reassessment"));

        let mut schedule_drift = target;
        schedule_drift.schedules[0].hours = "22:00-22:01".into();
        assert!(lint_migration_origins(&schedule_drift)
            .iter()
            .any(|finding| finding.code == "migration_resolver_reassessment"));
    }

    #[test]
    fn migration_origin_lint_requires_bodies_and_detects_pack_body_drift() {
        let (_root, master) = fixture(simple());
        let loaded = loader::load_config(&master, OffsetDateTime::UNIX_EPOCH).unwrap();
        let mut target = target_config(&loaded.config).unwrap();
        let pack_id = Id::new("base-policy").unwrap();
        target.custom_lists.push(CustomList {
            id: pack_id.clone(),
            display_name: "Base policy".into(),
            description: String::new(),
        });
        target
            .profiles
            .get_mut("base")
            .unwrap()
            .custom_lists
            .push(pack_id.clone());
        let source = target.profiles.get("base").unwrap().clone();
        let raw_bodies = BTreeMap::from([(pack_id.clone(), b"||before.example^\n".to_vec())]);
        let mut clone = source.clone();
        clone.display_name = "Device snapshot".into();
        clone.migration_origin = Some(MigrationOriginV1 {
            source_profile: Id::new("base").unwrap(),
            source_group: None,
            device_id: Id::new("device").unwrap(),
            source_policy_hash: target_profile_policy_hash(&source, &[], &raw_bodies).unwrap(),
            source_pack_digests: profile_pack_digests(&source, &[], &raw_bodies).unwrap(),
            resolver_source_hash: "1".repeat(64),
            added_custom_lists: Vec::new(),
        });
        target.profiles.insert("device-snapshot".into(), clone);

        let unrelated_id = Id::new("unrelated-policy").unwrap();
        target.custom_lists.push(CustomList {
            id: unrelated_id.clone(),
            display_name: "Unrelated policy".into(),
            description: String::new(),
        });
        target.profiles.insert(
            "unrelated".into(),
            ProfileV5 {
                custom_lists: vec![unrelated_id.clone()],
                ..ProfileV5::default()
            },
        );

        assert!(lint_migration_origins(&target)
            .iter()
            .any(|finding| finding.code == "migration_pack_policy_unverified"));

        let matching = PackBodiesV5::new(BTreeMap::from([
            (pack_id.clone(), Arc::<str>::from("||before.example^\n")),
            (
                unrelated_id.clone(),
                Arc::<str>::from("||unrelated-before.example^\n"),
            ),
        ]));
        assert!(!lint_migration_origins_with_bodies(&target, &matching)
            .iter()
            .any(|finding| finding.code == "migration_pack_bytes_changed_unclassified"));

        let unrelated_changed = PackBodiesV5::new(BTreeMap::from([
            (pack_id.clone(), Arc::<str>::from("||before.example^\n")),
            (
                unrelated_id.clone(),
                Arc::<str>::from("||unrelated-after.example^\n"),
            ),
        ]));
        assert!(
            !lint_migration_origins_with_bodies(&target, &unrelated_changed)
                .iter()
                .any(|finding| finding.code == "migration_clone_drift")
        );

        let comment_only = PackBodiesV5::new(BTreeMap::from([(
            pack_id.clone(),
            Arc::<str>::from("# cosmetic\n||before.example^\n"),
        )]));
        let comment_findings = lint_migration_origins_with_bodies(&target, &comment_only);
        assert!(comment_findings
            .iter()
            .any(|finding| finding.code == "migration_pack_bytes_changed_unclassified"));
        assert!(!comment_findings
            .iter()
            .any(|finding| finding.code == "migration_clone_drift"));

        let rule_changed = PackBodiesV5::new(BTreeMap::from([
            (pack_id, Arc::<str>::from("||after.example^\n")),
            (
                unrelated_id,
                Arc::<str>::from("||unrelated-before.example^\n"),
            ),
        ]));
        let findings = lint_migration_origins_with_bodies(&target, &rule_changed);
        assert!(findings
            .iter()
            .any(|finding| finding.code == "migration_pack_bytes_changed_unclassified"));
        assert!(findings
            .iter()
            .any(|finding| finding.code == "migration_clone_drift"));

        let mut warnings = crate::config::schema::validator::AuditWarnings::silent();
        target_v5::validate_v5_collect_with_bodies(
            &target,
            &rule_changed,
            OffsetDateTime::UNIX_EPOCH,
            &mut warnings,
            None,
        )
        .unwrap();
        assert!(warnings
            .into_messages()
            .iter()
            .any(|message| message.contains("migration_pack_bytes_changed_unclassified")));
    }

    #[test]
    fn device_analysis_uses_reverse_group_membership_and_inactive_schedule() {
        let (_root, master) = fixture(
            r#"schema_version = 4
[server]
default_profile = "base"
[profiles.base]
admin_rules = ["profile-allow"]
[profiles.night]
[[admin_rules]]
id = "profile-allow"
rule = "@@||example.test^$important"
[[admin_rules]]
id = "device-deny"
rule = "||example.test^"
[[devices]]
id = "screen"
display_name = "Screen"
ip = "192.0.2.20"
deny_rules = ["device-deny"]
[[groups]]
id = "room"
display_name = "Room"
profile = "base"
devices = ["screen"]
[[schedules]]
id = "night"
display_name = "Night"
target_type = "group"
target_id = "room"
profile = "night"
days = ["all"]
hours = "23:00-23:01"
[upstream]
servers = ["192.0.2.1:53"]
"#,
        );
        let plan = plan(&master, None).unwrap();
        assert!(plan.findings.iter().any(|finding| {
            finding.code == FindingCodeV1::DynamicProfileSource && finding.scope == "device:screen"
        }));
        assert!(plan
            .findings
            .iter()
            .any(|finding| { finding.code == FindingCodeV1::OverlayPrecedenceNotRepresentable }));
        assert_eq!(plan.clones[0].source_group.as_deref(), Some("room"));
    }

    #[test]
    fn granular_acceptance_stays_declared_in_the_replanned_result() {
        let (_root, master) = fixture(
            r#"schema_version = 4
[server]
default_profile = "base"
[profiles.base]
admin_rules = ["allow-advanced"]
[[admin_rules]]
id = "allow-advanced"
rule = "@@||*.advanced.test^"
[upstream]
servers = ["192.0.2.1:53"]
"#,
        );
        let initial = plan(&master, None).unwrap();
        let mut choices = MigrationChoicesV1::empty(&initial.source_config_revision);
        choices.finding_decisions = initial
            .findings
            .iter()
            .map(|finding| FindingDecisionV1 {
                finding_id: finding.finding_id.clone(),
                decision: MigrationDecisionV1::AcceptV5Semantics,
            })
            .collect();
        let accepted = plan(&master, Some(choices)).unwrap();
        assert!(!accepted.blocked);
        assert!(accepted.findings.iter().all(|finding| matches!(
            finding.equivalence,
            EquivalenceV1::ChangedAccepted | EquivalenceV1::UnprovenAccepted
        )));
    }

    #[test]
    fn apply_rollback_and_finalize_are_receipt_scoped() {
        let (root, master) = fixture(simple());
        mark_lease_aware(&master);
        let original = fs::read(&master).unwrap();
        let planned = plan(&master, None).unwrap();
        let receipt = apply(&master, &planned, &planned.plan_hash).unwrap();
        assert_eq!(receipt.persistence, "committed");
        assert!(String::from_utf8(fs::read(&master).unwrap())
            .unwrap()
            .contains("schema_version = 5"));
        let rollback_result = rollback(
            &master,
            &receipt.receipt_id,
            &receipt.candidate_config_revision,
        )
        .unwrap();
        assert!(matches!(rollback_result, RollbackResultV1::Restored { .. }));
        assert_eq!(fs::read(&master).unwrap(), original);

        let (other_root, other_master) = fixture(simple());
        mark_lease_aware(&other_master);
        let other_plan = plan(&other_master, None).unwrap();
        let other = apply(&other_master, &other_plan, &other_plan.plan_hash).unwrap();
        assert!(matches!(
            finalize(&other_master, &other.receipt_id).unwrap(),
            FinalizeResultV1::Finalized { .. }
        ));
        assert!(matches!(
            rollback(
                &other_master,
                &other.receipt_id,
                &other.candidate_config_revision
            )
            .unwrap(),
            RollbackResultV1::NotFound
        ));
        drop((root, other_root));
    }

    #[test]
    fn tree_bound_daemon_lease_spans_load_and_blocks_apply_and_rollback() {
        let (_root, master) = fixture(simple());
        let planned = plan(&master, None).unwrap();
        let daemon_lease = crate::config::runtime_lease::acquire_for_daemon(&master).unwrap();
        loader::load_config(&master, OffsetDateTime::UNIX_EPOCH).unwrap();
        daemon_lease.attest_schema5_runtime(5).unwrap();
        let before = fs::read(&master).unwrap();
        let apply_error = apply(&master, &planned, &planned.plan_hash).unwrap_err();
        assert!(apply_error.to_string().contains("NodeNotOffline"));
        assert_eq!(fs::read(&master).unwrap(), before);
        drop(daemon_lease);

        let receipt = apply(&master, &planned, &planned.plan_hash).unwrap();
        let migrated = fs::read(&master).unwrap();
        let daemon_lease = crate::config::runtime_lease::acquire_for_daemon(&master).unwrap();
        let rollback_error = rollback(
            &master,
            &receipt.receipt_id,
            &receipt.candidate_config_revision,
        )
        .unwrap_err();
        assert!(rollback_error.to_string().contains("NodeNotOffline"));
        assert_eq!(fs::read(&master).unwrap(), migrated);
        drop(daemon_lease);
        assert!(matches!(
            rollback(
                &master,
                &receipt.receipt_id,
                &receipt.candidate_config_revision,
            )
            .unwrap(),
            RollbackResultV1::Restored { .. }
        ));
    }

    #[test]
    fn fresh_schema4_apply_and_receipt_rollback_need_no_runtime_attestation() {
        let (root, master) = fixture(simple());
        let original = fs::read(&master).unwrap();
        let capability = root.path().join(".purge-warden-runtime-capability.json");
        let planned = plan(&master, None).unwrap();
        let receipt = apply(&master, &planned, &planned.plan_hash).unwrap();
        assert_eq!(receipt.persistence, "committed");
        assert!(!capability.exists());
        loader::load_config_v5_executable(&master, OffsetDateTime::now_utc()).unwrap();
        let replay = apply(&master, &planned, &planned.plan_hash).unwrap();
        assert_eq!(replay, receipt);
        assert!(rollback(&master, &receipt.receipt_id, "wrong-revision").is_err());
        assert!(matches!(
            rollback(
                &master,
                &receipt.receipt_id,
                &receipt.candidate_config_revision
            )
            .unwrap(),
            RollbackResultV1::Restored { .. }
        ));
        assert_eq!(fs::read(&master).unwrap(), original);
        assert!(!capability.exists());
        assert!(matches!(
            rollback(
                &master,
                &receipt.receipt_id,
                &receipt.candidate_config_revision
            )
            .unwrap(),
            RollbackResultV1::AlreadyRestored { .. }
        ));
    }

    #[test]
    fn rolled_back_bootstrap_can_apply_the_same_plan_once_again() {
        let (root, master) = fixture(simple());
        let original = fs::read(&master).unwrap();
        let planned = plan(&master, None).unwrap();
        let first = apply(&master, &planned, &planned.plan_hash).unwrap();
        assert!(matches!(
            rollback(&master, &first.receipt_id, &first.candidate_config_revision).unwrap(),
            RollbackResultV1::Restored { .. }
        ));
        assert_eq!(fs::read(&master).unwrap(), original);
        assert_eq!(plan(&master, None).unwrap(), planned);

        let second = apply(&master, &planned, &planned.plan_hash).unwrap();
        assert_eq!(second.persistence, "committed");
        assert_ne!(second.receipt_id, first.receipt_id);
        assert_eq!(second.plan_hash, first.plan_hash);
        assert_eq!(
            second.candidate_config_revision,
            first.candidate_config_revision
        );
        let after = tree_bytes(root.path());
        assert_eq!(
            apply(&master, &planned, &planned.plan_hash).unwrap(),
            second
        );
        assert_eq!(tree_bytes(root.path()), after);
        loader::load_config_v5_executable(&master, OffsetDateTime::now_utc()).unwrap();

        assert!(matches!(
            rollback(&master, &first.receipt_id, &first.candidate_config_revision).unwrap(),
            RollbackResultV1::AlreadyRestored { .. }
        ));
        assert_eq!(tree_bytes(root.path()), after);
        assert!(matches!(
            rollback(
                &master,
                &second.receipt_id,
                &second.candidate_config_revision
            )
            .unwrap(),
            RollbackResultV1::Restored { .. }
        ));
        assert_eq!(fs::read(&master).unwrap(), original);
    }

    #[test]
    fn fresh_bootstrap_refuses_wrong_hash_stale_source_and_blocked_plan() {
        let (root, master) = fixture(simple());
        let original = fs::read(&master).unwrap();
        let planned = plan(&master, None).unwrap();
        assert!(apply(&master, &planned, "wrong-hash").is_err());
        fs::write(&master, format!("{}\n# drift", simple())).unwrap();
        assert!(apply(&master, &planned, &planned.plan_hash).is_err());
        assert!(!root
            .path()
            .join(".purge-warden-runtime-capability.json")
            .exists());
        assert!(!root
            .path()
            .join(crate::config::migration_journal::TXN_DIR_NAME)
            .exists());

        let blocked = simple().replace(
            "rule = \"||example.test^\"",
            "rule = \"@@||*.example.test^\"",
        );
        fs::write(&master, blocked).unwrap();
        let planned = plan(&master, None).unwrap();
        assert!(planned.blocked);
        let before = fs::read(&master).unwrap();
        let error = apply(&master, &planned, &planned.plan_hash).unwrap_err();
        assert!(error.to_string().contains("unresolved findings"));
        assert_eq!(fs::read(&master).unwrap(), before);
        assert_ne!(before, original);
        assert!(!root
            .path()
            .join(crate::config::migration_journal::TXN_DIR_NAME)
            .exists());
    }

    #[test]
    fn bootstrap_prepared_failure_recovers_only_the_approved_plan() {
        let (root, master) = fixture(simple());
        let original = fs::read(&master).unwrap();
        let planned = plan(&master, None).unwrap();
        let mut choices = planned.choices.clone();
        choices
            .list_mappings
            .push(super::super::choices::MappingChoiceV1 {
                source_id: "base".into(),
                target_id: "different-rules".into(),
            });
        let different = plan(&master, Some(choices)).unwrap();
        policy_transaction::fail_after_prepared_for_test();
        assert!(apply(&master, &planned, &planned.plan_hash).is_err());
        assert_eq!(fs::read(&master).unwrap(), original);
        let before = tree_bytes(root.path());
        let error = apply(&master, &different, &different.plan_hash).unwrap_err();
        assert!(error.to_string().contains("BootstrapRecoveryMismatch"));
        assert_eq!(tree_bytes(root.path()), before);
        assert!(rollback(
            &master,
            "unrelated-receipt",
            &planned.candidate_config_revision.clone().unwrap()
        )
        .is_err());
        assert_eq!(tree_bytes(root.path()), before);

        let recovered = apply(&master, &planned, &planned.plan_hash).unwrap();
        assert_eq!(recovered.persistence, "committed");
        let replay = apply(&master, &planned, &planned.plan_hash).unwrap();
        assert_eq!(recovered, replay);
        assert!(matches!(
            rollback(
                &master,
                &recovered.receipt_id,
                &recovered.candidate_config_revision
            )
            .unwrap(),
            RollbackResultV1::Restored { .. }
        ));
        assert_eq!(fs::read(&master).unwrap(), original);
        assert!(!root
            .path()
            .join(crate::config::migration_journal::TXN_DIR_NAME)
            .exists());
        assert!(!root
            .path()
            .join(".purge-warden-runtime-capability.json")
            .exists());
    }

    #[test]
    fn bootstrap_rollback_refuses_policy_drift_and_unattested_old_receipt() {
        let (root, master) = fixture(simple());
        let planned = plan(&master, None).unwrap();
        let receipt = apply(&master, &planned, &planned.plan_hash).unwrap();
        let changed = format!(
            "{}\n# after migration",
            fs::read_to_string(&master).unwrap()
        );
        fs::write(&master, &changed).unwrap();
        assert!(matches!(
            rollback(
                &master,
                &receipt.receipt_id,
                &receipt.candidate_config_revision
            )
            .unwrap(),
            RollbackResultV1::NotApplicable
        ));
        assert_eq!(fs::read_to_string(&master).unwrap(), changed);

        let (_other, master) = fixture(simple());
        mark_lease_aware(&master);
        let planned = plan(&master, None).unwrap();
        let receipt = apply(&master, &planned, &planned.plan_hash).unwrap();
        fs::remove_file(
            master
                .parent()
                .unwrap()
                .join(".purge-warden-runtime-capability.json"),
        )
        .unwrap();
        let before = fs::read(&master).unwrap();
        let error = rollback(
            &master,
            &receipt.receipt_id,
            &receipt.candidate_config_revision,
        )
        .unwrap_err();
        assert!(error.to_string().contains("BootstrapAuthorizationMismatch"));
        assert_eq!(fs::read(&master).unwrap(), before);
        drop(root);
    }

    #[test]
    fn bootstrap_refuses_legacy_daemon_without_runtime_lease() {
        let (_root, master) = fixture(simple());
        let planned = plan(&master, None).unwrap();
        let pid_path = master.with_extension("custom-daemon.pid");
        let _legacy = crate::cli::commands::pid::acquire_pid_lock(&pid_path).unwrap();
        let before = fs::read(&master).unwrap();
        let error = super::apply_with_pid_file(&master, &pid_path, &planned, &planned.plan_hash)
            .unwrap_err();
        assert!(error.to_string().contains("NodeNotOffline"));
        assert!(
            super::rollback_with_pid_file(&master, &pid_path, "unknown", "unknown")
                .unwrap_err()
                .to_string()
                .contains("NodeNotOffline")
        );
        assert!(super::finalize_with_pid_file(&master, &pid_path, "unknown")
            .unwrap_err()
            .to_string()
            .contains("NodeNotOffline"));
        assert_eq!(fs::read(&master).unwrap(), before);
    }

    #[test]
    fn finalize_refuses_pending_bootstrap_without_recovery_or_cleanup() {
        let (root, master) = fixture(simple());
        let planned = plan(&master, None).unwrap();
        policy_transaction::fail_after_prepared_for_test();
        assert!(apply(&master, &planned, &planned.plan_hash).is_err());
        let before = tree_bytes(root.path());
        let error = finalize(&master, "unknown").unwrap_err();
        assert!(error.to_string().contains("finalize cannot recover"));
        assert_eq!(tree_bytes(root.path()), before);
    }

    #[test]
    fn bootstrap_recovery_rejects_unapproved_blob_inventories_and_schemas() {
        for tamper in [
            "before",
            "after",
            "source_schema",
            "target_schema",
            "choices_digest",
            "fingerprint",
        ] {
            let (root, master) = fixture(simple());
            let planned = plan(&master, None).unwrap();
            policy_transaction::fail_after_prepared_for_test();
            assert!(apply(&master, &planned, &planned.plan_hash).is_err());
            let fence = root
                .path()
                .join(crate::config::migration_journal::TXN_DIR_NAME);
            let journal_path = fence.join(crate::config::migration_journal::JOURNAL_NAME);
            let mut journal: serde_json::Value =
                serde_json::from_slice(&fs::read(&journal_path).unwrap()).unwrap();
            if tamper == "choices_digest" {
                journal["receipt"]["operation_manifest"]["choices_digest"] = "altered".into();
            } else if tamper == "fingerprint" {
                journal["request_fingerprint"] = "a".repeat(64).into();
                journal["receipt"]["plan_hash"] = "a".repeat(64).into();
            } else if tamper.ends_with("schema") {
                journal[tamper] = 3.into();
            } else {
                let state = &mut journal["members"]
                    .as_array_mut()
                    .unwrap()
                    .iter_mut()
                    .find(|member| member[tamper].is_object())
                    .unwrap()[tamper];
                let blob = fence.join(state["blob"].as_str().unwrap());
                let mut bytes = fs::read(&blob).unwrap();
                bytes.extend_from_slice(b"\n# unapproved bytes\n");
                fs::write(blob, &bytes).unwrap();
                state["length"] = bytes.len().into();
                state["digest"] = digest(&bytes).into();
            }
            fs::write(&journal_path, serde_json::to_vec(&journal).unwrap()).unwrap();
            let before = tree_bytes(root.path());
            let error = apply(&master, &planned, &planned.plan_hash).unwrap_err();
            assert!(
                error.to_string().contains("BootstrapRecoveryMismatch"),
                "{tamper}: {error:#}"
            );
            assert_eq!(tree_bytes(root.path()), before, "{tamper}");
        }
    }

    #[test]
    fn bootstrap_recovery_executes_the_same_decoded_journal_it_authorized() {
        let (root, master) = fixture(simple());
        let planned = plan(&master, None).unwrap();
        policy_transaction::fail_after_prepared_for_test();
        assert!(apply(&master, &planned, &planned.plan_hash).is_err());
        let journal_path = root
            .path()
            .join(crate::config::migration_journal::TXN_DIR_NAME)
            .join(crate::config::migration_journal::JOURNAL_NAME);
        let guard = write_lock::acquire_for_migration(&master).unwrap();
        let data = crate::config::state_dir::open_for_migration(&guard).unwrap();
        let receipts = ReceiptStore::open(&data, &guard).unwrap();
        let outcome =
            policy_transaction::recover_bootstrap_migration(&guard, &receipts, |receipt| {
                verify_bootstrap_receipt(receipt)?;
                assert_eq!(
                    receipt.operator_plan_hash.as_deref(),
                    Some(planned.plan_hash.as_str())
                );
                let mut replacement: serde_json::Value =
                    serde_json::from_slice(&fs::read(&journal_path)?)?;
                replacement["receipt"]["actor"] = "unauthorized-replacement".into();
                fs::write(&journal_path, serde_json::to_vec(&replacement)?)?;
                Ok(())
            })
            .unwrap();
        let policy_transaction::RecoveryOutcome::Recovered(receipt) = outcome else {
            panic!("missing recovery receipt")
        };
        assert_eq!(receipt.actor, ACTOR);
        assert_eq!(receipt.persistence, Persistence::Aborted);
        assert_eq!(
            receipt.operator_plan_hash.as_deref(),
            Some(planned.plan_hash.as_str())
        );
    }

    #[test]
    fn bootstrap_terminal_crash_driver() {
        let Some(master) = std::env::var_os("WARDEN_MIGRATION_TERMINAL_CRASH_MASTER") else {
            return;
        };
        let master = PathBuf::from(master);
        let planned = plan(&master, None).unwrap();
        match std::env::var("WARDEN_MIGRATION_CRASH_BOUNDARY").as_deref() {
            Ok("setup") => policy_transaction::kill_before_first_blob_fsync_for_test(),
            Ok("prepared") => policy_transaction::kill_before_prepared_receipt_for_test(),
            _ => policy_transaction::kill_after_terminal_rename_for_test(),
        }
        let _ = apply(&master, &planned, &planned.plan_hash);
        panic!("terminal rename crash point was not reached");
    }

    #[test]
    fn unpublished_bootstrap_crashes_clean_only_artifacts_and_allow_same_plan_retry() {
        use std::os::unix::fs::MetadataExt;
        use std::os::unix::process::ExitStatusExt;
        for boundary in ["setup", "prepared"] {
            let (root, master) = fixture(simple());
            let source = fs::read(&master).unwrap();
            let source_inode = fs::metadata(&master).unwrap().ino();
            let planned = plan(&master, None).unwrap();
            let child = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "config::migration::v4_to_v5::tests::bootstrap_terminal_crash_driver",
                ])
                .env("WARDEN_MIGRATION_TERMINAL_CRASH_MASTER", &master)
                .env("WARDEN_MIGRATION_CRASH_BOUNDARY", boundary)
                .output()
                .unwrap();
            assert_eq!(child.status.signal(), Some(libc::SIGKILL), "{child:?}");
            let fence = root
                .path()
                .join(crate::config::migration_journal::TXN_DIR_NAME);
            let journal: serde_json::Value = serde_json::from_slice(
                &fs::read(fence.join(crate::config::migration_journal::JOURNAL_NAME)).unwrap(),
            )
            .unwrap();
            assert_eq!(journal["phase"], boundary);
            assert!(!tree_bytes(root.path()).iter().any(|(path, _)| path
                .starts_with(policy_transaction::RECEIPT_DIR)
                && path.extension().is_some_and(|ext| ext == "json")));
            if boundary == "setup" {
                let blobs: Vec<_> = fs::read_dir(&fence)
                    .unwrap()
                    .map(Result::unwrap)
                    .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "blob"))
                    .collect();
                assert_eq!(blobs.len(), 1);
                // Model a torn, not-yet-fsynced first blob as well as missing siblings.
                fs::OpenOptions::new()
                    .write(true)
                    .open(blobs[0].path())
                    .unwrap()
                    .set_len(1)
                    .unwrap();
            }
            {
                let guard = write_lock::acquire_for_migration(&master).unwrap();
                let data = crate::config::state_dir::open_for_migration(&guard).unwrap();
                let receipts = ReceiptStore::open(&data, &guard).unwrap();
                let before = tree_bytes(root.path());
                assert!(
                    policy_transaction::recover_bootstrap_migration(&guard, &receipts, |_| {
                        anyhow::bail!("wrong approved plan")
                    })
                    .is_err()
                );
                assert_eq!(tree_bytes(root.path()), before);
                let result =
                    policy_transaction::recover_bootstrap_migration(&guard, &receipts, |receipt| {
                        verify_bootstrap_receipt(receipt)?;
                        ensure!(
                            receipt.operator_plan_hash.as_deref() == Some(&planned.plan_hash),
                            "wrong plan"
                        );
                        Ok(())
                    })
                    .unwrap();
                assert_eq!(result, policy_transaction::RecoveryOutcome::SetupRemoved);
            }
            assert!(!fence.exists());
            assert_eq!(fs::read(&master).unwrap(), source);
            assert_eq!(fs::metadata(&master).unwrap().ino(), source_inode);
            assert_eq!(fs::read_dir(root.path().join("packs")).unwrap().count(), 0);
            let receipt = apply(&master, &planned, &planned.plan_hash).unwrap();
            assert_eq!(receipt.persistence, "committed");
            assert_eq!(
                apply(&master, &planned, &planned.plan_hash)
                    .unwrap()
                    .receipt_id,
                receipt.receipt_id
            );
        }
    }

    #[test]
    fn active_rollback_recovery_cannot_replace_the_durable_intent() {
        for tamper in ["manifest", "before"] {
            let (root, master) = fixture(simple());
            let planned = plan(&master, None).unwrap();
            let receipt = apply(&master, &planned, &planned.plan_hash).unwrap();
            policy_transaction::fail_after_rollback_intent_for_test();
            assert!(rollback(
                &master,
                &receipt.receipt_id,
                &receipt.candidate_config_revision
            )
            .is_err());
            let fence = root
                .path()
                .join(crate::config::migration_journal::TXN_DIR_NAME);
            let path = fence.join(crate::config::migration_journal::JOURNAL_NAME);
            let mut journal: serde_json::Value =
                serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
            assert_eq!(journal["phase"], "rolling_back");
            if tamper == "before" {
                let member = journal["members"]
                    .as_array_mut()
                    .unwrap()
                    .iter_mut()
                    .find(|member| member["before"].is_object())
                    .unwrap();
                let state = &mut member["before"];
                let blob = fence.join(state["blob"].as_str().unwrap());
                let mut bytes = fs::read(&blob).unwrap();
                bytes.extend_from_slice(b"\n# altered rollback source\n");
                fs::write(&blob, &bytes).unwrap();
                state["length"] = bytes.len().into();
                state["digest"] = digest(&bytes).into();
                let members = journal["members"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .filter(|member| member["before"].is_object())
                    .map(|member| {
                        PolicyRevisionMember::present(
                            serde_json::from_value::<policy_transaction::MemberRole>(
                                member["role"].clone(),
                            )
                            .unwrap()
                            .into(),
                            PathBuf::from(member["path"].as_str().unwrap()),
                            fs::read(fence.join(member["before"]["blob"].as_str().unwrap()))
                                .unwrap(),
                        )
                        .unwrap()
                    })
                    .collect();
                let revision = PolicyRevisionInventory::new(members)
                    .unwrap()
                    .revision()
                    .to_string();
                journal["receipt"]["before_revision"] = revision.clone().into();
                journal["receipt"]["operation_manifest"]["source_config_revision"] =
                    revision.into();
            } else {
                journal["receipt"]["operation_manifest"]["choices_digest"] = "altered".into();
            }
            fs::write(&path, serde_json::to_vec(&journal).unwrap()).unwrap();
            let before = tree_bytes(root.path());
            let error = rollback(
                &master,
                &receipt.receipt_id,
                &receipt.candidate_config_revision,
            )
            .unwrap_err();
            assert!(
                error.to_string().contains("journal intent differs"),
                "{error:#}"
            );
            assert_eq!(tree_bytes(root.path()), before);
        }
    }

    #[test]
    fn old_committed_journal_cannot_erase_completed_rollback() {
        let (root, master) = fixture(simple());
        let planned = plan(&master, None).unwrap();
        let receipt = apply(&master, &planned, &planned.plan_hash).unwrap();
        let (path, original) = tree_bytes(root.path())
            .into_iter()
            .find(|(path, _)| {
                path.starts_with(policy_transaction::STORE_DIR_NAME)
                    && path.file_name().unwrap() == crate::config::migration_journal::JOURNAL_NAME
            })
            .unwrap();
        rollback(
            &master,
            &receipt.receipt_id,
            &receipt.candidate_config_revision,
        )
        .unwrap();
        fs::write(root.path().join(path), original).unwrap();
        let before = tree_bytes(root.path());
        for result in [
            apply(&master, &planned, &planned.plan_hash).map(|_| ()),
            rollback(
                &master,
                &receipt.receipt_id,
                &receipt.candidate_config_revision,
            )
            .map(|_| ()),
        ] {
            assert!(result.unwrap_err().to_string().contains("regresses"));
            assert_eq!(tree_bytes(root.path()), before);
        }
        assert!(fs::read_to_string(&master)
            .unwrap()
            .contains("schema_version = 4"));
    }

    #[test]
    fn terminal_reconciliation_requires_the_durable_approved_intent() {
        use std::os::unix::process::ExitStatusExt;
        for tamper in [
            "none",
            "before",
            "revision",
            "manifest",
            "source_schema",
            "identity",
        ] {
            let (root, master) = fixture(simple());
            let planned = plan(&master, None).unwrap();
            let child = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "config::migration::v4_to_v5::tests::bootstrap_terminal_crash_driver",
                ])
                .env("WARDEN_MIGRATION_TERMINAL_CRASH_MASTER", &master)
                .output()
                .unwrap();
            assert_eq!(child.status.signal(), Some(libc::SIGKILL), "{child:?}");
            assert!(!root
                .path()
                .join(crate::config::migration_journal::TXN_DIR_NAME)
                .exists());
            let files = tree_bytes(root.path());
            let (relative, bytes) = files
                .iter()
                .find(|(path, _)| {
                    path.starts_with(policy_transaction::STORE_DIR_NAME)
                        && path.file_name().unwrap()
                            == crate::config::migration_journal::JOURNAL_NAME
                })
                .unwrap();
            let journal_path = root.path().join(relative);
            let undo = journal_path.parent().unwrap();
            let mut journal: serde_json::Value = serde_json::from_slice(bytes).unwrap();
            let receipt_id = journal["receipt"]["transaction_id"]
                .as_str()
                .unwrap()
                .to_owned();
            let candidate_revision = journal["receipt"]["after_revision"]
                .as_str()
                .unwrap()
                .to_owned();
            assert!(
                files.iter().any(|(path, bytes)| {
                    path.extension()
                        .is_some_and(|extension| extension == "json")
                        && serde_json::from_slice::<serde_json::Value>(bytes).is_ok_and(|record| {
                            record["receipt"]["transaction_id"] == receipt_id
                                && record["receipt"]["persistence"] == "prepared"
                        })
                }),
                "crash must leave the durable receipt prepared"
            );
            match tamper {
                "none" => {
                    let receipt = apply(&master, &planned, &planned.plan_hash).unwrap();
                    assert_eq!(receipt.persistence, "committed");
                    assert_eq!(receipt.receipt_id, receipt_id);
                    rollback(&master, &receipt_id, &candidate_revision).unwrap();
                    continue;
                }
                "manifest" => {
                    journal["receipt"]["operation_manifest"]["choices_digest"] = "unapproved".into()
                }
                "source_schema" => journal["source_schema"] = 3.into(),
                "identity" => {
                    journal["receipt"]["transaction_id"] = "00112233445566778899aabbccddeeff".into()
                }
                _ => {
                    let member = journal["members"]
                        .as_array_mut()
                        .unwrap()
                        .iter_mut()
                        .find(|member| member["before"].is_object())
                        .unwrap();
                    let state = &mut member["before"];
                    let blob = undo.join(state["blob"].as_str().unwrap());
                    let mut bytes = fs::read(&blob).unwrap();
                    bytes.extend_from_slice(b"\n# altered prepared intent\n");
                    fs::write(blob, &bytes).unwrap();
                    state["length"] = bytes.len().into();
                    state["digest"] = digest(&bytes).into();
                    if tamper == "revision" {
                        let members = journal["members"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .filter(|member| member["before"].is_object())
                            .map(|member| {
                                PolicyRevisionMember::present(
                                    serde_json::from_value::<policy_transaction::MemberRole>(
                                        member["role"].clone(),
                                    )
                                    .unwrap()
                                    .into(),
                                    PathBuf::from(member["path"].as_str().unwrap()),
                                    fs::read(undo.join(member["before"]["blob"].as_str().unwrap()))
                                        .unwrap(),
                                )
                                .unwrap()
                            })
                            .collect();
                        journal["receipt"]["before_revision"] =
                            PolicyRevisionInventory::new(members)
                                .unwrap()
                                .revision()
                                .to_string()
                                .into();
                    }
                }
            }
            fs::write(&journal_path, serde_json::to_vec(&journal).unwrap()).unwrap();
            // Move process-ID bookkeeping from the killed child to this
            // process before asserting that failed authorization writes nothing.
            drop(
                crate::config::runtime_lease::acquire_for_migration(
                    &master,
                    &master.with_extension("test.pid"),
                )
                .unwrap(),
            );
            let before = tree_bytes(root.path());
            for result in [
                apply(&master, &planned, &planned.plan_hash).map(|_| ()),
                rollback(&master, &receipt_id, &candidate_revision).map(|_| ()),
            ] {
                let error = result.unwrap_err();
                assert!(
                    error.to_string().contains("Bootstrap"),
                    "{tamper}: {error:#}"
                );
                assert_eq!(tree_bytes(root.path()), before, "{tamper}");
            }
        }
    }

    #[test]
    fn terminal_migration_undo_rejects_altered_preimages_and_receipts_before_writing() {
        for tamper in ["before", "source_schema", "receipt"] {
            let (root, master) = fixture(simple());
            let planned = plan(&master, None).unwrap();
            let receipt = apply(&master, &planned, &planned.plan_hash).unwrap();
            let namespace = fs::read_dir(root.path().join(policy_transaction::STORE_DIR_NAME))
                .unwrap()
                .map(Result::unwrap)
                .find(|entry| entry.file_type().unwrap().is_dir())
                .unwrap()
                .path();
            let undo = fs::read_dir(namespace)
                .unwrap()
                .map(Result::unwrap)
                .find(|entry| entry.file_type().unwrap().is_dir())
                .unwrap()
                .path();
            let journal_path = undo.join(crate::config::migration_journal::JOURNAL_NAME);
            let mut journal: serde_json::Value =
                serde_json::from_slice(&fs::read(&journal_path).unwrap()).unwrap();
            match tamper {
                "source_schema" => journal["source_schema"] = 3.into(),
                "receipt" => {
                    journal["receipt"]["operation_manifest"]["choices_digest"] = "unapproved".into()
                }
                _ => {
                    let member = journal["members"]
                        .as_array_mut()
                        .unwrap()
                        .iter_mut()
                        .find(|member| member["before"].is_object())
                        .unwrap();
                    let state = &mut member["before"];
                    let blob = undo.join(state["blob"].as_str().unwrap());
                    let mut bytes = fs::read(&blob).unwrap();
                    bytes.extend_from_slice(b"\n# corrupt terminal preimage\n");
                    fs::write(blob, &bytes).unwrap();
                    state["length"] = bytes.len().into();
                    state["digest"] = digest(&bytes).into();
                }
            }
            fs::write(&journal_path, serde_json::to_vec(&journal).unwrap()).unwrap();
            let before = tree_bytes(root.path());
            let error = rollback(
                &master,
                &receipt.receipt_id,
                &receipt.candidate_config_revision,
            )
            .unwrap_err();
            assert!(
                error.to_string().contains("Bootstrap"),
                "{tamper}: {error:#}"
            );
            assert_eq!(tree_bytes(root.path()), before, "{tamper}");
        }
    }
}
