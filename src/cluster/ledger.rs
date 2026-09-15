//! Receiver ownership tied to exact transaction evidence, never to file names.

use std::collections::{BTreeMap, BTreeSet};
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use anyhow::{ensure, Context};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::manifest::{digest, is_hash, Manifest};
use super::store::PrivateStore;
use super::transaction::{
    expected_objects, EvidenceResolver, MemberBeforeState, MemberIdentity, OperationBinding,
    OperationEvidence, BUNDLE_PATH,
};
use crate::config::policy_revision::{
    PolicyMemberState, PolicyRevisionInventory, PolicyRevisionMember,
};
use crate::config::policy_transaction::{
    BaseReceipt, MemberOperation, MemberRole, Persistence, ReceiptStore,
};
use crate::config::schema::Id;
use crate::config::write_lock::MigrationWriteLock;

pub(crate) const STORE_DIR: &str = ".warden-cluster-ownership";
const STATE: &str = "state.json";
const MAX_STATE_BYTES: u64 = 8 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OwnedMember {
    pub path: String,
    pub role: MemberRole,
    pub identity: MemberIdentity,
    pub committed_identity: MemberIdentity,
    /// Receipt attesting this identity, including members left unchanged by its journal.
    pub transaction_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OwnershipLedger {
    pub format: u32,
    pub manifest: Manifest,
    pub config_revision: String,
    pub transaction_id: String,
    pub entries: BTreeMap<String, OwnedMember>,
    pub receipt: BaseReceipt,
    pub operation_manifest: Value,
    pub rollback_proofs: Vec<RollbackProof>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BaselineMember {
    pub path: String,
    pub role: MemberRole,
    pub identity: MemberIdentity,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RollbackMemberProof {
    pub role: MemberRole,
    pub before: MemberIdentity,
    pub journal_before: MemberBeforeState,
    pub restored: MemberIdentity,
}

/// Each link retains the failed transaction's evidence while the ledger's
/// committed receipt continues to identify the artifact that owns the files.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RollbackProof {
    pub manifest: Manifest,
    pub before_revision: String,
    pub receipt: BaseReceipt,
    pub operation_manifest: Value,
    pub members: BTreeMap<String, RollbackMemberProof>,
}

/// Before authority and the candidate are durably joined before prepare starts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PendingApply {
    pub manifest: Manifest,
    pub before: Option<OwnershipLedger>,
    #[serde(default)]
    pub enrollment: bool,
    pub before_revision: String,
    pub before_members: BTreeMap<String, BaselineMember>,
    pub binding: OperationBinding,
    pub transaction_id: Option<String>,
}

impl PendingApply {
    pub(crate) fn payload(&self) -> anyhow::Result<Vec<u8>> {
        self.binding.payload()
    }

    pub(crate) fn operation_manifest(&self) -> anyhow::Result<Value> {
        self.binding.operation_manifest()
    }
}

pub(crate) struct OwnershipPlan {
    pub delete_paths: Vec<String>,
    pub replay: bool,
    artifact_hash: String,
    before: Option<OwnershipLedger>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RecoveryStatus {
    NoPending,
    Completed(Box<OwnershipLedger>),
    Aborted,
    AwaitingReceipt,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct State {
    format: u32,
    root_device: u64,
    root_inode: u64,
    ledger: Option<OwnershipLedger>,
    pending: Option<PendingApply>,
}

pub(crate) struct OwnershipStore<'g> {
    guard: &'g MigrationWriteLock,
    files: PrivateStore<'g>,
    state: State,
    poisoned: bool,
}

impl<'g> OwnershipStore<'g> {
    pub(crate) fn open(guard: &'g MigrationWriteLock) -> anyhow::Result<Self> {
        let files = PrivateStore::open(guard, STORE_DIR)?;
        ensure!(
            files.names(2)?.iter().all(|name| name == STATE),
            "ArtifactOwnershipConflict: unexpected ownership store entry"
        );
        let root = guard.tree_io().root.metadata()?;
        let state = match files.read(STATE, MAX_STATE_BYTES)? {
            Some(bytes) => serde_json::from_slice(&bytes)
                .context("ArtifactOwnershipConflict: invalid ledger")?,
            None => State {
                format: 1,
                root_device: root.dev(),
                root_inode: root.ino(),
                ledger: None,
                pending: None,
            },
        };
        ensure!(
            state.root_device == root.dev() && state.root_inode == root.ino(),
            "ArtifactOwnershipConflict: configuration root was replaced"
        );
        validate_state(&state)?;
        Ok(Self {
            guard,
            files,
            state,
            poisoned: false,
        })
    }

    pub(crate) fn current(&self) -> Option<&OwnershipLedger> {
        self.state.ledger.as_ref()
    }

    pub(crate) fn pending(&self) -> Option<&PendingApply> {
        self.state.pending.as_ref()
    }

    /// `local_declarations` means declarations OUTSIDE the artifact namespace,
    /// derived from guarded provenance by the caller, including noncolliding IDs.
    /// `has_existing_policy` includes any previous bundle, even an empty v1 one.
    pub(crate) fn preflight(
        &self,
        manifest: &Manifest,
        local_declarations: &[Id],
        has_existing_policy: bool,
    ) -> anyhow::Result<OwnershipPlan> {
        self.check()?;
        ensure!(
            self.state.pending.is_none(),
            "ArtifactRecoveryRequired: pending ownership intent"
        );
        manifest.validate()?;
        ensure!(
            local_declarations.is_empty(),
            "ArtifactEnrollmentRequired: local Custom List declarations"
        );
        crate::config::custom_list::validate_flat_pack_tree_under_tree(self.guard.tree_io())?;
        let expected = expected_objects(manifest);
        let replay = if let Some(previous) = &self.state.ledger {
            ensure!(
                manifest.primary_lineage == previous.manifest.primary_lineage,
                "ArtifactEnrollmentRequired: primary lineage changed"
            );
            ensure!(
                manifest.policy_epoch >= previous.manifest.policy_epoch,
                "ArtifactReplayRejected: older policy epoch"
            );
            if manifest.policy_epoch == previous.manifest.policy_epoch {
                ensure!(
                    manifest.artifact_hash == previous.manifest.artifact_hash,
                    "ArtifactReplayRejected: epoch reused for another artifact"
                );
            }
            for member in previous.entries.values() {
                verify_live(self.guard, member)?;
            }
            manifest.policy_epoch == previous.manifest.policy_epoch
        } else {
            ensure!(
                !has_existing_policy,
                "ArtifactEnrollmentRequired: existing policy has no ownership ledger"
            );
            false
        };
        for path in expected.keys() {
            if self
                .state
                .ledger
                .as_ref()
                .is_some_and(|ledger| ledger.entries.contains_key(path))
            {
                continue;
            }
            ensure!(
                self.guard
                    .tree_io()
                    .plan_root_file_no_follow(Path::new(path))?
                    .is_new(),
                "ArtifactOwnershipConflict: destination occupied by an unowned file: {path}"
            );
        }
        let delete_paths = self.state.ledger.as_ref().map_or_else(Vec::new, |ledger| {
            ledger
                .entries
                .keys()
                .filter(|path| !expected.contains_key(*path))
                .cloned()
                .collect()
        });
        self.check()?;
        Ok(OwnershipPlan {
            delete_paths,
            replay,
            artifact_hash: manifest.artifact_hash.clone(),
            before: self.state.ledger.clone(),
        })
    }

    pub(crate) fn begin(
        &mut self,
        plan: OwnershipPlan,
        manifest: &Manifest,
        before: &PolicyRevisionInventory,
        expected_after_revision: &str,
        actor: &str,
        request_id: &str,
    ) -> anyhow::Result<PendingApply> {
        self.check()?;
        ensure!(
            !plan.replay
                && plan.artifact_hash == manifest.artifact_hash
                && plan.before == self.state.ledger
                && self.state.pending.is_none(),
            "ArtifactIntentMismatch: stale ownership plan"
        );
        // Recheck destinations at the last boundary before intent. The caller
        // retains the same exclusive tree guard through the policy transaction.
        let checked = self.preflight(manifest, &[], false)?;
        ensure!(
            checked.delete_paths == plan.delete_paths,
            "ArtifactIntentMismatch: ownership plan changed"
        );
        let pending = PendingApply {
            manifest: manifest.clone(),
            before: plan.before,
            enrollment: false,
            before_revision: before.revision().to_string(),
            before_members: capture_baseline(self.guard, before)?,
            binding: OperationBinding::for_apply(
                manifest,
                expected_after_revision,
                actor,
                request_id,
            )?,
            transaction_id: None,
        };
        let mut next = self.state.clone();
        next.pending = Some(pending.clone());
        self.persist(next)?;
        Ok(pending)
    }

    /// Associate a reviewed complete replacement inventory with transaction proof.
    /// Occupied destinations must belong to the captured configuration inventory.
    pub(crate) fn begin_enrollment(
        &mut self,
        manifest: &Manifest,
        before: &PolicyRevisionInventory,
        expected_after_revision: &str,
        actor: &str,
        request_id: &str,
    ) -> anyhow::Result<PendingApply> {
        self.check()?;
        ensure!(
            self.state.pending.is_none() && self.state.ledger.is_none(),
            "leave existing artifact ownership before enrollment"
        );
        manifest.validate()?;
        crate::config::custom_list::validate_flat_pack_tree_under_tree(self.guard.tree_io())?;
        let before_members = capture_baseline(self.guard, before)?;
        for path in expected_objects(manifest).keys() {
            if !self
                .guard
                .tree_io()
                .plan_root_file_no_follow(Path::new(path))?
                .is_new()
            {
                ensure!(
                    before_members.contains_key(path),
                    "join would overwrite an unreviewed file: {path}"
                );
            }
        }
        let pending = PendingApply {
            manifest: manifest.clone(),
            before: None,
            enrollment: true,
            before_revision: before.revision().to_string(),
            before_members,
            binding: OperationBinding::for_apply(
                manifest,
                expected_after_revision,
                actor,
                request_id,
            )?,
            transaction_id: None,
        };
        let mut next = self.state.clone();
        next.pending = Some(pending.clone());
        self.persist(next)?;
        Ok(pending)
    }

    /// Release replication ownership only after a committed standalone transition.
    pub(crate) fn release_after_leave(&mut self, receipt: &BaseReceipt) -> anyhow::Result<()> {
        self.check()?;
        ensure!(
            receipt.persistence == Persistence::Committed
                && receipt.operation == "nodes.leave"
                && !receipt.rollback_restored
                && self.state.pending.is_none(),
            "leave requires committed transaction evidence"
        );
        let loaded = crate::config::loader::load_config_v5_with_policy_overlays_under_service_migration_guard(self.guard, self.guard.canonical_master(), time::OffsetDateTime::now_utc(), None, None)
            .map_err(|error| anyhow::anyhow!("standalone validation: {error:?}"))?;
        ensure!(
            !loaded.config.cluster.enabled,
            "cannot release an enrolled node"
        );
        let mut next = self.state.clone();
        next.ledger = None;
        self.persist(next)
    }

    /// Invoke after prepare returns and before commit. Failure leaves a recoverable
    /// policy intent; do not promote after failing to bind its transaction ID.
    pub(crate) fn bind_prepared(&mut self, receipt: &BaseReceipt) -> anyhow::Result<()> {
        self.check()?;
        let pending = self
            .state
            .pending
            .as_ref()
            .context("ArtifactRecoveryRequired: no pending intent")?;
        pending
            .binding
            .verify_receipt(receipt, &pending.operation_manifest()?)?;
        ensure!(
            receipt.persistence == Persistence::Prepared
                && !receipt.rollback_restored
                && receipt.before_revision == pending.before_revision
                && pending
                    .transaction_id
                    .as_ref()
                    .is_none_or(|id| id == &receipt.transaction_id),
            "ArtifactIntentMismatch: prepared transaction"
        );
        let mut next = self.state.clone();
        next.pending.as_mut().unwrap().transaction_id = Some(receipt.transaction_id.clone());
        self.persist(next)
    }

    /// Derive ownership only from the trusted journal evidence. Live reads below
    /// verify the recorded identity; they never supply a replacement identity.
    pub(crate) fn complete(
        &mut self,
        evidence: &OperationEvidence,
    ) -> anyhow::Result<OwnershipLedger> {
        self.check()?;
        let pending = self
            .state
            .pending
            .as_ref()
            .context("ArtifactRecoveryRequired: no pending intent")?;
        verify_pending(pending, evidence)?;
        ensure!(
            evidence.receipt.persistence == Persistence::Committed
                && !evidence.receipt.rollback_restored,
            "ArtifactRecoveryRequired: transaction is not committed"
        );
        let mut members = BTreeMap::new();
        for member in &evidence.members {
            ensure!(
                members.insert(member.path.as_str(), member).is_none(),
                "ArtifactIntentMismatch: duplicate journal member evidence"
            );
        }
        let mut entries = BTreeMap::new();
        for (path, object) in &pending.binding.objects {
            let member = members
                .get(path.as_str())
                .context("ArtifactIntentMismatch: missing journal member evidence")?;
            let identity = member
                .after
                .as_ref()
                .context("ArtifactIntentMismatch: absent after identity")?;
            ensure!(
                member.role == expected_role(path)
                    && member.operation != Some(MemberOperation::Delete)
                    && identity.sha256 == object.sha256
                    && identity.bytes == object.bytes,
                "ArtifactIntentMismatch: after member differs from artifact"
            );
            validate_identity(identity)?;
            let owned = OwnedMember {
                path: path.clone(),
                role: member.role,
                identity: identity.clone(),
                committed_identity: identity.clone(),
                transaction_id: evidence.receipt.transaction_id.clone(),
            };
            verify_live(self.guard, &owned)?;
            entries.insert(path.clone(), owned);
        }
        if let Some(before) = &pending.before {
            for path in before
                .entries
                .keys()
                .filter(|path| !entries.contains_key(*path))
            {
                let member = members
                    .get(path.as_str())
                    .context("ArtifactIntentMismatch: missing delete evidence")?;
                ensure!(
                    member.operation == Some(MemberOperation::Delete)
                        && member.role == expected_role(path)
                        && member.after.is_none(),
                    "ArtifactIntentMismatch: invalid delete evidence"
                );
                ensure!(
                    self.guard
                        .tree_io()
                        .plan_root_file_no_follow(Path::new(path))?
                        .is_new(),
                    "ArtifactOwnershipConflict: deleted destination is occupied"
                );
            }
        }
        let ledger = OwnershipLedger {
            format: 1,
            manifest: pending.manifest.clone(),
            config_revision: evidence.receipt.after_revision.clone(),
            transaction_id: evidence.receipt.transaction_id.clone(),
            entries,
            receipt: evidence.receipt.clone(),
            operation_manifest: evidence.operation_manifest.clone(),
            rollback_proofs: Vec::new(),
        };
        validate_ledger(&ledger)?;
        let mut next = self.state.clone();
        next.ledger = Some(ledger.clone());
        next.pending = None;
        self.persist(next)?;
        Ok(ledger)
    }

    pub(crate) fn recover(
        &mut self,
        receipts: &ReceiptStore,
        resolver: &impl EvidenceResolver,
    ) -> anyhow::Result<RecoveryStatus> {
        self.check()?;
        let Some(pending) = self.state.pending.as_ref() else {
            return Ok(RecoveryStatus::NoPending);
        };
        let Some(evidence) = resolver.lookup(
            self.guard,
            receipts,
            &pending.binding.actor,
            &pending.binding.request_id,
        )?
        else {
            // A missing receipt alone says nothing about publication. Prove
            // the entire before inventory and every new destination instead.
            verify_unchanged(self.guard, pending)?;
            let mut next = self.state.clone();
            next.pending = None;
            self.persist(next)?;
            return Ok(RecoveryStatus::Aborted);
        };
        verify_pending(pending, &evidence)?;
        match evidence.receipt.persistence {
            Persistence::Committed if !evidence.receipt.rollback_restored => self
                .complete(&evidence)
                .map(Box::new)
                .map(RecoveryStatus::Completed),
            Persistence::Committed | Persistence::Aborted => {
                let restored = restore_ownership(self.guard, pending, &evidence)?;
                let mut next = self.state.clone();
                next.ledger = restored;
                next.pending = None;
                self.persist(next)?;
                Ok(RecoveryStatus::Aborted)
            }
            Persistence::Prepared | Persistence::DurabilityUncertain => {
                Ok(RecoveryStatus::AwaitingReceipt)
            }
        }
    }

    fn check(&self) -> anyhow::Result<()> {
        ensure!(
            !self.poisoned,
            "ArtifactRecoveryRequired: reopen ownership store after uncertain write"
        );
        self.files.check()
    }

    fn persist(&mut self, next: State) -> anyhow::Result<()> {
        self.check()?;
        validate_state(&next)?;
        let bytes = serde_json::to_vec(&next)?;
        ensure!(
            bytes.len() as u64 <= MAX_STATE_BYTES,
            "ArtifactLimitExceeded: ownership state"
        );
        self.poisoned = true;
        self.files.write(STATE, &bytes)?;
        self.state = next;
        self.poisoned = false;
        Ok(())
    }
}

fn verify_pending(pending: &PendingApply, evidence: &OperationEvidence) -> anyhow::Result<()> {
    pending
        .binding
        .verify_receipt(&evidence.receipt, &evidence.operation_manifest)?;
    ensure!(
        pending
            .transaction_id
            .as_ref()
            .is_none_or(|id| id == &evidence.receipt.transaction_id)
            && evidence.receipt.before_revision == pending.before_revision,
        "ArtifactIntentMismatch: transaction ID or before revision"
    );
    Ok(())
}

fn expected_role(path: &str) -> MemberRole {
    if path == BUNDLE_PATH {
        MemberRole::Include
    } else {
        MemberRole::Pack
    }
}

fn validate_identity(identity: &MemberIdentity) -> anyhow::Result<()> {
    ensure!(
        is_hash(&identity.sha256) && identity.mode & !0o7777 == 0 && identity.inode != 0,
        "ArtifactOwnershipConflict: invalid file receipt"
    );
    Ok(())
}

fn same_contents_and_metadata(left: &MemberIdentity, right: &MemberIdentity) -> bool {
    left.sha256 == right.sha256
        && left.bytes == right.bytes
        && left.uid == right.uid
        && left.gid == right.gid
        && left.mode == right.mode
}

fn is_restored_receipt(receipt: &BaseReceipt) -> bool {
    matches!(
        (receipt.persistence, receipt.rollback_restored),
        (Persistence::Aborted, false) | (Persistence::Committed, true)
    )
}

fn capture_baseline(
    guard: &MigrationWriteLock,
    inventory: &PolicyRevisionInventory,
) -> anyhow::Result<BTreeMap<String, BaselineMember>> {
    let mut baseline = BTreeMap::new();
    for member in inventory.members() {
        let PolicyMemberState::Present(bytes) = member.state() else {
            anyhow::bail!("ArtifactIntentMismatch: before inventory contains an absent member");
        };
        let path = member
            .path()
            .to_str()
            .context("ArtifactIntentMismatch: non-UTF-8 before path")?;
        let plan = guard.tree_io().plan_root_file_no_follow(member.path())?;
        let meta = plan
            .original_metadata()
            .context("ArtifactOwnershipConflict: before member missing")?;
        let identity = MemberIdentity {
            sha256: digest(bytes),
            bytes: bytes.len() as u64,
            uid: meta.uid(),
            gid: meta.gid(),
            mode: meta.mode() & 0o7777,
            device: meta.dev(),
            inode: meta.ino(),
        };
        verify_identity(guard, path, &identity)?;
        baseline.insert(
            path.to_owned(),
            BaselineMember {
                path: path.to_owned(),
                role: member.kind().into(),
                identity,
            },
        );
    }
    Ok(baseline)
}

fn verify_new_absent(guard: &MigrationWriteLock, pending: &PendingApply) -> anyhow::Result<()> {
    for path in pending
        .binding
        .objects
        .keys()
        .filter(|path| !pending.before_members.contains_key(*path))
    {
        ensure!(
            guard
                .tree_io()
                .plan_root_file_no_follow(Path::new(path))?
                .is_new(),
            "ArtifactOwnershipConflict: new destination is occupied during recovery: {path}"
        );
    }
    Ok(())
}

fn verify_unchanged(guard: &MigrationWriteLock, pending: &PendingApply) -> anyhow::Result<()> {
    for member in pending.before_members.values() {
        verify_identity(guard, &member.path, &member.identity)?;
    }
    verify_new_absent(guard, pending)
}

fn restore_ownership(
    guard: &MigrationWriteLock,
    pending: &PendingApply,
    evidence: &OperationEvidence,
) -> anyhow::Result<Option<OwnershipLedger>> {
    ensure!(
        is_restored_receipt(&evidence.receipt),
        "ArtifactIntentMismatch: receipt does not prove a terminal rollback"
    );
    let mut members = BTreeMap::new();
    for member in &evidence.members {
        ensure!(
            members.insert(member.path.as_str(), member).is_none(),
            "ArtifactIntentMismatch: duplicate rollback member evidence"
        );
    }
    let mut ledger = pending.before.clone();
    let mut restored = BTreeMap::new();
    for (path, baseline) in &pending.before_members {
        let member = members.get(path.as_str());
        if let Some(before) = member.and_then(|member| member.before.as_ref()) {
            ensure!(
                member.unwrap().role == baseline.role
                    && before == &MemberBeforeState::from(&baseline.identity),
                "ArtifactOwnershipConflict: rollback before evidence differs from ownership"
            );
        }
        if let Some(identity) = member.and_then(|member| member.restored.as_ref()) {
            let member = member.unwrap();
            ensure!(
                member.role == baseline.role
                    && member.before.as_ref() == Some(&MemberBeforeState::from(&baseline.identity))
                    && same_contents_and_metadata(identity, &baseline.identity),
                "ArtifactOwnershipConflict: incoherent restored-member evidence"
            );
            validate_identity(identity)?;
            verify_identity(guard, path, identity)?;
            if identity != &baseline.identity && ledger.is_some() {
                let owned = ledger
                    .as_mut()
                    .and_then(|ledger| ledger.entries.get_mut(path))
                    .context("ArtifactOwnershipConflict: rollback changed a node-local member")?;
                restored.insert(
                    path.clone(),
                    RollbackMemberProof {
                        role: baseline.role,
                        before: baseline.identity.clone(),
                        restored: identity.clone(),
                        journal_before: member
                            .before
                            .clone()
                            .context("ArtifactOwnershipConflict: missing rollback before state")?,
                    },
                );
                owned.identity = identity.clone();
            }
        } else {
            verify_identity(guard, path, &baseline.identity).context(
                "ArtifactOwnershipConflict: rollback requires verified restored-member evidence",
            )?;
        }
    }
    verify_new_absent(guard, pending)?;
    if !restored.is_empty() {
        ledger
            .as_mut()
            .context("ArtifactOwnershipConflict: restored ownership has no ledger")?
            .rollback_proofs
            .push(RollbackProof {
                manifest: pending.manifest.clone(),
                before_revision: pending.before_revision.clone(),
                receipt: evidence.receipt.clone(),
                operation_manifest: evidence.operation_manifest.clone(),
                members: restored,
            });
    }
    Ok(ledger)
}

fn validate_ledger(ledger: &OwnershipLedger) -> anyhow::Result<()> {
    ledger.manifest.validate()?;
    ensure!(
        ledger.format == 1 && is_hash(&ledger.config_revision) && !ledger.transaction_id.is_empty(),
        "ArtifactOwnershipConflict: invalid ledger identity"
    );
    ensure!(
        ledger.receipt.transaction_id == ledger.transaction_id
            && ledger.receipt.persistence == Persistence::Committed
            && !ledger.receipt.rollback_restored,
        "ArtifactOwnershipConflict: invalid terminal receipt"
    );
    let binding = OperationBinding::for_apply(
        &ledger.manifest,
        &ledger.config_revision,
        &ledger.receipt.actor,
        &ledger.receipt.request_id,
    )?;
    binding.verify_receipt(&ledger.receipt, &ledger.operation_manifest)?;
    let objects = expected_objects(&ledger.manifest);
    ensure!(
        objects.keys().eq(ledger.entries.keys()),
        "ArtifactOwnershipConflict: ledger inventory"
    );
    for (path, member) in &ledger.entries {
        let object = &objects[path];
        validate_identity(&member.identity)?;
        validate_identity(&member.committed_identity)?;
        ensure!(
            member.path == *path
                && member.role == expected_role(path)
                && member.transaction_id == ledger.transaction_id
                && member.identity.sha256 == object.sha256
                && member.identity.bytes == object.bytes,
            "ArtifactOwnershipConflict: inconsistent member receipt"
        );
        ensure!(same_contents_and_metadata(&member.identity, &member.committed_identity),
            "ArtifactOwnershipConflict: restored content or metadata differs from committed ownership");
    }
    validate_rollback_proofs(ledger)?;
    Ok(())
}

fn validate_rollback_proofs(ledger: &OwnershipLedger) -> anyhow::Result<()> {
    let mut identities: BTreeMap<_, _> = ledger
        .entries
        .iter()
        .map(|(path, member)| (path.as_str(), member.committed_identity.clone()))
        .collect();
    let mut transactions = BTreeSet::from([ledger.transaction_id.as_str()]);
    for proof in &ledger.rollback_proofs {
        ensure!(
            is_hash(&proof.before_revision)
                && proof.receipt.before_revision == proof.before_revision
                && is_restored_receipt(&proof.receipt)
                && !proof.members.is_empty()
                && transactions.insert(proof.receipt.transaction_id.as_str()),
            "ArtifactOwnershipConflict: invalid rollback receipt chain"
        );
        ensure!(
            proof.manifest.primary_lineage == ledger.manifest.primary_lineage
                && proof.manifest.policy_epoch > ledger.manifest.policy_epoch,
            "ArtifactOwnershipConflict: rollback artifact lineage or epoch"
        );
        let binding = OperationBinding::for_apply(
            &proof.manifest,
            &proof.receipt.after_revision,
            &proof.receipt.actor,
            &proof.receipt.request_id,
        )?;
        binding.verify_receipt(&proof.receipt, &proof.operation_manifest)?;
        for (path, member) in &proof.members {
            let before = identities
                .get_mut(path.as_str())
                .context("ArtifactOwnershipConflict: rollback proof claims an unowned member")?;
            ensure!(
                member.role == expected_role(path)
                    && *before == member.before
                    && member.journal_before == MemberBeforeState::from(&member.before)
                    && same_contents_and_metadata(&member.before, &member.restored),
                "ArtifactOwnershipConflict: broken rollback member chain"
            );
            validate_identity(&member.restored)?;
            *before = member.restored.clone();
        }
    }
    for (path, member) in &ledger.entries {
        ensure!(
            identities[path.as_str()] == member.identity,
            "ArtifactOwnershipConflict: current inode lacks a rollback proof"
        );
    }
    Ok(())
}

fn validate_state(state: &State) -> anyhow::Result<()> {
    ensure!(
        state.format == 1,
        "ArtifactOwnershipConflict: unknown ledger format"
    );
    if let Some(ledger) = &state.ledger {
        validate_ledger(ledger)?;
    }
    if let Some(pending) = &state.pending {
        pending.manifest.validate()?;
        let expected = OperationBinding::for_apply(
            &pending.manifest,
            &pending.binding.expected_after_revision,
            &pending.binding.actor,
            &pending.binding.request_id,
        )?;
        ensure!(
            pending.binding == expected
                && pending.before == state.ledger
                && (!pending.enrollment || pending.before.is_none()),
            "ArtifactOwnershipConflict: inconsistent pending intent"
        );
        ensure!(
            is_hash(&pending.before_revision),
            "ArtifactOwnershipConflict: invalid before revision"
        );
        let mut inventory = Vec::new();
        for (path, member) in &pending.before_members {
            validate_identity(&member.identity)?;
            ensure!(
                member.path == *path,
                "ArtifactOwnershipConflict: invalid before member path"
            );
            inventory.push(PolicyRevisionMember::present(
                member.role.into(),
                path.into(),
                Vec::new(),
            )?);
        }
        PolicyRevisionInventory::new(inventory)?;
        for path in pending.binding.objects.keys() {
            if pending.before_members.contains_key(path) {
                ensure!(
                    pending.enrollment
                        || pending
                            .before
                            .as_ref()
                            .is_some_and(|ledger| ledger.entries.contains_key(path)),
                    "ArtifactOwnershipConflict: before inventory claims an unowned destination"
                );
            }
        }
        if let Some(previous) = &pending.before {
            ensure!(
                pending.manifest.primary_lineage == previous.manifest.primary_lineage
                    && pending.manifest.policy_epoch > previous.manifest.policy_epoch,
                "ArtifactReplayRejected: pending lineage or epoch"
            );
            for (path, member) in &previous.entries {
                ensure!(
                    pending
                        .before_members
                        .get(path)
                        .is_some_and(|baseline| baseline.role == member.role
                            && baseline.identity == member.identity),
                    "ArtifactOwnershipConflict: before inventory omits owned identity"
                );
            }
        }
    }
    Ok(())
}

fn verify_live(guard: &MigrationWriteLock, member: &OwnedMember) -> anyhow::Result<()> {
    verify_identity(guard, &member.path, &member.identity)
}

fn verify_identity(
    guard: &MigrationWriteLock,
    path: &str,
    expected: &MemberIdentity,
) -> anyhow::Result<()> {
    guard.verify_root_linked()?;
    let plan = guard.tree_io().plan_root_file_no_follow(Path::new(path))?;
    let meta = plan
        .original_metadata()
        .context("ArtifactOwnershipConflict: owned file missing")?;
    ensure!(
        meta.dev() == expected.device
            && meta.ino() == expected.inode
            && meta.uid() == expected.uid
            && meta.gid() == expected.gid
            && meta.mode() & 0o7777 == expected.mode
            && meta.len() == expected.bytes,
        "ArtifactOwnershipConflict: owned inode or metadata changed: {}",
        path
    );
    ensure!(
        plan.original_sha256()?
            .is_some_and(|value| hex::encode(value) == expected.sha256),
        "ArtifactOwnershipConflict: owned bytes changed: {}",
        path
    );
    // A pathname swapped while the old descriptor was being hashed is drift too.
    let current = guard.tree_io().plan_root_file_no_follow(Path::new(path))?;
    let current = current
        .original_metadata()
        .context("ArtifactOwnershipConflict: owned path disappeared")?;
    ensure!(
        current.dev() == expected.device
            && current.ino() == expected.inode
            && current.uid() == expected.uid
            && current.gid() == expected.gid
            && current.mode() & 0o7777 == expected.mode
            && current.len() == expected.bytes,
        "ArtifactOwnershipConflict: owned path changed while hashing"
    );
    guard.verify_root_linked()
}

#[cfg(test)]
mod tests {
    use super::super::transaction::{test_support::*, MemberEvidence};
    use super::*;
    use crate::config::policy_revision::PolicyMemberKind;
    use crate::config::policy_transaction::{self, PrepareOutcome};
    use crate::config::write_lock::acquire_for_migration;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    const MASTER: &str = "schema_version = 5\nincludes = [\"cluster.d/*.toml\"]\n[server]\nlisten = \"127.0.0.1:15354\"\n[cluster]\nenabled = true\nrole = \"secondary\"\npeer = \"https://192.0.2.1\"\ntoken_hash = \"fixture-token-hash\"\n";

    struct FixedEvidence(OperationEvidence);
    impl EvidenceResolver for FixedEvidence {
        fn lookup(
            &self,
            _: &MigrationWriteLock,
            _: &ReceiptStore,
            _: &str,
            _: &str,
        ) -> anyhow::Result<Option<OperationEvidence>> {
            Ok(Some(self.0.clone()))
        }
    }

    fn before_inventory(store: &OwnershipStore<'_>) -> PolicyRevisionInventory {
        let root = &store.guard.identity().root;
        if !root.join("config.toml").exists() {
            fs::write(root.join("config.toml"), MASTER).unwrap();
        }
        let mut members = vec![PolicyRevisionMember::present(
            PolicyMemberKind::Master,
            "config.toml".into(),
            fs::read(root.join("config.toml")).unwrap(),
        )
        .unwrap()];
        if let Some(ledger) = store.current() {
            for (path, member) in &ledger.entries {
                members.push(
                    PolicyRevisionMember::present(
                        member.role.into(),
                        path.into(),
                        fs::read(root.join(path)).unwrap(),
                    )
                    .unwrap(),
                );
            }
        }
        PolicyRevisionInventory::new(members).unwrap()
    }

    fn pending_receipt(pending: &PendingApply, persistence: Persistence) -> BaseReceipt {
        let mut result = receipt(&pending.binding, persistence);
        result.before_revision = pending.before_revision.clone();
        result.transaction_id = digest(pending.binding.request_id.as_bytes())[..32].into();
        result
    }

    fn after_inventory(
        before: &PolicyRevisionInventory,
        manifest: &Manifest,
        objects: &BTreeMap<String, std::sync::Arc<[u8]>>,
    ) -> PolicyRevisionInventory {
        let mut members: Vec<_> = before
            .members()
            .iter()
            .filter(|member| member.kind() == PolicyMemberKind::Master)
            .cloned()
            .collect();
        for (path, object) in expected_objects(manifest) {
            members.push(
                PolicyRevisionMember::present(
                    expected_role(&path).into(),
                    path.into(),
                    objects[&object.sha256].to_vec(),
                )
                .unwrap(),
            );
        }
        PolicyRevisionInventory::new(members).unwrap()
    }

    fn accept(
        store: &mut OwnershipStore<'_>,
        manifest: &Manifest,
        objects: &BTreeMap<String, std::sync::Arc<[u8]>>,
    ) -> OwnershipLedger {
        let plan = store.preflight(manifest, &[], false).unwrap();
        let before = before_inventory(store);
        let pending = store
            .begin(
                plan,
                manifest,
                &before,
                &"b".repeat(64),
                "actor",
                &format!("request-{}", manifest.policy_epoch),
            )
            .unwrap();
        let removed: Vec<_> = pending
            .before
            .as_ref()
            .into_iter()
            .flat_map(|ledger| ledger.entries.keys())
            .filter(|path| !pending.binding.objects.contains_key(*path))
            .cloned()
            .collect();
        install(&store.guard.identity().root, manifest, objects);
        let mut members = fixture_members(&store.guard.identity().root, manifest);
        for path in removed {
            fs::remove_file(store.guard.identity().root.join(&path)).unwrap();
            members.push(MemberEvidence {
                role: expected_role(&path),
                path,
                operation: Some(MemberOperation::Delete),
                before: None,
                after: None,
                restored: None,
            });
        }
        store
            .complete(&OperationEvidence {
                receipt: pending_receipt(&pending, Persistence::Committed),
                operation_manifest: pending.operation_manifest().unwrap(),
                members,
            })
            .unwrap()
    }

    #[test]
    fn full_inventory_attestation_stays_bounded_at_one_thousand_members() {
        let names: Vec<_> = (0..999)
            .map(|index| format!("{}{index:04}", "a".repeat(60)))
            .collect();
        let packs: Vec<_> = names.iter().map(|name| (name.as_str(), "")).collect();
        let (mut manifest, _) = artifact(1, &packs);
        let mut first_size = None;
        for epoch in 1..=32 {
            manifest.policy_epoch = epoch;
            manifest.packs[epoch as usize % 999].sha256 = digest(&epoch.to_le_bytes());
            manifest.config_revision = digest(&epoch.to_be_bytes());
            manifest.artifact_hash = manifest.canonical_hash().unwrap();
            let binding = OperationBinding::for_apply(
                &manifest,
                &manifest.config_revision,
                &"a".repeat(256),
                &format!("{}{:020}", "r".repeat(236), epoch),
            )
            .unwrap();
            let receipt = receipt(&binding, Persistence::Committed);
            let entries: BTreeMap<_, _> = expected_objects(&manifest)
                .into_iter()
                .map(|(path, object)| {
                    let identity = MemberIdentity {
                        sha256: object.sha256,
                        bytes: object.bytes,
                        uid: u32::MAX,
                        gid: u32::MAX,
                        mode: 0o7777,
                        device: u64::MAX,
                        inode: u64::MAX,
                    };
                    (
                        path.clone(),
                        OwnedMember {
                            role: expected_role(&path),
                            path,
                            identity: identity.clone(),
                            committed_identity: identity,
                            transaction_id: receipt.transaction_id.clone(),
                        },
                    )
                })
                .collect();
            assert_eq!(entries.len(), 1000);
            let ledger = OwnershipLedger {
                format: 1,
                manifest: manifest.clone(),
                config_revision: manifest.config_revision.clone(),
                transaction_id: receipt.transaction_id.clone(),
                entries,
                receipt,
                operation_manifest: binding.operation_manifest().unwrap(),
                rollback_proofs: Vec::new(),
            };
            validate_ledger(&ledger).unwrap();
            // Include both durable copies of the prior ledger in an outstanding intent.
            let mut next_manifest = manifest.clone();
            next_manifest.policy_epoch += 1;
            next_manifest.artifact_hash = next_manifest.canonical_hash().unwrap();
            let next_binding = OperationBinding::for_apply(
                &next_manifest,
                &manifest.config_revision,
                &binding.actor,
                &binding.request_id,
            )
            .unwrap();
            let mut pending = PendingApply {
                manifest: next_manifest,
                before: Some(ledger.clone()),
                enrollment: false,
                before_revision: manifest.config_revision.clone(),
                before_members: ledger
                    .entries
                    .iter()
                    .map(|(path, member)| {
                        (
                            path.clone(),
                            BaselineMember {
                                path: path.clone(),
                                role: member.role,
                                identity: member.identity.clone(),
                            },
                        )
                    })
                    .collect(),
                binding: next_binding,
                transaction_id: None,
            };
            pending.before_members.insert(
                "config.toml".into(),
                BaselineMember {
                    path: "config.toml".into(),
                    role: MemberRole::Master,
                    identity: MemberIdentity {
                        sha256: digest(MASTER.as_bytes()),
                        bytes: MASTER.len() as u64,
                        uid: u32::MAX,
                        gid: u32::MAX,
                        mode: 0o7777,
                        device: u64::MAX,
                        inode: u64::MAX,
                    },
                },
            );
            let state = State {
                format: 1,
                root_device: u64::MAX,
                root_inode: u64::MAX,
                ledger: Some(ledger),
                pending: Some(pending),
            };
            validate_state(&state).unwrap();
            let size = serde_json::to_vec(&state).unwrap().len();
            assert!(
                (size as u64) < MAX_STATE_BYTES,
                "epoch {epoch}: {size} bytes"
            );
            let baseline = *first_size.get_or_insert(size);
            assert!(
                size.abs_diff(baseline) < 1024,
                "attestation accumulated historical manifests"
            );
        }
    }

    #[test]
    fn enrollment_and_same_content_orphans_are_never_adopted() {
        let root = tempfile::tempdir().unwrap();
        let guard = acquire_for_migration(&root.path().join("config.toml")).unwrap();
        let store = OwnershipStore::open(&guard).unwrap();
        let (manifest, objects) = artifact(1, &[("list", "example.org\n")]);
        assert!(store.preflight(&manifest, &[], true).is_err());
        assert!(store
            .preflight(&manifest, &[Id::new("noncolliding").unwrap()], false)
            .is_err());
        install(root.path(), &manifest, &objects);
        assert!(store.preflight(&manifest, &[], false).is_err());
    }

    #[test]
    fn owned_bytes_mode_and_replaced_inode_are_all_drift() {
        for change in ["bytes", "mode", "inode"] {
            let root = tempfile::tempdir().unwrap();
            let guard = acquire_for_migration(&root.path().join("config.toml")).unwrap();
            let mut store = OwnershipStore::open(&guard).unwrap();
            let (manifest, objects) = artifact(1, &[("list", "example.org\n")]);
            accept(&mut store, &manifest, &objects);
            let path = root.path().join("packs/list.txt");
            match change {
                "bytes" => fs::write(&path, b"example.com\n").unwrap(),
                "mode" => {
                    let mode = fs::metadata(&path).unwrap().mode() & 0o7777;
                    fs::set_permissions(&path, fs::Permissions::from_mode(mode ^ 0o100)).unwrap();
                }
                _ => {
                    fs::rename(&path, root.path().join("original")).unwrap();
                    fs::write(&path, b"example.org\n").unwrap();
                }
            }
            assert!(store.preflight(&manifest, &[], true).is_err(), "{change}");
        }
    }

    #[test]
    fn epoch_lineage_and_delete_plan_use_only_previous_ownership() {
        let root = tempfile::tempdir().unwrap();
        let guard = acquire_for_migration(&root.path().join("config.toml")).unwrap();
        let mut store = OwnershipStore::open(&guard).unwrap();
        let (manifest, objects) = artifact(2, &[("list", "example.org\n")]);
        accept(&mut store, &manifest, &objects);
        assert!(store.preflight(&manifest, &[], true).unwrap().replay);
        let (older, _) = artifact(1, &[]);
        assert!(store.preflight(&older, &[], true).is_err());
        let (different, _) = artifact(2, &[]);
        assert!(store.preflight(&different, &[], true).is_err());
        let (mut next, _) = artifact(3, &[]);
        fs::write(root.path().join("packs/stray.txt"), b"unowned\n").unwrap();
        assert_eq!(
            store.preflight(&next, &[], true).unwrap().delete_paths,
            ["packs/list.txt"]
        );
        next.primary_lineage = "d".repeat(64);
        next.artifact_hash = next.canonical_hash().unwrap();
        assert!(store.preflight(&next, &[], true).is_err());
    }

    #[test]
    fn durable_pending_recovers_only_the_recorded_exact_identity() {
        let root = tempfile::tempdir().unwrap();
        let guard = acquire_for_migration(&root.path().join("config.toml")).unwrap();
        let (manifest, objects) = artifact(1, &[("list", "example.org\n")]);
        let mut store = OwnershipStore::open(&guard).unwrap();
        let plan = store.preflight(&manifest, &[], false).unwrap();
        let before = before_inventory(&store);
        let pending = store
            .begin(
                plan,
                &manifest,
                &before,
                &"b".repeat(64),
                "actor",
                "request",
            )
            .unwrap();
        install(root.path(), &manifest, &objects);
        let evidence = FixedEvidence(OperationEvidence {
            receipt: pending_receipt(&pending, Persistence::Committed),
            operation_manifest: pending.operation_manifest().unwrap(),
            members: fixture_members(root.path(), &manifest),
        });
        drop(store);
        let mut store = OwnershipStore::open(&guard).unwrap();
        let receipts =
            ReceiptStore::open(&guard.tree_io().root.try_clone().unwrap(), &guard).unwrap();
        let path = root.path().join("packs/list.txt");
        fs::rename(&path, root.path().join("original")).unwrap();
        fs::write(&path, b"example.org\n").unwrap();
        assert!(store.recover(&receipts, &evidence).is_err());
        assert!(store.pending().is_some());
        fs::remove_file(&path).unwrap();
        fs::rename(root.path().join("original"), &path).unwrap();
        assert!(matches!(
            store.recover(&receipts, &evidence).unwrap(),
            RecoveryStatus::Completed(_)
        ));
        assert!(store.pending().is_none());
    }

    #[test]
    fn ownership_store_detects_descriptor_root_drift() {
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("root");
        fs::create_dir(&root).unwrap();
        let guard = acquire_for_migration(&root.join("config.toml")).unwrap();
        let store = OwnershipStore::open(&guard).unwrap();
        fs::rename(&root, parent.path().join("old")).unwrap();
        fs::create_dir(&root).unwrap();
        let (manifest, _) = artifact(1, &[]);
        assert!(store.preflight(&manifest, &[], false).is_err());
    }

    #[test]
    fn crash_after_begin_child() {
        let Some(root) = std::env::var_os("WARDEN_ARTIFACT_CRASH_ROOT") else {
            return;
        };
        let guard = acquire_for_migration(&Path::new(&root).join("config.toml")).unwrap();
        let mut store = OwnershipStore::open(&guard).unwrap();
        let (manifest, _) = artifact(1, &[]);
        let before = before_inventory(&store);
        let plan = store.preflight(&manifest, &[], false).unwrap();
        store
            .begin(
                plan,
                &manifest,
                &before,
                &"b".repeat(64),
                "actor",
                "crash-request",
            )
            .unwrap();
        // Exit without running destructors: recovery must use only durable state.
        unsafe { libc::_exit(93) };
    }

    #[test]
    fn restart_after_begin_without_receipt_proves_unchanged_and_allows_retry() {
        let root = tempfile::tempdir().unwrap();
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "cluster::ledger::tests::crash_after_begin_child",
                "--nocapture",
            ])
            .env("WARDEN_ARTIFACT_CRASH_ROOT", root.path())
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(93));
        let guard = acquire_for_migration(&root.path().join("config.toml")).unwrap();
        let receipts = ReceiptStore::open(guard.tree_io().root, &guard).unwrap();
        let mut store = OwnershipStore::open(&guard).unwrap();
        assert!(store.pending().is_some());
        assert_eq!(
            store
                .recover(
                    &receipts,
                    &super::super::transaction::ExistingReceiptAdapter
                )
                .unwrap(),
            RecoveryStatus::Aborted
        );
        assert!(store.pending().is_none());
        let (manifest, objects) = artifact(1, &[]);
        accept(&mut store, &manifest, &objects);
    }

    #[test]
    fn prepare_failure_without_receipt_recovers_after_restart_and_retries() {
        let root = tempfile::tempdir().unwrap();
        let master = root.path().join("config.toml");
        let (manifest, objects) = artifact(1, &[("list", "example.org\n")]);
        {
            let guard = acquire_for_migration(&master).unwrap();
            let receipts = ReceiptStore::open(guard.tree_io().root, &guard).unwrap();
            let mut store = OwnershipStore::open(&guard).unwrap();
            let before = before_inventory(&store);
            let after = after_inventory(&before, &manifest, &objects);
            let plan = store.preflight(&manifest, &[], false).unwrap();
            let pending = store
                .begin(
                    plan,
                    &manifest,
                    &before,
                    &after.revision().to_string(),
                    "actor",
                    "rejected",
                )
                .unwrap();
            let result = super::super::transaction::prepare_apply(
                &guard,
                &receipts,
                &pending,
                &before,
                &after,
                || anyhow::bail!("fixture candidate validation failure"),
            );
            assert!(result.is_err());
            assert!(
                policy_transaction::lookup_receipt(&guard, &receipts, "actor", "rejected")
                    .unwrap()
                    .is_none()
            );
        }
        let guard = acquire_for_migration(&master).unwrap();
        let receipts = ReceiptStore::open(guard.tree_io().root, &guard).unwrap();
        let mut store = OwnershipStore::open(&guard).unwrap();
        assert_eq!(
            store
                .recover(
                    &receipts,
                    &super::super::transaction::ExistingReceiptAdapter
                )
                .unwrap(),
            RecoveryStatus::Aborted
        );
        let before = before_inventory(&store);
        let after = after_inventory(&before, &manifest, &objects);
        let plan = store.preflight(&manifest, &[], false).unwrap();
        let pending = store
            .begin(
                plan,
                &manifest,
                &before,
                &after.revision().to_string(),
                "actor",
                "retry",
            )
            .unwrap();
        let prepared = super::super::transaction::prepare_apply(
            &guard,
            &receipts,
            &pending,
            &before,
            &after,
            || Ok(()),
        )
        .unwrap();
        let PrepareOutcome::Prepared(transaction) = prepared else {
            panic!("retry must prepare a fresh transaction");
        };
        store.bind_prepared(&transaction.receipt()).unwrap();
        let receipt = transaction.commit().unwrap();
        assert_eq!(
            receipt.persistence,
            Persistence::Committed,
            "{:?}",
            receipt.failure
        );
        store
            .complete(&OperationEvidence {
                receipt,
                operation_manifest: pending.operation_manifest().unwrap(),
                members: fixture_members(root.path(), &manifest),
            })
            .unwrap();
    }

    #[test]
    fn missing_receipt_never_clears_drifted_before_or_occupied_new_destination() {
        for drift in ["master", "new", "owned"] {
            let root = tempfile::tempdir().unwrap();
            let guard = acquire_for_migration(&root.path().join("config.toml")).unwrap();
            let receipts = ReceiptStore::open(guard.tree_io().root, &guard).unwrap();
            let mut store = OwnershipStore::open(&guard).unwrap();
            if drift == "owned" {
                let (initial, objects) = artifact(1, &[("old", "old.example\n")]);
                accept(&mut store, &initial, &objects);
            }
            let (manifest, _) = artifact(2, &[("new", "new.example\n")]);
            let before = before_inventory(&store);
            let plan = store.preflight(&manifest, &[], false).unwrap();
            store
                .begin(
                    plan,
                    &manifest,
                    &before,
                    &"b".repeat(64),
                    "actor",
                    "no-receipt",
                )
                .unwrap();
            let path = match drift {
                "master" => root.path().join("config.toml"),
                "owned" => root.path().join("packs/old.txt"),
                _ => root.path().join("packs/new.txt"),
            };
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            let body = fs::read(&path).unwrap_or_else(|_| b"new.example\n".to_vec());
            if path.exists() {
                fs::rename(&path, root.path().join("saved-before")).unwrap();
            }
            fs::write(&path, &body).unwrap();
            drop(store);
            let mut store = OwnershipStore::open(&guard).unwrap();
            assert!(
                store
                    .recover(
                        &receipts,
                        &super::super::transaction::ExistingReceiptAdapter
                    )
                    .is_err(),
                "{drift}"
            );
            assert!(store.pending().is_some());
            assert_eq!(fs::read(path).unwrap(), body);
        }
    }

    #[test]
    fn aborted_restoration_requires_exact_proof_and_persists_an_inode_chain() {
        let root = tempfile::tempdir().unwrap();
        let guard = acquire_for_migration(&root.path().join("config.toml")).unwrap();
        let receipts = ReceiptStore::open(guard.tree_io().root, &guard).unwrap();
        let mut store = OwnershipStore::open(&guard).unwrap();
        let (initial, objects) = artifact(1, &[("list", "example.org\n")]);
        let committed = accept(&mut store, &initial, &objects);
        let (candidate, objects) = artifact(
            2,
            &[("list", "changed.example\n"), ("new", "new.example\n")],
        );
        // Retain the old inode through promotion and rollback so it cannot be reused.
        let _original_file = fs::File::open(root.path().join("packs/list.txt")).unwrap();
        for attempt in 1..=2 {
            let before = before_inventory(&store);
            let after = after_inventory(&before, &candidate, &objects);
            let plan = store.preflight(&candidate, &[], true).unwrap();
            let pending = store
                .begin(
                    plan,
                    &candidate,
                    &before,
                    &after.revision().to_string(),
                    "actor",
                    &format!("aborted-{attempt}"),
                )
                .unwrap();
            let path = root.path().join("packs/list.txt");
            let baseline = pending.before_members["packs/list.txt"].identity.clone();
            // Model the journal's completed rollback after a publication fault:
            // same before bytes and metadata, a newly restored inode.
            fs::rename(&path, root.path().join(format!("before-{attempt}"))).unwrap();
            fs::write(&path, b"||example.org^").unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(baseline.mode)).unwrap();
            let meta = fs::metadata(&path).unwrap();
            let restored = MemberIdentity {
                device: meta.dev(),
                inode: meta.ino(),
                ..baseline.clone()
            };
            assert_ne!(restored.inode, baseline.inode);
            let mut receipt = pending_receipt(
                &pending,
                if attempt == 1 {
                    Persistence::Aborted
                } else {
                    Persistence::Committed
                },
            );
            receipt.rollback_restored = attempt == 2;
            let evidence = OperationEvidence {
                receipt,
                operation_manifest: pending.operation_manifest().unwrap(),
                members: vec![MemberEvidence {
                    path: "packs/list.txt".into(),
                    role: MemberRole::Pack,
                    operation: Some(MemberOperation::Replace),
                    before: Some(MemberBeforeState::from(&baseline)),
                    after: None,
                    restored: Some(restored.clone()),
                }],
            };
            drop(store);
            store = OwnershipStore::open(&guard).unwrap();
            let mut incomplete = evidence.clone();
            incomplete.members[0].restored = None;
            assert!(store
                .recover(&receipts, &FixedEvidence(incomplete))
                .is_err());
            let mut incoherent = evidence.clone();
            incoherent.members[0].before.as_mut().unwrap().sha256 = "f".repeat(64);
            assert!(store
                .recover(&receipts, &FixedEvidence(incoherent))
                .is_err());
            let mut foreign_before = evidence.clone();
            foreign_before.members[0].before.as_mut().unwrap().inode += 1;
            assert!(store
                .recover(&receipts, &FixedEvidence(foreign_before))
                .is_err());
            let mut changed_restored_digest = evidence.clone();
            changed_restored_digest.members[0]
                .restored
                .as_mut()
                .unwrap()
                .sha256 = "f".repeat(64);
            assert!(store
                .recover(&receipts, &FixedEvidence(changed_restored_digest))
                .is_err());
            let mut changed_restored_metadata = evidence.clone();
            changed_restored_metadata.members[0]
                .restored
                .as_mut()
                .unwrap()
                .mode ^= 0o100;
            assert!(store
                .recover(&receipts, &FixedEvidence(changed_restored_metadata))
                .is_err());
            let mut wrong_revision = evidence.clone();
            wrong_revision.receipt.before_revision = "e".repeat(64);
            assert!(store
                .recover(&receipts, &FixedEvidence(wrong_revision))
                .is_err());
            fs::rename(&path, root.path().join("journal-restored")).unwrap();
            fs::write(&path, b"||example.org^").unwrap();
            assert!(store
                .recover(&receipts, &FixedEvidence(evidence.clone()))
                .is_err());
            assert!(store.pending().is_some());
            fs::remove_file(&path).unwrap();
            fs::rename(root.path().join("journal-restored"), &path).unwrap();
            assert_eq!(
                store
                    .recover(&receipts, &FixedEvidence(evidence.clone()))
                    .unwrap(),
                RecoveryStatus::Aborted
            );
            drop(store);
            store = OwnershipStore::open(&guard).unwrap();
            let ledger = store.current().unwrap();
            assert_eq!(ledger.receipt, committed.receipt);
            assert_eq!(ledger.manifest, committed.manifest);
            assert_eq!(ledger.rollback_proofs.len(), attempt);
            assert_eq!(ledger.entries["packs/list.txt"].identity, restored);
            assert_eq!(
                ledger.entries["packs/list.txt"].committed_identity,
                committed.entries["packs/list.txt"].identity
            );
            assert!(store.preflight(&initial, &[], true).unwrap().replay);
            let mut broken = ledger.clone();
            broken.rollback_proofs.clear();
            assert!(validate_ledger(&broken).is_err());
        }
    }

    #[test]
    fn real_transaction_rollback_recovers_original_ownership_after_restart() {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("config.toml"), MASTER).unwrap();
        let guard = acquire_for_migration(&root.path().join("config.toml")).unwrap();
        let receipts = ReceiptStore::open(guard.tree_io().root, &guard).unwrap();
        let mut store = OwnershipStore::open(&guard).unwrap();
        let (initial, objects) = artifact(1, &[("list", "example.org\n")]);
        let original = accept(&mut store, &initial, &objects);
        // Keep the replaced inode alive so the filesystem cannot recycle it
        // before the assertion that proves rollback created a new file.
        let _original_file = fs::File::open(root.path().join("packs/list.txt")).unwrap();
        let (candidate, objects) = artifact(
            2,
            &[("list", "changed.example\n"), ("new", "new.example\n")],
        );
        let before = before_inventory(&store);
        let after = after_inventory(&before, &candidate, &objects);
        let plan = store.preflight(&candidate, &[], true).unwrap();
        let pending = store
            .begin(
                plan,
                &candidate,
                &before,
                &after.revision().to_string(),
                "actor",
                "real-rollback",
            )
            .unwrap();
        let prepared = super::super::transaction::prepare_apply(
            &guard,
            &receipts,
            &pending,
            &before,
            &after,
            || Ok(()),
        )
        .unwrap();
        let PrepareOutcome::Prepared(transaction) = prepared else {
            panic!("candidate must prepare a new transaction");
        };
        store.bind_prepared(&transaction.receipt()).unwrap();
        let committed = transaction.commit().unwrap();
        assert_eq!(
            committed.persistence,
            Persistence::Committed,
            "{:?}",
            committed.failure
        );
        assert_eq!(
            fs::read(root.path().join("packs/list.txt")).unwrap(),
            b"||changed.example^"
        );
        assert!(matches!(
            policy_transaction::rollback(&guard, &receipts, "actor", "real-rollback").unwrap(),
            policy_transaction::RollbackOutcome::Restored(_)
        ));
        let receipt =
            policy_transaction::lookup_receipt(&guard, &receipts, "actor", "real-rollback")
                .unwrap()
                .unwrap();
        assert_eq!(
            receipt.persistence,
            Persistence::Committed,
            "{:?}",
            receipt.failure
        );
        assert!(receipt.rollback_restored);
        assert_eq!(receipt.transaction_id, committed.transaction_id);
        assert!(!root.path().join("packs/new.txt").exists());

        // The real rollback above exercises restore_members. Only this fixture
        // uses stat to supply the trusted adapter DTO at the journal boundary.
        let mut members = fixture_members(root.path(), &initial);
        for member in &mut members {
            member.before = Some(MemberBeforeState::from(
                &pending.before_members[&member.path].identity,
            ));
            member.restored = member.after.take();
            member.operation = Some(MemberOperation::Replace);
        }
        let evidence = FixedEvidence(OperationEvidence {
            receipt,
            operation_manifest: pending.operation_manifest().unwrap(),
            members,
        });
        assert_ne!(
            fs::metadata(root.path().join("packs/list.txt"))
                .unwrap()
                .ino(),
            original.entries["packs/list.txt"].identity.inode
        );
        drop(store);
        let mut store = OwnershipStore::open(&guard).unwrap();
        assert_eq!(
            store.recover(&receipts, &evidence).unwrap(),
            RecoveryStatus::Aborted
        );
        drop(store);
        let store = OwnershipStore::open(&guard).unwrap();
        let restored = store.current().unwrap();
        assert_eq!(restored.manifest, original.manifest);
        assert_eq!(restored.receipt, original.receipt);
        assert_eq!(restored.transaction_id, original.transaction_id);
        assert_eq!(restored.rollback_proofs.len(), 1);
        assert!(store.preflight(&initial, &[], true).unwrap().replay);
        assert_eq!(
            fs::read(root.path().join("packs/list.txt")).unwrap(),
            b"||example.org^"
        );
    }
}
