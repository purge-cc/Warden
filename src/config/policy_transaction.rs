//! Recoverable, descriptor-relative transactions over a closed policy inventory.
//!
//! Callers supply complete effective inventories and validate the complete candidate
//! before publication. The fixed migration directory fences readers; terminal
//! receipts and undo data do not prevent subsequent policy writes.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{CStr, CString, OsStr};
use std::fs::{File, Metadata, Permissions};
use std::io::{self, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, ensure, Context};
use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::atomic_write::{
    hardened_atomic_create_only_at_with_transaction_boundaries,
    hardened_atomic_write_at_with_transaction_boundaries,
    stage_journaled_anonymous_at_with_transaction_boundaries, AnonymousStageOpts,
    AtomicCreateOnlyAtOpts, AtomicStaging, AtomicWriteAtOpts, AtomicWriteBoundary,
};
use super::migration_journal::{self, JOURNAL_NAME, TXN_DIR_NAME};
use super::policy_revision::{
    PolicyMemberKind, PolicyMemberState, PolicyRevision, PolicyRevisionInventory,
    PolicyRevisionMember,
};
use super::tree_io::{
    inspect_at, rename_at, rename_noreplace_at, same_inode, unlink_at, CappedRead, PinnedTarget,
    TargetPlan, TreeIo,
};
use super::write_lock::{
    open_at, preserve_owner, reopen_inspected, MigrationWriteLock, POLICY_RECEIPT_STORE_DIR,
    POLICY_TRANSACTION_STORE_DIR, WRITE_STAGE_PREFIX,
};

pub(crate) const STORE_DIR_NAME: &str = POLICY_TRANSACTION_STORE_DIR;
pub(crate) const FORMAT_VERSION: u64 = 2;
pub(crate) const MAX_RECEIPTS: usize = 4096;
pub(crate) const MIN_RETENTION_SECONDS: u64 = 24 * 60 * 60;
const MAX_MANIFEST_BYTES: u64 = 4 * 1024 * 1024;
pub(crate) const MAX_POLICY_BYTES: u64 = 256 * 1024 * 1024;
const MAX_BLOB_BYTES: u64 = MAX_POLICY_BYTES;
const MAX_MEMBERS: usize = 4096;
const SETUP_MARKER: &str = "format2.setup";
const JOURNAL_NEXT: &str = "journal.next";
const SETUP_STAGE: &str = ".warden-write-policy-setup";
const WRITE_STAGE_PAYLOAD: &str = "payload";
pub(crate) const RECEIPT_DIR: &str = POLICY_RECEIPT_STORE_DIR;

/// Node-local receipt storage below the caller's pinned effective data directory.
/// Offline and daemon callers must supply the same directory and canonical master.
/// Each master owns a separate namespace even when roots share a data directory.
pub(crate) struct ReceiptStore {
    parent: File,
    base: File,
    namespace: String,
    directory: File,
    owner: Metadata,
}

impl ReceiptStore {
    pub(crate) fn open(data_directory: &File, guard: &MigrationWriteLock) -> anyhow::Result<Self> {
        guard.verify_root_linked()?;
        let owner = data_directory.metadata()?;
        ensure!(owner.is_dir(), "receipt data directory is not a directory");
        let base = private_dir(data_directory, RECEIPT_DIR, &owner, true)?;
        let namespace = master_namespace(guard.canonical_master());
        let directory = private_dir(&base, &namespace, &owner, true)?;
        let store = Self {
            parent: data_directory.try_clone()?,
            base,
            namespace,
            directory,
            owner,
        };
        store.check()?;
        Ok(store)
    }

    fn duplicate(&self) -> anyhow::Result<Self> {
        self.check()?;
        Ok(Self {
            parent: self.parent.try_clone()?,
            base: self.base.try_clone()?,
            namespace: self.namespace.clone(),
            directory: self.directory.try_clone()?,
            owner: self.owner.clone(),
        })
    }

    fn check(&self) -> anyhow::Result<()> {
        ensure!(is_hash(&self.namespace), "invalid receipt master namespace");
        for (parent, name, directory) in [
            (&self.parent, RECEIPT_DIR, &self.base),
            (&self.base, self.namespace.as_str(), &self.directory),
        ] {
            let meta = directory.metadata()?;
            let linked =
                inspect_at(parent, OsStr::new(name))?.context("receipt store disappeared")?;
            ensure!(
                same_inode(&meta, &linked.metadata()?),
                "receipt store directory was replaced"
            );
            ensure!(
                meta.is_dir()
                    && meta.mode() & 0o7777 == 0o700
                    && meta.uid() == self.owner.uid()
                    && meta.gid() == self.owner.gid(),
                "receipt store owner or mode changed"
            );
        }
        self.directory.sync_all()?;
        Ok(())
    }

    fn check_for_tree(&self, tree: TreeIo<'_>) -> anyhow::Result<()> {
        ensure!(
            self.namespace == master_namespace(&tree.identity.canonical_master),
            "ReceiptStoreMismatch: receipt namespace belongs to another canonical master"
        );
        self.check()
    }

    fn read(&self, key: &str, tree: TreeIo<'_>) -> anyhow::Result<Option<StoredReceipt>> {
        self.check_for_tree(tree)?;
        let Some(bytes) = read_optional_private(
            &self.directory,
            &format!("{key}.json"),
            &self.owner,
            MAX_MANIFEST_BYTES,
        )?
        else {
            return Ok(None);
        };
        let stored: StoredReceipt =
            serde_json::from_slice(&bytes).context("invalid receipt record")?;
        ensure!(
            stored.format_version == 1
                && stored.tree == Inode::of(&tree.root.metadata()?)
                && request_key(&stored.receipt.actor, &stored.receipt.request_id) == key,
            "receipt identity mismatch"
        );
        ensure!(
            stored
                .receipt
                .operator_plan_hash
                .as_deref()
                .is_none_or(is_hash),
            "invalid operator plan hash"
        );
        validate_operation_manifest(stored.receipt.operation_manifest.as_ref())?;
        ensure!(
            stored.retain_until
                >= stored
                    .receipt
                    .created_unix_seconds
                    .saturating_add(MIN_RETENTION_SECONDS),
            "invalid receipt retention promise"
        );
        Ok(Some(stored))
    }

    fn write(&self, journal: &Journal, tree: TreeIo<'_>) -> anyhow::Result<()> {
        self.check_for_tree(tree)?;
        ensure!(
            journal.receipt_store == Inode::of(&self.directory.metadata()?),
            "ReceiptStoreMismatch: transaction belongs to another receipt store"
        );
        let key = request_key(&journal.receipt.actor, &journal.receipt.request_id);
        let now = unix_seconds()?;
        let retained = self
            .read(&key, tree)?
            .map_or(0, |record| record.retain_until);
        let record = StoredReceipt {
            format_version: 1,
            tree: journal.root.clone(),
            fingerprint: journal.request_fingerprint.clone(),
            retain_until: retained.max(now.saturating_add(MIN_RETENTION_SECONDS)),
            receipt: journal.receipt.clone(),
        };
        self.write_record(&key, &record)
    }

    fn write_record(&self, key: &str, record: &StoredReceipt) -> anyhow::Result<()> {
        ensure!(is_hash(key), "invalid receipt key");
        let bytes = serde_json::to_vec(record)?;
        ensure!(
            bytes.len() as u64 <= MAX_MANIFEST_BYTES,
            "receipt size budget exceeded"
        );
        let stage = format!("{key}.next");
        if inspect_at(&self.directory, OsStr::new(&stage))?.is_some() {
            checked_private_file(&self.directory, &stage, &self.owner, MAX_MANIFEST_BYTES)?;
            unlink_at(&self.directory, OsStr::new(&stage))?;
        }
        write_new(&self.directory, &stage, &bytes, &self.owner)?;
        rename_at(
            &self.directory,
            OsStr::new(&stage),
            &self.directory,
            OsStr::new(&format!("{key}.json")),
        )?;
        self.directory.sync_all()?;
        Ok(())
    }

    fn update(
        &self,
        tree: TreeIo<'_>,
        actor: &str,
        request_id: &str,
        operation_id: &str,
        update: impl FnOnce(&mut BaseReceipt) -> anyhow::Result<()>,
    ) -> anyhow::Result<BaseReceipt> {
        self.check_for_tree(tree)?;
        let key = request_key(actor, request_id);
        let mut record = self
            .read(&key, tree)?
            .context("operator-rule receipt does not exist")?;
        ensure!(
            record.receipt.transaction_id == operation_id,
            "operator-rule receipt identity mismatch"
        );
        update(&mut record.receipt)?;
        self.write_record(&key, &record)?;
        Ok(record.receipt)
    }

    fn admit(
        &self,
        tree: TreeIo<'_>,
        undo_store: &File,
        now: u64,
        limit: usize,
    ) -> anyhow::Result<()> {
        self.check_for_tree(tree)?;
        let owner = tree.identity.owner_metadata(tree.root)?;
        let mut live = 0;
        for name in directory_names(&self.directory, MAX_RECEIPTS * 2)? {
            if let Some(key) = name.strip_suffix(".next") {
                ensure!(is_hash(key), "unexpected receipt staging file");
                checked_private_file(&self.directory, &name, &self.owner, MAX_MANIFEST_BYTES)?;
                unlink_at(&self.directory, OsStr::new(&name))?;
                continue;
            }
            let key = name
                .strip_suffix(".json")
                .context("unexpected receipt store member")?;
            ensure!(is_hash(key), "invalid receipt store key");
            let record = self.read(key, tree)?.context("receipt disappeared")?;
            if now >= record.retain_until
                && matches!(
                    record.receipt.persistence,
                    Persistence::Committed | Persistence::Aborted
                )
                && receipt_completion_settled(&record.receipt)
            {
                expire_undo(undo_store, key, &owner, tree)?;
                unlink_at(&self.directory, OsStr::new(&name))?;
            } else {
                live += 1;
            }
        }
        self.directory.sync_all()?;
        ensure!(
            live < limit,
            "IdempotencyStoreFull: receipt admission capacity reached"
        );
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredReceipt {
    format_version: u64,
    tree: Inode,
    fingerprint: String,
    retain_until: u64,
    receipt: BaseReceipt,
}

#[derive(Debug, Clone)]
pub(crate) struct TransactionRequest {
    pub(crate) request_id: String,
    pub(crate) actor: String,
    pub(crate) origin: String,
    pub(crate) operation: String,
    pub(crate) payload: Vec<u8>,
    pub(crate) expected_revision: PolicyRevision,
    pub(crate) source_schema: u64,
    pub(crate) target_schema: u64,
}

/// The interpretation of receipt digests is explicit, including on recovery.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RevisionScope {
    #[default]
    PolicyTreeV1,
    RepairDestinationSetV1,
}

/// A digest of named repair destinations, never a global configuration revision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RepairDestinationRevision(String);

#[derive(Debug, Clone)]
pub(crate) struct RepairRequest {
    pub(crate) request_id: String,
    pub(crate) actor: String,
    pub(crate) origin: String,
    pub(crate) operation: String,
    pub(crate) payload: Vec<u8>,
    pub(crate) expected_destinations: RepairDestinationRevision,
    pub(crate) source_schema: u64,
    pub(crate) target_schema: u64,
}

/// Raw before images pinned under the exclusive guard for a deletion-free repair.
pub(crate) struct RepairDestinationSet<'g> {
    guard: &'g MigrationWriteLock,
    before_revision: RepairDestinationRevision,
    after_revision: RepairDestinationRevision,
    planned: PlannedMembers<'g>,
}

impl<'g> RepairDestinationSet<'g> {
    pub(crate) fn capture(
        guard: &'g MigrationWriteLock,
        desired: &PolicyRevisionInventory,
    ) -> anyhow::Result<Self> {
        Self::capture_with_blob_budget(guard, desired, MAX_BLOB_BYTES)
    }

    fn capture_with_blob_budget(
        guard: &'g MigrationWriteLock,
        desired: &PolicyRevisionInventory,
        blob_budget: u64,
    ) -> anyhow::Result<Self> {
        guard.verify_root_linked()?;
        let tree = guard.tree_io();
        migration_journal::refuse_normal_write(tree)?;
        validate_inventory(desired, tree)?;
        validate_flat_packs(tree)?;
        let owner = tree.identity.owner_metadata(tree.root)?;
        let planned = plan_members_with_blob_budget(tree, None, desired, &owner, blob_budget)?;
        verify_repair_before(tree, &planned.0)?;
        Ok(Self {
            guard,
            before_revision: RepairDestinationRevision(repair_digest(&planned.0, true)),
            after_revision: RepairDestinationRevision(repair_digest(&planned.0, false)),
            planned,
        })
    }

    pub(crate) fn revision(&self) -> RepairDestinationRevision {
        self.before_revision.clone()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Persistence {
    Prepared,
    Committed,
    Aborted,
    DurabilityUncertain,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ReceiptActivationState {
    NotRequired,
    Pending,
    Applied,
    Superseded,
    Failed,
    #[default]
    Unknown,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReceiptActivation {
    pub(crate) state: ReceiptActivationState,
    pub(crate) correlation_id: Option<String>,
    pub(crate) reload_outcome: Option<String>,
    pub(crate) active_config_revision: Option<String>,
    pub(crate) active_policy_hash: Option<String>,
    pub(crate) daemon_instance_id: Option<String>,
    pub(crate) superseded_by: Option<String>,
    pub(crate) failure: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ReceiptSemanticContext {
    pub(crate) before_policy_hash: Option<String>,
    pub(crate) after_policy_hash: Option<String>,
    pub(crate) audit: ReceiptAuditContext,
}

#[derive(Debug, Default)]
pub(crate) struct ReceiptPreparationContext<'a> {
    pub(crate) operator_plan_hash: Option<&'a str>,
    pub(crate) semantic: ReceiptSemanticContext,
    pub(crate) operation_manifest: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReceiptAuditContext {
    pub(crate) list_ids: Vec<String>,
    pub(crate) profile_ids: Vec<String>,
    pub(crate) operations: u32,
    pub(crate) rules_added: u32,
    pub(crate) rules_removed: u32,
    pub(crate) rules_replaced: u32,
    pub(crate) mounts_added: u32,
    pub(crate) mounts_removed: u32,
    pub(crate) affected_profiles: u32,
    pub(crate) affected_destinations: u32,
    pub(crate) potential_destinations: u32,
    pub(crate) truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ReceiptCompletion {
    Queued {
        correlation_id: String,
    },
    Applied {
        correlation_id: String,
        active_config_revision: String,
        active_policy_hash: String,
        daemon_instance_id: String,
    },
    Superseded {
        correlation_id: String,
        active_config_revision: String,
        active_policy_hash: String,
        daemon_instance_id: String,
        superseded_by: Option<String>,
    },
    Failed {
        correlation_id: String,
        reload_outcome: String,
        failure: String,
    },
    Unknown {
        correlation_id: Option<String>,
        reload_outcome: String,
        failure: Option<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BaseReceipt {
    #[serde(default)]
    pub(crate) revision_scope: RevisionScope,
    pub(crate) transaction_id: String,
    pub(crate) request_id: String,
    pub(crate) actor: String,
    pub(crate) origin: String,
    pub(crate) operation: String,
    pub(crate) payload_hash: String,
    pub(crate) plan_hash: String,
    #[serde(default)]
    pub(crate) operator_plan_hash: Option<String>,
    #[serde(default)]
    pub(crate) before_policy_hash: Option<String>,
    #[serde(default)]
    pub(crate) after_policy_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) operation_manifest: Option<serde_json::Value>,
    pub(crate) before_revision: String,
    pub(crate) after_revision: String,
    pub(crate) created_unix_seconds: u64,
    pub(crate) persistence: Persistence,
    pub(crate) changed_members: usize,
    pub(crate) rollback_restored: bool,
    pub(crate) audit_pending: bool,
    #[serde(default)]
    pub(crate) audit_context: ReceiptAuditContext,
    #[serde(default)]
    pub(crate) audit_activation: Option<ReceiptActivationState>,
    #[serde(default)]
    pub(crate) activation: ReceiptActivation,
    pub(crate) failure: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum MemberRole {
    Master,
    Include,
    Pack,
}

impl From<PolicyMemberKind> for MemberRole {
    fn from(kind: PolicyMemberKind) -> Self {
        match kind {
            PolicyMemberKind::Master => Self::Master,
            PolicyMemberKind::Include => Self::Include,
            PolicyMemberKind::Pack => Self::Pack,
        }
    }
}

impl From<MemberRole> for PolicyMemberKind {
    fn from(role: MemberRole) -> Self {
        match role {
            MemberRole::Master => Self::Master,
            MemberRole::Include => Self::Include,
            MemberRole::Pack => Self::Pack,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum MemberOperation {
    Create,
    Replace,
    Delete,
}

/// Journal-backed evidence for one member in a terminal operation's full inventory.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(
    dead_code,
    reason = "shared receipt evidence API consumed by feature-gated publishers"
)]
pub(crate) struct ReceiptMemberEvidence {
    pub(crate) path: String,
    pub(crate) role: MemberRole,
    pub(crate) operation: Option<MemberOperation>,
    pub(crate) before_digest: Option<String>,
    pub(crate) before_length: Option<u64>,
    pub(crate) before_uid: Option<u32>,
    pub(crate) before_gid: Option<u32>,
    pub(crate) before_mode: Option<u32>,
    pub(crate) before_device: Option<u64>,
    pub(crate) before_inode: Option<u64>,
    pub(crate) after_digest: Option<String>,
    pub(crate) after_length: Option<u64>,
    pub(crate) after_uid: Option<u32>,
    pub(crate) after_gid: Option<u32>,
    pub(crate) after_mode: Option<u32>,
    pub(crate) promoted_device: Option<u64>,
    pub(crate) promoted_inode: Option<u64>,
    pub(crate) restored_digest: Option<String>,
    pub(crate) restored_length: Option<u64>,
    pub(crate) restored_uid: Option<u32>,
    pub(crate) restored_gid: Option<u32>,
    pub(crate) restored_mode: Option<u32>,
    pub(crate) restored_device: Option<u64>,
    pub(crate) restored_inode: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Inode {
    device: u64,
    inode: u64,
}

impl Inode {
    fn of(meta: &Metadata) -> Self {
        Self {
            device: meta.dev(),
            inode: meta.ino(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileState {
    length: u64,
    digest: String,
    uid: u32,
    gid: u32,
    mode: u32,
    blob: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StagingReceipt {
    parent: Inode,
    name: String,
    directory: Inode,
    directory_uid: u32,
    directory_gid: u32,
    directory_mode: u32,
    payload: Inode,
    payload_uid: u32,
    payload_gid: u32,
    payload_mode: u32,
    payload_links: u64,
    payload_length: u64,
    payload_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LinkedStagingReceipt {
    parent: Inode,
    name: String,
    payload: Inode,
    payload_uid: u32,
    payload_gid: u32,
    payload_mode: u32,
    payload_length: u64,
    payload_digest: String,
}

/// A rollback copy is named in the member's own parent before publication.
/// `linked` is false while publication is still pending or after cleanup has
/// been durably announced; recovery must then tolerate either name state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RollbackStagingReceipt {
    parent: Inode,
    name: String,
    payload: Inode,
    payload_uid: u32,
    payload_gid: u32,
    payload_mode: u32,
    payload_length: u64,
    payload_digest: String,
    linked: bool,
}

impl FileState {
    fn new(bytes: &[u8], metadata: &Metadata, blob: String) -> Self {
        Self {
            length: bytes.len() as u64,
            digest: hash(bytes),
            uid: metadata.uid(),
            gid: metadata.gid(),
            mode: metadata.mode() & 0o7777,
            blob,
        }
    }

    fn matches(&self, bytes: &[u8], metadata: &Metadata) -> bool {
        metadata.is_file()
            && metadata.nlink() == 1
            && metadata.len() == self.length
            && metadata.uid() == self.uid
            && metadata.gid() == self.gid
            && metadata.mode() & 0o7777 == self.mode
            && bytes.len() as u64 == self.length
            && hash(bytes) == self.digest
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Member {
    path: String,
    role: MemberRole,
    operation: Option<MemberOperation>,
    before: Option<FileState>,
    after: Option<FileState>,
    before_inode: Option<Inode>,
    promoted_inode: Option<Inode>,
    restored_inode: Option<Inode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    staging: Option<StagingReceipt>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    linked_staging: Option<LinkedStagingReceipt>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    rollback_staging: Option<RollbackStagingReceipt>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Phase {
    Setup,
    Prepared,
    /// The before inventory is restored; rollback copies await cleanup.
    AbortCleanup,
    /// The commit decision is durable, but rollback copies still await cleanup.
    Committing,
    Committed,
    RollingBack,
    /// An explicit undo is restored; rollback copies await cleanup.
    RollbackCleanup,
    Aborted,
    RolledBack,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    format_version: u64,
    #[serde(default)]
    revision_scope: RevisionScope,
    master: String,
    root: Inode,
    receipt_store: Inode,
    source_schema: u64,
    target_schema: u64,
    request_fingerprint: String,
    receipt: BaseReceipt,
    phase: Phase,
    #[serde(default)]
    rollback_ready: bool,
    members: Vec<Member>,
}

pub(crate) enum PrepareOutcome<'g> {
    Replay(Box<BaseReceipt>),
    Prepared(Box<PreparedTransaction<'g>>),
}

pub(crate) struct PreparedTransaction<'g> {
    guard: &'g MigrationWriteLock,
    fence: File,
    store: File,
    owner: Metadata,
    receipts: ReceiptStore,
    journal: RefCell<Journal>,
    targets: Vec<PinnedTarget<'g>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RecoveryOutcome {
    Absent,
    LegacyActive,
    SetupRemoved,
    Recovered(Box<BaseReceipt>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(
    dead_code,
    reason = "terminal undo result retained by the transaction API"
)]
pub(crate) enum RollbackOutcome {
    NoReceipt,
    RollbackNotApplicable,
    Restored(Box<BaseReceipt>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum FinalizeOutcome {
    NoReceipt,
    AlreadyFinalized(Box<BaseReceipt>),
    Finalized(Box<BaseReceipt>),
}

pub(crate) struct PolicyRevisionTransition<'a> {
    before: &'a PolicyRevisionInventory,
    after: &'a PolicyRevisionInventory,
    verified_candidate: Option<&'a crate::operator_rules::VerifiedPolicyCandidate>,
}

impl<'a> PolicyRevisionTransition<'a> {
    pub(crate) fn new(
        before: &'a PolicyRevisionInventory,
        after: &'a PolicyRevisionInventory,
    ) -> Self {
        Self {
            before,
            after,
            verified_candidate: None,
        }
    }

    pub(crate) fn with_verified_candidate(
        mut self,
        candidate: Option<&'a crate::operator_rules::VerifiedPolicyCandidate>,
    ) -> Self {
        self.verified_candidate = candidate;
        self
    }
}

/// Prepare an already validated, complete policy candidate under one exclusive lock.
///
/// The callback validates the entire candidate graph and pack overlay. It must not
/// acquire another config lock or request reload. Both inventories contain present
/// files only; deleting a member means omitting it from the candidate inventory.
pub(crate) fn prepare<'g>(
    guard: &'g MigrationWriteLock,
    receipts: &ReceiptStore,
    request: &TransactionRequest,
    before: &PolicyRevisionInventory,
    after: &PolicyRevisionInventory,
    validate: impl FnOnce() -> anyhow::Result<()>,
) -> anyhow::Result<PrepareOutcome<'g>> {
    prepare_with_hook(
        guard,
        receipts,
        request,
        PolicyRevisionTransition::new(before, after),
        ReceiptPreparationContext::default(),
        validate,
        |_| {},
    )
}

/// Notify the supervisor after intent and its base receipt are durable.
pub(crate) fn prepare_with_hook<'g>(
    guard: &'g MigrationWriteLock,
    receipts: &ReceiptStore,
    request: &TransactionRequest,
    transition: PolicyRevisionTransition<'_>,
    context: ReceiptPreparationContext<'_>,
    validate: impl FnOnce() -> anyhow::Result<()>,
    on_prepared: impl FnOnce(&BaseReceipt),
) -> anyhow::Result<PrepareOutcome<'g>> {
    prepare_with_hook_impl(
        guard,
        receipts,
        request,
        transition,
        context,
        validate,
        on_prepared,
        true,
    )
}

pub(crate) fn prepare_with_hook_after_recovery<'g>(
    guard: &'g MigrationWriteLock,
    receipts: &ReceiptStore,
    request: &TransactionRequest,
    transition: PolicyRevisionTransition<'_>,
    context: ReceiptPreparationContext<'_>,
    validate: impl FnOnce() -> anyhow::Result<()>,
    on_prepared: impl FnOnce(&BaseReceipt),
) -> anyhow::Result<PrepareOutcome<'g>> {
    prepare_with_hook_impl(
        guard,
        receipts,
        request,
        transition,
        context,
        validate,
        on_prepared,
        false,
    )
}

#[allow(clippy::too_many_arguments)]
fn prepare_with_hook_impl<'g>(
    guard: &'g MigrationWriteLock,
    receipts: &ReceiptStore,
    request: &TransactionRequest,
    transition: PolicyRevisionTransition<'_>,
    context: ReceiptPreparationContext<'_>,
    validate: impl FnOnce() -> anyhow::Result<()>,
    on_prepared: impl FnOnce(&BaseReceipt),
    recover: bool,
) -> anyhow::Result<PrepareOutcome<'g>> {
    let PolicyRevisionTransition {
        before,
        after,
        verified_candidate,
    } = transition;
    let ReceiptPreparationContext {
        operator_plan_hash,
        semantic,
        operation_manifest,
    } = context;
    validate_request(request)?;
    ensure!(
        operator_plan_hash.is_none_or(is_hash),
        "invalid operator plan hash"
    );
    validate_operation_manifest(operation_manifest.as_ref())?;
    ensure!(
        semantic.before_policy_hash.as_deref().is_none_or(is_hash)
            && semantic.after_policy_hash.as_deref().is_none_or(is_hash),
        "invalid operator policy hash"
    );
    if recover
        && matches!(
            recover_active(guard, receipts)?,
            RecoveryOutcome::LegacyActive
        )
    {
        bail!("legacy migration requires its own recovery");
    }
    migration_journal::refuse_normal_write(guard.tree_io())?;
    let tree = guard.tree_io();
    let owner = tree.identity.owner_metadata(tree.root)?;
    let fingerprint = request_fingerprint(request, before, after)?;
    let store = open_store(tree, &owner, true)?.context("receipt store missing")?;
    let key = request_key(&request.actor, &request.request_id);
    if let Some(receipt) = lookup_in(&store, &owner, tree, receipts, &key, Some(&fingerprint))? {
        return Ok(PrepareOutcome::Replay(Box::new(receipt)));
    }
    receipts.admit(tree, &store, unix_seconds()?, MAX_RECEIPTS)?;
    ensure!(
        before.revision() == request.expected_revision,
        "RevisionConflict: stale base revision"
    );
    if let Some(candidate) = verified_candidate {
        ensure!(
            request.target_schema == super::schema::TARGET_SCHEMA_VERSION_V5 as u64
                && candidate.revision() == after.revision().to_string()
                && semantic.after_policy_hash.as_deref() == Some(candidate.policy_hash()),
            "RevisionConflict: compiled candidate does not match transaction inventory"
        );
    }
    validate_inventory(before, tree)?;
    validate_inventory(after, tree)?;
    validate_flat_packs(tree)?;
    let (members, plans, blobs) = plan_members(tree, Some(before), after, &owner)?;
    validate()?;
    let blob_total = blobs.values().try_fold(0_u64, |total, bytes| {
        total
            .checked_add(bytes.len() as u64)
            .context("blob budget overflow")
    })?;
    ensure!(
        blob_total <= MAX_BLOB_BYTES,
        "policy transaction blob budget exceeded"
    );
    preflight_space(
        tree.root,
        blob_total
            .saturating_mul(2)
            .saturating_add(MAX_MANIFEST_BYTES),
    )?;
    let mut random = [0_u8; 16];
    rand_core::OsRng
        .try_fill_bytes(&mut random)
        .map_err(|error| anyhow::anyhow!("transaction identity entropy: {error}"))?;
    let receipt = BaseReceipt {
        revision_scope: RevisionScope::PolicyTreeV1,
        transaction_id: hex(&random),
        request_id: request.request_id.clone(),
        actor: request.actor.clone(),
        origin: request.origin.clone(),
        operation: request.operation.clone(),
        payload_hash: hash(&request.payload),
        plan_hash: fingerprint.clone(),
        operator_plan_hash: operator_plan_hash.map(str::to_owned),
        before_policy_hash: semantic.before_policy_hash,
        after_policy_hash: semantic.after_policy_hash,
        operation_manifest,
        before_revision: before.revision().to_string(),
        after_revision: after.revision().to_string(),
        created_unix_seconds: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        persistence: Persistence::Prepared,
        changed_members: members
            .iter()
            .filter(|member| member.operation.is_some())
            .count(),
        rollback_restored: false,
        audit_pending: true,
        audit_context: semantic.audit,
        audit_activation: None,
        activation: ReceiptActivation {
            state: if operator_plan_hash.is_some()
                && members.iter().any(|member| member.operation.is_some())
            {
                ReceiptActivationState::Pending
            } else {
                ReceiptActivationState::NotRequired
            },
            ..ReceiptActivation::default()
        },
        failure: None,
    };
    let journal = Journal {
        format_version: FORMAT_VERSION,
        revision_scope: RevisionScope::PolicyTreeV1,
        master: master_name(tree)?,
        root: Inode::of(&tree.root.metadata()?),
        receipt_store: Inode::of(&receipts.directory.metadata()?),
        source_schema: request.source_schema,
        target_schema: request.target_schema,
        request_fingerprint: fingerprint,
        receipt,
        phase: Phase::Setup,
        rollback_ready: false,
        members,
    };
    publish_prepared(
        guard,
        receipts,
        store,
        owner,
        journal,
        (plans, blobs),
        on_prepared,
    )
}

#[allow(
    clippy::too_many_arguments,
    reason = "one publication boundary for both typed transaction scopes"
)]
fn publish_prepared<'g>(
    guard: &'g MigrationWriteLock,
    receipts: &ReceiptStore,
    store: File,
    owner: Metadata,
    mut journal: Journal,
    files: (Vec<TargetPlan<'g>>, BTreeMap<String, Vec<u8>>),
    on_prepared: impl FnOnce(&BaseReceipt),
) -> anyhow::Result<PrepareOutcome<'g>> {
    let (plans, blobs) = files;
    let tree = guard.tree_io();
    encode(&journal)?;
    guard.verify_root_linked()?;
    receipts.check_for_tree(tree)?;
    let fence = publish_fence(tree, &owner)?;
    write_journal(&fence, &owner, &journal)?;
    for (name, bytes) in blobs {
        write_declared_blob(&fence, &name, &bytes, &owner)?;
    }
    fence.sync_all()?;
    journal.phase = Phase::Prepared;
    write_journal(&fence, &owner, &journal)?;
    tree.root.sync_all()?;
    receipts.write(&journal, tree)?;
    on_prepared(&journal.receipt);
    fault(FaultPoint::AfterPreparedReceiptHook)?;
    let targets = plans
        .into_iter()
        .map(TargetPlan::materialize)
        .collect::<anyhow::Result<Vec<_>>>()?;
    Ok(PrepareOutcome::Prepared(Box::new(PreparedTransaction {
        guard,
        fence,
        store,
        owner,
        receipts: receipts.duplicate()?,
        journal: RefCell::new(journal),
        targets,
    })))
}

/// Repair only the captured destinations. Candidate validation runs before intent.
pub(crate) fn apply_repair(
    receipts: &ReceiptStore,
    request: &RepairRequest,
    destinations: RepairDestinationSet<'_>,
    validate: impl FnOnce() -> anyhow::Result<()>,
) -> anyhow::Result<BaseReceipt> {
    match prepare_repair(receipts, request, destinations, validate)? {
        PrepareOutcome::Replay(receipt) => Ok(*receipt),
        PrepareOutcome::Prepared(transaction) => transaction.commit(),
    }
}

fn prepare_repair<'g>(
    receipts: &ReceiptStore,
    request: &RepairRequest,
    destinations: RepairDestinationSet<'g>,
    validate: impl FnOnce() -> anyhow::Result<()>,
) -> anyhow::Result<PrepareOutcome<'g>> {
    validate_request_fields(
        [
            &request.actor,
            &request.request_id,
            &request.origin,
            &request.operation,
        ],
        &request.payload,
        request.source_schema,
        request.target_schema,
    )?;
    let guard = destinations.guard;
    match recover_active(guard, receipts)? {
        RecoveryOutcome::LegacyActive => bail!("legacy migration requires its own recovery"),
        _ => migration_journal::refuse_normal_write(guard.tree_io())?,
    }
    let tree = guard.tree_io();
    let owner = tree.identity.owner_metadata(tree.root)?;
    let fingerprint = repair_request_fingerprint(request, &destinations.after_revision);
    let store = open_store(tree, &owner, true)?.context("receipt store missing")?;
    let key = request_key(&request.actor, &request.request_id);
    if let Some(receipt) = lookup_in(&store, &owner, tree, receipts, &key, Some(&fingerprint))? {
        return Ok(PrepareOutcome::Replay(Box::new(receipt)));
    }
    receipts.admit(tree, &store, unix_seconds()?, MAX_RECEIPTS)?;
    ensure!(
        request.expected_destinations == destinations.before_revision,
        "RevisionConflict: stale repair destinations"
    );
    let (members, plans, blobs) = destinations.planned;
    verify_repair_before(tree, &members)?;
    validate()?;
    verify_repair_before(tree, &members)?;
    let blob_total = blobs.values().try_fold(0_u64, |total, bytes| {
        total
            .checked_add(bytes.len() as u64)
            .context("blob budget overflow")
    })?;
    ensure!(
        blob_total <= MAX_BLOB_BYTES,
        "repair transaction blob budget exceeded"
    );
    preflight_space(
        tree.root,
        blob_total
            .saturating_mul(2)
            .saturating_add(MAX_MANIFEST_BYTES),
    )?;
    let mut random = [0_u8; 16];
    rand_core::OsRng
        .try_fill_bytes(&mut random)
        .map_err(|error| anyhow::anyhow!("transaction identity entropy: {error}"))?;
    let receipt = BaseReceipt {
        revision_scope: RevisionScope::RepairDestinationSetV1,
        transaction_id: hex(&random),
        request_id: request.request_id.clone(),
        actor: request.actor.clone(),
        origin: request.origin.clone(),
        operation: request.operation.clone(),
        payload_hash: hash(&request.payload),
        plan_hash: fingerprint.clone(),
        operator_plan_hash: None,
        before_policy_hash: None,
        after_policy_hash: None,
        operation_manifest: None,
        before_revision: destinations.before_revision.0,
        after_revision: destinations.after_revision.0,
        created_unix_seconds: unix_seconds()?,
        persistence: Persistence::Prepared,
        changed_members: members
            .iter()
            .filter(|member| member.operation.is_some())
            .count(),
        rollback_restored: false,
        audit_pending: true,
        audit_context: ReceiptAuditContext::default(),
        audit_activation: None,
        activation: ReceiptActivation::default(),
        failure: None,
    };
    let journal = Journal {
        format_version: FORMAT_VERSION,
        revision_scope: RevisionScope::RepairDestinationSetV1,
        master: master_name(tree)?,
        root: Inode::of(&tree.root.metadata()?),
        receipt_store: Inode::of(&receipts.directory.metadata()?),
        source_schema: request.source_schema,
        target_schema: request.target_schema,
        request_fingerprint: fingerprint,
        receipt,
        phase: Phase::Setup,
        rollback_ready: false,
        members,
    };
    publish_prepared(
        guard,
        receipts,
        store,
        owner,
        journal,
        (plans, blobs),
        |_| {},
    )
}

pub(crate) fn apply(
    guard: &MigrationWriteLock,
    receipts: &ReceiptStore,
    request: &TransactionRequest,
    before: &PolicyRevisionInventory,
    after: &PolicyRevisionInventory,
    validate: impl FnOnce() -> anyhow::Result<()>,
) -> anyhow::Result<BaseReceipt> {
    match prepare(guard, receipts, request, before, after, validate)? {
        PrepareOutcome::Replay(receipt) => Ok(*receipt),
        PrepareOutcome::Prepared(transaction) => transaction.commit(),
    }
}

impl PreparedTransaction<'_> {
    pub(crate) fn receipt(&self) -> BaseReceipt {
        self.journal.borrow().receipt.clone()
    }

    /// Commit returns an uncertain receipt when a publication or durability barrier
    /// fails after intent. The active fence remains recoverable in that case.
    pub(crate) fn commit(self) -> anyhow::Result<BaseReceipt> {
        let result = self.promote_and_commit();
        match result {
            Ok(receipt) => Ok(receipt),
            Err(error) => {
                let cleanup_error = cleanup_staging_receipts(
                    self.guard.tree_io(),
                    &self.fence,
                    &self.owner,
                    &self.journal,
                )
                .err();
                let mut journal = self.journal.borrow_mut();
                journal.receipt.persistence = Persistence::DurabilityUncertain;
                let failure = cleanup_error.map_or_else(
                    || format!("{error:#}"),
                    |cleanup| format!("{error:#}; staging cleanup: {cleanup:#}"),
                );
                journal.receipt.failure = Some(failure.chars().take(1024).collect());
                // The persisted phase controls recovery; an uncertain response never
                // changes whether the commit decision reached the journal.
                let _ = write_journal(&self.fence, &self.owner, &journal);
                let _ = self.receipts.write(&journal, self.guard.tree_io());
                Ok(journal.receipt.clone())
            }
        }
    }

    fn promote_and_commit(&self) -> anyhow::Result<BaseReceipt> {
        self.guard.verify_root_linked()?;
        self.receipts.check_for_tree(self.guard.tree_io())?;
        // Every destructive member gets a durable, same-parent before image
        // before a target entry can change.  A failed stage therefore leaves
        // the complete policy inventory untouched.
        stage_rollback_members(
            self.guard,
            &self.fence,
            &self.owner,
            &self.journal,
            &self.targets,
        )?;
        let members = self.journal.borrow().members.clone();
        for (index, (member, target)) in members.iter().zip(&self.targets).enumerate() {
            self.guard.verify_root_linked()?;
            verify_target(target, member.before.as_ref(), member.before_inode.as_ref())?;
            match member.operation {
                None => {}
                Some(MemberOperation::Delete) => {
                    fault(FaultPoint::BeforePromotion)?;
                    target.unlink()?;
                    fault(FaultPoint::AfterPromotion)?;
                }
                Some(MemberOperation::Create | MemberOperation::Replace) => {
                    self.write_member(
                        index,
                        target,
                        member.after.as_ref().context("after image")?,
                        false,
                    )?;
                }
            }
        }
        self.guard.verify_root_linked()?;
        verify_inventory(
            self.guard,
            &self.fence,
            &self.owner,
            &self.journal.borrow(),
            false,
            true,
            true,
        )?;
        {
            let mut journal = self.journal.borrow_mut();
            // Keep rollback copies through the durable decision.  The
            // nonterminal phase lets recovery clean them after proving after.
            journal.phase = Phase::Committing;
            journal.receipt.persistence = Persistence::Committed;
            journal.receipt.failure = None;
            write_journal(&self.fence, &self.owner, &journal)?;
        }
        cleanup_rollback_staging(
            self.guard.tree_io(),
            &self.fence,
            &self.owner,
            &self.journal,
        )?;
        {
            let mut journal = self.journal.borrow_mut();
            journal.phase = Phase::Committed;
            write_journal(&self.fence, &self.owner, &journal)?;
        }
        terminalize(
            self.guard.tree_io(),
            &self.store,
            &self.fence,
            &self.journal.borrow(),
        )?;
        self.receipts
            .write(&self.journal.borrow(), self.guard.tree_io())?;
        Ok(self.receipt())
    }

    fn write_member(
        &self,
        index: usize,
        target: &PinnedTarget<'_>,
        state: &FileState,
        restoring: bool,
    ) -> anyhow::Result<()> {
        promote_blob(
            &self.fence,
            &self.owner,
            &self.journal,
            index,
            target,
            state,
            restoring,
        )
    }
}

#[allow(
    dead_code,
    reason = "durable idempotency lookup retained by the transaction API"
)]
pub(crate) fn lookup_receipt(
    guard: &MigrationWriteLock,
    receipts: &ReceiptStore,
    actor: &str,
    request_id: &str,
) -> anyhow::Result<Option<BaseReceipt>> {
    if let RecoveryOutcome::LegacyActive = recover_active(guard, receipts)? {
        bail!("legacy migration requires its own recovery");
    }
    lookup_receipt_after_recovery(guard, receipts, actor, request_id)
}

pub(crate) fn lookup_receipt_after_recovery(
    guard: &MigrationWriteLock,
    receipts: &ReceiptStore,
    actor: &str,
    request_id: &str,
) -> anyhow::Result<Option<BaseReceipt>> {
    migration_journal::refuse_normal_write(guard.tree_io())?;
    let tree = guard.tree_io();
    let owner = tree.identity.owner_metadata(tree.root)?;
    let Some(store) = open_store(tree, &owner, false)? else {
        return Ok(None);
    };
    lookup_in(
        &store,
        &owner,
        tree,
        receipts,
        &request_key(actor, request_id),
        None,
    )
}

/// Find a durable operation owned by the authenticated actor with bounded scanning.
pub(crate) fn lookup_operation_receipt(
    guard: &MigrationWriteLock,
    receipts: &ReceiptStore,
    actor: &str,
    operation_id: &str,
) -> anyhow::Result<Option<BaseReceipt>> {
    if let RecoveryOutcome::LegacyActive = recover_active(guard, receipts)? {
        bail!("legacy migration requires its own recovery");
    }
    lookup_operation_receipt_after_recovery(guard, receipts, actor, operation_id)
}

pub(crate) fn lookup_operation_receipt_after_recovery(
    guard: &MigrationWriteLock,
    receipts: &ReceiptStore,
    actor: &str,
    operation_id: &str,
) -> anyhow::Result<Option<BaseReceipt>> {
    migration_journal::refuse_normal_write(guard.tree_io())?;
    let tree = guard.tree_io();
    for name in directory_names(&receipts.directory, MAX_RECEIPTS * 2)? {
        let Some(key) = name.strip_suffix(".json") else {
            continue;
        };
        ensure!(is_hash(key), "invalid receipt store key");
        if let Some(stored) = receipts.read(key, tree)? {
            if stored.receipt.actor == actor && stored.receipt.transaction_id == operation_id {
                return Ok(Some(stored.receipt));
            }
        }
    }
    Ok(None)
}

/// Return evidence from the retained journal of a terminal operation.
///
/// A committed receipt exposes the planned before/after states and the inode
/// actually promoted for each non-delete after state; restoration fields are
/// absent. An aborted or rolled-back receipt retains the same evidence and
/// additionally exposes a restored state only where rollback promoted a
/// before image. Restoring absence has no digest or inode. No field is
/// reconstructed from the live path. Unchanged members have `operation: None`,
/// identical before/after states and no promoted/restored inode; their recorded
/// before inode attests the unchanged after identity.
#[allow(
    dead_code,
    reason = "shared receipt evidence API consumed by feature-gated publishers"
)]
pub(crate) fn lookup_operation_member_evidence(
    guard: &MigrationWriteLock,
    receipts: &ReceiptStore,
    actor: &str,
    operation_id: &str,
) -> anyhow::Result<Option<(BaseReceipt, Vec<ReceiptMemberEvidence>)>> {
    let Some(receipt) = lookup_operation_receipt(guard, receipts, actor, operation_id)? else {
        return Ok(None);
    };
    let tree = guard.tree_io();
    let owner = tree.identity.owner_metadata(tree.root)?;
    let store = open_store(tree, &owner, false)?
        .context("terminal receipt exists but its retained member evidence is unavailable")?;
    let key = request_key(&receipt.actor, &receipt.request_id);
    let undo = private_dir(&store, &key, &owner, false)
        .context("terminal receipt exists but its retained member evidence is unavailable")?;
    let journal = read_journal(&undo, &owner, tree)?;
    receipts.check_for_tree(tree)?;
    ensure!(
        journal.receipt_store == Inode::of(&receipts.directory.metadata()?),
        "ReceiptStoreMismatch: transaction belongs to another receipt store"
    );
    ensure!(
        matches!(
            journal.phase,
            Phase::Committed | Phase::Aborted | Phase::RolledBack
        ) && journal.receipt == receipt,
        "member evidence does not belong to the terminal receipt"
    );
    validate_fence_inventory(&undo, &owner, &journal)?;
    validate_all_blobs(&undo, &owner, &journal)?;

    let evidence = journal
        .members
        .iter()
        .map(|member| {
            let restored = member.restored_inode.as_ref().and(member.before.as_ref());
            ReceiptMemberEvidence {
                path: member.path.clone(),
                role: member.role,
                operation: member.operation,
                before_digest: member.before.as_ref().map(|state| state.digest.clone()),
                before_length: member.before.as_ref().map(|state| state.length),
                before_uid: member.before.as_ref().map(|state| state.uid),
                before_gid: member.before.as_ref().map(|state| state.gid),
                before_mode: member.before.as_ref().map(|state| state.mode),
                before_device: member.before_inode.as_ref().map(|inode| inode.device),
                before_inode: member.before_inode.as_ref().map(|inode| inode.inode),
                after_digest: member.after.as_ref().map(|state| state.digest.clone()),
                after_length: member.after.as_ref().map(|state| state.length),
                after_uid: member.after.as_ref().map(|state| state.uid),
                after_gid: member.after.as_ref().map(|state| state.gid),
                after_mode: member.after.as_ref().map(|state| state.mode),
                promoted_device: member.promoted_inode.as_ref().map(|inode| inode.device),
                promoted_inode: member.promoted_inode.as_ref().map(|inode| inode.inode),
                restored_digest: restored.map(|state| state.digest.clone()),
                restored_length: restored.map(|state| state.length),
                restored_uid: restored.map(|state| state.uid),
                restored_gid: restored.map(|state| state.gid),
                restored_mode: restored.map(|state| state.mode),
                restored_device: member.restored_inode.as_ref().map(|inode| inode.device),
                restored_inode: member.restored_inode.as_ref().map(|inode| inode.inode),
            }
        })
        .collect::<Vec<_>>();
    ensure!(
        evidence
            .iter()
            .filter(|member| member.operation.is_some())
            .count()
            == receipt.changed_members,
        "terminal receipt has incomplete member evidence"
    );
    Ok(Some((receipt, evidence)))
}

/// Enumerate durable transaction decisions whose audit delivery or exact
/// activation completion still needs work after restart.
pub(crate) fn pending_completion_receipts(
    guard: &MigrationWriteLock,
    receipts: &ReceiptStore,
) -> anyhow::Result<Vec<BaseReceipt>> {
    if let RecoveryOutcome::LegacyActive = recover_active(guard, receipts)? {
        bail!("legacy migration requires its own recovery");
    }
    let tree = guard.tree_io();
    let mut pending = Vec::new();
    for name in directory_names(&receipts.directory, MAX_RECEIPTS * 2)? {
        let Some(key) = name.strip_suffix(".json") else {
            continue;
        };
        ensure!(is_hash(key), "invalid receipt store key");
        let receipt = receipts
            .read(key, tree)?
            .context("receipt disappeared")?
            .receipt;
        if receipt.operator_plan_hash.is_some()
            && matches!(
                receipt.persistence,
                Persistence::Committed | Persistence::Aborted
            )
            && !receipt_completion_settled(&receipt)
        {
            pending.push(receipt);
        }
    }
    pending.sort_by(|left, right| {
        (left.created_unix_seconds, &left.transaction_id)
            .cmp(&(right.created_unix_seconds, &right.transaction_id))
    });
    Ok(pending)
}

fn receipt_completion_settled(receipt: &BaseReceipt) -> bool {
    receipt.operator_plan_hash.is_none()
        || (!receipt.audit_pending && receipt.activation.state != ReceiptActivationState::Pending)
}

/// Persist a post-commit activation observation on the existing durable receipt.
///
/// Callers acquire the tree's exclusive lock before entering this function, but
/// must not retain it while waiting for the daemon reload.  The receipt update is
/// node-local operational state; it never changes the committed policy revision.
pub(crate) fn complete_receipt_activation(
    guard: &MigrationWriteLock,
    receipts: &ReceiptStore,
    actor: &str,
    request_id: &str,
    operation_id: &str,
    completion: ReceiptCompletion,
) -> anyhow::Result<BaseReceipt> {
    if let RecoveryOutcome::LegacyActive = recover_active(guard, receipts)? {
        bail!("legacy migration requires its own recovery");
    }
    receipts.update(
        guard.tree_io(),
        actor,
        request_id,
        operation_id,
        |receipt| {
            ensure!(
                receipt.persistence == Persistence::Committed,
                "activation cannot complete before policy commit"
            );
            apply_completion(&mut receipt.activation, completion)
        },
    )
}

/// Mark delivery to the deduplicating semantic audit sink as complete.
pub(crate) fn mark_receipt_audit_recorded(
    guard: &MigrationWriteLock,
    receipts: &ReceiptStore,
    actor: &str,
    request_id: &str,
    operation_id: &str,
) -> anyhow::Result<BaseReceipt> {
    if let RecoveryOutcome::LegacyActive = recover_active(guard, receipts)? {
        bail!("legacy migration requires its own recovery");
    }
    receipts.update(
        guard.tree_io(),
        actor,
        request_id,
        operation_id,
        |receipt| {
            receipt.audit_pending = false;
            Ok(())
        },
    )
}

/// Freeze the activation outcome represented by the operation's one logical
/// audit event before attempting delivery. Retries then reproduce the same
/// payload even if a later explicit activation retry changes the live status.
pub(crate) fn freeze_receipt_audit(
    guard: &MigrationWriteLock,
    receipts: &ReceiptStore,
    actor: &str,
    request_id: &str,
    operation_id: &str,
) -> anyhow::Result<BaseReceipt> {
    if let RecoveryOutcome::LegacyActive = recover_active(guard, receipts)? {
        bail!("legacy migration requires its own recovery");
    }
    receipts.update(
        guard.tree_io(),
        actor,
        request_id,
        operation_id,
        |receipt| {
            ensure!(
                matches!(
                    receipt.persistence,
                    Persistence::Committed | Persistence::Aborted
                ),
                "audit cannot be delivered before a transaction decision"
            );
            receipt
                .audit_activation
                .get_or_insert(receipt.activation.state);
            Ok(())
        },
    )
}

fn apply_completion(
    activation: &mut ReceiptActivation,
    completion: ReceiptCompletion,
) -> anyhow::Result<()> {
    let valid_text = |value: &str, max: usize| {
        !value.is_empty() && value.len() <= max && !value.chars().any(char::is_control)
    };
    match completion {
        ReceiptCompletion::Queued { correlation_id } => {
            ensure!(
                valid_text(&correlation_id, 128),
                "invalid reload correlation id"
            );
            activation.state = ReceiptActivationState::Pending;
            activation.correlation_id = Some(correlation_id);
            activation.reload_outcome = Some("queued".into());
            activation.failure = None;
        }
        ReceiptCompletion::Applied {
            correlation_id,
            active_config_revision,
            active_policy_hash,
            daemon_instance_id,
        } => {
            ensure!(
                valid_text(&correlation_id, 128),
                "invalid reload correlation id"
            );
            ensure!(
                is_hash(&active_config_revision),
                "invalid active config revision"
            );
            ensure!(is_hash(&active_policy_hash), "invalid active policy hash");
            ensure!(
                valid_text(&daemon_instance_id, 128),
                "invalid daemon instance id"
            );
            activation.state = ReceiptActivationState::Applied;
            activation.correlation_id = Some(correlation_id);
            activation.reload_outcome = Some("reloaded".into());
            activation.active_config_revision = Some(active_config_revision);
            activation.active_policy_hash = Some(active_policy_hash);
            activation.daemon_instance_id = Some(daemon_instance_id);
            activation.superseded_by = None;
            activation.failure = None;
        }
        ReceiptCompletion::Superseded {
            correlation_id,
            active_config_revision,
            active_policy_hash,
            daemon_instance_id,
            superseded_by,
        } => {
            ensure!(
                valid_text(&correlation_id, 128),
                "invalid reload correlation id"
            );
            ensure!(
                is_hash(&active_config_revision),
                "invalid active config revision"
            );
            ensure!(is_hash(&active_policy_hash), "invalid active policy hash");
            ensure!(
                valid_text(&daemon_instance_id, 128),
                "invalid daemon instance id"
            );
            ensure!(
                superseded_by
                    .as_deref()
                    .is_none_or(|value| valid_text(value, 128)),
                "invalid superseding operation id"
            );
            activation.state = ReceiptActivationState::Superseded;
            activation.correlation_id = Some(correlation_id);
            activation.reload_outcome = Some("superseded".into());
            activation.active_config_revision = Some(active_config_revision);
            activation.active_policy_hash = Some(active_policy_hash);
            activation.daemon_instance_id = Some(daemon_instance_id);
            activation.superseded_by = superseded_by;
            activation.failure = None;
        }
        ReceiptCompletion::Failed {
            correlation_id,
            reload_outcome,
            failure,
        } => {
            ensure!(
                valid_text(&correlation_id, 128),
                "invalid reload correlation id"
            );
            ensure!(valid_text(&reload_outcome, 64), "invalid reload outcome");
            activation.state = ReceiptActivationState::Failed;
            activation.correlation_id = Some(correlation_id);
            activation.reload_outcome = Some(reload_outcome);
            activation.failure = Some(failure.chars().take(4096).collect());
        }
        ReceiptCompletion::Unknown {
            correlation_id,
            reload_outcome,
            failure,
        } => {
            ensure!(
                correlation_id
                    .as_deref()
                    .is_none_or(|value| valid_text(value, 128)),
                "invalid reload correlation id"
            );
            ensure!(valid_text(&reload_outcome, 64), "invalid reload outcome");
            activation.state = ReceiptActivationState::Unknown;
            activation.correlation_id = correlation_id;
            activation.reload_outcome = Some(reload_outcome);
            activation.failure = failure.map(|value| value.chars().take(4096).collect());
        }
    }
    Ok(())
}

/// Validate the live flat pack tree before restore recovery can change it.
///
/// An active format-2 transaction may own same-directory rollback links. Only
/// links named by its strict journal and still matching their descriptor,
/// inode, ownership, mode, length and digest receipts are excluded. Every
/// other write-stage name, nested entry or special file remains a hard error.
pub(crate) fn preflight_restore_pack_tree(guard: &MigrationWriteLock) -> anyhow::Result<()> {
    guard.verify_root_linked()?;
    let tree = guard.tree_io();
    let owner = tree.identity.owner_metadata(tree.root)?;
    let mut overlay = super::custom_list::PackOverlay::default();

    if inspect_at(tree.root, OsStr::new(TXN_DIR_NAME))?.is_some() {
        let fence = private_dir(tree.root, TXN_DIR_NAME, &owner, false)?;
        if let Some(bytes) =
            read_optional_private(&fence, JOURNAL_NAME, &owner, MAX_MANIFEST_BYTES)?
        {
            #[derive(Deserialize)]
            struct Format {
                format_version: u64,
            }
            let format: Format =
                serde_json::from_slice(&bytes).context("invalid migration format discriminator")?;
            if format.format_version == FORMAT_VERSION {
                let journal = decode(&bytes, tree)?;
                validate_fence_inventory(&fence, &owner, &journal)?;
                for member in &journal.members {
                    if member.role != MemberRole::Pack {
                        continue;
                    }
                    let Some(receipt) = &member.rollback_staging else {
                        continue;
                    };
                    let state = member
                        .before
                        .as_ref()
                        .context("pack rollback receipt lacks before image")?;
                    let target = tree
                        .plan_root_file_no_follow(Path::new(&member.path))?
                        .materialize()?;
                    if verify_rollback_staging(&target, state, receipt)?.is_some() {
                        overlay
                            .ignore_verified_stage(PathBuf::from("packs").join(&receipt.name))?;
                    }
                }
            }
        }
    }

    super::custom_list::validate_flat_pack_tree_under_tree_with_overlay(tree, Some(&overlay))
        .context("refusing restore with an unsupported live packs/ tree")?;
    Ok(())
}

/// Recover only a verified schema-4 to schema-5 intent approved by the caller.
pub(crate) fn recover_bootstrap_migration(
    guard: &MigrationWriteLock,
    receipts: &ReceiptStore,
    authorize: impl FnOnce(&BaseReceipt) -> anyhow::Result<()>,
) -> anyhow::Result<RecoveryOutcome> {
    recover_active_impl(guard, receipts, true, |_, _, journal| {
        authorize(&journal.receipt)
    })
}

fn validate_migration_journal_revisions(
    fence: &File,
    owner: &Metadata,
    journal: &Journal,
) -> anyhow::Result<()> {
    ensure!(
        journal.source_schema == 4
            && journal.target_schema == 5
            && journal.revision_scope == RevisionScope::PolicyTreeV1,
        "BootstrapRecoveryMismatch: journal is not a schema-4 to schema-5 policy migration"
    );
    for (before, expected) in [
        (true, &journal.receipt.before_revision),
        (false, &journal.receipt.after_revision),
    ] {
        let mut members = Vec::new();
        for member in &journal.members {
            if let Some(state) = if before {
                member.before.as_ref()
            } else {
                member.after.as_ref()
            } {
                members.push(PolicyRevisionMember::present(
                    member.role.into(),
                    PathBuf::from(&member.path),
                    read_blob(fence, owner, state)?,
                )?);
            }
        }
        ensure!(
            PolicyRevisionInventory::new(members)?
                .revision()
                .to_string()
                == *expected,
            "BootstrapRecoveryMismatch: verified blobs differ from the approved revision"
        );
    }
    Ok(())
}

/// Recover format2 only. Format1 remains owned by its existing decoder and state machine.
pub(crate) fn recover_active(
    guard: &MigrationWriteLock,
    receipts: &ReceiptStore,
) -> anyhow::Result<RecoveryOutcome> {
    recover_active_impl(guard, receipts, false, |_, _, _| Ok(()))
}

fn recover_active_impl(
    guard: &MigrationWriteLock,
    receipts: &ReceiptStore,
    bootstrap: bool,
    authorize: impl FnOnce(&File, &Metadata, &Journal) -> anyhow::Result<()>,
) -> anyhow::Result<RecoveryOutcome> {
    guard.verify_root_linked()?;
    let tree = guard.tree_io();
    receipts.check_for_tree(tree)?;
    let owner = tree.identity.owner_metadata(tree.root)?;
    if inspect_at(tree.root, OsStr::new(TXN_DIR_NAME))?.is_none() {
        if cleanup_setup_stage(tree, &owner)? {
            return Ok(RecoveryOutcome::SetupRemoved);
        }
        reconcile_terminal_receipts(tree, receipts, &owner)?;
        return Ok(RecoveryOutcome::Absent);
    }
    let owner = tree.identity.owner_metadata(tree.root)?;
    let fence = private_dir(tree.root, TXN_DIR_NAME, &owner, false)?;
    let Some(bytes) = read_optional_private(&fence, JOURNAL_NAME, &owner, MAX_MANIFEST_BYTES)?
    else {
        if let Some(marker) = read_optional_private(&fence, SETUP_MARKER, &owner, 2)? {
            ensure!(marker == b"2\n", "invalid format2 setup marker");
            remove_setup(tree.root, &fence, &owner)?;
            return Ok(RecoveryOutcome::SetupRemoved);
        }
        ensure!(
            !bootstrap,
            "BootstrapRecoveryMismatch: active migration has no format2 authorization"
        );
        return Ok(RecoveryOutcome::LegacyActive);
    };
    #[derive(Deserialize)]
    struct Format {
        format_version: u64,
    }
    let format: Format =
        serde_json::from_slice(&bytes).context("invalid migration format discriminator")?;
    if format.format_version == 1 {
        ensure!(
            !bootstrap,
            "BootstrapRecoveryMismatch: legacy journal cannot authorize bootstrap recovery"
        );
        return Ok(RecoveryOutcome::LegacyActive);
    }
    ensure!(
        format.format_version == FORMAT_VERSION,
        "unknown migration journal format"
    );
    let journal = RefCell::new(decode(&bytes, tree)?);
    receipts.check()?;
    ensure!(
        journal.borrow().receipt_store == Inode::of(&receipts.directory.metadata()?),
        "ReceiptStoreMismatch: transaction belongs to another receipt store"
    );
    validate_fence_inventory(&fence, &owner, &journal.borrow())?;
    let key = request_key(
        &journal.borrow().receipt.actor,
        &journal.borrow().receipt.request_id,
    );
    let stored = receipts.read(&key, tree)?;
    validate_journal_receipt(&journal.borrow(), stored.as_ref())?;
    let unpublished = stored.is_none();
    if bootstrap || is_schema_migration(&journal.borrow()) {
        if unpublished {
            ensure!(
                journal.borrow().source_schema == 4 && journal.borrow().target_schema == 5,
                "BootstrapRecoveryMismatch: setup is not a schema-4 to schema-5 migration"
            );
            let now = time::OffsetDateTime::now_utc();
            let loaded = super::loader::load_config_for_schema_under_migration_guard(
                guard,
                guard.canonical_master(),
                4,
                now,
            )
            .map_err(graph_validation_error)?;
            let (snapshot, _) =
                super::policy_revision::capture_coherent_loaded_under_migration_guard(
                    guard, &loaded, 4, now,
                )?;
            ensure!(
                snapshot.revision().to_string() == journal.borrow().receipt.before_revision,
                "BootstrapRecoveryMismatch: setup source inventory changed"
            );
        } else {
            validate_migration_journal_revisions(&fence, &owner, &journal.borrow())?;
        }
    }
    authorize(&fence, &owner, &journal.borrow())?;
    if unpublished {
        verify_inventory(guard, &fence, &owner, &journal.borrow(), true, true, false)?;
        remove_unpublished_setup(tree.root, &fence, &owner, &journal.borrow())?;
        return Ok(RecoveryOutcome::SetupRemoved);
    }
    cleanup_staging_receipts(tree, &fence, &owner, &journal)?;
    let store = open_store(tree, &owner, true)?.context("receipt store missing")?;
    let phase = journal.borrow().phase;
    match phase {
        Phase::Setup => unreachable!("unpublished setup was removed before recovery"),
        Phase::Prepared => {
            if !journal.borrow().rollback_ready {
                verify_inventory(guard, &fence, &owner, &journal.borrow(), true, true, true)?;
                cleanup_rollback_staging(tree, &fence, &owner, &journal)?;
                let mut record = journal.borrow_mut();
                record.phase = Phase::Aborted;
                record.receipt.persistence = Persistence::Aborted;
                record.receipt.failure = None;
                write_journal(&fence, &owner, &record)?;
            } else {
                validate_all_blobs(&fence, &owner, &journal.borrow())?;
                restore_members(guard, &fence, &owner, &journal)?;
            }
        }
        Phase::AbortCleanup => {
            verify_inventory(guard, &fence, &owner, &journal.borrow(), true, true, true)?;
            cleanup_rollback_staging(tree, &fence, &owner, &journal)?;
            let mut record = journal.borrow_mut();
            record.phase = Phase::Aborted;
            record.receipt.persistence = Persistence::Aborted;
            record.receipt.failure = None;
            write_journal(&fence, &owner, &record)?;
        }
        Phase::RollingBack => {
            if !journal.borrow().rollback_ready {
                // Explicit rollback has moved a committed undo into the
                // active fence, but no reverse mutation can have started.
                verify_inventory(guard, &fence, &owner, &journal.borrow(), false, true, true)?;
                cleanup_rollback_staging(tree, &fence, &owner, &journal)?;
                let mut record = journal.borrow_mut();
                record.phase = Phase::Committed;
                record.receipt.persistence = Persistence::Committed;
                record.receipt.failure = None;
                write_journal(&fence, &owner, &record)?;
            } else {
                validate_all_blobs(&fence, &owner, &journal.borrow())?;
                restore_members(guard, &fence, &owner, &journal)?;
            }
        }
        Phase::RollbackCleanup => {
            verify_inventory(guard, &fence, &owner, &journal.borrow(), true, true, true)?;
            cleanup_rollback_staging(tree, &fence, &owner, &journal)?;
            let mut record = journal.borrow_mut();
            record.phase = Phase::RolledBack;
            record.receipt.persistence = Persistence::Committed;
            record.receipt.rollback_restored = true;
            record.receipt.failure = None;
            write_journal(&fence, &owner, &record)?;
        }
        Phase::Committing => {
            validate_all_blobs(&fence, &owner, &journal.borrow())?;
            verify_inventory(guard, &fence, &owner, &journal.borrow(), false, true, true)?;
            cleanup_rollback_staging(tree, &fence, &owner, &journal)?;
            let mut record = journal.borrow_mut();
            record.phase = Phase::Committed;
            record.receipt.persistence = Persistence::Committed;
            record.receipt.failure = None;
            write_journal(&fence, &owner, &record)?;
        }
        Phase::Committed => {
            validate_all_blobs(&fence, &owner, &journal.borrow())?;
            verify_inventory(guard, &fence, &owner, &journal.borrow(), false, true, true)?;
            let mut record = journal.borrow_mut();
            record.receipt.persistence = Persistence::Committed;
            record.receipt.failure = None;
            write_journal(&fence, &owner, &record)?;
        }
        Phase::Aborted | Phase::RolledBack => {
            verify_inventory(guard, &fence, &owner, &journal.borrow(), true, true, true)?;
        }
    }
    if journal.borrow().phase == Phase::Aborted {
        journal.borrow_mut().receipt.activation = ReceiptActivation {
            state: ReceiptActivationState::NotRequired,
            ..ReceiptActivation::default()
        };
    }
    if let Some(stored) = &stored {
        preserve_post_decision_observations(&mut journal.borrow_mut().receipt, &stored.receipt);
    }
    terminalize(tree, &store, &fence, &journal.borrow())?;
    receipts.write(&journal.borrow(), tree)?;
    Ok(RecoveryOutcome::Recovered(Box::new(
        journal.into_inner().receipt,
    )))
}

/// Restore a committed undo only while its complete after inventory still matches.
#[allow(
    dead_code,
    reason = "terminal undo operation retained by the transaction API"
)]
pub(crate) fn rollback(
    guard: &MigrationWriteLock,
    receipts: &ReceiptStore,
    actor: &str,
    request_id: &str,
) -> anyhow::Result<RollbackOutcome> {
    match recover_active(guard, receipts)? {
        RecoveryOutcome::LegacyActive => bail!("legacy migration requires its own recovery"),
        _ => migration_journal::refuse_normal_write(guard.tree_io())?,
    }
    rollback_after_recovery(guard, receipts, actor, request_id)
}

pub(crate) fn rollback_after_recovery(
    guard: &MigrationWriteLock,
    receipts: &ReceiptStore,
    actor: &str,
    request_id: &str,
) -> anyhow::Result<RollbackOutcome> {
    rollback_after_recovery_impl(guard, receipts, actor, request_id, |_, _, _| Ok(()))
}

pub(crate) fn rollback_migration_after_recovery(
    guard: &MigrationWriteLock,
    receipts: &ReceiptStore,
    actor: &str,
    request_id: &str,
    authorize: impl FnOnce(&BaseReceipt) -> anyhow::Result<()>,
) -> anyhow::Result<RollbackOutcome> {
    rollback_after_recovery_impl(
        guard,
        receipts,
        actor,
        request_id,
        |undo, owner, journal| {
            validate_migration_journal_revisions(undo, owner, journal)?;
            authorize(&journal.receipt)
        },
    )
}

fn rollback_after_recovery_impl(
    guard: &MigrationWriteLock,
    receipts: &ReceiptStore,
    actor: &str,
    request_id: &str,
    authorize: impl FnOnce(&File, &Metadata, &Journal) -> anyhow::Result<()>,
) -> anyhow::Result<RollbackOutcome> {
    migration_journal::refuse_normal_write(guard.tree_io())?;
    let tree = guard.tree_io();
    let owner = tree.identity.owner_metadata(tree.root)?;
    let Some(store) = open_store(tree, &owner, false)? else {
        return Ok(RollbackOutcome::NoReceipt);
    };
    let key = request_key(actor, request_id);
    if inspect_at(&store, OsStr::new(&key))?.is_none() {
        return Ok(RollbackOutcome::NoReceipt);
    }
    let undo = private_dir(&store, &key, &owner, false)?;
    let journal = RefCell::new(read_journal(&undo, &owner, tree)?);
    receipts.check()?;
    ensure!(
        journal.borrow().receipt_store == Inode::of(&receipts.directory.metadata()?),
        "ReceiptStoreMismatch: transaction belongs to another receipt store"
    );
    let stored = receipts.read(&key, tree)?;
    validate_journal_receipt(&journal.borrow(), stored.as_ref())?;
    authorize(&undo, &owner, &journal.borrow())?;
    if journal.borrow().phase == Phase::RolledBack {
        return Ok(RollbackOutcome::Restored(Box::new(
            journal.borrow().receipt.clone(),
        )));
    }
    if journal.borrow().phase != Phase::Committed
        || verify_inventory(guard, &undo, &owner, &journal.borrow(), false, true, true).is_err()
    {
        return Ok(RollbackOutcome::RollbackNotApplicable);
    }
    validate_fence_inventory(&undo, &owner, &journal.borrow())?;
    validate_all_blobs(&undo, &owner, &journal.borrow())?;
    rename_noreplace_at(
        &store,
        OsStr::new(&key),
        tree.root,
        OsStr::new(TXN_DIR_NAME),
    )?;
    store.sync_all()?;
    tree.root.sync_all()?;
    {
        let mut record = journal.borrow_mut();
        record.phase = Phase::RollingBack;
        record.rollback_ready = false;
        write_journal(&undo, &owner, &record)?;
    }
    let members = journal.borrow().members.clone();
    let targets = members
        .iter()
        .map(|member| {
            tree.plan_root_file_no_follow(Path::new(&member.path))?
                .materialize()
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    stage_rollback_members(guard, &undo, &owner, &journal, &targets)?;
    restore_members(guard, &undo, &owner, &journal)?;
    if let Some(stored) = &stored {
        preserve_post_decision_observations(&mut journal.borrow_mut().receipt, &stored.receipt);
    }
    terminalize(tree, &store, &undo, &journal.borrow())?;
    receipts.write(&journal.borrow(), tree)?;
    Ok(RollbackOutcome::Restored(Box::new(
        journal.into_inner().receipt,
    )))
}

/// Remove only terminal undo, refusing an active recovery fence.
pub(crate) fn finalize_after_recovery(
    guard: &MigrationWriteLock,
    receipts: &ReceiptStore,
    actor: &str,
    operation_id: &str,
) -> anyhow::Result<FinalizeOutcome> {
    let Some(receipt) =
        lookup_operation_receipt_after_recovery(guard, receipts, actor, operation_id)?
    else {
        return Ok(FinalizeOutcome::NoReceipt);
    };
    ensure!(
        matches!(
            receipt.persistence,
            Persistence::Committed | Persistence::Aborted
        ),
        "cannot finalize a nonterminal transaction"
    );
    let tree = guard.tree_io();
    let owner = tree.identity.owner_metadata(tree.root)?;
    let Some(store) = open_store(tree, &owner, false)? else {
        return Ok(FinalizeOutcome::AlreadyFinalized(Box::new(receipt)));
    };
    let key = request_key(&receipt.actor, &receipt.request_id);
    if inspect_at(&store, OsStr::new(&key))?.is_none()
        && inspect_at(&store, OsStr::new(&format!("retired-{key}")))?.is_none()
    {
        return Ok(FinalizeOutcome::AlreadyFinalized(Box::new(receipt)));
    }
    expire_undo(&store, &key, &owner, tree)?;
    store.sync_all()?;
    Ok(FinalizeOutcome::Finalized(Box::new(receipt)))
}

type PlannedMembers<'g> = (Vec<Member>, Vec<TargetPlan<'g>>, BTreeMap<String, Vec<u8>>);

fn verify_repair_before(tree: TreeIo<'_>, members: &[Member]) -> anyhow::Result<()> {
    for member in members {
        let plan = tree.plan_root_file_no_follow(Path::new(&member.path))?;
        ensure!(
            plan_matches(&plan, member.before.as_ref(), member.before_inode.as_ref())?,
            "RevisionConflict: repair destination changed: {}",
            member.path
        );
    }
    Ok(())
}

fn plan_members<'g>(
    tree: TreeIo<'g>,
    before: Option<&PolicyRevisionInventory>,
    after: &PolicyRevisionInventory,
    owner: &Metadata,
) -> anyhow::Result<PlannedMembers<'g>> {
    plan_members_with_blob_budget(tree, before, after, owner, MAX_BLOB_BYTES)
}

fn plan_members_with_blob_budget<'g>(
    tree: TreeIo<'g>,
    before: Option<&PolicyRevisionInventory>,
    after: &PolicyRevisionInventory,
    owner: &Metadata,
    blob_budget: u64,
) -> anyhow::Result<PlannedMembers<'g>> {
    let old: BTreeMap<_, _> = before
        .into_iter()
        .flat_map(PolicyRevisionInventory::members)
        .map(|member| (member.path(), member))
        .collect();
    let new: BTreeMap<_, _> = after
        .members()
        .iter()
        .map(|member| (member.path(), member))
        .collect();
    let mut paths: Vec<_> = old
        .keys()
        .chain(new.keys())
        .copied()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    paths.sort_by(|left, right| {
        let master = Path::new(tree.identity.canonical_master.file_name().unwrap());
        (*left == master)
            .cmp(&(*right == master))
            .then_with(|| left.cmp(right))
    });
    ensure!(
        paths.len() <= MAX_MEMBERS,
        "policy transaction member budget exceeded"
    );
    let mut members = Vec::new();
    let mut plans = Vec::new();
    let mut blobs = BTreeMap::new();
    let mut blob_total = 0_u64;
    for (index, path) in paths.into_iter().enumerate() {
        let plan = tree.plan_root_file_no_follow(path)?;
        let old_member = old.get(path).copied();
        let new_member = new.get(path).copied();
        if let (Some(old), Some(new)) = (old_member, new_member) {
            ensure!(old.kind() == new.kind(), "member role cannot change");
        }
        let new_bytes = new_member.map(member_bytes).transpose()?;
        let recorded_old_bytes = old_member.map(member_bytes).transpose()?;
        let metadata = plan.original_metadata();
        if before.is_some() {
            ensure!(
                metadata.is_some() == recorded_old_bytes.is_some(),
                "RevisionConflict: member presence changed: {}",
                path.display()
            );
            if let (Some(metadata), Some(bytes)) = (metadata, recorded_old_bytes) {
                ensure!(
                    metadata.len() == bytes.len() as u64,
                    "RevisionConflict: member changed: {}",
                    path.display()
                );
            }
        }
        let before_len = if before.is_some() {
            recorded_old_bytes.map_or(0, |bytes| bytes.len() as u64)
        } else {
            metadata.map_or(0, Metadata::len)
        };
        let after_len = new_bytes.map_or(0, |bytes| bytes.len() as u64);
        let estimated_member_blob_bytes = before_len
            .checked_add(after_len)
            .context("blob budget overflow")?;
        let remaining = blob_budget
            .checked_sub(blob_total)
            .context("policy transaction blob budget exceeded")?;
        ensure!(
            estimated_member_blob_bytes <= remaining,
            "policy transaction blob budget exceeded"
        );

        // The aggregate admission precedes both the descriptor read and the
        // retained before/after copies. Reserve the candidate bytes before
        // reading the live inode so concurrent growth cannot consume their
        // share of the transaction budget.
        let before_read_cap = remaining
            .checked_sub(after_len)
            .context("policy transaction blob budget exceeded")?;
        let live = read_plan(&plan, before_read_cap)?;
        let old_bytes = if before.is_some() {
            recorded_old_bytes
        } else {
            live.as_deref()
        };
        ensure!(
            live.as_deref() == old_bytes,
            "RevisionConflict: member changed: {}",
            path.display()
        );
        ensure!(
            metadata.is_some() == old_bytes.is_some(),
            "RevisionConflict: member presence changed: {}",
            path.display()
        );
        let member_blob_bytes = old_bytes
            .map_or(0, |bytes| bytes.len() as u64)
            .checked_add(after_len)
            .context("blob budget overflow")?;
        ensure!(
            member_blob_bytes <= remaining,
            "policy transaction blob budget exceeded"
        );
        let before_state = old_bytes.map(|bytes| {
            let name = blob_name(index, true);
            blobs.insert(name.clone(), bytes.to_vec());
            FileState::new(bytes, metadata.unwrap(), name)
        });
        let after_state = new_bytes.map(|bytes| {
            let name = blob_name(index, false);
            blobs.insert(name.clone(), bytes.to_vec());
            let mut state = FileState::new(bytes, metadata.unwrap_or(owner), name);
            if metadata.is_none() {
                state.mode = 0o640;
            }
            state
        });
        let operation = match (old_bytes, new_bytes) {
            (None, Some(_)) => Some(MemberOperation::Create),
            (Some(_), None) => Some(MemberOperation::Delete),
            (Some(old), Some(new)) if old != new => Some(MemberOperation::Replace),
            _ => None,
        };
        members.push(Member {
            path: path
                .to_str()
                .context("policy member path must be UTF-8")?
                .to_owned(),
            role: old_member.or(new_member).unwrap().kind().into(),
            operation,
            before: before_state,
            after: after_state,
            before_inode: metadata.map(Inode::of),
            promoted_inode: None,
            restored_inode: None,
            staging: None,
            linked_staging: None,
            rollback_staging: None,
        });
        plans.push(plan);
        blob_total = blob_total
            .checked_add(member_blob_bytes)
            .context("blob budget overflow")?;
    }
    debug_assert_eq!(
        blob_total,
        blobs.values().map(|bytes| bytes.len() as u64).sum::<u64>()
    );
    Ok((members, plans, blobs))
}

fn promote_blob(
    fence: &File,
    owner: &Metadata,
    journal: &RefCell<Journal>,
    index: usize,
    target: &PinnedTarget<'_>,
    state: &FileState,
    restoring: bool,
) -> anyhow::Result<()> {
    let bytes = read_blob(fence, owner, state)?;
    let current = journal.borrow().members[index].clone();
    let expected = if restoring {
        current.after.as_ref()
    } else {
        current.before.as_ref()
    };
    let expected_inode = if restoring {
        current.promoted_inode.as_ref()
    } else {
        current.before_inode.as_ref()
    };
    let before_link = |parent: &File, file: &File, name: &OsStr| -> Result<(), String> {
        (|| -> anyhow::Result<()> {
            verify_target(target, expected, expected_inode)?;
            let staging = pin_linked_staging(target, state, parent, file, name)?;
            let mut record = journal.borrow_mut();
            let inode = Some(Inode::of(&file.metadata()?));
            if restoring {
                record.members[index].restored_inode = inode;
            } else {
                record.members[index].promoted_inode = inode;
            }
            record.members[index].linked_staging = Some(staging);
            write_journal(fence, owner, &record)?;
            fault(FaultPoint::BeforePromotion)?;
            Ok(())
        })()
        .map_err(|error| format!("{error:#}"))
    };
    if target.original.is_none() {
        let mut source = checked_private_file(fence, &state.blob, owner, state.length)?;
        hardened_atomic_create_only_at_with_transaction_boundaries(
            target,
            &mut source,
            state.length,
            AtomicCreateOnlyAtOpts {
                mode: Some(state.mode),
                owner: Some((state.uid, state.gid)),
                validator: None,
                staging: AtomicStaging::JournaledAnonymous {
                    before_link: &before_link,
                    after_link: None,
                },
                #[cfg(test)]
                test_failure: None,
            },
            &atomic_write_boundary,
        )?;
    } else {
        hardened_atomic_write_at_with_transaction_boundaries(
            target,
            &bytes,
            AtomicWriteAtOpts {
                validator: None,
                mode: Some(state.mode),
                owner: Some((state.uid, state.gid)),
                staging: AtomicStaging::JournaledAnonymous {
                    before_link: &before_link,
                    after_link: None,
                },
                ..Default::default()
            },
            &atomic_write_boundary,
        )?;
    }
    cleanup_staging_member(fence, owner, journal, index, target)?;
    fault(FaultPoint::AfterPromotion)?;
    Ok(())
}

fn pin_linked_staging(
    target: &PinnedTarget<'_>,
    state: &FileState,
    parent: &File,
    payload: &File,
    name: &OsStr,
) -> anyhow::Result<LinkedStagingReceipt> {
    let name = name.to_str().context("invalid atomic-write staging name")?;
    ensure!(
        is_write_stage_name(name),
        "invalid atomic-write staging name"
    );
    let parent_meta = parent.metadata()?;
    ensure!(
        same_inode(&parent_meta, &target.parent.metadata()?),
        "atomic-write staging parent changed"
    );
    let payload_meta = payload.metadata()?;
    ensure!(
        payload_meta.is_file()
            && payload_meta.nlink() == 0
            && payload_meta.len() == state.length
            && payload_meta.uid() == state.uid
            && payload_meta.gid() == state.gid
            && payload_meta.mode() & 0o7777 == state.mode,
        "unsafe anonymous atomic-write staging payload"
    );
    ensure!(
        hash(&read_fd(payload, state.length)?) == state.digest,
        "anonymous atomic-write staging content mismatch"
    );
    Ok(LinkedStagingReceipt {
        parent: Inode::of(&parent_meta),
        name: name.to_owned(),
        payload: Inode::of(&payload_meta),
        payload_uid: payload_meta.uid(),
        payload_gid: payload_meta.gid(),
        payload_mode: payload_meta.mode() & 0o7777,
        payload_length: payload_meta.len(),
        payload_digest: state.digest.clone(),
    })
}

#[allow(
    dead_code,
    reason = "private-directory receipt encoder retained for format2 compatibility"
)]
fn pin_staging(
    target: &PinnedTarget<'_>,
    state: &FileState,
    payload: &File,
    staged_path: &Path,
) -> anyhow::Result<StagingReceipt> {
    ensure!(
        staged_path.file_name() == Some(OsStr::new(WRITE_STAGE_PAYLOAD))
            && staged_path.parent().and_then(Path::parent) == target.display().parent(),
        "invalid atomic-write staging path"
    );
    let name = staged_path
        .parent()
        .and_then(Path::file_name)
        .and_then(OsStr::to_str)
        .context("invalid atomic-write staging name")?;
    ensure!(
        is_write_stage_name(name),
        "invalid atomic-write staging name"
    );

    let inspected = inspect_at(&target.parent, OsStr::new(name))?
        .context("atomic-write staging directory disappeared")?;
    let directory = open_at(
        &target.parent,
        OsStr::new(name),
        libc::O_RDONLY | libc::O_DIRECTORY,
        0,
    )?;
    let directory_meta = directory.metadata()?;
    // SAFETY: geteuid has no preconditions and cannot fail.
    let effective_uid = unsafe { libc::geteuid() };
    ensure!(
        same_inode(&inspected.metadata()?, &directory_meta)
            && directory_meta.is_dir()
            && directory_meta.mode() & 0o7777 == 0o700
            && directory_meta.uid() == effective_uid,
        "unsafe atomic-write staging directory"
    );
    let names = directory_names(&directory, 2)?;
    ensure!(
        names.len() == 1 && names[0] == WRITE_STAGE_PAYLOAD,
        "unexpected atomic-write staging member"
    );
    let staged_payload = inspect_at(&directory, OsStr::new(WRITE_STAGE_PAYLOAD))?
        .context("atomic-write staging payload disappeared")?;
    let staged_meta = staged_payload.metadata()?;
    let payload_meta = payload.metadata()?;
    ensure!(
        same_inode(&staged_meta, &payload_meta)
            && payload_meta.is_file()
            && payload_meta.nlink() == 1
            && payload_meta.len() == state.length
            && payload_meta.uid() == state.uid
            && payload_meta.gid() == state.gid
            && payload_meta.mode() & 0o7777 == state.mode,
        "unsafe atomic-write staging payload"
    );
    ensure!(
        hash(&read_fd(payload, state.length)?) == state.digest,
        "atomic-write staging payload content mismatch"
    );
    directory.sync_all()?;
    target.parent.sync_all()?;
    Ok(StagingReceipt {
        parent: Inode::of(&target.parent.metadata()?),
        name: name.to_owned(),
        directory: Inode::of(&directory_meta),
        directory_uid: directory_meta.uid(),
        directory_gid: directory_meta.gid(),
        directory_mode: directory_meta.mode() & 0o7777,
        payload: Inode::of(&payload_meta),
        payload_uid: payload_meta.uid(),
        payload_gid: payload_meta.gid(),
        payload_mode: payload_meta.mode() & 0o7777,
        payload_links: payload_meta.nlink(),
        payload_length: payload_meta.len(),
        payload_digest: state.digest.clone(),
    })
}

fn cleanup_staging_member(
    fence: &File,
    owner: &Metadata,
    journal: &RefCell<Journal>,
    index: usize,
    target: &PinnedTarget<'_>,
) -> anyhow::Result<()> {
    cleanup_linked_staging_member(fence, owner, journal, index, target)?;
    let Some(receipt) = journal.borrow().members[index].staging.clone() else {
        return Ok(());
    };
    ensure!(
        receipt.parent == Inode::of(&target.parent.metadata()?),
        "RecoveryConflict: staging parent was replaced"
    );
    if let Some(inspected) = inspect_at(&target.parent, OsStr::new(&receipt.name))? {
        let directory = open_at(
            &target.parent,
            OsStr::new(&receipt.name),
            libc::O_RDONLY | libc::O_DIRECTORY,
            0,
        )
        .context("RecoveryConflict: owned staging directory was replaced")?;
        let metadata = directory.metadata()?;
        ensure!(
            same_inode(&inspected.metadata()?, &metadata)
                && Inode::of(&metadata) == receipt.directory
                && metadata.is_dir()
                && metadata.uid() == receipt.directory_uid
                && metadata.gid() == receipt.directory_gid
                && metadata.mode() & 0o7777 == receipt.directory_mode,
            "RecoveryConflict: owned staging directory was replaced"
        );
        let names = directory_names(&directory, 2)?;
        ensure!(
            names.is_empty() || (names.len() == 1 && names[0] == WRITE_STAGE_PAYLOAD),
            "RecoveryConflict: foreign staging directory contents"
        );
        if !names.is_empty() {
            let payload = inspect_at(&directory, OsStr::new(WRITE_STAGE_PAYLOAD))?
                .context("RecoveryConflict: owned staging payload disappeared")?;
            let metadata = payload.metadata()?;
            let bytes = read_fd(&payload, receipt.payload_length)
                .context("RecoveryConflict: cannot verify owned staging payload")?;
            ensure!(
                Inode::of(&metadata) == receipt.payload
                    && metadata.is_file()
                    && metadata.nlink() == receipt.payload_links
                    && metadata.len() == receipt.payload_length
                    && metadata.uid() == receipt.payload_uid
                    && metadata.gid() == receipt.payload_gid
                    && metadata.mode() & 0o7777 == receipt.payload_mode
                    && hash(&bytes) == receipt.payload_digest,
                "RecoveryConflict: owned staging payload was replaced"
            );
            let current = inspect_at(&directory, OsStr::new(WRITE_STAGE_PAYLOAD))?
                .context("RecoveryConflict: owned staging payload disappeared")?;
            ensure!(
                same_inode(&current.metadata()?, &metadata),
                "RecoveryConflict: owned staging payload was replaced"
            );
            unlink_at(&directory, OsStr::new(WRITE_STAGE_PAYLOAD))?;
            directory.sync_all()?;
        }
        ensure!(
            directory_names(&directory, 1)?.is_empty(),
            "RecoveryConflict: foreign staging directory contents"
        );
        remove_empty_dir(&target.parent, &receipt.name, &directory)
            .context("RecoveryConflict: cannot remove owned staging directory")?;
    } else {
        target.parent.sync_all()?;
    }
    let mut record = journal.borrow_mut();
    record.members[index].staging = None;
    write_journal(fence, owner, &record)?;
    Ok(())
}

fn cleanup_linked_staging_member(
    fence: &File,
    owner: &Metadata,
    journal: &RefCell<Journal>,
    index: usize,
    target: &PinnedTarget<'_>,
) -> anyhow::Result<()> {
    let Some(receipt) = journal.borrow().members[index].linked_staging.clone() else {
        return Ok(());
    };
    ensure!(
        receipt.parent == Inode::of(&target.parent.metadata()?),
        "RecoveryConflict: linked staging parent was replaced"
    );
    if let Some(inspected) = inspect_at(&target.parent, OsStr::new(&receipt.name))? {
        let metadata = inspected.metadata()?;
        let payload = reopen_inspected(&inspected, libc::O_RDONLY)
            .context("RecoveryConflict: linked staging payload is not a plain file")?;
        let bytes = read_fd(&payload, receipt.payload_length)
            .context("RecoveryConflict: cannot verify linked staging payload")?;
        ensure!(
            Inode::of(&metadata) == receipt.payload
                && metadata.is_file()
                && metadata.nlink() == 1
                && metadata.len() == receipt.payload_length
                && metadata.uid() == receipt.payload_uid
                && metadata.gid() == receipt.payload_gid
                && metadata.mode() & 0o7777 == receipt.payload_mode
                && hash(&bytes) == receipt.payload_digest,
            "RecoveryConflict: linked staging payload was replaced"
        );
        let current = inspect_at(&target.parent, OsStr::new(&receipt.name))?
            .context("RecoveryConflict: linked staging payload disappeared")?;
        ensure!(
            same_inode(&current.metadata()?, &metadata),
            "RecoveryConflict: linked staging payload was replaced"
        );
        unlink_at(&target.parent, OsStr::new(&receipt.name))?;
        target.parent.sync_all()?;
    } else {
        target.parent.sync_all()?;
    }
    let mut record = journal.borrow_mut();
    record.members[index].linked_staging = None;
    write_journal(fence, owner, &record)?;
    Ok(())
}

fn cleanup_staging_receipts(
    tree: TreeIo<'_>,
    fence: &File,
    owner: &Metadata,
    journal: &RefCell<Journal>,
) -> anyhow::Result<()> {
    let members = journal.borrow().members.clone();
    for (index, member) in members.iter().enumerate() {
        if member.staging.is_none() && member.linked_staging.is_none() {
            continue;
        }
        let target = tree
            .plan_root_file_no_follow(Path::new(&member.path))?
            .materialize()?;
        cleanup_staging_member(fence, owner, journal, index, &target)?;
    }
    Ok(())
}

/// Stage each existing before image beneath precisely the parent that will be
/// mutated.  Forward publication staging is intentionally not involved here:
/// these names are retained rollback assets, not write temporaries.
fn stage_rollback_members(
    guard: &MigrationWriteLock,
    fence: &File,
    owner: &Metadata,
    journal: &RefCell<Journal>,
    targets: &[PinnedTarget<'_>],
) -> anyhow::Result<()> {
    ensure!(
        !journal.borrow().rollback_ready,
        "rollback staging is already ready"
    );
    let members = journal.borrow().members.clone();
    let explicit_rollback = journal.borrow().phase == Phase::RollingBack;
    for (index, (member, target)) in members.iter().zip(targets).enumerate() {
        guard.verify_root_linked()?;
        if !matches!(
            member.operation,
            Some(MemberOperation::Replace | MemberOperation::Delete)
        ) {
            continue;
        }
        if member.rollback_staging.is_some() {
            continue;
        }
        let state = member.before.as_ref().context("rollback before image")?;
        let (expected, expected_inode) = if explicit_rollback {
            (member.after.as_ref(), member.promoted_inode.as_ref())
        } else {
            (Some(state), member.before_inode.as_ref())
        };
        verify_target(target, expected, expected_inode)?;
        let bytes = read_blob(fence, owner, state)?;
        let before_link = |parent: &File, payload: &File, name: &OsStr| -> Result<(), String> {
            (|| -> anyhow::Result<()> {
                verify_target(target, expected, expected_inode)?;
                let receipt = pin_rollback_staging(target, state, parent, payload, name, false)?;
                let mut record = journal.borrow_mut();
                ensure!(
                    record.members[index].rollback_staging.is_none(),
                    "duplicate rollback stage"
                );
                record.members[index].rollback_staging = Some(receipt);
                write_journal(fence, owner, &record)?;
                fault(FaultPoint::BeforeRollbackStageLink)?;
                Ok(())
            })()
            .map_err(|error| format!("{error:#}"))
        };
        let after_link = |parent: &File, payload: &File, name: &OsStr| -> Result<(), String> {
            (|| -> anyhow::Result<()> {
                let receipt = pin_rollback_staging(target, state, parent, payload, name, true)?;
                let mut record = journal.borrow_mut();
                let prior = record.members[index]
                    .rollback_staging
                    .as_ref()
                    .context("rollback pre-link receipt disappeared")?;
                ensure!(
                    prior.parent == receipt.parent
                        && prior.name == receipt.name
                        && prior.payload == receipt.payload,
                    "rollback stage changed between callbacks"
                );
                record.members[index].rollback_staging = Some(receipt);
                write_journal(fence, owner, &record)?;
                fault(FaultPoint::AfterRollbackStageLink)?;
                Ok(())
            })()
            .map_err(|error| format!("{error:#}"))
        };
        let staged = stage_journaled_anonymous_at_with_transaction_boundaries(
            target,
            &bytes,
            AnonymousStageOpts {
                validator: None,
                mode: state.mode,
                owner: (state.uid, state.gid),
                before_link: &before_link,
                after_link: Some(&after_link),
            },
            &atomic_write_boundary,
        )?;
        let receipt = journal.borrow().members[index]
            .rollback_staging
            .clone()
            .context("rollback staging receipt disappeared")?;
        ensure!(
            receipt.linked
                && staged.basename == OsStr::new(&receipt.name)
                && Inode::of(&staged.payload.metadata()?) == receipt.payload,
            "rollback staging result differs from its durable receipt"
        );
        // The durable name, not the returned descriptor, remains the authority.
        drop(staged);
    }
    let mut record = journal.borrow_mut();
    ensure!(
        record.members.iter().all(|member| !matches!(
            member.operation,
            Some(MemberOperation::Replace | MemberOperation::Delete)
        ) || member
            .rollback_staging
            .as_ref()
            .is_some_and(|receipt| receipt.linked)),
        "rollback staging did not complete"
    );
    record.rollback_ready = true;
    write_journal(fence, owner, &record)?;
    fault(FaultPoint::RollbackReady)?;
    Ok(())
}

fn pin_rollback_staging(
    target: &PinnedTarget<'_>,
    state: &FileState,
    parent: &File,
    payload: &File,
    name: &OsStr,
    linked: bool,
) -> anyhow::Result<RollbackStagingReceipt> {
    let name = name.to_str().context("invalid rollback staging name")?;
    ensure!(is_write_stage_name(name), "invalid rollback staging name");
    let parent_meta = parent.metadata()?;
    ensure!(
        same_inode(&parent_meta, &target.parent.metadata()?),
        "rollback staging parent changed"
    );
    let payload_meta = payload.metadata()?;
    ensure!(
        payload_meta.is_file()
            && payload_meta.nlink() == if linked { 1 } else { 0 }
            && payload_meta.len() == state.length
            && payload_meta.uid() == state.uid
            && payload_meta.gid() == state.gid
            && payload_meta.mode() & 0o7777 == state.mode
            && hash(&read_fd(payload, state.length)?) == state.digest,
        "unsafe rollback staging payload"
    );
    Ok(RollbackStagingReceipt {
        parent: Inode::of(&parent_meta),
        name: name.to_owned(),
        payload: Inode::of(&payload_meta),
        payload_uid: payload_meta.uid(),
        payload_gid: payload_meta.gid(),
        payload_mode: payload_meta.mode() & 0o7777,
        payload_length: payload_meta.len(),
        payload_digest: state.digest.clone(),
        linked,
    })
}

fn verify_rollback_staging(
    target: &PinnedTarget<'_>,
    state: &FileState,
    receipt: &RollbackStagingReceipt,
) -> anyhow::Result<Option<File>> {
    ensure!(
        receipt.parent == Inode::of(&target.parent.metadata()?),
        "RecoveryConflict: rollback parent was replaced"
    );
    let Some(inspected) = inspect_at(&target.parent, OsStr::new(&receipt.name))? else {
        return Ok(None);
    };
    let payload = reopen_inspected(&inspected, libc::O_RDONLY)
        .context("RecoveryConflict: rollback stage is not a plain file")?;
    let metadata = payload.metadata()?;
    let bytes = read_fd(&payload, receipt.payload_length)?;
    ensure!(
        metadata.is_file()
            && metadata.nlink() == 1
            && Inode::of(&metadata) == receipt.payload
            && metadata.uid() == receipt.payload_uid
            && metadata.gid() == receipt.payload_gid
            && metadata.mode() & 0o7777 == receipt.payload_mode
            && metadata.len() == receipt.payload_length
            && metadata.len() == state.length
            && hash(&bytes) == receipt.payload_digest
            && receipt.payload_digest == state.digest,
        "RecoveryConflict: rollback stage was replaced"
    );
    Ok(Some(payload))
}

fn cleanup_rollback_staging_member(
    fence: &File,
    owner: &Metadata,
    journal: &RefCell<Journal>,
    index: usize,
    target: &PinnedTarget<'_>,
) -> anyhow::Result<()> {
    let Some(receipt) = journal.borrow().members[index].rollback_staging.clone() else {
        return Ok(());
    };
    let state = journal.borrow().members[index]
        .before
        .clone()
        .context("rollback receipt lacks before image")?;
    if verify_rollback_staging(target, &state, &receipt)?.is_some() {
        if receipt.linked {
            let mut record = journal.borrow_mut();
            record.members[index]
                .rollback_staging
                .as_mut()
                .context("rollback receipt disappeared during cleanup")?
                .linked = false;
            write_journal(fence, owner, &record)?;
        }
        fault(FaultPoint::BeforeRollbackStageUnlink)?;
        unlink_at(&target.parent, OsStr::new(&receipt.name))?;
        target.parent.sync_all()?;
        fault(FaultPoint::AfterRollbackStageUnlink)?;
    } else if receipt.linked {
        let member = journal.borrow().members[index].clone();
        ensure!(
            member.restored_inode.as_ref() == Some(&receipt.payload),
            "RecoveryConflict: durable rollback stage disappeared"
        );
        verify_target(target, Some(&state), member.restored_inode.as_ref())?;
    }
    target.parent.sync_all()?;
    let mut record = journal.borrow_mut();
    record.members[index].rollback_staging = None;
    write_journal(fence, owner, &record)
}

fn cleanup_rollback_staging(
    tree: TreeIo<'_>,
    fence: &File,
    owner: &Metadata,
    journal: &RefCell<Journal>,
) -> anyhow::Result<()> {
    let members = journal.borrow().members.clone();
    for (index, member) in members.iter().enumerate() {
        if member.rollback_staging.is_none() {
            continue;
        }
        let target = tree
            .plan_root_file_no_follow(Path::new(&member.path))?
            .materialize()?;
        cleanup_rollback_staging_member(fence, owner, journal, index, &target)?;
    }
    let mut record = journal.borrow_mut();
    record.rollback_ready = false;
    write_journal(fence, owner, &record)
}

fn is_write_stage_name(name: &str) -> bool {
    name.strip_prefix(WRITE_STAGE_PREFIX).is_some_and(|suffix| {
        suffix.len() == 32
            && suffix
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn restore_members(
    guard: &MigrationWriteLock,
    fence: &File,
    owner: &Metadata,
    journal: &RefCell<Journal>,
) -> anyhow::Result<()> {
    let tree = guard.tree_io();
    let members = journal.borrow().members.clone();
    let mut plans = Vec::with_capacity(members.len());
    for member in &members {
        let plan = tree.plan_root_file_no_follow(Path::new(&member.path))?;
        let before = plan_matches(
            &plan,
            member.before.as_ref(),
            member
                .restored_inode
                .as_ref()
                .or(member.before_inode.as_ref()),
        )?;
        let after = plan_matches(
            &plan,
            member.after.as_ref(),
            if member.operation.is_none() {
                member.before_inode.as_ref()
            } else {
                member.promoted_inode.as_ref()
            },
        )?;
        ensure!(
            before || after,
            "RecoveryConflict: foreign member {}",
            member.path
        );
        plans.push((plan, before));
    }
    // Every member is checked before restoring any member. Each atomic writer
    // checks the retained inode and bytes again immediately before its rename.
    for (index, ((plan, before), member)) in plans.into_iter().zip(&members).enumerate() {
        if before {
            continue;
        }
        let target = plan.materialize()?;
        if let Some(state) = &member.before {
            restore_rollback_stage(fence, owner, journal, index, &target, state)?;
        } else {
            verify_target(
                &target,
                member.after.as_ref(),
                member.promoted_inode.as_ref(),
            )?;
            fault(FaultPoint::BeforePromotion)?;
            target.unlink()?;
            fault(FaultPoint::AfterPromotion)?;
        }
    }
    verify_inventory(guard, fence, owner, &journal.borrow(), true, true, true)?;
    let mut record = journal.borrow_mut();
    let explicit = record.phase == Phase::RollingBack;
    record.phase = if explicit {
        Phase::RollbackCleanup
    } else {
        Phase::AbortCleanup
    };
    record.receipt.persistence = if explicit {
        Persistence::Committed
    } else {
        Persistence::Aborted
    };
    record.receipt.rollback_restored = explicit;
    record.receipt.failure = None;
    record.rollback_ready = false;
    write_journal(fence, owner, &record)?;
    drop(record);
    cleanup_rollback_staging(tree, fence, owner, journal)?;
    let mut record = journal.borrow_mut();
    record.phase = if explicit {
        Phase::RolledBack
    } else {
        Phase::Aborted
    };
    write_journal(fence, owner, &record)?;
    Ok(())
}

/// Restore only from the durable rollback copy.  No anonymous write is opened
/// on this path: recovery either consumes the exact staged inode or observes
/// the already-restored inode recorded before its rename.
fn restore_rollback_stage(
    fence: &File,
    owner: &Metadata,
    journal: &RefCell<Journal>,
    index: usize,
    target: &PinnedTarget<'_>,
    state: &FileState,
) -> anyhow::Result<()> {
    let member = journal.borrow().members[index].clone();
    let receipt = member
        .rollback_staging
        .as_ref()
        .context("RecoveryConflict: rollback stage is missing")?;
    let Some(payload) = verify_rollback_staging(target, state, receipt)? else {
        ensure!(
            member.restored_inode.is_some(),
            "RecoveryConflict: rollback stage disappeared before restore"
        );
        verify_target(target, Some(state), member.restored_inode.as_ref())?;
        let mut record = journal.borrow_mut();
        record.members[index].rollback_staging = None;
        write_journal(fence, owner, &record)?;
        return Ok(());
    };
    verify_target(
        target,
        member.after.as_ref(),
        member.promoted_inode.as_ref(),
    )?;
    let restored = Inode::of(&payload.metadata()?);
    {
        let mut record = journal.borrow_mut();
        // This receipt is the redo marker for a death after the rename.  It
        // deliberately precedes the rename and never reuses a pre-stage inode.
        record.members[index].restored_inode = Some(restored);
        write_journal(fence, owner, &record)?;
    }
    fault(FaultPoint::BeforeRollbackRestoreRename)?;
    let master = target.master.map(|_| payload.try_clone()).transpose()?;
    rename_at(
        &target.parent,
        OsStr::new(&receipt.name),
        &target.parent,
        &target.name,
    )?;
    target.record_promotion(payload, master);
    fault(FaultPoint::AfterRollbackRestoreRename)?;
    fault(FaultPoint::BeforeRollbackRestoreParentFsync)?;
    target.parent.sync_all()?;
    fault(FaultPoint::AfterRollbackRestoreParentFsync)?;
    let mut record = journal.borrow_mut();
    record.members[index].rollback_staging = None;
    write_journal(fence, owner, &record)
}

fn verify_inventory(
    guard: &MigrationWriteLock,
    fence: &File,
    owner: &Metadata,
    journal: &Journal,
    before: bool,
    check_inode: bool,
    validate_graph: bool,
) -> anyhow::Result<()> {
    let tree = guard.tree_io();
    let mut inventory = Vec::new();
    for member in &journal.members {
        let plan = tree.plan_root_file_no_follow(Path::new(&member.path))?;
        let state = if before {
            member.before.as_ref()
        } else {
            member.after.as_ref()
        };
        let inode = if before {
            member
                .restored_inode
                .as_ref()
                .or(member.before_inode.as_ref())
        } else if member.operation.is_none() {
            member.before_inode.as_ref()
        } else {
            member.promoted_inode.as_ref()
        };
        ensure!(
            plan_matches(&plan, state, if check_inode { inode } else { None })?,
            "RecoveryConflict: member drift: {}",
            member.path
        );
        if journal.revision_scope == RevisionScope::PolicyTreeV1 {
            if let Some(bytes) = read_plan(&plan, MAX_BLOB_BYTES)? {
                inventory.push(PolicyRevisionMember::present(
                    member.role.into(),
                    PathBuf::from(&member.path),
                    bytes,
                )?);
            }
        }
    }
    let observed = match journal.revision_scope {
        RevisionScope::PolicyTreeV1 => {
            if validate_graph {
                verify_effective_policy_graph(guard, fence, owner, journal, before)?;
            }
            PolicyRevisionInventory::new(inventory)?
                .revision()
                .to_string()
        }
        RevisionScope::RepairDestinationSetV1 => repair_digest(&journal.members, before),
    };
    let expected = if before {
        &journal.receipt.before_revision
    } else {
        &journal.receipt.after_revision
    };
    ensure!(
        observed == *expected,
        "RevisionConflict: transaction inventory changed"
    );
    Ok(())
}

fn verify_effective_policy_graph(
    guard: &MigrationWriteLock,
    fence: &File,
    owner: &Metadata,
    journal: &Journal,
    before: bool,
) -> anyhow::Result<()> {
    let tree = guard.tree_io();
    let mut toml_overlay = super::loader::LoaderOverlay::default();
    let mut pack_overlay = super::custom_list::PackOverlay::default();
    let mut expected_toml = BTreeSet::new();
    let mut expected_packs = BTreeSet::new();

    for member in &journal.members {
        let state = if before {
            member.before.as_ref()
        } else {
            member.after.as_ref()
        };
        match member.role {
            MemberRole::Master | MemberRole::Include => {
                let plan = tree.plan_root_file_no_follow(Path::new(&member.path))?;
                if let Some(state) = state {
                    let bytes = read_blob(fence, owner, state)?;
                    let text = String::from_utf8(bytes)
                        .with_context(|| format!("policy TOML is not UTF-8: {}", member.path))?;
                    toml_overlay.stage_plan_reachable_only(&plan, text)?;
                    expected_toml.insert(tree.identity.root.join(&member.path));
                } else if !plan.is_new() {
                    toml_overlay.omit_plan(&plan)?;
                }
            }
            MemberRole::Pack => {
                if let Some(receipt) = &member.rollback_staging {
                    let target = tree
                        .plan_root_file_no_follow(Path::new(&member.path))?
                        .materialize()?;
                    let rollback = member
                        .before
                        .as_ref()
                        .context("pack rollback receipt lacks before image")?;
                    if verify_rollback_staging(&target, rollback, receipt)?.is_some() {
                        pack_overlay
                            .ignore_verified_stage(PathBuf::from("packs").join(&receipt.name))?;
                    }
                }
                let id = pack_id_for_member(&member.path)?;
                if let Some(state) = state {
                    pack_overlay.stage(id.clone(), read_blob(fence, owner, state)?);
                    expected_packs.insert(id);
                } else {
                    pack_overlay.omit(id);
                }
            }
        }
    }

    let schema = u32::try_from(if before {
        journal.source_schema
    } else {
        journal.target_schema
    })
    .context("policy schema does not fit u32")?;
    let now = time::OffsetDateTime::now_utc();
    let (actual_toml, actual_packs): (BTreeSet<_>, BTreeSet<_>) = match schema {
        3 | 4 => {
            let loaded = super::loader::load_config_with_policy_overlays_under_migration_guard(
                guard,
                guard.canonical_master(),
                schema,
                now,
                Some(&toml_overlay),
                Some(&pack_overlay),
            )
            .map_err(graph_validation_error)?;
            (
                loaded.files_loaded.into_iter().collect(),
                loaded
                    .config
                    .custom_lists
                    .into_iter()
                    .map(|list| list.id)
                    .collect(),
            )
        }
        super::schema::TARGET_SCHEMA_VERSION_V5 => {
            let loaded = super::loader::load_merged_v5_with_policy_overlays_under_migration_guard(
                guard,
                guard.canonical_master(),
                now,
                Some(&toml_overlay),
                Some(&pack_overlay),
            )
            .map_err(graph_validation_error)?;
            let mut warnings = super::schema::validator::AuditWarnings::emitting();
            let secrets = super::secrets::load_secrets_under_tree(tree).ok();
            super::target_v5::validate_v5_collect_with_bodies(
                &loaded.config,
                &loaded.pack_bodies,
                now,
                &mut warnings,
                secrets.as_ref(),
            )
            .context("RevisionConflict: effective schema-5 policy graph no longer validates")?;
            // Compilation is admitted by the caller before prepare and bound
            // to this inventory by PolicyRevisionTransition. Recovery repeats
            // graph validation here; the daemon's next capture compiles with
            // its shared admission before any recovered policy is activated.
            (
                loaded.files_loaded.into_iter().collect(),
                loaded
                    .config
                    .custom_lists
                    .into_iter()
                    .map(|list| list.id)
                    .collect(),
            )
        }
        _ => bail!("unsupported policy schema"),
    };
    ensure!(
        actual_toml == expected_toml && actual_packs == expected_packs,
        "RevisionConflict: effective policy membership changed"
    );
    Ok(())
}

fn graph_validation_error(errors: Vec<super::error::ConfigError>) -> anyhow::Error {
    anyhow::anyhow!(
        "RevisionConflict: effective policy graph no longer validates: {}",
        errors
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("; ")
    )
}

fn pack_id_for_member(path: &str) -> anyhow::Result<super::schema::Id> {
    let path = Path::new(path);
    let mut components = path.components();
    ensure!(
        components.next() == Some(Component::Normal(OsStr::new("packs")))
            && components.next().is_some()
            && components.next().is_none(),
        "invalid pack member path"
    );
    let id = path
        .file_stem()
        .and_then(OsStr::to_str)
        .context("pack member ID is not UTF-8")?;
    super::schema::Id::new(id).map_err(Into::into)
}

fn plan_matches(
    plan: &TargetPlan<'_>,
    state: Option<&FileState>,
    inode: Option<&Inode>,
) -> anyhow::Result<bool> {
    let bytes = match plan
        .read_original_capped(state.map_or(MAX_BLOB_BYTES, |state| state.length))
        .with_context(|| {
            format!(
                "RecoveryConflict: cannot snapshot {}",
                plan.display().display()
            )
        })? {
        CappedRead::Missing => None,
        CappedRead::Contents(bytes) => Some(bytes),
        // Recovery compares both images; a longer live image can match the other one.
        CappedRead::LimitExceeded { .. } => return Ok(false),
    };
    Ok(match (state, plan.original_metadata(), bytes) {
        (None, None, None) => true,
        (Some(state), Some(metadata), Some(bytes)) => {
            state.matches(&bytes, metadata)
                && inode.is_some_and(|inode| *inode == Inode::of(metadata))
        }
        _ => false,
    })
}

fn verify_target(
    target: &PinnedTarget<'_>,
    state: Option<&FileState>,
    inode: Option<&Inode>,
) -> anyhow::Result<()> {
    target.check_original()?;
    match (state, target.original.as_ref()) {
        (None, None) => Ok(()),
        (Some(state), Some(file)) => {
            let metadata = file.metadata()?;
            let bytes = read_fd(file, state.length)
                .context("RecoveryConflict: retained member changed size")?;
            ensure!(
                state.matches(&bytes, &metadata)
                    && inode.is_some_and(|inode| *inode == Inode::of(&metadata)),
                "RecoveryConflict: retained target drift: {}",
                target.display().display()
            );
            Ok(())
        }
        _ => bail!("RecoveryConflict: target presence changed"),
    }
}

fn lookup_in(
    store: &File,
    owner: &Metadata,
    tree: TreeIo<'_>,
    receipts: &ReceiptStore,
    key: &str,
    fingerprint: Option<&str>,
) -> anyhow::Result<Option<BaseReceipt>> {
    let stored = receipts.read(key, tree)?;
    if stored.as_ref().is_some_and(|record| {
        matches!(
            record.receipt.persistence,
            Persistence::Committed | Persistence::Aborted
        ) && receipt_completion_settled(&record.receipt)
            && unix_seconds().is_ok_and(|now| now >= record.retain_until)
    }) {
        if fingerprint.is_some() {
            bail!("IdempotencyExpired: read/plan again and use a new request ID");
        }
        return Ok(None);
    }
    if let (Some(record), Some(fingerprint)) = (&stored, fingerprint) {
        ensure!(
            record.fingerprint == fingerprint,
            "IdempotencyConflict: request identity reused with different payload or preconditions"
        );
    }
    if inspect_at(store, OsStr::new(key))?.is_none() {
        ensure!(
            stored.as_ref().is_none_or(|record| matches!(
                record.receipt.persistence,
                Persistence::Committed | Persistence::Aborted
            )),
            "RecoveryConflict: pending receipt has no transaction intent"
        );
        return Ok(stored.map(|record| record.receipt));
    }
    let dir = private_dir(store, key, owner, false)?;
    let mut journal = read_journal(&dir, owner, tree)?;
    ensure!(
        journal.receipt_store == Inode::of(&receipts.directory.metadata()?),
        "ReceiptStoreMismatch: transaction belongs to another receipt store"
    );
    ensure!(
        request_key(&journal.receipt.actor, &journal.receipt.request_id) == key,
        "receipt key mismatch"
    );
    if let Some(fingerprint) = fingerprint {
        ensure!(
            journal.request_fingerprint == fingerprint,
            "IdempotencyConflict: request identity reused with different payload or preconditions"
        );
    }
    ensure!(
        matches!(
            journal.phase,
            Phase::Committed | Phase::Aborted | Phase::RolledBack
        ),
        "receipt is not terminal"
    );
    validate_terminal_receipt(&dir, owner, &journal, stored.as_ref())?;
    // Re-establish the move's durability after a process died between rename and
    // either directory fsync. This never rewrites the live policy.
    dir.sync_all()?;
    store.sync_all()?;
    tree.root.sync_all()?;
    journal.receipt.persistence = if journal.phase == Phase::Aborted {
        Persistence::Aborted
    } else {
        Persistence::Committed
    };
    if journal.phase == Phase::Aborted {
        journal.receipt.activation = ReceiptActivation {
            state: ReceiptActivationState::NotRequired,
            ..ReceiptActivation::default()
        };
    }
    journal.receipt.failure = None;
    // The terminal journal is authoritative for the transaction decision,
    // while the receipt ledger owns observations made after that decision.
    // Replaying an undo journal must not erase a queued or completed
    // activation, nor make an already delivered audit event pending again.
    if let Some(stored) = &stored {
        preserve_post_decision_observations(&mut journal.receipt, &stored.receipt);
    }
    if stored
        .as_ref()
        .is_none_or(|stored| stored.receipt != journal.receipt)
    {
        receipts.write(&journal, tree)?;
    }
    Ok(Some(journal.receipt))
}

fn validate_terminal_receipt(
    dir: &File,
    owner: &Metadata,
    journal: &Journal,
    stored: Option<&StoredReceipt>,
) -> anyhow::Result<()> {
    validate_journal_receipt(journal, stored)?;
    if is_schema_migration(journal) {
        ensure!(
            stored.is_some(),
            "BootstrapRecoveryMismatch: terminal migration lacks a durable receipt"
        );
        validate_migration_journal_revisions(dir, owner, journal)?;
    }
    Ok(())
}

fn is_schema_migration(journal: &Journal) -> bool {
    journal
        .receipt
        .operation_manifest
        .as_ref()
        .is_some_and(|manifest| {
            manifest.get("kind").and_then(serde_json::Value::as_str) == Some("v4_to_v5_migration")
        })
}

fn validate_journal_receipt(
    journal: &Journal,
    stored: Option<&StoredReceipt>,
) -> anyhow::Result<()> {
    if let Some(stored) = stored {
        // Only decision/observation fields may advance after the prepared
        // receipt is durable. A retained journal cannot approve a new intent.
        let mut immutable = journal.receipt.clone();
        immutable.persistence = stored.receipt.persistence;
        immutable.rollback_restored = stored.receipt.rollback_restored;
        immutable.audit_pending = stored.receipt.audit_pending;
        immutable.audit_activation = stored.receipt.audit_activation;
        immutable.activation.clone_from(&stored.receipt.activation);
        immutable.failure.clone_from(&stored.receipt.failure);
        ensure!(
            immutable == stored.receipt && journal.request_fingerprint == stored.fingerprint,
            "BootstrapRecoveryMismatch: journal intent differs from its durable receipt"
        );
        let decision_advances = match stored.receipt.persistence {
            Persistence::Prepared | Persistence::DurabilityUncertain => {
                journal.phase != Phase::Setup
            }
            Persistence::Committed => matches!(
                journal.phase,
                Phase::Committing
                    | Phase::Committed
                    | Phase::RollingBack
                    | Phase::RollbackCleanup
                    | Phase::RolledBack
            ),
            Persistence::Aborted => journal.phase == Phase::Aborted,
        };
        ensure!(
            decision_advances
                && (!stored.receipt.rollback_restored
                    || (journal.phase == Phase::RolledBack && journal.receipt.rollback_restored)),
            "BootstrapRecoveryMismatch: journal regresses the durable transaction decision"
        );
    } else {
        ensure!(
            matches!(journal.phase, Phase::Setup | Phase::Prepared)
                && journal.receipt.persistence == Persistence::Prepared
                && !journal.rollback_ready
                && journal
                    .members
                    .iter()
                    .all(|member| member.promoted_inode.is_none()
                        && member.restored_inode.is_none()
                        && member.staging.is_none()
                        && member.linked_staging.is_none()
                        && member.rollback_staging.is_none()),
            "BootstrapRecoveryMismatch: published intent lacks a durable receipt"
        );
    }
    Ok(())
}

fn preserve_post_decision_observations(recovered: &mut BaseReceipt, stored: &BaseReceipt) {
    // The journal owns the persistence decision, never newer activation or
    // audit observations. Abort alone makes activation unnecessary.
    if recovered.persistence == Persistence::Committed {
        recovered.activation.clone_from(&stored.activation);
    }
    recovered.audit_pending = stored.audit_pending;
    recovered.audit_activation = stored.audit_activation;
}

fn reconcile_terminal_receipts(
    tree: TreeIo<'_>,
    receipts: &ReceiptStore,
    owner: &Metadata,
) -> anyhow::Result<()> {
    receipts.check_for_tree(tree)?;
    let undo = open_store(tree, owner, false)?;
    for name in directory_names(&receipts.directory, MAX_RECEIPTS * 2)? {
        if name.ends_with(".next") {
            continue;
        }
        let key = name
            .strip_suffix(".json")
            .context("unexpected receipt store member")?;
        ensure!(is_hash(key), "invalid receipt key");
        let record = receipts.read(key, tree)?.context("receipt disappeared")?;
        if matches!(
            record.receipt.persistence,
            Persistence::Prepared | Persistence::DurabilityUncertain
        ) {
            let undo = undo
                .as_ref()
                .context("RecoveryConflict: pending receipt has no undo store")?;
            ensure!(
                inspect_at(undo, OsStr::new(key))?.is_some(),
                "RecoveryConflict: pending receipt has no transaction intent"
            );
            // The decision is durable in the same-filesystem terminal undo. A
            // death before its data-directory ledger write is reconciled here.
            lookup_in(undo, owner, tree, receipts, key, None)?;
        }
    }
    Ok(())
}

fn terminalize(
    tree: TreeIo<'_>,
    store: &File,
    fence: &File,
    journal: &Journal,
) -> anyhow::Result<()> {
    let linked_store = open_store(tree, &store.metadata()?, false)?
        .context("terminal undo namespace disappeared")?;
    ensure!(
        same_inode(&linked_store.metadata()?, &store.metadata()?),
        "terminal undo namespace was replaced"
    );
    fence.sync_all()?;
    let current =
        inspect_at(tree.root, OsStr::new(TXN_DIR_NAME))?.context("active fence disappeared")?;
    ensure!(
        same_inode(&current.metadata()?, &fence.metadata()?),
        "active fence identity changed"
    );
    let key = request_key(&journal.receipt.actor, &journal.receipt.request_id);
    fault(FaultPoint::BeforeTerminalRename)?;
    rename_noreplace_at(tree.root, OsStr::new(TXN_DIR_NAME), store, OsStr::new(&key))?;
    fault(FaultPoint::AfterTerminalRename)?;
    store.sync_all()?;
    fault(FaultPoint::RootFsync)?;
    tree.root.sync_all()?;
    Ok(())
}

fn validate_request(request: &TransactionRequest) -> anyhow::Result<()> {
    validate_request_fields(
        [
            &request.actor,
            &request.request_id,
            &request.origin,
            &request.operation,
        ],
        &request.payload,
        request.source_schema,
        request.target_schema,
    )
}

fn validate_request_fields(
    identity: [&str; 4],
    payload: &[u8],
    source_schema: u64,
    target_schema: u64,
) -> anyhow::Result<()> {
    for value in identity {
        ensure!(
            !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control),
            "invalid transaction identity"
        );
    }
    ensure!(
        payload.len() <= 64 * 1024,
        "request payload budget exceeded"
    );
    ensure!(
        (3..=5).contains(&source_schema) && (3..=5).contains(&target_schema),
        "unsupported policy schema"
    );
    Ok(())
}

fn validate_inventory(inventory: &PolicyRevisionInventory, tree: TreeIo<'_>) -> anyhow::Result<()> {
    ensure!(
        !inventory.members().is_empty() && inventory.members().len() <= MAX_MEMBERS,
        "invalid inventory size"
    );
    let mut masters = 0;
    let mut total = 0_u64;
    let mut toml_total = 0_u64;
    for member in inventory.members() {
        validate_member_path(member.path(), member.kind().into(), &master_name(tree)?)?;
        if member.kind() == PolicyMemberKind::Master {
            masters += 1;
        }
        let len = member_bytes(member)?.len() as u64;
        total = total
            .checked_add(len)
            .context("inventory byte budget overflow")?;
        if member.kind() != PolicyMemberKind::Pack {
            toml_total += len;
        }
    }
    ensure!(masters == 1, "inventory requires exactly one master");
    ensure!(
        total <= MAX_BLOB_BYTES && toml_total <= super::loader::MAX_TOTAL_BYTES,
        "inventory byte budget exceeded"
    );
    Ok(())
}

fn validate_member_path(path: &Path, role: MemberRole, master: &str) -> anyhow::Result<()> {
    let text = path.to_str().context("policy member path must be UTF-8")?;
    ensure!(
        !text.is_empty() && text.len() <= 4096 && !text.contains('\0'),
        "invalid policy member path"
    );
    ensure!(
        path.components()
            .all(|part| matches!(part, Component::Normal(_)))
            && !text
                .split('/')
                .any(|part| part.is_empty() || part == "." || part == ".."),
        "unsafe policy member path"
    );
    ensure!(
        !path.components().any(
            |part| super::write_lock::reserved_component(part.as_os_str())
                || part.as_os_str() == STORE_DIR_NAME
                || part.as_os_str() == RECEIPT_DIR
        ),
        "reserved policy member path"
    );
    match role {
        MemberRole::Master => ensure!(text == master, "master path mismatch"),
        MemberRole::Include => ensure!(
            text != master && !text.starts_with("packs/"),
            "invalid include path"
        ),
        MemberRole::Pack => {
            let id = text
                .strip_prefix("packs/")
                .and_then(|name| name.strip_suffix(".txt"))
                .context("pack must be packs/<id>.txt")?;
            ensure!(!id.contains('/'), "pack directory must be flat");
            super::schema::Id::new(id).context("invalid pack ID")?;
        }
    }
    Ok(())
}

fn validate_flat_packs(tree: TreeIo<'_>) -> anyhow::Result<()> {
    tree.plan_root_file_no_follow(Path::new("packs/.transaction-probe"))?;
    if let Some(directory) = tree.directory_from(&tree.master_key(), Path::new("packs"))? {
        let mut count = 0;
        super::tree_io::for_each_dir_name(&directory, |name| {
            count += 1;
            ensure!(count <= MAX_MEMBERS, "pack inventory budget exceeded");
            let path = Path::new("packs").join(name);
            validate_member_path(&path, MemberRole::Pack, &master_name(tree)?)?;
            ensure!(
                !tree.plan_root_file_no_follow(&path)?.is_new(),
                "pack disappeared during inventory"
            );
            Ok(())
        })?;
    }
    Ok(())
}

fn member_bytes(member: &PolicyRevisionMember) -> anyhow::Result<&[u8]> {
    match member.state() {
        PolicyMemberState::Present(bytes) => Ok(bytes),
        PolicyMemberState::Absent => {
            bail!("live and candidate inventories contain present files only")
        }
    }
}

fn request_fingerprint(
    request: &TransactionRequest,
    before: &PolicyRevisionInventory,
    after: &PolicyRevisionInventory,
) -> anyhow::Result<String> {
    let mut digest = Sha256::new();
    digest.update(b"purge-warden.policy-plan\0\x01");
    let before_revision = before.revision();
    let after_revision = after.revision();
    for bytes in [
        request.actor.as_bytes(),
        request.request_id.as_bytes(),
        request.origin.as_bytes(),
        request.operation.as_bytes(),
        &request.payload,
        request.expected_revision.as_bytes(),
        before_revision.as_bytes(),
        after_revision.as_bytes(),
    ] {
        digest.update((bytes.len() as u64).to_be_bytes());
        digest.update(bytes);
    }
    digest.update(request.source_schema.to_be_bytes());
    digest.update(request.target_schema.to_be_bytes());
    Ok(hex(&digest.finalize()))
}

fn repair_digest(members: &[Member], before: bool) -> String {
    let mut digest = Sha256::new();
    digest.update(b"purge-warden.repair-destinations\0\x01");
    digest.update((members.len() as u64).to_be_bytes());
    let mut ordered: Vec<_> = members.iter().collect();
    ordered.sort_by(|left, right| left.path.cmp(&right.path));
    for member in ordered {
        digest.update([match member.role {
            MemberRole::Master => 1,
            MemberRole::Include => 2,
            MemberRole::Pack => 3,
        }]);
        digest.update((member.path.len() as u64).to_be_bytes());
        digest.update(member.path.as_bytes());
        if let Some(state) = if before {
            &member.before
        } else {
            &member.after
        } {
            digest.update([1]);
            digest.update(state.length.to_be_bytes());
            digest.update(state.digest.as_bytes());
        } else {
            digest.update([0]);
        }
    }
    hex(&digest.finalize())
}

fn repair_request_fingerprint(
    request: &RepairRequest,
    after: &RepairDestinationRevision,
) -> String {
    let mut digest = Sha256::new();
    digest.update(b"purge-warden.repair-plan\0\x01");
    for bytes in [
        request.actor.as_bytes(),
        request.request_id.as_bytes(),
        request.origin.as_bytes(),
        request.operation.as_bytes(),
        &request.payload,
        request.expected_destinations.0.as_bytes(),
        after.0.as_bytes(),
    ] {
        digest.update((bytes.len() as u64).to_be_bytes());
        digest.update(bytes);
    }
    digest.update(request.source_schema.to_be_bytes());
    digest.update(request.target_schema.to_be_bytes());
    hex(&digest.finalize())
}

fn request_key(actor: &str, request_id: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(b"purge-warden.policy-request\0\x01");
    for value in [actor, request_id] {
        digest.update((value.len() as u64).to_be_bytes());
        digest.update(value.as_bytes());
    }
    hex(&digest.finalize())
}

fn master_namespace(canonical_master: &Path) -> String {
    let mut digest = Sha256::new();
    digest.update(b"purge-warden.policy-master\0\x01");
    let bytes = canonical_master.as_os_str().as_bytes();
    digest.update((bytes.len() as u64).to_be_bytes());
    digest.update(bytes);
    hex(&digest.finalize())
}

fn master_name(tree: TreeIo<'_>) -> anyhow::Result<String> {
    Ok(tree
        .identity
        .canonical_master
        .file_name()
        .and_then(OsStr::to_str)
        .context("invalid master filename")?
        .to_owned())
}

fn blob_name(index: usize, before: bool) -> String {
    format!("{}{:04}.blob", if before { 'b' } else { 'a' }, index)
}
fn hash(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn is_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_operation_manifest(manifest: Option<&serde_json::Value>) -> anyhow::Result<()> {
    let Some(manifest) = manifest else {
        return Ok(());
    };
    let object = manifest
        .as_object()
        .context("operation_manifest must be a JSON object")?;
    ensure!(
        object
            .get("manifest_version")
            .and_then(serde_json::Value::as_u64)
            .is_some_and(|version| version != 0),
        "operation_manifest requires a positive integer manifest_version"
    );
    ensure!(
        serde_json::to_vec(manifest)?.len() as u64 <= MAX_MANIFEST_BYTES,
        "operation_manifest byte budget exceeded"
    );
    Ok(())
}

fn read_plan(plan: &TargetPlan<'_>, cap: u64) -> anyhow::Result<Option<Vec<u8>>> {
    match plan.read_original_capped(cap)? {
        CappedRead::Missing => Ok(None),
        CappedRead::Contents(bytes) => Ok(Some(bytes)),
        CappedRead::LimitExceeded { .. } => bail!("policy member exceeds byte budget"),
    }
}

fn read_fd(file: &File, cap: u64) -> anyhow::Result<Vec<u8>> {
    ensure!(file.metadata()?.len() <= cap, "file exceeds byte budget");
    let mut bytes = Vec::new();
    reopen_inspected(file, libc::O_RDONLY)?
        .take(cap.saturating_add(1))
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() as u64 <= cap, "file exceeds byte budget");
    Ok(bytes)
}

fn open_store(tree: TreeIo<'_>, owner: &Metadata, create: bool) -> anyhow::Result<Option<File>> {
    if !create && inspect_at(tree.root, OsStr::new(STORE_DIR_NAME))?.is_none() {
        return Ok(None);
    }
    let base = private_dir(tree.root, STORE_DIR_NAME, owner, create)?;
    let namespace = master_namespace(&tree.identity.canonical_master);
    if !create && inspect_at(&base, OsStr::new(&namespace))?.is_none() {
        return Ok(None);
    }
    private_dir(&base, &namespace, owner, create).map(Some)
}

fn private_dir(parent: &File, name: &str, owner: &Metadata, create: bool) -> anyhow::Result<File> {
    if create {
        let name_c = CString::new(name)?;
        // SAFETY: parent is an open directory and name_c is a NUL-terminated basename.
        let result = unsafe { libc::mkdirat(parent.as_raw_fd(), name_c.as_ptr(), 0o700) };
        if result == 0 {
            let file = open_at(
                parent,
                OsStr::new(name),
                libc::O_RDONLY | libc::O_DIRECTORY,
                0,
            )?;
            preserve_owner(&file, owner)?;
            file.set_permissions(Permissions::from_mode(0o700))?;
            file.sync_all()?;
            parent.sync_all()?;
        } else if io::Error::last_os_error().kind() != io::ErrorKind::AlreadyExists {
            return Err(io::Error::last_os_error().into());
        }
    }
    let dir = open_at(
        parent,
        OsStr::new(name),
        libc::O_RDONLY | libc::O_DIRECTORY,
        0,
    )?;
    let meta = dir.metadata()?;
    ensure!(
        meta.is_dir()
            && meta.mode() & 0o7777 == 0o700
            && meta.uid() == owner.uid()
            && meta.gid() == owner.gid(),
        "unsafe transaction directory ownership or permissions"
    );
    Ok(dir)
}

fn checked_private_file(
    parent: &File,
    name: &str,
    owner: &Metadata,
    cap: u64,
) -> anyhow::Result<File> {
    let file = open_at(parent, OsStr::new(name), libc::O_PATH, 0)?;
    let meta = file.metadata()?;
    ensure!(
        meta.is_file()
            && meta.nlink() == 1
            && meta.mode() & 0o7777 == 0o600
            && meta.uid() == owner.uid()
            && meta.gid() == owner.gid()
            && meta.len() <= cap,
        "unsafe transaction file type, owner, mode or size"
    );
    Ok(reopen_inspected(&file, libc::O_RDONLY)?)
}

fn read_optional_private(
    parent: &File,
    name: &str,
    owner: &Metadata,
    cap: u64,
) -> anyhow::Result<Option<Vec<u8>>> {
    if inspect_at(parent, OsStr::new(name))?.is_none() {
        return Ok(None);
    }
    read_fd(&checked_private_file(parent, name, owner, cap)?, cap).map(Some)
}

fn write_new(parent: &File, name: &str, bytes: &[u8], owner: &Metadata) -> anyhow::Result<()> {
    write_new_inner(parent, name, bytes, owner, false)
}

fn write_declared_blob(
    parent: &File,
    name: &str,
    bytes: &[u8],
    owner: &Metadata,
) -> anyhow::Result<()> {
    write_new_inner(parent, name, bytes, owner, true)
}

fn write_new_inner(
    parent: &File,
    name: &str,
    bytes: &[u8],
    owner: &Metadata,
    declared_blob: bool,
) -> anyhow::Result<()> {
    fault(FaultPoint::WriteBlob)?;
    let mut file = open_at(
        parent,
        OsStr::new(name),
        libc::O_RDWR | libc::O_CREAT | libc::O_EXCL,
        0o600,
    )?;
    preserve_owner(&file, owner)?;
    let meta = file.metadata()?;
    ensure!(
        meta.mode() & 0o7777 == 0o600 && meta.uid() == owner.uid() && meta.gid() == owner.gid(),
        "transaction file ownership mismatch"
    );
    file.write_all(bytes)?;
    if declared_blob {
        fault(FaultPoint::BeforeBlobFsync)?;
    }
    file.sync_all()?;
    if declared_blob {
        fault(FaultPoint::AfterBlobFsync)?;
    }
    Ok(())
}

fn write_journal(fence: &File, owner: &Metadata, journal: &Journal) -> anyhow::Result<()> {
    let bytes = encode(journal)?;
    if let Some(file) = inspect_at(fence, OsStr::new(JOURNAL_NEXT))? {
        let checked = checked_private_file(fence, JOURNAL_NEXT, owner, MAX_MANIFEST_BYTES)?;
        ensure!(
            same_inode(&file.metadata()?, &checked.metadata()?),
            "journal stage replaced"
        );
        unlink_at(fence, OsStr::new(JOURNAL_NEXT))?;
    }
    write_new(fence, JOURNAL_NEXT, &bytes, owner)?;
    fault(FaultPoint::JournalRename)?;
    rename_at(
        fence,
        OsStr::new(JOURNAL_NEXT),
        fence,
        OsStr::new(JOURNAL_NAME),
    )?;
    fault(FaultPoint::JournalFsync)?;
    fence.sync_all()?;
    Ok(())
}

fn encode(journal: &Journal) -> anyhow::Result<Vec<u8>> {
    validate_scope(journal)?;
    struct Bounded(Vec<u8>);
    impl Write for Bounded {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.0.len().saturating_add(bytes.len()) > MAX_MANIFEST_BYTES as usize {
                return Err(io::Error::other("manifest byte budget exceeded"));
            }
            self.0.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut out = Bounded(Vec::new());
    serde_json::to_writer(&mut out, journal)?;
    Ok(out.0)
}

fn decode(bytes: &[u8], tree: TreeIo<'_>) -> anyhow::Result<Journal> {
    ensure!(
        bytes.len() as u64 <= MAX_MANIFEST_BYTES,
        "manifest byte budget exceeded"
    );
    let journal: Journal =
        serde_json::from_slice(bytes).context("invalid strict format2 manifest")?;
    validate_scope(&journal)?;
    ensure!(
        journal.format_version == FORMAT_VERSION,
        "unsupported journal format"
    );
    ensure!(
        journal.master == master_name(tree)? && journal.root == Inode::of(&tree.root.metadata()?),
        "transaction tree identity mismatch"
    );
    ensure!(
        (3..=5).contains(&journal.source_schema) && (3..=5).contains(&journal.target_schema),
        "unsupported schema version"
    );
    ensure!(
        !journal.members.is_empty() && journal.members.len() <= MAX_MEMBERS,
        "invalid journal member count"
    );
    let receipt = &journal.receipt;
    for value in [
        &receipt.actor,
        &receipt.request_id,
        &receipt.origin,
        &receipt.operation,
    ] {
        ensure!(
            !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control),
            "invalid receipt identity"
        );
    }
    ensure!(
        receipt.transaction_id.len() == 32
            && receipt
                .transaction_id
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit()),
        "invalid transaction ID"
    );
    for value in [
        &receipt.payload_hash,
        &receipt.plan_hash,
        &receipt.before_revision,
        &receipt.after_revision,
        &journal.request_fingerprint,
    ] {
        ensure!(is_hash(value), "invalid journal digest");
    }
    ensure!(
        receipt.operator_plan_hash.as_deref().is_none_or(is_hash),
        "invalid operator plan hash"
    );
    validate_operation_manifest(receipt.operation_manifest.as_ref())?;
    ensure!(
        receipt.plan_hash == journal.request_fingerprint
            && receipt
                .failure
                .as_ref()
                .is_none_or(|failure| failure.len() <= 4096),
        "invalid receipt plan or failure"
    );
    let mut paths = BTreeSet::new();
    let mut total = 0_u64;
    let mut masters = 0;
    for (index, member) in journal.members.iter().enumerate() {
        validate_member_path(Path::new(&member.path), member.role, &journal.master)?;
        ensure!(paths.insert(&member.path), "duplicate transaction member");
        if member.role == MemberRole::Master {
            masters += 1;
            ensure!(
                member.after.is_some()
                    && (member.before.is_some()
                        || journal.revision_scope == RevisionScope::RepairDestinationSetV1),
                "policy master cannot be created or deleted"
            );
        }
        ensure!(
            member.before.is_some() == member.before_inode.is_some(),
            "invalid before inode receipt"
        );
        let valid = match member.operation {
            Some(MemberOperation::Create) => member.before.is_none() && member.after.is_some(),
            Some(MemberOperation::Delete) => {
                member.before.is_some() && member.after.is_none() && member.promoted_inode.is_none()
            }
            Some(MemberOperation::Replace) => member.before.is_some() && member.after.is_some(),
            None => match (&member.before, &member.after) {
                (Some(before), Some(after)) => {
                    before.length == after.length
                        && before.digest == after.digest
                        && before.uid == after.uid
                        && before.gid == after.gid
                        && before.mode == after.mode
                        && member.promoted_inode.is_none()
                        && member.restored_inode.is_none()
                }
                _ => false,
            },
        };
        ensure!(valid, "invalid member operation states");
        ensure!(
            member.staging.is_none() || member.linked_staging.is_none(),
            "member has multiple staging receipts"
        );
        ensure!(
            member.rollback_staging.is_none() || member.staging.is_none(),
            "member has incompatible private and rollback staging receipts"
        );
        if let Some(staging) = &member.rollback_staging {
            let state = member
                .before
                .as_ref()
                .context("rollback receipt lacks before image")?;
            ensure!(
                matches!(
                    member.operation,
                    Some(MemberOperation::Replace | MemberOperation::Delete)
                ) && is_write_stage_name(&staging.name)
                    && staging.payload_uid == state.uid
                    && staging.payload_gid == state.gid
                    && staging.payload_mode == state.mode
                    && staging.payload_length == state.length
                    && staging.payload_digest == state.digest
                    && is_hash(&staging.payload_digest),
                "invalid rollback staging receipt"
            );
        }
        if let Some(staging) = &member.staging {
            let operation_can_stage = matches!(
                member.operation,
                Some(MemberOperation::Create | MemberOperation::Replace)
            ) || (member.operation == Some(MemberOperation::Delete)
                && member.restored_inode.is_some());
            ensure!(
                operation_can_stage
                    && is_write_stage_name(&staging.name)
                    && staging.directory_mode == 0o700
                    && staging.payload_links == 1
                    && staging.payload_mode <= 0o7777
                    && is_hash(&staging.payload_digest),
                "invalid staging receipt shape"
            );
            let (state, inode) = if let Some(restored) = &member.restored_inode {
                (member.before.as_ref(), restored)
            } else {
                (
                    member.after.as_ref(),
                    member
                        .promoted_inode
                        .as_ref()
                        .context("staging receipt lacks a promotion inode")?,
                )
            };
            let state = state.context("staging receipt lacks payload state")?;
            ensure!(
                &staging.payload == inode
                    && staging.payload_uid == state.uid
                    && staging.payload_gid == state.gid
                    && staging.payload_mode == state.mode
                    && staging.payload_length == state.length
                    && staging.payload_digest == state.digest,
                "staging receipt does not match member state"
            );
        }
        if let Some(staging) = &member.linked_staging {
            let operation_can_stage = matches!(
                member.operation,
                Some(MemberOperation::Create | MemberOperation::Replace)
            ) || (member.operation == Some(MemberOperation::Delete)
                && member.restored_inode.is_some());
            ensure!(
                operation_can_stage
                    && is_write_stage_name(&staging.name)
                    && staging.payload_mode <= 0o7777
                    && is_hash(&staging.payload_digest),
                "invalid linked staging receipt shape"
            );
            let (state, inode) = if let Some(restored) = &member.restored_inode {
                (member.before.as_ref(), restored)
            } else {
                (
                    member.after.as_ref(),
                    member
                        .promoted_inode
                        .as_ref()
                        .context("linked staging receipt lacks a promotion inode")?,
                )
            };
            let state = state.context("linked staging receipt lacks payload state")?;
            ensure!(
                &staging.payload == inode
                    && staging.payload_uid == state.uid
                    && staging.payload_gid == state.gid
                    && staging.payload_mode == state.mode
                    && staging.payload_length == state.length
                    && staging.payload_digest == state.digest,
                "linked staging receipt does not match member state"
            );
        }
        for (before, state) in [(true, &member.before), (false, &member.after)] {
            if let Some(state) = state {
                ensure!(
                    state.blob == blob_name(index, before)
                        && is_hash(&state.digest)
                        && state.mode <= 0o7777,
                    "invalid blob receipt"
                );
                total = total
                    .checked_add(state.length)
                    .context("blob budget overflow")?;
            }
        }
    }
    ensure!(
        masters == 1
            && total <= MAX_BLOB_BYTES
            && receipt.changed_members
                == journal
                    .members
                    .iter()
                    .filter(|member| member.operation.is_some())
                    .count(),
        "invalid manifest inventory or budget"
    );
    let persistence_valid = match journal.phase {
        Phase::Setup => receipt.persistence == Persistence::Prepared,
        Phase::Prepared => matches!(
            receipt.persistence,
            Persistence::Prepared | Persistence::DurabilityUncertain
        ),
        Phase::Committing
        | Phase::Committed
        | Phase::RollingBack
        | Phase::RollbackCleanup
        | Phase::RolledBack => matches!(
            receipt.persistence,
            Persistence::Committed | Persistence::DurabilityUncertain
        ),
        Phase::AbortCleanup | Phase::Aborted => matches!(
            receipt.persistence,
            Persistence::Aborted | Persistence::DurabilityUncertain
        ),
    };
    ensure!(
        persistence_valid
            && receipt.rollback_restored
                == matches!(journal.phase, Phase::RollbackCleanup | Phase::RolledBack),
        "invalid journal persistence state"
    );
    if matches!(journal.phase, Phase::Setup) {
        ensure!(
            journal
                .members
                .iter()
                .all(|member| member.promoted_inode.is_none()
                    && member.restored_inode.is_none()
                    && member.staging.is_none()
                    && member.linked_staging.is_none()
                    && member.rollback_staging.is_none())
                && !journal.rollback_ready,
            "setup cannot contain promotion receipts"
        );
    }
    if matches!(
        journal.phase,
        Phase::Committing
            | Phase::Committed
            | Phase::RollingBack
            | Phase::RollbackCleanup
            | Phase::RolledBack
    ) {
        ensure!(
            journal.members.iter().all(|member| !matches!(
                member.operation,
                Some(MemberOperation::Create | MemberOperation::Replace)
            ) || member.promoted_inode.is_some()),
            "committed member lacks a promotion receipt"
        );
    }
    if matches!(
        journal.phase,
        Phase::Committed | Phase::Aborted | Phase::RolledBack
    ) {
        ensure!(
            journal.members.iter().all(|member| {
                member.staging.is_none()
                    && member.linked_staging.is_none()
                    && member.rollback_staging.is_none()
            }) && !journal.rollback_ready,
            "terminal transaction contains a staging receipt"
        );
    }
    if journal.rollback_ready {
        ensure!(
            matches!(
                journal.phase,
                Phase::Prepared | Phase::RollingBack | Phase::Committing
            ),
            "invalid rollback readiness marker"
        );
        if matches!(journal.phase, Phase::Prepared | Phase::RollingBack) {
            ensure!(
                journal.members.iter().all(|member| {
                    !matches!(
                        member.operation,
                        Some(MemberOperation::Replace | MemberOperation::Delete)
                    ) || member
                        .rollback_staging
                        .as_ref()
                        .is_some_and(|receipt| receipt.linked)
                        || member.restored_inode.is_some()
                }),
                "invalid rollback readiness marker"
            );
        }
    }
    Ok(journal)
}

fn validate_scope(journal: &Journal) -> anyhow::Result<()> {
    ensure!(
        journal.revision_scope == journal.receipt.revision_scope,
        "journal and receipt revision scope differ"
    );
    if journal.revision_scope == RevisionScope::RepairDestinationSetV1 {
        ensure!(
            journal.members.iter().all(|member| member.after.is_some()
                && member.operation != Some(MemberOperation::Delete)),
            "repair destinations cannot contain deletions"
        );
        ensure!(
            repair_digest(&journal.members, true) == journal.receipt.before_revision
                && repair_digest(&journal.members, false) == journal.receipt.after_revision,
            "repair destination digest mismatch"
        );
    }
    Ok(())
}

fn read_journal(dir: &File, owner: &Metadata, tree: TreeIo<'_>) -> anyhow::Result<Journal> {
    decode(
        &read_optional_private(dir, JOURNAL_NAME, owner, MAX_MANIFEST_BYTES)?
            .context("missing transaction journal")?,
        tree,
    )
}

fn read_blob(dir: &File, owner: &Metadata, state: &FileState) -> anyhow::Result<Vec<u8>> {
    let bytes = read_fd(
        &checked_private_file(dir, &state.blob, owner, state.length)?,
        state.length,
    )?;
    ensure!(
        bytes.len() as u64 == state.length && hash(&bytes) == state.digest,
        "transaction blob digest mismatch"
    );
    Ok(bytes)
}

fn validate_all_blobs(dir: &File, owner: &Metadata, journal: &Journal) -> anyhow::Result<()> {
    for member in &journal.members {
        for state in [member.before.as_ref(), member.after.as_ref()]
            .into_iter()
            .flatten()
        {
            read_blob(dir, owner, state)?;
        }
    }
    Ok(())
}

fn validate_fence_inventory(dir: &File, owner: &Metadata, journal: &Journal) -> anyhow::Result<()> {
    let mut allowed: BTreeSet<_> = [JOURNAL_NAME, JOURNAL_NEXT, SETUP_MARKER]
        .into_iter()
        .map(str::to_owned)
        .collect();
    for member in &journal.members {
        for state in [member.before.as_ref(), member.after.as_ref()]
            .into_iter()
            .flatten()
        {
            allowed.insert(state.blob.clone());
        }
    }
    for name in directory_names(dir, MAX_MEMBERS * 2 + 3)? {
        ensure!(allowed.contains(&name), "unexpected transaction artifact");
        checked_private_file(dir, &name, owner, MAX_BLOB_BYTES)?;
    }
    Ok(())
}

fn expire_undo(store: &File, key: &str, owner: &Metadata, tree: TreeIo<'_>) -> anyhow::Result<()> {
    let retired_name = format!("retired-{key}");
    if inspect_at(store, OsStr::new(key))?.is_some() {
        let undo = private_dir(store, key, owner, false)?;
        let journal = read_journal(&undo, owner, tree)?;
        ensure!(
            matches!(
                journal.phase,
                Phase::Committed | Phase::Aborted | Phase::RolledBack
            ),
            "cannot expire active undo"
        );
        validate_fence_inventory(&undo, owner, &journal)?;
        rename_noreplace_at(store, OsStr::new(key), store, OsStr::new(&retired_name))?;
        store.sync_all()?;
    }
    if inspect_at(store, OsStr::new(&retired_name))?.is_none() {
        return Ok(());
    }
    let retired = private_dir(store, &retired_name, owner, false)?;
    let names = directory_names(&retired, MAX_MEMBERS * 2 + 3)?;
    for name in &names {
        let blob = name.strip_suffix(".blob").is_some_and(|base| {
            base.len() == 5
                && matches!(base.as_bytes()[0], b'a' | b'b')
                && base.as_bytes()[1..].iter().all(u8::is_ascii_digit)
        });
        ensure!(
            blob || name == JOURNAL_NAME || name == JOURNAL_NEXT || name == SETUP_MARKER,
            "unexpected retired transaction member"
        );
        checked_private_file(&retired, name, owner, MAX_BLOB_BYTES)?;
    }
    for name in names {
        unlink_at(&retired, OsStr::new(&name))?;
    }
    retired.sync_all()?;
    remove_empty_dir(store, &retired_name, &retired)?;
    Ok(())
}

fn publish_fence(tree: TreeIo<'_>, owner: &Metadata) -> anyhow::Result<File> {
    ensure!(
        inspect_at(tree.root, OsStr::new(SETUP_STAGE))?.is_none(),
        "unfinished format2 setup stage"
    );
    let stage = private_dir(tree.root, SETUP_STAGE, owner, true)?;
    write_new(&stage, SETUP_MARKER, b"2\n", owner)?;
    stage.sync_all()?;
    tree.root.sync_all()?;
    fault(FaultPoint::SetupReady)?;
    rename_noreplace_at(
        tree.root,
        OsStr::new(SETUP_STAGE),
        tree.root,
        OsStr::new(TXN_DIR_NAME),
    )?;
    fault(FaultPoint::FencePublished)?;
    tree.root.sync_all()?;
    Ok(stage)
}

fn cleanup_setup_stage(tree: TreeIo<'_>, owner: &Metadata) -> anyhow::Result<bool> {
    if inspect_at(tree.root, OsStr::new(SETUP_STAGE))?.is_none() {
        return Ok(false);
    }
    ensure!(
        inspect_at(tree.root, OsStr::new(TXN_DIR_NAME))?.is_none(),
        "both active fence and setup stage exist"
    );
    let stage = private_dir(tree.root, SETUP_STAGE, owner, false)?;
    let names = directory_names(&stage, 2)?;
    for name in names {
        match name.as_str() {
            SETUP_MARKER => {
                let marker = read_optional_private(&stage, SETUP_MARKER, owner, 2)?
                    .context("setup stage marker disappeared")?;
                ensure!(b"2\n".starts_with(&marker), "invalid format2 setup marker");
            }
            JOURNAL_NEXT => {
                checked_private_file(&stage, &name, owner, MAX_MANIFEST_BYTES)?;
            }
            _ => bail!("unexpected setup stage member"),
        }
        unlink_at(&stage, OsStr::new(&name))?;
    }
    stage.sync_all()?;
    remove_empty_dir(tree.root, SETUP_STAGE, &stage)?;
    Ok(true)
}

fn remove_empty_dir(parent: &File, name: &str, directory: &File) -> anyhow::Result<()> {
    let current = inspect_at(parent, OsStr::new(name))?.context("owned directory disappeared")?;
    ensure!(
        same_inode(&current.metadata()?, &directory.metadata()?),
        "owned directory replaced"
    );
    let name = CString::new(name)?;
    // SAFETY: parent is an open directory and name is a NUL-terminated basename.
    if unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    parent.sync_all()?;
    Ok(())
}

fn unix_seconds() -> anyhow::Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

fn directory_names(dir: &File, cap: usize) -> anyhow::Result<Vec<String>> {
    let file = reopen_inspected(dir, libc::O_RDONLY | libc::O_DIRECTORY)?;
    // SAFETY: file holds a valid descriptor; fcntl duplicates it without borrowing memory.
    let raw_fd = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
    ensure!(raw_fd >= 0, "cannot duplicate transaction directory fd");
    // SAFETY: raw_fd is a fresh, owned directory descriptor transferred to DIR on success.
    let raw = unsafe { libc::fdopendir(raw_fd) };
    if raw.is_null() {
        // SAFETY: fdopendir failed, so ownership of the valid duplicate remains here.
        drop(unsafe { File::from_raw_fd(raw_fd) });
        return Err(io::Error::last_os_error().into());
    }
    struct Stream(*mut libc::DIR);
    impl Drop for Stream {
        fn drop(&mut self) {
            // SAFETY: Stream exclusively owns the non-null DIR pointer from fdopendir.
            unsafe {
                libc::closedir(self.0);
            }
        }
    }
    let stream = Stream(raw);
    let mut names = Vec::new();
    loop {
        // SAFETY: errno is thread-local; clearing it distinguishes EOF from readdir failure.
        unsafe {
            *libc::__errno_location() = 0;
        }
        // SAFETY: stream owns a live DIR and this loop is its only accessor.
        let entry = unsafe { libc::readdir(stream.0) };
        if entry.is_null() {
            if io::Error::last_os_error().raw_os_error() != Some(0) {
                return Err(io::Error::last_os_error().into());
            }
            break;
        }
        // SAFETY: a non-null readdir entry contains a NUL-terminated d_name valid until
        // the next readdir call; the bytes are consumed before that call.
        let bytes = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        if bytes == b"." || bytes == b".." {
            continue;
        }
        ensure!(
            names.len() < cap,
            "transaction directory inventory budget exceeded"
        );
        names.push(
            std::str::from_utf8(bytes)
                .context("non-UTF8 transaction artifact")?
                .to_owned(),
        );
    }
    names.sort();
    Ok(names)
}

fn remove_setup(root: &File, fence: &File, owner: &Metadata) -> anyhow::Result<()> {
    let names = directory_names(fence, 2)?;
    for name in &names {
        ensure!(
            name == SETUP_MARKER || name == JOURNAL_NEXT,
            "unexpected incomplete transaction artifact"
        );
        checked_private_file(fence, name, owner, MAX_MANIFEST_BYTES)?;
    }
    let current = inspect_at(root, OsStr::new(TXN_DIR_NAME))?.context("setup fence disappeared")?;
    ensure!(
        same_inode(&current.metadata()?, &fence.metadata()?),
        "setup fence replaced"
    );
    ensure!(
        inspect_at(root, OsStr::new(SETUP_STAGE))?.is_none(),
        "setup cleanup stage already exists"
    );
    rename_noreplace_at(
        root,
        OsStr::new(TXN_DIR_NAME),
        root,
        OsStr::new(SETUP_STAGE),
    )?;
    fault(FaultPoint::SetupCleanupPublished)?;
    root.sync_all()?;
    for name in names {
        unlink_at(fence, OsStr::new(&name))?;
    }
    fault(FaultPoint::SetupCleanupMemberUnlinked)?;
    fence.sync_all()?;
    remove_empty_dir(root, SETUP_STAGE, fence)?;
    Ok(())
}

fn remove_unpublished_setup(
    root: &File,
    fence: &File,
    owner: &Metadata,
    journal: &Journal,
) -> anyhow::Result<()> {
    // Retain the decoded Setup intent until every partial blob is durably
    // gone. A death during cleanup can then repeat the same source-only proof.
    for member in &journal.members {
        for state in [member.before.as_ref(), member.after.as_ref()]
            .into_iter()
            .flatten()
        {
            if inspect_at(fence, OsStr::new(&state.blob))?.is_some() {
                checked_private_file(fence, &state.blob, owner, state.length)?;
                unlink_at(fence, OsStr::new(&state.blob))?;
            }
        }
    }
    fence.sync_all()?;
    if inspect_at(fence, OsStr::new(JOURNAL_NEXT))?.is_some() {
        unlink_at(fence, OsStr::new(JOURNAL_NEXT))?;
    }
    unlink_at(fence, OsStr::new(JOURNAL_NAME))?;
    fence.sync_all()?;
    remove_setup(root, fence, owner)
}

fn preflight_space(root: &File, required: u64) -> anyhow::Result<()> {
    let mut stat = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: root is a valid descriptor and stat points to writable statvfs storage.
    if unsafe { libc::fstatvfs(root.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    // SAFETY: successful fstatvfs initialized the complete output structure.
    let stat = unsafe { stat.assume_init() };
    ensure!(
        stat.f_bavail.saturating_mul(stat.f_frsize) >= required,
        "insufficient transaction space (ENOSPC)"
    );
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FaultPoint {
    AfterPreparedReceiptHook,
    SetupReady,
    FencePublished,
    SetupCleanupPublished,
    SetupCleanupMemberUnlinked,
    WriteBlob,
    BeforeBlobFsync,
    AfterBlobFsync,
    JournalRename,
    JournalFsync,
    BeforePromotion,
    AfterStagingLink,
    AfterPromotion,
    BeforeAnonymousInodeFsync,
    AfterAnonymousInodeFsync,
    BeforeStagingLink,
    BeforeStagingLinkParentFsync,
    AfterStagingLinkParentFsync,
    BeforePromotionRename,
    AfterPromotionRename,
    BeforePostRenameParentFsync,
    AfterPostRenameParentFsync,
    BeforeRollbackStageLink,
    AfterRollbackStageLink,
    BeforeRollbackStageUnlink,
    AfterRollbackStageUnlink,
    RollbackReady,
    BeforeRollbackRestoreRename,
    AfterRollbackRestoreRename,
    BeforeRollbackRestoreParentFsync,
    AfterRollbackRestoreParentFsync,
    BeforeTerminalRename,
    AfterTerminalRename,
    RootFsync,
}

fn atomic_write_boundary(boundary: AtomicWriteBoundary) -> Result<(), String> {
    let point = match boundary {
        AtomicWriteBoundary::BeforeAnonymousInodeFsync => FaultPoint::BeforeAnonymousInodeFsync,
        AtomicWriteBoundary::AfterAnonymousInodeFsync => FaultPoint::AfterAnonymousInodeFsync,
        AtomicWriteBoundary::BeforeStagingLink => FaultPoint::BeforeStagingLink,
        AtomicWriteBoundary::AfterStagingLink => FaultPoint::AfterStagingLink,
        AtomicWriteBoundary::BeforeStagingLinkParentFsync => {
            FaultPoint::BeforeStagingLinkParentFsync
        }
        AtomicWriteBoundary::AfterStagingLinkParentFsync => FaultPoint::AfterStagingLinkParentFsync,
        AtomicWriteBoundary::BeforePromotionRename => FaultPoint::BeforePromotionRename,
        AtomicWriteBoundary::AfterPromotionRename => FaultPoint::AfterPromotionRename,
        AtomicWriteBoundary::BeforePostRenameParentFsync => FaultPoint::BeforePostRenameParentFsync,
        AtomicWriteBoundary::AfterPostRenameParentFsync => FaultPoint::AfterPostRenameParentFsync,
    };
    fault(point).map_err(|error| format!("{error:#}"))
}

fn fault(point: FaultPoint) -> anyhow::Result<()> {
    #[cfg(test)]
    TEST_KILL.with(|kill| {
        let mut configured = kill.borrow_mut();
        if let Some((expected, remaining)) = configured.as_mut() {
            if *expected == point {
                if *remaining == 0 {
                    // SAFETY: getpid returns this process and kill accepts SIGKILL for it.
                    unsafe {
                        libc::kill(libc::getpid(), libc::SIGKILL);
                    }
                }
                *remaining = remaining.saturating_sub(1);
            }
        }
    });
    #[cfg(test)]
    TEST_FAULT.with(|fault| -> anyhow::Result<()> {
        let mut configured = fault.borrow_mut();
        if let Some((expected, remaining)) = configured.as_mut() {
            if *expected == point {
                if *remaining == 0 {
                    *configured = None;
                    return Err(io::Error::from_raw_os_error(libc::ENOSPC).into());
                }
                *remaining -= 1;
            }
        }
        Ok(())
    })?;
    let _ = point;
    Ok(())
}

#[cfg(test)]
thread_local! { static TEST_FAULT: RefCell<Option<(FaultPoint, usize)>> = const { RefCell::new(None) }; }

#[cfg(test)]
pub(crate) fn fail_after_prepared_for_test() {
    TEST_FAULT.with(|fault| *fault.borrow_mut() = Some((FaultPoint::AfterPreparedReceiptHook, 0)));
}

#[cfg(test)]
pub(crate) fn kill_after_terminal_rename_for_test() {
    TEST_KILL.with(|kill| *kill.borrow_mut() = Some((FaultPoint::AfterTerminalRename, 0)));
}

#[cfg(test)]
pub(crate) fn kill_before_first_blob_fsync_for_test() {
    TEST_KILL.with(|kill| *kill.borrow_mut() = Some((FaultPoint::BeforeBlobFsync, 0)));
}

#[cfg(test)]
pub(crate) fn kill_before_prepared_receipt_for_test() {
    TEST_KILL.with(|kill| *kill.borrow_mut() = Some((FaultPoint::JournalFsync, 1)));
}

#[cfg(test)]
pub(crate) fn fail_after_rollback_intent_for_test() {
    TEST_FAULT.with(|fault| *fault.borrow_mut() = Some((FaultPoint::JournalFsync, 0)));
}

#[cfg(test)]
thread_local! { static TEST_KILL: RefCell<Option<(FaultPoint, usize)>> = const { RefCell::new(None) }; }

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::symlink;

    fn test_receipts(guard: &MigrationWriteLock) -> ReceiptStore {
        let path = guard.tree_io().identity.root.join("node-data");
        fs::create_dir_all(&path).unwrap();
        ReceiptStore::open(&File::open(path).unwrap(), guard).unwrap()
    }

    fn prepare<'g>(
        guard: &'g MigrationWriteLock,
        request: &TransactionRequest,
        before: &PolicyRevisionInventory,
        after: &PolicyRevisionInventory,
        validate: impl FnOnce() -> anyhow::Result<()>,
    ) -> anyhow::Result<PrepareOutcome<'g>> {
        super::prepare(
            guard,
            &test_receipts(guard),
            request,
            before,
            after,
            validate,
        )
    }

    fn apply(
        guard: &MigrationWriteLock,
        request: &TransactionRequest,
        before: &PolicyRevisionInventory,
        after: &PolicyRevisionInventory,
        validate: impl FnOnce() -> anyhow::Result<()>,
    ) -> anyhow::Result<BaseReceipt> {
        super::apply(
            guard,
            &test_receipts(guard),
            request,
            before,
            after,
            validate,
        )
    }

    fn lookup_receipt(
        guard: &MigrationWriteLock,
        actor: &str,
        request_id: &str,
    ) -> anyhow::Result<Option<BaseReceipt>> {
        super::lookup_receipt(guard, &test_receipts(guard), actor, request_id)
    }

    fn recover_active(guard: &MigrationWriteLock) -> anyhow::Result<RecoveryOutcome> {
        super::recover_active(guard, &test_receipts(guard))
    }

    fn rollback(
        guard: &MigrationWriteLock,
        actor: &str,
        request_id: &str,
    ) -> anyhow::Result<RollbackOutcome> {
        super::rollback(guard, &test_receipts(guard), actor, request_id)
    }

    struct Fixture {
        root: tempfile::TempDir,
        before: PolicyRevisionInventory,
        after: PolicyRevisionInventory,
    }

    impl Fixture {
        fn new() -> Self {
            let root = tempfile::tempdir().unwrap();
            fs::create_dir(root.path().join("packs")).unwrap();
            let before = inventory(&[
                (
                    PolicyMemberKind::Master,
                    "config.toml",
                    "schema_version = 4\nincludes = [\"include.toml\"]\n# before\n[upstream]\nservers = [\"192.0.2.1:53\"]\n\n[[custom_lists]]\nid = \"old\"\n\n[[custom_lists]]\nid = \"kept\"\n",
                ),
                (
                    PolicyMemberKind::Include,
                    "include.toml",
                    "# original include\n",
                ),
                (PolicyMemberKind::Pack, "packs/old.txt", "old.example\n"),
                (
                    PolicyMemberKind::Pack,
                    "packs/kept.txt",
                    "changed-kept.example\n",
                ),
            ]);
            let after = inventory(&[
                (
                    PolicyMemberKind::Master,
                    "config.toml",
                    "schema_version = 4\nincludes = [\"include.toml\"]\n# after\n[upstream]\nservers = [\"192.0.2.1:53\"]\n\n[[custom_lists]]\nid = \"new\"\n\n[[custom_lists]]\nid = \"kept\"\n",
                ),
                (
                    PolicyMemberKind::Include,
                    "include.toml",
                    "# changed include\n",
                ),
                (PolicyMemberKind::Pack, "packs/new.txt", "new.example\n"),
                (PolicyMemberKind::Pack, "packs/kept.txt", "kept.example\n"),
            ]);
            for member in before.members() {
                let path = root.path().join(member.path());
                fs::write(&path, member_bytes(member).unwrap()).unwrap();
                fs::set_permissions(path, Permissions::from_mode(0o640)).unwrap();
            }
            fs::write(root.path().join("packs/orphan.txt"), b"orphan.example\n").unwrap();
            Self {
                root,
                before,
                after,
            }
        }

        fn master(&self) -> PathBuf {
            self.root.path().join("config.toml")
        }

        fn guard(&self) -> MigrationWriteLock {
            super::super::write_lock::acquire_for_migration(&self.master()).unwrap()
        }

        fn request(&self) -> TransactionRequest {
            TransactionRequest {
                request_id: "request-1".into(),
                actor: "operator-1".into(),
                origin: "cli".into(),
                operation: "import".into(),
                payload: b"candidate".to_vec(),
                expected_revision: self.before.revision(),
                source_schema: 4,
                target_schema: 4,
            }
        }

        fn assert_inventory(&self, inventory: &PolicyRevisionInventory) {
            for member in inventory.members() {
                assert_eq!(
                    fs::read(self.root.path().join(member.path())).unwrap(),
                    member_bytes(member).unwrap()
                );
            }
        }

        fn prepare<'g>(&self, guard: &'g MigrationWriteLock) -> PreparedTransaction<'g> {
            match prepare(guard, &self.request(), &self.before, &self.after, || Ok(())).unwrap() {
                PrepareOutcome::Prepared(transaction) => *transaction,
                PrepareOutcome::Replay(_) => panic!("unexpected replay"),
            }
        }
    }

    fn assert_no_write_stages(root: &Path) {
        for directory in [root.to_path_buf(), root.join("packs")] {
            for entry in fs::read_dir(directory).unwrap() {
                let name = entry.unwrap().file_name();
                assert!(
                    !name.as_bytes().starts_with(WRITE_STAGE_PREFIX.as_bytes()),
                    "staging residue remained at {}",
                    root.join(name).display()
                );
            }
        }
    }

    fn assert_policy_loadable(fixture: &Fixture, guard: &MigrationWriteLock) {
        validate_flat_packs(guard.tree_io()).unwrap();
        super::super::loader::load_config_for_schema_under_migration_guard(
            guard,
            &fixture.master(),
            4,
            time::OffsetDateTime::UNIX_EPOCH,
        )
        .unwrap();
    }

    fn inventory(entries: &[(PolicyMemberKind, &str, &str)]) -> PolicyRevisionInventory {
        PolicyRevisionInventory::new(
            entries
                .iter()
                .map(|(kind, path, body)| {
                    PolicyRevisionMember::present(
                        *kind,
                        PathBuf::from(path),
                        body.as_bytes().to_vec(),
                    )
                    .unwrap()
                })
                .collect(),
        )
        .unwrap()
    }

    fn schema5_inventory(master: &[u8]) -> PolicyRevisionInventory {
        PolicyRevisionInventory::new(vec![
            PolicyRevisionMember::present(
                PolicyMemberKind::Master,
                PathBuf::from("config.toml"),
                master.to_vec(),
            )
            .unwrap(),
            PolicyRevisionMember::present(
                PolicyMemberKind::Pack,
                PathBuf::from("packs/streaming.txt"),
                include_bytes!("../../tests/fixtures/target-v5/packs/streaming.txt").to_vec(),
            )
            .unwrap(),
            PolicyRevisionMember::present(
                PolicyMemberKind::Pack,
                PathBuf::from("packs/archive.txt"),
                include_bytes!("../../tests/fixtures/target-v5/packs/archive.txt").to_vec(),
            )
            .unwrap(),
        ])
        .unwrap()
    }

    fn schema5_master_with_token_ref(reference: &str) -> Vec<u8> {
        let mut master = include_bytes!("../../tests/fixtures/target-v5/config.toml").to_vec();
        master.extend_from_slice(
            format!(
                "\n[[blocklists]]\nid = \"private-source\"\ndisplay_name = \"Private source\"\nurl = \"https://lists.example.invalid/private.txt\"\nauth_token_ref = \"{reference}\"\n"
            )
            .as_bytes(),
        );
        master
    }

    fn write_schema5_inventory(root: &Path, inventory: &PolicyRevisionInventory) {
        fs::create_dir_all(root.join("packs")).unwrap();
        for member in inventory.members() {
            fs::write(root.join(member.path()), member_bytes(member).unwrap()).unwrap();
        }
    }

    fn with_fault<T>(point: FaultPoint, skip: usize, body: impl FnOnce() -> T) -> T {
        struct Reset;
        impl Drop for Reset {
            fn drop(&mut self) {
                TEST_FAULT.with(|fault| *fault.borrow_mut() = None);
            }
        }
        TEST_FAULT.with(|fault| *fault.borrow_mut() = Some((point, skip)));
        let _reset = Reset;
        body()
    }

    fn repair_request(destinations: &RepairDestinationSet<'_>) -> RepairRequest {
        RepairRequest {
            request_id: "repair-1".into(),
            actor: "operator-1".into(),
            origin: "cli".into(),
            operation: "config.restore.repair".into(),
            payload: b"archive".to_vec(),
            expected_destinations: destinations.revision(),
            source_schema: 4,
            target_schema: 4,
        }
    }

    fn prepared_repair<'g>(
        fixture: &Fixture,
        guard: &'g MigrationWriteLock,
    ) -> PreparedTransaction<'g> {
        let destinations = RepairDestinationSet::capture(guard, &fixture.after).unwrap();
        let request = repair_request(&destinations);
        match prepare_repair(&test_receipts(guard), &request, destinations, || Ok(())).unwrap() {
            PrepareOutcome::Prepared(transaction) => *transaction,
            PrepareOutcome::Replay(_) => panic!("unexpected repair replay"),
        }
    }

    #[test]
    fn repair_captures_present_and_absent_master_include_and_pack_preserving_metadata() {
        for missing in 0..8 {
            let fixture = Fixture::new();
            for (bit, name) in ["config.toml", "include.toml", "packs/kept.txt"]
                .iter()
                .enumerate()
            {
                if missing & (1 << bit) != 0 {
                    fs::remove_file(fixture.root.path().join(name)).unwrap();
                } else {
                    fs::set_permissions(
                        fixture.root.path().join(name),
                        Permissions::from_mode(0o600),
                    )
                    .unwrap();
                }
            }
            let orphan = fixture.root.path().join("packs/orphan.txt");
            let orphan_inode = fs::metadata(&orphan).unwrap().ino();
            let guard = fixture.guard();
            let transaction = prepared_repair(&fixture, &guard);
            assert!(transaction
                .journal
                .borrow()
                .members
                .iter()
                .all(|member| member.operation != Some(MemberOperation::Delete)));
            let receipt = transaction.commit().unwrap();
            assert_eq!(receipt.persistence, Persistence::Committed);
            assert_eq!(
                receipt.revision_scope,
                RevisionScope::RepairDestinationSetV1
            );
            fixture.assert_inventory(&fixture.after);
            for (bit, name) in ["config.toml", "include.toml", "packs/kept.txt"]
                .iter()
                .enumerate()
            {
                let metadata = fs::metadata(fixture.root.path().join(name)).unwrap();
                assert_eq!(
                    metadata.mode() & 0o777,
                    if missing & (1 << bit) == 0 {
                        0o600
                    } else {
                        0o640
                    }
                );
                assert_eq!(
                    metadata.uid(),
                    fs::metadata(fixture.root.path()).unwrap().uid()
                );
                assert_eq!(
                    metadata.gid(),
                    fs::metadata(fixture.root.path()).unwrap().gid()
                );
            }
            assert_eq!(fs::metadata(&orphan).unwrap().ino(), orphan_inode);
            assert_eq!(
                fs::read(fixture.root.path().join("packs/old.txt")).unwrap(),
                b"old.example\n"
            );
            assert_policy_loadable(&fixture, &guard);
        }
    }

    #[test]
    fn repair_noop_has_a_distinct_scope_and_preserves_named_inodes() {
        let fixture = Fixture::new();
        let guard = fixture.guard();
        let inode = fs::metadata(fixture.master()).unwrap().ino();
        let destinations = RepairDestinationSet::capture(&guard, &fixture.before).unwrap();
        let request = repair_request(&destinations);
        let receipt = super::apply_repair(&test_receipts(&guard), &request, destinations, || {
            fs::write(
                fixture.root.path().join("packs/orphan.txt"),
                b"external edit\n",
            )?;
            Ok(())
        })
        .unwrap();
        assert_eq!(receipt.changed_members, 0);
        assert_eq!(receipt.before_revision, receipt.after_revision);
        assert_ne!(
            receipt.before_revision,
            fixture.before.revision().to_string()
        );
        assert_eq!(fs::metadata(fixture.master()).unwrap().ino(), inode);
        assert_eq!(
            fs::read(fixture.root.path().join("packs/orphan.txt")).unwrap(),
            b"external edit\n"
        );
    }

    #[test]
    fn repair_replay_checks_payload_and_typed_precondition() {
        let fixture = Fixture::new();
        let guard = fixture.guard();
        let destinations = RepairDestinationSet::capture(&guard, &fixture.after).unwrap();
        let request = repair_request(&destinations);
        let receipt =
            super::apply_repair(&test_receipts(&guard), &request, destinations, || Ok(())).unwrap();
        let destinations = RepairDestinationSet::capture(&guard, &fixture.after).unwrap();
        let replay = super::apply_repair(&test_receipts(&guard), &request, destinations, || {
            bail!("replay must not validate")
        })
        .unwrap();
        assert_eq!(receipt, replay);
        for payload in [false, true] {
            let destinations = RepairDestinationSet::capture(&guard, &fixture.after).unwrap();
            let mut changed = request.clone();
            if payload {
                changed.payload.push(0);
            } else {
                changed.expected_destinations = destinations.revision();
            }
            let error =
                super::apply_repair(&test_receipts(&guard), &changed, destinations, || Ok(()))
                    .unwrap_err();
            assert!(
                error.to_string().contains("IdempotencyConflict"),
                "{error:#}"
            );
        }
    }

    #[test]
    fn repair_terminal_undo_restores_an_absent_master_and_retains_unnamed_changes() {
        let fixture = Fixture::new();
        fs::remove_file(fixture.master()).unwrap();
        let guard = fixture.guard();
        prepared_repair(&fixture, &guard).commit().unwrap();
        fs::write(
            fixture.root.path().join("packs/orphan.txt"),
            b"# external edit\n",
        )
        .unwrap();
        let RollbackOutcome::Restored(receipt) =
            rollback(&guard, "operator-1", "repair-1").unwrap()
        else {
            panic!("expected repair undo");
        };
        assert!(receipt.rollback_restored);
        assert_eq!(
            receipt.revision_scope,
            RevisionScope::RepairDestinationSetV1
        );
        assert!(!fixture.master().exists());
        assert_eq!(
            fs::read(fixture.root.path().join("include.toml")).unwrap(),
            b"# original include\n"
        );
        assert_eq!(
            fs::read(fixture.root.path().join("packs/orphan.txt")).unwrap(),
            b"# external edit\n"
        );
        assert!(!fixture.root.path().join("packs/new.txt").exists());
    }

    #[test]
    fn repair_named_drift_before_intent_and_during_recovery_is_never_overwritten() {
        for after_intent in [false, true] {
            for replace_inode in [false, true] {
                let fixture = Fixture::new();
                let guard = fixture.guard();
                let named = fixture.root.path().join("include.toml");
                let destinations = RepairDestinationSet::capture(&guard, &fixture.after).unwrap();
                let request = repair_request(&destinations);
                let transaction = if after_intent {
                    match prepare_repair(&test_receipts(&guard), &request, destinations, || Ok(()))
                        .unwrap()
                    {
                        PrepareOutcome::Prepared(transaction) => Some(transaction),
                        _ => unreachable!(),
                    }
                } else {
                    if replace_inode {
                        fs::rename(&named, fixture.root.path().join("detached.toml")).unwrap();
                    }
                    fs::write(&named, b"# external edit\n").unwrap();
                    let error =
                        super::apply_repair(&test_receipts(&guard), &request, destinations, || {
                            Ok(())
                        })
                        .unwrap_err();
                    assert!(error.to_string().contains("RevisionConflict"), "{error:#}");
                    assert!(!fixture.root.path().join(TXN_DIR_NAME).exists());
                    None
                };
                if let Some(transaction) = transaction {
                    if replace_inode {
                        fs::rename(&named, fixture.root.path().join("detached.toml")).unwrap();
                    }
                    fs::write(&named, b"# external edit\n").unwrap();
                    assert_eq!(
                        transaction.commit().unwrap().persistence,
                        Persistence::DurabilityUncertain
                    );
                    assert!(recover_active(&guard)
                        .unwrap_err()
                        .to_string()
                        .contains("RecoveryConflict"));
                }
                assert_eq!(fs::read(&named).unwrap(), b"# external edit\n");
                assert_eq!(
                    fs::read(fixture.root.path().join("packs/orphan.txt")).unwrap(),
                    b"orphan.example\n"
                );
            }
        }
    }

    #[test]
    fn repair_rejects_named_drift_inside_candidate_validation_before_intent() {
        let fixture = Fixture::new();
        let guard = fixture.guard();
        let destinations = RepairDestinationSet::capture(&guard, &fixture.after).unwrap();
        let request = repair_request(&destinations);
        let error = super::apply_repair(&test_receipts(&guard), &request, destinations, || {
            fs::write(
                fixture.root.path().join("include.toml"),
                b"# external edit\n",
            )?;
            Ok(())
        })
        .unwrap_err();
        assert!(error.to_string().contains("RevisionConflict"));
        assert!(!fixture.root.path().join(TXN_DIR_NAME).exists());
    }

    #[test]
    fn repair_scope_decoder_is_strict_and_legacy_defaults_to_policy_tree() {
        let fixture = Fixture::new();
        let guard = fixture.guard();
        let transaction = fixture.prepare(&guard);
        let mut legacy = serde_json::to_value(&*transaction.journal.borrow()).unwrap();
        legacy.as_object_mut().unwrap().remove("revision_scope");
        legacy["receipt"]
            .as_object_mut()
            .unwrap()
            .remove("revision_scope");
        assert_eq!(
            decode(&serde_json::to_vec(&legacy).unwrap(), guard.tree_io())
                .unwrap()
                .revision_scope,
            RevisionScope::PolicyTreeV1
        );
        for value in [
            serde_json::json!("future"),
            serde_json::json!(null),
            serde_json::json!({}),
            serde_json::json!(4),
        ] {
            for receipt in [false, true] {
                let mut malformed = legacy.clone();
                if receipt {
                    malformed["receipt"]["revision_scope"] = value.clone();
                } else {
                    malformed["revision_scope"] = value.clone();
                }
                assert!(decode(&serde_json::to_vec(&malformed).unwrap(), guard.tree_io()).is_err());
            }
        }
        let mut mismatch = legacy;
        mismatch["revision_scope"] = serde_json::json!("repair_destination_set_v1");
        assert!(decode(&serde_json::to_vec(&mismatch).unwrap(), guard.tree_io()).is_err());
    }

    #[test]
    fn repair_plans_cannot_capture_or_serialize_deletions() {
        let fixture = Fixture::new();
        let guard = fixture.guard();
        let deletion = PolicyRevisionInventory::new(vec![
            fixture.after.members()[0].clone(),
            PolicyRevisionMember::absent(PolicyMemberKind::Include, PathBuf::from("include.toml"))
                .unwrap(),
        ])
        .unwrap();
        assert!(RepairDestinationSet::capture(&guard, &deletion).is_err());
        let transaction = prepared_repair(&fixture, &guard);
        let mut journal = transaction.journal.borrow().clone();
        let member = journal
            .members
            .iter_mut()
            .find(|member| member.role == MemberRole::Include)
            .unwrap();
        member.operation = Some(MemberOperation::Delete);
        member.after = None;
        assert!(encode(&journal)
            .unwrap_err()
            .to_string()
            .contains("deletions"));
        assert!(decode(&serde_json::to_vec(&journal).unwrap(), guard.tree_io()).is_err());
    }

    #[test]
    fn repair_promotion_faults_restore_absent_and_invalid_preimages() {
        for missing_master in [false, true] {
            for point in [FaultPoint::BeforePromotion, FaultPoint::AfterPromotion] {
                for skip in 0..4 {
                    let fixture = Fixture::new();
                    if missing_master {
                        fs::remove_file(fixture.master()).unwrap();
                    } else {
                        fs::write(fixture.master(), b"[broken").unwrap();
                    }
                    let guard = fixture.guard();
                    let transaction = prepared_repair(&fixture, &guard);
                    assert_eq!(
                        with_fault(point, skip, || transaction.commit())
                            .unwrap()
                            .persistence,
                        Persistence::DurabilityUncertain
                    );
                    let RecoveryOutcome::Recovered(receipt) = recover_active(&guard).unwrap()
                    else {
                        panic!("expected recovery")
                    };
                    assert_eq!(receipt.persistence, Persistence::Aborted);
                    assert_eq!(
                        receipt.revision_scope,
                        RevisionScope::RepairDestinationSetV1
                    );
                    if missing_master {
                        assert!(!fixture.master().exists());
                    } else {
                        assert_eq!(fs::read(fixture.master()).unwrap(), b"[broken");
                    }
                    assert_eq!(
                        fs::read(fixture.root.path().join("include.toml")).unwrap(),
                        b"# original include\n"
                    );
                    assert!(!fixture.root.path().join("packs/new.txt").exists());
                    assert_no_write_stages(fixture.root.path());
                }
            }
        }
    }

    #[test]
    fn mixed_commit_is_private_preserves_metadata_and_leaves_orphans() {
        let fixture = Fixture::new();
        fs::set_permissions(
            fixture.root.path().join("include.toml"),
            Permissions::from_mode(0o604),
        )
        .unwrap();
        let original = fs::metadata(fixture.root.path().join("include.toml")).unwrap();
        let guard = fixture.guard();
        let transaction = fixture.prepare(&guard);
        assert_eq!(transaction.receipt().persistence, Persistence::Prepared);
        assert!(migration_journal::refuse_normal_access(guard.tree_io()).is_err());
        let receipt = transaction.commit().unwrap();
        assert_eq!(receipt.persistence, Persistence::Committed);
        assert_eq!(receipt.changed_members, 5);
        fixture.assert_inventory(&fixture.after);
        assert!(!fixture.root.path().join("packs/old.txt").exists());
        assert_eq!(
            fs::read(fixture.root.path().join("packs/orphan.txt")).unwrap(),
            b"orphan.example\n"
        );
        let replaced = fs::metadata(fixture.root.path().join("include.toml")).unwrap();
        assert_eq!(
            (original.uid(), original.gid(), original.mode()),
            (replaced.uid(), replaced.gid(), replaced.mode())
        );
        let store = fixture.root.path().join(STORE_DIR_NAME);
        assert_eq!(fs::metadata(&store).unwrap().mode() & 0o7777, 0o700);
        let namespace = store.join(master_namespace(guard.canonical_master()));
        assert_eq!(fs::metadata(&namespace).unwrap().mode() & 0o7777, 0o700);
        let undo = namespace.join(request_key("operator-1", "request-1"));
        assert_eq!(fs::metadata(&undo).unwrap().mode() & 0o7777, 0o700);
        for entry in fs::read_dir(undo).unwrap() {
            let meta = entry.unwrap().metadata().unwrap();
            assert!(meta.is_file());
            assert_eq!(meta.mode() & 0o7777, 0o600);
            assert_eq!(meta.nlink(), 1);
        }
        migration_journal::refuse_normal_write(guard.tree_io()).unwrap();
    }

    #[test]
    fn stale_revision_and_stale_member_fail_before_intent() {
        let fixture = Fixture::new();
        let guard = fixture.guard();
        let mut request = fixture.request();
        request.expected_revision = fixture.after.revision();
        assert!(
            apply(&guard, &request, &fixture.before, &fixture.after, || Ok(()))
                .unwrap_err()
                .to_string()
                .contains("RevisionConflict")
        );
        fs::write(
            fixture.root.path().join("packs/old.txt"),
            b"external.example\n",
        )
        .unwrap();
        assert!(apply(
            &guard,
            &fixture.request(),
            &fixture.before,
            &fixture.after,
            || Ok(())
        )
        .unwrap_err()
        .to_string()
        .contains("RevisionConflict"));
        assert!(!fixture.root.path().join(TXN_DIR_NAME).exists());
    }

    #[test]
    fn validator_failure_does_not_publish_intent() {
        let fixture = Fixture::new();
        let guard = fixture.guard();
        assert!(apply(
            &guard,
            &fixture.request(),
            &fixture.before,
            &fixture.after,
            || bail!("invalid candidate graph")
        )
        .is_err());
        fixture.assert_inventory(&fixture.before);
        assert!(!fixture.root.path().join(TXN_DIR_NAME).exists());
    }

    #[test]
    fn restart_replay_is_identical_and_payload_or_precondition_reuse_conflicts() {
        let fixture = Fixture::new();
        let first = {
            let guard = fixture.guard();
            apply(
                &guard,
                &fixture.request(),
                &fixture.before,
                &fixture.after,
                || Ok(()),
            )
            .unwrap()
        };
        let guard = fixture.guard();
        let replay = apply(
            &guard,
            &fixture.request(),
            &fixture.before,
            &fixture.after,
            || bail!("must not revalidate replay"),
        )
        .unwrap();
        assert_eq!(first, replay);
        assert_eq!(
            lookup_receipt(&guard, "operator-1", "request-1").unwrap(),
            Some(first)
        );
        let mut request = fixture.request();
        request.payload.push(b'!');
        assert!(
            apply(&guard, &request, &fixture.before, &fixture.after, || Ok(()))
                .unwrap_err()
                .to_string()
                .contains("IdempotencyConflict")
        );
        request = fixture.request();
        request.expected_revision = fixture.after.revision();
        assert!(
            apply(&guard, &request, &fixture.before, &fixture.after, || Ok(()))
                .unwrap_err()
                .to_string()
                .contains("IdempotencyConflict")
        );
    }

    #[test]
    fn admission_saturates_without_eviction_and_store_failures_precede_mutation() {
        let fixture = Fixture::new();
        let guard = fixture.guard();
        fixture.prepare(&guard).commit().unwrap();
        let tree = guard.tree_io();
        let owner = tree.identity.owner_metadata(tree.root).unwrap();
        let store = open_store(tree, &owner, false).unwrap().unwrap();
        assert!(test_receipts(&guard)
            .admit(tree, &store, unix_seconds().unwrap(), 1)
            .unwrap_err()
            .to_string()
            .contains("IdempotencyStoreFull"));
        assert_eq!(MAX_RECEIPTS, 4096);
        assert_eq!(MIN_RETENTION_SECONDS, 86_400);
        fs::set_permissions(
            fixture.root.path().join(STORE_DIR_NAME),
            Permissions::from_mode(0o755),
        )
        .unwrap();
        let mut request = fixture.request();
        request.request_id = "second".into();
        request.expected_revision = fixture.after.revision();
        assert!(apply(&guard, &request, &fixture.after, &fixture.after, || Ok(())).is_err());
        assert!(!fixture.root.path().join(TXN_DIR_NAME).exists());
    }

    #[test]
    fn abandoned_prepared_intent_recovers_and_retry_returns_aborted_receipt() {
        let fixture = Fixture::new();
        let original = {
            let guard = fixture.guard();
            let transaction = fixture.prepare(&guard);
            transaction.receipt()
        };
        let guard = fixture.guard();
        let RecoveryOutcome::Recovered(receipt) = recover_active(&guard).unwrap() else {
            panic!("expected recovery");
        };
        assert_eq!(receipt.transaction_id, original.transaction_id);
        assert_eq!(receipt.persistence, Persistence::Aborted);
        fixture.assert_inventory(&fixture.before);
        assert_eq!(
            apply(
                &guard,
                &fixture.request(),
                &fixture.before,
                &fixture.after,
                || Ok(())
            )
            .unwrap(),
            *receipt
        );
        assert_eq!(recover_active(&guard).unwrap(), RecoveryOutcome::Absent);
    }

    #[test]
    fn promotion_interruptions_restore_create_replace_delete_after_restart() {
        for skip in 0..5 {
            let fixture = Fixture::new();
            {
                let guard = fixture.guard();
                let transaction = fixture.prepare(&guard);
                let receipt =
                    with_fault(FaultPoint::AfterPromotion, skip, || transaction.commit()).unwrap();
                assert_eq!(receipt.persistence, Persistence::DurabilityUncertain);
            }
            let guard = fixture.guard();
            let RecoveryOutcome::Recovered(receipt) = recover_active(&guard).unwrap() else {
                panic!("expected recovery");
            };
            assert_eq!(receipt.persistence, Persistence::Aborted);
            fixture.assert_inventory(&fixture.before);
            assert!(!fixture.root.path().join("packs/new.txt").exists());
        }
    }

    #[test]
    fn handled_pre_promotion_failure_clears_owned_pack_staging() {
        let fixture = Fixture::new();
        let guard = fixture.guard();
        let transaction = fixture.prepare(&guard);
        let receipt = with_fault(FaultPoint::BeforePromotion, 1, || transaction.commit()).unwrap();
        assert_eq!(receipt.persistence, Persistence::DurabilityUncertain);
        let tree = guard.tree_io();
        let owner = tree.identity.owner_metadata(tree.root).unwrap();
        let fence = private_dir(tree.root, TXN_DIR_NAME, &owner, false).unwrap();
        assert!(read_journal(&fence, &owner, tree)
            .unwrap()
            .members
            .iter()
            .all(|member| member.staging.is_none() && member.linked_staging.is_none()));
        assert!(matches!(
            recover_active(&guard).unwrap(),
            RecoveryOutcome::Recovered(_)
        ));
        fixture.assert_inventory(&fixture.before);
        assert_policy_loadable(&fixture, &guard);
        assert_no_write_stages(fixture.root.path());
    }

    #[test]
    fn another_crash_during_recovery_remains_recoverable() {
        let fixture = Fixture::new();
        {
            let guard = fixture.guard();
            let transaction = fixture.prepare(&guard);
            with_fault(FaultPoint::AfterPromotion, 2, || transaction.commit()).unwrap();
        }
        {
            let guard = fixture.guard();
            assert!(with_fault(FaultPoint::AfterPromotion, 0, || recover_active(&guard)).is_err());
            assert!(fixture.root.path().join(TXN_DIR_NAME).exists());
        }
        let guard = fixture.guard();
        assert!(matches!(
            recover_active(&guard).unwrap(),
            RecoveryOutcome::Recovered(_)
        ));
        fixture.assert_inventory(&fixture.before);
    }

    #[test]
    fn terminal_reconciliation_cannot_change_an_aborted_decision() {
        let fixture = Fixture::new();
        let guard = fixture.guard();
        drop(fixture.prepare(&guard));
        recover_active(&guard).unwrap();
        let receipts = test_receipts(&guard);
        let tree = guard.tree_io();
        let owner = tree.identity.owner_metadata(tree.root).unwrap();
        let key = request_key("operator-1", "request-1");
        let store = open_store(tree, &owner, false).unwrap().unwrap();
        let undo = private_dir(&store, &key, &owner, false).unwrap();
        let mut journal = read_journal(&undo, &owner, tree).unwrap();
        assert_eq!(journal.phase, Phase::Aborted);
        journal.phase = Phase::Committed;
        journal.receipt.persistence = Persistence::Committed;
        // Supply structurally valid forged promotion evidence so rejection
        // must come from the durable aborted decision, not journal shape.
        for member in &mut journal.members {
            if matches!(
                member.operation,
                Some(MemberOperation::Create | MemberOperation::Replace)
            ) {
                member.promoted_inode = Some(Inode::of(&tree.root.metadata().unwrap()));
            }
        }
        write_journal(&undo, &owner, &journal).unwrap();
        let before = read_optional_private(
            &receipts.directory,
            &format!("{key}.json"),
            &receipts.owner,
            MAX_MANIFEST_BYTES,
        )
        .unwrap();
        let error = lookup_receipt(&guard, "operator-1", "request-1").unwrap_err();
        assert!(error.to_string().contains("regresses"), "{error:#}");
        assert_eq!(
            read_optional_private(
                &receipts.directory,
                &format!("{key}.json"),
                &receipts.owner,
                MAX_MANIFEST_BYTES
            )
            .unwrap(),
            before
        );
        fixture.assert_inventory(&fixture.before);
    }

    #[test]
    fn terminal_reconciliation_preserves_newer_activation_and_audit_observations() {
        let fixture = Fixture::new();
        let guard = fixture.guard();
        let receipt = fixture.prepare(&guard).commit().unwrap();
        let receipts = test_receipts(&guard);
        super::complete_receipt_activation(
            &guard,
            &receipts,
            &receipt.actor,
            &receipt.request_id,
            &receipt.transaction_id,
            ReceiptCompletion::Applied {
                correlation_id: "verified-reload".into(),
                active_config_revision: receipt.after_revision.clone(),
                active_policy_hash: "a".repeat(64),
                daemon_instance_id: "daemon-1".into(),
            },
        )
        .unwrap();
        let observed = super::mark_receipt_audit_recorded(
            &guard,
            &receipts,
            &receipt.actor,
            &receipt.request_id,
            &receipt.transaction_id,
        )
        .unwrap();
        // The retained terminal journal still predates these observations.
        let recovered = lookup_receipt(&guard, &receipt.actor, &receipt.request_id)
            .unwrap()
            .unwrap();
        assert_eq!(recovered, observed);
        assert_eq!(recovered.activation.state, ReceiptActivationState::Applied);
        assert!(!recovered.audit_pending);
    }

    #[test]
    fn rename_and_fsync_failures_report_uncertainty_and_recover_commit_decision() {
        for point in [
            FaultPoint::BeforeTerminalRename,
            FaultPoint::AfterTerminalRename,
            FaultPoint::RootFsync,
        ] {
            let fixture = Fixture::new();
            {
                let guard = fixture.guard();
                let transaction = fixture.prepare(&guard);
                let receipt = with_fault(point, 0, || transaction.commit()).unwrap();
                assert_eq!(receipt.persistence, Persistence::DurabilityUncertain);
            }
            let guard = fixture.guard();
            let receipt = lookup_receipt(&guard, "operator-1", "request-1")
                .unwrap()
                .unwrap();
            assert_eq!(receipt.persistence, Persistence::Committed);
            fixture.assert_inventory(&fixture.after);
            migration_journal::refuse_normal_write(guard.tree_io()).unwrap();
        }
    }

    #[test]
    fn journal_rename_and_fsync_failures_never_promote_without_durable_preimages() {
        for point in [
            FaultPoint::JournalRename,
            FaultPoint::JournalFsync,
            FaultPoint::WriteBlob,
        ] {
            let fixture = Fixture::new();
            {
                let guard = fixture.guard();
                assert!(with_fault(point, 1, || prepare(
                    &guard,
                    &fixture.request(),
                    &fixture.before,
                    &fixture.after,
                    || Ok(())
                ))
                .is_err());
                fixture.assert_inventory(&fixture.before);
            }
            let guard = fixture.guard();
            assert!(!matches!(
                recover_active(&guard).unwrap(),
                RecoveryOutcome::LegacyActive
            ));
            fixture.assert_inventory(&fixture.before);
        }
    }

    #[test]
    fn rollback_restores_mixed_plan_and_is_idempotent() {
        let fixture = Fixture::new();
        {
            let guard = fixture.guard();
            fixture.prepare(&guard).commit().unwrap();
        }
        let guard = fixture.guard();
        let RollbackOutcome::Restored(receipt) =
            rollback(&guard, "operator-1", "request-1").unwrap()
        else {
            panic!("expected restore");
        };
        assert!(receipt.rollback_restored);
        assert_eq!(receipt.persistence, Persistence::Committed);
        fixture.assert_inventory(&fixture.before);
        assert!(!fixture.root.path().join("packs/new.txt").exists());
        assert_eq!(
            rollback(&guard, "operator-1", "request-1").unwrap(),
            RollbackOutcome::Restored(receipt)
        );
        migration_journal::refuse_normal_write(guard.tree_io()).unwrap();
    }

    #[test]
    fn unchanged_member_evidence_attests_the_full_inventory_without_live_recapture() {
        let fixture = Fixture::new();
        let guard = fixture.guard();
        let request = fixture.request();
        let receipt = apply(
            &guard,
            &request,
            &fixture.before,
            &fixture.before,
            || Ok(()),
        )
        .unwrap();
        assert_eq!(receipt.changed_members, 0);
        let receipts = test_receipts(&guard);
        let (stored, evidence) = lookup_operation_member_evidence(
            &guard,
            &receipts,
            &request.actor,
            &receipt.transaction_id,
        )
        .unwrap()
        .unwrap();
        assert_eq!(stored, receipt);
        assert_eq!(evidence.len(), fixture.before.members().len());
        assert!(evidence.iter().all(|member| member.operation.is_none()
            && member.before_digest == member.after_digest
            && member.before_length == member.after_length
            && member.before_uid == member.after_uid
            && member.before_gid == member.after_gid
            && member.before_mode == member.after_mode
            && member.before_inode.is_some()
            && member.before_device.is_some()
            && member.promoted_inode.is_none()
            && member.promoted_device.is_none()
            && member.restored_inode.is_none()
            && member.restored_digest.is_none()));
        fs::remove_file(fixture.root.path().join("packs/kept.txt")).unwrap();
        fs::write(
            fixture.root.path().join("packs/kept.txt"),
            b"foreign replacement",
        )
        .unwrap();
        let (_, retained) = lookup_operation_member_evidence(
            &guard,
            &receipts,
            &request.actor,
            &receipt.transaction_id,
        )
        .unwrap()
        .unwrap();
        assert_eq!(retained, evidence);
    }

    #[test]
    fn terminal_member_evidence_comes_from_the_owned_journal() {
        let fixture = Fixture::new();
        let guard = fixture.guard();
        let receipt = fixture.prepare(&guard).commit().unwrap();
        let receipts = test_receipts(&guard);
        let (stored, evidence) = lookup_operation_member_evidence(
            &guard,
            &receipts,
            "operator-1",
            &receipt.transaction_id,
        )
        .unwrap()
        .unwrap();
        assert_eq!(stored, receipt);
        assert_eq!(
            evidence
                .iter()
                .filter(|member| member.operation.is_some())
                .count(),
            receipt.changed_members
        );
        let created = evidence
            .iter()
            .find(|entry| entry.operation == Some(MemberOperation::Create))
            .unwrap();
        assert!(created.after_digest.is_some());
        assert!(created.promoted_device.is_some());
        assert!(created.promoted_inode.is_some());
        assert!(created.before_digest.is_none());
        assert!(created.restored_digest.is_none());
        let deleted = evidence
            .iter()
            .find(|entry| entry.operation == Some(MemberOperation::Delete))
            .unwrap();
        assert!(deleted.after_digest.is_none());
        assert!(deleted.promoted_device.is_none());
        assert!(deleted.promoted_inode.is_none());
        assert!(deleted.before_digest.is_some());
        assert!(deleted.before_device.is_some());
        assert!(deleted.before_inode.is_some());
        assert!(deleted.restored_digest.is_none());

        fs::remove_file(fixture.root.path().join(&created.path)).unwrap();
        fs::write(
            fixture.root.path().join(&created.path),
            b"foreign replacement",
        )
        .unwrap();
        let (_, recorded) = lookup_operation_member_evidence(
            &guard,
            &receipts,
            "operator-1",
            &receipt.transaction_id,
        )
        .unwrap()
        .unwrap();
        assert_eq!(recorded, evidence);
    }

    #[test]
    fn rolled_back_member_evidence_records_the_restored_inode_across_reopen() {
        let fixture = Fixture::new();
        let operation_id;
        let expected;
        {
            let guard = fixture.guard();
            let committed = fixture.prepare(&guard).commit().unwrap();
            operation_id = committed.transaction_id;
            let RollbackOutcome::Restored(restored) =
                rollback(&guard, "operator-1", "request-1").unwrap()
            else {
                panic!("expected restore");
            };
            let receipts = test_receipts(&guard);
            let (stored, evidence) =
                lookup_operation_member_evidence(&guard, &receipts, "operator-1", &operation_id)
                    .unwrap()
                    .unwrap();
            assert_eq!(stored, *restored);
            let replaced = evidence
                .iter()
                .find(|entry| entry.operation == Some(MemberOperation::Replace))
                .unwrap();
            assert_eq!(replaced.restored_digest, replaced.before_digest);
            assert_eq!(replaced.restored_length, replaced.before_length);
            assert_eq!(replaced.restored_uid, replaced.before_uid);
            assert_eq!(replaced.restored_gid, replaced.before_gid);
            assert_eq!(replaced.restored_mode, replaced.before_mode);
            assert!(replaced.restored_device.is_some());
            assert!(replaced.restored_inode.is_some());
            assert_ne!(replaced.restored_inode, replaced.promoted_inode);
            expected = evidence;
        }

        let guard = fixture.guard();
        let receipts = test_receipts(&guard);
        let (_, reopened) =
            lookup_operation_member_evidence(&guard, &receipts, "operator-1", &operation_id)
                .unwrap()
                .unwrap();
        assert_eq!(reopened, expected);
    }

    #[test]
    fn versioned_operation_manifest_is_durable_before_promotion() {
        let fixture = Fixture::new();
        let guard = fixture.guard();
        let receipts = test_receipts(&guard);
        let manifest = serde_json::json!({
            "manifest_version": 1,
            "kind": "test_publication",
            "members": ["config.toml"]
        });
        let outcome = super::prepare_with_hook(
            &guard,
            &receipts,
            &fixture.request(),
            PolicyRevisionTransition::new(&fixture.before, &fixture.after),
            ReceiptPreparationContext {
                operator_plan_hash: None,
                semantic: ReceiptSemanticContext::default(),
                operation_manifest: Some(manifest.clone()),
            },
            || Ok(()),
            |prepared| assert_eq!(prepared.operation_manifest.as_ref(), Some(&manifest)),
        )
        .unwrap();
        let receipt = match outcome {
            PrepareOutcome::Prepared(transaction) => transaction.commit().unwrap(),
            PrepareOutcome::Replay(_) => panic!("unexpected replay"),
        };
        assert_eq!(receipt.operation_manifest, Some(manifest));
        assert_eq!(
            lookup_receipt(&guard, "operator-1", "request-1")
                .unwrap()
                .unwrap()
                .operation_manifest,
            receipt.operation_manifest
        );
    }

    #[test]
    fn schema5_candidate_commits_and_terminal_undo_revalidates_offline() {
        let root = tempfile::tempdir().unwrap();
        let before_master = include_bytes!("../../tests/fixtures/target-v5/config.toml");
        let mut after_master = before_master.to_vec();
        after_master.extend_from_slice(b"\n# committed candidate\n");
        let before = schema5_inventory(before_master);
        let after = schema5_inventory(&after_master);
        write_schema5_inventory(root.path(), &before);
        let master = root.path().join("config.toml");
        let guard = super::super::write_lock::acquire_for_migration(&master).unwrap();
        let request = TransactionRequest {
            request_id: "schema5-commit".into(),
            actor: "operator".into(),
            origin: "offline".into(),
            operation: "edit".into(),
            payload: Vec::new(),
            expected_revision: before.revision(),
            source_schema: 5,
            target_schema: 5,
        };

        assert_eq!(
            apply(&guard, &request, &before, &after, || Ok(()))
                .unwrap()
                .persistence,
            Persistence::Committed
        );
        assert_eq!(fs::read(&master).unwrap(), after_master);
        let orphan = root.path().join("packs/orphan.txt");
        fs::write(&orphan, b"orphan.example\n").unwrap();
        let orphan_inode = fs::metadata(&orphan).unwrap().ino();
        assert!(matches!(
            rollback(&guard, "operator", "schema5-commit").unwrap(),
            RollbackOutcome::Restored(_)
        ));
        assert_eq!(fs::read(&master).unwrap(), before_master);
        assert_eq!(fs::metadata(&orphan).unwrap().ino(), orphan_inode);
        assert_eq!(fs::read(&orphan).unwrap(), b"orphan.example\n");
    }

    #[test]
    fn schema5_terminal_undo_checks_loaded_secret_references() {
        for (reference, should_restore) in [
            ("missing-private-token", false),
            ("known-private-token", true),
        ] {
            let root = tempfile::tempdir().unwrap();
            let before_master = include_bytes!("../../tests/fixtures/target-v5/config.toml");
            let after_master = schema5_master_with_token_ref(reference);
            let before = schema5_inventory(before_master);
            let after = schema5_inventory(&after_master);
            write_schema5_inventory(root.path(), &before);
            let secrets = root.path().join(super::super::secrets::SECRETS_FILENAME);
            fs::write(&secrets, "known-private-token = \"secret\"\n").unwrap();
            fs::set_permissions(&secrets, Permissions::from_mode(0o600)).unwrap();
            let master = root.path().join("config.toml");
            let guard = super::super::write_lock::acquire_for_migration(&master).unwrap();
            let request = TransactionRequest {
                request_id: format!("schema5-secret-{reference}"),
                actor: "operator".into(),
                origin: "offline".into(),
                operation: "edit".into(),
                payload: Vec::new(),
                expected_revision: before.revision(),
                source_schema: 5,
                target_schema: 5,
            };
            let receipt = apply(&guard, &request, &before, &after, || Ok(())).unwrap();

            let outcome = rollback(&guard, "operator", &request.request_id).unwrap();
            if should_restore {
                assert_eq!(receipt.persistence, Persistence::Committed);
                assert!(matches!(outcome, RollbackOutcome::Restored(_)));
                assert_eq!(fs::read(&master).unwrap(), before_master);
            } else {
                assert_eq!(receipt.persistence, Persistence::DurabilityUncertain);
                assert_eq!(outcome, RollbackOutcome::RollbackNotApplicable);
                assert_eq!(fs::read(&master).unwrap(), before_master);
            }
        }
    }

    #[test]
    fn schema5_terminal_undo_refuses_unsafe_foreign_pack_entries() {
        for variant in ["nested", "symlink", "hardlink", "fifo"] {
            let root = tempfile::tempdir().unwrap();
            let before_master = include_bytes!("../../tests/fixtures/target-v5/config.toml");
            let mut after_master = before_master.to_vec();
            after_master.extend_from_slice(format!("\n# {variant} candidate\n").as_bytes());
            let before = schema5_inventory(before_master);
            let after = schema5_inventory(&after_master);
            write_schema5_inventory(root.path(), &before);
            let master = root.path().join("config.toml");
            let guard = super::super::write_lock::acquire_for_migration(&master).unwrap();
            let request = TransactionRequest {
                request_id: format!("schema5-unsafe-{variant}"),
                actor: "operator".into(),
                origin: "offline".into(),
                operation: "edit".into(),
                payload: Vec::new(),
                expected_revision: before.revision(),
                source_schema: 5,
                target_schema: 5,
            };
            apply(&guard, &request, &before, &after, || Ok(())).unwrap();
            let packs = root.path().join("packs");
            match variant {
                "nested" => fs::create_dir(packs.join("nested")).unwrap(),
                "symlink" => symlink("../config.toml", packs.join("linked.txt")).unwrap(),
                "hardlink" => {
                    let source = root.path().join("foreign-source");
                    fs::write(&source, b"foreign\n").unwrap();
                    fs::hard_link(source, packs.join("linked.txt")).unwrap();
                }
                "fifo" => {
                    let path =
                        CString::new(packs.join("special.txt").as_os_str().as_bytes()).unwrap();
                    // SAFETY: path is a valid, NUL-terminated pathname in the owned fixture.
                    assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
                }
                _ => unreachable!(),
            }

            assert_eq!(
                rollback(&guard, "operator", &request.request_id).unwrap(),
                RollbackOutcome::RollbackNotApplicable,
                "variant {variant}"
            );
            assert_eq!(
                fs::read(&master).unwrap(),
                after_master,
                "variant {variant}"
            );
            assert_eq!(
                fs::read(root.path().join("packs/streaming.txt")).unwrap(),
                include_bytes!("../../tests/fixtures/target-v5/packs/streaming.txt"),
                "variant {variant}"
            );
        }
    }

    #[test]
    fn interrupted_schema5_commit_recovers_through_target_validation() {
        let root = tempfile::tempdir().unwrap();
        let before_master = include_bytes!("../../tests/fixtures/target-v5/config.toml");
        let mut after_master = before_master.to_vec();
        after_master.extend_from_slice(b"\n# interrupted candidate\n");
        let before = schema5_inventory(before_master);
        let after = schema5_inventory(&after_master);
        write_schema5_inventory(root.path(), &before);
        let master = root.path().join("config.toml");
        let guard = super::super::write_lock::acquire_for_migration(&master).unwrap();
        let request = TransactionRequest {
            request_id: "schema5-recovery".into(),
            actor: "operator".into(),
            origin: "offline".into(),
            operation: "edit".into(),
            payload: Vec::new(),
            expected_revision: before.revision(),
            source_schema: 5,
            target_schema: 5,
        };
        let PrepareOutcome::Prepared(transaction) =
            prepare(&guard, &request, &before, &after, || Ok(())).unwrap()
        else {
            panic!("unexpected replay");
        };
        assert_eq!(
            with_fault(FaultPoint::AfterPromotion, 0, || transaction.commit())
                .unwrap()
                .persistence,
            Persistence::DurabilityUncertain
        );

        let RecoveryOutcome::Recovered(receipt) = recover_active(&guard).unwrap() else {
            panic!("expected schema-5 recovery");
        };
        assert_eq!(receipt.persistence, Persistence::Aborted);
        assert_eq!(fs::read(&master).unwrap(), before_master);
        let receipts = test_receipts(&guard);
        let (stored, evidence) = lookup_operation_member_evidence(
            &guard,
            &receipts,
            "operator",
            &receipt.transaction_id,
        )
        .unwrap()
        .unwrap();
        assert_eq!(stored, *receipt);
        assert_eq!(receipt.changed_members, 1);
        let replaced = evidence
            .iter()
            .find(|member| member.operation == Some(MemberOperation::Replace))
            .unwrap();
        assert_eq!(replaced.restored_digest, replaced.before_digest);
        assert_eq!(replaced.restored_length, replaced.before_length);
        assert_eq!(replaced.restored_uid, replaced.before_uid);
        assert_eq!(replaced.restored_gid, replaced.before_gid);
        assert_eq!(replaced.restored_mode, replaced.before_mode);
        assert!(replaced.restored_device.is_some());
        assert!(replaced.restored_inode.is_some());
        assert_ne!(replaced.restored_inode, replaced.promoted_inode);
        assert!(evidence
            .iter()
            .filter(|member| member.operation.is_none())
            .all(|member| member.before_digest == member.after_digest
                && member.before_length == member.after_length
                && member.before_uid == member.after_uid
                && member.before_gid == member.after_gid
                && member.before_mode == member.after_mode
                && member.before_device.is_some()
                && member.before_inode.is_some()
                && member.promoted_device.is_none()
                && member.promoted_inode.is_none()
                && member.restored_device.is_none()
                && member.restored_inode.is_none()
                && member.restored_digest.is_none()));
    }

    #[test]
    fn schema3_commit_and_interrupted_recovery_use_the_historical_loader() {
        for interrupted in [false, true] {
            let root = tempfile::tempdir().unwrap();
            let before_master =
                "schema_version = 3\n# before\n[upstream]\nservers = [\"192.0.2.1:53\"]\n";
            let after_master =
                "schema_version = 3\n# after\n[upstream]\nservers = [\"192.0.2.1:53\"]\n";
            let before = inventory(&[(PolicyMemberKind::Master, "config.toml", before_master)]);
            let after = inventory(&[(PolicyMemberKind::Master, "config.toml", after_master)]);
            let master = root.path().join("config.toml");
            fs::write(&master, before_master).unwrap();
            let guard = super::super::write_lock::acquire_for_migration(&master).unwrap();
            let request = TransactionRequest {
                request_id: format!("schema3-{interrupted}"),
                actor: "operator".into(),
                origin: "offline".into(),
                operation: "edit".into(),
                payload: Vec::new(),
                expected_revision: before.revision(),
                source_schema: 3,
                target_schema: 3,
            };

            if interrupted {
                let PrepareOutcome::Prepared(transaction) =
                    prepare(&guard, &request, &before, &after, || Ok(())).unwrap()
                else {
                    panic!("unexpected replay");
                };
                assert_eq!(
                    with_fault(FaultPoint::AfterPromotion, 0, || transaction.commit())
                        .unwrap()
                        .persistence,
                    Persistence::DurabilityUncertain
                );
                assert!(matches!(
                    recover_active(&guard).unwrap(),
                    RecoveryOutcome::Recovered(_)
                ));
                assert_eq!(fs::read(&master).unwrap(), before_master.as_bytes());
            } else {
                assert_eq!(
                    apply(&guard, &request, &before, &after, || Ok(()))
                        .unwrap()
                        .persistence,
                    Persistence::Committed
                );
                assert_eq!(fs::read(&master).unwrap(), after_master.as_bytes());
                assert!(matches!(
                    rollback(&guard, "operator", &request.request_id).unwrap(),
                    RollbackOutcome::Restored(_)
                ));
                assert_eq!(fs::read(&master).unwrap(), before_master.as_bytes());
            }
        }
    }

    #[test]
    fn terminal_undo_allows_later_edit_and_old_rollback_becomes_inapplicable() {
        let fixture = Fixture::new();
        let guard = fixture.guard();
        fixture.prepare(&guard).commit().unwrap();
        migration_journal::refuse_normal_write(guard.tree_io()).unwrap();
        let mut second = fixture.request();
        second.request_id = "second".into();
        second.expected_revision = fixture.after.revision();
        let mut members = fixture.after.members().to_vec();
        members.retain(|member| member.path() != Path::new("packs/new.txt"));
        members.push(
            PolicyRevisionMember::present(
                PolicyMemberKind::Pack,
                PathBuf::from("packs/new.txt"),
                b"later.example\n".to_vec(),
            )
            .unwrap(),
        );
        let later = PolicyRevisionInventory::new(members).unwrap();
        assert_eq!(
            apply(&guard, &second, &fixture.after, &later, || Ok(()))
                .unwrap()
                .persistence,
            Persistence::Committed
        );
        assert_eq!(
            rollback(&guard, "operator-1", "request-1").unwrap(),
            RollbackOutcome::RollbackNotApplicable
        );
        fixture.assert_inventory(&later);
    }

    #[test]
    fn terminal_undo_rejects_a_new_glob_selected_include() {
        let root = tempfile::tempdir().unwrap();
        let includes = root.path().join("profiles.d");
        fs::create_dir(&includes).unwrap();
        let master = root.path().join("config.toml");
        let before_master = "schema_version = 4\nincludes = [\"profiles.d/*.toml\"]\n# before\n[upstream]\nservers = [\"192.0.2.1:53\"]\n";
        let after_master = "schema_version = 4\nincludes = [\"profiles.d/*.toml\"]\n# after\n[upstream]\nservers = [\"192.0.2.1:53\"]\n";
        let before = inventory(&[
            (PolicyMemberKind::Master, "config.toml", before_master),
            (
                PolicyMemberKind::Include,
                "profiles.d/existing.toml",
                "# existing before\n",
            ),
        ]);
        let after = inventory(&[
            (PolicyMemberKind::Master, "config.toml", after_master),
            (
                PolicyMemberKind::Include,
                "profiles.d/existing.toml",
                "# existing after\n",
            ),
        ]);
        for member in before.members() {
            fs::write(
                root.path().join(member.path()),
                member_bytes(member).unwrap(),
            )
            .unwrap();
        }
        let guard = super::super::write_lock::acquire_for_migration(&master).unwrap();
        let request = TransactionRequest {
            request_id: "glob-undo".into(),
            actor: "operator".into(),
            origin: "cli".into(),
            operation: "edit".into(),
            payload: Vec::new(),
            expected_revision: before.revision(),
            source_schema: 4,
            target_schema: 4,
        };
        assert_eq!(
            apply(&guard, &request, &before, &after, || Ok(()))
                .unwrap()
                .persistence,
            Persistence::Committed
        );
        fs::write(includes.join("late.toml"), b"# late policy\n").unwrap();

        assert_eq!(
            rollback(&guard, "operator", "glob-undo").unwrap(),
            RollbackOutcome::RollbackNotApplicable
        );
        assert_eq!(fs::read(&master).unwrap(), after_master.as_bytes());
        assert_eq!(
            fs::read(includes.join("existing.toml")).unwrap(),
            b"# existing after\n"
        );
        assert_eq!(
            fs::read(includes.join("late.toml")).unwrap(),
            b"# late policy\n"
        );
    }

    #[test]
    fn content_or_inode_drift_prevents_recovery_overwrite() {
        for inode_only in [false, true] {
            let fixture = Fixture::new();
            {
                let guard = fixture.guard();
                let transaction = fixture.prepare(&guard);
                with_fault(FaultPoint::AfterPromotion, 0, || transaction.commit()).unwrap();
            }
            let path = fixture.root.path().join("include.toml");
            let bytes = fs::read(&path).unwrap();
            if inode_only {
                let foreign = fixture.root.path().join("foreign");
                fs::write(&foreign, &bytes).unwrap();
                fs::set_permissions(&foreign, Permissions::from_mode(0o640)).unwrap();
                fs::rename(foreign, &path).unwrap();
            } else {
                fs::write(&path, b"# foreign mutation\n").unwrap();
            }
            let expected = fs::read(&path).unwrap();
            let guard = fixture.guard();
            assert!(recover_active(&guard)
                .unwrap_err()
                .to_string()
                .contains("RecoveryConflict"));
            assert_eq!(fs::read(path).unwrap(), expected);
            assert!(fixture.root.path().join(TXN_DIR_NAME).exists());
        }
    }

    #[test]
    fn same_inode_content_drift_after_prepare_is_detected_before_promotion() {
        let fixture = Fixture::new();
        let guard = fixture.guard();
        let transaction = fixture.prepare(&guard);
        let path = fixture.root.path().join("include.toml");
        fs::write(&path, b"# altered in place\n").unwrap();
        let receipt = transaction.commit().unwrap();
        assert_eq!(receipt.persistence, Persistence::DurabilityUncertain);
        assert_eq!(fs::read(path).unwrap(), b"# altered in place\n");
    }

    #[test]
    fn unsupported_pack_subtree_links_and_specials_fail_before_fence() {
        for variant in 0..4 {
            let fixture = Fixture::new();
            let path = fixture.root.path().join("packs/bad.txt");
            match variant {
                0 => fs::create_dir(&path).unwrap(),
                1 => symlink("kept.txt", &path).unwrap(),
                2 => fs::hard_link(fixture.root.path().join("packs/kept.txt"), &path).unwrap(),
                _ => {
                    let cpath = CString::new(path.as_os_str().as_bytes()).unwrap();
                    // SAFETY: cpath is a valid NUL-terminated path and mode is valid.
                    assert_eq!(unsafe { libc::mkfifo(cpath.as_ptr(), 0o600) }, 0);
                }
            }
            let guard = fixture.guard();
            assert!(prepare(
                &guard,
                &fixture.request(),
                &fixture.before,
                &fixture.after,
                || Ok(())
            )
            .is_err());
            assert!(!fixture.root.path().join(TXN_DIR_NAME).exists());
        }
    }

    #[test]
    fn decoder_rejects_unknown_duplicate_path_role_blob_and_staging_fields() {
        let fixture = Fixture::new();
        let guard = fixture.guard();
        let transaction = fixture.prepare(&guard);
        let bytes = encode(&transaction.journal.borrow()).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        for mutation in 0..7 {
            let mut invalid = value.clone();
            match mutation {
                0 => {
                    invalid["future_field"] = true.into();
                }
                1 => {
                    invalid["format_version"] = 3.into();
                }
                2 => {
                    invalid["members"][0]["path"] = "../escape".into();
                }
                3 => {
                    invalid["members"][0]["before"]["blob"] = "../escape".into();
                }
                4 => {
                    invalid["members"][1]["path"] = invalid["members"][0]["path"].clone();
                }
                5 => {
                    invalid["members"][0]["role"] = "directory_tree".into();
                }
                _ => {
                    let uid = invalid["members"][0]["after"]["uid"].clone();
                    let gid = invalid["members"][0]["after"]["gid"].clone();
                    let mode = invalid["members"][0]["after"]["mode"].clone();
                    let length = invalid["members"][0]["after"]["length"].clone();
                    let digest = invalid["members"][0]["after"]["digest"].clone();
                    invalid["members"][0]["promoted_inode"] =
                        serde_json::json!({"device": 1, "inode": 2});
                    invalid["members"][0]["staging"] = serde_json::json!({
                        "parent": {"device": 1, "inode": 1},
                        "name": ".warden-write-ABCDEF0123456789ABCDEF0123456789",
                        "directory": {"device": 1, "inode": 3},
                        "directory_uid": uid.clone(),
                        "directory_gid": gid.clone(),
                        "directory_mode": 448,
                        "payload": {"device": 1, "inode": 2},
                        "payload_uid": uid,
                        "payload_gid": gid,
                        "payload_mode": mode,
                        "payload_links": 1,
                        "payload_length": length,
                        "payload_digest": digest
                    });
                }
            }
            assert!(decode(&serde_json::to_vec(&invalid).unwrap(), guard.tree_io()).is_err());
        }
        let duplicate = String::from_utf8(bytes).unwrap().replacen(
            "\"format_version\":2",
            "\"format_version\":2,\"format_version\":2",
            1,
        );
        assert!(decode(duplicate.as_bytes(), guard.tree_io()).is_err());
    }

    #[test]
    fn legacy_format_is_not_decoded_or_mutated_by_format2() {
        let fixture = Fixture::new();
        let guard = fixture.guard();
        migration_journal::create_fence(&guard).unwrap();
        let tree = guard.tree_io();
        let owner = tree.identity.owner_metadata(tree.root).unwrap();
        let fence = private_dir(tree.root, TXN_DIR_NAME, &owner, false).unwrap();
        let bytes = br#"{"format_version":1,"legacy":"opaque"}"#;
        write_new(&fence, JOURNAL_NAME, bytes, &owner).unwrap();
        assert_eq!(
            recover_active(&guard).unwrap(),
            RecoveryOutcome::LegacyActive
        );
        assert_eq!(
            read_optional_private(&fence, JOURNAL_NAME, &owner, MAX_MANIFEST_BYTES)
                .unwrap()
                .unwrap(),
            bytes
        );
    }

    #[test]
    fn noop_receipt_keeps_revision_and_inode() {
        let fixture = Fixture::new();
        let before_inode = Inode::of(&fs::metadata(fixture.master()).unwrap());
        let guard = fixture.guard();
        let receipt = apply(
            &guard,
            &fixture.request(),
            &fixture.before,
            &fixture.before,
            || Ok(()),
        )
        .unwrap();
        assert_eq!(receipt.changed_members, 0);
        assert_eq!(receipt.before_revision, receipt.after_revision);
        assert_eq!(
            before_inode,
            Inode::of(&fs::metadata(fixture.master()).unwrap())
        );
    }

    #[test]
    fn format2_setup_is_identified_atomically_on_both_sides_of_rename() {
        for point in [FaultPoint::SetupReady, FaultPoint::FencePublished] {
            let fixture = Fixture::new();
            {
                let guard = fixture.guard();
                assert!(with_fault(point, 0, || prepare(
                    &guard,
                    &fixture.request(),
                    &fixture.before,
                    &fixture.after,
                    || Ok(())
                ))
                .is_err());
                if fixture.root.path().join(TXN_DIR_NAME).exists() {
                    assert_eq!(
                        fs::read(fixture.root.path().join(TXN_DIR_NAME).join(SETUP_MARKER))
                            .unwrap(),
                        b"2\n"
                    );
                }
            }
            let guard = fixture.guard();
            assert_eq!(
                recover_active(&guard).unwrap(),
                RecoveryOutcome::SetupRemoved
            );
            fixture.assert_inventory(&fixture.before);
        }
    }

    #[test]
    fn format2_setup_cleanup_survives_sigkill() {
        for point in [
            FaultPoint::SetupCleanupPublished,
            FaultPoint::SetupCleanupMemberUnlinked,
        ] {
            let fixture = Fixture::new();
            child_crash(fixture.root.path(), FaultPoint::JournalRename, 0, false);
            child_crash(fixture.root.path(), point, 0, true);
            let guard = fixture.guard();
            assert_eq!(
                recover_active(&guard).unwrap(),
                RecoveryOutcome::SetupRemoved
            );
            assert!(!fixture.root.path().join(TXN_DIR_NAME).exists());
            assert!(!fixture.root.path().join(SETUP_STAGE).exists());
            fixture.assert_inventory(&fixture.before);
        }
    }

    #[test]
    fn active_format2_marker_must_be_exact() {
        let fixture = Fixture::new();
        let guard = fixture.guard();
        let tree = guard.tree_io();
        let owner = tree.identity.owner_metadata(tree.root).unwrap();
        let fence = publish_fence(tree, &owner).unwrap();
        unlink_at(&fence, OsStr::new(SETUP_MARKER)).unwrap();
        write_new(&fence, SETUP_MARKER, b"", &owner).unwrap();
        assert!(recover_active(&guard)
            .unwrap_err()
            .to_string()
            .contains("invalid format2 setup marker"));
        assert!(fixture.root.path().join(TXN_DIR_NAME).exists());
    }

    #[test]
    fn snapshot_matching_accepts_empty_and_exact_size_and_rejects_other_lengths() {
        let fixture = Fixture::new();
        let guard = fixture.guard();
        for bytes in [b"".as_slice(), b"exact bytes".as_slice()] {
            let member = fixture.root.path().join("snapshot.toml");
            fs::write(&member, bytes).unwrap();
            let plan = guard
                .tree_io()
                .plan_root_file_no_follow(Path::new("snapshot.toml"))
                .unwrap();
            let metadata = plan.original_metadata().unwrap();
            let inode = Inode::of(metadata);
            let state = FileState::new(bytes, metadata, "unused".into());
            assert_eq!(
                read_plan(&plan, bytes.len() as u64).unwrap(),
                Some(bytes.to_vec())
            );
            assert!(plan_matches(&plan, Some(&state), Some(&inode)).unwrap());

            let longer = FileState::new(b"a longer candidate image", metadata, "unused".into());
            assert!(!plan_matches(&plan, Some(&longer), Some(&inode)).unwrap());
            if !bytes.is_empty() {
                let shorter = FileState::new(b"", metadata, "unused".into());
                assert!(!plan_matches(&plan, Some(&shorter), Some(&inode)).unwrap());
                assert!(read_plan(&plan, 0).is_err());
            }
        }
    }

    #[test]
    fn member_plan_admits_combined_blobs_at_exact_budget_and_rejects_plus_one() {
        let root = tempfile::tempdir().unwrap();
        let master = root.path().join("config.toml");
        let before_bytes = "before";
        let after_bytes = "after!!";
        fs::write(&master, before_bytes).unwrap();
        let guard = super::super::write_lock::acquire_for_migration(&master).unwrap();
        let tree = guard.tree_io();
        let owner = tree.identity.owner_metadata(tree.root).unwrap();
        let before = inventory(&[(PolicyMemberKind::Master, "config.toml", before_bytes)]);
        let after = inventory(&[(PolicyMemberKind::Master, "config.toml", after_bytes)]);
        let exact = (before_bytes.len() + after_bytes.len()) as u64;

        let (_, _, blobs) =
            plan_members_with_blob_budget(tree, Some(&before), &after, &owner, exact).unwrap();
        assert_eq!(
            blobs.values().map(|bytes| bytes.len() as u64).sum::<u64>(),
            exact
        );
        let error = plan_members_with_blob_budget(tree, Some(&before), &after, &owner, exact - 1)
            .err()
            .unwrap()
            .to_string();
        assert!(error.contains("blob budget exceeded"), "{error}");
    }

    #[test]
    fn repair_capture_applies_the_combined_budget_before_retaining_images() {
        let root = tempfile::tempdir().unwrap();
        let master = root.path().join("config.toml");
        let before_bytes = "old";
        let after_bytes = "new!";
        fs::write(&master, before_bytes).unwrap();
        let guard = super::super::write_lock::acquire_for_migration(&master).unwrap();
        let desired = inventory(&[(PolicyMemberKind::Master, "config.toml", after_bytes)]);
        let exact = (before_bytes.len() + after_bytes.len()) as u64;

        RepairDestinationSet::capture_with_blob_budget(&guard, &desired, exact).unwrap();
        let error = RepairDestinationSet::capture_with_blob_budget(&guard, &desired, exact - 1)
            .err()
            .unwrap()
            .to_string();
        assert!(error.contains("blob budget exceeded"), "{error}");
    }

    #[test]
    fn recovery_accepts_either_image_when_before_and_after_have_different_lengths() {
        for (old, new) in [("", "longer image"), ("longer image", ""), ("same", "size")] {
            for committed in [false, true] {
                let root = tempfile::tempdir().unwrap();
                let master = root.path().join("config.toml");
                let master_bytes = "schema_version = 4\n[upstream]\nservers = [\"192.0.2.1:53\"]\n\n[[custom_lists]]\nid = \"payload\"\n";
                fs::write(&master, master_bytes).unwrap();
                fs::create_dir(root.path().join("packs")).unwrap();
                let pack = root.path().join("packs/payload.txt");
                fs::write(&pack, old).unwrap();
                let guard = super::super::write_lock::acquire_for_migration(&master).unwrap();
                let before = inventory(&[
                    (PolicyMemberKind::Master, "config.toml", master_bytes),
                    (PolicyMemberKind::Pack, "packs/payload.txt", old),
                ]);
                let after = inventory(&[
                    (PolicyMemberKind::Master, "config.toml", master_bytes),
                    (PolicyMemberKind::Pack, "packs/payload.txt", new),
                ]);
                let request = TransactionRequest {
                    request_id: "recovery-lengths".into(),
                    actor: "operator".into(),
                    origin: "cli".into(),
                    operation: "edit".into(),
                    payload: Vec::new(),
                    expected_revision: before.revision(),
                    source_schema: 4,
                    target_schema: 4,
                };
                let PrepareOutcome::Prepared(transaction) =
                    prepare(&guard, &request, &before, &after, || Ok(())).unwrap()
                else {
                    panic!("unexpected replay");
                };
                if committed {
                    assert_eq!(
                        transaction.commit().unwrap().persistence,
                        Persistence::Committed
                    );
                    assert!(matches!(
                        rollback(&guard, "operator", "recovery-lengths").unwrap(),
                        RollbackOutcome::Restored(_)
                    ));
                } else {
                    drop(transaction);
                    assert!(matches!(
                        recover_active(&guard).unwrap(),
                        RecoveryOutcome::Recovered(_)
                    ));
                }
                assert_eq!(fs::read(&master).unwrap(), master_bytes.as_bytes());
                assert_eq!(fs::read(&pack).unwrap(), old.as_bytes());
            }
        }
    }

    #[test]
    fn root_replacement_before_prepare_or_during_validation_never_publishes_intent() {
        for during_validation in [false, true] {
            let fixture = Fixture::new();
            let guard = fixture.guard();
            let receipts = test_receipts(&guard);
            let displaced = tempfile::tempdir().unwrap();
            let detached = displaced.path().join("detached");
            let replace = || {
                fs::rename(fixture.root.path(), &detached).unwrap();
                fs::create_dir(fixture.root.path()).unwrap();
            };
            if !during_validation {
                replace();
            }

            let result = super::prepare(
                &guard,
                &receipts,
                &fixture.request(),
                &fixture.before,
                &fixture.after,
                || {
                    if during_validation {
                        replace();
                    }
                    Ok(())
                },
            );
            assert!(result.is_err());
            assert!(!fixture.root.path().join(TXN_DIR_NAME).exists());
            assert!(!detached.join(TXN_DIR_NAME).exists());
            assert!(!detached.join(SETUP_STAGE).exists());
            for member in fixture.before.members() {
                assert_eq!(
                    fs::read(detached.join(member.path())).unwrap(),
                    member_bytes(member).unwrap()
                );
            }
            assert!(directory_names(&receipts.directory, 1).unwrap().is_empty());
        }
    }

    #[test]
    fn root_replacement_refuses_recovery_without_touching_the_detached_intent() {
        let fixture = Fixture::new();
        let guard = fixture.guard();
        let receipts = test_receipts(&guard);
        drop(fixture.prepare(&guard));
        let journal = fs::read(fixture.root.path().join(TXN_DIR_NAME).join(JOURNAL_NAME)).unwrap();
        let displaced = tempfile::tempdir().unwrap();
        let detached = displaced.path().join("detached");
        fs::rename(fixture.root.path(), &detached).unwrap();
        fs::create_dir(fixture.root.path()).unwrap();

        assert!(super::recover_active(&guard, &receipts).is_err());
        assert_eq!(
            fs::read(detached.join(TXN_DIR_NAME).join(JOURNAL_NAME)).unwrap(),
            journal
        );
        assert!(fs::read_dir(fixture.root.path()).unwrap().next().is_none());
    }

    fn assert_independent_masters(masters: &[PathBuf; 2], data: &File) {
        const BEFORE: &str =
            "schema_version = 4\n# before\n[upstream]\nservers = [\"192.0.2.1:53\"]\n";
        const AFTER: &str =
            "schema_version = 4\n# after\n[upstream]\nservers = [\"192.0.2.1:53\"]\n";
        let mut completed = Vec::new();
        for (index, master) in masters.iter().enumerate() {
            let name = master.file_name().unwrap().to_str().unwrap();
            let before = inventory(&[(PolicyMemberKind::Master, name, BEFORE)]);
            let after = inventory(&[(PolicyMemberKind::Master, name, AFTER)]);
            fs::create_dir_all(master.parent().unwrap()).unwrap();
            fs::write(master, BEFORE).unwrap();
            let guard = super::super::write_lock::acquire_for_migration(master).unwrap();
            let receipts = ReceiptStore::open(data, &guard).unwrap();
            assert!(is_hash(&receipts.namespace));
            let request = TransactionRequest {
                request_id: "same-request".into(),
                actor: "same-actor".into(),
                origin: "cli".into(),
                operation: "edit".into(),
                payload: vec![index as u8],
                expected_revision: before.revision(),
                source_schema: 4,
                target_schema: 4,
            };
            let receipt =
                super::apply(&guard, &receipts, &request, &before, &after, || Ok(())).unwrap();
            assert_eq!(receipt.persistence, Persistence::Committed);
            completed.push((request, before, after, receipt, receipts.namespace));
        }
        assert_ne!(completed[0].4, completed[1].4);
        for (master, (request, before, after, expected, namespace)) in masters.iter().zip(completed)
        {
            let guard = super::super::write_lock::acquire_for_migration(master).unwrap();
            let receipts = ReceiptStore::open(data, &guard).unwrap();
            assert_eq!(receipts.namespace, namespace);
            assert_eq!(
                super::recover_active(&guard, &receipts).unwrap(),
                RecoveryOutcome::Absent
            );
            assert_eq!(
                super::apply(&guard, &receipts, &request, &before, &after, || {
                    bail!("retry must replay without validation")
                })
                .unwrap(),
                expected
            );
            assert_eq!(fs::read(master).unwrap(), AFTER.as_bytes());
        }
    }

    #[test]
    fn nested_config_roots_sharing_data_have_independent_receipts_and_retry_keys() {
        let base = tempfile::tempdir().unwrap();
        let data = tempfile::tempdir().unwrap();
        assert_independent_masters(
            &[
                base.path().join("config.toml"),
                base.path().join("staging/config.toml"),
            ],
            &File::open(data.path()).unwrap(),
        );
    }

    #[test]
    fn different_masters_in_one_root_have_independent_receipts_undo_and_retry_keys() {
        let base = tempfile::tempdir().unwrap();
        assert_independent_masters(
            &[
                base.path().join("first.toml"),
                base.path().join("second.toml"),
            ],
            &File::open(base.path()).unwrap(),
        );
    }

    #[test]
    fn recovery_does_not_parse_a_foreign_masters_receipts() {
        let fixture = Fixture::new();
        let foreign = Fixture::new();
        let data = tempfile::tempdir().unwrap();
        let directory = File::open(data.path()).unwrap();
        let guard = fixture.guard();
        let foreign_guard = foreign.guard();
        let receipts = ReceiptStore::open(&directory, &guard).unwrap();
        let foreign_receipts = ReceiptStore::open(&directory, &foreign_guard).unwrap();
        let key = request_key("same-actor", "same-request");
        write_new(
            &foreign_receipts.directory,
            &format!("{key}.json"),
            b"invalid foreign JSON",
            &foreign_receipts.owner,
        )
        .unwrap();

        assert_eq!(
            super::recover_active(&guard, &receipts).unwrap(),
            RecoveryOutcome::Absent
        );
        assert!(super::recover_active(&foreign_guard, &foreign_receipts).is_err());
        assert!(super::recover_active(&guard, &foreign_receipts)
            .unwrap_err()
            .to_string()
            .contains("ReceiptStoreMismatch"));
    }

    #[test]
    fn receipt_base_and_master_namespace_refuse_mode_changes_and_replacement() {
        for namespace in [false, true] {
            let fixture = Fixture::new();
            let guard = fixture.guard();
            let data = tempfile::tempdir().unwrap();
            let directory = File::open(data.path()).unwrap();
            let receipts = ReceiptStore::open(&directory, &guard).unwrap();
            let path = if namespace {
                data.path().join(RECEIPT_DIR).join(&receipts.namespace)
            } else {
                data.path().join(RECEIPT_DIR)
            };
            fs::set_permissions(&path, Permissions::from_mode(0o750)).unwrap();
            assert!(receipts.check().is_err());
            assert!(ReceiptStore::open(&directory, &guard).is_err());
            fs::set_permissions(&path, Permissions::from_mode(0o700)).unwrap();
            receipts.check().unwrap();
            fs::rename(&path, data.path().join("detached")).unwrap();
            fs::create_dir(&path).unwrap();
            fs::set_permissions(&path, Permissions::from_mode(0o700)).unwrap();
            assert!(receipts.check().is_err());
        }
    }

    #[test]
    fn receipt_store_is_node_local_and_mismatch_or_replacement_refuses_recovery() {
        let fixture = Fixture::new();
        let guard = fixture.guard();
        let data = tempfile::tempdir().unwrap();
        let receipts = ReceiptStore::open(&File::open(data.path()).unwrap(), &guard).unwrap();
        let transaction = match super::prepare(
            &guard,
            &receipts,
            &fixture.request(),
            &fixture.before,
            &fixture.after,
            || Ok(()),
        )
        .unwrap()
        {
            PrepareOutcome::Prepared(transaction) => transaction,
            _ => panic!("unexpected replay"),
        };
        let key = request_key("operator-1", "request-1");
        assert!(data
            .path()
            .join(RECEIPT_DIR)
            .join(master_namespace(guard.canonical_master()))
            .join(format!("{key}.json"))
            .exists());
        assert!(!fixture.root.path().join(RECEIPT_DIR).exists());
        drop(transaction);
        let unrelated_data = tempfile::tempdir().unwrap();
        let unrelated =
            ReceiptStore::open(&File::open(unrelated_data.path()).unwrap(), &guard).unwrap();
        assert!(super::recover_active(&guard, &unrelated)
            .unwrap_err()
            .to_string()
            .contains("ReceiptStoreMismatch"));
        fs::rename(data.path().join(RECEIPT_DIR), data.path().join("detached")).unwrap();
        fs::create_dir(data.path().join(RECEIPT_DIR)).unwrap();
        fs::set_permissions(data.path().join(RECEIPT_DIR), Permissions::from_mode(0o700)).unwrap();
        assert!(receipts.check().is_err());
        fixture.assert_inventory(&fixture.before);
    }

    #[test]
    fn legacy_base_receipt_without_operator_plan_hash_still_decodes() {
        let encoded = serde_json::json!({
            "revision_scope": "policy_tree_v1",
            "transaction_id": "0".repeat(32),
            "request_id": "legacy-request",
            "actor": "legacy-actor",
            "origin": "legacy-origin",
            "operation": "legacy-operation",
            "payload_hash": "1".repeat(64),
            "plan_hash": "2".repeat(64),
            "before_revision": "3".repeat(64),
            "after_revision": "4".repeat(64),
            "created_unix_seconds": 1,
            "persistence": "committed",
            "changed_members": 1,
            "rollback_restored": false,
            "audit_pending": false,
            "failure": null
        });
        let receipt: BaseReceipt = serde_json::from_value(encoded).unwrap();
        assert_eq!(receipt.operator_plan_hash, None);
    }

    #[test]
    fn expiry_reclaims_only_terminal_records_after_retention_promise() {
        let fixture = Fixture::new();
        let guard = fixture.guard();
        let receipt = fixture.prepare(&guard).commit().unwrap();
        let tree = guard.tree_io();
        let receipts = test_receipts(&guard);
        let owner = tree.identity.owner_metadata(tree.root).unwrap();
        let undo = open_store(tree, &owner, false).unwrap().unwrap();
        let key = request_key("operator-1", "request-1");
        let record = receipts.read(&key, tree).unwrap().unwrap();
        assert!(record.retain_until >= receipt.created_unix_seconds + MIN_RETENTION_SECONDS);
        assert!(receipts
            .admit(tree, &undo, record.retain_until - 1, 1)
            .is_err());
        assert!(receipts.read(&key, tree).unwrap().is_some());
        receipts.admit(tree, &undo, record.retain_until, 1).unwrap();
        assert!(receipts.read(&key, tree).unwrap().is_none());
        assert!(inspect_at(&undo, OsStr::new(&key)).unwrap().is_none());
        fixture.assert_inventory(&fixture.after);
    }

    #[test]
    fn unavailable_receipt_store_does_not_promote() {
        let fixture = Fixture::new();
        let guard = fixture.guard();
        let receipts = test_receipts(&guard);
        receipts
            .directory
            .set_permissions(Permissions::from_mode(0o500))
            .unwrap();
        assert!(super::prepare(
            &guard,
            &receipts,
            &fixture.request(),
            &fixture.before,
            &fixture.after,
            || Ok(())
        )
        .is_err());
        assert!(!fixture.root.path().join(TXN_DIR_NAME).exists());
        fixture.assert_inventory(&fixture.before);
    }

    #[test]
    fn rollback_stage_failure_before_readiness_preserves_every_member_and_aborts() {
        let fixture = Fixture::new();
        let guard = fixture.guard();
        let transaction = fixture.prepare(&guard);
        let receipt = with_fault(FaultPoint::BeforeRollbackStageLink, 2, || {
            transaction.commit()
        })
        .unwrap();
        assert_eq!(receipt.persistence, Persistence::DurabilityUncertain);
        fixture.assert_inventory(&fixture.before);
        let RecoveryOutcome::Recovered(receipt) = recover_active(&guard).unwrap() else {
            panic!("expected aborted recovery");
        };
        assert_eq!(receipt.persistence, Persistence::Aborted);
        fixture.assert_inventory(&fixture.before);
        assert_no_write_stages(fixture.root.path());
    }

    #[test]
    fn restore_pack_preflight_accepts_only_receipted_format2_rollback_stages() {
        let fixture = Fixture::new();
        let guard = fixture.guard();
        let transaction = fixture.prepare(&guard);
        stage_rollback_members(
            transaction.guard,
            &transaction.fence,
            &transaction.owner,
            &transaction.journal,
            &transaction.targets,
        )
        .unwrap();
        let journal_before =
            fs::read(fixture.root.path().join(TXN_DIR_NAME).join(JOURNAL_NAME)).unwrap();

        preflight_restore_pack_tree(&guard).unwrap();
        assert_eq!(
            fs::read(fixture.root.path().join(TXN_DIR_NAME).join(JOURNAL_NAME)).unwrap(),
            journal_before
        );

        let foreign = fixture.root.path().join("packs").join(format!(
            "{WRITE_STAGE_PREFIX}ffffffffffffffffffffffffffffffff"
        ));
        fs::write(&foreign, b"foreign\n").unwrap();
        assert!(preflight_restore_pack_tree(&guard).is_err());
        assert!(foreign.exists());
    }

    #[test]
    fn restore_pack_preflight_is_strict_without_a_format2_receipt() {
        for variant in ["foreign-stage", "nested", "special"] {
            let root = tempfile::tempdir().unwrap();
            let master = root.path().join("config.toml");
            fs::write(&master, "schema_version = 4\n").unwrap();
            let packs = root.path().join("packs");
            fs::create_dir(&packs).unwrap();
            match variant {
                "foreign-stage" => {
                    fs::write(
                        packs.join(format!(
                            "{WRITE_STAGE_PREFIX}ffffffffffffffffffffffffffffffff"
                        )),
                        b"foreign\n",
                    )
                    .unwrap();
                }
                "nested" => fs::create_dir(packs.join("nested")).unwrap(),
                "special" => symlink(&master, packs.join("linked.txt")).unwrap(),
                _ => unreachable!(),
            }
            let guard = super::super::write_lock::acquire_for_migration(&master).unwrap();
            assert!(
                preflight_restore_pack_tree(&guard).is_err(),
                "{variant} must be rejected"
            );
        }
    }

    #[test]
    fn restore_pack_preflight_does_not_exempt_stages_for_setup_or_legacy_journals() {
        for active in ["absent", "setup", "legacy"] {
            let root = tempfile::tempdir().unwrap();
            let master = root.path().join("config.toml");
            fs::write(&master, "schema_version = 4\n").unwrap();
            let packs = root.path().join("packs");
            fs::create_dir(&packs).unwrap();
            let foreign = packs.join(format!(
                "{WRITE_STAGE_PREFIX}ffffffffffffffffffffffffffffffff"
            ));
            fs::write(&foreign, b"foreign\n").unwrap();
            let guard = super::super::write_lock::acquire_for_migration(&master).unwrap();
            if active != "absent" {
                let tree = guard.tree_io();
                let owner = tree.identity.owner_metadata(tree.root).unwrap();
                let fence = private_dir(tree.root, TXN_DIR_NAME, &owner, true).unwrap();
                if active == "setup" {
                    write_new(&fence, SETUP_MARKER, b"2\n", &owner).unwrap();
                } else {
                    write_new(&fence, JOURNAL_NAME, br#"{"format_version":1}"#, &owner).unwrap();
                }
            }

            assert!(
                preflight_restore_pack_tree(&guard).is_err(),
                "{active} must not exempt a foreign stage"
            );
            assert!(foreign.exists());
        }
    }

    #[test]
    fn decoder_rejects_terminal_rollback_readiness_and_receipts() {
        let fixture = Fixture::new();
        let guard = fixture.guard();
        let transaction = fixture.prepare(&guard);
        let mut terminal = transaction.journal.borrow().clone();
        terminal.phase = Phase::Committed;
        terminal.receipt.persistence = Persistence::Committed;
        terminal.rollback_ready = true;
        assert!(decode(&serde_json::to_vec(&terminal).unwrap(), guard.tree_io()).is_err());

        terminal.rollback_ready = false;
        let member = terminal
            .members
            .iter_mut()
            .find(|member| member.operation == Some(MemberOperation::Replace))
            .unwrap();
        let state = member.before.as_ref().unwrap();
        member.rollback_staging = Some(RollbackStagingReceipt {
            parent: Inode {
                device: 1,
                inode: 1,
            },
            name: format!("{WRITE_STAGE_PREFIX}00000000000000000000000000000000"),
            payload: Inode {
                device: 1,
                inode: 2,
            },
            payload_uid: state.uid,
            payload_gid: state.gid,
            payload_mode: state.mode,
            payload_length: state.length,
            payload_digest: state.digest.clone(),
            linked: true,
        });
        assert!(decode(&serde_json::to_vec(&terminal).unwrap(), guard.tree_io()).is_err());
    }

    fn child_crash(root: &Path, point: FaultPoint, skip: usize, recovering: bool) {
        child_crash_scoped(root, point, skip, recovering, false);
    }

    fn add_atomic_write_crash_boundaries(
        points: &mut Vec<(FaultPoint, usize)>,
        staging_operations: usize,
        promotion_operations: usize,
    ) {
        for skip in 0..staging_operations {
            for point in [
                FaultPoint::BeforeAnonymousInodeFsync,
                FaultPoint::AfterAnonymousInodeFsync,
                FaultPoint::BeforeStagingLink,
                FaultPoint::AfterStagingLink,
                FaultPoint::BeforeStagingLinkParentFsync,
                FaultPoint::AfterStagingLinkParentFsync,
            ] {
                points.push((point, skip));
            }
        }
        for skip in 0..promotion_operations {
            for point in [
                FaultPoint::BeforePromotionRename,
                FaultPoint::AfterPromotionRename,
                FaultPoint::BeforePostRenameParentFsync,
                FaultPoint::AfterPostRenameParentFsync,
            ] {
                points.push((point, skip));
            }
        }
    }

    fn add_blob_fsync_crash_boundaries(points: &mut Vec<(FaultPoint, usize)>, blob_count: usize) {
        for skip in 0..blob_count {
            points.push((FaultPoint::BeforeBlobFsync, skip));
            points.push((FaultPoint::AfterBlobFsync, skip));
        }
    }

    fn child_crash_scoped(
        root: &Path,
        point: FaultPoint,
        skip: usize,
        recovering: bool,
        repair: bool,
    ) {
        use std::os::unix::process::ExitStatusExt;
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "config::policy_transaction::tests::subprocess_crash_driver",
                "--nocapture",
            ])
            .env("WARDEN_POLICY_CRASH_ROOT", root)
            .env("WARDEN_POLICY_CRASH_POINT", format!("{point:?}"))
            .env("WARDEN_POLICY_CRASH_SKIP", skip.to_string())
            .env("WARDEN_POLICY_CRASH_REPAIR", if repair { "1" } else { "0" })
            .env(
                "WARDEN_POLICY_CRASH_RECOVER",
                if recovering { "1" } else { "0" },
            )
            .output()
            .unwrap();
        assert_eq!(
            output.status.signal(),
            Some(libc::SIGKILL),
            "child did not reach crash boundary {point:?}/{skip}: {} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn subprocess_crash_driver() {
        let Some(root) = std::env::var_os("WARDEN_POLICY_CRASH_ROOT") else {
            return;
        };
        let fixture = Fixture::new();
        let guard = super::super::write_lock::acquire_for_migration(
            &PathBuf::from(root).join("config.toml"),
        )
        .unwrap();
        let point = match std::env::var("WARDEN_POLICY_CRASH_POINT").unwrap().as_str() {
            "SetupReady" => FaultPoint::SetupReady,
            "FencePublished" => FaultPoint::FencePublished,
            "SetupCleanupPublished" => FaultPoint::SetupCleanupPublished,
            "SetupCleanupMemberUnlinked" => FaultPoint::SetupCleanupMemberUnlinked,
            "JournalRename" => FaultPoint::JournalRename,
            "JournalFsync" => FaultPoint::JournalFsync,
            "BeforeBlobFsync" => FaultPoint::BeforeBlobFsync,
            "AfterBlobFsync" => FaultPoint::AfterBlobFsync,
            "BeforePromotion" => FaultPoint::BeforePromotion,
            "AfterStagingLink" => FaultPoint::AfterStagingLink,
            "AfterPromotion" => FaultPoint::AfterPromotion,
            "BeforeAnonymousInodeFsync" => FaultPoint::BeforeAnonymousInodeFsync,
            "AfterAnonymousInodeFsync" => FaultPoint::AfterAnonymousInodeFsync,
            "BeforeStagingLink" => FaultPoint::BeforeStagingLink,
            "BeforeStagingLinkParentFsync" => FaultPoint::BeforeStagingLinkParentFsync,
            "AfterStagingLinkParentFsync" => FaultPoint::AfterStagingLinkParentFsync,
            "BeforePromotionRename" => FaultPoint::BeforePromotionRename,
            "AfterPromotionRename" => FaultPoint::AfterPromotionRename,
            "BeforePostRenameParentFsync" => FaultPoint::BeforePostRenameParentFsync,
            "AfterPostRenameParentFsync" => FaultPoint::AfterPostRenameParentFsync,
            "BeforeRollbackStageLink" => FaultPoint::BeforeRollbackStageLink,
            "AfterRollbackStageLink" => FaultPoint::AfterRollbackStageLink,
            "BeforeRollbackStageUnlink" => FaultPoint::BeforeRollbackStageUnlink,
            "AfterRollbackStageUnlink" => FaultPoint::AfterRollbackStageUnlink,
            "RollbackReady" => FaultPoint::RollbackReady,
            "BeforeRollbackRestoreRename" => FaultPoint::BeforeRollbackRestoreRename,
            "AfterRollbackRestoreRename" => FaultPoint::AfterRollbackRestoreRename,
            "BeforeRollbackRestoreParentFsync" => FaultPoint::BeforeRollbackRestoreParentFsync,
            "AfterRollbackRestoreParentFsync" => FaultPoint::AfterRollbackRestoreParentFsync,
            "BeforeTerminalRename" => FaultPoint::BeforeTerminalRename,
            "AfterTerminalRename" => FaultPoint::AfterTerminalRename,
            "RootFsync" => FaultPoint::RootFsync,
            _ => panic!("unknown crash point"),
        };
        let skip = std::env::var("WARDEN_POLICY_CRASH_SKIP")
            .unwrap()
            .parse()
            .unwrap();
        TEST_KILL.with(|kill| *kill.borrow_mut() = Some((point, skip)));
        if std::env::var("WARDEN_POLICY_CRASH_RECOVER").unwrap() == "1" {
            recover_active(&guard).unwrap();
        } else if std::env::var("WARDEN_POLICY_CRASH_REPAIR").unwrap() == "1" {
            let destinations = RepairDestinationSet::capture(&guard, &fixture.after).unwrap();
            let request = repair_request(&destinations);
            super::apply_repair(&test_receipts(&guard), &request, destinations, || Ok(())).unwrap();
        } else {
            apply(
                &guard,
                &fixture.request(),
                &fixture.before,
                &fixture.after,
                || Ok(()),
            )
            .unwrap();
        }
        panic!("requested crash point was not reached");
    }

    #[test]
    fn repair_sigkill_restart_recovers_create_replace_and_terminal_boundaries() {
        let base_points = vec![
            (FaultPoint::SetupReady, 0),
            (FaultPoint::FencePublished, 0),
            (FaultPoint::JournalRename, 0),
            (FaultPoint::JournalFsync, 0),
            (FaultPoint::BeforeTerminalRename, 0),
            (FaultPoint::AfterTerminalRename, 0),
            (FaultPoint::RootFsync, 0),
        ];
        for missing_master in [false, true] {
            let mut points = base_points.clone();
            for skip in 0..4 {
                points.push((FaultPoint::BeforePromotion, skip));
                points.push((FaultPoint::AfterPromotion, skip));
            }
            add_atomic_write_crash_boundaries(&mut points, if missing_master { 6 } else { 7 }, 4);
            add_blob_fsync_crash_boundaries(&mut points, if missing_master { 6 } else { 7 });
            for &(point, skip) in &points {
                let fixture = Fixture::new();
                if missing_master {
                    fs::remove_file(fixture.master()).unwrap();
                } else {
                    fs::write(fixture.master(), b"[broken").unwrap();
                }
                child_crash_scoped(fixture.root.path(), point, skip, false, true);
                let guard = fixture.guard();
                assert_ne!(
                    recover_active(&guard).unwrap(),
                    RecoveryOutcome::LegacyActive
                );
                let receipt = lookup_receipt(&guard, "operator-1", "repair-1").unwrap();
                if matches!(
                    point,
                    FaultPoint::BeforeTerminalRename
                        | FaultPoint::AfterTerminalRename
                        | FaultPoint::RootFsync
                ) {
                    let receipt = receipt.unwrap();
                    assert_eq!(receipt.persistence, Persistence::Committed);
                    assert_eq!(
                        receipt.revision_scope,
                        RevisionScope::RepairDestinationSetV1
                    );
                    fixture.assert_inventory(&fixture.after);
                    assert_policy_loadable(&fixture, &guard);
                } else {
                    assert!(
                        receipt.is_none_or(|receipt| receipt.persistence == Persistence::Aborted)
                    );
                    if missing_master {
                        assert!(!fixture.master().exists());
                    } else {
                        assert_eq!(fs::read(fixture.master()).unwrap(), b"[broken");
                    }
                    assert_eq!(
                        fs::read(fixture.root.path().join("include.toml")).unwrap(),
                        b"# original include\n"
                    );
                    assert!(!fixture.root.path().join("packs/new.txt").exists());
                    assert!(
                        super::super::loader::load_config_for_schema_under_migration_guard(
                            &guard,
                            &fixture.master(),
                            4,
                            time::OffsetDateTime::UNIX_EPOCH
                        )
                        .is_err()
                    );
                }
                assert_eq!(
                    fs::read(fixture.root.path().join("packs/old.txt")).unwrap(),
                    b"old.example\n"
                );
                assert_eq!(
                    fs::read(fixture.root.path().join("packs/orphan.txt")).unwrap(),
                    b"orphan.example\n"
                );
                assert_no_write_stages(fixture.root.path());
            }
        }
    }

    #[test]
    fn repair_recovery_survives_another_sigkill_and_preserves_unnamed_edits() {
        let fixture = Fixture::new();
        fs::remove_file(fixture.master()).unwrap();
        child_crash_scoped(
            fixture.root.path(),
            FaultPoint::AfterPromotion,
            3,
            false,
            true,
        );
        fs::write(
            fixture.root.path().join("packs/orphan.txt"),
            b"# external edit\n",
        )
        .unwrap();
        child_crash_scoped(
            fixture.root.path(),
            FaultPoint::BeforeRollbackRestoreRename,
            0,
            true,
            true,
        );
        let guard = fixture.guard();
        assert!(matches!(
            recover_active(&guard).unwrap(),
            RecoveryOutcome::Recovered(_)
        ));
        assert!(!fixture.master().exists());
        assert_eq!(
            fs::read(fixture.root.path().join("packs/orphan.txt")).unwrap(),
            b"# external edit\n"
        );
        assert_no_write_stages(fixture.root.path());
    }

    #[test]
    fn sigkill_restart_recovers_each_publication_boundary() {
        let mut points = vec![
            (FaultPoint::SetupReady, 0),
            (FaultPoint::FencePublished, 0),
            (FaultPoint::JournalRename, 0),
            (FaultPoint::JournalFsync, 0),
            (FaultPoint::BeforeTerminalRename, 0),
            (FaultPoint::AfterTerminalRename, 0),
            (FaultPoint::RootFsync, 0),
        ];
        for skip in 0..5 {
            points.push((FaultPoint::BeforePromotion, skip));
            points.push((FaultPoint::AfterPromotion, skip));
        }
        for skip in 0..4 {
            points.push((FaultPoint::BeforeRollbackStageLink, skip));
            points.push((FaultPoint::AfterRollbackStageLink, skip));
            points.push((FaultPoint::BeforeRollbackStageUnlink, skip));
            points.push((FaultPoint::AfterRollbackStageUnlink, skip));
        }
        add_atomic_write_crash_boundaries(&mut points, 8, 4);
        add_blob_fsync_crash_boundaries(&mut points, 8);
        points.push((FaultPoint::RollbackReady, 0));
        for (point, skip) in points {
            let fixture = Fixture::new();
            child_crash(fixture.root.path(), point, skip, false);
            let guard = fixture.guard();
            let outcome = recover_active(&guard)
                .unwrap_or_else(|error| panic!("recovery failed at {point:?}/{skip}: {error:#}"));
            assert_ne!(outcome, RecoveryOutcome::LegacyActive);
            let receipt = lookup_receipt(&guard, "operator-1", "request-1").unwrap();
            if matches!(
                point,
                FaultPoint::BeforeTerminalRename
                    | FaultPoint::AfterTerminalRename
                    | FaultPoint::RootFsync
                    | FaultPoint::BeforeRollbackStageUnlink
                    | FaultPoint::AfterRollbackStageUnlink
            ) {
                assert_eq!(receipt.unwrap().persistence, Persistence::Committed);
                fixture.assert_inventory(&fixture.after);
            } else {
                assert!(receipt.is_none_or(|receipt| receipt.persistence == Persistence::Aborted));
                fixture.assert_inventory(&fixture.before);
            }
            assert_no_write_stages(fixture.root.path());
            assert_policy_loadable(&fixture, &guard);
        }
    }

    #[test]
    fn recovery_refuses_replaced_modified_or_hardlinked_staging_payloads() {
        for variant in 0..3 {
            let fixture = Fixture::new();
            child_crash(fixture.root.path(), FaultPoint::AfterStagingLink, 6, false);
            let guard = fixture.guard();
            let tree = guard.tree_io();
            let owner = tree.identity.owner_metadata(tree.root).unwrap();
            let fence = private_dir(tree.root, TXN_DIR_NAME, &owner, false).unwrap();
            let journal = read_journal(&fence, &owner, tree).unwrap();
            let (path, staging) = journal
                .members
                .iter()
                .find_map(|member| {
                    member
                        .linked_staging
                        .clone()
                        .map(|staging| (member.path.clone(), staging))
                })
                .expect("forward staging receipt");
            let stage = fixture
                .root
                .path()
                .join(Path::new(&path).parent().unwrap_or(Path::new("")))
                .join(&staging.name);
            let expected = match variant {
                0 => {
                    fs::write(&stage, b"in-place drift\n").unwrap();
                    fs::read(&stage).unwrap()
                }
                1 => {
                    fs::remove_file(&stage).unwrap();
                    fs::write(&stage, b"replacement\n").unwrap();
                    fs::set_permissions(&stage, Permissions::from_mode(staging.payload_mode))
                        .unwrap();
                    fs::read(&stage).unwrap()
                }
                _ => {
                    let extra = fixture.root.path().join("foreign-stage-link");
                    fs::hard_link(&stage, &extra).unwrap();
                    fs::read(&extra).unwrap()
                }
            };
            let error = recover_active(&guard).unwrap_err().to_string();
            assert!(error.contains("RecoveryConflict"), "{error}");
            if variant == 2 {
                assert_eq!(
                    fs::read(fixture.root.path().join("foreign-stage-link")).unwrap(),
                    expected
                );
            } else {
                assert_eq!(fs::read(&stage).unwrap(), expected);
            }
            assert!(stage.exists());
            assert!(fixture.root.path().join(TXN_DIR_NAME).exists());
        }
    }

    #[test]
    fn sigkill_during_rollback_recovery_is_restartable() {
        for point in [
            FaultPoint::BeforeRollbackRestoreRename,
            FaultPoint::AfterRollbackRestoreRename,
            FaultPoint::BeforeRollbackRestoreParentFsync,
            FaultPoint::AfterRollbackRestoreParentFsync,
        ] {
            for skip in 0..2 {
                let fixture = Fixture::new();
                {
                    let guard = fixture.guard();
                    let transaction = fixture.prepare(&guard);
                    with_fault(FaultPoint::AfterPromotion, 2, || transaction.commit()).unwrap();
                }
                child_crash(fixture.root.path(), point, skip, true);
                let guard = fixture.guard();
                assert!(matches!(
                    recover_active(&guard).unwrap(),
                    RecoveryOutcome::Recovered(_)
                ));
                fixture.assert_inventory(&fixture.before);
                assert_no_write_stages(fixture.root.path());
            }
        }
    }

    #[test]
    fn sigkill_while_recreating_a_deleted_member_keeps_the_journal_recoverable() {
        for (point, skip) in [
            (FaultPoint::BeforeRollbackRestoreRename, 2),
            (FaultPoint::AfterRollbackRestoreRename, 2),
            (FaultPoint::BeforeRollbackRestoreParentFsync, 2),
            (FaultPoint::AfterRollbackRestoreParentFsync, 2),
        ] {
            let fixture = Fixture::new();
            child_crash(fixture.root.path(), FaultPoint::AfterPromotion, 4, false);
            child_crash(fixture.root.path(), point, skip, true);

            let guard = fixture.guard();
            assert!(matches!(
                recover_active(&guard).unwrap(),
                RecoveryOutcome::Recovered(_)
            ));
            fixture.assert_inventory(&fixture.before);
            assert_no_write_stages(fixture.root.path());
        }
    }
}
