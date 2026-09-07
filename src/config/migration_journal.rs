//! The fixed directory is the fence, including crashes before a journal exists.

use std::collections::BTreeSet;
use std::ffi::{CStr, CString, OsStr};
use std::fs::{File, Metadata};
use std::io::{self, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::path::{Component, Path, PathBuf};

use anyhow::{ensure, Context};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::atomic_write::{hardened_atomic_write_at, AtomicWriteAtOpts};
use super::tree_io::{
    inspect_at, rename_noreplace_at, same_inode, CappedRead, PinnedTarget, TargetPlan, TreeIo,
};
use super::write_lock::{open_at, preserve_owner, reserved_component, MigrationWriteLock};

pub(crate) const TXN_DIR_NAME: &str = ".warden-migration";
pub(crate) const CLEANUP_DIR_PREFIX: &str = ".warden-migration.cleanup-";
pub(crate) const FINALIZED_DIR_PREFIX: &str = ".warden-migration.finalized-";
pub(crate) const JOURNAL_NAME: &str = "journal.json";
pub(crate) const JOURNAL_FORMAT_VERSION: u64 = 1;
const MAX_JOURNAL_BYTES: u64 = 4 * 1024 * 1024;
const ORIGINALS_DIR_NAME: &str = "originals";
const JOURNAL_STAGE_NAME: &str = "journal.staging";

/// A candidate member whose original inode was captured by the migration planner.
pub(crate) struct MigrationMember {
    path: PathBuf,
    role: MemberRole,
    before: Vec<u8>,
    after: Vec<u8>,
    metadata: Metadata,
    before_receipt: FileReceipt,
    after_receipt: FileReceipt,
}

impl MigrationMember {
    pub(crate) fn new(
        path: PathBuf,
        role: MemberRole,
        before: Vec<u8>,
        after: Vec<u8>,
        metadata: Metadata,
    ) -> anyhow::Result<Self> {
        let path_text = path
            .to_str()
            .context("migration member path is not valid UTF-8")?;
        validate_member_path(path_text)?;
        ensure!(
            metadata.is_file() && metadata.nlink() == 1,
            "migration member must be a regular single-link file"
        );
        ensure!(
            metadata.len() == before.len() as u64,
            "migration member metadata length does not match its before image"
        );
        let before_receipt = FileReceipt::from_bytes_with_metadata(&metadata, &before)?;
        let after_receipt = FileReceipt::from_bytes_with_metadata(&metadata, &after)?;
        Ok(Self {
            path,
            role,
            before,
            after,
            metadata,
            before_receipt,
            after_receipt,
        })
    }
}

/// A published fixed-fence transaction. Dropping it deliberately retains the fence.
pub(crate) struct PublishedMigration<'g> {
    guard: &'g MigrationWriteLock,
    members: Vec<MigrationMember>,
    targets: Vec<PinnedTarget<'g>>,
    journal: Journal,
    journal_hash: String,
    fence: File,
    owner: Metadata,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum CommitError {
    #[error("migration commit rename did not land: {0:#}")]
    RenameNotLanded(anyhow::Error),
    #[error("migration commit rename landed at {cleanup} but root fsync is uncertain: {source:#}")]
    RootFsyncUncertain {
        cleanup: PathBuf,
        #[source]
        source: anyhow::Error,
    },
}

impl CommitError {
    pub(crate) fn rename_landed(&self) -> bool {
        matches!(self, Self::RootFsyncUncertain { .. })
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum RecoveryOutcome {
    Absent,
    SetupRemoved,
    RolledBack,
}

/// Result of an explicit release-gate rollback.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum RollbackOutcome {
    NoArtifact,
    SetupRemoved,
    Restored,
}

/// Result of discarding a healthy migration's retained undo snapshot.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum FinalizeOutcome {
    NoArtifact,
    Finalized,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum LiveState {
    Before,
    After,
    BeforeAndAfter,
    Other,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RollbackSyncPoint {
    FixedFence,
    Cleanup,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Journal {
    format_version: u64,
    migration: String,
    from_schema: u64,
    to_schema: u64,
    master: String,
    members: Vec<JournalMember>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct JournalMember {
    path: String,
    role: MemberRole,
    original_blob: String,
    before: FileReceipt,
    after: FileReceipt,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum MemberRole {
    Include,
    Master,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FileReceipt {
    len: u64,
    sha256: String,
    uid: u32,
    gid: u32,
    mode: u32,
}

impl Journal {
    pub(crate) fn new(master: &Path, mut members: Vec<JournalMember>) -> anyhow::Result<Self> {
        let master = master
            .to_str()
            .context("journal master path is not valid UTF-8")?
            .to_owned();
        for (index, member) in members.iter_mut().enumerate() {
            member.original_blob = original_blob_name(index);
        }
        let journal = Self {
            format_version: JOURNAL_FORMAT_VERSION,
            migration: "v3-to-v4".to_owned(),
            from_schema: 3,
            to_schema: 4,
            master,
            members,
        };
        validate_journal_fields(&journal, Path::new(&journal.master))?;
        Ok(journal)
    }

    pub(crate) fn members(&self) -> &[JournalMember] {
        &self.members
    }

    pub(crate) fn to_json_bytes(&self) -> anyhow::Result<Vec<u8>> {
        let mut output = BoundedBytes::new(MAX_JOURNAL_BYTES as usize);
        serde_json::to_writer(&mut output, self).context("serialize journal JSON")?;
        Ok(output.into_inner())
    }
}

impl JournalMember {
    pub(crate) fn new(
        path: &Path,
        role: MemberRole,
        before: FileReceipt,
        after: FileReceipt,
    ) -> anyhow::Result<Self> {
        let path = path
            .to_str()
            .context("journal member path is not valid UTF-8")?
            .to_owned();
        validate_member_path(&path)?;
        validate_receipt(&before)?;
        validate_receipt(&after)?;
        ensure!(
            (after.uid, after.gid, after.mode) == (before.uid, before.gid, before.mode),
            "journal after receipt must preserve owner and mode"
        );
        Ok(Self {
            path,
            role,
            original_blob: String::new(),
            before,
            after,
        })
    }
}

impl FileReceipt {
    pub(crate) fn new(
        len: u64,
        sha256: String,
        uid: u32,
        gid: u32,
        mode: u32,
    ) -> anyhow::Result<Self> {
        let receipt = Self {
            len,
            sha256,
            uid,
            gid,
            mode,
        };
        validate_receipt(&receipt)?;
        Ok(receipt)
    }

    pub(crate) fn from_bytes_with_metadata(
        metadata: &Metadata,
        bytes: &[u8],
    ) -> anyhow::Result<Self> {
        Self::new(
            bytes.len() as u64,
            sha256_hex(bytes),
            metadata.uid(),
            metadata.gid(),
            metadata.mode() & 0o7777,
        )
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> u64 {
        self.len
    }

    #[cfg(test)]
    pub(crate) fn sha256(&self) -> &str {
        &self.sha256
    }

    #[cfg(test)]
    pub(crate) fn uid(&self) -> u32 {
        self.uid
    }

    #[cfg(test)]
    pub(crate) fn gid(&self) -> u32 {
        self.gid
    }

    #[cfg(test)]
    pub(crate) fn mode(&self) -> u32 {
        self.mode
    }
}

struct BoundedBytes {
    bytes: Vec<u8>,
    limit: usize,
}

impl BoundedBytes {
    fn new(limit: usize) -> Self {
        Self {
            bytes: Vec::new(),
            limit,
        }
    }

    fn into_inner(self) -> Vec<u8> {
        self.bytes
    }
}

impl Write for BoundedBytes {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.limit.saturating_sub(self.bytes.len()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "serialized journal exceeds size limit",
            ));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Parse the immutable journal before using any pathname it contains.
pub(crate) fn validate_journal(bytes: &[u8], expected_master: &Path) -> anyhow::Result<Journal> {
    ensure!(
        bytes.len() as u64 <= MAX_JOURNAL_BYTES,
        "journal exceeds size limit"
    );
    let journal: Journal = serde_json::from_slice(bytes).context("malformed journal JSON")?;
    validate_journal_fields(&journal, expected_master)?;
    Ok(journal)
}

fn validate_journal_fields(journal: &Journal, expected_master: &Path) -> anyhow::Result<()> {
    ensure!(
        journal.format_version == JOURNAL_FORMAT_VERSION
            && journal.migration == "v3-to-v4"
            && journal.from_schema == 3
            && journal.to_schema == 4,
        "unknown or malformed journal envelope"
    );
    validate_member_path(&journal.master)?;
    ensure!(
        Path::new(&journal.master) == expected_master,
        "journal master does not match the locked config root"
    );
    ensure!(
        !journal.members.is_empty() && journal.members.len() <= super::loader::MAX_INCLUDE_FILES,
        "journal member count is outside the allowed range"
    );

    let mut before_bytes = 0_u64;
    let mut after_bytes = 0_u64;
    let mut paths = std::collections::BTreeSet::new();
    for (index, member) in journal.members.iter().enumerate() {
        validate_member_path(&member.path)?;
        ensure!(
            paths.insert(&member.path),
            "journal member paths must be unique"
        );
        ensure!(
            member.original_blob == original_blob_name(index),
            "journal original blob is not canonical and positional"
        );
        validate_receipt(&member.before)?;
        validate_receipt(&member.after)?;
        ensure!(
            (member.after.uid, member.after.gid, member.after.mode)
                == (member.before.uid, member.before.gid, member.before.mode),
            "journal after receipt must preserve owner and mode"
        );
        before_bytes = before_bytes
            .checked_add(member.before.len)
            .context("journal before-image byte count overflows")?;
        ensure!(
            before_bytes <= super::loader::MAX_TOTAL_BYTES,
            "journal before-image bytes exceed the config tree limit"
        );
        after_bytes = after_bytes
            .checked_add(member.after.len)
            .context("journal after-image byte count overflows")?;
        ensure!(
            after_bytes <= super::loader::MAX_TOTAL_BYTES,
            "journal after-image bytes exceed the config tree limit"
        );
    }
    let Some((last, preceding)) = journal.members.split_last() else {
        unreachable!("checked non-empty members")
    };
    ensure!(
        last.role == MemberRole::Master,
        "journal master must be final"
    );
    ensure!(
        last.path == journal.master,
        "journal final master does not match top-level master"
    );
    ensure!(
        preceding
            .iter()
            .all(|member| member.role == MemberRole::Include),
        "journal contains a non-final master"
    );
    Ok(())
}

/// Read and validate one original through the fixed fence descriptor.
pub(crate) fn validate_original_blob(
    fence: &File,
    owner: &Metadata,
    index: usize,
    member: &JournalMember,
) -> anyhow::Result<Vec<u8>> {
    validate_original_blob_held(fence, owner, index, member).map(|(_, bytes)| bytes)
}

fn validate_original_blob_held(
    fence: &File,
    owner: &Metadata,
    index: usize,
    member: &JournalMember,
) -> anyhow::Result<(File, Vec<u8>)> {
    ensure!(
        member.original_blob == original_blob_name(index),
        "original blob is not canonical and positional"
    );
    let originals = open_at(
        fence,
        OsStr::new(ORIGINALS_DIR_NAME),
        libc::O_RDONLY | libc::O_DIRECTORY,
        0,
    )
    .context("open original blob directory without following symlinks")?;
    let originals_meta = originals.metadata()?;
    ensure!(
        originals_meta.is_dir()
            && (originals_meta.uid(), originals_meta.gid()) == (owner.uid(), owner.gid())
            && originals_meta.mode() & 0o7777 == 0o700,
        "unsafe original blob directory ownership or permissions"
    );
    let held = open_at(
        &originals,
        OsStr::new(&original_blob_file_name(index)),
        libc::O_PATH,
        0,
    )
    .context("open original blob without following symlinks")?;
    let bytes = validate_original_blob_file(&held, owner, member)?;
    Ok((held, bytes))
}

fn validate_original_blob_file(
    held: &File,
    owner: &Metadata,
    member: &JournalMember,
) -> anyhow::Result<Vec<u8>> {
    let meta = held.metadata()?;
    ensure!(
        meta.is_file()
            && meta.nlink() == 1
            && (meta.uid(), meta.gid()) == (owner.uid(), owner.gid())
            && meta.mode() & 0o7777 == 0o600,
        "unsafe original blob type, ownership or permissions"
    );
    ensure!(
        meta.len() == member.before.len,
        "original blob length mismatch"
    );
    let blob = super::write_lock::reopen_inspected(held, libc::O_RDONLY)?;
    let mut bytes = Vec::with_capacity(usize::try_from(meta.len()).unwrap_or(0));
    blob.take(member.before.len.saturating_add(1))
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 == member.before.len,
        "original blob length changed while reading"
    );
    ensure!(
        sha256_hex(&bytes) == member.before.sha256,
        "original blob hash mismatch"
    );
    Ok(bytes)
}

fn validate_member_path(path: &str) -> anyhow::Result<()> {
    ensure!(
        !path.is_empty() && !path.as_bytes().contains(&0),
        "invalid journal path"
    );
    let parsed = Path::new(path);
    ensure!(
        !parsed.is_absolute()
            && parsed
                .components()
                .all(|part| matches!(part, Component::Normal(_))),
        "journal path is not normalized and root-relative"
    );
    let normalized: PathBuf = parsed.components().collect();
    ensure!(
        normalized.as_os_str() == parsed.as_os_str(),
        "journal path is not normalized"
    );
    let mut components = 0_usize;
    for part in parsed.components() {
        let Component::Normal(name) = part else {
            unreachable!("validated journal path contains only normal components")
        };
        components += 1;
        ensure!(
            components <= 8192,
            "journal path exceeds resolution work limit"
        );
        ensure!(
            name.as_bytes().len() <= libc::NAME_MAX as usize,
            "journal path component exceeds filesystem name limit"
        );
        ensure!(
            !reserved_component(name),
            "journal path uses a reserved transaction component"
        );
    }
    Ok(())
}

fn validate_receipt(receipt: &FileReceipt) -> anyhow::Result<()> {
    ensure!(
        receipt.len <= super::loader::MAX_TOTAL_BYTES,
        "journal receipt length exceeds the config tree limit"
    );
    ensure!(
        is_sha256(&receipt.sha256),
        "journal receipt has an invalid SHA-256"
    );
    ensure!(
        receipt.mode & !0o7777 == 0,
        "journal receipt mode is outside Unix permission and special bits"
    );
    Ok(())
}

fn original_blob_name(index: usize) -> String {
    format!("{ORIGINALS_DIR_NAME}/{index:04}.toml")
}

fn original_blob_file_name(index: usize) -> String {
    format!("{index:04}.toml")
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum FenceState {
    Absent,
    // Setup artifacts require inspection by the recovery layer.
    Empty,
    // The recovery layer must validate the full manifest before using it.
    Journal,
    Invalid(String),
}

pub(crate) fn inspect(tree: TreeIo<'_>) -> anyhow::Result<FenceState> {
    let identity = tree.identity;
    let root = tree.root;
    let dir = match open_at(
        root,
        OsStr::new(TXN_DIR_NAME),
        libc::O_RDONLY | libc::O_DIRECTORY,
        0,
    ) {
        Ok(dir) => dir,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(FenceState::Absent),
        Err(e) => {
            return Ok(FenceState::Invalid(format!(
                "cannot open fixed fence directory: {e}"
            )))
        }
    };
    let owner = identity.owner_metadata(root)?;
    let meta = dir.metadata()?;
    if meta.uid() != owner.uid() || meta.gid() != owner.gid() || meta.mode() & 0o7777 != 0o700 {
        return Ok(FenceState::Invalid(
            "unsafe fence ownership or permissions".into(),
        ));
    }
    let journal = match open_at(&dir, OsStr::new(JOURNAL_NAME), libc::O_PATH, 0) {
        Ok(journal) => journal,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(FenceState::Empty),
        Err(e) => {
            return Ok(FenceState::Invalid(format!(
                "cannot open journal without following symlinks: {e}"
            )))
        }
    };
    let meta = journal.metadata()?;
    if !meta.is_file()
        || meta.nlink() != 1
        || meta.uid() != owner.uid()
        || meta.gid() != owner.gid()
        || meta.mode() & 0o7777 != 0o600
        || meta.len() > MAX_JOURNAL_BYTES
    {
        return Ok(FenceState::Invalid(
            "unsafe journal type, ownership, permissions or size".into(),
        ));
    }
    let journal = super::write_lock::reopen_inspected(&journal, libc::O_RDONLY)?;
    let mut bytes = Vec::new();
    journal
        .take(MAX_JOURNAL_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_JOURNAL_BYTES {
        return Ok(FenceState::Invalid("journal exceeds size limit".into()));
    }
    let master = identity
        .canonical_master
        .file_name()
        .context("canonical master filename")?;
    match validate_journal(&bytes, Path::new(master)) {
        Ok(_) => Ok(FenceState::Journal),
        Err(e) => Ok(FenceState::Invalid(format!("invalid journal: {e:#}"))),
    }
}

#[derive(Debug, thiserror::Error)]
#[error("unfinished v3-to-v4 migration at {journal}; run `warden migrate v3-to-v4 --from-config {master}` to recover ({detail})")]
pub(crate) struct FenceRefusal {
    pub(crate) journal: PathBuf,
    master: String,
    detail: String,
}

pub(crate) fn refuse_normal_access(tree: TreeIo<'_>) -> anyhow::Result<()> {
    let identity = tree.identity;
    let detail = match inspect(tree) {
        Ok(FenceState::Absent) => return Ok(()),
        Ok(FenceState::Empty) => "fixed fence exists without a canonical journal".into(),
        Ok(FenceState::Journal) => "journal requires recovery validation".into(),
        Ok(FenceState::Invalid(reason)) => reason,
        Err(e) => format!("cannot safely inspect migration fence: {e:#}"),
    };
    let master = identity.canonical_master.to_string_lossy();
    let master = format!("'{}'", master.replace('\'', "'\\''"));
    Err(FenceRefusal {
        journal: identity.txn_dir.join(JOURNAL_NAME),
        master,
        detail,
    }
    .into())
}

#[derive(Debug, thiserror::Error)]
#[error("retained v3 undo snapshot at {artifact}; run `warden migrate v3-to-v4 --from-config {master} --rollback` or `warden migrate v3-to-v4 --from-config {master} --finalize` before writing ({detail})")]
pub(crate) struct UndoWriteRefusal {
    artifact: PathBuf,
    master: String,
    detail: String,
}

#[derive(Debug, thiserror::Error)]
#[error("incomplete v3-to-v4 finalization at {artifact}; run `warden migrate v3-to-v4 --from-config {master} --finalize` before writing ({detail})")]
pub(crate) struct FinalizeWriteRefusal {
    artifact: PathBuf,
    master: String,
    detail: String,
}

/// Ordinary reads only fence an in-progress publication.  A retained undo is
/// deliberately readable so the candidate daemon can be health-checked.
pub(crate) fn refuse_normal_write(tree: TreeIo<'_>) -> anyhow::Result<()> {
    refuse_normal_access(tree)?;
    let identity = tree.identity;
    let (artifact, detail) = match cleanup_candidate(tree.root) {
        Ok(None) => match finalized_candidate(tree.root) {
            Ok(None) => return Ok(()),
            Ok(Some(name)) => {
                let master = identity.canonical_master.to_string_lossy();
                let master = format!("'{}'", master.replace('\'', "'\\''"));
                return Err(FinalizeWriteRefusal {
                    artifact: identity.root.join(name),
                    master,
                    detail: "terminal cleanup must re-establish its durability barrier".into(),
                }
                .into());
            }
            Err(error) => {
                let master = identity.canonical_master.to_string_lossy();
                let master = format!("'{}'", master.replace('\'', "'\\''"));
                return Err(FinalizeWriteRefusal {
                    artifact: identity.root.join(FINALIZED_DIR_PREFIX),
                    master,
                    detail: format!("cannot safely inspect terminal cleanup: {error:#}"),
                }
                .into());
            }
        },
        Ok(Some(name)) => (
            identity.root.join(name),
            "committed undo snapshot is retained for the release health gate".into(),
        ),
        Err(error) => (
            identity.root.join(CLEANUP_DIR_PREFIX),
            format!("cannot safely inspect retained undo snapshot: {error:#}"),
        ),
    };
    let master = identity.canonical_master.to_string_lossy();
    let master = format!("'{}'", master.replace('\'', "'\\''"));
    Err(UndoWriteRefusal {
        artifact,
        master,
        detail,
    }
    .into())
}

pub(crate) fn create_fence(guard: &MigrationWriteLock) -> anyhow::Result<()> {
    let identity = guard.identity();
    let root = guard.tree_io().root;
    let owner = identity.owner_metadata(root)?;
    let name = CString::new(TXN_DIR_NAME)?;
    let rc = unsafe { libc::mkdirat(root.as_raw_fd(), name.as_ptr(), 0o700) };
    if rc != 0 {
        return Err(io::Error::last_os_error())
            .with_context(|| format!("create migration fence {}", identity.txn_dir.display()));
    }
    // Failure leaves the fixed fence in place so no reader can infer completion.
    let dir = open_at(
        root,
        OsStr::new(TXN_DIR_NAME),
        libc::O_RDONLY | libc::O_DIRECTORY,
        0,
    )?;
    preserve_owner(&dir, &owner)?;
    dir.set_permissions(std::fs::Permissions::from_mode(0o700))?;
    let meta = dir.metadata()?;
    ensure!(
        meta.uid() == owner.uid() && meta.gid() == owner.gid(),
        "migration fence ownership does not match the config tree"
    );
    dir.sync_all()?;
    root.sync_all()?;
    Ok(())
}

pub(crate) fn publish<'g>(
    guard: &'g MigrationWriteLock,
    members: Vec<MigrationMember>,
) -> anyhow::Result<PublishedMigration<'g>> {
    validate_migration_members(guard, &members)?;
    ensure!(
        matches!(inspect(guard.tree_io())?, FenceState::Absent),
        "a fixed migration fence already exists"
    );
    ensure!(
        !root_has_cleanup_artifact(guard.tree_io().root)?,
        "a migration cleanup artifact already exists"
    );

    let tree = guard.tree_io();
    let mut plans = Vec::with_capacity(members.len());
    for member in &members {
        let plan = tree.plan_root_file_no_follow(&member.path)?;
        let metadata = plan
            .original_metadata()
            .context("migration member disappeared before publication")?;
        ensure!(
            receipt_matches(
                metadata,
                &read_plan_bytes(&plan, member.before.len() as u64)?,
                &member.before_receipt
            ),
            "migration member changed before publication: {}",
            member.path.display()
        );
        ensure!(
            same_metadata(metadata, &member.metadata),
            "migration member metadata changed before publication: {}",
            member.path.display()
        );
        plans.push(plan);
    }
    let targets = plans
        .into_iter()
        .map(|plan| plan.materialize())
        .collect::<anyhow::Result<Vec<_>>>()?;

    let journal_members = members
        .iter()
        .map(|member| {
            JournalMember::new(
                &member.path,
                member.role,
                member.before_receipt.clone(),
                member.after_receipt.clone(),
            )
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    let master = guard
        .canonical_master()
        .file_name()
        .context("canonical master filename")?;
    let journal = Journal::new(Path::new(master), journal_members)?;
    let journal_bytes = journal.to_json_bytes()?;
    let journal_hash = sha256_hex(&journal_bytes);

    create_fence(guard)?;
    let root = guard.tree_io().root;
    let owner = guard.identity().owner_metadata(root)?;
    let fence = open_at(
        root,
        OsStr::new(TXN_DIR_NAME),
        libc::O_RDONLY | libc::O_DIRECTORY,
        0,
    )?;
    let originals = create_owned_directory(&fence, ORIGINALS_DIR_NAME, &owner)?;
    for (index, member) in members.iter().enumerate() {
        write_original_blob(&originals, index, &member.before, &owner)?;
    }
    originals.sync_all()?;
    #[cfg(test)]
    run_test_hook(TestHookPoint::OriginalsReady);
    for (index, member) in journal.members().iter().enumerate() {
        validate_original_blob(&fence, &owner, index, member)?;
    }
    write_journal(&fence, &journal_bytes, &owner, Path::new(master))?;

    let parsed = read_valid_journal(&fence, &owner, Path::new(master))?;
    let _inventory = validate_fence_inventory(&fence, &owner, &parsed, false)?;
    for (index, member) in parsed.members().iter().enumerate() {
        validate_original_blob(&fence, &owner, index, member)?;
    }
    Ok(PublishedMigration {
        guard,
        members,
        targets,
        journal: parsed,
        journal_hash,
        fence,
        owner,
    })
}

impl PublishedMigration<'_> {
    pub(crate) fn promote_all(&mut self) -> anyhow::Result<()> {
        self.validate_snapshot()?;
        for member in &self.members {
            ensure!(
                matches!(
                    classify_live(self.guard, member)?,
                    LiveState::Before | LiveState::BeforeAndAfter
                ),
                "migration member is not its expected before image before promotion: {}",
                member.path.display()
            );
        }
        for (member, target) in self.members.iter().zip(&self.targets) {
            hardened_atomic_write_at(
                target,
                &member.after,
                AtomicWriteAtOpts {
                    mode: Some(member.after_receipt.mode),
                    owner: Some((member.after_receipt.uid, member.after_receipt.gid)),
                    fsync_parent: true,
                    ..Default::default()
                },
            )
            .map_err(anyhow::Error::from)
            .with_context(|| format!("promote migration member {}", member.path.display()))?;
            #[cfg(test)]
            if take_promotion_failure_after_success() {
                anyhow::bail!("injected promotion failure");
            }
        }
        Ok(())
    }

    pub(crate) fn commit(self) -> Result<PathBuf, CommitError> {
        self.validate_snapshot()
            .map_err(CommitError::RenameNotLanded)?;
        for (member, target) in self.members.iter().zip(&self.targets) {
            let plan = self
                .guard
                .tree_io()
                .plan_root_file_no_follow(&member.path)
                .map_err(CommitError::RenameNotLanded)?;
            let state = classify_receipts(&plan, &member.before_receipt, &member.after_receipt)
                .map_err(CommitError::RenameNotLanded)?;
            if !matches!(state, LiveState::After | LiveState::BeforeAndAfter) {
                return Err(CommitError::RenameNotLanded(anyhow::anyhow!(
                    "migration member is not its expected after image: {}",
                    member.path.display()
                )));
            }
            target
                .sync_held_file_and_parent()
                .map_err(|error| CommitError::RenameNotLanded(error.into()))?;
        }
        let cleanup = cleanup_name(&self.journal_hash);
        let current_fence = inspect_at(self.guard.tree_io().root, OsStr::new(TXN_DIR_NAME))
            .map_err(|error| CommitError::RenameNotLanded(error.into()))?
            .ok_or_else(|| {
                CommitError::RenameNotLanded(anyhow::anyhow!(
                    "fixed migration fence disappeared before commit"
                ))
            })?;
        if !same_inode(
            &current_fence
                .metadata()
                .map_err(|error| CommitError::RenameNotLanded(error.into()))?,
            &self
                .fence
                .metadata()
                .map_err(|error| CommitError::RenameNotLanded(error.into()))?,
        ) {
            return Err(CommitError::RenameNotLanded(anyhow::anyhow!(
                "fixed migration fence was replaced before commit"
            )));
        }
        #[cfg(test)]
        if take_commit_failure_before_rename() {
            return Err(CommitError::RenameNotLanded(anyhow::anyhow!(
                "injected commit failure before fence rename"
            )));
        }
        rename_noreplace_at(
            self.guard.tree_io().root,
            OsStr::new(TXN_DIR_NAME),
            self.guard.tree_io().root,
            OsStr::new(&cleanup),
        )
        .map_err(|error| CommitError::RenameNotLanded(error.into()))?;
        let cleanup_path = self.guard.identity().root.join(&cleanup);
        #[cfg(test)]
        if take_commit_root_fsync_uncertain() {
            return Err(CommitError::RootFsyncUncertain {
                cleanup: cleanup_path,
                source: anyhow::anyhow!("injected root fsync uncertainty after fence rename"),
            });
        }
        self.guard
            .tree_io()
            .sync_root()
            .map_err(|error| CommitError::RootFsyncUncertain {
                cleanup: cleanup_path.clone(),
                source: error.into(),
            })?;
        Ok(cleanup_path)
    }

    fn validate_snapshot(&self) -> anyhow::Result<()> {
        let master = self
            .guard
            .canonical_master()
            .file_name()
            .context("canonical master filename")?;
        let bytes = read_journal_bytes(&self.fence, &self.owner)?;
        ensure!(
            sha256_hex(&bytes) == self.journal_hash,
            "published journal changed after validation"
        );
        let journal = validate_journal(&bytes, Path::new(master))?;
        ensure!(
            journal.members().len() == self.journal.members().len(),
            "published journal member count changed"
        );
        let _inventory = validate_fence_inventory(&self.fence, &self.owner, &journal, false)?;
        for (index, member) in journal.members().iter().enumerate() {
            validate_original_blob(&self.fence, &self.owner, index, member)?;
        }
        Ok(())
    }
}

pub(crate) fn recover_fixed(
    guard: &MigrationWriteLock,
    validate_restored_v3: impl FnOnce() -> anyhow::Result<()>,
) -> anyhow::Result<RecoveryOutcome> {
    recover_fixed_with_inventory(guard, |_| validate_restored_v3())
}

fn recover_fixed_with_inventory(
    guard: &MigrationWriteLock,
    validate_restored_v3: impl FnOnce(&[PathBuf]) -> anyhow::Result<()>,
) -> anyhow::Result<RecoveryOutcome> {
    let root = guard.tree_io().root;
    let fence = match open_at(
        root,
        OsStr::new(TXN_DIR_NAME),
        libc::O_RDONLY | libc::O_DIRECTORY,
        0,
    ) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return recover_cleanup(guard),
        Err(error) => return Err(error).context("open fixed migration fence"),
    };
    let owner = guard.identity().owner_metadata(root)?;
    validate_owned_directory(&fence, &owner, 0o700, "migration fence")?;
    let journal_file = inspect_at(&fence, OsStr::new(JOURNAL_NAME))?;
    if journal_file.is_none() {
        let inventory = validate_setup_inventory(&fence, &owner)?;
        remove_setup_fence(root, &fence, inventory)?;
        return Ok(RecoveryOutcome::SetupRemoved);
    }

    let master = guard
        .canonical_master()
        .file_name()
        .context("canonical master filename")?;
    let journal = read_valid_journal(&fence, &owner, Path::new(master))?;
    let inventory = validate_fence_inventory(&fence, &owner, &journal, false)?;
    let originals = journal
        .members()
        .iter()
        .enumerate()
        .map(|(index, member)| validate_original_blob(&fence, &owner, index, member))
        .collect::<anyhow::Result<Vec<_>>>()?;
    let mut states = Vec::with_capacity(journal.members().len());
    let mut plans = Vec::with_capacity(journal.members().len());
    for member in journal.members() {
        let plan = guard
            .tree_io()
            .plan_root_file_no_follow(Path::new(&member.path))?;
        states.push(classify_receipts(&plan, &member.before, &member.after)?);
        plans.push(plan);
    }
    ensure!(
        !states.contains(&LiveState::Other),
        "migration recovery found an untrusted live member"
    );
    #[cfg(test)]
    run_test_hook(TestHookPoint::RecoveryClassified);
    ensure_current_inode(
        root,
        OsStr::new(TXN_DIR_NAME),
        &fence,
        "fixed migration fence",
    )?;
    // Recovery may be retrying an undo-to-fixed rename whose fsync was uncertain.
    sync_rollback_root(root, RollbackSyncPoint::FixedFence)?;

    let targets = plans
        .into_iter()
        .zip(&states)
        .map(|(plan, state)| {
            (state == &LiveState::After)
                .then(|| plan.materialize())
                .transpose()
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    for index in (0..journal.members().len()).rev() {
        if states[index] != LiveState::After {
            continue;
        }
        let member = &journal.members()[index];
        let target = targets[index]
            .as_ref()
            .expect("after state has a pinned target");
        hardened_atomic_write_at(
            target,
            &originals[index],
            AtomicWriteAtOpts {
                mode: Some(member.before.mode),
                owner: Some((member.before.uid, member.before.gid)),
                fsync_parent: true,
                ..Default::default()
            },
        )
        .map_err(anyhow::Error::from)
        .with_context(|| format!("restore migration member {}", member.path))?;
    }
    for member in journal.members() {
        ensure!(
            matches!(
                classify_receipts(
                    &guard
                        .tree_io()
                        .plan_root_file_no_follow(Path::new(&member.path))?,
                    &member.before,
                    &member.after,
                )?,
                LiveState::Before | LiveState::BeforeAndAfter
            ),
            "migration member did not restore to its before image: {}",
            member.path
        );
    }
    let members = journal_member_inventory(&journal);
    validate_restored_v3(&members)?;

    let journal_hash = sha256_hex(&read_journal_bytes(&fence, &owner)?);
    let cleanup = cleanup_name(&journal_hash);
    rename_noreplace_at(root, OsStr::new(TXN_DIR_NAME), root, OsStr::new(&cleanup))?;
    sync_rollback_root(root, RollbackSyncPoint::Cleanup)?;
    remove_validated_fence(root, &fence, &cleanup, &journal, inventory)?;
    root.sync_all()?;
    Ok(RecoveryOutcome::RolledBack)
}

fn recover_cleanup(guard: &MigrationWriteLock) -> anyhow::Result<RecoveryOutcome> {
    let root = guard.tree_io().root;
    let Some(cleanup) = cleanup_candidate(root)? else {
        return Ok(RecoveryOutcome::Absent);
    };
    let fence = open_at(root, &cleanup, libc::O_RDONLY | libc::O_DIRECTORY, 0)
        .context("open migration cleanup directory")?;
    let owner = guard.identity().owner_metadata(root)?;
    validate_owned_directory(&fence, &owner, 0o700, "migration cleanup directory")?;
    if inspect_at(&fence, OsStr::new(JOURNAL_NAME))?.is_none() {
        let mut empty = true;
        visit_directory(&fence, |_| {
            empty = false;
            Ok(true)
        })?;
        ensure!(empty, "journal-less migration cleanup is not empty");
        checked_rmdir(root, &cleanup, &fence)?;
        root.sync_all()?;
        return Ok(RecoveryOutcome::RolledBack);
    }
    let master = guard
        .canonical_master()
        .file_name()
        .context("canonical master filename")?;
    let journal_bytes = read_journal_bytes(&fence, &owner)?;
    let expected_cleanup = cleanup_name(&sha256_hex(&journal_bytes));
    ensure!(
        cleanup == OsStr::new(&expected_cleanup),
        "migration cleanup name does not match its journal"
    );
    let journal = validate_journal(&journal_bytes, Path::new(master))?;
    let inventory = validate_cleanup_inventory(&fence, &owner, &journal)?;
    let mut before_only = true;
    let mut after_only = true;
    for member in journal.members() {
        let plan = guard
            .tree_io()
            .plan_root_file_no_follow(Path::new(&member.path))?;
        match classify_receipts(&plan, &member.before, &member.after)? {
            LiveState::Before => after_only = false,
            LiveState::After => before_only = false,
            LiveState::BeforeAndAfter => {}
            LiveState::Other => anyhow::bail!("migration cleanup found an untrusted live member"),
        }
    }
    ensure!(
        before_only || after_only,
        "migration cleanup has mixed live members"
    );
    if after_only {
        ensure!(
            inventory.originals.is_some(),
            "committed migration cleanup is missing its originals directory"
        );
        for (index, member) in journal.members().iter().enumerate() {
            let blob = inventory.blobs[index]
                .as_ref()
                .context("committed migration cleanup is missing an original blob")?;
            validate_original_blob_file(blob, &owner, member)?;
        }
        return Ok(RecoveryOutcome::Absent);
    }
    ensure_current_inode(root, &cleanup, &fence, "migration recovery cleanup")?;
    sync_rollback_root(root, RollbackSyncPoint::Cleanup)?;
    remove_cleanup_inventory(root, &fence, &cleanup, &journal, inventory)?;
    root.sync_all()?;
    Ok(RecoveryOutcome::RolledBack)
}

/// Restore a committed undo only when the installed tree is wholly the
/// journal's after-image.  The rename back to the fixed fence makes a failed
/// rollback retry use the same pre-commit recovery path.
pub(crate) fn rollback(
    guard: &MigrationWriteLock,
    validate_restored_v3: impl FnOnce(&[PathBuf]) -> anyhow::Result<()>,
) -> anyhow::Result<RollbackOutcome> {
    let fixed = inspect(guard.tree_io())?;
    let root = guard.tree_io().root;
    let terminal = finalized_candidate(root)?;
    let cleanup = cleanup_candidate(root)?;
    if !matches!(fixed, FenceState::Absent) {
        ensure!(
            cleanup.is_none() && terminal.is_none(),
            "fixed migration fence conflicts with another migration artifact"
        );
        return match recover_fixed_with_inventory(guard, validate_restored_v3)? {
            RecoveryOutcome::SetupRemoved => Ok(RollbackOutcome::SetupRemoved),
            RecoveryOutcome::RolledBack => Ok(RollbackOutcome::Restored),
            RecoveryOutcome::Absent => {
                anyhow::bail!("fixed migration fence disappeared during rollback")
            }
        };
    }

    ensure!(
        terminal.is_none() || cleanup.is_none(),
        "simultaneous migration undo and terminal artifacts"
    );
    let Some(cleanup) = cleanup else {
        ensure!(
            terminal.is_none(),
            "terminal migration cleanup cannot be used as rollback evidence"
        );
        return Ok(RollbackOutcome::NoArtifact);
    };

    let fence = open_at(root, &cleanup, libc::O_RDONLY | libc::O_DIRECTORY, 0)
        .context("open committed migration undo directory")?;
    let owner = guard.identity().owner_metadata(root)?;
    validate_owned_directory(&fence, &owner, 0o700, "committed migration undo directory")?;
    if inspect_at(&fence, OsStr::new(JOURNAL_NAME))?.is_none() {
        let mut empty = true;
        visit_directory(&fence, |_| {
            empty = false;
            Ok(true)
        })?;
        ensure!(empty, "journal-less migration cleanup is not empty");
        checked_rmdir(root, &cleanup, &fence)?;
        root.sync_all()?;
        return Ok(RollbackOutcome::SetupRemoved);
    }
    let master = guard
        .canonical_master()
        .file_name()
        .context("canonical master filename")?;
    let bytes = read_journal_bytes(&fence, &owner)?;
    ensure!(
        cleanup == OsStr::new(&cleanup_name(&sha256_hex(&bytes))),
        "migration cleanup name does not match its journal"
    );
    let journal = validate_journal(&bytes, Path::new(master))?;
    let inventory = validate_cleanup_inventory(&fence, &owner, &journal)?;
    let mut before_only = true;
    let mut after_only = true;
    for member in journal.members() {
        match classify_receipts(
            &guard
                .tree_io()
                .plan_root_file_no_follow(Path::new(&member.path))?,
            &member.before,
            &member.after,
        )? {
            LiveState::Before => after_only = false,
            LiveState::After => before_only = false,
            LiveState::BeforeAndAfter => {}
            LiveState::Other => {
                anyhow::bail!("committed migration undo found an untrusted live member")
            }
        }
    }
    ensure!(
        before_only || after_only,
        "committed migration undo has mixed live members"
    );
    if before_only {
        let members = journal_member_inventory(&journal);
        ensure_current_inode(root, &cleanup, &fence, "migration rollback cleanup")?;
        // Recovery may be retrying a fixed-to-cleanup rename whose fsync was uncertain.
        sync_rollback_root(root, RollbackSyncPoint::Cleanup)?;
        validate_restored_v3(&members)?;
        ensure_current_inode(root, &cleanup, &fence, "migration rollback cleanup")?;
        remove_cleanup_inventory(root, &fence, &cleanup, &journal, inventory)?;
        root.sync_all()?;
        return Ok(RollbackOutcome::Restored);
    }
    ensure!(
        inventory.originals.is_some(),
        "committed migration cleanup is missing its originals directory"
    );
    for (index, member) in journal.members().iter().enumerate() {
        let blob = inventory.blobs[index]
            .as_ref()
            .context("committed migration cleanup is missing an original blob")?;
        validate_original_blob_file(blob, &owner, member)?;
    }
    ensure_current_inode(root, &cleanup, &fence, "committed migration undo")?;
    rename_noreplace_at(root, &cleanup, root, OsStr::new(TXN_DIR_NAME))?;
    // Once this rename lands, ordinary access is fenced until this rollback finishes.
    sync_rollback_root(root, RollbackSyncPoint::FixedFence)?;
    match recover_fixed_with_inventory(guard, validate_restored_v3)? {
        RecoveryOutcome::RolledBack => Ok(RollbackOutcome::Restored),
        RecoveryOutcome::SetupRemoved | RecoveryOutcome::Absent => {
            anyhow::bail!("renamed committed undo lost its validated journal")
        }
    }
}

/// Commit the decision to retain v4, then delete the retained undo in a
/// namespace that can only ever be resumed as deletion.
pub(crate) fn finalize(
    guard: &MigrationWriteLock,
    validate_installed_v4: impl FnOnce(&[PathBuf]) -> anyhow::Result<()>,
) -> anyhow::Result<FinalizeOutcome> {
    ensure!(
        matches!(inspect(guard.tree_io())?, FenceState::Absent),
        "cannot finalize while a fixed migration fence exists"
    );
    let root = guard.tree_io().root;
    let terminal = finalized_candidate(root)?;
    let cleanup = cleanup_candidate(root)?;
    ensure!(
        terminal.is_none() || cleanup.is_none(),
        "simultaneous migration undo and terminal artifacts"
    );
    if let Some(terminal) = terminal {
        resume_terminal_cleanup(guard, &terminal)?;
        return Ok(FinalizeOutcome::Finalized);
    }
    let Some(cleanup) = cleanup else {
        return Ok(FinalizeOutcome::NoArtifact);
    };

    let fence = open_at(root, &cleanup, libc::O_RDONLY | libc::O_DIRECTORY, 0)
        .context("open committed migration undo directory")?;
    let owner = guard.identity().owner_metadata(root)?;
    validate_owned_directory(&fence, &owner, 0o700, "committed migration undo directory")?;
    let master = guard
        .canonical_master()
        .file_name()
        .context("canonical master filename")?;
    let bytes = read_journal_bytes(&fence, &owner)?;
    let hash = sha256_hex(&bytes);
    ensure!(
        cleanup == OsStr::new(&cleanup_name(&hash)),
        "migration cleanup name does not match its journal"
    );
    let journal = validate_journal(&bytes, Path::new(master))?;
    let inventory = validate_cleanup_inventory(&fence, &owner, &journal)?;
    ensure!(
        inventory.originals.is_some() && inventory.blobs.iter().all(Option::is_some),
        "committed migration cleanup is missing part of its undo snapshot"
    );
    for (index, member) in journal.members().iter().enumerate() {
        validate_original_blob_file(
            inventory.blobs[index]
                .as_ref()
                .expect("checked complete undo"),
            &owner,
            member,
        )?;
        ensure!(
            matches!(
                classify_receipts(
                    &guard
                        .tree_io()
                        .plan_root_file_no_follow(Path::new(&member.path))?,
                    &member.before,
                    &member.after,
                )?,
                LiveState::After | LiveState::BeforeAndAfter
            ),
            "committed migration undo does not match the complete installed after-image: {}",
            member.path
        );
    }
    let members = journal_member_inventory(&journal);
    validate_installed_v4(&members)?;

    let terminal = finalized_name(&hash);
    ensure_current_inode(root, &cleanup, &fence, "committed migration undo")?;
    rename_noreplace_at(root, &cleanup, root, OsStr::new(&terminal))?;
    // This is the irreversible release-gate decision; deletion follows only after it is durable.
    sync_finalize_root(root)?;
    remove_cleanup_inventory(root, &fence, OsStr::new(&terminal), &journal, inventory)?;
    root.sync_all()?;
    Ok(FinalizeOutcome::Finalized)
}

fn resume_terminal_cleanup(guard: &MigrationWriteLock, terminal: &OsStr) -> anyhow::Result<()> {
    let root = guard.tree_io().root;
    let fence = open_at(root, terminal, libc::O_RDONLY | libc::O_DIRECTORY, 0)
        .context("open terminal migration cleanup directory")?;
    let owner = guard.identity().owner_metadata(root)?;
    validate_owned_directory(
        &fence,
        &owner,
        0o700,
        "terminal migration cleanup directory",
    )?;
    ensure_current_inode(root, terminal, &fence, "terminal migration cleanup")?;
    // A prior finalize may have returned after the rename but before its fsync.
    // Re-establish that irreversible decision before deleting rollback data.
    sync_finalize_root(root)?;
    if inspect_at(&fence, OsStr::new(JOURNAL_NAME))?.is_none() {
        let mut empty = true;
        visit_directory(&fence, |_| {
            empty = false;
            Ok(true)
        })?;
        ensure!(
            empty,
            "terminal migration cleanup without a journal is not empty"
        );
        checked_rmdir(root, terminal, &fence)?;
        root.sync_all()?;
        return Ok(());
    }
    let master = guard
        .canonical_master()
        .file_name()
        .context("canonical master filename")?;
    let bytes = read_journal_bytes(&fence, &owner)?;
    ensure!(
        terminal == OsStr::new(&finalized_name(&sha256_hex(&bytes))),
        "terminal migration cleanup name does not match its journal"
    );
    let journal = validate_journal(&bytes, Path::new(master))?;
    let inventory = validate_cleanup_inventory(&fence, &owner, &journal)?;
    remove_cleanup_inventory(root, &fence, terminal, &journal, inventory)?;
    root.sync_all()?;
    Ok(())
}

fn ensure_current_inode(root: &File, name: &OsStr, held: &File, what: &str) -> anyhow::Result<()> {
    let current = inspect_at(root, name)?.context("migration artifact disappeared")?;
    ensure!(
        same_inode(&current.metadata()?, &held.metadata()?),
        "{what} was replaced"
    );
    Ok(())
}

fn journal_member_inventory(journal: &Journal) -> Vec<PathBuf> {
    journal
        .members()
        .iter()
        .map(|member| PathBuf::from(&member.path))
        .collect()
}

fn cleanup_candidate(root: &File) -> anyhow::Result<Option<std::ffi::OsString>> {
    artifact_candidate(root, CLEANUP_DIR_PREFIX, "cleanup")
}

fn finalized_candidate(root: &File) -> anyhow::Result<Option<std::ffi::OsString>> {
    artifact_candidate(root, FINALIZED_DIR_PREFIX, "terminal")
}

fn artifact_candidate(
    root: &File,
    prefix: &str,
    kind: &str,
) -> anyhow::Result<Option<std::ffi::OsString>> {
    let mut candidates = Vec::with_capacity(2);
    visit_directory(root, |name| {
        let bytes = name.as_bytes();
        if !bytes.starts_with(prefix.as_bytes()) {
            return Ok(false);
        }
        let suffix = &bytes[prefix.len()..];
        ensure!(
            suffix.len() == 32
                && suffix
                    .iter()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')),
            "malformed migration {kind} artifact"
        );
        candidates.push(name.to_os_string());
        Ok(candidates.len() == 2)
    })?;
    ensure!(candidates.len() <= 1, "multiple migration {kind} artifacts");
    Ok(candidates.pop())
}

fn validate_migration_members(
    guard: &MigrationWriteLock,
    members: &[MigrationMember],
) -> anyhow::Result<()> {
    ensure!(
        !members.is_empty() && members.len() <= super::loader::MAX_INCLUDE_FILES,
        "migration member count is outside the allowed range"
    );
    let master = guard
        .canonical_master()
        .file_name()
        .context("canonical master filename")?;
    let mut paths = BTreeSet::new();
    for (index, member) in members.iter().enumerate() {
        validate_member_path(
            member
                .path
                .to_str()
                .context("migration member path is not valid UTF-8")?,
        )?;
        ensure!(
            paths.insert(&member.path),
            "migration member paths must be unique"
        );
        if index + 1 == members.len() {
            ensure!(
                member.role == MemberRole::Master && member.path == Path::new(master),
                "migration master must be canonical and final"
            );
        } else {
            ensure!(
                member.role == MemberRole::Include,
                "migration includes must precede the master"
            );
            if index > 0 {
                ensure!(
                    members[index - 1].path.as_os_str().as_bytes()
                        < member.path.as_os_str().as_bytes(),
                    "migration includes must be bytewise sorted"
                );
            }
        }
    }
    Ok(())
}

fn read_plan_bytes(
    plan: &super::tree_io::TargetPlan<'_>,
    expected_len: u64,
) -> anyhow::Result<Vec<u8>> {
    match plan.read_original_capped(expected_len)? {
        CappedRead::Contents(bytes) => Ok(bytes),
        CappedRead::Missing => anyhow::bail!("migration member disappeared while reading"),
        CappedRead::LimitExceeded { .. } => anyhow::bail!("migration member exceeds its receipt"),
    }
}

fn receipt_matches(metadata: &Metadata, bytes: &[u8], receipt: &FileReceipt) -> bool {
    metadata.is_file()
        && metadata.nlink() == 1
        && metadata.len() == receipt.len
        && metadata.uid() == receipt.uid
        && metadata.gid() == receipt.gid
        && metadata.mode() & 0o7777 == receipt.mode
        && sha256_hex(bytes) == receipt.sha256
}

fn same_metadata(current: &Metadata, captured: &Metadata) -> bool {
    current.dev() == captured.dev()
        && current.ino() == captured.ino()
        && current.ctime() == captured.ctime()
        && current.ctime_nsec() == captured.ctime_nsec()
        && current.len() == captured.len()
        && current.uid() == captured.uid()
        && current.gid() == captured.gid()
        && current.mode() == captured.mode()
        && current.nlink() == captured.nlink()
}

fn classify_live(
    guard: &MigrationWriteLock,
    member: &MigrationMember,
) -> anyhow::Result<LiveState> {
    let plan = guard.tree_io().plan_root_file_no_follow(&member.path)?;
    classify_receipts(&plan, &member.before_receipt, &member.after_receipt)
}

fn classify_receipts(
    plan: &TargetPlan<'_>,
    before: &FileReceipt,
    after: &FileReceipt,
) -> anyhow::Result<LiveState> {
    let Some(metadata) = plan.original_metadata() else {
        return Ok(LiveState::Other);
    };
    let bytes = match plan.read_original_capped(super::loader::MAX_TOTAL_BYTES)? {
        CappedRead::Contents(bytes) => bytes,
        CappedRead::Missing | CappedRead::LimitExceeded { .. } => return Ok(LiveState::Other),
    };
    let is_before = receipt_matches(metadata, &bytes, before);
    let is_after = receipt_matches(metadata, &bytes, after);
    Ok(match (is_before, is_after) {
        (true, true) => LiveState::BeforeAndAfter,
        (true, false) => LiveState::Before,
        (false, true) => LiveState::After,
        (false, false) => LiveState::Other,
    })
}

fn validate_owned_directory(
    directory: &File,
    owner: &Metadata,
    mode: u32,
    name: &str,
) -> anyhow::Result<()> {
    let metadata = directory.metadata()?;
    ensure!(
        metadata.is_dir()
            && (metadata.uid(), metadata.gid()) == (owner.uid(), owner.gid())
            && metadata.mode() & 0o7777 == mode,
        "unsafe {name} ownership or permissions"
    );
    Ok(())
}

fn create_owned_directory(parent: &File, name: &str, owner: &Metadata) -> anyhow::Result<File> {
    let name_c = CString::new(name)?;
    if unsafe { libc::mkdirat(parent.as_raw_fd(), name_c.as_ptr(), 0o700) } != 0 {
        return Err(io::Error::last_os_error()).with_context(|| format!("create {name}"));
    }
    let directory = open_at(
        parent,
        OsStr::new(name),
        libc::O_RDONLY | libc::O_DIRECTORY,
        0,
    )?;
    preserve_owner(&directory, owner)?;
    directory.set_permissions(std::fs::Permissions::from_mode(0o700))?;
    validate_owned_directory(&directory, owner, 0o700, name)?;
    directory.sync_all()?;
    parent.sync_all()?;
    Ok(directory)
}

fn write_original_blob(
    originals: &File,
    index: usize,
    bytes: &[u8],
    owner: &Metadata,
) -> anyhow::Result<()> {
    let name = original_blob_file_name(index);
    let mut blob = open_at(
        originals,
        OsStr::new(&name),
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        0o600,
    )?;
    preserve_owner(&blob, owner)?;
    blob.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    blob.write_all(bytes)?;
    blob.sync_all()?;
    let metadata = blob.metadata()?;
    ensure!(
        metadata.is_file()
            && metadata.nlink() == 1
            && (metadata.uid(), metadata.gid()) == (owner.uid(), owner.gid())
            && metadata.mode() & 0o7777 == 0o600
            && metadata.len() == bytes.len() as u64,
        "original blob metadata changed during publication"
    );
    Ok(())
}

fn write_journal(
    fence: &File,
    bytes: &[u8],
    owner: &Metadata,
    master: &Path,
) -> anyhow::Result<()> {
    let mut stage = open_at(
        fence,
        OsStr::new(JOURNAL_STAGE_NAME),
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        0o600,
    )?;
    preserve_owner(&stage, owner)?;
    stage.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    stage.write_all(bytes)?;
    stage.sync_all()?;
    #[cfg(test)]
    run_test_hook(TestHookPoint::JournalStageReady);
    let staged = validate_safe_file(fence, OsStr::new(JOURNAL_STAGE_NAME), owner, 0o600, None)?;
    let staged_meta = staged.metadata()?;
    ensure!(
        staged_meta.len() <= MAX_JOURNAL_BYTES,
        "journal stage exceeds size limit"
    );
    let mut staged_bytes = Vec::with_capacity(staged_meta.len() as usize);
    super::write_lock::reopen_inspected(&staged, libc::O_RDONLY)?
        .take(MAX_JOURNAL_BYTES + 1)
        .read_to_end(&mut staged_bytes)?;
    ensure!(
        staged_bytes == bytes && sha256_hex(&staged_bytes) == sha256_hex(bytes),
        "journal stage changed during publication"
    );
    validate_journal(&staged_bytes, master)?;
    rename_noreplace_at(
        fence,
        OsStr::new(JOURNAL_STAGE_NAME),
        fence,
        OsStr::new(JOURNAL_NAME),
    )?;
    fence.sync_all()?;
    Ok(())
}

fn read_journal_bytes(fence: &File, owner: &Metadata) -> anyhow::Result<Vec<u8>> {
    let file = open_at(fence, OsStr::new(JOURNAL_NAME), libc::O_PATH, 0)?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file()
            && metadata.nlink() == 1
            && (metadata.uid(), metadata.gid()) == (owner.uid(), owner.gid())
            && metadata.mode() & 0o7777 == 0o600
            && metadata.len() <= MAX_JOURNAL_BYTES,
        "unsafe journal type, ownership, permissions or size"
    );
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    super::write_lock::reopen_inspected(&file, libc::O_RDONLY)?
        .take(MAX_JOURNAL_BYTES + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= MAX_JOURNAL_BYTES,
        "journal exceeds size limit"
    );
    Ok(bytes)
}

fn read_valid_journal(fence: &File, owner: &Metadata, master: &Path) -> anyhow::Result<Journal> {
    validate_journal(&read_journal_bytes(fence, owner)?, master)
}

fn visit_directory(
    directory: &File,
    mut visit: impl FnMut(&OsStr) -> anyhow::Result<bool>,
) -> anyhow::Result<()> {
    let readable =
        super::write_lock::reopen_inspected(directory, libc::O_RDONLY | libc::O_DIRECTORY)?;
    let fd = unsafe { libc::fcntl(readable.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error().into());
    }
    let raw = unsafe { libc::fdopendir(fd) };
    if raw.is_null() {
        drop(unsafe { File::from_raw_fd(fd) });
        return Err(io::Error::last_os_error().into());
    }
    struct Stream(*mut libc::DIR);
    impl Drop for Stream {
        fn drop(&mut self) {
            unsafe { libc::closedir(self.0) };
        }
    }
    let stream = Stream(raw);
    loop {
        unsafe { *libc::__errno_location() = 0 };
        let entry = unsafe { libc::readdir(stream.0) };
        if entry.is_null() {
            if io::Error::last_os_error().raw_os_error() != Some(0) {
                return Err(io::Error::last_os_error().into());
            }
            break;
        }
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        if name != b"." && name != b".." && visit(OsStr::from_bytes(name))? {
            break;
        }
    }
    Ok(())
}

struct FenceInventory {
    journal: File,
    originals: File,
    blobs: Vec<File>,
}

struct CleanupInventory {
    journal: File,
    originals: Option<File>,
    blobs: Vec<Option<File>>,
}

fn validate_cleanup_inventory(
    fence: &File,
    owner: &Metadata,
    journal: &Journal,
) -> anyhow::Result<CleanupInventory> {
    let mut count = 0_usize;
    visit_directory(fence, |name| {
        count += 1;
        ensure!(count <= 3, "too many migration cleanup artifacts");
        ensure!(
            name == OsStr::new(JOURNAL_NAME) || name == OsStr::new(ORIGINALS_DIR_NAME),
            "unexpected migration cleanup artifact: {}",
            Path::new(name).display()
        );
        Ok(false)
    })?;
    let journal_file = validate_safe_file(fence, OsStr::new(JOURNAL_NAME), owner, 0o600, None)?;
    let Some(originals) = inspect_at(fence, OsStr::new(ORIGINALS_DIR_NAME))? else {
        return Ok(CleanupInventory {
            journal: journal_file,
            originals: None,
            blobs: (0..journal.members().len()).map(|_| None).collect(),
        });
    };
    validate_owned_directory(&originals, owner, 0o700, "original blob directory")?;
    let originals =
        super::write_lock::reopen_inspected(&originals, libc::O_RDONLY | libc::O_DIRECTORY)?;
    let mut blobs = (0..journal.members().len())
        .map(|_| None)
        .collect::<Vec<_>>();
    let mut count = 0_usize;
    visit_directory(&originals, |name| {
        count += 1;
        ensure!(
            count <= journal.members().len() + 1,
            "too many migration cleanup blobs"
        );
        let text = name.to_str().context("non-UTF-8 migration cleanup blob")?;
        let index = parse_blob_index(text).context("unexpected migration cleanup blob")?;
        ensure!(index < blobs.len(), "unexpected migration cleanup blob");
        ensure!(blobs[index].is_none(), "duplicate migration cleanup blob");
        blobs[index] = Some(validate_safe_file(&originals, name, owner, 0o600, None)?);
        Ok(false)
    })?;
    Ok(CleanupInventory {
        journal: journal_file,
        originals: Some(originals),
        blobs,
    })
}

fn validate_fence_inventory(
    fence: &File,
    owner: &Metadata,
    journal: &Journal,
    allow_stage: bool,
) -> anyhow::Result<FenceInventory> {
    let expected = [JOURNAL_NAME, ORIGINALS_DIR_NAME];
    let mut count = 0_usize;
    visit_directory(fence, |name| {
        count += 1;
        ensure!(
            count <= expected.len() + usize::from(allow_stage),
            "too many migration fence artifacts"
        );
        let text = name.to_str().context("non-UTF-8 fence artifact")?;
        ensure!(
            expected.contains(&text) || (allow_stage && text == JOURNAL_STAGE_NAME),
            "unexpected migration fence artifact: {text}"
        );
        Ok(false)
    })?;
    let originals = open_at(
        fence,
        OsStr::new(ORIGINALS_DIR_NAME),
        libc::O_RDONLY | libc::O_DIRECTORY,
        0,
    )?;
    validate_owned_directory(&originals, owner, 0o700, "original blob directory")?;
    let expected_blobs = (0..journal.members().len())
        .map(original_blob_file_name)
        .collect::<BTreeSet<_>>();
    let mut count = 0_usize;
    visit_directory(&originals, |name| {
        count += 1;
        ensure!(
            count <= journal.members().len() + 1,
            "too many original blob artifacts"
        );
        let text = name.to_str().context("non-UTF-8 original blob artifact")?;
        ensure!(
            expected_blobs.contains(text),
            "unexpected original blob artifact: {text}"
        );
        Ok(false)
    })?;
    let journal_file = validate_safe_file(fence, OsStr::new(JOURNAL_NAME), owner, 0o600, None)?;
    let mut blobs = Vec::with_capacity(journal.members().len());
    for (index, member) in journal.members().iter().enumerate() {
        blobs.push(validate_original_blob_held(fence, owner, index, member)?.0);
    }
    Ok(FenceInventory {
        journal: journal_file,
        originals,
        blobs,
    })
}

struct SetupInventory {
    stage: Option<File>,
    originals: Option<File>,
    blobs: Vec<(std::ffi::OsString, File)>,
}

fn validate_setup_inventory(fence: &File, owner: &Metadata) -> anyhow::Result<SetupInventory> {
    let mut has_originals = false;
    let mut stage = None;
    let mut count = 0_usize;
    visit_directory(fence, |name| {
        count += 1;
        ensure!(count <= 3, "too many setup artifacts");
        ensure!(
            name == OsStr::new(JOURNAL_STAGE_NAME) || name == OsStr::new(ORIGINALS_DIR_NAME),
            "unexpected setup artifact: {}",
            name.display()
        );
        if name == OsStr::new(JOURNAL_STAGE_NAME) {
            let held =
                validate_safe_file(fence, OsStr::new(JOURNAL_STAGE_NAME), owner, 0o600, None)?;
            ensure!(
                held.metadata()?.len() <= MAX_JOURNAL_BYTES,
                "setup journal stage exceeds size limit"
            );
            stage = Some(held);
        } else {
            has_originals = true;
        }
        Ok(false)
    })?;
    if has_originals {
        let originals = open_at(
            fence,
            OsStr::new(ORIGINALS_DIR_NAME),
            libc::O_RDONLY | libc::O_DIRECTORY,
            0,
        )?;
        validate_owned_directory(&originals, owner, 0o700, "original blob directory")?;
        let mut indexes = BTreeSet::new();
        let mut blobs = Vec::new();
        visit_directory(&originals, |name| {
            ensure!(
                indexes.len() < super::loader::MAX_INCLUDE_FILES,
                "too many setup blobs"
            );
            let text = name.to_str().context("non-UTF-8 setup blob")?;
            let Some(index) = parse_blob_index(text) else {
                anyhow::bail!("unexpected setup original blob: {text}");
            };
            ensure!(indexes.insert(index), "duplicate setup original blob index");
            blobs.push((
                index,
                name.to_os_string(),
                validate_safe_file(&originals, name, owner, 0o600, None)?,
            ));
            Ok(false)
        })?;
        ensure!(
            indexes.iter().copied().eq(0..indexes.len()),
            "setup original blobs are not positional"
        );
        blobs.sort_by_key(|(index, _, _)| std::cmp::Reverse(*index));
        return Ok(SetupInventory {
            stage,
            originals: Some(originals),
            blobs: blobs
                .into_iter()
                .map(|(_, name, blob)| (name, blob))
                .collect(),
        });
    }
    Ok(SetupInventory {
        stage,
        originals: None,
        blobs: Vec::new(),
    })
}

fn validate_safe_file(
    parent: &File,
    name: &OsStr,
    owner: &Metadata,
    mode: u32,
    expected_len: Option<u64>,
) -> anyhow::Result<File> {
    let file = open_at(parent, name, libc::O_PATH, 0)?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file()
            && metadata.nlink() == 1
            && (metadata.uid(), metadata.gid()) == (owner.uid(), owner.gid())
            && metadata.mode() & 0o7777 == mode
            && expected_len.is_none_or(|length| metadata.len() == length),
        "unsafe file artifact"
    );
    Ok(file)
}

fn parse_blob_index(name: &str) -> Option<usize> {
    let digits = name.strip_suffix(".toml")?;
    (digits.len() == 4 && digits.bytes().all(|byte| byte.is_ascii_digit()))
        .then(|| digits.parse().ok())
        .flatten()
}

fn remove_setup_fence(root: &File, fence: &File, inventory: SetupInventory) -> anyhow::Result<()> {
    if let Some(stage) = inventory.stage.as_ref() {
        checked_unlink(fence, OsStr::new(JOURNAL_STAGE_NAME), stage)?;
    }
    if let Some(originals) = inventory.originals.as_ref() {
        for (name, blob) in &inventory.blobs {
            checked_unlink(originals, name, blob)?;
        }
        checked_rmdir(fence, OsStr::new(ORIGINALS_DIR_NAME), originals)?;
    }
    checked_rmdir(root, OsStr::new(TXN_DIR_NAME), fence)?;
    root.sync_all()?;
    Ok(())
}

fn remove_validated_fence(
    root: &File,
    fence: &File,
    cleanup: &str,
    journal: &Journal,
    inventory: FenceInventory,
) -> anyhow::Result<()> {
    for index in (0..journal.members().len()).rev() {
        checked_unlink(
            &inventory.originals,
            OsStr::new(&original_blob_file_name(index)),
            &inventory.blobs[index],
        )?;
    }
    checked_rmdir(fence, OsStr::new(ORIGINALS_DIR_NAME), &inventory.originals)?;
    checked_unlink(fence, OsStr::new(JOURNAL_NAME), &inventory.journal)?;
    fence.sync_all()?;
    checked_rmdir(root, OsStr::new(cleanup), fence)?;
    Ok(())
}

fn remove_cleanup_inventory(
    root: &File,
    fence: &File,
    cleanup: &OsStr,
    journal: &Journal,
    inventory: CleanupInventory,
) -> anyhow::Result<()> {
    if let Some(originals) = inventory.originals.as_ref() {
        for index in (0..journal.members().len()).rev() {
            if let Some(blob) = inventory.blobs[index].as_ref() {
                checked_unlink(originals, OsStr::new(&original_blob_file_name(index)), blob)?;
            }
        }
        checked_rmdir(fence, OsStr::new(ORIGINALS_DIR_NAME), originals)?;
    }
    checked_unlink(fence, OsStr::new(JOURNAL_NAME), &inventory.journal)?;
    fence.sync_all()?;
    checked_rmdir(root, cleanup, fence)
}

fn rmdir_at(parent: &File, name: &OsStr) -> io::Result<()> {
    let name = CString::new(name.as_bytes())?;
    if unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn checked_unlink(parent: &File, name: &OsStr, held: &File) -> anyhow::Result<()> {
    let current = inspect_at(parent, name)?.context("cleanup artifact disappeared")?;
    ensure!(
        same_inode(&current.metadata()?, &held.metadata()?),
        "cleanup artifact was replaced"
    );
    #[cfg(test)]
    cleanup_test_hook();
    let current = inspect_at(parent, name)?.context("cleanup artifact disappeared")?;
    ensure!(
        same_inode(&current.metadata()?, &held.metadata()?),
        "cleanup artifact was replaced"
    );
    super::tree_io::unlink_at(parent, name)?;
    parent.sync_all()?;
    Ok(())
}

fn checked_rmdir(parent: &File, name: &OsStr, held: &File) -> anyhow::Result<()> {
    let current = inspect_at(parent, name)?.context("cleanup directory disappeared")?;
    ensure!(
        same_inode(&current.metadata()?, &held.metadata()?),
        "cleanup directory was replaced"
    );
    rmdir_at(parent, name)?;
    parent.sync_all()?;
    Ok(())
}

fn sync_rollback_root(root: &File, point: RollbackSyncPoint) -> anyhow::Result<()> {
    #[cfg(not(test))]
    let _ = point;
    #[cfg(test)]
    ROLLBACK_ROOT_FSYNC_FAILURE.with(|slot| {
        if slot.get() == Some(point) {
            slot.set(None);
            anyhow::bail!("injected rollback root fsync failure");
        }
        Ok(())
    })?;
    root.sync_all()?;
    Ok(())
}

fn sync_finalize_root(root: &File) -> anyhow::Result<()> {
    #[cfg(test)]
    if FINALIZE_ROOT_FSYNC_FAILURE.with(|slot| slot.replace(false)) {
        anyhow::bail!("injected finalize root fsync failure");
    }
    root.sync_all()?;
    Ok(())
}

#[cfg(test)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum TestHookPoint {
    OriginalsReady,
    JournalStageReady,
    RecoveryClassified,
}

#[cfg(test)]
type TestHook = Option<(TestHookPoint, Box<dyn FnOnce()>)>;

#[cfg(test)]
thread_local! {
    static TEST_HOOK: std::cell::RefCell<TestHook> = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
fn run_test_hook(point: TestHookPoint) {
    TEST_HOOK.with(|slot| {
        let matches = slot
            .borrow()
            .as_ref()
            .is_some_and(|(expected, _)| *expected == point);
        if matches {
            let (_, hook) = slot.borrow_mut().take().expect("matching test hook");
            hook();
        }
    });
}

#[cfg(test)]
pub(crate) fn with_test_hook<R>(
    point: TestHookPoint,
    hook: impl FnOnce() + 'static,
    operation: impl FnOnce() -> R,
) -> R {
    TEST_HOOK.with(|slot| *slot.borrow_mut() = Some((point, Box::new(hook))));
    let result = operation();
    TEST_HOOK.with(|slot| *slot.borrow_mut() = None);
    result
}

#[cfg(test)]
thread_local! {
    static PROMOTION_FAILURE_AFTER: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
    static COMMIT_FAILURE_BEFORE_RENAME: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static COMMIT_ROOT_FSYNC_UNCERTAIN: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static ROLLBACK_ROOT_FSYNC_FAILURE: std::cell::Cell<Option<RollbackSyncPoint>> = const { std::cell::Cell::new(None) };
    static FINALIZE_ROOT_FSYNC_FAILURE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
fn with_rollback_root_fsync_failure<R>(
    point: RollbackSyncPoint,
    operation: impl FnOnce() -> R,
) -> R {
    struct Reset(Option<RollbackSyncPoint>);
    impl Drop for Reset {
        fn drop(&mut self) {
            ROLLBACK_ROOT_FSYNC_FAILURE.with(|slot| slot.set(self.0));
        }
    }
    let _reset = ROLLBACK_ROOT_FSYNC_FAILURE.with(|slot| Reset(slot.replace(Some(point))));
    operation()
}

#[cfg(test)]
fn with_finalize_root_fsync_failure<R>(operation: impl FnOnce() -> R) -> R {
    struct Reset(bool);
    impl Drop for Reset {
        fn drop(&mut self) {
            FINALIZE_ROOT_FSYNC_FAILURE.with(|slot| slot.set(self.0));
        }
    }
    let _reset = FINALIZE_ROOT_FSYNC_FAILURE.with(|slot| Reset(slot.replace(true)));
    operation()
}

#[cfg(test)]
pub(crate) fn with_promotion_failure_after<R>(
    successful_promotions: usize,
    operation: impl FnOnce() -> R,
) -> R {
    assert!(
        successful_promotions > 0,
        "promotion failure must follow a promotion"
    );
    struct Reset(Option<usize>);
    impl Drop for Reset {
        fn drop(&mut self) {
            PROMOTION_FAILURE_AFTER.with(|slot| slot.set(self.0));
        }
    }
    let _reset =
        PROMOTION_FAILURE_AFTER.with(|slot| Reset(slot.replace(Some(successful_promotions))));
    operation()
}

#[cfg(test)]
fn take_promotion_failure_after_success() -> bool {
    PROMOTION_FAILURE_AFTER.with(|slot| match slot.get() {
        Some(1) => {
            slot.set(None);
            true
        }
        Some(remaining) => {
            slot.set(Some(remaining - 1));
            false
        }
        None => false,
    })
}

#[cfg(test)]
pub(crate) fn with_commit_failure_before_rename<R>(operation: impl FnOnce() -> R) -> R {
    struct Reset(bool);
    impl Drop for Reset {
        fn drop(&mut self) {
            COMMIT_FAILURE_BEFORE_RENAME.with(|slot| slot.set(self.0));
        }
    }
    let _reset = COMMIT_FAILURE_BEFORE_RENAME.with(|slot| Reset(slot.replace(true)));
    operation()
}

#[cfg(test)]
pub(crate) fn with_commit_root_fsync_uncertain<R>(operation: impl FnOnce() -> R) -> R {
    struct Reset(bool);
    impl Drop for Reset {
        fn drop(&mut self) {
            COMMIT_ROOT_FSYNC_UNCERTAIN.with(|slot| slot.set(self.0));
        }
    }
    let _reset = COMMIT_ROOT_FSYNC_UNCERTAIN.with(|slot| Reset(slot.replace(true)));
    operation()
}

#[cfg(test)]
fn take_commit_failure_before_rename() -> bool {
    COMMIT_FAILURE_BEFORE_RENAME.with(|slot| slot.replace(false))
}

#[cfg(test)]
fn take_commit_root_fsync_uncertain() -> bool {
    COMMIT_ROOT_FSYNC_UNCERTAIN.with(|slot| slot.replace(false))
}

#[cfg(test)]
thread_local! {
    static CLEANUP_TEST_HOOK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
fn cleanup_test_hook() {
    CLEANUP_TEST_HOOK.with(|hook| {
        if let Some(hook) = hook.borrow_mut().take() {
            hook();
        }
    });
}

#[cfg(test)]
fn with_cleanup_test_hook<R>(hook: impl FnOnce() + 'static, operation: impl FnOnce() -> R) -> R {
    CLEANUP_TEST_HOOK.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
    let result = operation();
    CLEANUP_TEST_HOOK.with(|slot| *slot.borrow_mut() = None);
    result
}

fn cleanup_name(hash: &str) -> String {
    format!("{CLEANUP_DIR_PREFIX}{}", &hash[..32])
}

fn finalized_name(hash: &str) -> String {
    format!("{FINALIZED_DIR_PREFIX}{}", &hash[..32])
}

fn root_has_cleanup_artifact(root: &File) -> anyhow::Result<bool> {
    let mut found = false;
    visit_directory(root, |name| {
        found = name.as_bytes().starts_with(CLEANUP_DIR_PREFIX.as_bytes())
            || name.as_bytes().starts_with(FINALIZED_DIR_PREFIX.as_bytes());
        Ok(found)
    })?;
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::write_lock::{acquire_for_migration, acquire_for_read, acquire_for_write};

    fn receipt(len: u64, hash: &str) -> FileReceipt {
        FileReceipt::new(
            len,
            hash.to_owned(),
            unsafe { libc::geteuid() },
            unsafe { libc::getegid() },
            0o640,
        )
        .unwrap()
    }

    fn receipt_json(len: u64, hash: &str) -> String {
        serde_json::to_string(&receipt(len, hash)).unwrap()
    }

    fn valid_journal(master: &str) -> String {
        let hash = "a".repeat(64);
        let member = JournalMember::new(
            Path::new(master),
            MemberRole::Master,
            receipt(0, &hash),
            receipt(0, &hash),
        )
        .unwrap();
        String::from_utf8(
            Journal::new(Path::new(master), vec![member])
                .unwrap()
                .to_json_bytes()
                .unwrap(),
        )
        .unwrap()
    }

    fn with_unknown_field(bytes: &str) -> String {
        let mut json: serde_json::Value = serde_json::from_str(bytes).unwrap();
        json.as_object_mut()
            .unwrap()
            .insert("extra".to_owned(), serde_json::Value::Bool(true));
        serde_json::to_string(&json).unwrap()
    }

    fn held_fence(guard: &MigrationWriteLock) -> File {
        open_at(
            guard.tree_io().root,
            OsStr::new(TXN_DIR_NAME),
            libc::O_RDONLY | libc::O_DIRECTORY,
            0,
        )
        .unwrap()
    }

    #[test]
    fn unsafe_journal_is_rejected_before_data_access() {
        let dir = tempfile::tempdir().unwrap();
        let guard = acquire_for_migration(&dir.path().join("config.toml")).unwrap();
        create_fence(&guard).unwrap();
        std::os::unix::fs::symlink("/dev/null", guard.identity().txn_dir.join(JOURNAL_NAME))
            .unwrap();
        crate::config::write_lock::with_test_hook(
            |event| {
                assert!(event != crate::config::write_lock::TestEvent::BeforeDataOpen);
            },
            || {
                assert!(matches!(
                    inspect(guard.tree_io()).unwrap(),
                    FenceState::Invalid(_)
                ))
            },
        );
    }

    #[test]
    fn durable_empty_fence_is_exclusive_and_survives_the_guard() {
        let dir = tempfile::tempdir().unwrap();
        let master = dir.path().join("config.toml");
        let guard = acquire_for_migration(&master).unwrap();
        assert_eq!(inspect(guard.tree_io()).unwrap(), FenceState::Absent);
        create_fence(&guard).unwrap();
        assert_eq!(inspect(guard.tree_io()).unwrap(), FenceState::Empty);
        assert!(create_fence(&guard).is_err());
        let identity = guard.identity().clone();
        drop(guard);
        let guard = acquire_for_migration(&master).unwrap();
        assert_eq!(inspect(guard.tree_io()).unwrap(), FenceState::Empty);
        drop(guard);
        assert!(acquire_for_read(&master).is_err());
        assert!(acquire_for_write(&master).is_err());
        assert_eq!(
            std::fs::metadata(identity.txn_dir).unwrap().mode() & 0o777,
            0o700
        );
    }

    #[test]
    fn inspection_never_repairs_or_accepts_an_unknown_envelope() {
        let dir = tempfile::tempdir().unwrap();
        let master = dir.path().join("config.toml");
        let guard = acquire_for_migration(&master).unwrap();
        create_fence(&guard).unwrap();
        let journal = guard.identity().txn_dir.join(JOURNAL_NAME);
        for (bytes, expected) in [
            ("{", false),
            (r#"{"format_version":2,"migration":"v3-to-v4"}"#, false),
            (&valid_journal("config.toml"), true),
        ] {
            std::fs::write(&journal, bytes).unwrap();
            std::fs::set_permissions(&journal, std::fs::Permissions::from_mode(0o600)).unwrap();
            let state = inspect(guard.tree_io()).unwrap();
            assert_eq!(matches!(state, FenceState::Journal), expected);
            assert!(refuse_normal_access(guard.tree_io()).is_err());
            assert_eq!(std::fs::read_to_string(&journal).unwrap(), bytes);
        }
    }

    #[test]
    fn unsafe_fence_and_journal_modes_always_refuse_without_repair() {
        let dir = tempfile::tempdir().unwrap();
        let master = dir.path().join("config.toml");
        let guard = acquire_for_migration(&master).unwrap();
        create_fence(&guard).unwrap();
        let fence = &guard.identity().txn_dir;
        let journal = fence.join(JOURNAL_NAME);
        std::fs::write(&journal, valid_journal("config.toml")).unwrap();
        std::fs::set_permissions(&journal, std::fs::Permissions::from_mode(0o600)).unwrap();
        for mode in [
            0o000, 0o400, 0o500, 0o600, 0o750, 0o777, 0o1700, 0o2700, 0o4700,
        ] {
            std::fs::set_permissions(fence, std::fs::Permissions::from_mode(mode)).unwrap();
            assert!(
                matches!(inspect(guard.tree_io()).unwrap(), FenceState::Invalid(_)),
                "fence mode {mode:o}"
            );
            assert!(refuse_normal_access(guard.tree_io()).is_err());
            assert_eq!(std::fs::metadata(fence).unwrap().mode() & 0o7777, mode);
        }
        std::fs::set_permissions(fence, std::fs::Permissions::from_mode(0o700)).unwrap();
        for mode in [
            0o000, 0o400, 0o200, 0o700, 0o640, 0o666, 0o1600, 0o2600, 0o4600,
        ] {
            std::fs::set_permissions(&journal, std::fs::Permissions::from_mode(mode)).unwrap();
            assert!(
                matches!(inspect(guard.tree_io()).unwrap(), FenceState::Invalid(_)),
                "journal mode {mode:o}"
            );
            assert!(refuse_normal_access(guard.tree_io()).is_err());
            assert_eq!(std::fs::metadata(&journal).unwrap().mode() & 0o7777, mode);
        }
    }

    #[test]
    fn symlinked_fence_or_journal_is_never_followed() {
        let dir = tempfile::tempdir().unwrap();
        let other = tempfile::tempdir().unwrap();
        let master = dir.path().join("config.toml");
        let guard = acquire_for_migration(&master).unwrap();
        let identity = guard.identity();
        std::os::unix::fs::symlink(other.path(), &identity.txn_dir).unwrap();
        assert!(matches!(
            inspect(guard.tree_io()).unwrap(),
            FenceState::Invalid(_)
        ));
        std::fs::remove_file(&identity.txn_dir).unwrap();
        std::os::unix::fs::symlink(other.path().join("missing"), &identity.txn_dir).unwrap();
        assert!(matches!(
            inspect(guard.tree_io()).unwrap(),
            FenceState::Invalid(_)
        ));
        std::fs::remove_file(&identity.txn_dir).unwrap();
        create_fence(&guard).unwrap();
        std::os::unix::fs::symlink(
            other.path().join("missing"),
            identity.txn_dir.join(JOURNAL_NAME),
        )
        .unwrap();
        assert!(matches!(
            inspect(guard.tree_io()).unwrap(),
            FenceState::Invalid(_)
        ));
        assert!(refuse_normal_access(guard.tree_io()).is_err());
    }

    #[test]
    fn strict_journal_rejects_missing_unknown_duplicate_and_bad_structure() {
        let valid = valid_journal("config.toml");
        for bytes in [
            with_unknown_field(&valid),
            r#"{"format_version":1,"migration":"v3-to-v4","from_schema":3,"to_schema":4,"master":"config.toml"}"#.to_string(),
            valid.replacen("\"migration\":\"v3-to-v4\",", "\"migration\":\"v3-to-v4\",\"migration\":\"v3-to-v4\",", 1),
            valid.replace("\"role\":\"master\"", "\"role\":\"include\""),
            valid.replace("\"originals/0000.toml\"", "\"originals/0001.toml\""),
        ] {
            assert!(validate_journal(bytes.as_bytes(), Path::new("config.toml")).is_err());
        }
        let hash = "a".repeat(64);
        let pair = |first_path: &str, first_role: &str| {
            format!(
                r#"{{"format_version":1,"migration":"v3-to-v4","from_schema":3,"to_schema":4,"master":"config.toml","members":[{{"path":"{first_path}","role":"{first_role}","original_blob":"originals/0000.toml","before":{},"after":{}}},{{"path":"config.toml","role":"master","original_blob":"originals/0001.toml","before":{},"after":{}}}]}}"#,
                receipt_json(0, &hash),
                receipt_json(0, &hash),
                receipt_json(0, &hash),
                receipt_json(0, &hash),
            )
        };
        assert!(validate_journal(
            pair("config.toml", "include").as_bytes(),
            Path::new("config.toml")
        )
        .is_err());
        assert!(validate_journal(
            pair("include.toml", "master").as_bytes(),
            Path::new("config.toml")
        )
        .is_err());
    }

    #[test]
    fn journal_rejects_unsafe_paths_hashes_and_bounds() {
        let valid = valid_journal("config.toml");
        for path in [
            "../config.toml",
            "/config.toml",
            ".warden-migration/config.toml",
            "nested//config.toml",
            "a/./config.toml",
        ] {
            let bytes = valid
                .replace(
                    "\"master\":\"config.toml\"",
                    &format!("\"master\":\"{path}\""),
                )
                .replace("\"path\":\"config.toml\"", &format!("\"path\":\"{path}\""));
            assert!(validate_journal(bytes.as_bytes(), Path::new(path)).is_err());
        }
        for hash in ["A".repeat(64), "a".repeat(63), "g".repeat(64)] {
            let bytes = valid.replacen(&"a".repeat(64), &hash, 1);
            assert!(validate_journal(bytes.as_bytes(), Path::new("config.toml")).is_err());
        }
        let invalid_mode = valid.replacen("\"mode\":416", "\"mode\":4096", 1);
        assert!(validate_journal(invalid_mode.as_bytes(), Path::new("config.toml")).is_err());

        let too_many_components = std::iter::repeat_n("a", 8193).collect::<Vec<_>>().join("/");
        let invalid_master_journal = |master: &str| {
            format!(
                r#"{{"format_version":1,"migration":"v3-to-v4","from_schema":3,"to_schema":4,"master":"{master}","members":[{{"path":"{master}","role":"master","original_blob":"originals/0000.toml","before":{},"after":{}}}]}}"#,
                receipt_json(0, &"a".repeat(64)),
                receipt_json(0, &"a".repeat(64)),
            )
        };
        let bytes = invalid_master_journal(&too_many_components);
        assert!(validate_journal(bytes.as_bytes(), Path::new(&too_many_components)).is_err());
        let too_long_component = "a".repeat(libc::NAME_MAX as usize + 1);
        let bytes = invalid_master_journal(&too_long_component);
        assert!(validate_journal(bytes.as_bytes(), Path::new(&too_long_component)).is_err());

        let hash = "a".repeat(64);
        let too_many = format!(
            r#"{{"format_version":1,"migration":"v3-to-v4","from_schema":3,"to_schema":4,"master":"config.toml","members":[{}]}}"#,
            (0..=super::super::loader::MAX_INCLUDE_FILES)
            .map(|index| {
                let (path, role) = if index == super::super::loader::MAX_INCLUDE_FILES {
                    ("config.toml".to_owned(), "master")
                } else {
                    (format!("include-{index}.toml"), "include")
                };
                format!(
                    r#"{{"path":"{path}","role":"{role}","original_blob":"originals/{index:04}.toml","before":{},"after":{}}}"#,
                    receipt_json(0, &hash),
                    receipt_json(0, &hash),
                )
            })
            .collect::<Vec<_>>()
            .join(","),
        );
        assert!(validate_journal(too_many.as_bytes(), Path::new("config.toml")).is_err());
        let after_total_exceeded = format!(
            r#"{{"format_version":1,"migration":"v3-to-v4","from_schema":3,"to_schema":4,"master":"config.toml","members":[{{"path":"include.toml","role":"include","original_blob":"originals/0000.toml","before":{},"after":{}}},{{"path":"config.toml","role":"master","original_blob":"originals/0001.toml","before":{},"after":{}}}]}}"#,
            receipt_json(0, &hash),
            receipt_json(super::super::loader::MAX_TOTAL_BYTES, &hash),
            receipt_json(0, &hash),
            receipt_json(1, &hash),
        );
        assert!(
            validate_journal(after_total_exceeded.as_bytes(), Path::new("config.toml")).is_err()
        );
    }

    #[test]
    fn journal_serialization_is_bounded() {
        let component = "a".repeat(libc::NAME_MAX as usize);
        let master = std::iter::repeat_n(component.as_str(), 8192)
            .collect::<Vec<_>>()
            .join("/");
        let hash = "a".repeat(64);
        let member = JournalMember::new(
            Path::new(&master),
            MemberRole::Master,
            receipt(0, &hash),
            receipt(0, &hash),
        )
        .unwrap();
        let journal = Journal::new(Path::new(&master), vec![member]).unwrap();

        let error = journal.to_json_bytes().unwrap_err();
        assert!(format!("{error:#}").contains("serialized journal exceeds size limit"));
    }

    #[test]
    fn receipt_uses_candidate_length_and_original_metadata() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, b"old").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        let metadata = std::fs::metadata(path).unwrap();

        let receipt = FileReceipt::from_bytes_with_metadata(&metadata, b"new contents").unwrap();

        assert_eq!(receipt.len(), 12);
        assert_eq!(receipt.sha256(), sha256_hex(b"new contents"));
        assert_eq!(receipt.uid(), metadata.uid());
        assert_eq!(receipt.gid(), metadata.gid());
        assert_eq!(receipt.mode(), 0o640);
    }

    #[test]
    fn original_blobs_require_safe_descriptors_and_matching_receipts() {
        let dir = tempfile::tempdir().unwrap();
        let guard = acquire_for_migration(&dir.path().join("config.toml")).unwrap();
        create_fence(&guard).unwrap();
        let bytes = b"before";
        let hash = sha256_hex(bytes);
        let before = FileReceipt::new(
            bytes.len() as u64,
            hash,
            unsafe { libc::geteuid() }.saturating_add(1),
            unsafe { libc::getegid() },
            0o640,
        )
        .unwrap();
        let journal = Journal::new(
            Path::new("config.toml"),
            vec![JournalMember::new(
                Path::new("config.toml"),
                MemberRole::Master,
                before.clone(),
                before,
            )
            .unwrap()],
        )
        .unwrap()
        .to_json_bytes()
        .unwrap();
        let fence = &guard.identity().txn_dir;
        let originals = fence.join(ORIGINALS_DIR_NAME);
        std::fs::create_dir(&originals).unwrap();
        std::fs::set_permissions(&originals, std::fs::Permissions::from_mode(0o700)).unwrap();
        let blob = originals.join("0000.toml");
        std::fs::write(&blob, bytes).unwrap();
        std::fs::set_permissions(&blob, std::fs::Permissions::from_mode(0o600)).unwrap();
        let owner = guard
            .identity()
            .owner_metadata(guard.tree_io().root)
            .unwrap();
        let parsed = validate_journal(&journal, Path::new("config.toml")).unwrap();
        assert_eq!(
            validate_original_blob(&held_fence(&guard), &owner, 0, &parsed.members()[0]).unwrap(),
            bytes
        );
        assert!(
            validate_original_blob(&held_fence(&guard), &owner, 1, &parsed.members()[0]).is_err()
        );

        std::fs::set_permissions(&originals, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(
            validate_original_blob(&held_fence(&guard), &owner, 0, &parsed.members()[0]).is_err()
        );
        std::fs::set_permissions(&originals, std::fs::Permissions::from_mode(0o700)).unwrap();

        for replacement in [
            b"other".as_slice(),
            b"before!".as_slice(),
            b"after!".as_slice(),
        ] {
            std::fs::write(&blob, replacement).unwrap();
            std::fs::set_permissions(&blob, std::fs::Permissions::from_mode(0o600)).unwrap();
            assert!(
                validate_original_blob(&held_fence(&guard), &owner, 0, &parsed.members()[0])
                    .is_err()
            );
        }
        std::fs::write(&blob, bytes).unwrap();
        std::fs::set_permissions(&blob, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(
            validate_original_blob(&held_fence(&guard), &owner, 0, &parsed.members()[0]).is_err()
        );

        if unsafe { libc::geteuid() } == 0 {
            std::fs::set_permissions(&blob, std::fs::Permissions::from_mode(0o600)).unwrap();
            std::os::unix::fs::lchown(&blob, Some(65534), Some(65534)).unwrap();
            assert!(
                validate_original_blob(&held_fence(&guard), &owner, 0, &parsed.members()[0])
                    .is_err()
            );
            std::os::unix::fs::lchown(&blob, Some(owner.uid()), Some(owner.gid())).unwrap();
        }

        std::fs::remove_file(&blob).unwrap();
        std::os::unix::fs::symlink("/dev/null", &blob).unwrap();
        assert!(
            validate_original_blob(&held_fence(&guard), &owner, 0, &parsed.members()[0]).is_err()
        );
        std::fs::remove_file(&blob).unwrap();
        std::fs::create_dir(&blob).unwrap();
        assert!(
            validate_original_blob(&held_fence(&guard), &owner, 0, &parsed.members()[0]).is_err()
        );
        std::fs::remove_dir(&blob).unwrap();
        std::fs::write(&blob, bytes).unwrap();
        std::fs::hard_link(&blob, originals.join("linked.toml")).unwrap();
        std::fs::set_permissions(&blob, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(
            validate_original_blob(&held_fence(&guard), &owner, 0, &parsed.members()[0]).is_err()
        );
        std::fs::remove_file(originals.join("linked.toml")).unwrap();
        assert_eq!(
            validate_original_blob(&held_fence(&guard), &owner, 0, &parsed.members()[0]).unwrap(),
            bytes
        );
    }

    fn migration_member(
        root: &Path,
        path: &str,
        role: MemberRole,
        before: &[u8],
        after: &[u8],
    ) -> MigrationMember {
        MigrationMember::new(
            PathBuf::from(path),
            role,
            before.to_vec(),
            after.to_vec(),
            std::fs::metadata(root.join(path)).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn publication_rejects_corrupt_originals_and_journal_stage() {
        for point in [
            TestHookPoint::OriginalsReady,
            TestHookPoint::JournalStageReady,
        ] {
            let dir = tempfile::tempdir().unwrap();
            let master = dir.path().join("config.toml");
            std::fs::write(&master, b"master-v3").unwrap();
            let guard = acquire_for_migration(&master).unwrap();
            let artifact = match point {
                TestHookPoint::OriginalsReady => guard
                    .identity()
                    .txn_dir
                    .join(ORIGINALS_DIR_NAME)
                    .join("0000.toml"),
                TestHookPoint::JournalStageReady => {
                    guard.identity().txn_dir.join(JOURNAL_STAGE_NAME)
                }
                TestHookPoint::RecoveryClassified => unreachable!(),
            };
            let result = with_test_hook(
                point,
                move || std::fs::write(artifact, b"corrupt").unwrap(),
                || {
                    publish(
                        &guard,
                        vec![migration_member(
                            dir.path(),
                            "config.toml",
                            MemberRole::Master,
                            b"master-v3",
                            b"master-v4",
                        )],
                    )
                },
            );

            assert!(result.is_err());
            assert!(!guard.identity().txn_dir.join(JOURNAL_NAME).exists());
        }
    }

    #[test]
    fn publication_promotion_and_commit_keep_the_v3_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("include.toml"), b"include-v3").unwrap();
        std::fs::write(dir.path().join("config.toml"), b"master-v3").unwrap();
        let guard = acquire_for_migration(&dir.path().join("config.toml")).unwrap();
        let mut published = publish(
            &guard,
            vec![
                migration_member(
                    dir.path(),
                    "include.toml",
                    MemberRole::Include,
                    b"include-v3",
                    b"include-v4",
                ),
                migration_member(
                    dir.path(),
                    "config.toml",
                    MemberRole::Master,
                    b"master-v3",
                    b"master-v4",
                ),
            ],
        )
        .unwrap();
        assert_eq!(
            std::fs::read(dir.path().join("include.toml")).unwrap(),
            b"include-v3"
        );
        assert_eq!(
            std::fs::read(dir.path().join("config.toml")).unwrap(),
            b"master-v3"
        );
        assert!(dir.path().join(TXN_DIR_NAME).join(JOURNAL_NAME).is_file());
        published.promote_all().unwrap();
        let cleanup = published.commit().unwrap();
        assert_eq!(
            std::fs::read(dir.path().join("include.toml")).unwrap(),
            b"include-v4"
        );
        assert_eq!(
            std::fs::read(dir.path().join("config.toml")).unwrap(),
            b"master-v4"
        );
        assert!(cleanup.is_dir());
        assert!(!dir.path().join(TXN_DIR_NAME).exists());
    }

    #[test]
    fn recovery_restores_promoted_members_before_retiring_the_fence() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("config.toml"), b"master-v3").unwrap();
        let guard = acquire_for_migration(&dir.path().join("config.toml")).unwrap();
        let mut published = publish(
            &guard,
            vec![migration_member(
                dir.path(),
                "config.toml",
                MemberRole::Master,
                b"master-v3",
                b"master-v4",
            )],
        )
        .unwrap();
        published.promote_all().unwrap();
        drop(published);
        drop(guard);
        let guard = acquire_for_migration(&dir.path().join("config.toml")).unwrap();
        assert_eq!(
            recover_fixed(&guard, || Ok(())).unwrap(),
            RecoveryOutcome::RolledBack
        );
        assert_eq!(
            std::fs::read(dir.path().join("config.toml")).unwrap(),
            b"master-v3"
        );
        assert!(!dir.path().join(TXN_DIR_NAME).exists());
    }

    #[test]
    fn recovery_rejects_a_third_state_before_any_restore() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("include.toml"), b"include-v3").unwrap();
        std::fs::write(dir.path().join("config.toml"), b"master-v3").unwrap();
        let guard = acquire_for_migration(&dir.path().join("config.toml")).unwrap();
        let mut published = publish(
            &guard,
            vec![
                migration_member(
                    dir.path(),
                    "include.toml",
                    MemberRole::Include,
                    b"include-v3",
                    b"include-v4",
                ),
                migration_member(
                    dir.path(),
                    "config.toml",
                    MemberRole::Master,
                    b"master-v3",
                    b"master-v4",
                ),
            ],
        )
        .unwrap();
        published.promote_all().unwrap();
        drop(published);
        std::fs::write(dir.path().join("config.toml"), b"replacement").unwrap();
        drop(guard);
        let guard = acquire_for_migration(&dir.path().join("config.toml")).unwrap();
        assert!(recover_fixed(&guard, || Ok(())).is_err());
        assert_eq!(
            std::fs::read(dir.path().join("include.toml")).unwrap(),
            b"include-v4"
        );
        assert_eq!(
            std::fs::read(dir.path().join("config.toml")).unwrap(),
            b"replacement"
        );
        assert!(dir.path().join(TXN_DIR_NAME).is_dir());
    }

    #[test]
    fn recovery_rejects_replacement_after_classification() {
        let dir = tempfile::tempdir().unwrap();
        let master = dir.path().join("config.toml");
        std::fs::write(&master, b"master-v3").unwrap();
        let guard = acquire_for_migration(&master).unwrap();
        let mut published = publish(
            &guard,
            vec![migration_member(
                dir.path(),
                "config.toml",
                MemberRole::Master,
                b"master-v3",
                b"master-v4",
            )],
        )
        .unwrap();
        published.promote_all().unwrap();
        drop(published);
        let replacement = dir.path().join("replacement.toml");
        std::fs::write(&replacement, b"master-v4").unwrap();
        let mode = std::fs::metadata(&master).unwrap().permissions();
        std::fs::set_permissions(&replacement, mode).unwrap();
        let master_for_hook = master.clone();
        let result = with_test_hook(
            TestHookPoint::RecoveryClassified,
            move || std::fs::rename(replacement, master_for_hook).unwrap(),
            || recover_fixed(&guard, || Ok(())),
        );

        assert!(result.is_err());
        assert_eq!(std::fs::read(master).unwrap(), b"master-v4");
        assert!(dir.path().join(TXN_DIR_NAME).is_dir());
    }

    #[test]
    fn recovery_callback_failure_keeps_the_fence_for_retry() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("include.toml"), b"include-v3").unwrap();
        std::fs::write(dir.path().join("config.toml"), b"master-v3").unwrap();
        let guard = acquire_for_migration(&dir.path().join("config.toml")).unwrap();
        let mut published = publish(
            &guard,
            vec![
                migration_member(
                    dir.path(),
                    "include.toml",
                    MemberRole::Include,
                    b"include-v3",
                    b"include-v4",
                ),
                migration_member(
                    dir.path(),
                    "config.toml",
                    MemberRole::Master,
                    b"master-v3",
                    b"master-v4",
                ),
            ],
        )
        .unwrap();
        published.promote_all().unwrap();
        drop(published);
        std::fs::write(dir.path().join("include.toml"), b"include-v3").unwrap();
        assert!(recover_fixed(&guard, || anyhow::bail!("v3 validation failed")).is_err());
        assert!(dir.path().join(TXN_DIR_NAME).is_dir());
        assert_eq!(
            std::fs::read(dir.path().join("include.toml")).unwrap(),
            b"include-v3"
        );
        assert_eq!(
            std::fs::read(dir.path().join("config.toml")).unwrap(),
            b"master-v3"
        );
        drop(guard);
        let guard = acquire_for_migration(&dir.path().join("config.toml")).unwrap();
        assert_eq!(
            recover_fixed(&guard, || Ok(())).unwrap(),
            RecoveryOutcome::RolledBack
        );
        assert!(!dir.path().join(TXN_DIR_NAME).exists());
    }

    #[test]
    fn journal_less_setup_cleanup_is_checked() {
        let dir = tempfile::tempdir().unwrap();
        let master = dir.path().join("config.toml");
        let guard = acquire_for_migration(&master).unwrap();
        create_fence(&guard).unwrap();
        assert_eq!(
            recover_fixed(&guard, || Ok(())).unwrap(),
            RecoveryOutcome::SetupRemoved
        );
        assert!(!dir.path().join(TXN_DIR_NAME).exists());
        create_fence(&guard).unwrap();
        std::fs::write(guard.identity().txn_dir.join("unexpected"), b"x").unwrap();
        assert!(recover_fixed(&guard, || Ok(())).is_err());
        assert!(guard.identity().txn_dir.join("unexpected").exists());
    }

    #[test]
    fn setup_cleanup_unlinks_highest_blob_first_and_resumes() {
        let dir = tempfile::tempdir().unwrap();
        let master = dir.path().join("config.toml");
        let guard = acquire_for_migration(&master).unwrap();
        create_fence(&guard).unwrap();
        let originals = guard.identity().txn_dir.join(ORIGINALS_DIR_NAME);
        std::fs::create_dir(&originals).unwrap();
        std::fs::set_permissions(&originals, std::fs::Permissions::from_mode(0o700)).unwrap();
        for index in 0..3 {
            let blob = originals.join(original_blob_file_name(index));
            std::fs::write(&blob, b"v3").unwrap();
            std::fs::set_permissions(&blob, std::fs::Permissions::from_mode(0o600)).unwrap();
        }

        let owner = guard
            .identity()
            .owner_metadata(guard.tree_io().root)
            .unwrap();
        let mut inventory = validate_setup_inventory(&held_fence(&guard), &owner).unwrap();
        assert_eq!(inventory.blobs[0].0, OsStr::new("0002.toml"));
        let (name, blob) = inventory.blobs.remove(0);
        checked_unlink(inventory.originals.as_ref().unwrap(), &name, &blob).unwrap();

        assert!(!originals.join("0002.toml").exists());
        assert!(originals.join("0000.toml").exists());
        assert!(originals.join("0001.toml").exists());
        assert_eq!(
            recover_fixed(&guard, || Ok(())).unwrap(),
            RecoveryOutcome::SetupRemoved
        );
        assert!(!guard.identity().txn_dir.exists());
    }

    #[test]
    fn cleanup_resumes_before_and_retains_after() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("config.toml"), b"master-v3").unwrap();
        let guard = acquire_for_migration(&dir.path().join("config.toml")).unwrap();
        let published = publish(
            &guard,
            vec![migration_member(
                dir.path(),
                "config.toml",
                MemberRole::Master,
                b"master-v3",
                b"master-v4",
            )],
        )
        .unwrap();
        let cleanup = cleanup_name(&sha256_hex(
            &std::fs::read(guard.identity().txn_dir.join(JOURNAL_NAME)).unwrap(),
        ));
        drop(published);
        std::fs::rename(guard.identity().txn_dir.clone(), dir.path().join(&cleanup)).unwrap();
        std::fs::remove_file(
            dir.path()
                .join(&cleanup)
                .join(ORIGINALS_DIR_NAME)
                .join("0000.toml"),
        )
        .unwrap();
        assert_eq!(
            recover_fixed(&guard, || Ok(())).unwrap(),
            RecoveryOutcome::RolledBack
        );
        assert!(!dir.path().join(&cleanup).exists());

        let mut published = publish(
            &guard,
            vec![migration_member(
                dir.path(),
                "config.toml",
                MemberRole::Master,
                b"master-v3",
                b"master-v4",
            )],
        )
        .unwrap();
        published.promote_all().unwrap();
        let cleanup = cleanup_name(&sha256_hex(
            &std::fs::read(guard.identity().txn_dir.join(JOURNAL_NAME)).unwrap(),
        ));
        drop(published);
        std::fs::rename(guard.identity().txn_dir.clone(), dir.path().join(&cleanup)).unwrap();
        assert_eq!(
            recover_fixed(&guard, || Ok(())).unwrap(),
            RecoveryOutcome::Absent
        );
        assert!(dir.path().join(&cleanup).is_dir());
    }

    #[test]
    fn recovery_reestablishes_uncertain_cleanup_before_deleting_undo() {
        let dir = tempfile::tempdir().unwrap();
        let master = dir.path().join("config.toml");
        std::fs::write(&master, b"master-v3").unwrap();
        let guard = acquire_for_migration(&master).unwrap();
        let published = publish(
            &guard,
            vec![migration_member(
                dir.path(),
                "config.toml",
                MemberRole::Master,
                b"master-v3",
                b"master-v4",
            )],
        )
        .unwrap();
        let cleanup = cleanup_name(&sha256_hex(
            &std::fs::read(guard.identity().txn_dir.join(JOURNAL_NAME)).unwrap(),
        ));
        drop(published);
        std::fs::rename(guard.identity().txn_dir.clone(), dir.path().join(&cleanup)).unwrap();

        assert!(
            with_rollback_root_fsync_failure(RollbackSyncPoint::Cleanup, || {
                recover_fixed(&guard, || Ok(()))
            })
            .is_err()
        );
        assert!(dir.path().join(&cleanup).join(JOURNAL_NAME).exists());
        assert_eq!(
            recover_fixed(&guard, || Ok(())).unwrap(),
            RecoveryOutcome::RolledBack
        );
        assert!(!dir.path().join(cleanup).exists());
    }

    #[test]
    fn committed_cleanup_requires_a_complete_valid_undo_snapshot() {
        for corrupt in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let master = dir.path().join("config.toml");
            std::fs::write(&master, b"master-v3").unwrap();
            let guard = acquire_for_migration(&master).unwrap();
            let mut published = publish(
                &guard,
                vec![migration_member(
                    dir.path(),
                    "config.toml",
                    MemberRole::Master,
                    b"master-v3",
                    b"master-v4",
                )],
            )
            .unwrap();
            published.promote_all().unwrap();
            let cleanup = cleanup_name(&sha256_hex(
                &std::fs::read(guard.identity().txn_dir.join(JOURNAL_NAME)).unwrap(),
            ));
            drop(published);
            std::fs::rename(guard.identity().txn_dir.clone(), dir.path().join(&cleanup)).unwrap();
            let blob = dir
                .path()
                .join(&cleanup)
                .join(ORIGINALS_DIR_NAME)
                .join("0000.toml");
            if corrupt {
                std::fs::write(&blob, b"corrupt").unwrap();
            } else {
                std::fs::remove_file(&blob).unwrap();
            }

            assert!(recover_fixed(&guard, || Ok(())).is_err());
            assert!(dir.path().join(&cleanup).is_dir());
            assert_eq!(std::fs::read(&master).unwrap(), b"master-v4");
        }
    }

    #[test]
    fn checked_unlink_preserves_a_replacement() {
        let dir = tempfile::tempdir().unwrap();
        let original = dir.path().join("original");
        let replacement = dir.path().join("replacement");
        std::fs::write(&original, b"old").unwrap();
        std::fs::write(&replacement, b"new").unwrap();
        let parent = File::open(dir.path()).unwrap();
        let held = inspect_at(&parent, OsStr::new("original"))
            .unwrap()
            .unwrap();
        let original_for_hook = original.clone();
        with_cleanup_test_hook(
            move || std::fs::rename(&replacement, original_for_hook).unwrap(),
            || assert!(checked_unlink(&parent, OsStr::new("original"), &held).is_err()),
        );
        assert_eq!(std::fs::read(original).unwrap(), b"new");
    }

    #[test]
    fn commit_rejects_a_replaced_promoted_member() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("config.toml"), b"master-v3").unwrap();
        let guard = acquire_for_migration(&dir.path().join("config.toml")).unwrap();
        let mut published = publish(
            &guard,
            vec![migration_member(
                dir.path(),
                "config.toml",
                MemberRole::Master,
                b"master-v3",
                b"master-v4",
            )],
        )
        .unwrap();
        published.promote_all().unwrap();
        let target = dir.path().join("config.toml");
        let replacement = dir.path().join("replacement.toml");
        std::fs::write(&replacement, b"master-v4").unwrap();
        let mode = std::fs::metadata(&target).unwrap().permissions();
        std::fs::set_permissions(&replacement, mode).unwrap();
        std::fs::rename(replacement, &target).unwrap();
        assert!(matches!(
            published.commit(),
            Err(CommitError::RenameNotLanded(_))
        ));
        assert_eq!(std::fs::read(target).unwrap(), b"master-v4");
        assert!(dir.path().join(TXN_DIR_NAME).is_dir());
    }

    fn commit_split_tree(dir: &Path) -> (MigrationWriteLock, String) {
        std::fs::write(dir.join("include.toml"), b"include-v3").unwrap();
        std::fs::write(dir.join("config.toml"), b"master-v3").unwrap();
        std::fs::set_permissions(
            dir.join("include.toml"),
            std::fs::Permissions::from_mode(0o640),
        )
        .unwrap();
        let guard = acquire_for_migration(&dir.join("config.toml")).unwrap();
        let mut published = publish(
            &guard,
            vec![
                migration_member(
                    dir,
                    "include.toml",
                    MemberRole::Include,
                    b"include-v3",
                    b"include-v4",
                ),
                migration_member(
                    dir,
                    "config.toml",
                    MemberRole::Master,
                    b"master-v3",
                    b"master-v4",
                ),
            ],
        )
        .unwrap();
        published.promote_all().unwrap();
        let cleanup = published.commit().unwrap();
        (
            guard,
            cleanup.file_name().unwrap().to_str().unwrap().to_owned(),
        )
    }

    #[test]
    fn committed_undo_rollback_restores_the_complete_v3_tree_and_metadata() {
        let dir = tempfile::tempdir().unwrap();
        let (guard, cleanup) = commit_split_tree(dir.path());
        let mut inventory = None;
        assert_eq!(
            rollback(&guard, |members| {
                inventory = Some(members.to_vec());
                Ok(())
            })
            .unwrap(),
            RollbackOutcome::Restored
        );
        assert_eq!(
            inventory.unwrap(),
            [PathBuf::from("include.toml"), PathBuf::from("config.toml")]
        );
        assert_eq!(
            std::fs::read(dir.path().join("include.toml")).unwrap(),
            b"include-v3"
        );
        assert_eq!(
            std::fs::read(dir.path().join("config.toml")).unwrap(),
            b"master-v3"
        );
        assert_eq!(
            std::fs::metadata(dir.path().join("include.toml"))
                .unwrap()
                .mode()
                & 0o7777,
            0o640
        );
        assert!(!dir.path().join(cleanup).exists());
    }

    #[test]
    fn rollback_retries_from_the_fixed_fence_after_undo_rename() {
        let dir = tempfile::tempdir().unwrap();
        let (guard, cleanup) = commit_split_tree(dir.path());
        std::fs::rename(dir.path().join(cleanup), dir.path().join(TXN_DIR_NAME)).unwrap();
        assert_eq!(
            rollback(&guard, |_| Ok(())).unwrap(),
            RollbackOutcome::Restored
        );
        assert_eq!(
            std::fs::read(dir.path().join("config.toml")).unwrap(),
            b"master-v3"
        );
        assert!(!dir.path().join(TXN_DIR_NAME).exists());
    }

    #[test]
    fn rollback_reestablishes_an_uncertain_fixed_fence_before_restoring() {
        let dir = tempfile::tempdir().unwrap();
        let (guard, cleanup) = commit_split_tree(dir.path());
        assert!(
            with_rollback_root_fsync_failure(RollbackSyncPoint::FixedFence, || {
                rollback(&guard, |_| Ok(()))
            })
            .is_err()
        );
        assert!(!dir.path().join(cleanup).exists());
        assert!(dir.path().join(TXN_DIR_NAME).exists());
        assert_eq!(
            std::fs::read(dir.path().join("config.toml")).unwrap(),
            b"master-v4"
        );

        assert_eq!(
            rollback(&guard, |_| Ok(())).unwrap(),
            RollbackOutcome::Restored
        );
    }

    #[test]
    fn rollback_reestablishes_uncertain_cleanup_before_deleting_undo() {
        let dir = tempfile::tempdir().unwrap();
        let (guard, cleanup) = commit_split_tree(dir.path());
        std::fs::rename(dir.path().join(&cleanup), dir.path().join(TXN_DIR_NAME)).unwrap();
        assert!(
            with_rollback_root_fsync_failure(RollbackSyncPoint::Cleanup, || {
                rollback(&guard, |_| Ok(()))
            })
            .is_err()
        );
        let cleanup_path = dir.path().join(&cleanup);
        assert!(cleanup_path.join(JOURNAL_NAME).exists());
        assert!(cleanup_path
            .join(ORIGINALS_DIR_NAME)
            .join("0000.toml")
            .exists());
        assert_eq!(
            std::fs::read(dir.path().join("config.toml")).unwrap(),
            b"master-v3"
        );

        assert_eq!(
            rollback(&guard, |_| Ok(())).unwrap(),
            RollbackOutcome::Restored
        );
        assert!(!cleanup_path.exists());
    }

    #[test]
    fn rollback_resumes_cleanup_after_the_v3_tree_was_restored() {
        let dir = tempfile::tempdir().unwrap();
        let (guard, cleanup) = commit_split_tree(dir.path());
        std::fs::write(dir.path().join("include.toml"), b"include-v3").unwrap();
        std::fs::write(dir.path().join("config.toml"), b"master-v3").unwrap();
        std::fs::remove_file(
            dir.path()
                .join(&cleanup)
                .join(ORIGINALS_DIR_NAME)
                .join("0001.toml"),
        )
        .unwrap();

        let mut validated = false;
        assert_eq!(
            rollback(&guard, |members| {
                assert_eq!(
                    members,
                    [PathBuf::from("include.toml"), PathBuf::from("config.toml")]
                );
                validated = true;
                Ok(())
            })
            .unwrap(),
            RollbackOutcome::Restored
        );
        assert!(validated);
        assert!(!dir.path().join(cleanup).exists());
    }

    #[test]
    fn rollback_reports_an_empty_post_validation_cleanup_without_fabricating_inventory() {
        let dir = tempfile::tempdir().unwrap();
        let (guard, cleanup) = commit_split_tree(dir.path());
        std::fs::write(dir.path().join("include.toml"), b"include-v3").unwrap();
        std::fs::write(dir.path().join("config.toml"), b"master-v3").unwrap();
        let cleanup_path = dir.path().join(&cleanup);
        std::fs::remove_dir_all(cleanup_path.join(ORIGINALS_DIR_NAME)).unwrap();
        std::fs::remove_file(cleanup_path.join(JOURNAL_NAME)).unwrap();

        assert_eq!(
            rollback(&guard, |_| unreachable!()).unwrap(),
            RollbackOutcome::SetupRemoved
        );
        assert!(!cleanup_path.exists());
    }

    #[test]
    fn rollback_refuses_a_committed_undo_third_state_without_rewriting_it() {
        let dir = tempfile::tempdir().unwrap();
        let (guard, _) = commit_split_tree(dir.path());
        std::fs::write(dir.path().join("config.toml"), b"replacement").unwrap();
        assert!(rollback(&guard, |_| Ok(())).is_err());
        assert_eq!(
            std::fs::read(dir.path().join("include.toml")).unwrap(),
            b"include-v4"
        );
        assert_eq!(
            std::fs::read(dir.path().join("config.toml")).unwrap(),
            b"replacement"
        );
    }

    #[test]
    fn rollback_refuses_fixed_and_committed_artifacts_together() {
        for artifacts in [
            vec![".warden-migration.cleanup-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
            vec![".warden-migration.finalized-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
            vec![".warden-migration.finalized-not-a-hash"],
            vec![
                ".warden-migration.finalized-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                ".warden-migration.finalized-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            ],
        ] {
            let dir = tempfile::tempdir().unwrap();
            let master = dir.path().join("config.toml");
            std::fs::write(&master, b"master-v3").unwrap();
            let guard = acquire_for_migration(&master).unwrap();
            create_fence(&guard).unwrap();
            for artifact in &artifacts {
                std::fs::create_dir(dir.path().join(artifact)).unwrap();
            }

            assert!(rollback(&guard, |_| Ok(())).is_err());
            assert!(dir.path().join(TXN_DIR_NAME).exists());
            for artifact in artifacts {
                assert!(dir.path().join(artifact).exists());
            }
        }
    }

    #[test]
    fn finalize_validates_v4_then_keeps_it_while_removing_the_undo() {
        let dir = tempfile::tempdir().unwrap();
        let (guard, cleanup) = commit_split_tree(dir.path());
        assert_eq!(
            finalize(&guard, |members| {
                assert_eq!(
                    members,
                    [PathBuf::from("include.toml"), PathBuf::from("config.toml")]
                );
                Ok(())
            })
            .unwrap(),
            FinalizeOutcome::Finalized
        );
        assert_eq!(
            std::fs::read(dir.path().join("include.toml")).unwrap(),
            b"include-v4"
        );
        assert_eq!(
            std::fs::read(dir.path().join("config.toml")).unwrap(),
            b"master-v4"
        );
        assert!(!dir.path().join(cleanup).exists());
    }

    #[test]
    fn terminal_cleanup_resumes_from_each_deletion_boundary() {
        for boundary in ["blob", "originals", "empty"] {
            let dir = tempfile::tempdir().unwrap();
            let (guard, cleanup) = commit_split_tree(dir.path());
            let bytes = std::fs::read(dir.path().join(&cleanup).join(JOURNAL_NAME)).unwrap();
            let terminal = finalized_name(&sha256_hex(&bytes));
            std::fs::rename(dir.path().join(cleanup), dir.path().join(&terminal)).unwrap();
            let terminal_path = dir.path().join(&terminal);
            match boundary {
                "blob" => {
                    std::fs::remove_file(terminal_path.join(ORIGINALS_DIR_NAME).join("0001.toml"))
                        .unwrap()
                }
                "originals" => {
                    std::fs::remove_dir_all(terminal_path.join(ORIGINALS_DIR_NAME)).unwrap()
                }
                "empty" => {
                    std::fs::remove_dir_all(terminal_path.join(ORIGINALS_DIR_NAME)).unwrap();
                    std::fs::remove_file(terminal_path.join(JOURNAL_NAME)).unwrap();
                }
                _ => unreachable!(),
            }
            assert_eq!(
                finalize(&guard, |_| unreachable!()).unwrap(),
                FinalizeOutcome::Finalized
            );
            assert!(!terminal_path.exists(), "{boundary}");
            assert_eq!(
                std::fs::read(dir.path().join("config.toml")).unwrap(),
                b"master-v4"
            );
        }
    }

    #[test]
    fn finalize_refuses_fixed_or_untrusted_terminal_artifacts() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("config.toml"), b"master-v3").unwrap();
        let guard = acquire_for_migration(&dir.path().join("config.toml")).unwrap();
        create_fence(&guard).unwrap();
        assert!(finalize(&guard, |_| Ok(())).is_err());
        recover_fixed(&guard, || Ok(())).unwrap();
        std::fs::create_dir(dir.path().join(".warden-migration.finalized-not-a-hash")).unwrap();
        assert!(finalize(&guard, |_| Ok(())).is_err());
        assert!(dir
            .path()
            .join(".warden-migration.finalized-not-a-hash")
            .exists());

        let first = ".warden-migration.finalized-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let second = ".warden-migration.finalized-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        std::fs::remove_dir(dir.path().join(".warden-migration.finalized-not-a-hash")).unwrap();
        std::fs::create_dir(dir.path().join(first)).unwrap();
        std::fs::create_dir(dir.path().join(second)).unwrap();
        assert!(finalize(&guard, |_| Ok(())).is_err());
        assert!(dir.path().join(first).exists());
        assert!(dir.path().join(second).exists());
    }

    #[test]
    fn retained_undo_allows_reads_but_refuses_writes_until_finalized() {
        let dir = tempfile::tempdir().unwrap();
        let (guard, _) = commit_split_tree(dir.path());
        drop(guard);
        assert!(acquire_for_read(&dir.path().join("config.toml")).is_ok());
        let error = acquire_for_write(&dir.path().join("config.toml")).unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("--rollback") && message.contains("--finalize"));
        let guard = acquire_for_migration(&dir.path().join("config.toml")).unwrap();
        finalize(&guard, |_| Ok(())).unwrap();
        drop(guard);
        assert!(acquire_for_write(&dir.path().join("config.toml")).is_ok());
    }

    #[test]
    fn terminal_cleanup_refuses_writes_until_finalize_resumes_it() {
        let dir = tempfile::tempdir().unwrap();
        let (guard, _) = commit_split_tree(dir.path());
        assert!(with_finalize_root_fsync_failure(|| finalize(&guard, |_| Ok(()))).is_err());
        drop(guard);

        assert!(acquire_for_read(&dir.path().join("config.toml")).is_ok());
        let error = acquire_for_write(&dir.path().join("config.toml")).unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("--finalize"));
        assert!(!message.contains("--rollback"));

        let guard = acquire_for_migration(&dir.path().join("config.toml")).unwrap();
        assert_eq!(
            finalize(&guard, |_| unreachable!()).unwrap(),
            FinalizeOutcome::Finalized
        );
        drop(guard);
        assert!(acquire_for_write(&dir.path().join("config.toml")).is_ok());
    }

    #[test]
    fn malformed_or_multiple_terminal_cleanup_refuses_writes() {
        for artifacts in [
            vec![".warden-migration.finalized-not-a-hash"],
            vec![
                ".warden-migration.finalized-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                ".warden-migration.finalized-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            ],
        ] {
            let dir = tempfile::tempdir().unwrap();
            let master = dir.path().join("config.toml");
            std::fs::write(&master, b"master-v4").unwrap();
            for artifact in &artifacts {
                std::fs::create_dir(dir.path().join(artifact)).unwrap();
            }

            assert!(acquire_for_write(&master).is_err());
            for artifact in artifacts {
                assert!(dir.path().join(artifact).exists());
            }
        }
    }

    #[test]
    fn publication_refuses_a_leftover_terminal_artifact() {
        let dir = tempfile::tempdir().unwrap();
        let master = dir.path().join("config.toml");
        std::fs::write(&master, b"master-v3").unwrap();
        let terminal = dir
            .path()
            .join(".warden-migration.finalized-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        std::fs::create_dir(&terminal).unwrap();
        let guard = acquire_for_migration(&master).unwrap();
        assert!(publish(
            &guard,
            vec![migration_member(
                dir.path(),
                "config.toml",
                MemberRole::Master,
                b"master-v3",
                b"master-v4",
            )]
        )
        .is_err());
        assert!(terminal.exists());
    }
}

#[cfg(test)]
mod pinned_tests {
    use super::*;
    #[test]
    fn fence_creation_and_inspection_stay_on_the_held_root() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("root");
        std::fs::create_dir(&root).unwrap();
        let guard =
            super::super::write_lock::acquire_for_migration(&root.join("config.toml")).unwrap();
        let old = dir.path().join("old");
        std::fs::rename(&root, &old).unwrap();
        std::fs::create_dir(&root).unwrap();
        std::fs::create_dir(root.join(TXN_DIR_NAME)).unwrap();
        assert_eq!(inspect(guard.tree_io()).unwrap(), FenceState::Absent);
        std::fs::remove_dir(root.join(TXN_DIR_NAME)).unwrap();
        create_fence(&guard).unwrap();
        assert_eq!(inspect(guard.tree_io()).unwrap(), FenceState::Empty);
        assert!(old.join(TXN_DIR_NAME).is_dir());
        assert!(!root.join(TXN_DIR_NAME).exists());
    }
}
