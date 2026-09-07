//! `warden config backup` — timestamped tar.gz snapshot of the config tree.
//!
//! The archive captures the master config file
//! plus every include the config actually declares, so the backup
//! contains the full operator-facing state. Writes happen via the system
//! `tar` binary (present on every production target) to keep the Rust
//! crate footprint small; the archive format is the standard gzipped tar
//! understood by `warden config restore`.
//!
//! # Coverage is derived, never guessed
//!
//! Previously a seven-name `KNOWN_INCLUDE_DIRS` list — declared here
//! AND again in `restore.rs` — decided what got captured. A config with
//! `includes = ["custom/*.toml"]` produced a backup that silently omitted
//! it, and the operator found out at restore time, which is the worst
//! possible moment.
//!
//! Coverage is the union of the locked root-directory inventory and the
//! include graph resolved by the guarded loader. The latter preserves hidden
//! declared roots while the former keeps undeclared operator files.
//!
//! Inventory is descriptor-relative and rejects aliases, hard links, special
//! files, and unsupported names instead of asking `tar` to recurse.
//!
//! **`backup` and `restore` deliberately bias in opposite directions.**
//! For a backup the failure is losing bytes, so the set is a superset.
//! For a restore the failure is writing bytes nobody asked for into a
//! live config tree, so `restore` promotes only what the staged master
//! declares — an unreferenced archive member is extracted to staging and
//! then simply not installed.
//!
//! A backup that quietly omits a file is worse than one that refuses, so
//! an include that cannot be expressed as an archive entry (a loaded file
//! outside the config directory) is a hard error, not a skip.
//!
//! Output path defaults to `<config-parent>/backups/config-<ts>.tar.gz`
//! where `<ts>` is the current UTC timestamp (`YYYYMMDDThhmmssZ`). The
//! parent directory is created with mode 0750 if missing.

use std::ffi::{CString, OsStr};
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::Context;
use rand_core::RngCore;
use serde::{Deserialize, Serialize};

use crate::config::atomic_write::{hardened_atomic_write, AtomicWriteOpts};
use crate::config::loader::load_config_for_schema_under_read_guard;
use crate::config::migration_journal;
use crate::config::schema::SCHEMA_VERSION_V1;
use crate::config::tree_io::{
    for_each_dir_name, inspect_at, plan_external_directory_from, rename_noreplace_at, same_inode,
    unlink_at, ExternalDirectoryPlan, PinnedDirectory, TreeIo,
};
use crate::config::write_lock::{self, reserved_component, ConfigReadLock};

use super::TIMESTAMP_FORMAT;

// ────────────────────────────────────────────────────────────────────
// Scheduler engine constants.
// ────────────────────────────────────────────────────────────────────

/// File name of the concurrency lock under `<backup_dir>`.
const LOCK_FILE: &str = ".lock";
/// File name of the persistent auto-backup state under `<backup_dir>`.
const STATE_FILE: &str = ".auto_state";
/// Locks older than this are treated as stale (left by a crashed
/// process) and auto-removed on the next acquire.
const STALE_LOCK_AGE: time::Duration = time::Duration::minutes(5);
/// POSIX `EX_TEMPFAIL` — exit code returned when another backup is
/// already in flight.
const EX_TEMPFAIL: i32 = 75;

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BackupTestEvent {
    OutputOwned,
    BeforeStateLoad,
    SourceGuardDropped,
    BeforePublish,
    BeforePrivateCleanup,
    BeforeStateSave,
    BeforePrune,
    ResetStateLoaded,
    AfterGuardedLoadFailure,
}

#[cfg(test)]
type BackupTestHook = Box<dyn FnMut(BackupTestEvent)>;

#[cfg(test)]
thread_local! {
    static BACKUP_TEST_HOOK: std::cell::RefCell<Option<BackupTestHook>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
fn backup_test_event(event: BackupTestEvent) {
    BACKUP_TEST_HOOK.with(|slot| {
        let Some(mut hook) = slot.borrow_mut().take() else {
            return;
        };
        hook(event);
        *slot.borrow_mut() = Some(hook);
    });
}

#[cfg(test)]
fn with_backup_test_hook<T>(
    hook: impl FnMut(BackupTestEvent) + 'static,
    body: impl FnOnce() -> T,
) -> T {
    struct Reset(Option<BackupTestHook>);
    impl Drop for Reset {
        fn drop(&mut self) {
            BACKUP_TEST_HOOK.with(|slot| *slot.borrow_mut() = self.0.take());
        }
    }
    let _reset = Reset(BACKUP_TEST_HOOK.with(|slot| slot.replace(Some(Box::new(hook)))));
    body()
}

/// Fault-injection boundaries in the legacy lock's post-create
/// initialization. They are deliberately local to this module: production
/// never needs a lock-init timeout or recovery policy beyond the retained
/// inode cleanup below.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LockInitTestEvent {
    Created,
    BeforeWrite,
    BeforeFileSync,
    BeforeDirectorySync,
}

#[cfg(test)]
type LockInitTestHook = Box<dyn FnMut(LockInitTestEvent) -> std::io::Result<()>>;

#[cfg(test)]
thread_local! {
    static LOCK_INIT_TEST_HOOK: std::cell::RefCell<Option<LockInitTestHook>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
fn lock_init_test_event(event: LockInitTestEvent) -> std::io::Result<()> {
    LOCK_INIT_TEST_HOOK.with(|slot| {
        let Some(mut hook) = slot.borrow_mut().take() else {
            return Ok(());
        };
        let result = hook(event);
        *slot.borrow_mut() = Some(hook);
        result
    })
}

#[cfg(test)]
fn with_lock_init_test_hook<T>(
    hook: impl FnMut(LockInitTestEvent) -> std::io::Result<()> + 'static,
    body: impl FnOnce() -> T,
) -> T {
    struct Reset(Option<LockInitTestHook>);
    impl Drop for Reset {
        fn drop(&mut self) {
            LOCK_INIT_TEST_HOOK.with(|slot| *slot.borrow_mut() = self.0.take());
        }
    }
    let _reset = Reset(LOCK_INIT_TEST_HOOK.with(|slot| slot.replace(Some(Box::new(hook)))));
    body()
}

/// The top-level entries under `root` that `files_loaded` reaches, sorted
/// and deduplicated — the unit both `backup` (archive members, via
/// `tar -C <root>`) and `restore` (install set) operate on.
///
/// Derived from the resolved file paths rather than by parsing the
/// `includes` globs, so the glob shape is irrelevant: `custom/*.toml`,
/// `*.d/*.toml`, a bare `extra.toml` and a nested `a/b/c.toml` all reduce
/// correctly. The master's own file name comes out as an entry, since it
/// is `files_loaded[0]`.
///
/// Granularity is the TOP-LEVEL component, so `includes =
/// ["custom/*.toml"]` yields `custom` and the archive carries everything
/// under `custom/`, not only the `.toml` files the glob matched. That is
/// a superset of the declared coverage — deliberately, and the same
/// granularity the old `.d`-directory list had. A backup that captures a
/// neighbouring `custom/README` is harmless; one that drops a declared
/// slice is not.
///
/// # Errors
///
/// A loaded file outside `root` — reachable only through a symlink the
/// loader accepted — cannot be expressed as an entry relative to
/// `tar -C <root>`, and on restore would be written somewhere the
/// operator did not ask for. That is the "cannot capture" case, and it
/// fails loudly rather than being skipped.
fn include_roots_from_canonical(
    root: &Path,
    files_loaded: &[PathBuf],
) -> anyhow::Result<Vec<String>> {
    let mut out: Vec<String> = Vec::new();
    for file in files_loaded {
        let rel = file.strip_prefix(root).map_err(|_| {
            anyhow::anyhow!(
                "config file {} lies outside the config directory {} and cannot be \
                 captured in a backup anchored there.\n\
                 A backup that silently omits a declared include is worse than one that \
                 refuses — move the file under the config directory, or point `--config` \
                 at a directory that contains it.",
                file.display(),
                root.display()
            )
        })?;
        let first = rel.components().next().ok_or_else(|| {
            anyhow::anyhow!("config file {} resolved to an empty path", file.display())
        })?;
        let name = first.as_os_str().to_str().ok_or_else(|| {
            anyhow::anyhow!(
                "config path component {:?} is not valid UTF-8; tar entry names must be",
                first.as_os_str()
            )
        })?;
        if !out.iter().any(|e| e == name) {
            out.push(name.to_string());
        }
    }
    out.sort();
    Ok(out)
}

fn required_members_from_canonical(
    root: &Path,
    files_loaded: &[PathBuf],
) -> anyhow::Result<Vec<String>> {
    let mut members = Vec::with_capacity(files_loaded.len());
    for file in files_loaded {
        let relative = file.strip_prefix(root).map_err(|_| {
            anyhow::anyhow!(
                "config file {} lies outside the config directory {}",
                file.display(),
                root.display()
            )
        })?;
        anyhow::ensure!(
            relative
                .components()
                .all(|component| matches!(component, std::path::Component::Normal(_))),
            "config file {} is not a normal root-relative member",
            file.display()
        );
        let member = relative.to_str().ok_or_else(|| {
            anyhow::anyhow!("config path {:?} is not valid UTF-8", relative.as_os_str())
        })?;
        anyhow::ensure!(!member.is_empty(), "config member path is empty");
        members.push(member.to_owned());
    }
    members.sort();
    members.dedup();
    Ok(members)
}

pub(crate) fn include_roots(root: &Path, files_loaded: &[PathBuf]) -> anyhow::Result<Vec<String>> {
    let canonical = root
        .canonicalize()
        .map_err(|e| anyhow::anyhow!("cannot resolve config directory {}: {e}", root.display()))?;
    include_roots_from_canonical(&canonical, files_loaded)
}

fn validate_source_relative_output(
    relative: Option<&Path>,
    display: &Path,
    include_roots: &[String],
) -> anyhow::Result<Option<String>> {
    let Some(relative) = relative else {
        return Ok(None);
    };
    let components: Vec<_> = relative.components().collect();
    if components.is_empty() {
        anyhow::bail!("backup output must not be the config source root");
    }
    let names: Vec<_> = components
        .iter()
        .map(|component| match component {
            std::path::Component::Normal(name) => Ok(name),
            _ => anyhow::bail!(
                "backup output is not a canonical child of config root: {}",
                display.display()
            ),
        })
        .collect::<anyhow::Result<_>>()?;
    if names.iter().any(|name| reserved_component(name)) {
        anyhow::bail!(
            "backup output uses the reserved config namespace: {}",
            display.display()
        );
    }
    if names.len() != 1 {
        anyhow::bail!(
            "backup output is nested in captured config data: {}",
            display.display()
        );
    }
    let name = names[0].to_str().ok_or_else(|| {
        anyhow::anyhow!("backup output component {:?} is not valid UTF-8", names[0])
    })?;
    if include_roots.iter().any(|entry| entry == name) {
        anyhow::bail!(
            "backup output is re-added by the declared include graph: {}",
            display.display()
        );
    }
    Ok(Some(name.to_owned()))
}

fn absolute_from_cwd(path: &Path, cwd: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        cwd.join(path)
    }
}

fn push_unique(values: &mut Vec<String>, value: Option<String>) {
    if let Some(value) = value {
        if !values.contains(&value) {
            values.push(value);
        }
    }
}

struct OutputPlan {
    requested: PathBuf,
    cwd: PathBuf,
    source_root: std::fs::File,
    external: ExternalDirectoryPlan,
    excluded_roots: Vec<String>,
}

#[derive(Debug)]
struct PreparedOutput {
    dir: std::fs::File,
    path: PathBuf,
    excluded_roots: Vec<String>,
}

/// One pinned backup output directory and its legacy-format ownership inode.
///
/// The lock entry intentionally remains `.lock` for interoperation with older
/// binaries. POSIX has no conditional unlink-by-inode operation, so Drop can
/// check identity before `unlinkat`, but cannot close a hostile replacement
/// race between those two operations.
#[derive(Debug)]
struct OwnedOutput {
    prepared: PreparedOutput,
    lock_file: std::fs::File,
}

impl OwnedOutput {
    fn dir(&self) -> &std::fs::File {
        &self.prepared.dir
    }

    fn path(&self) -> &Path {
        &self.prepared.path
    }

    fn excluded_roots(&self) -> &[String] {
        &self.prepared.excluded_roots
    }

    /// A descriptor-anchored path for helpers that currently accept paths.
    fn proc_dir(&self) -> PathBuf {
        PathBuf::from(format!("/proc/self/fd/{}", self.prepared.dir.as_raw_fd()))
    }
}

impl Drop for OwnedOutput {
    fn drop(&mut self) {
        remove_lock_if_owned(self.dir(), &self.lock_file);
    }
}

fn remove_lock_if_owned(dir: &std::fs::File, held: &std::fs::File) {
    let Ok(Some(current)) = inspect_at(dir, OsStr::new(LOCK_FILE)) else {
        return;
    };
    let Ok(same) = current
        .metadata()
        .and_then(|current| held.metadata().map(|held| same_inode(&current, &held)))
    else {
        return;
    };
    if same && unlink_at(dir, OsStr::new(LOCK_FILE)).is_ok() {
        let _ = dir.sync_all();
    }
}

/// A lock inode created by `O_EXCL` but not yet safe to advertise as output
/// ownership. Its Drop path is deliberately identity-checked, so every
/// initialization error releases only the inode this invocation created.
struct ProvisionalLock<'dir> {
    dir: &'dir std::fs::File,
    file: Option<std::fs::File>,
    cleanup_on_drop: bool,
}

impl<'dir> ProvisionalLock<'dir> {
    fn new(dir: &'dir std::fs::File, file: std::fs::File) -> Self {
        Self {
            dir,
            file: Some(file),
            cleanup_on_drop: true,
        }
    }

    fn file_mut(&mut self) -> &mut std::fs::File {
        self.file
            .as_mut()
            .expect("provisional lock retains its inode")
    }

    fn revalidate_name(&self) -> std::io::Result<()> {
        let current = inspect_at(self.dir, OsStr::new(LOCK_FILE))?.ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "backup lock disappeared during initialization",
            )
        })?;
        let held = self
            .file
            .as_ref()
            .expect("provisional lock retains its inode")
            .metadata()?;
        if same_inode(&current.metadata()?, &held) {
            Ok(())
        } else {
            Err(std::io::Error::other(
                "backup lock entry changed during initialization",
            ))
        }
    }

    fn into_file(mut self) -> std::io::Result<std::fs::File> {
        self.revalidate_name()?;
        self.cleanup_on_drop = false;
        Ok(self
            .file
            .take()
            .expect("provisional lock retains its inode"))
    }
}

impl Drop for ProvisionalLock<'_> {
    fn drop(&mut self) {
        if !self.cleanup_on_drop {
            return;
        }
        let Some(file) = self.file.as_ref() else {
            return;
        };
        remove_lock_if_owned(self.dir, file);
    }
}

fn plan_output(
    tree: TreeIo<'_>,
    requested: &Path,
    include_roots: &[String],
) -> anyhow::Result<OutputPlan> {
    plan_output_from(tree, requested, include_roots, tree.cwd)
}

/// Plan output relative to the caller's already-resolved working directory.
fn plan_output_from(
    tree: TreeIo<'_>,
    requested: &Path,
    include_roots: &[String],
    cwd: &Path,
) -> anyhow::Result<OutputPlan> {
    let cwd = cwd.to_path_buf();
    let requested = absolute_from_cwd(requested, &cwd);
    let mut excluded_roots = Vec::new();
    let source_root = tree.backup_root_fd()?;
    let external = plan_external_directory_from(&requested, &cwd)?;
    push_unique(
        &mut excluded_roots,
        validate_source_relative_output(
            external.relative_to(&source_root)?.as_deref(),
            external.resolved(),
            include_roots,
        )?,
    );
    Ok(OutputPlan {
        requested,
        cwd,
        source_root,
        external,
        excluded_roots,
    })
}

fn prepare_output(
    mut plan: OutputPlan,
    include_roots: &[String],
) -> anyhow::Result<PreparedOutput> {
    let dir = plan.external.open_or_create().map_err(|e| {
        anyhow::anyhow!(
            "cannot open or create backup directory {}: {e:#}",
            plan.requested.display()
        )
    })?;

    let current = plan_external_directory_from(&plan.requested, &plan.cwd)?;
    push_unique(
        &mut plan.excluded_roots,
        validate_source_relative_output(
            current.relative_to(&plan.source_root)?.as_deref(),
            current.resolved(),
            include_roots,
        )?,
    );
    let resolved = current.resolved().to_path_buf();
    let current_dir = current.open_existing()?;
    anyhow::ensure!(
        same_inode(&dir.metadata()?, &current_dir.metadata()?),
        "backup output changed while it was being prepared: {}",
        resolved.display()
    );
    Ok(PreparedOutput {
        dir,
        path: resolved,
        excluded_roots: plan.excluded_roots,
    })
}

fn archive_name() -> anyhow::Result<String> {
    let ts = time::OffsetDateTime::now_utc()
        .format(&TIMESTAMP_FORMAT)
        .map_err(|e| anyhow::anyhow!("failed to format timestamp: {e}"))?;
    Ok(format!("config-{ts}.tar.gz"))
}

static PRIVATE_ARCHIVE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

fn create_private_archive(dir: &std::fs::File) -> anyhow::Result<(String, std::fs::File)> {
    for _ in 0..32 {
        let mut random = [0; 16];
        rand_core::OsRng
            .try_fill_bytes(&mut random)
            .map_err(|e| anyhow::anyhow!("cannot generate private archive name: {e}"))?;
        let name = format!(
            ".warden-backup-{}-{}-{:032x}",
            std::process::id(),
            PRIVATE_ARCHIVE_SEQUENCE.fetch_add(1, Ordering::Relaxed),
            u128::from_ne_bytes(random),
        );
        let c_name = CString::new(name.as_bytes())?;
        let fd = unsafe {
            libc::openat(
                dir.as_raw_fd(),
                c_name.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if fd >= 0 {
            let file = unsafe { std::fs::File::from_raw_fd(fd) };
            return Ok((name, file));
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::AlreadyExists {
            return Err(error.into());
        }
    }
    anyhow::bail!("cannot allocate a unique private backup archive")
}

fn remove_private_if_owned(
    dir: &std::fs::File,
    name: &str,
    file: &std::fs::File,
) -> anyhow::Result<()> {
    let Some(current) = inspect_at(dir, OsStr::new(name))? else {
        return Ok(());
    };
    if same_inode(&current.metadata()?, &file.metadata()?) {
        unlink_at(dir, OsStr::new(name))?;
        dir.sync_all()?;
    }
    Ok(())
}

fn require_final_absent(dir: &std::fs::File, name: &str) -> anyhow::Result<()> {
    if inspect_at(dir, OsStr::new(name))?.is_some() {
        anyhow::bail!("backup archive target already exists: {name}");
    }
    Ok(())
}

fn publish_archive(
    dir: &std::fs::File,
    private_name: &str,
    private_file: &std::fs::File,
    final_name: &str,
) -> anyhow::Result<()> {
    private_file.sync_all()?;
    let current_private = inspect_at(dir, OsStr::new(private_name))?
        .context("private backup archive disappeared before publication")?;
    anyhow::ensure!(
        same_inode(&current_private.metadata()?, &private_file.metadata()?)
            && private_file.metadata()?.nlink() == 1,
        "private backup archive changed before publication"
    );
    require_final_absent(dir, final_name)?;
    rename_noreplace_at(dir, OsStr::new(private_name), dir, OsStr::new(final_name))?;
    dir.sync_all()?;
    Ok(())
}

fn inventory_directory(
    tree: TreeIo<'_>,
    directory: &PinnedDirectory<'_>,
    members: &mut Vec<String>,
) -> anyhow::Result<()> {
    let mut names = Vec::new();
    for_each_dir_name(directory, |name| {
        let utf8 = name.to_str().ok_or_else(|| {
            anyhow::anyhow!(
                "config directory entry {:?} is not valid UTF-8 and cannot be archived",
                name
            )
        })?;
        if !reserved_component(name) && !is_restore_residue(name) {
            names.push(utf8.to_owned());
        }
        Ok(())
    })?;
    names.sort();
    for name in names {
        let name_os = OsStr::new(&name);
        let (_, meta) = tree.backup_inspect_child(directory, name_os)?;
        let relative = directory.backup_relative().join(&name);
        anyhow::ensure!(
            !meta.file_type().is_symlink(),
            "backup refuses symlink member {}",
            relative.display()
        );
        if meta.is_dir() {
            members.push(relative.to_string_lossy().into_owned());
            let child = tree.backup_child_directory(directory, name_os)?;
            inventory_directory(tree, &child, members)?;
        } else {
            anyhow::ensure!(
                meta.is_file(),
                "backup refuses special member {}",
                relative.display()
            );
            anyhow::ensure!(
                meta.nlink() == 1,
                "backup refuses hard-linked member {}",
                relative.display()
            );
            members.push(relative.to_string_lossy().into_owned());
        }
    }
    Ok(())
}

fn is_restore_residue(name: &OsStr) -> bool {
    let Some(name) = name.to_str() else {
        return false;
    };
    let Some(name) = name.strip_prefix('.') else {
        return false;
    };
    [".incoming-", ".pre-restore-"].iter().any(|marker| {
        name.rfind(marker).is_some_and(|index| {
            let (base, suffix) = name.split_at(index);
            let suffix = &suffix[marker.len()..];
            let mut parts = suffix.split('-');
            !base.is_empty()
                && parts
                    .next()
                    .is_some_and(|pid| !pid.is_empty() && pid.bytes().all(|b| b.is_ascii_digit()))
                && parts
                    .next()
                    .is_some_and(|seq| !seq.is_empty() && seq.bytes().all(|b| b.is_ascii_digit()))
                && parts.next().is_none()
        })
    })
}

fn inventory_members(
    tree: TreeIo<'_>,
    master_name: &str,
    master_alias: Option<&OsStr>,
    output_roots: &[String],
    include_roots: &[String],
    required_members: &[String],
) -> anyhow::Result<(Vec<String>, Vec<String>)> {
    let root = tree.backup_root_directory()?;
    let mut roots = vec![master_name.to_owned()];
    for_each_dir_name(&root, |name| {
        if Some(name) == master_alias {
            return Ok(());
        }
        let name = name.to_str().ok_or_else(|| {
            anyhow::anyhow!(
                "config directory entry {:?} is not valid UTF-8 and cannot be archived",
                name
            )
        })?;
        if name != master_name
            && !reserved_component(OsStr::new(name))
            && !is_restore_residue(OsStr::new(name))
            && !output_roots.iter().any(|output| output == name)
        {
            roots.push(name.to_owned());
        }
        Ok(())
    })?;
    for name in include_roots {
        if output_roots.iter().any(|output| output == name) {
            anyhow::bail!("backup output is re-added by the declared include graph: {name}");
        }
        if !reserved_component(OsStr::new(name))
            && !is_restore_residue(OsStr::new(name))
            && !roots.contains(name)
        {
            roots.push(name.clone());
        }
    }
    roots.sort();
    roots.dedup();

    let mut members = Vec::new();
    for name in &roots {
        let (_, meta) = tree.backup_inspect_child(&root, OsStr::new(name))?;
        anyhow::ensure!(
            !meta.file_type().is_symlink(),
            "backup refuses symlink member {name}"
        );
        if meta.is_dir() {
            members.push(name.clone());
            let child = tree.backup_child_directory(&root, OsStr::new(name))?;
            inventory_directory(tree, &child, &mut members)?;
        } else {
            anyhow::ensure!(meta.is_file(), "backup refuses special member {name}");
            anyhow::ensure!(
                meta.nlink() == 1,
                "backup refuses hard-linked member {name}"
            );
            members.push(name.clone());
        }
    }
    members.sort();
    for required in required_members {
        anyhow::ensure!(
            members.binary_search(required).is_ok(),
            "backup safety policy excludes required config member {required}"
        );
    }
    Ok((roots, members))
}

/// Structured result of a backup, for callers that render their own
/// output (the TUI) rather than printing to stdout.
pub struct BackupReport {
    /// Full path of the archive written.
    pub archive: PathBuf,
    /// Entry names captured, relative to the config dir: the master file
    /// plus each `*.d/` include dir that exists.
    pub entries: Vec<String>,
}

struct BackupAdmission {
    config: crate::config::schema::BackupConfig,
    include_roots: Vec<String>,
    required_members: Vec<String>,
    config_verified: bool,
    auto_interval_error: Option<String>,
}

#[derive(Clone, Copy)]
enum BackupAdmissionPurpose {
    Archive,
    AutoArchive,
    StateOnly,
}

fn admit_backup(guard: &ConfigReadLock) -> anyhow::Result<BackupAdmission> {
    admit_backup_for(
        guard,
        BackupAdmissionPurpose::Archive,
        &mut std::io::stderr(),
    )
}

fn admit_backup_for(
    guard: &ConfigReadLock,
    purpose: BackupAdmissionPurpose,
    notices: &mut dyn Write,
) -> anyhow::Result<BackupAdmission> {
    let master = guard.canonical_master();
    let root = master.parent().context("canonical master has no parent")?;
    // Fence admission is fatal; schema diagnostics below remain best effort.
    migration_journal::refuse_normal_access(guard.tree_io())?;
    match load_config_for_schema_under_read_guard(
        guard,
        master,
        SCHEMA_VERSION_V1,
        time::OffsetDateTime::now_utc(),
    ) {
        Ok(loaded) => {
            let include_roots = include_roots_from_canonical(root, &loaded.files_loaded)?;
            let required_members = required_members_from_canonical(root, &loaded.files_loaded)?;
            Ok(BackupAdmission {
                config: loaded.config.backup,
                include_roots,
                required_members,
                config_verified: true,
                auto_interval_error: None,
            })
        }
        Err(errs) => {
            let auto_interval_error = only_auto_interval_validation_error(&errs);
            #[cfg(test)]
            backup_test_event(BackupTestEvent::AfterGuardedLoadFailure);
            migration_journal::refuse_normal_access(guard.tree_io())?;
            let master_plan = guard.tree_io().plan_master_target()?;
            anyhow::ensure!(
                !master_plan.is_new(),
                "backup refuses an absent canonical master: {}",
                guard.canonical_master().display()
            );
            if matches!(purpose, BackupAdmissionPurpose::Archive)
                || (matches!(purpose, BackupAdmissionPurpose::AutoArchive)
                    && auto_interval_error.is_none())
            {
                let _ = writeln!(
                    notices,
                    "warning: {} does not currently load ({} error(s)); the archive captures {} \
                     as it stands, but its coverage was not verified against the declared includes.",
                    master.display(),
                    errs.len(),
                    root.display()
                );
                let _ = writeln!(notices, "  first error: {}", errs[0]);
            }
            Ok(BackupAdmission {
                config: crate::config::schema::BackupConfig::default(),
                include_roots: Vec::new(),
                required_members: vec![master
                    .file_name()
                    .and_then(OsStr::to_str)
                    .context("canonical master filename is not valid UTF-8")?
                    .to_owned()],
                config_verified: false,
                auto_interval_error,
            })
        }
    }
}

/// Return the validator's interval diagnostic only when it is the sole
/// structured config error. This is intentionally based on the typed error
/// context rather than rendered human prose: all other validation failures
/// remain recovery-snapshot admissions.
fn only_auto_interval_validation_error(
    errors: &[crate::config::error::ConfigError],
) -> Option<String> {
    (errors.len() == 1
        && errors[0].kind() == "validation_failed"
        && errors[0].context().entity.as_deref() == Some("backup.auto_interval"))
    .then(|| errors[0].context().reason.clone())
}

/// A private archive that cannot outlive the output ownership capability.
struct PendingArchive<'o> {
    output: &'o OwnedOutput,
    private_name: String,
    private_file: std::fs::File,
    final_name: String,
    entries: Vec<String>,
    members: Vec<String>,
    cleanup_on_drop: bool,
}

impl<'o> PendingArchive<'o> {
    fn prepare(
        guard: &ConfigReadLock,
        output: &'o OwnedOutput,
        admission: &BackupAdmission,
    ) -> anyhow::Result<Self> {
        let master = guard.canonical_master();
        let master_name = master
            .file_name()
            .and_then(OsStr::to_str)
            .context("canonical master filename is not valid UTF-8")?;
        let (entries, members) = inventory_members(
            guard.tree_io(),
            master_name,
            guard.tree_io().backup_master_alias(),
            output.excluded_roots(),
            &admission.include_roots,
            &admission.required_members,
        )?;
        let final_name = archive_name()?;
        require_final_absent(output.dir(), &final_name)?;
        let (private_name, private_file) = create_private_archive(output.dir())?;
        Ok(Self {
            output,
            private_name,
            private_file,
            final_name,
            entries,
            members,
            cleanup_on_drop: true,
        })
    }

    fn run_tar(&self, guard: &ConfigReadLock, tar_program: &OsStr) -> anyhow::Result<()> {
        migration_journal::refuse_normal_access(guard.tree_io())?;
        let root_fd = guard.tree_io().backup_root_fd()?;
        let mut command = Command::new(tar_program);
        command
            .arg("--create")
            .arg("--gzip")
            .arg("--file=-")
            .arg("--no-recursion")
            .arg("--null")
            .arg("--verbatim-files-from")
            .arg("--files-from=-")
            .env_remove("TAR_OPTIONS")
            .stdin(Stdio::piped())
            .stdout(Stdio::from(self.private_file.try_clone()?));
        unsafe {
            command.pre_exec(move || {
                if libc::fchdir(root_fd.as_raw_fd()) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = command
            .spawn()
            .map_err(|e| anyhow::anyhow!("failed to run tar: {e}"))?;
        let mut input = match child.stdin.take() {
            Some(input) => input,
            None => {
                let _ = child.wait();
                anyhow::bail!("tar stdin unavailable");
            }
        };
        let write_result = (|| -> std::io::Result<()> {
            for member in &self.members {
                input.write_all(member.as_bytes())?;
                input.write_all(&[0])?;
            }
            Ok(())
        })();
        drop(input);
        let status = child.wait()?;
        write_result.map_err(|e| anyhow::anyhow!("cannot feed tar member list: {e}"))?;
        anyhow::ensure!(status.success(), "tar exited with {status}");
        Ok(())
    }

    fn cleanup(&self) -> anyhow::Result<()> {
        #[cfg(test)]
        backup_test_event(BackupTestEvent::BeforePrivateCleanup);
        remove_private_if_owned(self.output.dir(), &self.private_name, &self.private_file)
    }

    fn abort(mut self, primary_error: anyhow::Error) -> anyhow::Result<BackupReport> {
        self.cleanup_on_drop = false;
        if let Err(cleanup) = self.cleanup() {
            return Err(primary_error.context(format!(
                "also failed to clean private backup archive: {cleanup:#}"
            )));
        }
        Err(primary_error)
    }

    fn publish(mut self) -> anyhow::Result<BackupReport> {
        #[cfg(test)]
        backup_test_event(BackupTestEvent::BeforePublish);
        if let Err(error) = publish_archive(
            self.output.dir(),
            &self.private_name,
            &self.private_file,
            &self.final_name,
        ) {
            self.cleanup_on_drop = false;
            if let Err(cleanup) = self.cleanup() {
                return Err(error.context(format!(
                    "also failed to clean private backup archive: {cleanup:#}"
                )));
            }
            return Err(error);
        }
        self.cleanup_on_drop = false;
        Ok(BackupReport {
            archive: self.output.path().join(&self.final_name),
            entries: std::mem::take(&mut self.entries),
        })
    }
}

impl Drop for PendingArchive<'_> {
    fn drop(&mut self) {
        if self.cleanup_on_drop {
            let _ =
                remove_private_if_owned(self.output.dir(), &self.private_name, &self.private_file);
        }
    }
}

fn create_backup_in_owned_output_with_tar(
    guard: ConfigReadLock,
    output: &OwnedOutput,
    admission: &BackupAdmission,
    tar_program: &OsStr,
) -> anyhow::Result<BackupReport> {
    let pending = PendingArchive::prepare(&guard, output, admission)?;
    let tar_result = pending.run_tar(&guard, tar_program);
    drop(guard);
    #[cfg(test)]
    backup_test_event(BackupTestEvent::SourceGuardDropped);
    match tar_result {
        Ok(()) => pending.publish(),
        Err(error) => pending.abort(error),
    }
}

/// Create a tar.gz snapshot through one read capability, without printing.
pub fn create_backup(config_path: &Path, out: Option<&Path>) -> anyhow::Result<BackupReport> {
    let guard = write_lock::acquire_for_read(config_path)?;
    let admission = admit_backup(&guard)?;
    let requested_out = out
        .map(Path::to_path_buf)
        .unwrap_or_else(|| admission.config.resolve_dir(guard.canonical_master()));
    let prepared = prepare_output(
        plan_output(guard.tree_io(), &requested_out, &admission.include_roots)?,
        &admission.include_roots,
    )?;
    let output = acquire_output(prepared, time::OffsetDateTime::now_utc())?;
    create_backup_in_owned_output_with_tar(guard, &output, &admission, OsStr::new("tar"))
}

/// CLI entry point: create a backup and print the human summary. Returns
/// the archive path for the operator to inspect / copy away.
pub fn run_backup(config_path: &Path, out: Option<&Path>) -> anyhow::Result<PathBuf> {
    let report = create_backup(config_path, out)?;
    println!("backup written: {}", report.archive.display());
    println!("  {} entry/entries captured:", report.entries.len());
    for e in &report.entries {
        println!("    - {e}");
    }
    Ok(report.archive)
}

/// One restore point discovered by [`list_backups`].
pub struct BackupEntry {
    /// Full path of the `config-<ts>.tar.gz` archive.
    pub path: PathBuf,
    /// Creation time (UTC), parsed from the archive name.
    pub timestamp: time::OffsetDateTime,
    /// Archive size in bytes.
    pub size: u64,
    /// `Some(reason)` when the archive is on disk but cannot be opened.
    /// Listed anyway: an archive the caller cannot read is a different
    /// operator problem from one that is not there, and reporting both as
    /// absence sends them after the wrong one.
    pub unreadable: Option<String>,
}

/// A pre-migration rollback copy — the plain master a `warden migrate`
/// verb sets aside before it rewrites anything, named
/// `pre-migration-<ts>.toml` (plus a `-N` suffix on a same-second
/// collision).
///
/// Deliberately NOT a [`BackupEntry`]. It is not a `tar` archive, and
/// every consumer of [`list_backups`] treats what it returns as
/// restorable: [`latest_archive`] hands the newest entry straight to the
/// restore path, and [`prune_archives`] deletes from that list by
/// retention. The rollback copy is the newest thing in the directory in
/// the minutes after an upgrade — exactly when both would reach for it.
pub struct MigrationBackup {
    /// Full path of the `pre-migration-<ts>.toml` copy.
    pub path: PathBuf,
    /// Size in bytes.
    pub size: u64,
    /// `Some(reason)` when the copy is on disk but cannot be opened.
    pub unreadable: Option<String>,
}

/// Everything one backup directory holds, in the two shapes that live
/// there, plus the reason it could not be read.
///
/// The separation that matters is "the directory is not there" (a fresh
/// install — not an error) from "the directory is there and cannot be
/// read". Collapsing those into an empty list is what let a rollback copy
/// that was plainly on disk report as absent.
pub struct BackupScan {
    /// `Some` when the directory exists and `read_dir` failed. A missing
    /// directory leaves this `None` with both lists empty.
    pub dir_error: Option<std::io::Error>,
    /// Restorable `config-<ts>.tar.gz` archives, newest first.
    pub archives: Vec<BackupEntry>,
    /// Pre-migration rollback copies, newest first.
    pub migration: Vec<MigrationBackup>,
}

/// `Some(reason)` when `path` cannot be opened for reading.
///
/// A name match says nothing about access. The rollback copy a root
/// migration writes beside a daemon-owned config matches by name and
/// fails at `open(2)`, and that is the case the operator needs told
/// apart from an empty directory.
fn open_failure(path: &Path) -> Option<String> {
    std::fs::File::open(path).err().map(|e| e.to_string())
}

/// True for `pre-migration-<ts>.toml` and its numeric collision variants.
fn is_migration_backup(name: &str) -> bool {
    let Some(rest) = name.strip_prefix("pre-migration-") else {
        return false;
    };
    let base = rest
        .rsplit_once('-')
        .filter(|(_, n)| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
        .map_or(rest, |(head, _)| head);
    base.ends_with(".toml")
}

/// Read `dir` once and sort what is in it into the two kinds of backup,
/// annotating each with whether it can actually be opened.
pub fn scan_backup_dir(dir: &Path) -> BackupScan {
    let mut scan = BackupScan {
        dir_error: None,
        archives: Vec::new(),
        migration: Vec::new(),
    };
    let read_dir = match std::fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return scan,
        Err(e) => {
            scan.dir_error = Some(e);
            return scan;
        }
    };
    for entry in read_dir.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
        if let Some(ts_str) = name
            .strip_prefix("config-")
            .and_then(|s| s.strip_suffix(".tar.gz"))
        {
            let Ok(parsed) = time::PrimitiveDateTime::parse(ts_str, &TIMESTAMP_FORMAT) else {
                continue;
            };
            scan.archives.push(BackupEntry {
                unreadable: open_failure(&path),
                path,
                timestamp: parsed.assume_utc(),
                size,
            });
        } else if is_migration_backup(name) {
            scan.migration.push(MigrationBackup {
                unreadable: open_failure(&path),
                path,
                size,
            });
        }
    }
    scan.archives
        .sort_by_key(|b| std::cmp::Reverse(b.timestamp));
    // Sorted by name, not by a parsed timestamp: the migrator's name is
    // RFC3339 with `:` swapped for `-`, and it may carry a collision
    // suffix. Lexicographic order over that fixed-width prefix is
    // chronological to the second, which is all the name records.
    scan.migration
        .sort_by(|a, b| b.path.file_name().cmp(&a.path.file_name()));
    scan
}

/// List the restorable backup archives in `dir`, newest first.
///
/// Recognises only the `config-<YYYYMMDDThhmmssZ>.tar.gz` names
/// [`create_backup`] writes. That narrowness is load-bearing, not
/// incidental: [`latest_archive`] unpacks what this returns and
/// [`prune_archives`] deletes from it. Pre-migration rollback copies are
/// reported through [`BackupScan::migration`] instead.
///
/// A missing directory yields an empty list — "no backups yet" is not an
/// error. An *unreadable* directory also yields an empty list, because
/// this signature has no way to say otherwise; callers that must tell the
/// two apart read [`scan_backup_dir`] directly.
pub fn list_backups(dir: &Path) -> Vec<BackupEntry> {
    scan_backup_dir(dir).archives
}

/// Resolve the backup directory for `config_path` by loading the master
/// best-effort: the `[backup] dir` if the config is loadable, else the
/// `<config-parent>/backups` default. Best-effort so a broken master can
/// still be backed up / listed from the default location.
pub fn resolved_backup_dir(config_path: &Path) -> PathBuf {
    use crate::config::schema::BackupConfig;
    crate::config::loader::load_config(config_path, time::OffsetDateTime::now_utc())
        .map(|loaded| loaded.config.backup.resolve_dir(&loaded.master_path))
        .unwrap_or_else(|_| {
            let canonical = crate::config::write_lock::ConfigTreeIdentity::resolve(config_path)
                .map(|identity| identity.canonical_master)
                .unwrap_or_else(|_| config_path.to_path_buf());
            BackupConfig::default().resolve_dir(&canonical)
        })
}

/// Resolve the newest archive in `config_path`'s configured backup dir,
/// for `warden config restore --latest`.
///
/// "Latest" stays literal: an unreadable newest archive is an error
/// naming the access failure, never a silent fall-through to an older
/// one. Each of the three ways this can fail — directory unreadable,
/// newest archive unreadable, nothing restorable there — says which one
/// it was, because the operator's next move differs in all three.
pub fn latest_archive(config_path: &Path) -> anyhow::Result<PathBuf> {
    let dir = resolved_backup_dir(config_path);
    let scan = scan_backup_dir(&dir);
    if let Some(e) = scan.dir_error {
        anyhow::bail!("cannot read backup directory {}: {e}", dir.display());
    }
    match scan.archives.first() {
        Some(entry) => match &entry.unreadable {
            None => Ok(entry.path.clone()),
            Some(reason) => anyhow::bail!(
                "newest backup {} cannot be read: {reason} — run as a user that can, \
                 or pick another with --list",
                entry.path.display()
            ),
        },
        None if !scan.migration.is_empty() => anyhow::bail!(
            "no restorable archive in {} — it holds {} pre-migration rollback file(s), \
             which are plain config files: copy one over the master by hand",
            dir.display(),
            scan.migration.len()
        ),
        None => anyhow::bail!("no backups in {} — nothing to restore", dir.display()),
    }
}

/// Size for the listing, or the reason the file could not be opened.
fn size_or_reason(size: u64, unreadable: &Option<String>) -> String {
    match unreadable {
        Some(reason) => format!("unreadable: {reason}"),
        None => human_bytes(size),
    }
}

/// Append the labelled pre-migration block for `dir`. No-op when there is
/// nothing to say.
fn push_migration_block(lines: &mut Vec<String>, dir: &Path, copies: &[MigrationBackup]) {
    if copies.is_empty() {
        return;
    }
    lines.push(format!(
        "{} pre-migration rollback file(s) in {}:",
        copies.len(),
        dir.display()
    ));
    for m in copies {
        let name = m.path.file_name().unwrap_or_default().to_string_lossy();
        lines.push(format!(
            "  {name}  ({})",
            size_or_reason(m.size, &m.unreadable)
        ));
    }
    lines.push(
        "  these are plain config files, not archives: restore one by copying it over".to_string(),
    );
    lines.push(
        "  the master config. `warden config restore` unpacks config-<ts>.tar.gz only.".to_string(),
    );
}

/// The lines `warden config restore --list` prints for one directory.
///
/// Split from the printer so the output is testable without standing up a
/// loadable master config. Errs — rather than printing an empty list —
/// when the directory is present and unreadable.
pub(crate) fn restore_points_lines(dir: &Path) -> anyhow::Result<Vec<String>> {
    let scan = scan_backup_dir(dir);
    if let Some(e) = scan.dir_error {
        anyhow::bail!("cannot read backup directory {}: {e}", dir.display());
    }

    let mut lines = Vec::new();
    if scan.archives.is_empty() && scan.migration.is_empty() {
        lines.push(format!("no backups in {}", dir.display()));
        return Ok(lines);
    }

    if scan.archives.is_empty() {
        lines.push(format!("no restore point in {}", dir.display()));
    } else {
        lines.push(format!(
            "{} restore point(s) in {}:",
            scan.archives.len(),
            dir.display()
        ));
        for e in &scan.archives {
            let name = e.path.file_name().unwrap_or_default().to_string_lossy();
            lines.push(format!(
                "  {name}  ({})",
                size_or_reason(e.size, &e.unreadable)
            ));
        }
    }

    push_migration_block(&mut lines, dir, &scan.migration);
    Ok(lines)
}

/// Everything `warden config restore --list` prints for `config_path`.
///
/// Two directories, not one. The migrator writes its rollback copy to
/// `<config-parent>/backups` and cannot do otherwise — it runs on a config
/// the current loader refuses, which is the reason it is running — while
/// this listing resolves `[backup] dir`. Under a configured backup dir the
/// two are different places, and listing only the configured one reports a
/// rollback copy that is plainly on disk as absent: the exact failure this
/// listing exists to prevent. An unreadable second directory is skipped
/// silently; it is a fallback location, and the configured one has already
/// been reported on.
pub(crate) fn restore_list_lines(config_path: &Path) -> anyhow::Result<Vec<String>> {
    let dir = resolved_backup_dir(config_path);
    let mut lines = restore_points_lines(&dir)?;

    let canonical_master = crate::config::write_lock::ConfigTreeIdentity::resolve(config_path)
        .map(|identity| identity.canonical_master)
        .unwrap_or_else(|_| config_path.to_path_buf());
    let beside_config = canonical_master
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("backups");
    if beside_config != dir {
        push_migration_block(
            &mut lines,
            &beside_config,
            &scan_backup_dir(&beside_config).migration,
        );
    }
    Ok(lines)
}

/// CLI `warden config restore --list`: print the restore points in the
/// configured backup dir, newest first (name + size), then any
/// pre-migration rollback files. The TUI restore picker renders the
/// [`list_backups`] half with richer formatting.
pub fn run_list_restore_points(config_path: &Path) -> anyhow::Result<()> {
    for line in restore_list_lines(config_path)? {
        println!("{line}");
    }
    Ok(())
}

/// Compact human-readable byte size (e.g. `1.2 KiB`). Shared with the TUI
/// restore picker so both surfaces format archive sizes identically.
pub(crate) fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 4] = ["B", "KiB", "MiB", "GiB"];
    let mut value = n as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{n} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

// ════════════════════════════════════════════════════════════════════
// Scheduler engine: lock + state + retention + orchestrator.
// ════════════════════════════════════════════════════════════════════

/// Errors returned by output ownership acquisition.
#[derive(Debug, thiserror::Error)]
enum LockError {
    #[error("backup in progress (lock held since {since})")]
    Held { since: time::OffsetDateTime },
    #[error("cannot create lock file at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

/// Acquire pinned output ownership with the legacy O_EXCL `.lock` protocol.
fn acquire_output(
    prepared: PreparedOutput,
    now: time::OffsetDateTime,
) -> Result<OwnedOutput, LockError> {
    let path = prepared.path.join(LOCK_FILE);
    let body = format!(
        "{}:{}\n",
        std::process::id(),
        now.format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_else(|_| "unknown".into())
    );

    match try_create_lock_at(&prepared.dir, OsStr::new(LOCK_FILE), body.as_bytes()) {
        Ok(lock_file) => {
            #[cfg(test)]
            backup_test_event(BackupTestEvent::OutputOwned);
            Ok(OwnedOutput {
                prepared,
                lock_file,
            })
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            let current = inspect_at(&prepared.dir, OsStr::new(LOCK_FILE)).map_err(|source| {
                LockError::Io {
                    path: path.clone(),
                    source,
                }
            })?;
            let Some(current) = current else {
                return Err(LockError::Held { since: now });
            };
            let metadata = current.metadata().map_err(|source| LockError::Io {
                path: path.clone(),
                source,
            })?;
            if !metadata.is_file() {
                return Err(LockError::Io {
                    path,
                    source: std::io::Error::other("backup lock entry is not a regular file"),
                });
            }
            let mtime = metadata
                .modified()
                .map(time::OffsetDateTime::from)
                .unwrap_or(now);
            if now - mtime < STALE_LOCK_AGE {
                return Err(LockError::Held { since: mtime });
            }
            // Stale — identity-check its name and retry exactly once. A
            // changed entry is another owner's lock, not ours to remove.
            let replacement =
                inspect_at(&prepared.dir, OsStr::new(LOCK_FILE)).map_err(|source| {
                    LockError::Io {
                        path: path.clone(),
                        source,
                    }
                })?;
            let Some(replacement) = replacement else {
                return Err(LockError::Held { since: now });
            };
            let replacement_metadata = replacement.metadata().map_err(|source| LockError::Io {
                path: path.clone(),
                source,
            })?;
            if !replacement_metadata.is_file() || !same_inode(&metadata, &replacement_metadata) {
                let since = replacement_metadata
                    .modified()
                    .map(time::OffsetDateTime::from)
                    .unwrap_or(now);
                return Err(LockError::Held { since });
            }
            unlink_at(&prepared.dir, OsStr::new(LOCK_FILE)).map_err(|source| LockError::Io {
                path: path.clone(),
                source,
            })?;
            prepared.dir.sync_all().map_err(|source| LockError::Io {
                path: path.clone(),
                source,
            })?;
            match try_create_lock_at(&prepared.dir, OsStr::new(LOCK_FILE), body.as_bytes()) {
                Ok(lock_file) => {
                    #[cfg(test)]
                    backup_test_event(BackupTestEvent::OutputOwned);
                    Ok(OwnedOutput {
                        prepared,
                        lock_file,
                    })
                }
                Err(e2) if e2.kind() == std::io::ErrorKind::AlreadyExists => {
                    // Lost the race to another process — treat as held.
                    let mtime2 = inspect_at(&prepared.dir, OsStr::new(LOCK_FILE))
                        .ok()
                        .flatten()
                        .and_then(|lock| lock.metadata().ok())
                        .and_then(|metadata| metadata.modified().ok())
                        .map(time::OffsetDateTime::from)
                        .unwrap_or(now);
                    Err(LockError::Held { since: mtime2 })
                }
                Err(e2) => Err(LockError::Io {
                    path: path.clone(),
                    source: e2,
                }),
            }
        }
        Err(e) => Err(LockError::Io {
            path: path.clone(),
            source: e,
        }),
    }
}

fn try_create_lock_at(
    dir: &std::fs::File,
    name: &OsStr,
    body: &[u8],
) -> std::io::Result<std::fs::File> {
    let name = CString::new(name.as_bytes())?;
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o640,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut file = ProvisionalLock::new(dir, unsafe { std::fs::File::from_raw_fd(fd) });
    #[cfg(test)]
    lock_init_test_event(LockInitTestEvent::Created)?;
    #[cfg(test)]
    lock_init_test_event(LockInitTestEvent::BeforeWrite)?;
    file.file_mut().write_all(body)?;
    #[cfg(test)]
    lock_init_test_event(LockInitTestEvent::BeforeFileSync)?;
    file.file_mut().sync_all()?;
    #[cfg(test)]
    lock_init_test_event(LockInitTestEvent::BeforeDirectorySync)?;
    dir.sync_all()?;
    file.into_file()
}

/// Persistent auto-backup state. Lives at `<backup_dir>/.auto_state`.
/// Tracks consecutive failures + last attempt + last outcome +
/// disabled latch.
#[derive(Default, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutoState {
    #[serde(default)]
    pub consecutive_failures: u32,
    #[serde(default, with = "rfc3339_option")]
    pub last_attempt: Option<time::OffsetDateTime>,
    #[serde(default)]
    pub last_outcome: Option<AutoOutcome>,
    #[serde(default)]
    pub disabled: bool,
}

/// Discriminated outcome of the most recent backup attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum AutoOutcome {
    Ok,
    Err { message: String },
}

/// Custom serde adapter for `Option<OffsetDateTime>` in RFC3339 form,
/// without pulling in the `serde-well-known` feature of the `time`
/// crate. Used by [`AutoState::last_attempt`].
mod rfc3339_option {
    use serde::{Deserialize, Deserializer, Serializer};
    use time::format_description::well_known::Rfc3339;
    use time::OffsetDateTime;

    pub fn serialize<S: Serializer>(
        ts: &Option<OffsetDateTime>,
        ser: S,
    ) -> Result<S::Ok, S::Error> {
        match ts {
            Some(t) => {
                let s = t.format(&Rfc3339).map_err(serde::ser::Error::custom)?;
                ser.serialize_some(&s)
            }
            None => ser.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        de: D,
    ) -> Result<Option<OffsetDateTime>, D::Error> {
        let opt: Option<String> = Option::deserialize(de)?;
        match opt {
            None => Ok(None),
            Some(s) => OffsetDateTime::parse(&s, &Rfc3339)
                .map(Some)
                .map_err(serde::de::Error::custom),
        }
    }
}

/// Load `<backup_dir>/.auto_state`. Missing or malformed file ⇒
/// [`AutoState::default`] (a corrupted state file must not block
/// backups indefinitely — the next successful run rewrites it clean).
pub fn load_auto_state(backup_dir: &Path) -> AutoState {
    load_auto_state_from(backup_dir, backup_dir)
}

fn load_auto_state_from(backup_dir: &Path, display_dir: &Path) -> AutoState {
    let path = backup_dir.join(STATE_FILE);
    let raw = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(_) => return AutoState::default(),
    };
    serde_json::from_str(&raw).unwrap_or_else(|e| {
        // stderr, not `tracing`: this runs under a CLI dispatch with no
        // global subscriber, and losing the failure counter silently is
        // how a latched auto-backup un-latches without anyone knowing.
        eprintln!(
            "warning: malformed {} ({e}); resetting to default",
            display_dir.join(STATE_FILE).display()
        );
        AutoState::default()
    })
}

/// Persist `state` to `<backup_dir>/.auto_state` via hardened
/// atomic-write (fsync, mode preservation, rename-atomic).
pub fn save_auto_state(backup_dir: &Path, state: &AutoState) -> anyhow::Result<()> {
    std::fs::create_dir_all(backup_dir)?;
    let path = backup_dir.join(STATE_FILE);
    let body = serde_json::to_vec_pretty(state)?;
    hardened_atomic_write(&path, &body, AtomicWriteOpts::default())
        .map_err(|e| anyhow::anyhow!("save auto_state: {e}"))
}

fn load_auto_state_owned(output: &OwnedOutput) -> AutoState {
    #[cfg(test)]
    backup_test_event(BackupTestEvent::BeforeStateLoad);
    load_auto_state_from(&output.proc_dir(), output.path())
}

fn save_auto_state_owned(output: &OwnedOutput, state: &AutoState) -> anyhow::Result<()> {
    #[cfg(test)]
    backup_test_event(BackupTestEvent::BeforeStateSave);
    let proc_dir = output.proc_dir();
    save_auto_state(&proc_dir, state).map_err(|error| stable_owned_error(error, &proc_dir, output))
}

/// Owner-scoped helpers operate through a procfs descriptor anchor so an
/// output alias cannot redirect scheduler work. Translate that implementation
/// detail at the boundary operators see, retaining the underlying stage and
/// OS cause without exposing `/proc/self/fd/<n>`.
fn stable_owned_error(
    error: anyhow::Error,
    proc_dir: &Path,
    output: &OwnedOutput,
) -> anyhow::Error {
    anyhow::anyhow!(
        "{}",
        format!("{error:#}").replace(
            &proc_dir.display().to_string(),
            &output.path().display().to_string()
        )
    )
}

/// Result of [`prune_archives`].
#[derive(Debug, Default, PartialEq, Eq)]
pub struct PruneReport {
    pub removed: Vec<PathBuf>,
    pub kept: u32,
}

/// Apply retention: drop timestamped archives where
/// `index >= retention_count` OR `now - mtime > retention_days` (OR'd).
/// `None` or `Some(0)` on either field ⇒ that axis is unbounded.
/// Never touches anything outside the `config-<ts>.tar.gz` glob —
/// `.lock`, `.auto_state`, `pre-migration-*.toml`, operator notes all
/// survive.
pub fn prune_archives(
    backup_dir: &Path,
    retention_count: Option<u32>,
    retention_days: Option<u32>,
    now: time::OffsetDateTime,
) -> anyhow::Result<PruneReport> {
    let count_unbounded = matches!(retention_count, None | Some(0));
    let days_unbounded = matches!(retention_days, None | Some(0));
    let entries = list_backups(backup_dir);
    if count_unbounded && days_unbounded {
        return Ok(PruneReport {
            removed: Vec::new(),
            kept: entries.len() as u32,
        });
    }

    let count_limit = retention_count.filter(|n| *n > 0).unwrap_or(u32::MAX);
    let age_limit = retention_days
        .filter(|n| *n > 0)
        .map(|d| time::Duration::days(d as i64));

    let mut removed = Vec::new();
    for (idx, entry) in entries.iter().enumerate() {
        let too_many = idx as u64 >= count_limit as u64;
        let too_old = age_limit
            .map(|limit| (now - entry.timestamp) > limit)
            .unwrap_or(false);
        if too_many || too_old {
            match std::fs::remove_file(&entry.path) {
                Ok(_) => removed.push(entry.path.clone()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => {
                    return Err(anyhow::anyhow!(
                        "failed to remove {}: {}",
                        entry.path.display(),
                        e
                    ))
                }
            }
        }
    }
    let kept = (entries.len() as u32).saturating_sub(removed.len() as u32);
    Ok(PruneReport { removed, kept })
}

fn prune_archives_owned(
    output: &OwnedOutput,
    retention_count: Option<u32>,
    retention_days: Option<u32>,
    now: time::OffsetDateTime,
) -> anyhow::Result<PruneReport> {
    #[cfg(test)]
    backup_test_event(BackupTestEvent::BeforePrune);
    let proc_dir = output.proc_dir();
    let mut report = prune_archives(&proc_dir, retention_count, retention_days, now)
        .map_err(|error| stable_owned_error(error, &proc_dir, output))?;
    for removed in &mut report.removed {
        let relative = removed.strip_prefix(&proc_dir).map_err(|_| {
            anyhow::anyhow!(
                "retention prune reported an entry outside pinned output {}",
                output.path().display()
            )
        })?;
        *removed = output.path().join(relative);
    }
    Ok(report)
}

/// Scheduler-aware backup orchestrator. Used by both `warden config
/// backup` (manual, `auto_mode = false`) and `warden config backup
/// --auto` (timer-driven, `auto_mode = true`).
///
/// Return value is the **process exit code**:
/// - `0` — backup ran successfully, or (auto only) not due / disabled /
///   `auto_interval` not set
/// - `75` — `EX_TEMPFAIL`, another backup is in flight (lock held)
/// - `Err(_)` — backup failed (anyhow propagation ⇒ main exits 1)
///
/// Manual mode invariant: `consecutive_failures` is never incremented
/// and `disabled` is never set. The operator running the verb is a
/// deliberate action, not a scheduling event.
pub fn run_backup_managed(
    config_path: &Path,
    out: Option<&Path>,
    auto_mode: bool,
    now: time::OffsetDateTime,
) -> anyhow::Result<i32> {
    run_backup_managed_to(&mut std::io::stderr(), config_path, out, auto_mode, now)
}

/// [`run_backup_managed`] with its operator notices routed to `notices`.
///
/// The notices go to **stderr, not `tracing`**. No CLI dispatch installs a
/// global subscriber, so a `tracing` event on this path is dropped by the
/// dispatcher and reaches neither stdout, stderr nor journald — which for
/// the disable latch below meant automatic backups stopped forever and
/// nothing said so. Under `purge-warden-backup.service` stderr *is*
/// journald, which is where an operator looks.
///
/// The sink is a parameter so a test can read back exactly what the
/// operator would have seen; a test asserting only the exit code is
/// satisfied by announcing into the void.
pub(crate) fn run_backup_managed_to(
    notices: &mut dyn Write,
    config_path: &Path,
    out: Option<&Path>,
    auto_mode: bool,
    now: time::OffsetDateTime,
) -> anyhow::Result<i32> {
    let guard = write_lock::acquire_for_read(config_path)?;
    let admission = admit_backup_for(
        &guard,
        if auto_mode {
            BackupAdmissionPurpose::AutoArchive
        } else {
            BackupAdmissionPurpose::Archive
        },
        notices,
    )?;
    let requested_out = match out {
        Some(p) => p.to_path_buf(),
        None => admission.config.resolve_dir(guard.canonical_master()),
    };
    let plan = plan_output(guard.tree_io(), &requested_out, &admission.include_roots)?;
    let retention_count = admission.config.retention_count;
    let retention_days = admission.config.retention_days;
    let disable_threshold = admission.config.disable_threshold();
    let mut interval = None;

    // Verified off/invalid settings are config-only decisions: preserve the
    // no-mkdir/no-lock scheduler-off behavior.
    if auto_mode {
        if let Some(error) = &admission.auto_interval_error {
            let _ = writeln!(
                notices,
                "warning: [backup] auto_interval invalid ({error}); treating as off"
            );
            return Ok(0);
        }
        if !admission.config_verified {
            let _ = writeln!(
                notices,
                "warning: backup settings could not be verified; attempting a recovery snapshot"
            );
        } else {
            match admission.config.auto_interval_parsed() {
                Ok(None) => {
                    let _ = writeln!(notices, "[backup] auto_interval not set; auto-backup off");
                    return Ok(0);
                }
                Ok(Some(value)) => interval = Some(value),
                Err(e) => {
                    let _ = writeln!(
                        notices,
                        "warning: [backup] auto_interval invalid ({e}); treating as off"
                    );
                    return Ok(0);
                }
            }
        }
    }

    let prepared = prepare_output(plan, &admission.include_roots)?;
    let output = match acquire_output(prepared, now) {
        Ok(output) => output,
        Err(LockError::Held { since }) => {
            let _ = writeln!(notices, "backup in progress (lock held since {since})");
            return Ok(EX_TEMPFAIL);
        }
        Err(LockError::Io { path, source }) => {
            return Err(anyhow::anyhow!(
                "cannot create lock file at {}: {}",
                path.display(),
                source
            ));
        }
    };
    let mut state = load_auto_state_owned(&output);

    // State-dependent scheduler decisions happen only under the output
    // owner, so a reset or another managed run cannot race their RMW.
    if auto_mode {
        if state.disabled {
            let _ = writeln!(
                notices,
                "auto-backup disabled (after {} consecutive failures); \
                 re-enable via warden config backup --reset-auto-failure",
                state.consecutive_failures
            );
            return Ok(0);
        }
        if let Some(interval) = interval {
            if let Some(last) = state.last_attempt {
                let elapsed = now - last;
                if elapsed < interval {
                    let _ = writeln!(
                        notices,
                        "auto-backup not due (last attempt {}, interval {}h, elapsed {}m)",
                        last,
                        interval.whole_hours(),
                        elapsed.whole_minutes()
                    );
                    return Ok(0);
                }
            }
        }
    }

    let outcome =
        create_backup_in_owned_output_with_tar(guard, &output, &admission, OsStr::new("tar"));

    match outcome {
        Ok(report) => {
            println!("backup written: {}", report.archive.display());
            println!("  {} entry/entries captured:", report.entries.len());
            for e in &report.entries {
                println!("    - {e}");
            }
            apply_success_to_state(&mut state, now);
            if let Err(e) = save_auto_state_owned(&output, &state) {
                let _ = writeln!(notices, "warning: {e}");
            }
            if let Err(e) = prune_archives_owned(&output, retention_count, retention_days, now) {
                let _ = writeln!(notices, "warning: retention prune: {e}");
            }
            Ok(0)
        }
        Err(err) => {
            let just_disabled = apply_failure_to_state(
                &mut state,
                err.to_string(),
                auto_mode,
                disable_threshold,
                now,
            );
            if just_disabled {
                let _ = writeln!(
                    notices,
                    "auto-backup disabled after {} consecutive failures; \
                     re-enable via warden config backup --reset-auto-failure",
                    state.consecutive_failures
                );
            }
            if let Err(e) = save_auto_state_owned(&output, &state) {
                let _ = writeln!(notices, "warning: {e}");
            }
            Err(err)
        }
    }
}

/// Mutate `state` for a successful backup outcome. Resets the failure
/// counter; never touches the `disabled` latch (only an operator
/// reset can clear it).
pub(crate) fn apply_success_to_state(state: &mut AutoState, now: time::OffsetDateTime) {
    state.consecutive_failures = 0;
    state.last_outcome = Some(AutoOutcome::Ok);
    state.last_attempt = Some(now);
}

/// Mutate `state` for a failed backup outcome. Returns `true` iff this
/// failure just tripped the auto-disable threshold (so the caller can
/// log once). Manual mode (`auto_mode = false`) never touches the
/// counter and never sets `disabled` — manual invocation is an
/// operator intent, not a scheduling event.
pub(crate) fn apply_failure_to_state(
    state: &mut AutoState,
    msg: String,
    auto_mode: bool,
    threshold: u32,
    now: time::OffsetDateTime,
) -> bool {
    state.last_outcome = Some(AutoOutcome::Err { message: msg });
    state.last_attempt = Some(now);
    if !auto_mode {
        return false;
    }
    state.consecutive_failures = state.consecutive_failures.saturating_add(1);
    let just_disabled = threshold > 0 && state.consecutive_failures >= threshold && !state.disabled;
    if just_disabled {
        state.disabled = true;
    }
    just_disabled
}

/// `warden config backup --reset-auto-failure` — operator recovery from
/// the auto-disable latch. Clears the failure counter and the
/// `disabled` flag in `<backup_dir>/.auto_state` so the next timer fire
/// runs normally again, persisting through the same hardened
/// [`save_auto_state`] path. Leaves `last_attempt` / `last_outcome`
/// intact as history. **Never creates an archive** — the operator runs
/// this after fixing the failure cause, not to snapshot.
pub fn run_reset_auto_failure(config_path: &Path) -> anyhow::Result<()> {
    run_reset_auto_failure_at(config_path, time::OffsetDateTime::now_utc())
}

fn run_reset_auto_failure_at(config_path: &Path, now: time::OffsetDateTime) -> anyhow::Result<()> {
    let guard = write_lock::acquire_for_read(config_path)?;
    let admission = admit_backup_for(
        &guard,
        BackupAdmissionPurpose::StateOnly,
        &mut std::io::sink(),
    )?;
    let requested_out = admission.config.resolve_dir(guard.canonical_master());
    let prepared = prepare_output(
        plan_output(guard.tree_io(), &requested_out, &admission.include_roots)?,
        &admission.include_roots,
    )?;
    let output = acquire_output(prepared, now)?;
    drop(guard);
    let mut state = load_auto_state_owned(&output);
    #[cfg(test)]
    backup_test_event(BackupTestEvent::ResetStateLoaded);

    // Nothing latched ⇒ idempotent no-op (don't rewrite the file).
    if !state.disabled && state.consecutive_failures == 0 {
        println!("auto-backup already enabled (0 consecutive failures); nothing to reset.");
        return Ok(());
    }

    let prior_failures = state.consecutive_failures;
    let was_disabled = state.disabled;
    state.consecutive_failures = 0;
    state.disabled = false;
    save_auto_state_owned(&output, &state)?;

    if was_disabled {
        println!(
            "auto-backup re-enabled (cleared {prior_failures} consecutive failure(s) \
             + disabled latch)."
        );
    } else {
        println!("auto-backup failure counter cleared (was {prior_failures}).");
    }
    println!("the next scheduled run will attempt a backup normally.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::ffi::OsStringExt;
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};
    use std::sync::{mpsc, Arc, Mutex};
    use std::time::Duration;

    fn make_single_file_config() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(
            &path,
            b"schema_version = 4\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
        )
        .unwrap();
        (dir, path)
    }

    fn archive_listing(archive: &Path) -> String {
        let output = Command::new("tar")
            .arg("-tzf")
            .arg(archive)
            .output()
            .expect("tar listing must run");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap()
    }

    fn assert_no_archive_or_private(output: &Path) {
        if !output.exists() {
            return;
        }
        for entry in std::fs::read_dir(output).unwrap() {
            let name = entry.unwrap().file_name();
            let name = name.to_string_lossy();
            assert!(!name.starts_with("config-"), "unexpected archive {name}");
            assert!(
                !name.starts_with(".warden-backup-"),
                "private residue {name}"
            );
        }
    }

    fn assert_no_private(output: &Path) {
        if !output.exists() {
            return;
        }
        for entry in std::fs::read_dir(output).unwrap() {
            let name = entry.unwrap().file_name();
            assert!(
                !name.to_string_lossy().starts_with(".warden-backup-"),
                "private residue {:?}",
                name
            );
        }
    }

    fn create_backup_with_tar_for_test(
        config: &Path,
        output: &Path,
        tar_program: &OsStr,
    ) -> anyhow::Result<BackupReport> {
        let guard = write_lock::acquire_for_read(config)?;
        let admission = admit_backup(&guard)?;
        let prepared = prepare_output(
            plan_output(guard.tree_io(), output, &admission.include_roots)?,
            &admission.include_roots,
        )?;
        let output = acquire_output(prepared, time::OffsetDateTime::now_utc())?;
        create_backup_in_owned_output_with_tar(guard, &output, &admission, tar_program)
    }

    fn acquire_output_for_test(
        backup_dir: &Path,
        now: time::OffsetDateTime,
    ) -> Result<OwnedOutput, LockError> {
        std::fs::create_dir_all(backup_dir).map_err(|source| LockError::Io {
            path: backup_dir.to_path_buf(),
            source,
        })?;
        let path = backup_dir.canonicalize().map_err(|source| LockError::Io {
            path: backup_dir.to_path_buf(),
            source,
        })?;
        acquire_output(
            PreparedOutput {
                dir: std::fs::File::open(&path).map_err(|source| LockError::Io {
                    path: path.clone(),
                    source,
                })?,
                path,
                excluded_roots: Vec::new(),
            },
            now,
        )
    }

    #[test]
    fn backup_creates_tar_gz_for_single_file_install() {
        let (_dir, path) = make_single_file_config();
        let archive = run_backup(&path, None).unwrap();
        assert!(archive.exists(), "archive file must exist");
        assert!(archive
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("config-"));
        assert!(archive
            .file_name()
            .unwrap()
            .to_string_lossy()
            .ends_with(".tar.gz"));
    }

    #[test]
    fn backup_honours_custom_output_directory() {
        let (_dir, path) = make_single_file_config();
        let out = tempfile::tempdir().unwrap();
        let archive = run_backup(&path, Some(out.path())).unwrap();
        assert!(archive.starts_with(out.path()));
    }

    #[test]
    fn include_roots_canonicalizes_a_symlinked_staging_root() {
        let parent = tempfile::tempdir().unwrap();
        let real = parent.path().join("real");
        std::fs::create_dir(&real).unwrap();
        std::fs::create_dir(real.join("profiles.d")).unwrap();
        let master = real.join("config.toml");
        let include = real.join("profiles.d/default.toml");
        std::fs::write(&master, "schema_version = 4\n").unwrap();
        std::fs::write(&include, "# profile\n").unwrap();
        let alias = parent.path().join("staging-alias");
        std::os::unix::fs::symlink(&real, &alias).unwrap();

        assert_eq!(
            include_roots(&alias, &[master, include]).unwrap(),
            vec!["config.toml", "profiles.d"]
        );
    }

    #[test]
    fn an_admitted_master_alias_is_not_rejected_as_a_source_symlink() {
        let (dir, config) = make_single_file_config();
        let original = std::fs::read_to_string(&config).unwrap();
        let alias = dir.path().join("active.toml");
        std::os::unix::fs::symlink("config.toml", &alias).unwrap();
        let output = tempfile::tempdir().unwrap();

        let archive = create_backup(&alias, Some(output.path())).unwrap().archive;
        let listing = archive_listing(&archive);
        assert!(listing.lines().any(|name| name == "config.toml"));
        assert!(!listing.lines().any(|name| name == "active.toml"));
        std::fs::write(&config, "garbage = true\n").unwrap();
        assert!(matches!(
            crate::cli::commands::config::restore_archive(&config, &archive).unwrap(),
            crate::cli::commands::config::RestoreOutcome::Restored { .. }
        ));
        assert_eq!(std::fs::read_to_string(config).unwrap(), original);
    }

    #[test]
    fn managed_alias_backup_and_discovery_use_the_canonical_master() {
        let workspace = tempfile::tempdir().unwrap();
        let real = workspace.path().join("real");
        let front = workspace.path().join("front");
        std::fs::create_dir(&real).unwrap();
        std::fs::create_dir(&front).unwrap();
        write_config(
            &real,
            "schema_version = 4\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
        );
        let alias = front.join("active.toml");
        std::os::unix::fs::symlink("../real/config.toml", &alias).unwrap();

        assert_eq!(
            run_backup_managed(
                &alias,
                None,
                false,
                time::macros::datetime!(2026-09-06 12:00 UTC),
            )
            .unwrap(),
            0
        );
        let canonical_dir = real.join("backups");
        let archive = list_backups(&canonical_dir).pop().unwrap().path;
        assert!(archive.starts_with(&canonical_dir));
        assert!(!front.join("backups").exists());
        assert_eq!(resolved_backup_dir(&alias), canonical_dir);
        assert_eq!(latest_archive(&alias).unwrap(), archive);
        assert!(restore_list_lines(&alias)
            .unwrap()
            .join("\n")
            .contains("restore point"));
    }

    #[test]
    fn resolved_default_uses_the_canonical_master_when_invalid() {
        let workspace = tempfile::tempdir().unwrap();
        let real = workspace.path().join("real");
        let front = workspace.path().join("front");
        std::fs::create_dir(&real).unwrap();
        std::fs::create_dir(&front).unwrap();
        let canonical = real.join("config.toml");
        std::fs::write(&canonical, "not valid toml = [").unwrap();
        let alias = front.join("active.toml");
        std::os::unix::fs::symlink("../real/config.toml", &alias).unwrap();
        assert_eq!(resolved_backup_dir(&alias), real.join("backups"));
    }

    #[test]
    fn an_external_alias_to_the_output_subtree_is_not_archived() {
        for configured in [false, true] {
            let (dir, config) = make_single_file_config();
            let backups = dir.path().join("backups");
            std::fs::create_dir(&backups).unwrap();
            std::fs::write(backups.join("old-archive"), "must not be captured").unwrap();
            let aliases = tempfile::tempdir().unwrap();
            let alias = aliases.path().join("destination");
            std::os::unix::fs::symlink(&backups, &alias).unwrap();
            if configured {
                std::fs::write(
                    &config,
                    format!(
                        "schema_version = 4\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n\n[backup]\ndir = {:?}\n",
                        alias.to_string_lossy()
                    ),
                )
                .unwrap();
            }

            let archive = create_backup(&config, (!configured).then_some(alias.as_path()))
                .unwrap()
                .archive;
            let listing = archive_listing(&archive);
            assert!(!listing.lines().any(|name| name.starts_with("backups")));
        }
    }

    #[test]
    fn an_output_alias_readded_by_includes_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config.toml");
        let backups = dir.path().join("backups");
        std::fs::create_dir(&backups).unwrap();
        std::fs::write(backups.join("settings.toml"), "# included\n").unwrap();
        std::fs::write(
            &config,
            "schema_version = 4\nincludes = [\"backups/*.toml\"]\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
        )
        .unwrap();
        let aliases = tempfile::tempdir().unwrap();
        let alias = aliases.path().join("destination");
        std::os::unix::fs::symlink(&backups, &alias).unwrap();

        assert!(create_backup(&config, Some(&alias)).is_err());
        assert_eq!(std::fs::read_dir(&backups).unwrap().count(), 1);
    }

    #[test]
    fn backup_captures_sibling_include_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config.toml");
        std::fs::write(
            &config,
            b"schema_version = 4\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
        )
        .unwrap();
        let dev_dir = dir.path().join("devices.d");
        std::fs::create_dir(&dev_dir).unwrap();
        std::fs::write(dev_dir.join("one.toml"), b"# device").unwrap();

        let archive = run_backup(&config, None).unwrap();
        // Inspect the archive contents via `tar -tzf`.
        let out = std::process::Command::new("tar")
            .arg("-tzf")
            .arg(&archive)
            .output()
            .expect("tar listing must run");
        let listing = String::from_utf8_lossy(&out.stdout);
        assert!(listing.contains("config.toml"));
        assert!(listing.contains("devices.d"));
    }

    #[test]
    fn backup_errors_when_config_missing() {
        let dir = tempfile::tempdir().unwrap();
        let ghost = dir.path().join("nonexistent.toml");
        let err = run_backup(&ghost, None);
        assert!(err.is_err());
    }

    #[test]
    fn backup_refuses_a_master_replacement_before_output_effects() {
        let (dir, config) = make_single_file_config();
        let replacement = dir.path().join("replacement.toml");
        std::fs::write(
            &replacement,
            "schema_version = 4\n\n[upstream]\nservers = [\"198.51.100.1:53\"]\n",
        )
        .unwrap();
        let output_parent = tempfile::tempdir().unwrap();
        let output = output_parent.path().join("not-created");
        let live = config.clone();

        let result = write_lock::with_test_hook(
            move |event| {
                if event == write_lock::TestEvent::RootLocked {
                    std::fs::rename(&replacement, &live).unwrap();
                }
            },
            || create_backup(&config, Some(&output)),
        );
        assert!(result.is_err());
        assert!(!output.exists());
    }

    #[test]
    fn backup_uses_the_held_root_after_its_path_is_replaced() {
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("root");
        std::fs::create_dir(&root).unwrap();
        let config = root.join("config.toml");
        std::fs::write(
            &config,
            "schema_version = 4\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
        )
        .unwrap();
        std::fs::write(root.join("generation"), "held").unwrap();
        let old = parent.path().join("old-root");
        let replacement = root.clone();
        let output = tempfile::tempdir().unwrap();

        let archive = write_lock::with_test_hook(
            move |event| {
                if event == write_lock::TestEvent::RootLocked {
                    std::fs::rename(&replacement, &old).unwrap();
                    std::fs::create_dir(&replacement).unwrap();
                    std::fs::write(
                        replacement.join("config.toml"),
                        "schema_version = 4\n\n[upstream]\nservers = [\"198.51.100.1:53\"]\n",
                    )
                    .unwrap();
                    std::fs::write(replacement.join("generation"), "replacement").unwrap();
                }
            },
            || create_backup(&config, Some(output.path())).unwrap().archive,
        );
        let extracted = tempfile::tempdir().unwrap();
        let status = Command::new("tar")
            .arg("-xzf")
            .arg(&archive)
            .arg("-C")
            .arg(extracted.path())
            .status()
            .unwrap();
        assert!(status.success());
        assert_eq!(
            std::fs::read_to_string(extracted.path().join("generation")).unwrap(),
            "held"
        );
    }

    #[test]
    fn a_waiting_writer_cannot_create_a_mixed_backup_generation() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config.toml");
        let include = dir.path().join("slice.toml");
        std::fs::write(
            &config,
            "schema_version = 4\nincludes = [\"slice.toml\"]\n# master-old\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
        )
        .unwrap();
        std::fs::write(&include, "# include-old\n").unwrap();
        let output = tempfile::tempdir().unwrap();
        let (contended_tx, contended_rx) = mpsc::channel();
        let contended_rx = Arc::new(Mutex::new(contended_rx));
        let worker = Arc::new(Mutex::new(None));
        let worker_for_hook = Arc::clone(&worker);
        let receiver_for_hook = Arc::clone(&contended_rx);
        let writer_master = config.clone();
        let writer_include = include.clone();
        let mut started = false;

        let archive = write_lock::with_test_hook(
            move |event| {
                if event != write_lock::TestEvent::RootLocked || started {
                    return;
                }
                started = true;
                let tx = contended_tx.clone();
                let master = writer_master.clone();
                let include = writer_include.clone();
                let handle = std::thread::spawn(move || {
                    write_lock::with_test_hook(
                        move |event| {
                            if event == write_lock::TestEvent::Contended {
                                let _ = tx.send(());
                            }
                        },
                        || {
                            let guard = write_lock::acquire_for_write_with_timeout(
                                &master,
                                Duration::from_secs(10),
                            )
                            .unwrap();
                            std::fs::write(
                                &master,
                                "schema_version = 4\nincludes = [\"slice.toml\"]\n# master-new\n\n[upstream]\nservers = [\"198.51.100.1:53\"]\n",
                            )
                            .unwrap();
                            std::fs::write(&include, "# include-new\n").unwrap();
                            drop(guard);
                        },
                    );
                });
                *worker_for_hook.lock().unwrap() = Some(handle);
                receiver_for_hook
                    .lock()
                    .unwrap()
                    .recv_timeout(Duration::from_secs(10))
                    .expect("writer must block behind the backup reader");
            },
            || create_backup(&config, Some(output.path())).unwrap().archive,
        );
        worker.lock().unwrap().take().unwrap().join().unwrap();

        let extracted = tempfile::tempdir().unwrap();
        assert!(Command::new("tar")
            .arg("-xzf")
            .arg(&archive)
            .arg("-C")
            .arg(extracted.path())
            .status()
            .unwrap()
            .success());
        assert!(
            std::fs::read_to_string(extracted.path().join("config.toml"))
                .unwrap()
                .contains("master-old")
        );
        assert!(std::fs::read_to_string(extracted.path().join("slice.toml"))
            .unwrap()
            .contains("include-old"));
        assert!(std::fs::read_to_string(config)
            .unwrap()
            .contains("master-new"));
        assert!(std::fs::read_to_string(include)
            .unwrap()
            .contains("include-new"));
    }

    #[test]
    fn migration_fences_precede_effects_at_every_backup_entry_point() {
        for shape in 0..3 {
            for output_kind in 0..3 {
                for entry in 0..3 {
                    let (dir, config) = make_single_file_config();
                    let fence = dir.path().join(migration_journal::TXN_DIR_NAME);
                    std::fs::create_dir(&fence).unwrap();
                    std::fs::set_permissions(&fence, std::fs::Permissions::from_mode(0o700))
                        .unwrap();
                    if shape != 0 {
                        let journal = fence.join(migration_journal::JOURNAL_NAME);
                        let bytes = if shape == 1 {
                            b"{\"format_version\":1,\"migration\":\"v3-to-v4\"}".as_slice()
                        } else {
                            b"not-json".as_slice()
                        };
                        std::fs::write(&journal, bytes).unwrap();
                        std::fs::set_permissions(&journal, std::fs::Permissions::from_mode(0o600))
                            .unwrap();
                    }

                    let output_parent = tempfile::tempdir().unwrap();
                    let explicit = output_parent.path().join("output");
                    let output = match output_kind {
                        0 => None,
                        1 => Some(explicit.as_path()),
                        _ => {
                            std::fs::create_dir(&explicit).unwrap();
                            std::fs::write(explicit.join("config-20260101T000000Z.tar.gz"), b"old")
                                .unwrap();
                            std::fs::write(explicit.join(STATE_FILE), b"state-before").unwrap();
                            Some(explicit.as_path())
                        }
                    };
                    let mut before = if output_kind == 2 {
                        std::fs::read_dir(&explicit)
                            .unwrap()
                            .map(|entry| {
                                let entry = entry.unwrap();
                                (entry.file_name(), std::fs::read(entry.path()).unwrap())
                            })
                            .collect::<Vec<_>>()
                    } else {
                        Vec::new()
                    };
                    before.sort_by(|left, right| left.0.cmp(&right.0));
                    let result = match entry {
                        0 => create_backup(&config, output).map(|_| 0),
                        1 => run_backup_managed(
                            &config,
                            output,
                            false,
                            time::macros::datetime!(2026-09-06 12:00 UTC),
                        ),
                        _ => run_backup_managed(
                            &config,
                            output,
                            true,
                            time::macros::datetime!(2026-09-06 12:00 UTC),
                        ),
                    };
                    assert!(
                        result.is_err(),
                        "shape {shape}, output {output_kind}, entry {entry} accepted a fence"
                    );
                    if output_kind == 0 {
                        assert!(
                            !dir.path().join("backups").exists(),
                            "default output was created for shape {shape}, entry {entry}"
                        );
                    } else if output_kind == 1 {
                        assert!(
                            !explicit.exists(),
                            "missing output was created for shape {shape}, entry {entry}"
                        );
                    } else {
                        let mut after = std::fs::read_dir(&explicit)
                            .unwrap()
                            .map(|entry| {
                                let entry = entry.unwrap();
                                (entry.file_name(), std::fs::read(entry.path()).unwrap())
                            })
                            .collect::<Vec<_>>();
                        after.sort_by(|left, right| left.0.cmp(&right.0));
                        assert_eq!(after, before, "existing output changed");
                    }
                }
            }
        }
    }

    #[test]
    fn a_fence_inserted_at_guarded_load_is_not_a_best_effort_diagnostic() {
        let (dir, config) = make_single_file_config();
        let output_parent = tempfile::tempdir().unwrap();
        let output = output_parent.path().join("not-created");
        let root = dir.path().to_path_buf();
        let result = write_lock::with_test_hook(
            move |event| {
                if event == write_lock::TestEvent::RootLocked {
                    std::fs::create_dir(root.join(migration_journal::TXN_DIR_NAME)).unwrap();
                }
            },
            || create_backup(&config, Some(&output)),
        );
        assert!(result.is_err());
        assert!(!output.exists());
    }

    #[test]
    fn invalid_config_still_gets_manual_and_automatic_recovery_snapshots() {
        for auto_mode in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let config = dir.path().join("config.toml");
            std::fs::write(
                &config,
                "schema_version = 4\n\n[server]\ndefault_profile = \"missing\"\n",
            )
            .unwrap();
            let output = tempfile::tempdir().unwrap();
            let mut notices = Vec::new();
            let code = run_backup_managed_to(
                &mut notices,
                &config,
                Some(output.path()),
                auto_mode,
                time::macros::datetime!(2026-09-06 12:00 UTC),
            )
            .unwrap();
            assert_eq!(code, 0);
            assert_eq!(list_backups(output.path()).len(), 1);
            if auto_mode {
                assert!(String::from_utf8(notices)
                    .unwrap()
                    .contains("attempting a recovery snapshot"));
            }
        }
    }

    #[test]
    fn backup_rejects_source_symlink_and_hardlink_members() {
        let (dir, config) = make_single_file_config();
        let linked = dir.path().join("linked.toml");
        std::os::unix::fs::symlink(&config, &linked).unwrap();
        assert!(create_backup(&config, Some(&dir.path().join("outside"))).is_err());
        std::fs::remove_file(linked).unwrap();
        std::fs::hard_link(&config, dir.path().join("hard-linked.toml")).unwrap();
        assert!(create_backup(&config, Some(&dir.path().join("outside-two"))).is_err());
    }

    #[test]
    fn backup_rejects_non_utf8_and_special_source_members() {
        let (dir, config) = make_single_file_config();
        let non_utf8 = std::ffi::OsString::from_vec(vec![b'b', b'a', b'd', 0xff]);
        std::fs::write(dir.path().join(&non_utf8), "bad").unwrap();
        let first_output = tempfile::tempdir().unwrap();
        assert!(create_backup(&config, Some(first_output.path())).is_err());
        assert_no_archive_or_private(first_output.path());
        std::fs::remove_file(dir.path().join(non_utf8)).unwrap();

        let socket = dir.path().join("source.socket");
        let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        let second_output = tempfile::tempdir().unwrap();
        assert!(create_backup(&config, Some(second_output.path())).is_err());
        assert_no_archive_or_private(second_output.path());
        drop(listener);
    }

    #[test]
    fn option_like_and_newline_names_are_tar_data() {
        let (dir, config) = make_single_file_config();
        let names = ["--checkpoint=1", "line\nbreak", "back\\slash"];
        for name in names {
            std::fs::write(dir.path().join(name), format!("contents:{name}")).unwrap();
        }
        let output = tempfile::tempdir().unwrap();
        let archive = create_backup(&config, Some(output.path())).unwrap().archive;
        let extracted = tempfile::tempdir().unwrap();
        let status = Command::new("tar")
            .arg("-xzf")
            .arg(&archive)
            .arg("-C")
            .arg(extracted.path())
            .status()
            .unwrap();
        assert!(status.success());
        for name in names {
            assert_eq!(
                std::fs::read_to_string(extracted.path().join(name)).unwrap(),
                format!("contents:{name}")
            );
        }
    }

    #[test]
    fn tar_input_failure_is_reaped_cleaned_and_releases_the_reader() {
        let (dir, config) = make_single_file_config();
        for index in 0..600 {
            let name = format!("{index:04}-{}", "x".repeat(180));
            std::fs::write(dir.path().join(name), "payload").unwrap();
        }
        let tools = tempfile::tempdir().unwrap();
        let marker = tools.path().join("child-finished");
        let fake_tar = tools.path().join("fake-tar");
        std::fs::write(
            &fake_tar,
            format!(
                "#!/bin/sh\nexec 0<&-\nsleep 0.2\nprintf done > \"{}\"\nexit 23\n",
                marker.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&fake_tar, std::fs::Permissions::from_mode(0o700)).unwrap();
        let output = tempfile::tempdir().unwrap();

        let error = create_backup_with_tar_for_test(&config, output.path(), fake_tar.as_os_str())
            .err()
            .unwrap();
        assert!(format!("{error:#}").contains("cannot feed tar member list"));
        assert_eq!(std::fs::read_to_string(marker).unwrap(), "done");
        assert_no_archive_or_private(output.path());
        assert!(!output.path().join(LOCK_FILE).exists());
        let writer = write_lock::acquire_for_write_with_timeout(&config, Duration::from_secs(10))
            .expect("reader must be released after tar failure");
        drop(writer);
    }

    #[test]
    fn output_under_source_must_be_a_disjoint_direct_child() {
        let (dir, config) = make_single_file_config();
        let direct = dir.path().join("backups");
        let archive = create_backup(&config, Some(&direct)).unwrap().archive;
        assert!(archive.starts_with(&direct));
        assert!(
            !archive_listing(&archive)
                .lines()
                .any(|member| member.starts_with("backups")),
            "the direct-child output must be excluded from inventory"
        );
        let nested = dir.path().join("operator-data").join("backup");
        assert!(create_backup(&config, Some(&nested)).is_err());
        assert!(!nested.exists(), "reject before mkdir");
        let reserved = dir.path().join(".warden-config.lock").join("backup");
        assert!(create_backup(&config, Some(&reserved)).is_err());
        assert!(!reserved.exists(), "reserved target must not be created");
    }

    #[test]
    fn descriptor_output_planning_resolves_dotdot_from_an_explicit_symlinked_cwd() {
        let workspace = tempfile::tempdir().unwrap();
        let config_root = workspace.path().join("config-root");
        std::fs::create_dir(&config_root).unwrap();
        let config = write_config(
            &config_root,
            "schema_version = 4\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
        );
        let descriptor_parent = workspace.path().join("descriptor-parent");
        let working_dir = descriptor_parent.join("working");
        std::fs::create_dir(&descriptor_parent).unwrap();
        std::fs::create_dir(&working_dir).unwrap();
        let lexical_cwd = workspace.path().join("lexical-cwd");
        std::os::unix::fs::symlink(&working_dir, &lexical_cwd).unwrap();
        let guard = write_lock::acquire_for_read(&config).unwrap();
        let admission = admit_backup(&guard).unwrap();

        let output = prepare_output(
            plan_output_from(
                guard.tree_io(),
                Path::new("../archives"),
                &admission.include_roots,
                &lexical_cwd,
            )
            .unwrap(),
            &admission.include_roots,
        )
        .unwrap();
        let resolved = descriptor_parent.join("archives");
        assert_eq!(output.path, resolved);
        assert!(output.path.is_dir());
        assert!(
            !workspace.path().join("archives").exists(),
            "lexical normalization must not choose the symlink's spelling parent"
        );
    }

    #[test]
    fn output_aliases_into_captured_or_reserved_source_paths_are_rejected() {
        for reserved in [false, true] {
            let (dir, config) = make_single_file_config();
            let target = if reserved {
                let target = dir.path().join(".warden-write-test");
                std::fs::create_dir(&target).unwrap();
                target
            } else {
                let target = dir.path().join("captured");
                std::fs::create_dir(&target).unwrap();
                target
            };
            let aliases = tempfile::tempdir().unwrap();
            let alias = aliases.path().join("alias");
            std::os::unix::fs::symlink(&target, &alias).unwrap();
            let requested = alias.join("new-output");

            assert!(create_backup(&config, Some(&requested)).is_err());
            assert!(!target.join("new-output").exists());
        }
    }

    #[test]
    fn retargeting_an_output_alias_cannot_redirect_mkdir_into_the_source() {
        let (dir, config) = make_single_file_config();
        let captured = dir.path().join("captured");
        std::fs::create_dir(&captured).unwrap();
        let aliases = tempfile::tempdir().unwrap();
        let safe = aliases.path().join("safe");
        std::fs::create_dir(&safe).unwrap();
        let alias = aliases.path().join("alias");
        std::os::unix::fs::symlink(&safe, &alias).unwrap();
        let requested = alias.join("new-output");
        let alias_for_hook = alias.clone();
        let captured_for_hook = captured.clone();
        let mut retargeted = false;

        let result = write_lock::with_test_hook(
            move |event| {
                if event == write_lock::TestEvent::BeforeMkdir && !retargeted {
                    std::fs::remove_file(&alias_for_hook).unwrap();
                    std::os::unix::fs::symlink(&captured_for_hook, &alias_for_hook).unwrap();
                    retargeted = true;
                }
            },
            || {
                run_backup_managed(
                    &config,
                    Some(&requested),
                    false,
                    time::macros::datetime!(2026-09-06 12:00 UTC),
                )
            },
        );
        assert!(result.is_err());
        assert!(!captured.join("new-output").exists());
        assert!(!captured.join(LOCK_FILE).exists());
        assert!(!captured.join(STATE_FILE).exists());
        assert!(safe.join("new-output").is_dir());
    }

    #[test]
    fn declared_hidden_root_is_archived_but_restore_residue_is_not() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config.toml");
        std::fs::write(
            &config,
            "schema_version = 4\nincludes = [\".private/*.toml\"]\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
        )
        .unwrap();
        std::fs::create_dir(dir.path().join(".private")).unwrap();
        std::fs::write(
            dir.path().join(".private").join("include.toml"),
            "# hidden\n",
        )
        .unwrap();
        std::fs::write(
            dir.path()
                .join(".private")
                .join(".include.toml.incoming-123-1"),
            "residue",
        )
        .unwrap();
        std::fs::write(
            dir.path().join(".private").join(".policy.incoming-1.toml"),
            "# legitimate include\n",
        )
        .unwrap();
        let archive = run_backup(&config, None).unwrap();
        let listing = archive_listing(&archive);
        assert!(listing.contains(".private/include.toml"));
        assert!(listing.contains(".private/.policy.incoming-1.toml"));
        assert!(!listing.contains(".include.toml.incoming-123-1"));
    }

    #[test]
    fn a_declared_member_with_an_exact_residue_name_is_refused_not_omitted() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config.toml");
        std::fs::write(
            &config,
            "schema_version = 4\nincludes = [\"custom/.policy.incoming-123-1\"]\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
        )
        .unwrap();
        std::fs::create_dir(dir.path().join("custom")).unwrap();
        std::fs::write(
            dir.path().join("custom/.policy.incoming-123-1"),
            "# declared\n",
        )
        .unwrap();
        let output = tempfile::tempdir().unwrap();

        let error = create_backup(&config, Some(output.path())).err().unwrap();
        assert!(format!("{error:#}").contains("excludes required config member"));
        assert_no_archive_or_private(output.path());
    }

    #[test]
    fn restore_residue_uses_the_final_marker_at_every_depth() {
        for name in [
            ".rules.incoming-old.incoming-123-1",
            ".rules.pre-restore-old.pre-restore-123-1",
        ] {
            assert!(is_restore_residue(OsStr::new(name)), "{name}");
        }
        for name in [
            ".rules.incoming-123-one",
            ".rules.incoming-123-1-extra",
            ".rules.incoming-old.incoming-123-one",
        ] {
            assert!(!is_restore_residue(OsStr::new(name)), "{name}");
        }

        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config.toml");
        std::fs::write(
            &config,
            "schema_version = 4\nincludes = [\"nested/*.toml\"]\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
        )
        .unwrap();
        let nested = dir.path().join("nested");
        std::fs::create_dir(&nested).unwrap();
        std::fs::write(
            dir.path().join(".rules.incoming-old.incoming-123-1"),
            "root",
        )
        .unwrap();
        std::fs::write(
            dir.path()
                .join("nested/.rules.pre-restore-old.pre-restore-123-1"),
            "nested",
        )
        .unwrap();
        std::fs::write(nested.join(".rules.incoming-123-one"), "keep").unwrap();
        std::fs::create_dir(nested.join("legitimate")).unwrap();
        std::fs::write(nested.join("legitimate/keep.toml"), "keep").unwrap();
        std::fs::write(nested.join(".warden-config.lock"), "reserved").unwrap();
        for reserved in [
            ".warden-write-stage",
            ".warden-migration",
            ".warden-migration.cleanup-stage",
        ] {
            std::fs::create_dir(nested.join(reserved)).unwrap();
            std::fs::write(nested.join(reserved).join("sentinel"), "reserved").unwrap();
        }
        let output = tempfile::tempdir().unwrap();
        let listing =
            archive_listing(&create_backup(&config, Some(output.path())).unwrap().archive);
        assert!(!listing.contains(".rules.incoming-old.incoming-123-1"));
        assert!(!listing.contains(".rules.pre-restore-old.pre-restore-123-1"));
        assert!(listing.contains("nested/.rules.incoming-123-one"));
        assert!(listing.contains("nested/legitimate/keep.toml"));
        for reserved in [
            "nested/.warden-config.lock",
            "nested/.warden-write-stage",
            "nested/.warden-migration",
            "nested/.warden-migration.cleanup-stage",
        ] {
            assert!(
                !listing
                    .lines()
                    .any(|member| member == reserved || member.starts_with(&format!("{reserved}/"))),
                "reserved archive member leaked: {reserved}"
            );
        }
    }

    #[test]
    fn restore_archive_round_trips_declared_hidden_nested_unusual_names() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config.toml");
        let include = dir.path().join(".hidden/nested/line\nbreak.toml");
        std::fs::create_dir_all(include.parent().unwrap()).unwrap();
        let master_bytes = b"schema_version = 4\nincludes = [\".hidden/nested/*.toml\"]\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n";
        let include_bytes = b"# unusual declared member\n";
        std::fs::write(&config, master_bytes).unwrap();
        std::fs::write(&include, include_bytes).unwrap();
        let output = tempfile::tempdir().unwrap();
        let archive = create_backup(&config, Some(output.path())).unwrap().archive;

        std::fs::write(&config, "corrupted").unwrap();
        std::fs::write(&include, "changed").unwrap();
        assert!(matches!(
            crate::cli::commands::config::restore_archive(&config, &archive).unwrap(),
            crate::cli::commands::config::RestoreOutcome::Restored { .. }
        ));
        assert_eq!(std::fs::read(&config).unwrap(), master_bytes);
        assert_eq!(std::fs::read(&include).unwrap(), include_bytes);
    }

    #[test]
    fn invalid_or_absent_canonical_master_never_creates_output_artifacts() {
        for dangling_alias in [false, true] {
            let workspace = tempfile::tempdir().unwrap();
            let source = workspace.path().join("source");
            let front = workspace.path().join("front");
            std::fs::create_dir(&source).unwrap();
            std::fs::create_dir(&front).unwrap();
            let config = if dangling_alias {
                let alias = front.join("active.toml");
                std::os::unix::fs::symlink("../source/missing.toml", &alias).unwrap();
                alias
            } else {
                source.join("missing.toml")
            };
            let output = workspace.path().join("output/not-created");
            assert!(run_backup_managed(
                &config,
                Some(&output),
                false,
                time::macros::datetime!(2026-09-06 12:00 UTC),
            )
            .is_err());
            assert!(!output.exists());
            assert!(!output.parent().unwrap().exists());
        }
    }

    #[test]
    fn final_symlink_and_hardlink_sentinels_are_not_publishable() {
        let dir = tempfile::tempdir().unwrap();
        let output = std::fs::File::open(dir.path()).unwrap();
        let name = "config-20260528T120000Z.tar.gz";
        let sentinel = dir.path().join("sentinel");
        std::fs::write(&sentinel, b"sentinel").unwrap();
        std::os::unix::fs::symlink(&sentinel, dir.path().join(name)).unwrap();
        let (private_name, mut private) = create_private_archive(&output).unwrap();
        private.write_all(b"archive").unwrap();
        assert!(publish_archive(&output, &private_name, &private, name).is_err());
        remove_private_if_owned(&output, &private_name, &private).unwrap();
        assert_eq!(std::fs::read(&sentinel).unwrap(), b"sentinel");
        std::fs::remove_file(dir.path().join(name)).unwrap();
        std::fs::hard_link(&sentinel, dir.path().join(name)).unwrap();
        let (private_name, mut private) = create_private_archive(&output).unwrap();
        private.write_all(b"archive").unwrap();
        assert!(publish_archive(&output, &private_name, &private, name).is_err());
        remove_private_if_owned(&output, &private_name, &private).unwrap();
        assert_eq!(std::fs::read(&sentinel).unwrap(), b"sentinel");
    }

    #[test]
    fn list_backups_sorts_newest_first_and_ignores_junk() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("config-20260101T000000Z.tar.gz"), b"old").unwrap();
        std::fs::write(
            dir.path().join("config-20260527T120000Z.tar.gz"),
            b"newer!!",
        )
        .unwrap();
        std::fs::write(dir.path().join("config-20260315T093000Z.tar.gz"), b"mid").unwrap();
        // Neither of these is a well-formed archive name → ignored.
        std::fs::write(dir.path().join("not-a-backup.txt"), b"junk").unwrap();
        std::fs::write(dir.path().join("config-bogus.tar.gz"), b"bad ts").unwrap();

        let got = list_backups(dir.path());
        assert_eq!(got.len(), 3, "only config-<ts>.tar.gz names are counted");
        let name = |i: usize| {
            got[i]
                .path
                .file_name()
                .unwrap()
                .to_string_lossy()
                .into_owned()
        };
        assert!(name(0).contains("20260527"), "newest first");
        assert!(name(1).contains("20260315"));
        assert!(name(2).contains("20260101"));
        assert_eq!(got[0].size, 7, "size reflects archive bytes (\"newer!!\")");
    }

    #[test]
    fn list_backups_missing_dir_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        assert!(list_backups(&dir.path().join("nope")).is_empty());
    }

    #[test]
    fn human_bytes_scales_units() {
        assert_eq!(human_bytes(0), "0 B");
        assert_eq!(human_bytes(512), "512 B");
        assert_eq!(human_bytes(1024), "1.0 KiB");
        assert_eq!(human_bytes(1536), "1.5 KiB");
        assert_eq!(human_bytes(1_048_576), "1.0 MiB");
    }

    // ════════════════════════════════════════════════════════════════
    // Scheduler engine tests.
    // ════════════════════════════════════════════════════════════════

    use time::macros::datetime;

    fn t(s: &str) -> time::OffsetDateTime {
        time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339).unwrap()
    }

    const TEST_COMPLETION_TIMEOUT: Duration = Duration::from_secs(60);

    fn spawn_with_completion<T: Send + 'static>(
        task: impl FnOnce() -> T + Send + 'static,
    ) -> (mpsc::Receiver<T>, std::thread::JoinHandle<()>) {
        let (complete_tx, complete_rx) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            let result = task();
            let _ = complete_tx.send(result);
        });
        (complete_rx, worker)
    }

    fn finish_with_timeout<T>(
        complete_rx: mpsc::Receiver<T>,
        worker: std::thread::JoinHandle<()>,
    ) -> T {
        let result = complete_rx
            .recv_timeout(TEST_COMPLETION_TIMEOUT)
            .expect("worker did not complete before the test timeout");
        worker
            .join()
            .expect("worker panicked after reporting completion");
        result
    }

    fn completes_with_timeout<T: Send + 'static>(task: impl FnOnce() -> T + Send + 'static) -> T {
        let (complete_rx, worker) = spawn_with_completion(task);
        finish_with_timeout(complete_rx, worker)
    }

    fn set_lock_mtime(path: &Path, when: time::OffsetDateTime) {
        std::fs::OpenOptions::new()
            .write(true)
            .open(path)
            .unwrap()
            .set_times(std::fs::FileTimes::new().set_modified(when.into()))
            .unwrap();
    }

    // ── Lock tests ──────────────────────────────────────────────────

    #[test]
    fn acquire_output_creates_legacy_lock_with_pid_body() {
        let dir = tempfile::tempdir().unwrap();
        let now = datetime!(2026-05-28 12:00:00 UTC);
        let guard = acquire_output_for_test(dir.path(), now).unwrap();
        let body = std::fs::read_to_string(dir.path().join(LOCK_FILE)).unwrap();
        assert_eq!(
            body,
            format!("{}:2026-05-28T12:00:00Z\n", std::process::id())
        );
        assert_eq!(
            std::fs::metadata(dir.path().join(LOCK_FILE))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o640
        );
        drop(guard);
    }

    #[test]
    fn acquire_output_returns_held_when_recent_lock_present() {
        let dir = tempfile::tempdir().unwrap();
        let now = datetime!(2026-05-28 12:00:00 UTC);
        let lock = dir.path().join(LOCK_FILE);
        std::fs::write(&lock, b"99999:2026-05-28T11:55:01Z\n").unwrap();
        set_lock_mtime(&lock, now - STALE_LOCK_AGE + time::Duration::seconds(1));
        let err = acquire_output_for_test(dir.path(), now).unwrap_err();
        assert!(matches!(err, LockError::Held { .. }));
        assert!(
            lock.exists(),
            "a lock just below five minutes remains fresh"
        );
    }

    #[test]
    fn acquire_output_clears_stale_lock_and_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        let lock_path = dir.path().join(LOCK_FILE);
        std::fs::write(&lock_path, b"99999:2020-01-01T00:00:00Z\n").unwrap();
        let now = time::OffsetDateTime::now_utc();
        set_lock_mtime(&lock_path, now - STALE_LOCK_AGE);
        let guard = acquire_output_for_test(dir.path(), now).unwrap();
        let body = std::fs::read_to_string(&lock_path).unwrap();
        assert_eq!(
            body,
            format!(
                "{}:{}\n",
                std::process::id(),
                now.format(&time::format_description::well_known::Rfc3339)
                    .unwrap()
            )
        );
        drop(guard);
    }

    #[test]
    fn output_owner_drop_removes_lock_file() {
        let dir = tempfile::tempdir().unwrap();
        let now = datetime!(2026-05-28 12:00:00 UTC);
        let lock_path = dir.path().join(LOCK_FILE);
        {
            let _g = acquire_output_for_test(dir.path(), now).unwrap();
            assert!(lock_path.exists());
        }
        assert!(!lock_path.exists(), "Drop must remove the lock file");
    }

    #[test]
    fn displaced_lock_guard_does_not_unlink_its_successor() {
        let dir = tempfile::tempdir().unwrap();
        let now = datetime!(2026-05-28 12:00:00 UTC);
        let first = acquire_output_for_test(dir.path(), now).unwrap();
        unlink_at(first.dir(), OsStr::new(LOCK_FILE)).unwrap();
        let second = acquire_output_for_test(dir.path(), now).unwrap();
        let current = inspect_at(second.dir(), OsStr::new(LOCK_FILE))
            .unwrap()
            .unwrap();
        assert!(same_inode(
            &current.metadata().unwrap(),
            &second.lock_file.metadata().unwrap()
        ));
        drop(first);
        let current = inspect_at(second.dir(), OsStr::new(LOCK_FILE))
            .unwrap()
            .unwrap();
        assert!(same_inode(
            &current.metadata().unwrap(),
            &second.lock_file.metadata().unwrap()
        ));
        drop(second);
        assert!(inspect_at(
            &std::fs::File::open(dir.path()).unwrap(),
            OsStr::new(LOCK_FILE)
        )
        .unwrap()
        .is_none());
    }

    #[test]
    fn nonregular_legacy_locks_are_not_stale_unlinked() {
        for kind in ["directory", "symlink", "fifo"] {
            let dir = tempfile::tempdir().unwrap();
            let lock = dir.path().join(LOCK_FILE);
            match kind {
                "directory" => std::fs::create_dir(&lock).unwrap(),
                "symlink" => {
                    let target = dir.path().join("target");
                    std::fs::write(&target, b"target").unwrap();
                    std::os::unix::fs::symlink(target, &lock).unwrap();
                }
                "fifo" => {
                    let name = CString::new(lock.as_os_str().as_bytes()).unwrap();
                    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o640) }, 0);
                }
                _ => unreachable!(),
            }
            let err = acquire_output_for_test(
                dir.path(),
                time::OffsetDateTime::now_utc() + time::Duration::minutes(10),
            )
            .unwrap_err();
            assert!(matches!(err, LockError::Io { .. }), "{kind}");
            let file_type = std::fs::symlink_metadata(&lock).unwrap().file_type();
            assert!(
                file_type.is_dir() || file_type.is_symlink() || file_type.is_fifo(),
                "{kind} lock was replaced or removed"
            );
        }
    }

    #[test]
    fn failed_lock_initialization_cleans_its_provisional_inode() {
        for stage in [
            LockInitTestEvent::BeforeWrite,
            LockInitTestEvent::BeforeFileSync,
            LockInitTestEvent::BeforeDirectorySync,
        ] {
            let dir = tempfile::tempdir().unwrap();
            let result = with_lock_init_test_hook(
                move |event| {
                    if event == stage {
                        Err(std::io::Error::other(
                            "injected lock initialization failure",
                        ))
                    } else {
                        Ok(())
                    }
                },
                || acquire_output_for_test(dir.path(), datetime!(2026-05-28 12:00:00 UTC)),
            );
            let error = result.unwrap_err();
            assert!(matches!(error, LockError::Io { .. }));
            assert!(
                error
                    .to_string()
                    .contains("injected lock initialization failure"),
                "the initialization error must survive provisional cleanup: {error}"
            );
            assert!(
                !dir.path().join(LOCK_FILE).exists(),
                "{stage:?} left a provisional lock behind"
            );
        }
    }

    #[test]
    fn provisional_lock_never_claims_or_removes_a_successor() {
        let dir = tempfile::tempdir().unwrap();
        let lock = dir.path().join(LOCK_FILE);
        let replacement = lock.clone();
        let result = with_lock_init_test_hook(
            move |event| {
                if event == LockInitTestEvent::Created {
                    std::fs::remove_file(&replacement).unwrap();
                    std::fs::write(&replacement, b"successor\n").unwrap();
                }
                Ok(())
            },
            || acquire_output_for_test(dir.path(), datetime!(2026-05-28 12:00:00 UTC)),
        );
        assert!(matches!(result, Err(LockError::Io { .. })));
        assert_eq!(std::fs::read(&lock).unwrap(), b"successor\n");
    }

    // ── AutoState tests ─────────────────────────────────────────────

    #[test]
    fn load_auto_state_returns_default_when_missing() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(load_auto_state(dir.path()), AutoState::default());
    }

    #[test]
    fn save_then_load_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let state = AutoState {
            consecutive_failures: 2,
            last_attempt: Some(datetime!(2026-05-28 03:00:00 UTC)),
            last_outcome: Some(AutoOutcome::Err {
                message: "tar exited with 1".into(),
            }),
            disabled: false,
        };
        save_auto_state(dir.path(), &state).unwrap();
        let loaded = load_auto_state(dir.path());
        assert_eq!(loaded, state);
    }

    #[test]
    fn load_auto_state_returns_default_on_malformed_json() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(STATE_FILE), b"not valid json {{{").unwrap();
        assert_eq!(load_auto_state(dir.path()), AutoState::default());
    }

    #[test]
    fn save_auto_state_round_trip_works_twice() {
        let dir = tempfile::tempdir().unwrap();
        let s1 = AutoState {
            consecutive_failures: 1,
            ..Default::default()
        };
        save_auto_state(dir.path(), &s1).unwrap();
        let s2 = AutoState {
            consecutive_failures: 7,
            disabled: true,
            ..Default::default()
        };
        save_auto_state(dir.path(), &s2).unwrap();
        assert_eq!(load_auto_state(dir.path()), s2);
    }

    #[test]
    fn owner_scoped_state_and_prune_reports_use_stable_output_paths() {
        let dir = tempfile::tempdir().unwrap();
        let output = dir.path().join("backups");
        let owner = acquire_output_for_test(&output, datetime!(2026-05-28 12:00:00 UTC)).unwrap();

        std::fs::create_dir(output.join(STATE_FILE)).unwrap();
        let save_error = save_auto_state_owned(&owner, &AutoState::default()).unwrap_err();
        let save_text = format!("{save_error:#}");
        assert!(save_text.contains(&output.join(STATE_FILE).display().to_string()));
        assert!(save_text.contains("cannot rename"));
        assert!(!save_text.contains("/proc/self/fd/"));
        std::fs::remove_dir(output.join(STATE_FILE)).unwrap();

        let old = output.join("config-20260101T000000Z.tar.gz");
        let newest = output.join("config-20260102T000000Z.tar.gz");
        std::fs::create_dir(&old).unwrap();
        std::fs::write(&newest, b"newest").unwrap();
        let prune_error =
            prune_archives_owned(&owner, Some(1), None, datetime!(2026-05-28 12:00:00 UTC))
                .unwrap_err();
        let prune_text = format!("{prune_error:#}");
        assert!(prune_text.contains(&old.display().to_string()));
        assert!(prune_text.contains("failed to remove"));
        assert!(!prune_text.contains("/proc/self/fd/"));
        drop(owner);

        let stable = dir.path().join("stable-output");
        let owner = acquire_output_for_test(&stable, datetime!(2026-05-28 12:00:00 UTC)).unwrap();
        let removed = make_archive(&stable, "20260101T000000Z", b"old");
        make_archive(&stable, "20260102T000000Z", b"new");
        let report =
            prune_archives_owned(&owner, Some(1), None, datetime!(2026-05-28 12:00:00 UTC))
                .unwrap();
        assert_eq!(report.removed, vec![removed]);
        assert!(report.removed.iter().all(|path| path.starts_with(&stable)));
    }

    // ── Retention tests ─────────────────────────────────────────────

    fn make_archive(dir: &Path, ts: &str, contents: &[u8]) -> PathBuf {
        let p = dir.join(format!("config-{ts}.tar.gz"));
        std::fs::write(&p, contents).unwrap();
        p
    }

    #[test]
    fn prune_keeps_newest_n() {
        let dir = tempfile::tempdir().unwrap();
        // Days 01..10 (avoid day=00, which TIMESTAMP_FORMAT rejects).
        for d in 1..=10u32 {
            make_archive(dir.path(), &format!("202601{:02}T000000Z", d), b"x");
        }
        let now = t("2026-02-01T00:00:00Z");
        let report = prune_archives(dir.path(), Some(3), None, now).unwrap();
        assert_eq!(report.removed.len(), 7);
        assert_eq!(report.kept, 3);
        let remaining = list_backups(dir.path());
        assert_eq!(remaining.len(), 3);
        let names: Vec<String> = remaining
            .iter()
            .map(|e| e.path.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert!(names.iter().any(|n| n.contains("20260110")));
        assert!(names.iter().any(|n| n.contains("20260109")));
        assert!(names.iter().any(|n| n.contains("20260108")));
    }

    #[test]
    fn prune_drops_older_than_d_days() {
        let dir = tempfile::tempdir().unwrap();
        // Now = 2026-02-01. Days = 7. Threshold = 2026-01-25.
        make_archive(dir.path(), "20260131T000000Z", b"1d");
        make_archive(dir.path(), "20260127T000000Z", b"5d");
        make_archive(dir.path(), "20260122T000000Z", b"10d");
        make_archive(dir.path(), "20260102T000000Z", b"30d");
        let now = t("2026-02-01T00:00:00Z");
        let report = prune_archives(dir.path(), None, Some(7), now).unwrap();
        assert_eq!(report.removed.len(), 2, "10d and 30d archives drop");
        let remaining: Vec<_> = list_backups(dir.path())
            .into_iter()
            .map(|e| e.path.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert!(remaining.iter().any(|n| n.contains("20260131")));
        assert!(remaining.iter().any(|n| n.contains("20260127")));
    }

    #[test]
    fn prune_oring_both_filters_each_axis_independently_triggers() {
        let dir = tempfile::tempdir().unwrap();
        // 5 archives at 1/2/3/4/5 day-old offsets. count=3 keeps the 3
        // newest. days=2 drops anything > 2 days old. OR'd ⇒ keep
        // only those that BOTH survive count AND survive age.
        make_archive(dir.path(), "20260131T000000Z", b"1d");
        make_archive(dir.path(), "20260130T000000Z", b"2d");
        make_archive(dir.path(), "20260129T000000Z", b"3d");
        make_archive(dir.path(), "20260128T000000Z", b"4d");
        make_archive(dir.path(), "20260127T000000Z", b"5d");
        let now = t("2026-02-01T00:00:00Z");
        let report = prune_archives(dir.path(), Some(3), Some(2), now).unwrap();
        // count=3 drops the 2 oldest (28th, 27th). days=2 (> 2 days)
        // also drops the 29th and 28th and 27th. Union: 29th, 28th, 27th
        // removed. Remaining: 31st (1d) and 30th (2d).
        let remaining: Vec<_> = list_backups(dir.path())
            .into_iter()
            .map(|e| e.path.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(remaining.len(), 2, "removed {:?}", report.removed);
        assert!(remaining.iter().any(|n| n.contains("20260131")));
        assert!(remaining.iter().any(|n| n.contains("20260130")));
    }

    #[test]
    fn prune_zero_count_means_unbounded() {
        let dir = tempfile::tempdir().unwrap();
        for d in 1..=5u32 {
            make_archive(dir.path(), &format!("202601{:02}T000000Z", d), b"x");
        }
        let now = t("2026-02-01T00:00:00Z");
        let report = prune_archives(dir.path(), Some(0), None, now).unwrap();
        assert!(report.removed.is_empty());
        assert_eq!(report.kept, 5);
    }

    #[test]
    fn prune_zero_days_means_unbounded() {
        let dir = tempfile::tempdir().unwrap();
        make_archive(dir.path(), "20200101T000000Z", b"ancient");
        let now = t("2026-02-01T00:00:00Z");
        let report = prune_archives(dir.path(), None, Some(0), now).unwrap();
        assert!(report.removed.is_empty());
        assert_eq!(report.kept, 1);
    }

    #[test]
    fn prune_does_not_touch_pre_migration_or_state_or_lock() {
        let dir = tempfile::tempdir().unwrap();
        // One archive (will be dropped by count=0 → no, by count=1
        // and 5 archives we drop 4 — but actually we want to verify
        // that sibling non-archive files survive an aggressive prune).
        make_archive(dir.path(), "20260131T000000Z", b"keeper");
        make_archive(dir.path(), "20260130T000000Z", b"dropper");
        let sibling_state = dir.path().join(STATE_FILE);
        let sibling_lock = dir.path().join(LOCK_FILE);
        let sibling_pre = dir.path().join("config.toml.pre-restore-20260101T000000Z");
        std::fs::write(&sibling_state, b"{}").unwrap();
        std::fs::write(&sibling_lock, b"123:2026-01-01T00:00:00Z").unwrap();
        std::fs::write(&sibling_pre, b"# old master").unwrap();
        let now = t("2026-02-01T00:00:00Z");
        let _ = prune_archives(dir.path(), Some(1), None, now).unwrap();
        assert!(sibling_state.exists(), ".auto_state must survive");
        assert!(sibling_lock.exists(), ".lock must survive");
        assert!(sibling_pre.exists(), "pre-restore-* must survive");
        // And exactly one archive remains.
        assert_eq!(list_backups(dir.path()).len(), 1);
    }

    // ── apply_success_to_state / apply_failure_to_state ─────────────

    #[test]
    fn apply_success_resets_counter_and_records_ok() {
        let mut state = AutoState {
            consecutive_failures: 5,
            disabled: false,
            ..Default::default()
        };
        let now = datetime!(2026-05-28 12:00:00 UTC);
        apply_success_to_state(&mut state, now);
        assert_eq!(state.consecutive_failures, 0);
        assert_eq!(state.last_outcome, Some(AutoOutcome::Ok));
        assert_eq!(state.last_attempt, Some(now));
    }

    #[test]
    fn apply_success_does_not_clear_disabled() {
        let mut state = AutoState {
            consecutive_failures: 3,
            disabled: true,
            ..Default::default()
        };
        let now = datetime!(2026-05-28 12:00:00 UTC);
        apply_success_to_state(&mut state, now);
        assert!(state.disabled, "only the operator reset clears disabled");
    }

    #[test]
    fn apply_failure_auto_increments_counter() {
        let mut state = AutoState::default();
        let now = datetime!(2026-05-28 12:00:00 UTC);
        let triggered = apply_failure_to_state(&mut state, "bang".into(), true, 3, now);
        assert!(!triggered);
        assert_eq!(state.consecutive_failures, 1);
        assert_eq!(
            state.last_outcome,
            Some(AutoOutcome::Err {
                message: "bang".into()
            })
        );
        assert_eq!(state.last_attempt, Some(now));
        assert!(!state.disabled);
    }

    #[test]
    fn apply_failure_auto_disables_at_threshold() {
        let mut state = AutoState {
            consecutive_failures: 2,
            ..Default::default()
        };
        let now = datetime!(2026-05-28 12:00:00 UTC);
        let triggered = apply_failure_to_state(&mut state, "bang".into(), true, 3, now);
        assert!(triggered, "the threshold trip must signal disable");
        assert_eq!(state.consecutive_failures, 3);
        assert!(state.disabled);
    }

    #[test]
    fn apply_failure_auto_threshold_zero_never_disables() {
        // disable_after_failures = 0 ⇒ never disable, even after many.
        let mut state = AutoState {
            consecutive_failures: 99,
            ..Default::default()
        };
        let now = datetime!(2026-05-28 12:00:00 UTC);
        let triggered = apply_failure_to_state(&mut state, "bang".into(), true, 0, now);
        assert!(!triggered);
        assert!(!state.disabled);
        assert_eq!(state.consecutive_failures, 100);
    }

    #[test]
    fn apply_failure_manual_never_increments_counter() {
        let mut state = AutoState {
            consecutive_failures: 2,
            ..Default::default()
        };
        let now = datetime!(2026-05-28 12:00:00 UTC);
        let triggered = apply_failure_to_state(&mut state, "bang".into(), false, 3, now);
        assert!(!triggered);
        assert_eq!(
            state.consecutive_failures, 2,
            "manual mode is invisible to the counter"
        );
        assert!(!state.disabled);
        assert_eq!(
            state.last_attempt,
            Some(now),
            "manual still bumps last_attempt"
        );
        assert_eq!(
            state.last_outcome,
            Some(AutoOutcome::Err {
                message: "bang".into()
            })
        );
    }

    #[test]
    fn apply_failure_does_not_redouble_disable_log() {
        // Already-disabled state: a further auto failure must not
        // return `true` (no log re-fire).
        let mut state = AutoState {
            consecutive_failures: 5,
            disabled: true,
            ..Default::default()
        };
        let now = datetime!(2026-05-28 12:00:00 UTC);
        let triggered = apply_failure_to_state(&mut state, "bang".into(), true, 3, now);
        assert!(!triggered);
        assert_eq!(state.consecutive_failures, 6);
        assert!(state.disabled);
    }

    // ── run_backup_managed end-to-end (happy + skip + lock paths) ───
    //
    // Failure-counter / disable-state transitions are covered by the
    // `apply_failure_to_state` unit tests above — those let the
    // state machine be exercised without contortions to force tar to
    // fail end-to-end. Here we cover what the helper tests can't:
    // - the auto-mode pre-checks (disabled / not-due / auto_interval
    //   absent)
    // - the lock-held EX_TEMPFAIL exit
    // - the success path's state + retention side effects

    fn write_config(dir: &Path, body: &str) -> PathBuf {
        let p = dir.join("config.toml");
        std::fs::write(&p, body).unwrap();
        p
    }

    #[test]
    fn auto_first_run_creates_archive_and_state() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = write_config(
            dir.path(),
            "schema_version = 4\n[backup]\nauto_interval = \"1h\"\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
        );
        let backup_dir = dir.path().join("backups");
        let now = datetime!(2026-05-28 12:00:00 UTC);
        let code = run_backup_managed(&cfg, Some(&backup_dir), true, now).unwrap();
        assert_eq!(code, 0);
        let state = load_auto_state(&backup_dir);
        assert_eq!(state.consecutive_failures, 0);
        assert_eq!(state.last_outcome, Some(AutoOutcome::Ok));
        assert_eq!(state.last_attempt, Some(now));
        assert!(!state.disabled);
        // Archive landed.
        let backups = list_backups(&backup_dir);
        assert_eq!(backups.len(), 1);
    }

    #[test]
    fn auto_not_due_exits_zero_without_running() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = write_config(
            dir.path(),
            "schema_version = 4\n[backup]\nauto_interval = \"24h\"\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
        );
        let backup_dir = dir.path().join("backups");
        std::fs::create_dir_all(&backup_dir).unwrap();
        // Pre-seed: last attempt 1 hour ago; interval is 24h ⇒ not due.
        let last = datetime!(2026-05-28 11:00:00 UTC);
        let now = datetime!(2026-05-28 12:00:00 UTC);
        save_auto_state(
            &backup_dir,
            &AutoState {
                last_attempt: Some(last),
                last_outcome: Some(AutoOutcome::Ok),
                ..Default::default()
            },
        )
        .unwrap();
        let code = run_backup_managed(&cfg, Some(&backup_dir), true, now).unwrap();
        assert_eq!(code, 0);
        // No archive ran — state.last_attempt still the seeded value.
        let state = load_auto_state(&backup_dir);
        assert_eq!(
            state.last_attempt,
            Some(last),
            "state untouched when not due"
        );
        assert!(list_backups(&backup_dir).is_empty());
    }

    #[test]
    fn auto_due_runs_and_resets_counter() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = write_config(
            dir.path(),
            "schema_version = 4\n[backup]\nauto_interval = \"1h\"\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
        );
        let backup_dir = dir.path().join("backups");
        std::fs::create_dir_all(&backup_dir).unwrap();
        let last = datetime!(2026-05-28 10:00:00 UTC);
        let now = datetime!(2026-05-28 12:00:00 UTC); // 2h elapsed, interval 1h
        save_auto_state(
            &backup_dir,
            &AutoState {
                consecutive_failures: 2,
                last_attempt: Some(last),
                last_outcome: Some(AutoOutcome::Err {
                    message: "old".into(),
                }),
                ..Default::default()
            },
        )
        .unwrap();
        let code = run_backup_managed(&cfg, Some(&backup_dir), true, now).unwrap();
        assert_eq!(code, 0);
        let state = load_auto_state(&backup_dir);
        assert_eq!(state.consecutive_failures, 0, "success resets counter");
        assert_eq!(state.last_outcome, Some(AutoOutcome::Ok));
        assert_eq!(state.last_attempt, Some(now));
    }

    #[test]
    fn auto_disabled_exits_zero_without_running() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = write_config(
            dir.path(),
            "schema_version = 4\n[backup]\nauto_interval = \"1h\"\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
        );
        let backup_dir = dir.path().join("backups");
        std::fs::create_dir_all(&backup_dir).unwrap();
        save_auto_state(
            &backup_dir,
            &AutoState {
                disabled: true,
                consecutive_failures: 3,
                ..Default::default()
            },
        )
        .unwrap();
        let now = datetime!(2026-05-28 12:00:00 UTC);
        let code = run_backup_managed(&cfg, Some(&backup_dir), true, now).unwrap();
        assert_eq!(code, 0);
        // No archive.
        assert!(list_backups(&backup_dir).is_empty());
        // State.disabled still true.
        assert!(load_auto_state(&backup_dir).disabled);
    }

    #[test]
    fn auto_interval_absent_exits_zero() {
        let dir = tempfile::tempdir().unwrap();
        // No [backup] section ⇒ auto_interval is None.
        let cfg = write_config(
            dir.path(),
            "schema_version = 4\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
        );
        let backup_dir = dir.path().join("backups");
        let now = datetime!(2026-05-28 12:00:00 UTC);
        let code = run_backup_managed(&cfg, Some(&backup_dir), true, now).unwrap();
        assert_eq!(code, 0);
        assert!(list_backups(&backup_dir).is_empty());
    }

    #[test]
    fn interval_only_validation_error_turns_auto_off_without_output_effects() {
        let dir = tempfile::tempdir().unwrap();
        let config = write_config(
            dir.path(),
            "schema_version = 4\n[backup]\nauto_interval = \"0h\"\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
        );
        let output = dir.path().join("missing-output");
        let mut notices = Vec::new();
        assert_eq!(
            run_backup_managed_to(
                &mut notices,
                &config,
                Some(&output),
                true,
                datetime!(2026-05-28 12:00:00 UTC),
            )
            .unwrap(),
            0
        );
        let notices = String::from_utf8(notices).unwrap();
        assert!(notices.contains("[backup] auto_interval invalid"));
        assert!(!notices.contains("archive captures"));
        assert!(!output.exists(), "an invalid auto interval must not mkdir");
        assert!(
            !output.join(STATE_FILE).exists(),
            "an invalid auto interval must not create scheduler state"
        );

        assert_eq!(
            completes_with_timeout(move || {
                run_backup_managed(
                    &config,
                    Some(&output),
                    false,
                    datetime!(2026-05-28 12:00:00 UTC),
                )
            })
            .unwrap(),
            0
        );
        assert_eq!(
            list_backups(&dir.path().join("missing-output")).len(),
            1,
            "manual invocation must retain the ordinary recovery snapshot"
        );
    }

    #[test]
    fn auto_interval_error_with_another_validation_error_still_recovers() {
        let dir = tempfile::tempdir().unwrap();
        let config = write_config(
            dir.path(),
            "schema_version = 4\n[backup]\nauto_interval = \"0h\"\n\n[server]\ndefault_profile = \"missing\"\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
        );
        let output = dir.path().join("backups");
        let worker_config = config.clone();
        let worker_output = output.clone();
        let notices = completes_with_timeout(move || {
            let mut notices = Vec::new();
            let code = run_backup_managed_to(
                &mut notices,
                &worker_config,
                Some(&worker_output),
                true,
                datetime!(2026-05-28 12:00:00 UTC),
            )
            .unwrap();
            (code, notices)
        });
        assert_eq!(notices.0, 0);
        let notices = String::from_utf8(notices.1).unwrap();
        assert!(notices.contains("archive captures"));
        assert!(notices.contains("attempting a recovery snapshot"));
        assert_eq!(list_backups(&output).len(), 1);
    }

    #[test]
    fn auto_skips_leave_missing_and_existing_outputs_unchanged() {
        for explicit in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let cfg = write_config(
                dir.path(),
                "schema_version = 4\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
            );
            let output = dir.path().join("elsewhere");
            let requested = explicit.then_some(output.as_path());
            assert_eq!(
                run_backup_managed(&cfg, requested, true, datetime!(2026-05-28 12:00:00 UTC))
                    .unwrap(),
                0
            );
            let expected = if explicit {
                output
            } else {
                dir.path().join("backups")
            };
            assert!(!expected.exists(), "an off scheduler must not mkdir");
        }

        for (disabled, last_attempt) in [
            (true, None),
            (false, Some(datetime!(2026-05-28 11:00:00 UTC))),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let cfg = write_config(
                dir.path(),
                "schema_version = 4\n[backup]\nauto_interval = \"24h\"\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
            );
            let output = dir.path().join("backups");
            std::fs::create_dir(&output).unwrap();
            std::fs::write(
                output.join("config-20260101T000000Z.tar.gz"),
                b"archive-before",
            )
            .unwrap();
            save_auto_state(
                &output,
                &AutoState {
                    disabled,
                    consecutive_failures: if disabled { 1 } else { 0 },
                    last_attempt,
                    last_outcome: Some(AutoOutcome::Ok),
                },
            )
            .unwrap();
            let archive_before =
                std::fs::read(output.join("config-20260101T000000Z.tar.gz")).unwrap();
            let state_before = std::fs::read(output.join(STATE_FILE)).unwrap();
            assert_eq!(
                run_backup_managed(
                    &cfg,
                    Some(&output),
                    true,
                    datetime!(2026-05-28 12:00:00 UTC)
                )
                .unwrap(),
                0
            );
            assert_eq!(
                std::fs::read(output.join("config-20260101T000000Z.tar.gz")).unwrap(),
                archive_before
            );
            assert_eq!(
                std::fs::read(output.join(STATE_FILE)).unwrap(),
                state_before
            );
            assert!(!output.join(LOCK_FILE).exists());
        }
    }

    #[test]
    fn manual_runs_regardless_of_disabled() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = write_config(
            dir.path(),
            "schema_version = 4\n[backup]\nauto_interval = \"1h\"\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
        );
        let backup_dir = dir.path().join("backups");
        std::fs::create_dir_all(&backup_dir).unwrap();
        save_auto_state(
            &backup_dir,
            &AutoState {
                disabled: true,
                consecutive_failures: 5,
                ..Default::default()
            },
        )
        .unwrap();
        let now = datetime!(2026-05-28 12:00:00 UTC);
        let code = run_backup_managed(&cfg, Some(&backup_dir), false, now).unwrap();
        assert_eq!(code, 0);
        assert_eq!(list_backups(&backup_dir).len(), 1, "manual runs through");
        let state = load_auto_state(&backup_dir);
        assert!(state.disabled, "manual does NOT clear disabled");
        // Manual success still resets the counter via apply_success_to_state.
        assert_eq!(state.consecutive_failures, 0);
    }

    #[test]
    fn lock_held_returns_75() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = write_config(
            dir.path(),
            "schema_version = 4\n[backup]\nauto_interval = \"1h\"\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
        );
        let backup_dir = dir.path().join("backups");
        std::fs::create_dir_all(&backup_dir).unwrap();
        // Hand-craft a fresh lock file owned by some "other" process.
        std::fs::write(backup_dir.join(LOCK_FILE), b"99999:2026-05-28T11:59:30Z").unwrap();
        let now = datetime!(2026-05-28 12:00:00 UTC);
        // Manual mode also exits 75 — the lock is shared with auto.
        let code = run_backup_managed(&cfg, Some(&backup_dir), false, now).unwrap();
        assert_eq!(code, 75);
        // No state update on lock-held (we never got past output ownership).
        // (Default AutoState since no prior save.)
        assert_eq!(load_auto_state(&backup_dir), AutoState::default());
    }

    #[test]
    fn manual_success_runs_retention_pruning() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = write_config(
            dir.path(),
            "schema_version = 4\n[backup]\nretention_count = 2\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
        );
        let backup_dir = dir.path().join("backups");
        std::fs::create_dir_all(&backup_dir).unwrap();
        // Pre-seed 5 old archives.
        for d in 1..=5u32 {
            make_archive(&backup_dir, &format!("202601{:02}T000000Z", d), b"x");
        }
        let now = datetime!(2026-05-28 12:00:00 UTC);
        let code = run_backup_managed(&cfg, Some(&backup_dir), false, now).unwrap();
        assert_eq!(code, 0);
        // After: the brand-new archive + the single newest of the
        // pre-seeded (retention_count=2). So 2 total.
        let remaining = list_backups(&backup_dir);
        assert_eq!(
            remaining.len(),
            2,
            "retention drops to count=2 after the new one lands"
        );
    }

    #[test]
    fn direct_and_managed_paths_share_the_same_output_owner() {
        let (dir, config) = make_single_file_config();
        let output = dir.path().join("backups");
        let worker_config = config.clone();
        let worker_output = output.clone();
        let (owned_tx, owned_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let (complete_rx, worker) = spawn_with_completion(move || {
            with_backup_test_hook(
                move |event| {
                    if event == BackupTestEvent::OutputOwned {
                        owned_tx.send(()).unwrap();
                        release_rx.recv_timeout(Duration::from_secs(10)).unwrap();
                    }
                },
                || create_backup(&worker_config, Some(&worker_output)),
            )
        });
        owned_rx.recv_timeout(Duration::from_secs(10)).unwrap();
        assert_eq!(
            run_backup_managed(
                &config,
                Some(&output),
                false,
                datetime!(2026-05-28 12:00:00 UTC)
            )
            .unwrap(),
            EX_TEMPFAIL
        );
        assert!(list_backups(&output).is_empty());
        assert!(
            !output.join(STATE_FILE).exists(),
            "a contended managed call must not create scheduler state"
        );
        release_tx.send(()).unwrap();
        let report = finish_with_timeout(complete_rx, worker).unwrap();
        assert!(report.archive.exists());
        assert_eq!(list_backups(&output).len(), 1);
        assert_no_private(&output);
        assert!(!output.join(LOCK_FILE).exists());
    }

    #[test]
    fn each_archive_outer_path_acquires_output_once() {
        let (dir, config) = make_single_file_config();
        for entry in 0..3 {
            let output = dir.path().join(format!("backups-{entry}"));
            let count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let observed = Arc::clone(&count);
            let config = config.clone();
            completes_with_timeout(move || {
                with_backup_test_hook(
                    move |event| {
                        if event == BackupTestEvent::OutputOwned {
                            observed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        }
                    },
                    || match entry {
                        0 => {
                            create_backup(&config, Some(&output)).unwrap();
                        }
                        1 => {
                            run_backup(&config, Some(&output)).unwrap();
                        }
                        _ => {
                            assert_eq!(
                                run_backup_managed(
                                    &config,
                                    Some(&output),
                                    false,
                                    datetime!(2026-05-28 12:00:00 UTC)
                                )
                                .unwrap(),
                                0
                            );
                        }
                    },
                );
            });
            assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 1);
        }
    }

    #[test]
    fn auto_state_is_read_after_output_ownership() {
        let dir = tempfile::tempdir().unwrap();
        let config = write_config(
            dir.path(),
            "schema_version = 4\n[backup]\nauto_interval = \"1h\"\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
        );
        let output = dir.path().join("backups");
        let injected = AutoState {
            disabled: true,
            consecutive_failures: 4,
            last_attempt: Some(datetime!(2026-05-28 11:00:00 UTC)),
            last_outcome: Some(AutoOutcome::Err {
                message: "new state".into(),
            }),
        };
        let output_for_hook = output.clone();
        let injected_for_hook = injected.clone();
        let before_state = Arc::new(Mutex::new(None));
        let before_state_hook = Arc::clone(&before_state);
        with_backup_test_hook(
            move |event| {
                if event == BackupTestEvent::OutputOwned {
                    save_auto_state(&output_for_hook, &injected_for_hook).unwrap();
                } else if event == BackupTestEvent::BeforeStateLoad {
                    *before_state_hook.lock().unwrap() =
                        Some(std::fs::read(output_for_hook.join(STATE_FILE)).unwrap());
                }
            },
            || {
                assert_eq!(
                    run_backup_managed(
                        &config,
                        Some(&output),
                        true,
                        datetime!(2026-05-28 12:00:00 UTC)
                    )
                    .unwrap(),
                    0
                );
            },
        );
        let bytes_before = before_state.lock().unwrap().take().unwrap();
        assert_eq!(
            std::fs::read(output.join(STATE_FILE)).unwrap(),
            bytes_before
        );
        assert_eq!(load_auto_state(&output), injected);
        assert!(list_backups(&output).is_empty());
        assert!(!output.join(LOCK_FILE).exists());
    }

    #[test]
    fn reset_and_backup_update_cannot_race_the_state_rmw() {
        let (dir, config) = make_single_file_config();
        let output = dir.path().join("backups");
        let seeded = AutoState {
            consecutive_failures: 2,
            last_attempt: Some(datetime!(2026-05-28 10:00:00 UTC)),
            last_outcome: Some(AutoOutcome::Err {
                message: "before".into(),
            }),
            disabled: true,
        };
        save_auto_state(&output, &seeded).unwrap();
        let worker_config = config.clone();
        let worker_output = output.clone();
        let (paused_tx, paused_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let (complete_rx, worker) = spawn_with_completion(move || {
            with_backup_test_hook(
                move |event| {
                    if event == BackupTestEvent::SourceGuardDropped {
                        paused_tx.send(()).unwrap();
                        release_rx.recv_timeout(Duration::from_secs(10)).unwrap();
                    }
                },
                || {
                    run_backup_managed(
                        &worker_config,
                        Some(&worker_output),
                        false,
                        datetime!(2026-05-28 12:00:00 UTC),
                    )
                },
            )
        });
        paused_rx.recv_timeout(Duration::from_secs(10)).unwrap();
        let before_reset = std::fs::read(output.join(STATE_FILE)).unwrap();
        let error =
            run_reset_auto_failure_at(&config, datetime!(2026-05-28 12:00:00 UTC)).unwrap_err();
        assert!(error.to_string().contains("backup in progress"));
        assert_eq!(
            std::fs::read(output.join(STATE_FILE)).unwrap(),
            before_reset
        );
        release_tx.send(()).unwrap();
        assert_eq!(finish_with_timeout(complete_rx, worker).unwrap(), 0);
        assert_eq!(load_auto_state(&output).last_outcome, Some(AutoOutcome::Ok));

        let reset_state = AutoState {
            consecutive_failures: 3,
            last_attempt: Some(datetime!(2026-05-28 09:00:00 UTC)),
            last_outcome: Some(AutoOutcome::Err {
                message: "history".into(),
            }),
            disabled: true,
        };
        save_auto_state(&output, &reset_state).unwrap();
        let reset_config = config.clone();
        let (paused_tx, paused_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let (complete_rx, reset) = spawn_with_completion(move || {
            with_backup_test_hook(
                move |event| {
                    if event == BackupTestEvent::ResetStateLoaded {
                        paused_tx.send(()).unwrap();
                        release_rx.recv_timeout(Duration::from_secs(10)).unwrap();
                    }
                },
                || run_reset_auto_failure_at(&reset_config, datetime!(2026-05-28 12:01:00 UTC)),
            )
        });
        paused_rx.recv_timeout(Duration::from_secs(10)).unwrap();
        assert_eq!(
            run_backup_managed(
                &config,
                Some(&output),
                false,
                datetime!(2026-05-28 12:01:00 UTC)
            )
            .unwrap(),
            EX_TEMPFAIL
        );
        release_tx.send(()).unwrap();
        finish_with_timeout(complete_rx, reset).unwrap();
        let after = load_auto_state(&output);
        assert_eq!(after.consecutive_failures, 0);
        assert!(!after.disabled);
        assert_eq!(after.last_attempt, reset_state.last_attempt);
        assert_eq!(after.last_outcome, reset_state.last_outcome);
    }

    #[test]
    fn source_writer_proceeds_while_post_snapshot_work_is_paused() {
        let (dir, config) = make_single_file_config();
        let output = dir.path().join("backups");
        let worker_config = config.clone();
        let worker_output = output.clone();
        let (paused_tx, paused_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let (complete_rx, worker) = spawn_with_completion(move || {
            with_backup_test_hook(
                move |event| {
                    if event == BackupTestEvent::SourceGuardDropped {
                        paused_tx.send(()).unwrap();
                        release_rx.recv_timeout(Duration::from_secs(10)).unwrap();
                    }
                },
                || create_backup(&worker_config, Some(&worker_output)),
            )
        });
        paused_rx.recv_timeout(Duration::from_secs(10)).unwrap();
        let writer = write_lock::acquire_for_write_with_timeout(&config, Duration::from_secs(2))
            .expect("source reader must be gone before publication");
        std::fs::write(
            &config,
            "schema_version = 4\n\n[upstream]\nservers = [\"198.51.100.1:53\"]\n",
        )
        .unwrap();
        drop(writer);
        assert!(matches!(
            acquire_output_for_test(&output, datetime!(2026-05-28 12:00:00 UTC)),
            Err(LockError::Held { .. })
        ));
        release_tx.send(()).unwrap();
        finish_with_timeout(complete_rx, worker).unwrap();
        assert!(!output.join(LOCK_FILE).exists());
    }

    #[test]
    fn output_owner_spans_publish_cleanup_state_and_prune() {
        let dir = tempfile::tempdir().unwrap();
        let config = write_config(
            dir.path(),
            "schema_version = 4\n[backup]\nretention_count = 2\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
        );
        let output = dir.path().join("backups");
        std::fs::create_dir_all(&output).unwrap();
        let deleted = make_archive(&output, "20260101T000000Z", b"oldest");
        make_archive(&output, "20260102T000000Z", b"newer");
        let output_for_hook = output.clone();
        let worker_output = output.clone();
        let worker_config = config.clone();
        let observed = Arc::new(Mutex::new(Vec::new()));
        let observed_hook = Arc::clone(&observed);
        completes_with_timeout(move || {
            with_backup_test_hook(
                move |event| {
                    if matches!(
                        event,
                        BackupTestEvent::BeforePublish
                            | BackupTestEvent::BeforeStateSave
                            | BackupTestEvent::BeforePrune
                    ) {
                        assert!(matches!(
                            acquire_output_for_test(
                                &output_for_hook,
                                datetime!(2026-05-28 12:00:00 UTC)
                            ),
                            Err(LockError::Held { .. })
                        ));
                        observed_hook.lock().unwrap().push(event);
                    }
                },
                || {
                    assert_eq!(
                        run_backup_managed(
                            &worker_config,
                            Some(&worker_output),
                            false,
                            datetime!(2026-05-28 12:00:00 UTC)
                        )
                        .unwrap(),
                        0
                    );
                },
            );
        });
        assert_eq!(
            *observed.lock().unwrap(),
            vec![
                BackupTestEvent::BeforePublish,
                BackupTestEvent::BeforeStateSave,
                BackupTestEvent::BeforePrune
            ]
        );
        assert!(!output.join(LOCK_FILE).exists());
        assert_no_private(&output);
        assert!(
            !deleted.exists(),
            "retention must delete a real old archive"
        );

        let cleanup_output = dir.path().join("cleanup-output");
        let cleanup_seen = Arc::new(Mutex::new(false));
        let cleanup_seen_hook = Arc::clone(&cleanup_seen);
        let output_for_hook = cleanup_output.clone();
        let worker_cleanup_output = cleanup_output.clone();
        let config = dir.path().join("config.toml");
        completes_with_timeout(move || {
            with_backup_test_hook(
                move |event| {
                    if event == BackupTestEvent::BeforePrivateCleanup {
                        assert!(matches!(
                            acquire_output_for_test(
                                &output_for_hook,
                                datetime!(2026-05-28 12:00:00 UTC)
                            ),
                            Err(LockError::Held { .. })
                        ));
                        *cleanup_seen_hook.lock().unwrap() = true;
                    }
                },
                || {
                    assert!(create_backup_with_tar_for_test(
                        &config,
                        &worker_cleanup_output,
                        OsStr::new("missing-tar-program")
                    )
                    .is_err());
                },
            );
        });
        assert!(*cleanup_seen.lock().unwrap());
        assert!(!cleanup_output.join(LOCK_FILE).exists());
        assert_no_archive_or_private(&cleanup_output);
    }

    // ── run_reset_auto_failure (operator recovery) ──────────────

    #[test]
    fn reset_auto_failure_clears_counter_and_disabled() {
        let (_dir, config) = make_single_file_config();
        let backup_dir = config.parent().unwrap().join("backups");
        // Seed a tripped/disabled state at the resolved backup dir.
        let seeded = AutoState {
            consecutive_failures: 3,
            last_attempt: Some(time::macros::datetime!(2026-05-28 03:00:00 UTC)),
            last_outcome: Some(AutoOutcome::Err {
                message: "tar exited with 1".into(),
            }),
            disabled: true,
        };
        save_auto_state(&backup_dir, &seeded).unwrap();

        run_reset_auto_failure(&config).unwrap();

        let after = load_auto_state(&backup_dir);
        assert_eq!(after.consecutive_failures, 0, "counter must reset to 0");
        assert!(!after.disabled, "disabled latch must clear");
        assert!(
            list_backups(&backup_dir).is_empty(),
            "reset must NOT create an archive"
        );
    }

    #[test]
    fn reset_auto_failure_idempotent_when_clean() {
        let (_dir, config) = make_single_file_config();
        // No .auto_state seeded — load yields a clean default.
        run_reset_auto_failure(&config).unwrap();

        let backup_dir = config.parent().unwrap().join("backups");
        assert!(
            list_backups(&backup_dir).is_empty(),
            "reset on a clean state must NOT create an archive"
        );
        let after = load_auto_state(&backup_dir);
        assert_eq!(after.consecutive_failures, 0);
        assert!(!after.disabled);
    }

    #[test]
    fn reset_fence_never_falls_back_to_default_output() {
        for shape in 0..3 {
            let dir = tempfile::tempdir().unwrap();
            let configured = dir.path().join("configured");
            let default = dir.path().join("backups");
            let config = write_config(
                dir.path(),
                &format!(
                    "schema_version = 4\n[backup]\ndir = {:?}\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
                    configured
                ),
            );
            let seeded = AutoState {
                consecutive_failures: 3,
                last_attempt: Some(datetime!(2026-05-28 11:00:00 UTC)),
                last_outcome: Some(AutoOutcome::Err {
                    message: "seeded".into(),
                }),
                disabled: true,
            };
            save_auto_state(&configured, &seeded).unwrap();
            save_auto_state(&default, &seeded).unwrap();
            let configured_before = std::fs::read(configured.join(STATE_FILE)).unwrap();
            let default_before = std::fs::read(default.join(STATE_FILE)).unwrap();
            let fence = dir.path().join(migration_journal::TXN_DIR_NAME);
            std::fs::create_dir(&fence).unwrap();
            if shape > 0 {
                std::fs::write(
                    fence.join(migration_journal::JOURNAL_NAME),
                    if shape == 1 {
                        b"{\"format_version\":1,\"migration\":\"v3-to-v4\"}".as_slice()
                    } else {
                        b"not-json".as_slice()
                    },
                )
                .unwrap();
            }
            assert!(
                run_reset_auto_failure_at(&config, datetime!(2026-05-28 12:00:00 UTC)).is_err()
            );
            assert_eq!(
                std::fs::read(configured.join(STATE_FILE)).unwrap(),
                configured_before
            );
            assert_eq!(
                std::fs::read(default.join(STATE_FILE)).unwrap(),
                default_before
            );
            assert!(!configured.join(LOCK_FILE).exists());
            assert!(!default.join(LOCK_FILE).exists());
        }

        let dir = tempfile::tempdir().unwrap();
        let configured = dir.path().join("configured");
        let config = write_config(
            dir.path(),
            &format!(
                "schema_version = 4\n[backup]\ndir = {:?}\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
                configured
            ),
        );
        let seeded = AutoState {
            consecutive_failures: 1,
            disabled: true,
            ..Default::default()
        };
        save_auto_state(&configured, &seeded).unwrap();
        let before = std::fs::read(configured.join(STATE_FILE)).unwrap();
        let root = dir.path().to_path_buf();
        let result = write_lock::with_test_hook(
            move |event| {
                if event == write_lock::TestEvent::RootLocked {
                    std::fs::create_dir(root.join(migration_journal::TXN_DIR_NAME)).unwrap();
                }
            },
            || run_reset_auto_failure_at(&config, datetime!(2026-05-28 12:00:00 UTC)),
        );
        assert!(result.is_err());
        assert_eq!(std::fs::read(configured.join(STATE_FILE)).unwrap(), before);
        assert!(!configured.join(LOCK_FILE).exists());
    }

    #[test]
    fn reset_rechecks_the_fence_after_a_guarded_validation_failure() {
        let dir = tempfile::tempdir().unwrap();
        let configured = dir.path().join("configured");
        let default = dir.path().join("backups");
        let config = write_config(
            dir.path(),
            &format!(
                "schema_version = 4\n[backup]\ndir = {:?}\nauto_interval = \"0h\"\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
                configured
            ),
        );
        let configured_state = AutoState {
            consecutive_failures: 4,
            disabled: true,
            ..Default::default()
        };
        let default_state = AutoState {
            consecutive_failures: 1,
            disabled: true,
            ..Default::default()
        };
        save_auto_state(&configured, &configured_state).unwrap();
        save_auto_state(&default, &default_state).unwrap();
        let configured_before = std::fs::read(configured.join(STATE_FILE)).unwrap();
        let default_before = std::fs::read(default.join(STATE_FILE)).unwrap();
        let root = dir.path().to_path_buf();
        let result = with_backup_test_hook(
            move |event| {
                if event == BackupTestEvent::AfterGuardedLoadFailure {
                    std::fs::create_dir(root.join(migration_journal::TXN_DIR_NAME)).unwrap();
                }
            },
            || run_reset_auto_failure_at(&config, datetime!(2026-05-28 12:00:00 UTC)),
        );
        assert!(result.is_err());
        assert_eq!(
            std::fs::read(configured.join(STATE_FILE)).unwrap(),
            configured_before
        );
        assert_eq!(
            std::fs::read(default.join(STATE_FILE)).unwrap(),
            default_before
        );
        assert!(!configured.join(LOCK_FILE).exists());
        assert!(!default.join(LOCK_FILE).exists());
        assert!(list_backups(&configured).is_empty());
        assert!(list_backups(&default).is_empty());
    }

    #[test]
    fn reset_uses_canonical_master_and_guarded_best_effort_rules() {
        let workspace = tempfile::tempdir().unwrap();
        let real = workspace.path().join("real");
        let front = workspace.path().join("front");
        std::fs::create_dir(&real).unwrap();
        std::fs::create_dir(&front).unwrap();
        let configured = workspace.path().join("configured");
        let canonical = write_config(
            &real,
            &format!(
                "schema_version = 4\n[backup]\ndir = {:?}\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
                configured
            ),
        );
        let alias = front.join("active.toml");
        std::os::unix::fs::symlink(&canonical, &alias).unwrap();
        let history = AutoState {
            consecutive_failures: 2,
            last_attempt: Some(datetime!(2026-05-28 10:00:00 UTC)),
            last_outcome: Some(AutoOutcome::Err {
                message: "history".into(),
            }),
            disabled: true,
        };
        save_auto_state(&configured, &history).unwrap();
        run_reset_auto_failure_at(&alias, datetime!(2026-05-28 12:00:00 UTC)).unwrap();
        let reset = load_auto_state(&configured);
        assert_eq!(reset.last_attempt, history.last_attempt);
        assert_eq!(reset.last_outcome, history.last_outcome);
        assert_eq!(reset.consecutive_failures, 0);
        assert!(!reset.disabled);
        assert!(!front.join("backups").exists());
        assert!(list_backups(&configured).is_empty());

        let invalid_real = workspace.path().join("invalid-real");
        let invalid_front = workspace.path().join("invalid-front");
        std::fs::create_dir(&invalid_real).unwrap();
        std::fs::create_dir(&invalid_front).unwrap();
        let invalid_canonical = invalid_real.join("config.toml");
        std::fs::write(&invalid_canonical, "not valid toml = [").unwrap();
        let invalid_alias = invalid_front.join("active.toml");
        std::os::unix::fs::symlink(&invalid_canonical, &invalid_alias).unwrap();
        let fallback = invalid_real.join("backups");
        save_auto_state(&fallback, &history).unwrap();
        run_reset_auto_failure_at(&invalid_alias, datetime!(2026-05-28 12:00:00 UTC)).unwrap();
        let reset = load_auto_state(&fallback);
        assert_eq!(reset.last_attempt, history.last_attempt);
        assert_eq!(reset.last_outcome, history.last_outcome);
        assert_eq!(reset.consecutive_failures, 0);
        assert!(!reset.disabled);
        assert!(list_backups(&fallback).is_empty());
        assert!(
            !invalid_front.join("backups").exists(),
            "fallback must be beside the canonical master, not its alias"
        );
    }

    // ── latest_archive (restore --latest ergonomic) ────────────────

    #[test]
    fn latest_archive_picks_newest() {
        let (_dir, config) = make_single_file_config();
        let backup_dir = config.parent().unwrap().join("backups");
        std::fs::create_dir_all(&backup_dir).unwrap();
        std::fs::write(backup_dir.join("config-20260101T000000Z.tar.gz"), b"old").unwrap();
        std::fs::write(backup_dir.join("config-20260527T120000Z.tar.gz"), b"new").unwrap();

        let picked = latest_archive(&config).unwrap();
        assert_eq!(
            picked.file_name().unwrap().to_string_lossy(),
            "config-20260527T120000Z.tar.gz",
            "must resolve the newest archive"
        );
    }

    #[test]
    fn latest_archive_errors_on_empty_dir() {
        let (_dir, config) = make_single_file_config();
        let err = latest_archive(&config);
        assert!(err.is_err(), "empty backup dir must error, not panic");
        assert!(
            err.unwrap_err().to_string().contains("nothing to restore"),
            "error must guide the operator toward the empty-dir cause"
        );
    }

    // ── operator notices reach a channel the operator reads ─────────
    //
    // These went through `tracing` and no CLI dispatch installs a global
    // subscriber, so every one of them was dropped by the dispatcher.
    // Each test below reads the sink back: against the old code every
    // buffer is EMPTY, which is the whole defect.

    /// The consequential one. Once the latch trips, automatic backups
    /// stop until an operator runs `--reset-auto-failure` — and the only
    /// line saying so was invisible.
    ///
    /// `disable_after_failures = 1` makes one failure latch. The failure
    /// itself is a config-directory entry whose name is not valid UTF-8:
    /// `sweep_config_dir` refuses it, so `create_backup` fails without
    /// needing a broken `tar`, a permission trick, or root.
    #[test]
    fn the_auto_disable_latch_is_announced_where_an_operator_can_see_it() {
        use std::os::unix::ffi::OsStrExt;

        let dir = tempfile::tempdir().unwrap();
        let cfg_dir = dir.path().join("cfg");
        std::fs::create_dir_all(&cfg_dir).unwrap();
        let cfg = write_config(
            &cfg_dir,
            "schema_version = 4\n[backup]\nauto_interval = \"1h\"\n\
             disable_after_failures = 1\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
        );
        std::fs::write(
            cfg_dir.join(std::ffi::OsStr::from_bytes(b"\xff\xfe.toml")),
            b"",
        )
        .unwrap();
        let backup_dir = dir.path().join("backups");
        let now = datetime!(2026-05-28 12:00:00 UTC);

        let mut notices: Vec<u8> = Vec::new();
        let outcome = run_backup_managed_to(&mut notices, &cfg, Some(&backup_dir), true, now);
        assert!(outcome.is_err(), "the backup must have failed");

        let seen = String::from_utf8(notices).unwrap();
        assert!(
            seen.contains("auto-backup disabled after 1 consecutive failures"),
            "the latch must be announced, not logged into the void: {seen:?}"
        );
        assert!(
            seen.contains("--reset-auto-failure"),
            "the notice must name the way out: {seen:?}"
        );
        assert!(load_auto_state(&backup_dir).disabled, "latch must be set");
    }

    /// Every later timer fire hits this early return, so without it
    /// `systemctl start purge-warden-backup` exits 0 saying nothing at
    /// all about backups having stopped.
    #[test]
    fn a_latched_auto_run_says_why_it_did_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = write_config(
            dir.path(),
            "schema_version = 4\n[backup]\nauto_interval = \"1h\"\n\n\
             [upstream]\nservers = [\"192.0.2.1:53\"]\n",
        );
        let backup_dir = dir.path().join("backups");
        std::fs::create_dir_all(&backup_dir).unwrap();
        save_auto_state(
            &backup_dir,
            &AutoState {
                disabled: true,
                consecutive_failures: 3,
                ..Default::default()
            },
        )
        .unwrap();
        let now = datetime!(2026-05-28 12:00:00 UTC);

        let mut notices: Vec<u8> = Vec::new();
        let code = run_backup_managed_to(&mut notices, &cfg, Some(&backup_dir), true, now).unwrap();
        assert_eq!(code, 0);

        let seen = String::from_utf8(notices).unwrap();
        assert!(
            seen.contains("auto-backup disabled") && seen.contains("--reset-auto-failure"),
            "a skipped-because-latched run must say so: {seen:?}"
        );
        assert!(list_backups(&backup_dir).is_empty());
    }

    /// Negative control for the two above: a run that actually backs up
    /// must NOT print a disabled notice. Without this, a sink that always
    /// carried the latch text would satisfy both.
    #[test]
    fn a_healthy_auto_run_announces_nothing_about_being_disabled() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = write_config(
            dir.path(),
            "schema_version = 4\n[backup]\nauto_interval = \"1h\"\n\n\
             [upstream]\nservers = [\"192.0.2.1:53\"]\n",
        );
        let backup_dir = dir.path().join("backups");
        let now = datetime!(2026-05-28 12:00:00 UTC);

        let mut notices: Vec<u8> = Vec::new();
        let code = run_backup_managed_to(&mut notices, &cfg, Some(&backup_dir), true, now).unwrap();
        assert_eq!(code, 0);
        let seen = String::from_utf8(notices).unwrap();
        assert!(
            !seen.contains("disabled"),
            "a successful backup must not claim to be disabled: {seen:?}"
        );
        assert_eq!(list_backups(&backup_dir).len(), 1);
    }

    /// The timer fires hourly against a 24h interval, so this is the
    /// ordinary case — and it too returned 0 in complete silence.
    #[test]
    fn a_not_due_auto_run_says_it_is_not_due() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = write_config(
            dir.path(),
            "schema_version = 4\n[backup]\nauto_interval = \"24h\"\n\n\
             [upstream]\nservers = [\"192.0.2.1:53\"]\n",
        );
        let backup_dir = dir.path().join("backups");
        std::fs::create_dir_all(&backup_dir).unwrap();
        save_auto_state(
            &backup_dir,
            &AutoState {
                last_attempt: Some(datetime!(2026-05-28 11:00:00 UTC)),
                last_outcome: Some(AutoOutcome::Ok),
                ..Default::default()
            },
        )
        .unwrap();

        let mut notices: Vec<u8> = Vec::new();
        let code = run_backup_managed_to(
            &mut notices,
            &cfg,
            Some(&backup_dir),
            true,
            datetime!(2026-05-28 12:00:00 UTC),
        )
        .unwrap();
        assert_eq!(code, 0);
        assert!(
            String::from_utf8(notices).unwrap().contains("not due"),
            "a skipped run must say why"
        );
    }

    /// `auto_interval` absent means the timer is installed but does
    /// nothing — worth one line, since the unit still exits 0.
    #[test]
    fn an_auto_run_with_no_interval_says_auto_backup_is_off() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = write_config(
            dir.path(),
            "schema_version = 4\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
        );
        let backup_dir = dir.path().join("backups");

        let mut notices: Vec<u8> = Vec::new();
        let code = run_backup_managed_to(
            &mut notices,
            &cfg,
            Some(&backup_dir),
            true,
            datetime!(2026-05-28 12:00:00 UTC),
        )
        .unwrap();
        assert_eq!(code, 0);
        assert!(
            String::from_utf8(notices)
                .unwrap()
                .contains("auto-backup off"),
            "an unconfigured auto-backup must say so"
        );
    }

    // ── the archive is never world- or group-readable, not even briefly ──

    /// The private archive is born at 0600 before tar receives its fd.
    #[test]
    fn a_fresh_archive_path_is_created_at_0600() {
        let dir = tempfile::tempdir().unwrap();
        let output = std::fs::File::open(dir.path()).unwrap();
        let (name, archive) = create_private_archive(&output).unwrap();

        let mode = archive.metadata().unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "archive must not be readable by group or other"
        );
        remove_private_if_owned(&output, &name, &archive).unwrap();
    }

    /// A same-second name is never replaced, regardless of its mode.
    #[test]
    fn an_existing_archive_target_is_not_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("config-20260528T120000Z.tar.gz");
        std::fs::write(&archive, b"stale").unwrap();
        std::fs::set_permissions(&archive, std::fs::Permissions::from_mode(0o644)).unwrap();
        let output = std::fs::File::open(dir.path()).unwrap();
        assert!(require_final_absent(&output, "config-20260528T120000Z.tar.gz").is_err());
        assert_eq!(std::fs::read(&archive).unwrap(), b"stale");
        assert_eq!(
            std::fs::metadata(&archive).unwrap().permissions().mode() & 0o777,
            0o644
        );
    }

    /// End to end: the archive an operator actually gets is 0600, whatever
    /// umask they ran the verb under.
    #[test]
    fn a_backup_run_leaves_the_archive_at_0600() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = write_config(
            dir.path(),
            "schema_version = 4\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
        );
        let backup_dir = dir.path().join("backups");

        let report = create_backup(&cfg, Some(&backup_dir)).unwrap();

        let mode = std::fs::metadata(&report.archive)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }

    // ── pre-migration rollback copies + unreadable-vs-absent ──────

    /// Root ignores file permission bits, so the two tests that make a
    /// path unreadable can only observe anything as an ordinary user.
    fn skip_as_root(test: &str) -> bool {
        // SAFETY: geteuid takes no arguments and cannot fail.
        if unsafe { libc::geteuid() } == 0 {
            eprintln!("SKIPPED {test}: root ignores the permission bits it turns on");
            return true;
        }
        false
    }

    #[test]
    fn migration_copies_are_scanned_but_never_listed_as_restore_points() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("config-20260101T000000Z.tar.gz"), b"old").unwrap();
        // Newer than the archive, which is the case that matters: right
        // after an upgrade the rollback copy is the newest thing here.
        std::fs::write(
            dir.path().join("pre-migration-2026-08-26T10-30-00Z.toml"),
            b"schema_version = 2\n",
        )
        .unwrap();

        let scan = scan_backup_dir(dir.path());
        assert_eq!(scan.migration.len(), 1, "the rollback copy is found");
        assert_eq!(
            scan.archives.len(),
            1,
            "and it is NOT an archive: `latest_archive` unpacks this list and \
             `prune_archives` deletes from it"
        );
        assert!(list_backups(dir.path())
            .iter()
            .all(|e| e.path.extension().unwrap() == "gz"));
    }

    #[test]
    fn the_same_second_collision_suffix_is_still_a_rollback_copy() {
        assert!(is_migration_backup(
            "pre-migration-2026-08-26T10-30-00Z.toml"
        ));
        assert!(is_migration_backup(
            "pre-migration-2026-08-26T10-30-00Z.toml-1"
        ));
        assert!(is_migration_backup(
            "pre-migration-2026-08-26T10-30-00.123456789Z.toml"
        ));
        assert!(!is_migration_backup("pre-migration-notes.txt"));
        assert!(!is_migration_backup("config-20260101T000000Z.tar.gz"));
        assert!(!is_migration_backup("pre-migration-.toml-x"));
    }

    #[test]
    fn restore_list_surfaces_the_pre_migration_copy() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("pre-migration-2026-08-26T10-30-00Z.toml"),
            b"schema_version = 2\n",
        )
        .unwrap();

        let lines = restore_points_lines(dir.path()).unwrap();
        let joined = lines.join("\n");
        assert!(
            !joined.contains("no backups in"),
            "a directory holding a rollback copy is not empty:\n{joined}"
        );
        assert!(
            joined.contains("pre-migration-2026-08-26T10-30-00Z.toml"),
            "the rollback copy must be named in the listing:\n{joined}"
        );
        assert!(
            joined.contains("copying it over"),
            "and the operator must be told it is not a `restore` input:\n{joined}"
        );
    }

    #[test]
    fn restore_list_says_no_backups_only_when_there_is_nothing() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            restore_points_lines(dir.path()).unwrap(),
            vec![format!("no backups in {}", dir.path().display())]
        );
        // A directory that is not there is still "no backups yet", not an
        // error — a fresh install has never made one.
        let absent = dir.path().join("nope");
        assert_eq!(
            restore_points_lines(&absent).unwrap(),
            vec![format!("no backups in {}", absent.display())]
        );
    }

    #[test]
    fn an_unreadable_backup_dir_is_an_error_not_an_empty_listing() {
        if skip_as_root("an_unreadable_backup_dir_is_an_error_not_an_empty_listing") {
            return;
        }
        let parent = tempfile::tempdir().unwrap();
        let dir = parent.path().join("backups");
        std::fs::create_dir(&dir).unwrap();
        std::fs::write(dir.join("config-20260101T000000Z.tar.gz"), b"old").unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o000)).unwrap();

        let err = restore_points_lines(&dir).unwrap_err().to_string();

        // Restore before asserting so a failure still leaves a removable dir.
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(
            err.contains("cannot read backup directory"),
            "an unreadable directory must not report as an empty one: {err}"
        );
    }

    #[test]
    fn an_unreadable_archive_is_listed_as_unreadable_not_dropped() {
        if skip_as_root("an_unreadable_archive_is_listed_as_unreadable_not_dropped") {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("config-20260101T000000Z.tar.gz");
        std::fs::write(&archive, b"old").unwrap();
        std::fs::set_permissions(&archive, std::fs::Permissions::from_mode(0o000)).unwrap();

        let scan = scan_backup_dir(dir.path());
        let lines = restore_points_lines(dir.path()).unwrap().join("\n");
        std::fs::set_permissions(&archive, std::fs::Permissions::from_mode(0o600)).unwrap();

        assert_eq!(
            scan.archives.len(),
            1,
            "membership must not change: retention still has to age this out"
        );
        assert!(scan.archives[0].unreadable.is_some());
        assert!(
            lines.contains("unreadable:"),
            "the listing must say why, not print a size it never read:\n{lines}"
        );
    }

    #[test]
    fn latest_archive_reports_an_unreadable_newest_rather_than_no_backups() {
        if skip_as_root("latest_archive_reports_an_unreadable_newest_rather_than_no_backups") {
            return;
        }
        let (_dir, config) = make_single_file_config();
        let backup_dir = config.parent().unwrap().join("backups");
        std::fs::create_dir(&backup_dir).unwrap();
        let archive = backup_dir.join("config-20260101T000000Z.tar.gz");
        std::fs::write(&archive, b"old").unwrap();
        std::fs::set_permissions(&archive, std::fs::Permissions::from_mode(0o000)).unwrap();

        let err = latest_archive(&config).unwrap_err().to_string();
        std::fs::set_permissions(&archive, std::fs::Permissions::from_mode(0o600)).unwrap();

        assert!(
            err.contains("cannot be read"),
            "unreadable is not absent: {err}"
        );
        assert!(
            !err.contains("no backups"),
            "and must not be phrased as absence: {err}"
        );
    }

    #[test]
    fn latest_archive_points_at_the_rollback_copy_when_that_is_all_there_is() {
        let (_dir, config) = make_single_file_config();
        let backup_dir = config.parent().unwrap().join("backups");
        std::fs::create_dir(&backup_dir).unwrap();
        std::fs::write(
            backup_dir.join("pre-migration-2026-08-26T10-30-00Z.toml"),
            b"schema_version = 2\n",
        )
        .unwrap();

        let err = latest_archive(&config).unwrap_err().to_string();
        assert!(
            err.contains("pre-migration rollback file"),
            "the operator has something to roll back to; say so: {err}"
        );
    }

    /// `backup_legacy` writes beside the config it is migrating and cannot
    /// do otherwise — it runs on a config the loader refuses. A configured
    /// `[backup] dir` therefore points the listing at a different directory
    /// entirely, and reading only that one reproduces the original symptom
    /// on every host that sets the field.
    #[test]
    fn a_configured_backup_dir_does_not_hide_the_migrators_rollback_copy() {
        let home = tempfile::tempdir().unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        let config = home.path().join("config.toml");
        std::fs::write(
            &config,
            format!(
                "schema_version = 4\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n\n\
                 [backup]\ndir = \"{}\"\n",
                elsewhere.path().display()
            ),
        )
        .unwrap();
        // Without this the fixture is vacuous: an unloadable master falls
        // back to `<config-parent>/backups`, which is the directory the
        // rollback copy is already in.
        assert_eq!(
            resolved_backup_dir(&config),
            elsewhere.path(),
            "fixture cannot discriminate: the master did not load"
        );

        let beside = home.path().join("backups");
        std::fs::create_dir(&beside).unwrap();
        std::fs::write(
            beside.join("pre-migration-2026-08-26T10-30-00Z.toml"),
            b"schema_version = 2\n",
        )
        .unwrap();

        let joined = restore_list_lines(&config).unwrap().join("\n");
        assert!(
            joined.contains("pre-migration-2026-08-26T10-30-00Z.toml"),
            "the rollback copy must be listed wherever the migrator put it:\n{joined}"
        );
        assert!(
            joined.contains(&beside.display().to_string()),
            "and the listing must name that directory:\n{joined}"
        );
    }
}
