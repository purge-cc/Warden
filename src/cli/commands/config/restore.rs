//! `warden config restore <archive>` — staged replace from a tar.gz backup.
//!
//! Flow:
//!
//! 1. Extract the archive into a staging directory.
//! 2. Locate the master `config.toml` in the staging tree.
//! 3. Run [`crate::config::loader::load_config`] against the staged
//!    master so every validator error is caught before the live tree
//!    is touched.
//! 4. If clean, atomically replace the live config file and every
//!    sibling `*.d/` directory, copy the previous master aside as
//!    `<name>.pre-restore-<ts>` for trivial rollback.
//! 5. Optionally send `SIGHUP` to the running daemon (via its PID file)
//!    so the swap is observable without a manual restart.
//!
//! Failure at step 3 leaves the live tree untouched and returns a
//! non-zero exit code. The staging directory is dropped on exit.

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

use crate::config::atomic_write::{
    hardened_atomic_create_only_at, hardened_atomic_write_at, AtomicCreateOnlyAtOpts,
    AtomicWriteAtOpts, AtomicWriteError,
};
use crate::config::loader;
use crate::config::migration_journal;
use crate::config::tree_io::{inspect_at, rename_noreplace_at, same_optional_inode};
use crate::config::write_lock::{self, ConfigWriteLock};
use anyhow::Context;

use super::backup::include_roots;

/// Outcome of [`restore_archive`] — distinguishes a clean reinstall from
/// a staged-config validation failure (which leaves the live tree
/// untouched) so callers can render their own output. Hard I/O / archive
/// errors are returned as `Err` instead.
pub enum RestoreOutcome {
    /// The live config was replaced. `pre_restore` is the path the prior
    /// master was saved to (`None` if there was no prior master).
    Restored { pre_restore: Option<PathBuf> },
    /// The staged config failed validation; the live tree is untouched.
    /// Carries the formatted validator errors.
    ValidationFailed(Vec<String>),
}

/// Restore the config tree from `archive` WITHOUT printing or signalling —
/// so the TUI can call it inside the alternate screen. The CLI wrapper
/// [`run_restore`] prints the summary, sends `SIGHUP`, and maps the
/// outcome to a process exit code.
pub fn restore_archive(live_config: &Path, archive: &Path) -> anyhow::Result<RestoreOutcome> {
    if !archive.exists() {
        anyhow::bail!("archive not found: {}", archive.display());
    }

    let staging = StagingDir::create()?;
    extract_archive(archive, staging.path())?;

    let staged_master = locate_staged_master(staging.path(), live_config)?;

    // Validate the staged tree before touching anything live. The load
    // also tells us WHICH files the archive's config actually declares —
    // the install set is derived from that instead of a hardcoded
    // `KNOWN_INCLUDE_DIRS` list. Two properties come out of using the STAGED master's
    // own graph rather than the archive's contents: an include the
    // operator declared outside `<class>.d/` is reinstalled, and the set
    // still bounds what an operator-supplied archive may write into the
    // live config dir (an unreferenced member is extracted to staging and
    // then simply not promoted).
    let now = time::OffsetDateTime::now_utc();
    let staged_loaded = match loader::load_config(&staged_master, now) {
        Ok(loaded) => loaded,
        Err(errs) => {
            return Ok(RestoreOutcome::ValidationFailed(
                errs.iter().map(|e| e.to_string()).collect(),
            ));
        }
    };
    let staged_files = staged_loaded.files_loaded.clone();
    // Read and bound the whole staged install set before acquiring the live
    // tree. Nothing below this point needs to inspect the caller's path.
    let staged_bytes = std::fs::read(&staged_master).map_err(|e| {
        anyhow::anyhow!(
            "cannot read staged master {}: {}",
            staged_master.display(),
            e
        )
    })?;
    let staged_root = staged_master
        .parent()
        .ok_or_else(|| anyhow::anyhow!("staged master has no parent"))?;
    let staged_master_name = staged_master
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(|| anyhow::anyhow!("staged master has no file name"))?;
    // A restored master that declares a custom list without its file is a
    // daemon that will not start — the recovery tool causing the outage it
    // exists to end. The pack files have to be promoted alongside the
    // includes.
    //
    // The promotion rule is unchanged: only what the staged master declares
    // is written into the live tree. Since the unit of promotion is a
    // top-level directory name, the bound is applied by pruning the staged
    // copy first, so the directory that gets promoted holds exactly the
    // declared set.
    let staged_pack_dir = crate::config::custom_list::pack_dir(staged_root);
    let mut promote_packs = false;
    if staged_pack_dir.is_dir() {
        let declared: std::collections::HashSet<PathBuf> = staged_loaded
            .config
            .custom_lists
            .iter()
            .map(|cl| crate::config::custom_list::pack_path(staged_root, &cl.id))
            .collect();
        for entry in std::fs::read_dir(&staged_pack_dir)? {
            let path = entry?.path();
            if !declared.contains(&path) {
                // Staging is a temp dir this function owns; nothing live is
                // touched. An archive member no entry names is dropped here
                // exactly as an unreferenced include is dropped by not
                // appearing in `include_entries`.
                let _ = std::fs::remove_file(&path);
            }
        }
        promote_packs = !declared.is_empty();
    }

    // The master is installed above by its own atomic write; everything
    // else the staged config reaches is an include entry to promote.
    let mut include_entries: Vec<String> = include_roots(staged_root, &staged_files)?
        .into_iter()
        .filter(|e| e != staged_master_name)
        .collect();
    if promote_packs && !include_entries.iter().any(|e| e == "packs") {
        include_entries.push("packs".to_string());
    }

    // The guard creates/adopts the canonical root, binds aliases, and is the
    // sole live-tree capability. Its scope deliberately ends before callers
    // print, signal, or await.
    {
        let guard = write_lock::acquire_for_write(live_config)?;
        migration_journal::refuse_normal_access(guard.tree_io())?;
        restore_staged_locked(
            &guard,
            live_config,
            staged_root,
            &staged_bytes,
            &include_entries,
        )
    }
}

fn restore_staged_locked(
    guard: &ConfigWriteLock,
    requested_master: &Path,
    staged_root: &Path,
    staged_bytes: &[u8],
    include_entries: &[String],
) -> anyhow::Result<RestoreOutcome> {
    guard.verify_master(requested_master)?;
    // This is the first restore-specific observation of the live tree.
    let master_plan = guard.tree_io().plan_master_target()?;
    let original_meta = master_plan.original_metadata().cloned();
    let master_target = master_plan.materialize()?;
    let root = guard.tree_io().backup_root_fd()?;
    let owner = guard.admitted_side_lock_owner()?;
    let canonical_root = guard
        .canonical_master()
        .parent()
        .ok_or_else(|| anyhow::anyhow!("canonical config master has no parent"))?;

    let mut original_source = None;
    let mut original_bytes = None;
    if let (Some(original), Some(meta)) = (master_target.original.as_ref(), original_meta.as_ref())
    {
        let mut source = write_lock::reopen_inspected(original, libc::O_RDONLY)?;
        let mut bytes = Vec::with_capacity(usize::try_from(meta.len()).unwrap_or(0));
        source.read_to_end(&mut bytes)?;
        anyhow::ensure!(
            bytes.len() as u64 == meta.len(),
            "canonical master changed while capturing its recovery copy"
        );
        original_source = Some(source);
        original_bytes = Some(bytes);
    }

    let mut pre_restore = match (original_source.as_mut(), original_meta.as_ref()) {
        (Some(source), Some(meta)) => Some(create_pre_restore_copy(guard, source, meta)?),
        _ => None,
    };

    // Phase A is additive and completes before the master changes.
    let mut swap = match prepare_include_entries(
        &mut std::io::stderr(),
        staged_root,
        &root,
        canonical_root,
        include_entries,
        owner,
    ) {
        Ok(swap) => swap,
        Err(error) => {
            let artifact = recovery_artifact(&pre_restore, guard.canonical_master());
            return match cleanup_pre_restore(pre_restore.take()) {
                Ok(()) => Err(error),
                Err(cleanup) => Err(error.context(format!(
                    "cleanup of pre-restore artifact was incomplete: {cleanup:#}; inspect {artifact}"
                ))),
            };
        }
    };

    if let Err(error) = hardened_atomic_write_at(
        &master_target,
        staged_bytes,
        AtomicWriteAtOpts {
            owner: Some(owner),
            ..Default::default()
        },
    ) {
        let landed = error.rename_landed();
        let mut recovery_errors = Vec::new();
        if landed {
            if let Err(rollback) =
                rollback_published_master(&master_target, original_bytes.as_deref())
            {
                recovery_errors.push(format!("canonical-master rollback failed: {rollback:#}"));
            }
        }
        if let Err(cleanup) = swap.cleanup_incoming(&root) {
            recovery_errors.push(format!("incoming cleanup failed: {cleanup:#}"));
        }
        let cause = anyhow::Error::new(error).context(format!(
            "failed to install staged config at {}",
            guard.canonical_master().display()
        ));
        if recovery_errors.is_empty() {
            let artifact = recovery_artifact(&pre_restore, guard.canonical_master());
            if let Err(cleanup) = cleanup_pre_restore(pre_restore.take()) {
                return Err(cause.context(format!(
                    "cleanup of pre-restore artifact failed: {cleanup:#}; inspect {artifact}"
                )));
            }
            return Err(cause);
        }
        return Err(cause.context(format!(
            "restore recovery is incomplete ({}); retain and inspect {}",
            recovery_errors.join("; "),
            recovery_inventory(
                &pre_restore,
                guard.canonical_master(),
                &swap,
                &root,
                canonical_root,
            ),
        )));
    }

    if let Err(error) = swap.promote(&root, |from_parent, from, to_parent, to| {
        rename_noreplace_at(from_parent, from, to_parent, to)
    }) {
        let include_rollback = swap.rollback(&root);
        let master_rollback = rollback_published_master(&master_target, original_bytes.as_deref());
        match (include_rollback, master_rollback) {
            (Ok(()), Ok(())) => {
                let artifact = recovery_artifact(&pre_restore, guard.canonical_master());
                if let Err(cleanup) = cleanup_pre_restore(pre_restore.take()) {
                    return Err(error.context(format!(
                        "restore rolled back, but cleanup of pre-restore artifact failed: \
                         {cleanup:#}; inspect {artifact}"
                    )));
                }
                return Err(error.context("restore aborted; live config rolled back"));
            }
            (include, master) => {
                let mut failures = Vec::new();
                if let Err(include) = include {
                    failures.push(format!("include rollback failed: {include:#}"));
                }
                if let Err(master) = master {
                    failures.push(format!("canonical-master rollback failed: {master:#}"));
                }
                return Err(error.context(format!(
                    "restore recovery is incomplete ({}); retain and inspect {}",
                    failures.join("; "),
                    recovery_inventory(
                        &pre_restore,
                        guard.canonical_master(),
                        &swap,
                        &root,
                        canonical_root,
                    ),
                )));
            }
        }
    }

    if let Err(error) = swap.finalize(&root) {
        let artifacts = swap.recovery_artifacts(&root, canonical_root);
        let retained = if artifacts.is_empty() {
            format!("the include root {}", canonical_root.display())
        } else {
            artifacts.join(", ")
        };
        eprintln!(
            "warning: restore committed, but cleanup retained {}: {error:#}",
            retained
        );
    }
    Ok(RestoreOutcome::Restored {
        pre_restore: pre_restore.map(|(path, _)| path),
    })
}

/// CLI entry point. Returns the intended process exit code (0 success,
/// 1 staged-config validation failure); hard I/O / archive errors
/// propagate as `Err`. Prints the human summary and, given a `pid_file`,
/// sends `SIGHUP` so a running daemon reloads.
pub fn run_restore(
    live_config: &Path,
    archive: &Path,
    pid_file: Option<&Path>,
) -> anyhow::Result<i32> {
    match restore_archive(live_config, archive)? {
        RestoreOutcome::ValidationFailed(errs) => {
            eprintln!(
                "staged config failed validation ({} error(s)) — live config untouched:",
                errs.len()
            );
            for e in &errs {
                eprintln!("  - {e}");
            }
            Ok(1)
        }
        RestoreOutcome::Restored { pre_restore } => {
            if let Some(prev) = &pre_restore {
                println!("saved previous config as {}", prev.display());
            }
            println!("restored config to {}", live_config.display());
            if let Some(pid) = pid_file {
                if let Err(e) = send_sighup_from_pid(pid) {
                    eprintln!(
                        "note: SIGHUP reload failed: {e} — run `systemctl reload purge-warden` manually"
                    );
                } else {
                    println!("sent SIGHUP — daemon reloading");
                }
            }
            Ok(0)
        }
    }
}

/// Self-cleaning staging directory. Mirrors the subset of
/// `tempfile::tempdir` we use here so the production build doesn't
/// need the `tempfile` crate as a runtime dependency (it stays a
/// dev-dep used only by the test suite).
///
/// `pub(crate)` so the cluster apply path (`crate::cluster::apply`)
/// reuses the exact hardened CSPRNG-named 0o700 staging dir rather than
/// re-implementing the TOCTOU-safe creation.
pub(crate) struct StagingDir {
    path: PathBuf,
}

impl StagingDir {
    /// Create a CSPRNG-named `0o700` staging dir under the system temp dir.
    /// Used by `restore`, which only *copies* out of staging (cross-filesystem
    /// is fine).
    pub(crate) fn create() -> anyhow::Result<Self> {
        Self::create_in(&std::env::temp_dir())
    }

    /// Create a CSPRNG-named `0o700` staging dir under `parent`.
    ///
    /// Exclusive + unpredictable. A fixed/predictable name with `create_dir_all`
    /// succeeds on EEXIST — so a local attacker could pre-create the dir or
    /// plant a symlink there and interpose on the validate↔install window (a
    /// classic TOCTOU; these flows may run privileged and write into system
    /// config dirs). `OsRng` (CSPRNG, per CLAUDE.md) names it and
    /// `DirBuilder::create` (NOT create_dir_all) fails on EEXIST, so we either
    /// own a freshly-made `0o700` directory or we abort.
    ///
    /// `parent` lets a caller pin staging onto a specific filesystem —
    /// `migrate` promotes staging→target with `rename(2)`, which `EXDEV`-fails
    /// across filesystems, so it must stage under the target dir, not `/tmp`.
    pub(crate) fn create_in(parent: &Path) -> anyhow::Result<Self> {
        use rand_core::{OsRng, RngCore};
        use std::os::unix::fs::DirBuilderExt;
        let mut rng = OsRng;
        for _ in 0..8 {
            let path = parent.join(format!(
                "purge-warden-stage-{}-{:016x}",
                std::process::id(),
                rng.next_u64()
            ));
            match std::fs::DirBuilder::new().mode(0o700).create(&path) {
                Ok(()) => return Ok(Self { path }),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => {
                    return Err(anyhow::anyhow!(
                        "cannot create staging directory {}: {}",
                        path.display(),
                        e
                    ))
                }
            }
        }
        anyhow::bail!(
            "cannot create a unique staging directory under {} after 8 attempts",
            parent.display()
        )
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for StagingDir {
    fn drop(&mut self) {
        // Best-effort cleanup — leaving a few KB of staged config on a
        // panic path is preferable to erroring out during unwinding.
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn extract_archive(archive: &Path, dest: &Path) -> anyhow::Result<()> {
    // Defend against a hostile backup archive. Before extracting,
    // list the members and reject any that could write outside `dest`:
    // absolute paths, `..` traversal, or symlink/hardlink members (a crafted
    // archive can use a symlink member to redirect a later write outside the
    // staging root). `restore` may run privileged and writes into system
    // config dirs, so an escape is an arbitrary-file-write primitive. Modern
    // GNU tar strips leading `/` and refuses `..` by default, but BSD/busybox
    // tar are weaker — so we enforce it ourselves rather than trust the
    // extractor.
    reject_hostile_members(archive)?;

    // `-C <dest>` must precede `-f <archive>` so it targets the extraction
    // destination rather than further positional args. No extra extract flag
    // is needed: `reject_hostile_members` above is the portable enforcement,
    // and GNU tar additionally strips leading `/` and refuses `..` by default.
    let status = std::process::Command::new("tar")
        .arg("-C")
        .arg(dest)
        .arg("-xzf")
        .arg(archive)
        .status()
        .map_err(|e| anyhow::anyhow!("failed to run tar: {}", e))?;
    if !status.success() {
        anyhow::bail!("tar -xzf {} exited with {status}", archive.display());
    }
    Ok(())
}

/// Reject a backup archive whose members could escape the staging root on
/// extraction: absolute paths, `..` traversal, or symlink/hardlink members.
/// Two passes so neither check is fooled by member names containing spaces:
/// `-tzf` yields one exact member path per line (path-safety check), `-tvzf`
/// adds the leading type column (`l` symlink, `h` hardlink).
fn reject_hostile_members(archive: &Path) -> anyhow::Result<()> {
    for name in run_tar_list(archive, &["-tzf"])?.lines() {
        let name = name.trim_end_matches('/'); // dir entries list with a trailing '/'
        if name.is_empty() {
            continue;
        }
        if is_unsafe_member_path(name) {
            anyhow::bail!(
                "refusing archive: member '{name}' is absolute or contains '..' \
                 (path traversal) — a backup must not write outside the staging dir"
            );
        }
    }
    // Second pass: the leading type column of `-tvzf` classifies each member.
    // Whitelist regular files (`-`) and directories (`d`); reject everything
    // else — symlink (`l`), hardlink (`h`), char/block device (`c`/`b`), FIFO
    // (`p`), socket (`s`). A blacklist that only catches `l`/`h` lets a
    // device/fifo/socket member through. A legit backup
    // (`tar -czf` of the config dir) holds only files and dirs, so this is a
    // fail-fast on obviously-hostile archives; the descriptor-rooted copy
    // re-checks extracted entries before they enter the live tree.
    for line in run_tar_list(archive, &["-tvzf"])?.lines() {
        match line.as_bytes().first() {
            None => {}                    // blank line
            Some(b'-') | Some(b'd') => {} // regular file or directory — allowed
            Some(_) => anyhow::bail!(
                "refusing archive: member is not a regular file or directory \
                 — symlink/hardlink/device/fifo/socket members can escape the \
                 staging directory ({})",
                line.trim()
            ),
        }
    }
    Ok(())
}

/// Run `tar <args> <archive>` and return stdout, erroring on non-zero exit.
fn run_tar_list(archive: &Path, args: &[&str]) -> anyhow::Result<String> {
    let output = std::process::Command::new("tar")
        .args(args)
        .arg(archive)
        .output()
        .map_err(|e| anyhow::anyhow!("failed to list archive {}: {}", archive.display(), e))?;
    if !output.status.success() {
        anyhow::bail!(
            "cannot list archive {} ({}): {}",
            archive.display(),
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// True if `name` is an absolute path or contains a `..` / root component —
/// either lets an archive member escape the extraction root.
fn is_unsafe_member_path(name: &str) -> bool {
    let p = Path::new(name);
    p.components().any(|c| {
        matches!(
            c,
            std::path::Component::ParentDir | std::path::Component::RootDir
        )
    })
}

fn recovery_artifact(
    pre_restore: &Option<(PathBuf, crate::config::tree_io::PinnedTarget<'_>)>,
    canonical_master: &Path,
) -> String {
    pre_restore
        .as_ref()
        .map(|(path, _)| path.display().to_string())
        .unwrap_or_else(|| canonical_master.display().to_string())
}

fn recovery_inventory(
    pre_restore: &Option<(PathBuf, crate::config::tree_io::PinnedTarget<'_>)>,
    canonical_master: &Path,
    swap: &IncludeSwap,
    root: &File,
    canonical_root: &Path,
) -> String {
    let mut artifacts = vec![recovery_artifact(pre_restore, canonical_master)];
    artifacts.extend(swap.recovery_artifacts(root, canonical_root));
    artifacts.join(", ")
}

/// Select one safe root-level staged master. Hints preserve old archives;
/// ambiguity is never resolved by filesystem enumeration order.
fn locate_staged_master(staging: &Path, live_config: &Path) -> anyhow::Result<PathBuf> {
    let requested_name = live_config
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("live config has no file name"))?
        .to_os_string();
    let canonical_name = write_lock::ConfigTreeIdentity::resolve(live_config)
        .ok()
        .and_then(|identity| {
            identity
                .canonical_master
                .file_name()
                .map(OsStr::to_os_string)
        });

    let entries: Vec<PathBuf> = std::fs::read_dir(staging)?
        .map(|entry| entry.map_err(anyhow::Error::from))
        .collect::<anyhow::Result<Vec<_>>>()?
        .into_iter()
        // `file_type` is lstat-based, so a staged symlink never becomes a
        // master hint merely because its destination is a regular file.
        .filter(|entry| entry.file_type().map(|ty| ty.is_file()).unwrap_or(false))
        .map(|e| e.path())
        .filter(|p| {
            p.file_name().and_then(|n| n.to_str()) != Some(crate::config::secrets::SECRETS_FILENAME)
        })
        .collect();
    if let Some(path) = entries
        .iter()
        .find(|path| path.file_name() == Some(requested_name.as_os_str()))
    {
        return Ok(path.clone());
    }
    if let Some(canonical_name) = canonical_name {
        if let Some(path) = entries
            .iter()
            .find(|path| path.file_name() == Some(canonical_name.as_os_str()))
        {
            return Ok(path.clone());
        }
    }
    let mut candidates: Vec<PathBuf> = entries
        .into_iter()
        .filter(|p| p.extension().is_some_and(|e| e == "toml"))
        .collect();
    candidates.sort();
    if candidates.len() == 1 {
        return Ok(candidates.remove(0));
    }
    if candidates.is_empty() {
        anyhow::bail!(
            "no master *.toml found in staged archive at {}",
            staging.display()
        );
    }
    anyhow::bail!(
        "ambiguous staged archive at {}: multiple non-secrets root TOML files ({})",
        staging.display(),
        candidates
            .iter()
            .filter_map(|path| path.file_name())
            .map(|name| name.to_string_lossy())
            .collect::<Vec<_>>()
            .join(", ")
    )
}

struct PreparedInclude {
    incoming: OsString,
    incoming_receipt: File,
    live: OsString,
    original: Option<File>,
}

struct Aside {
    name: OsString,
    live: OsString,
    receipt: File,
}

struct Promoted {
    name: OsString,
    receipt: File,
}

struct IncludeSwap {
    prepared: Vec<PreparedInclude>,
    asides: Vec<Aside>,
    promoted: Vec<Promoted>,
}

/// Phase A is entirely additive.  All later names are root-relative to the
/// held descriptor, never to the caller's spelling of the config path.
fn prepare_include_entries(
    notices: &mut dyn Write,
    staged_root: &Path,
    root: &File,
    canonical_root: &Path,
    entries: &[String],
    owner: (u32, u32),
) -> anyhow::Result<IncludeSwap> {
    let mut receipts = std::collections::HashMap::new();
    for entry in entries {
        let name = checked_live_entry_name(entry)?;
        let current = inspect_at(root, name)?;
        if let Some(current) = &current {
            let meta = current.metadata()?;
            anyhow::ensure!(
                !meta.file_type().is_symlink()
                    && (meta.is_dir() || (meta.is_file() && meta.nlink() == 1)),
                "unsafe live include entry: {}",
                canonical_root.join(entry).display()
            );
        }
        receipts.insert(entry.clone(), current);
    }

    let mut swap = IncludeSwap {
        prepared: Vec::new(),
        asides: Vec::new(),
        promoted: Vec::new(),
    };
    for entry in entries {
        let staged = staged_root.join(entry);
        let meta = match std::fs::symlink_metadata(&staged) {
            Ok(meta) => meta,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let _ = writeln!(
                    notices,
                    "warning: the restored config declares include entry {entry}, which the archive \
                     does not contain; {} is left as it stands",
                    canonical_root.join(entry).display()
                );
                continue;
            }
            Err(error) => {
                let error =
                    anyhow::Error::from(error).context(format!("staging include entry {entry}"));
                return Err(abort_include_preparation(&mut swap, root, error));
            }
        };
        if !meta.is_dir() && !meta.is_file() {
            let error = anyhow::anyhow!(
                "refusing to restore {}: not a regular file or directory",
                staged.display()
            );
            return Err(abort_include_preparation(&mut swap, root, error));
        }
        let live = checked_live_entry_name(entry)?.to_os_string();
        let incoming = match reserve_side_name(root, &live, "incoming") {
            Ok(incoming) => incoming,
            Err(error) => {
                return Err(abort_include_preparation(&mut swap, root, error));
            }
        };
        let incoming_receipt = match copy_staged_entry_at(&staged, root, &incoming, owner) {
            Ok(receipt) => receipt,
            Err(error) => {
                let error = error.context(format!(
                    "staging include entry {entry} at {}",
                    canonical_root.join(&incoming).display()
                ));
                return Err(abort_include_preparation(&mut swap, root, error));
            }
        };
        swap.prepared.push(PreparedInclude {
            incoming,
            incoming_receipt,
            live,
            original: receipts.remove(entry).expect("entry receipt"),
        });
    }
    Ok(swap)
}

fn abort_include_preparation(
    swap: &mut IncludeSwap,
    root: &File,
    error: anyhow::Error,
) -> anyhow::Error {
    match swap.cleanup_incoming(root) {
        Ok(()) => error,
        Err(cleanup) => error.context(format!(
            "cleanup after include preparation failure was incomplete: {cleanup:#}"
        )),
    }
}

impl IncludeSwap {
    fn promote(
        &mut self,
        root: &File,
        rename: impl Fn(&File, &OsStr, &File, &OsStr) -> std::io::Result<()>,
    ) -> anyhow::Result<()> {
        for item in &self.prepared {
            let incoming = inspect_at(root, &item.incoming)
                .map_err(anyhow::Error::from)
                .context("inspecting staged include before promotion")?;
            anyhow::ensure!(
                same_optional_inode(Some(&item.incoming_receipt), incoming.as_ref())?,
                "staged include entry changed before promotion: {:?}",
                item.incoming
            );
            let current = inspect_at(root, &item.live)
                .map_err(anyhow::Error::from)
                .context("inspecting live include before promotion")?;
            anyhow::ensure!(
                same_optional_inode(item.original.as_ref(), current.as_ref())?,
                "live include entry changed since its snapshot: {:?}",
                item.live
            );
            if let Some(original) = &item.original {
                let aside = reserve_side_name(root, &item.live, "pre-restore")?;
                let receipt = original.try_clone()?;
                rename(root, &item.live, root, &aside)
                    .map_err(anyhow::Error::from)
                    .context("moving live include aside")?;
                self.asides.push(Aside {
                    name: aside,
                    live: item.live.clone(),
                    receipt,
                });
            }
            let receipt = item.incoming_receipt.try_clone()?;
            rename(root, &item.incoming, root, &item.live)
                .map_err(anyhow::Error::from)
                .context("promoting staged include")?;
            self.promoted.push(Promoted {
                name: item.live.clone(),
                receipt,
            });
            let installed = inspect_at(root, &item.live)
                .map_err(anyhow::Error::from)
                .context("inspecting promoted include")?;
            anyhow::ensure!(
                same_optional_inode(Some(&item.incoming_receipt), installed.as_ref())?,
                "staged include entry changed during promotion: {:?}",
                item.live
            );
        }
        root.sync_all().context("sync restored include root")?;
        self.verify_promoted(root)?;
        Ok(())
    }

    fn finalize(&mut self, root: &File) -> anyhow::Result<()> {
        self.verify_promoted(root)?;
        for aside in &self.asides {
            remove_owned_entry_at(root, &aside.name, &aside.receipt)
                .with_context(|| format!("cleaning restore aside {:?}", aside.name))?;
        }
        root.sync_all()?;
        Ok(())
    }

    fn verify_promoted(&self, root: &File) -> anyhow::Result<()> {
        for promoted in &self.promoted {
            let current = inspect_at(root, &promoted.name)?;
            anyhow::ensure!(
                same_optional_inode(Some(&promoted.receipt), current.as_ref())?,
                "promoted include entry was replaced: {:?}",
                promoted.name
            );
        }
        Ok(())
    }

    fn cleanup_incoming(&mut self, root: &File) -> anyhow::Result<()> {
        let mut errors = Vec::new();
        for item in self.prepared.iter().rev() {
            if let Err(error) = remove_owned_entry_at(root, &item.incoming, &item.incoming_receipt)
            {
                errors.push(format!("{:?}: {error:#}", item.incoming));
            }
        }
        if let Err(error) = root.sync_all() {
            errors.push(format!("include-root sync: {error}"));
        }
        if errors.is_empty() {
            Ok(())
        } else {
            anyhow::bail!("incoming cleanup failures: {}", errors.join("; "))
        }
    }

    fn rollback(&mut self, root: &File) -> anyhow::Result<()> {
        let mut errors = Vec::new();
        for promoted in self.promoted.iter().rev() {
            if let Err(error) = remove_owned_entry_at(root, &promoted.name, &promoted.receipt) {
                errors.push(format!("promoted {:?}: {error:#}", promoted.name));
            }
        }
        for aside in self.asides.iter().rev() {
            let restore = (|| -> anyhow::Result<()> {
                let current = inspect_at(root, &aside.name)?;
                anyhow::ensure!(
                    same_optional_inode(Some(&aside.receipt), current.as_ref())?,
                    "restore aside was replaced: {:?}",
                    aside.name
                );
                rename_noreplace_at(root, &aside.name, root, &aside.live)?;
                Ok(())
            })();
            if let Err(error) = restore {
                errors.push(format!("aside {:?}: {error:#}", aside.name));
            }
        }
        for item in self.prepared.iter().rev() {
            if let Err(error) = remove_owned_entry_at(root, &item.incoming, &item.incoming_receipt)
            {
                errors.push(format!("incoming {:?}: {error:#}", item.incoming));
            }
        }
        if let Err(error) = root.sync_all() {
            errors.push(format!("include-root sync: {error}"));
        }
        if errors.is_empty() {
            Ok(())
        } else {
            anyhow::bail!("include rollback failures: {}", errors.join("; "))
        }
    }

    fn recovery_artifacts(&self, root: &File, canonical_root: &Path) -> Vec<String> {
        let mut artifacts = Vec::new();
        for (name, receipt) in self
            .prepared
            .iter()
            .map(|item| (&item.incoming, &item.incoming_receipt))
            .chain(
                self.asides
                    .iter()
                    .map(|aside| (&aside.name, &aside.receipt)),
            )
        {
            let display = canonical_root.join(name).display().to_string();
            match inspect_at(root, name) {
                Ok(None) => {}
                Ok(Some(current)) => match same_optional_inode(Some(receipt), Some(&current)) {
                    Ok(true) => artifacts.push(display),
                    Ok(false) => artifacts.push(format!("{display} (replacement preserved)")),
                    Err(error) => artifacts.push(format!("{display} (unverifiable: {error})")),
                },
                Err(error) => artifacts.push(format!("{display} (unverifiable: {error})")),
            }
        }
        artifacts
    }
}

fn checked_live_entry_name(entry: &str) -> anyhow::Result<&OsStr> {
    let name = OsStr::new(entry);
    crate::config::tree_io::check_basename(name)?;
    anyhow::ensure!(
        !write_lock::reserved_component(name),
        "restore include entry uses reserved config namespace: {entry}"
    );
    Ok(name)
}

fn reserve_side_name(root: &File, entry: &OsStr, kind: &str) -> anyhow::Result<OsString> {
    use rand_core::{OsRng, RngCore};
    for _ in 0..8 {
        let name = OsString::from(format!(
            ".{}.{}-{}-{:016x}",
            entry.to_string_lossy(),
            kind,
            std::process::id(),
            OsRng.next_u64()
        ));
        if inspect_at(root, &name)?.is_none() {
            return Ok(name);
        }
    }
    anyhow::bail!("cannot reserve a unique restore side entry")
}

fn create_pre_restore_copy<'g>(
    guard: &'g ConfigWriteLock,
    source: &mut File,
    metadata: &std::fs::Metadata,
) -> anyhow::Result<(PathBuf, crate::config::tree_io::PinnedTarget<'g>)> {
    source.seek(SeekFrom::Start(0))?;
    let timestamp = time::OffsetDateTime::now_utc()
        .format(&time::macros::format_description!(
            "[year][month][day]T[hour][minute][second]Z"
        ))
        .map_err(|e| anyhow::anyhow!("failed to format timestamp: {e}"))?;
    for suffix in 0_u32.. {
        let mut side = guard
            .canonical_master()
            .with_extension(format!("toml.pre-restore-{timestamp}"))
            .file_name()
            .ok_or_else(|| anyhow::anyhow!("canonical master has no filename"))?
            .to_os_string();
        if suffix != 0 {
            side.push(format!("-{suffix}"));
        }
        let plan = guard.tree_io().plan_root_file_no_follow(Path::new(&side))?;
        if !plan.is_new() {
            continue;
        }
        let target = plan.materialize()?;
        match hardened_atomic_create_only_at(
            &target,
            source,
            metadata.len(),
            AtomicCreateOnlyAtOpts {
                mode: Some(metadata.mode() & 0o7777),
                owner: Some((metadata.uid(), metadata.gid())),
                #[cfg(test)]
                test_failure: None,
            },
        ) {
            Ok(()) => return Ok((target.display().to_path_buf(), target)),
            Err(AtomicWriteError::TargetExists { .. }) => continue,
            Err(error) => return Err(anyhow::Error::new(error)),
        }
    }
    unreachable!("u32 pre-restore copy suffix space exhausted")
}

fn cleanup_pre_restore(
    pre_restore: Option<(PathBuf, crate::config::tree_io::PinnedTarget<'_>)>,
) -> anyhow::Result<()> {
    if let Some((_, target)) = pre_restore {
        target.rollback_target()?.unlink()?;
    }
    Ok(())
}

fn rollback_published_master(
    target: &crate::config::tree_io::PinnedTarget<'_>,
    original: Option<&[u8]>,
) -> anyhow::Result<()> {
    let rollback = target.rollback_target()?;
    match original {
        Some(bytes) => hardened_atomic_write_at(&rollback, bytes, AtomicWriteAtOpts::default())?,
        None => rollback.unlink()?,
    }
    Ok(())
}

fn copy_staged_entry_at(
    source: &Path,
    parent: &File,
    name: &OsStr,
    owner: (u32, u32),
) -> anyhow::Result<File> {
    let meta = std::fs::symlink_metadata(source)?;
    if meta.is_dir() {
        let destination = mkdir_new_at(parent, name, owner)?;
        if let Err(error) = (|| -> anyhow::Result<()> {
            copy_dir_contents_at(source, &destination, owner)?;
            destination.sync_all()?;
            parent.sync_all()?;
            Ok(())
        })() {
            if let Err(cleanup) = remove_owned_entry_at(parent, name, &destination) {
                return Err(error.context(format!(
                    "removing failed incoming directory {:?}: {cleanup:#}",
                    name
                )));
            }
            return Err(error);
        }
        Ok(destination)
    } else if meta.is_file() {
        copy_regular_file_at(source, parent, name, owner)
    } else {
        anyhow::bail!(
            "refusing to restore {}: not a regular file or directory",
            source.display()
        )
    }
}

fn copy_dir_contents_at(
    source: &Path,
    destination: &File,
    owner: (u32, u32),
) -> anyhow::Result<()> {
    for entry in std::fs::read_dir(source)? {
        let entry = entry?;
        let source = entry.path();
        let name = entry.file_name();
        crate::config::tree_io::check_basename(&name)?;
        let meta = entry.file_type()?;
        if meta.is_dir() {
            let child = mkdir_new_at(destination, &name, owner)?;
            copy_dir_contents_at(&source, &child, owner)?;
            child.sync_all()?;
        } else if meta.is_file() {
            copy_regular_file_at(&source, destination, &name, owner)?;
        } else {
            anyhow::bail!(
                "refusing to restore {}: not a regular file or directory",
                source.display()
            )
        }
    }
    destination.sync_all()?;
    Ok(())
}

fn mkdir_new_at(parent: &File, name: &OsStr, owner: (u32, u32)) -> anyhow::Result<File> {
    use std::os::unix::ffi::OsStrExt;
    crate::config::tree_io::check_basename(name)?;
    let name_c = std::ffi::CString::new(name.as_bytes())?;
    if unsafe { libc::mkdirat(parent.as_raw_fd(), name_c.as_ptr(), 0o750) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let dir = write_lock::open_at(parent, name, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
    if let Err(error) = set_restore_owner_and_mode(&dir, owner, 0o750) {
        if let Err(cleanup) = remove_owned_entry_at(parent, name, &dir) {
            return Err(error.context(format!("removing failed incoming directory: {cleanup:#}")));
        }
        return Err(error);
    }
    Ok(dir)
}

fn copy_regular_file_at(
    source: &Path,
    parent: &File,
    name: &OsStr,
    owner: (u32, u32),
) -> anyhow::Result<File> {
    let mut input = File::open(source)?;
    let mut output = write_lock::open_at(
        parent,
        name,
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        0o600,
    )?;
    if let Err(error) = (|| -> anyhow::Result<()> {
        std::io::copy(&mut input, &mut output)?;
        set_restore_owner_and_mode(&output, owner, 0o640)?;
        output.sync_all()?;
        Ok(())
    })() {
        if let Err(cleanup) = remove_owned_entry_at(parent, name, &output) {
            return Err(error.context(format!(
                "removing failed incoming file {:?}: {cleanup:#}",
                name
            )));
        }
        return Err(error);
    }
    Ok(output)
}

fn set_restore_owner_and_mode(file: &File, owner: (u32, u32), mode: u32) -> anyhow::Result<()> {
    if unsafe { libc::geteuid() } == 0
        && unsafe { libc::fchown(file.as_raw_fd(), owner.0, owner.1) } != 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    file.set_permissions(std::fs::Permissions::from_mode(mode))?;
    let meta = file.metadata()?;
    anyhow::ensure!(
        (meta.uid(), meta.gid()) == owner,
        "cannot preserve admitted config-tree ownership"
    );
    Ok(())
}

fn remove_owned_entry_at(root: &File, name: &OsStr, receipt: &File) -> anyhow::Result<()> {
    let Some(entry) = inspect_at(root, name)? else {
        return Ok(());
    };
    anyhow::ensure!(
        same_optional_inode(Some(receipt), Some(&entry))?,
        "restore side entry was replaced; retaining {:?}",
        name
    );
    let meta = entry.metadata()?;
    anyhow::ensure!(
        !meta.file_type().is_symlink() && (meta.is_dir() || meta.is_file()),
        "refusing to remove unsafe restore side entry: {:?}",
        name
    );
    if meta.is_dir() {
        let path = PathBuf::from(format!("/proc/self/fd/{}", root.as_raw_fd())).join(name);
        std::fs::remove_dir_all(path)?;
    } else {
        crate::config::tree_io::unlink_at(root, name)?;
    }
    root.sync_all()?;
    Ok(())
}

fn send_sighup_from_pid(pid_file: &Path) -> anyhow::Result<()> {
    // Reuse the shared `u32` reader: it rejects a leading '-' at parse (so
    // `-1`/`-N` can never reach `kill`), as well as empty/garbage content,
    // and renders a clear operator error. A PID file of `-1` parsed as
    // `i32` would turn `libc::kill(pid, SIGHUP)` into a host-wide broadcast
    // when restore runs as root.
    let pid = crate::cli::commands::pid::read_pid_file(pid_file)?;
    // POSIX kill() overloads non-positive PIDs into broadcasts. Route the range
    // check through the shared `pid::checked_pid` seam (the same guard
    // stop/status/update use) so there is ONE validator; keep the PID-file path
    // in the operator-facing error.
    let pid = crate::cli::commands::pid::checked_pid(pid)
        .map_err(|e| anyhow::anyhow!("{e} (from PID file {})", pid_file.display()))?;
    // Liveness/identity gate: only signal a PID whose file is still `flock`-held
    // by a live daemon (`acquire_pid_lock` holds `LOCK_EX` for the process
    // lifetime). An unlocked file means the daemon exited and the kernel
    // released the lock — the numeric PID may now belong to an unrelated
    // process, and SIGHUP's default disposition terminates most processes, so
    // signalling it could kill an innocent victim. Skip with a clear error
    // instead; the caller prints the manual-reload hint.
    if !crate::cli::commands::pid::pid_file_is_locked(pid_file) {
        anyhow::bail!(
            "PID file {} is not held by a running daemon (stale, or the daemon \
             is stopped) — not sending SIGHUP",
            pid_file.display()
        );
    }
    // SAFETY: libc::kill with SIGHUP only wakes the target's signal handler;
    // the kernel's permission check prevents delivery to processes the caller
    // cannot signal. `pid` is validated `> 0` above, so this never broadcasts.
    let rc = unsafe { libc::kill(pid, libc::SIGHUP) };
    if rc != 0 {
        anyhow::bail!(
            "kill({pid}, SIGHUP) failed: {}",
            std::io::Error::last_os_error()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::commands::config::backup::run_backup;

    const BASE: &str = r#"schema_version = 4

[server]
listen = "127.0.0.1:15353"
default_profile = "default"

[[blocklists]]
id = "privacy-ads"
display_name = "Privacy: ads"
url = "https://lists.purge.cc/privacy/ads.txt"

[profiles.default]
display_name = "Default"

[upstream]
servers = ["192.0.2.1:53"]
"#;

    #[test]
    fn restore_roundtrip_reinstates_identical_config() {
        // Write a config, back it up, overwrite with garbage, restore,
        // and verify the restored content matches the original.
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config.toml");
        std::fs::write(&config, BASE).unwrap();

        let archive = run_backup(&config, None).unwrap();

        // Simulate the live file being damaged.
        std::fs::write(&config, b"garbage = true\n").unwrap();

        let rc = run_restore(&config, &archive, None).unwrap();
        assert_eq!(rc, 0);
        let reloaded = std::fs::read_to_string(&config).unwrap();
        assert_eq!(reloaded, BASE);
    }

    #[test]
    fn restore_uses_one_write_guard_and_releases_it_before_return() {
        use std::cell::Cell;
        use std::rc::Rc;
        use std::time::Duration;

        let source = tempfile::tempdir().unwrap();
        let source_config = source.path().join("config.toml");
        std::fs::write(&source_config, BASE).unwrap();
        let archive = run_backup(&source_config, None).unwrap();

        let live = tempfile::tempdir().unwrap();
        let live_config = live.path().join("config.toml");
        std::fs::write(&live_config, "old = true\n").unwrap();
        let acquisitions = Rc::new(Cell::new(0));
        let seen = Rc::clone(&acquisitions);
        let outcome = write_lock::with_test_hook(
            move |event| {
                if event == write_lock::TestEvent::WriteRootLocked {
                    seen.set(seen.get() + 1);
                }
            },
            || restore_archive(&live_config, &archive),
        )
        .unwrap();
        assert!(matches!(outcome, RestoreOutcome::Restored { .. }));
        assert_eq!(acquisitions.get(), 1);

        let probe =
            write_lock::acquire_for_write_with_timeout(&live_config, Duration::from_millis(50))
                .expect("restore must release its guard before returning");
        drop(probe);
    }

    #[test]
    fn restore_refuses_a_migration_fence_before_live_effects() {
        let source = tempfile::tempdir().unwrap();
        let source_config = source.path().join("config.toml");
        std::fs::write(&source_config, BASE).unwrap();
        let archive = run_backup(&source_config, None).unwrap();

        let live = tempfile::tempdir().unwrap();
        let live_config = live.path().join("config.toml");
        let old = b"old = true\n";
        std::fs::write(&live_config, old).unwrap();
        let fence = live.path().join(migration_journal::TXN_DIR_NAME);

        let error = match write_lock::with_test_hook(
            move |event| {
                if event == write_lock::TestEvent::WriteRootLocked {
                    std::fs::create_dir(&fence).unwrap();
                }
            },
            || restore_archive(&live_config, &archive),
        ) {
            Ok(_) => panic!("a fenced destination must be refused"),
            Err(error) => error,
        };
        assert!(
            error.to_string().contains("unfinished v3-to-v4 migration"),
            "{error:#}"
        );
        assert_eq!(std::fs::read(&live_config).unwrap(), old);
        assert!(std::fs::read_dir(live.path()).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .contains("pre-restore")
        }));
    }

    #[test]
    fn restore_through_an_alias_updates_only_the_canonical_master() {
        use std::os::unix::fs::symlink;

        let source = tempfile::tempdir().unwrap();
        let source_config = source.path().join("config.toml");
        std::fs::write(&source_config, BASE).unwrap();
        let archive = run_backup(&source_config, None).unwrap();

        let live = tempfile::tempdir().unwrap();
        let real = live.path().join("real");
        let front = live.path().join("front");
        std::fs::create_dir(&real).unwrap();
        std::fs::create_dir(&front).unwrap();
        let canonical = real.join("config.toml");
        std::fs::write(&canonical, "old = true\n").unwrap();
        let alias = front.join("active.toml");
        symlink("../real/config.toml", &alias).unwrap();

        let pre_restore = match restore_archive(&alias, &archive).unwrap() {
            RestoreOutcome::Restored { pre_restore } => pre_restore.unwrap(),
            RestoreOutcome::ValidationFailed(errors) => {
                panic!("valid archive failed validation: {errors:?}")
            }
        };
        assert!(std::fs::symlink_metadata(&alias)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(std::fs::read_to_string(&canonical).unwrap(), BASE);
        assert_eq!(std::fs::read_to_string(&alias).unwrap(), BASE);
        assert_eq!(pre_restore.parent(), Some(real.as_path()));
        assert!(pre_restore
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("config.toml.pre-restore-"));
        assert_eq!(
            std::fs::read_to_string(pre_restore).unwrap(),
            "old = true\n"
        );
    }

    /// An include that does NOT live in a `<class>.d/` directory must
    /// survive backup and come back on restore.
    ///
    /// Pre-fix, `KNOWN_INCLUDE_DIRS` listed seven names, `custom` was not
    /// one of them, and the archive silently omitted the file. Restore
    /// then reinstalled the master alone — so the operator got back a
    /// config referencing a profile whose defining file was gone, and
    /// found out at the worst possible moment.
    ///
    /// The fixture makes `custom/` the ONLY home of the `kids` profile and
    /// `server.default_profile` points at it, so a restore that drops the
    /// directory produces a config that does not load — an assertion the
    /// old behaviour cannot satisfy by accident.
    #[test]
    fn roundtrip_preserves_a_non_conventional_include_directory() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config.toml");
        std::fs::write(
            &config,
            "schema_version = 4\nincludes = [\"custom/*.toml\"]\n\n\
             [server]\ndefault_profile = \"kids\"\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
        )
        .unwrap();
        std::fs::create_dir(dir.path().join("custom")).unwrap();
        let slice = dir.path().join("custom").join("policy.toml");
        std::fs::write(&slice, "[profiles.kids]\ndisplay_name = \"Kids\"\n").unwrap();

        let archive = run_backup(&config, None).unwrap();

        // It must be IN the archive — assert on the tar listing, not just
        // on the end state, so a restore that quietly reused the surviving
        // live directory could not make this pass.
        let listing = String::from_utf8_lossy(
            &std::process::Command::new("tar")
                .arg("-tzf")
                .arg(&archive)
                .output()
                .expect("tar listing must run")
                .stdout,
        )
        .into_owned();
        assert!(
            listing.contains("custom/policy.toml"),
            "backup omitted the declared non-conventional include: {listing}"
        );

        // Destroy both halves, then restore.
        std::fs::remove_dir_all(dir.path().join("custom")).unwrap();
        std::fs::write(&config, b"garbage = true\n").unwrap();

        assert_eq!(run_restore(&config, &archive, None).unwrap(), 0);
        assert_eq!(
            std::fs::read_to_string(&slice).unwrap(),
            "[profiles.kids]\ndisplay_name = \"Kids\"\n",
            "custom/policy.toml was not reinstalled"
        );
        // The restored tree must actually load — the operator-visible half.
        let loaded = loader::load_config(&config, time::OffsetDateTime::now_utc())
            .expect("restored config must load; a dropped include breaks default_profile");
        assert!(loaded.config.profiles.contains_key("kids"));
    }

    /// `includes = ["extra.toml"]` puts an include at the TOP
    /// level of the config directory rather than inside a directory.
    /// Backup can capture such a file, so restore has to be able to
    /// reinstall it — a captured-but-unrestorable include is the same
    /// silent omission one layer down.
    #[test]
    fn roundtrip_preserves_a_top_level_include_file() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config.toml");
        std::fs::write(
            &config,
            "schema_version = 4\nincludes = [\"extra.toml\"]\n\n\
             [server]\ndefault_profile = \"kids\"\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
        )
        .unwrap();
        let extra = dir.path().join("extra.toml");
        std::fs::write(&extra, "[profiles.kids]\ndisplay_name = \"Kids\"\n").unwrap();

        let archive = run_backup(&config, None).unwrap();
        std::fs::remove_file(&extra).unwrap();
        std::fs::write(&config, b"garbage = true\n").unwrap();

        assert_eq!(run_restore(&config, &archive, None).unwrap(), 0);
        assert!(
            extra.exists(),
            "a top-level include FILE was captured but not reinstalled"
        );
        let loaded = loader::load_config(&config, time::OffsetDateTime::now_utc())
            .expect("restored config must load");
        assert!(loaded.config.profiles.contains_key("kids"));
    }

    /// The install set is bounded by what the staged master DECLARES, not
    /// by what the archive happens to contain. An operator-supplied
    /// archive carrying an extra directory must not get it written into
    /// the live config tree just by being in the tarball.
    #[test]
    fn restore_does_not_promote_an_undeclared_archive_member() {
        let src = tempfile::tempdir().unwrap();
        let src_config = src.path().join("config.toml");
        std::fs::write(&src_config, BASE).unwrap();
        std::fs::create_dir(src.path().join("stowaway")).unwrap();
        std::fs::write(src.path().join("stowaway").join("x.toml"), "payload").unwrap();
        // The sweep captures it (backup is deliberately inclusive) …
        let archive = run_backup(&src_config, None).unwrap();

        let live = tempfile::tempdir().unwrap();
        let live_config = live.path().join("config.toml");
        std::fs::write(&live_config, BASE).unwrap();
        assert_eq!(run_restore(&live_config, &archive, None).unwrap(), 0);

        // … but restore promotes only what the staged master declares,
        // and BASE declares no includes.
        assert!(
            !live.path().join("stowaway").exists(),
            "an archive member no include references was written into the live config dir"
        );
    }

    #[test]
    fn restore_reinstates_the_pack_file_of_a_declared_custom_list() {
        let src = tempfile::tempdir().unwrap();
        let src_config = src.path().join("config.toml");
        std::fs::write(
            &src_config,
            format!("{BASE}\n[[custom_lists]]\nid = \"minecraft\"\n"),
        )
        .unwrap();
        std::fs::create_dir(src.path().join("packs")).unwrap();
        std::fs::write(
            src.path().join("packs").join("minecraft.txt"),
            "@@||cdn.example.com^\n",
        )
        .unwrap();
        let archive = run_backup(&src_config, None).unwrap();

        let live = tempfile::tempdir().unwrap();
        let live_config = live.path().join("config.toml");
        std::fs::write(&live_config, BASE).unwrap();
        assert_eq!(run_restore(&live_config, &archive, None).unwrap(), 0);

        let restored = live.path().join("packs").join("minecraft.txt");
        assert!(
            restored.exists(),
            "restore reinstated a master declaring a custom list without its file — \
             the daemon will refuse to start"
        );
        assert!(std::fs::read_to_string(&restored)
            .unwrap()
            .contains("cdn.example.com"));
    }

    #[test]
    fn restore_still_refuses_a_pack_file_no_entry_declares() {
        // The discipline is unchanged: only what the staged master declares
        // is promoted. Only the declaration source is new.
        let src = tempfile::tempdir().unwrap();
        let src_config = src.path().join("config.toml");
        std::fs::write(&src_config, BASE).unwrap();
        std::fs::create_dir(src.path().join("packs")).unwrap();
        std::fs::write(
            src.path().join("packs").join("stowaway.txt"),
            "@@||evil.example.com^\n",
        )
        .unwrap();
        let archive = run_backup(&src_config, None).unwrap();

        let live = tempfile::tempdir().unwrap();
        let live_config = live.path().join("config.toml");
        std::fs::write(&live_config, BASE).unwrap();
        assert_eq!(run_restore(&live_config, &archive, None).unwrap(), 0);

        assert!(
            !live.path().join("packs").join("stowaway.txt").exists(),
            "an undeclared pack file was promoted into the live config dir"
        );
    }

    #[test]
    fn restoring_an_old_master_over_live_pack_files_leaves_a_loadable_tree() {
        // The other direction: an archive predating custom lists restored
        // over a tree that has them. The restored master declares none, so
        // the leftover files are orphans — reported by lint, not fatal.
        let src = tempfile::tempdir().unwrap();
        let src_config = src.path().join("config.toml");
        std::fs::write(&src_config, BASE).unwrap();
        let archive = run_backup(&src_config, None).unwrap();

        let live = tempfile::tempdir().unwrap();
        let live_config = live.path().join("config.toml");
        std::fs::write(
            &live_config,
            format!("{BASE}\n[[custom_lists]]\nid = \"minecraft\"\n"),
        )
        .unwrap();
        std::fs::create_dir(live.path().join("packs")).unwrap();
        std::fs::write(
            live.path().join("packs").join("minecraft.txt"),
            "@@||cdn.example.com^\n",
        )
        .unwrap();

        assert_eq!(run_restore(&live_config, &archive, None).unwrap(), 0);
        crate::config::loader::load_config(&live_config, time::OffsetDateTime::now_utc())
            .expect("the restored tree must load");

        // The archive being restored predates custom lists and never
        // captured this file, so it is not recoverable if restore deletes
        // it — losing an operator-authored file to a master rollback is
        // exactly the class backup/restore exists to prevent.
        let orphan = live.path().join("packs").join("minecraft.txt");
        assert!(
            orphan.exists(),
            "restore deleted a live pack file that no include entry named — \
             the restored master no longer declares it, but the bytes are \
             still the operator's and are gone if this fails"
        );
        assert_eq!(
            std::fs::read_to_string(&orphan).unwrap(),
            "@@||cdn.example.com^\n",
            "restore must not modify a file it does not promote"
        );
    }

    #[test]
    fn restore_rejects_archive_with_invalid_staged_config() {
        // Build an archive whose master config fails validation
        // (cross-ref miss); the live file must remain untouched.
        let good_dir = tempfile::tempdir().unwrap();
        let live = good_dir.path().join("config.toml");
        std::fs::write(&live, BASE).unwrap();

        let bad_dir = tempfile::tempdir().unwrap();
        let bad_config = bad_dir.path().join("config.toml");
        std::fs::write(
            &bad_config,
            r#"schema_version = 4

[server]
default_profile = "missing-profile"

[[blocklists]]
id = "privacy-ads"
display_name = "Privacy: ads"
url = "https://lists.purge.cc/privacy/ads.txt"

[profiles.default]
display_name = "Default"

[upstream]
servers = ["192.0.2.1:53"]
"#,
        )
        .unwrap();
        let archive = run_backup(&bad_config, None).unwrap();

        let rc = run_restore(&live, &archive, None).unwrap();
        assert_eq!(rc, 1, "invalid archive must not overwrite live config");
        assert_eq!(std::fs::read_to_string(&live).unwrap(), BASE);
    }

    #[test]
    fn restore_errors_when_archive_missing() {
        let dir = tempfile::tempdir().unwrap();
        let live = dir.path().join("config.toml");
        let missing = dir.path().join("no-such-archive.tar.gz");
        let err = run_restore(&live, &missing, None);
        assert!(err.is_err());
    }

    /// The member-path safety predicate flags absolute paths and
    /// `..` traversal while leaving normal config-tree members alone.
    #[test]
    fn is_unsafe_member_path_flags_traversal_and_absolute() {
        assert!(is_unsafe_member_path("/etc/passwd"));
        assert!(is_unsafe_member_path("../escape.toml"));
        assert!(is_unsafe_member_path("a/../../b"));
        assert!(!is_unsafe_member_path("config.toml"));
        assert!(!is_unsafe_member_path("devices.d/laptop.toml"));
        assert!(!is_unsafe_member_path("./config.toml"));
    }

    /// A hostile archive carrying a symlink member must be rejected
    /// before extraction — a symlink can redirect a later write outside the
    /// staging root. (GNU tar stores symlinks as symlink members by default,
    /// so this reproduces the vector portably.)
    #[test]
    fn restore_rejects_archive_with_symlink_member() {
        let dir = tempfile::tempdir().unwrap();
        let payload = dir.path().join("payload");
        std::fs::create_dir(&payload).unwrap();
        std::fs::write(payload.join("config.toml"), BASE).unwrap();
        std::os::unix::fs::symlink("/etc/passwd", payload.join("evil")).unwrap();
        let archive = dir.path().join("evil.tar.gz");
        let built = std::process::Command::new("tar")
            .arg("-czf")
            .arg(&archive)
            .arg("-C")
            .arg(&payload)
            .arg(".")
            .status()
            .unwrap()
            .success();
        assert!(built, "test archive must build");

        let live = dir.path().join("config.toml");
        std::fs::write(&live, BASE).unwrap();
        // Avoid `unwrap_err` so we don't require `RestoreOutcome: Debug`.
        let err = match restore_archive(&live, &archive) {
            Ok(_) => panic!("symlink member must be rejected, but restore succeeded"),
            Err(e) => e,
        };
        assert!(
            err.to_string().contains("symlink"),
            "symlink member must be rejected: {err}"
        );
        // The live config must be untouched (rejected before any swap).
        assert_eq!(std::fs::read_to_string(&live).unwrap(), BASE);
    }

    /// A failure during the Phase B *rename* (the only
    /// destructive window) must roll the whole swap back — every live
    /// `.d/` left byte-identical to its pre-restore content and no
    /// transient side path leaked into the config dir.
    #[test]
    fn install_include_entries_rolls_back_on_phase_b_failure() {
        let live = tempfile::tempdir().unwrap();
        let staged = tempfile::tempdir().unwrap();
        for d in ["devices.d", "profiles.d"] {
            let p = live.path().join(d);
            std::fs::create_dir(&p).unwrap();
            std::fs::write(p.join("e.toml"), format!("original-{d}")).unwrap();
            let s = staged.path().join(d);
            std::fs::create_dir(&s).unwrap();
            std::fs::write(s.join("e.toml"), format!("new-{d}")).unwrap();
        }

        // Inject a Phase B failure on the SECOND dir's promotion (the
        // `incoming → live_sub` rename whose target is `…/profiles.d`).
        // The aside rename (target `…/.profiles.d.pre-restore-…`) and
        // every devices.d rename run for real.
        let root = File::open(live.path()).unwrap();
        let meta = root.metadata().unwrap();
        let mut swap = prepare_include_entries(
            &mut Vec::new(),
            staged.path(),
            &root,
            live.path(),
            &["devices.d".to_string(), "profiles.d".to_string()],
            (meta.uid(), meta.gid()),
        )
        .unwrap();
        let res = swap.promote(&root, |from_parent, from, to_parent, to| {
            if to == OsStr::new("profiles.d") {
                return Err(std::io::Error::other("injected"));
            }
            rename_noreplace_at(from_parent, from, to_parent, to)
        });
        assert!(
            res.is_err(),
            "injected Phase B failure must surface as an error"
        );
        swap.rollback(&root).unwrap();

        for d in ["devices.d", "profiles.d"] {
            let got = std::fs::read_to_string(live.path().join(d).join("e.toml")).unwrap();
            assert_eq!(got, format!("original-{d}"), "{d} must be rolled back");
        }
        for entry in std::fs::read_dir(live.path()).unwrap() {
            let name = entry.unwrap().file_name().to_string_lossy().into_owned();
            assert!(
                !name.contains(".incoming-") && !name.contains(".pre-restore-"),
                "leftover swap artifact in config dir: {name}"
            );
        }
    }

    #[test]
    fn rollback_preserves_a_replacement_at_a_promoted_name() {
        let live = tempfile::tempdir().unwrap();
        let staged = tempfile::tempdir().unwrap();
        for name in ["devices.d", "profiles.d"] {
            std::fs::create_dir(live.path().join(name)).unwrap();
            std::fs::write(live.path().join(name).join("entry.toml"), "old").unwrap();
            std::fs::create_dir(staged.path().join(name)).unwrap();
            std::fs::write(staged.path().join(name).join("entry.toml"), "new").unwrap();
        }
        let root = File::open(live.path()).unwrap();
        let meta = root.metadata().unwrap();
        let mut swap = prepare_include_entries(
            &mut Vec::new(),
            staged.path(),
            &root,
            live.path(),
            &["devices.d".to_string(), "profiles.d".to_string()],
            (meta.uid(), meta.gid()),
        )
        .unwrap();
        let visible_root = live.path().to_path_buf();
        let error = swap
            .promote(&root, |from_parent, from, to_parent, to| {
                if to == OsStr::new("profiles.d") {
                    std::fs::remove_dir_all(visible_root.join("devices.d"))?;
                    std::fs::write(visible_root.join("devices.d"), "replacement")?;
                    return Err(std::io::Error::other("injected"));
                }
                rename_noreplace_at(from_parent, from, to_parent, to)
            })
            .unwrap_err();
        assert!(error.to_string().contains("promoting staged include"));
        assert!(swap.rollback(&root).is_err());
        assert_eq!(
            std::fs::read_to_string(live.path().join("devices.d")).unwrap(),
            "replacement",
            "rollback must not delete an inode it did not create"
        );
        assert_eq!(
            std::fs::read_to_string(live.path().join("profiles.d/entry.toml")).unwrap(),
            "old"
        );
    }

    #[test]
    fn promotion_refuses_replaced_incoming_entries_and_reports_each_artifact() {
        let live = tempfile::tempdir().unwrap();
        let staged = tempfile::tempdir().unwrap();
        for name in ["devices.d", "profiles.d"] {
            std::fs::create_dir(live.path().join(name)).unwrap();
            std::fs::write(live.path().join(name).join("entry.toml"), "old").unwrap();
            std::fs::create_dir(staged.path().join(name)).unwrap();
            std::fs::write(staged.path().join(name).join("entry.toml"), "new").unwrap();
        }
        let root = File::open(live.path()).unwrap();
        let metadata = root.metadata().unwrap();
        let mut swap = prepare_include_entries(
            &mut Vec::new(),
            staged.path(),
            &root,
            live.path(),
            &["devices.d".to_string(), "profiles.d".to_string()],
            (metadata.uid(), metadata.gid()),
        )
        .unwrap();
        let incoming = swap
            .prepared
            .iter()
            .map(|item| item.incoming.clone())
            .collect::<Vec<_>>();
        for name in &incoming {
            std::fs::remove_dir_all(live.path().join(name)).unwrap();
            std::fs::write(live.path().join(name), "replacement").unwrap();
        }

        let error = swap
            .promote(&root, rename_noreplace_at)
            .expect_err("a replaced incoming inode must not be promoted");
        assert!(error.to_string().contains("changed before promotion"));
        for name in ["devices.d", "profiles.d"] {
            assert_eq!(
                std::fs::read_to_string(live.path().join(name).join("entry.toml")).unwrap(),
                "old"
            );
        }

        let artifacts = swap.recovery_artifacts(&root, live.path()).join("; ");
        let cleanup = swap.cleanup_incoming(&root).unwrap_err().to_string();
        for name in incoming {
            let name = name.to_string_lossy();
            assert!(artifacts.contains(name.as_ref()), "{artifacts}");
            assert!(artifacts.contains("replacement preserved"), "{artifacts}");
            assert!(cleanup.contains(name.as_ref()), "{cleanup}");
        }
    }

    #[test]
    fn production_include_copy_normalizes_modes_and_refuses_symlinks() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let staged = tempfile::tempdir().unwrap();
        let source = staged.path().join("entry.toml");
        std::fs::write(&source, "value = true\n").unwrap();
        std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o666)).unwrap();
        let live = tempfile::tempdir().unwrap();
        let root = File::open(live.path()).unwrap();
        let meta = root.metadata().unwrap();
        let owner = (meta.uid(), meta.gid());

        copy_staged_entry_at(&source, &root, OsStr::new("incoming.toml"), owner).unwrap();
        assert_eq!(
            std::fs::metadata(live.path().join("incoming.toml"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o640
        );

        let link = staged.path().join("link.toml");
        symlink(&source, &link).unwrap();
        assert!(copy_staged_entry_at(&link, &root, OsStr::new("link.toml"), owner).is_err());
        assert!(!live.path().join("link.toml").exists());
    }

    /// Mirror semantics: a successful swap makes the live `.d/`
    /// equal to the archive — a file the operator hand-dropped that is
    /// absent from the archive is removed (whole-dir replacement).
    #[test]
    fn install_include_entries_mirror_drops_unmanaged_files() {
        let live = tempfile::tempdir().unwrap();
        let staged = tempfile::tempdir().unwrap();
        let live_d = live.path().join("devices.d");
        std::fs::create_dir(&live_d).unwrap();
        std::fs::write(live_d.join("managed.toml"), "v1").unwrap();
        std::fs::write(live_d.join("hand-dropped.toml"), "operator").unwrap();
        let staged_d = staged.path().join("devices.d");
        std::fs::create_dir(&staged_d).unwrap();
        std::fs::write(staged_d.join("managed.toml"), "v2").unwrap();

        let root = File::open(live.path()).unwrap();
        let meta = root.metadata().unwrap();
        let mut swap = prepare_include_entries(
            &mut Vec::new(),
            staged.path(),
            &root,
            live.path(),
            &["devices.d".to_string()],
            (meta.uid(), meta.gid()),
        )
        .unwrap();
        swap.promote(&root, rename_noreplace_at).unwrap();
        swap.finalize(&root).unwrap();

        assert_eq!(
            std::fs::read_to_string(live_d.join("managed.toml")).unwrap(),
            "v2"
        );
        assert!(
            !live_d.join("hand-dropped.toml").exists(),
            "mirror semantics: unmanaged file must be removed by restore"
        );
    }

    // ── archive member type + restored perms ─────────────

    #[test]
    fn restore_rejects_archive_with_fifo_member() {
        // A FIFO (`p`) member must be rejected by the pre-extraction scan —
        // a blacklist that only catches symlink/hardlink lets special
        // files through.
        let dir = tempfile::tempdir().unwrap();
        let payload = dir.path().join("payload");
        std::fs::create_dir(&payload).unwrap();
        std::fs::write(payload.join("config.toml"), BASE).unwrap();
        let fifo = payload.join("evil.fifo");
        let cpath = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        let rc = unsafe { libc::mkfifo(cpath.as_ptr(), 0o644) };
        assert_eq!(rc, 0, "mkfifo must succeed for the test");

        let archive = dir.path().join("fifo.tar.gz");
        let built = std::process::Command::new("tar")
            .arg("-czf")
            .arg(&archive)
            .arg("-C")
            .arg(&payload)
            .arg(".")
            .status()
            .unwrap()
            .success();
        assert!(built, "test archive must build");

        let live = dir.path().join("config.toml");
        std::fs::write(&live, BASE).unwrap();
        let err = match restore_archive(&live, &archive) {
            Ok(_) => panic!("fifo member must be rejected, but restore succeeded"),
            Err(e) => e,
        };
        assert!(
            err.to_string().contains("not a regular file or directory"),
            "fifo member must be rejected: {err}"
        );
        assert_eq!(std::fs::read_to_string(&live).unwrap(), BASE);
    }

    #[test]
    fn staging_dir_create_in_is_0700_and_under_parent() {
        use std::os::unix::fs::PermissionsExt;
        // `migrate.rs` reuses this to stage on the target filesystem: a
        // CSPRNG-named 0o700 dir under the given parent, never a fixed name.
        let parent = tempfile::tempdir().unwrap();
        let s = StagingDir::create_in(parent.path()).unwrap();
        assert!(
            s.path().starts_with(parent.path()),
            "staging must be under the given parent"
        );
        let mode = std::fs::metadata(s.path()).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode, 0o700, "staging dir must be 0o700");
        let name = s.path().file_name().unwrap().to_string_lossy().into_owned();
        assert!(name.starts_with("purge-warden-stage-"), "name: {name}");
        assert_ne!(name, ".staging", "must not use the old predictable name");
    }

    // ── PID validation before SIGHUP ────────────────────────
    //
    // A corrupt/hostile PID file must never reach `libc::kill` with a value
    // that could broadcast (`-1`, `0`, a negative, or a value that wraps
    // negative through `as i32`). These drive the private helper directly with
    // a temp PID file and assert it errors *without* signalling. The
    // happy-path delivery (valid + flock-held → real SIGHUP) is covered by the
    // `pid::pid_file_is_locked` unit tests and by CT-smoke against a live
    // daemon — signalling self in-process would terminate the test runner.

    fn write_pidfile(contents: &str) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("daemon.pid");
        std::fs::write(&path, contents).unwrap();
        (dir, path)
    }

    #[test]
    fn send_sighup_refuses_negative_pid() {
        let (_d, p) = write_pidfile("-1");
        // `-1` is rejected at the u32 parse, long before any kill.
        assert!(send_sighup_from_pid(&p).is_err());
    }

    #[test]
    fn send_sighup_refuses_zero_pid() {
        let (_d, p) = write_pidfile("0");
        let err = send_sighup_from_pid(&p).unwrap_err();
        assert!(
            err.to_string().contains("out of range"),
            "0 must be refused as out of range: {err}"
        );
    }

    #[test]
    fn send_sighup_refuses_out_of_range_pid() {
        // Parses as u32 but exceeds i32::MAX → would wrap negative through
        // `as i32` → must be refused.
        let (_d, p) = write_pidfile("3000000000");
        let err = send_sighup_from_pid(&p).unwrap_err();
        assert!(
            err.to_string().contains("out of range"),
            "value > i32::MAX must be refused: {err}"
        );
    }

    #[test]
    fn send_sighup_refuses_garbage_pid() {
        let (_d, p) = write_pidfile("not-a-number");
        assert!(send_sighup_from_pid(&p).is_err());
    }

    #[test]
    fn send_sighup_refuses_empty_pid() {
        let (_d, p) = write_pidfile("");
        assert!(send_sighup_from_pid(&p).is_err());
    }

    #[test]
    fn send_sighup_refuses_trailing_junk_pid() {
        let (_d, p) = write_pidfile("1234 evil");
        assert!(send_sighup_from_pid(&p).is_err());
    }

    #[test]
    fn send_sighup_skips_unlocked_pid_file() {
        // A syntactically valid, in-range PID whose file is NOT flock-held is
        // stale: the liveness gate must skip the signal rather than risk
        // hitting a reused PID. Use our own PID (definitely alive, but the
        // plain file carries no lock) so the value guard passes and only the
        // flock gate trips.
        let (_d, p) = write_pidfile(&std::process::id().to_string());
        let err = send_sighup_from_pid(&p).unwrap_err();
        assert!(
            err.to_string().contains("not held by a running daemon"),
            "unlocked PID file must be skipped: {err}"
        );
    }

    // ── staged-master selection ─────────────────────────────────────

    /// `backup.rs`'s sweep captures every non-dot top-level entry, so a
    /// real archive carries `secrets.toml` beside the master. When the
    /// live master has a different name — the precise case this fallback
    /// exists for — `secrets.toml` was an equally valid pick, and
    /// `read_dir` order decided. It sorts before `config.toml`, so the old
    /// unordered scan could hand a recovery tool the secrets file and
    /// report validator errors about it mid-incident.
    #[test]
    fn the_staged_master_fallback_never_picks_secrets_toml() {
        let staging = tempfile::tempdir().unwrap();
        std::fs::write(staging.path().join("config.toml"), "schema_version = 4\n").unwrap();
        std::fs::write(staging.path().join("secrets.toml"), "token = \"x\"\n").unwrap();
        // Live master named something else, so the direct hit misses and
        // the fallback runs.
        let live = staging.path().join("warden.toml");

        let picked = locate_staged_master(staging.path(), &live).unwrap();
        assert_eq!(
            picked.file_name().unwrap(),
            "config.toml",
            "the secrets file is never a master"
        );
    }

    /// Multiple unhinted root TOMLs are ambiguous; sorting only stabilizes
    /// the diagnostic and never chooses what gets installed.
    #[test]
    fn the_staged_master_fallback_refuses_ambiguity() {
        let staging = tempfile::tempdir().unwrap();
        for name in ["zulu.toml", "alpha.toml", "mike.toml"] {
            std::fs::write(staging.path().join(name), "schema_version = 4\n").unwrap();
        }
        let live = staging.path().join("warden.toml");

        let error = locate_staged_master(staging.path(), &live).unwrap_err();
        let message = error.to_string();
        assert!(message.contains("ambiguous staged archive"), "{message}");
        assert!(message.contains("alpha.toml"), "{message}");
    }

    /// The direct name match still wins — the fallback must not have
    /// become the only path.
    #[test]
    fn the_staged_master_prefers_the_live_masters_own_name() {
        let staging = tempfile::tempdir().unwrap();
        std::fs::write(staging.path().join("alpha.toml"), "schema_version = 4\n").unwrap();
        std::fs::write(staging.path().join("warden.toml"), "schema_version = 4\n").unwrap();
        let live = staging.path().join("warden.toml");

        let picked = locate_staged_master(staging.path(), &live).unwrap();
        assert_eq!(picked.file_name().unwrap(), "warden.toml");
    }

    #[test]
    fn the_staged_master_accepts_a_safe_exact_non_toml_name() {
        let staging = tempfile::tempdir().unwrap();
        std::fs::write(staging.path().join("warden.conf"), "schema_version = 4\n").unwrap();
        std::fs::write(staging.path().join("other.toml"), "schema_version = 4\n").unwrap();
        let live = staging.path().join("warden.conf");

        let picked = locate_staged_master(staging.path(), &live).unwrap();
        assert_eq!(picked.file_name().unwrap(), "warden.conf");
    }

    // ── a declared include the archive does not contain ──────────────

    /// The archive's master declares `devices.d/` and the archive does
    /// not populate it. The live directory then survives untouched while
    /// the restored master still globs it, so every device the operator
    /// removed before taking the backup comes back — and the command
    /// reported success in silence.
    ///
    /// Replacing the live directory would delete operator config, so this
    /// pins the warning rather than the deletion; the mirror-semantics
    /// repair is a separate, destructive decision.
    #[test]
    fn a_declared_but_absent_include_entry_is_reported_not_skipped_silently() {
        let live = tempfile::tempdir().unwrap();
        let staged = tempfile::tempdir().unwrap();
        let live_d = live.path().join("devices.d");
        std::fs::create_dir(&live_d).unwrap();
        std::fs::write(live_d.join("kid-tablet.toml"), "removed before backup").unwrap();
        // `staged/devices.d` deliberately absent.

        let mut notices: Vec<u8> = Vec::new();
        let root = File::open(live.path()).unwrap();
        let meta = root.metadata().unwrap();
        let mut swap = prepare_include_entries(
            &mut notices,
            staged.path(),
            &root,
            live.path(),
            &["devices.d".to_string()],
            (meta.uid(), meta.gid()),
        )
        .unwrap();
        swap.promote(&root, rename_noreplace_at).unwrap();
        swap.finalize(&root).unwrap();

        let seen = String::from_utf8(notices).unwrap();
        assert!(
            seen.contains("devices.d"),
            "the un-mirrored entry must be named: {seen:?}"
        );
        assert!(
            live_d.join("kid-tablet.toml").exists(),
            "this fix warns; it does not delete live config"
        );
    }

    /// Negative control: an entry the archive DOES contain is promoted
    /// silently. Without this, a warning emitted unconditionally would
    /// satisfy the test above.
    #[test]
    fn a_populated_include_entry_is_promoted_without_a_warning() {
        let live = tempfile::tempdir().unwrap();
        let staged = tempfile::tempdir().unwrap();
        let staged_d = staged.path().join("devices.d");
        std::fs::create_dir(&staged_d).unwrap();
        std::fs::write(staged_d.join("kid-tablet.toml"), "v2").unwrap();

        let mut notices: Vec<u8> = Vec::new();
        let root = File::open(live.path()).unwrap();
        let meta = root.metadata().unwrap();
        let mut swap = prepare_include_entries(
            &mut notices,
            staged.path(),
            &root,
            live.path(),
            &["devices.d".to_string()],
            (meta.uid(), meta.gid()),
        )
        .unwrap();
        swap.promote(&root, rename_noreplace_at).unwrap();
        swap.finalize(&root).unwrap();

        assert!(
            notices.is_empty(),
            "a mirrored entry needs no warning: {:?}",
            String::from_utf8(notices).unwrap()
        );
        assert_eq!(
            std::fs::read_to_string(live.path().join("devices.d/kid-tablet.toml")).unwrap(),
            "v2"
        );
    }
}
