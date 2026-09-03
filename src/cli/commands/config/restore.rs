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
//!    sibling `*.d/` directory, move the previous master aside as
//!    `<name>.pre-restore-<ts>` for trivial rollback.
//! 5. Optionally send `SIGHUP` to the running daemon (via its PID file)
//!    so the swap is observable without a manual restart.
//!
//! Failure at step 3 leaves the live tree untouched and returns a
//! non-zero exit code. The staging directory is dropped on exit.

use std::io::Write;
use std::path::{Path, PathBuf};

use crate::config::atomic_write::atomic_write_and_validate;
use crate::config::loader;

use super::TIMESTAMP_FORMAT;

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

    let live_parent = live_config.parent().ok_or_else(|| {
        anyhow::anyhow!(
            "live config {} has no parent directory",
            live_config.display()
        )
    })?;
    std::fs::create_dir_all(live_parent).ok();

    // Save the previous master with a `.pre-restore-<ts>` suffix so the
    // operator has a trivial rollback path — and so we can roll the
    // master back if the include-dir swap below fails.
    let pre_restore_master: Option<PathBuf> = if live_config.exists() {
        let ts = time::OffsetDateTime::now_utc()
            .format(&TIMESTAMP_FORMAT)
            .map_err(|e| anyhow::anyhow!("failed to format timestamp: {}", e))?;
        // Bump the name on a same-second collision so a rapid restore retry
        // can't silently clobber the rollback copy it just wrote.
        let backup = crate::cli::commands::make_unique_path(
            live_config.with_extension(format!("toml.pre-restore-{ts}")),
        );
        std::fs::rename(live_config, &backup)
            .map_err(|e| anyhow::anyhow!("cannot move {} aside: {}", live_config.display(), e))?;
        Some(backup)
    } else {
        None
    };

    // Atomic install: read the staged master once, then write-temp +
    // validate + rename into place. Rename is atomic on POSIX within a
    // single filesystem; the temp + validate sequence guarantees that a
    // mid-operation crash never exposes a partially-written master to the
    // next reader. The validator here is a cheap TOML parse — the full
    // cross-reference load already ran above against `staged_master`;
    // re-running it after the copy would fail in the split-file layout
    // until the sibling `.d/` directories are swapped below, and the
    // upstream validation is the authoritative gate for installation
    // anyway.
    let staged_bytes = std::fs::read_to_string(&staged_master).map_err(|e| {
        anyhow::anyhow!(
            "cannot read staged master {}: {}",
            staged_master.display(),
            e
        )
    })?;
    atomic_write_and_validate(
        live_config,
        &staged_bytes,
        |staged: &Path| -> Result<(), String> {
            let raw = std::fs::read_to_string(staged).map_err(|e| e.to_string())?;
            raw.parse::<toml::Value>()
                .map(|_| ())
                .map_err(|e| e.to_string())
        },
    )
    .map_err(|e| {
        anyhow::anyhow!(
            "failed to install staged config at {}: {}",
            live_config.display(),
            e
        )
    })?;

    // Swap each include entry the staged config declares. The swap is
    // crash-safe: staged entries are copied to side paths first
    // (non-destructive), then promoted via metadata-only renames with
    // full rollback on failure. See `install_include_entries`.
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
    if let Err(e) = install_include_entries(
        &mut std::io::stderr(),
        staged_root,
        live_parent,
        &include_entries,
        copy_dir_recursive,
        |from, to| std::fs::rename(from, to),
    ) {
        // Roll the master back so we never leave a post-restore master
        // paired with the pre-restore `.d/` — an inconsistent window this
        // restore must never produce. Best-effort: if the rollback rename itself
        // fails, the master's `.pre-restore-<ts>` aside is still on disk
        // for manual recovery.
        if let Some(prev) = &pre_restore_master {
            if let Err(re) = std::fs::rename(prev, live_config) {
                return Err(e.context(format!(
                    "include-dir swap failed and master rollback also failed ({re}); \
                     recover the master manually from {}",
                    prev.display()
                )));
            }
        }
        return Err(e.context(aborted_restore_context(pre_restore_master.as_ref())));
    }

    Ok(RestoreOutcome::Restored {
        pre_restore: pre_restore_master,
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
    // fail-fast on obviously-hostile archives; copy_dir_recursive re-checks the
    // actually-extracted bytes as the authoritative, TOCTOU-immune gate.
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

/// What to tell the operator when the include swap failed and the
/// restore was abandoned.
///
/// `pre_restore_master` is `None` whenever there was no live master to
/// begin with — a rebuild, or a fresh install being seeded from a backup.
/// In that case the new master has already been installed by the atomic
/// write above, nothing was rolled back, and the tree is half-swapped. On
/// a recovery tool a false claim about the tree's state is worse than the
/// failure it reports: it tells the operator not to look at exactly the
/// thing they must now inspect.
fn aborted_restore_context(pre_restore_master: Option<&PathBuf>) -> &'static str {
    match pre_restore_master {
        Some(_) => "restore aborted; live config rolled back",
        None => {
            "restore aborted; the new master is installed but its include \
                 entries are NOT — remove it or re-run the restore"
        }
    }
}

/// Find the staged master config by matching the live master's file
/// name inside the staged tree. Falls back to the lexicographically
/// first non-secrets `*.toml` at the staging root.
fn locate_staged_master(staging: &Path, live_config: &Path) -> anyhow::Result<PathBuf> {
    let name = live_config
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("live config has no file name"))?;
    let direct = staging.join(name);
    if direct.exists() {
        return Ok(direct);
    }
    // Fallback: the archive may have been produced with a different master
    // name. `read_dir` order is filesystem-dependent, so the candidates are
    // sorted — taking the first unordered hit let the same archive restore
    // on one run and fail validation on the next, on two hosts or on two
    // attempts, in the middle of an incident.
    //
    // `secrets.toml` is excluded by name rather than by luck: `backup.rs`'s
    // sweep captures every non-dot top-level entry, so a real archive always
    // carries it beside the master. It is a candidate here and never a
    // master, and picking it hands the operator validator errors about a
    // secrets file while they are trying to restore a config.
    let mut candidates: Vec<PathBuf> = std::fs::read_dir(staging)?
        .filter_map(Result::ok)
        .filter(|e| e.file_type().map(|t| t.is_file()).unwrap_or(false))
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "toml"))
        .filter(|p| {
            p.file_name().and_then(|n| n.to_str()) != Some(crate::config::secrets::SECRETS_FILENAME)
        })
        .collect();
    candidates.sort();
    if let Some(first) = candidates.into_iter().next() {
        return Ok(first);
    }
    anyhow::bail!(
        "no master *.toml found in staged archive at {}",
        staging.display()
    )
}

pub(crate) fn copy_dir_recursive(src: &Path, dst: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    // Create the destination at 0o750 rather than the umask default so a
    // restored `.d/` tree can't end up world-listable. recursive(true) makes
    // this a no-op on an existing dir (like create_dir_all), applying the mode
    // only to dirs we actually create.
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o750)
        .create(dst)
        .map_err(|e| anyhow::anyhow!("cannot create {}: {}", dst.display(), e))?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        // `file_type()` is lstat-based (does NOT follow symlinks), so it sees
        // the member as it actually landed in the staging tree. This is the
        // TOCTOU-immune gate: whatever the pre-extraction archive scan missed
        // (or a swapped archive slipped past), we re-check the *extracted*
        // bytes and refuse anything that isn't a plain file or directory — a
        // symlink/fifo/device/socket here could redirect the copy outside the
        // live tree (fs::copy follows symlinks) or hang it.
        let ft = entry.file_type()?;
        if ft.is_dir() {
            copy_dir_recursive(&src_path, &dst_path)?;
        } else if ft.is_file() {
            std::fs::copy(&src_path, &dst_path)?;
            // Normalise to the house DEFAULT_TARGET_MODE instead of trusting
            // the archive's stored bits (a crafted/lax-umask backup could carry
            // 0o644/0o666 device-inventory slices).
            std::fs::set_permissions(&dst_path, std::fs::Permissions::from_mode(0o640))
                .map_err(|e| anyhow::anyhow!("cannot set mode on {}: {}", dst_path.display(), e))?;
        } else {
            anyhow::bail!(
                "refusing to restore {}: not a regular file or directory \
                 (symlink/device/fifo/socket members are rejected)",
                src_path.display()
            );
        }
    }
    Ok(())
}

/// Same-directory side-path name for a transient `.d/` swap artifact,
/// unique across concurrent restores in this process (pid + a
/// process-local counter — a wall-clock timestamp at second resolution
/// would collide on a same-second retry, the lesson `StagingDir::create`
/// already learned). The leading `.` plus a non-`.d` suffix keeps it out
/// of the `*.d/` include glob, so a mid-swap reader never mistakes it for
/// live config.
fn swap_side_path(live_parent: &Path, dir: &str, kind: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let pid = std::process::id();
    let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
    live_parent.join(format!(".{dir}.{kind}-{pid}-{seq}"))
}

/// Crash-safe replacement of the live include entries with the staged
/// copies. A two-phase transaction:
///
/// * **Phase A (non-destructive):** copy each staged entry into a fresh
///   same-directory `…incoming…` side path. The live tree is untouched,
///   so a failure here aborts with the live includes fully intact.
/// * **Phase B (metadata-only):** for each prepared entry, rename the
///   live one aside to `…pre-restore…`, then rename the incoming into
///   place. These are intra-filesystem renames (microseconds), shrinking
///   the crash window from the whole recursive copy down to two
///   `rename(2)`s.
///
/// On any Phase B failure the transaction rolls back — promoted entries
/// are dropped and every aside renamed back — leaving the live tree
/// exactly as it was so the caller can roll the master back too.
///
/// **Mirror semantics:** a restored include directory ends up equal to
/// the archive; a file an operator hand-dropped into the live `.d/` that
/// is absent from the archive is removed (whole-dir replacement). (Contrast
/// `migrate.rs::promote_recursive`, which deliberately chose file-granular
/// *overlay* so unmanaged files survive a migration.)
///
/// Entries are derived from the staged config's own includes rather than
/// a hardcoded `<class>.d` list, so an entry can be a plain FILE —
/// `includes = ["extra.toml"]` is legal, and backup captures it. Dropping
/// it here would have made a capturable include un-restorable, which is
/// the same silent omission one layer down.
///
/// `copy` / `rename` are injectable so the regression test can force a
/// Phase B `rename` failure and assert the rollback restores the live
/// tree; production passes [`copy_dir_recursive`] and [`std::fs::rename`].
/// `notices` carries operator warnings — stderr in production, a buffer in
/// tests. It is a sink rather than a `tracing` event because no CLI
/// dispatch installs a global subscriber, so a `tracing` warning on this
/// path would reach nobody.
fn install_include_entries<C, R>(
    notices: &mut dyn Write,
    staged_root: &Path,
    live_parent: &Path,
    entries: &[String],
    copy: C,
    rename: R,
) -> anyhow::Result<()>
where
    C: Fn(&Path, &Path) -> anyhow::Result<()>,
    R: Fn(&Path, &Path) -> std::io::Result<()>,
{
    // Phase A — stage every present entry into a side path. Pure additive;
    // the live tree is not touched until Phase B.
    let mut prepared: Vec<(PathBuf, PathBuf)> = Vec::new(); // (incoming, live_sub)
    for entry in entries {
        let staged_sub = staged_root.join(entry);
        // `symlink_metadata` (lstat) so a symlinked entry is seen as a
        // symlink and rejected below, not silently followed.
        let meta = match std::fs::symlink_metadata(&staged_sub) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // The staged master DECLARES this entry and the archive
                // does not populate it. The live directory of that name is
                // then left exactly as it was while the restored master
                // still globs it — so devices the operator removed before
                // taking the backup come back, against the mirror
                // semantics documented above. Replacing it with an empty
                // directory would delete live operator config, which is a
                // decision to take deliberately and not here; what this
                // must not do is be silent about it.
                let _ = writeln!(
                    notices,
                    "warning: the restored config declares include entry {entry}, which the \
                     archive does not contain; {} is left as it stands and may still hold \
                     entries the archive does not",
                    live_parent.join(entry).display()
                );
                continue;
            }
            Err(e) => {
                // Anything other than "absent" — EACCES, ENOTDIR — was
                // swallowed by the same skip, so an unreadable staged entry
                // silently produced a half-restored tree reported as success.
                for (inc, _) in &prepared {
                    remove_any(inc);
                }
                return Err(
                    anyhow::Error::from(e).context(format!("staging include entry {entry}"))
                );
            }
        };
        let incoming = swap_side_path(live_parent, entry, "incoming");
        let staged_result = if meta.is_dir() {
            copy(&staged_sub, &incoming)
        } else if meta.is_file() {
            copy_regular_file(&staged_sub, &incoming)
        } else {
            Err(anyhow::anyhow!(
                "refusing to restore {}: not a regular file or directory \
                 (symlink/device/fifo/socket members are rejected)",
                staged_sub.display()
            ))
        };
        if let Err(e) = staged_result {
            remove_any(&incoming);
            for (inc, _) in &prepared {
                remove_any(inc);
            }
            return Err(e.context(format!("staging include entry {entry}")));
        }
        prepared.push((incoming, live_parent.join(entry)));
    }

    // Phase B — promote via renames, recording undo state.
    let mut asides: Vec<(PathBuf, PathBuf)> = Vec::new(); // (aside, live_sub)
    let mut promoted: Vec<PathBuf> = Vec::new(); // live_subs now holding new content
    for (incoming, live_sub) in &prepared {
        if live_sub.exists() {
            let name = live_sub.file_name().and_then(|s| s.to_str()).unwrap_or("d");
            let aside = swap_side_path(live_parent, name, "pre-restore");
            if let Err(e) = rename(live_sub, &aside) {
                rollback_include_entries(&promoted, &asides, &prepared);
                return Err(anyhow::Error::new(e)
                    .context(format!("moving live {} aside", live_sub.display())));
            }
            asides.push((aside, live_sub.clone()));
        }
        if let Err(e) = rename(incoming, live_sub) {
            rollback_include_entries(&promoted, &asides, &prepared);
            return Err(anyhow::Error::new(e)
                .context(format!("promoting include entry {}", live_sub.display())));
        }
        promoted.push(live_sub.clone());
    }

    // Phase C — success: drop the transient `…pre-restore…` asides.
    // (The master's own `.pre-restore-<ts>` stays as the rollback point.)
    for (aside, _) in &asides {
        remove_any(aside);
    }
    Ok(())
}

/// Copy one regular file to `dst`, normalising the mode to the house
/// 0o640 rather than trusting the archive's stored bits — the same policy
/// [`copy_dir_recursive`] applies to every file it copies. Used for a
/// top-level include that is a plain file.
fn copy_regular_file(src: &Path, dst: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::copy(src, dst)
        .map_err(|e| anyhow::anyhow!("cannot copy {} to {}: {e}", src.display(), dst.display()))?;
    std::fs::set_permissions(dst, std::fs::Permissions::from_mode(0o640))
        .map_err(|e| anyhow::anyhow!("cannot set mode on {}: {e}", dst.display()))
}

/// Best-effort removal of a path that may be a directory or a plain file.
/// Every caller is either cleaning up a transient side-path artifact or is
/// already on an error path, so a failure is not worth propagating — the
/// leftover `…incoming…` / `…pre-restore…` name is inert (the leading `.`
/// plus a non-`.d` suffix keeps it outside every include glob).
fn remove_any(path: &Path) {
    if std::fs::remove_dir_all(path).is_err() {
        let _ = std::fs::remove_file(path);
    }
}

/// Best-effort undo of a partially-applied Phase B swap: drop the
/// freshly-promoted entries, rename every recorded aside back over its
/// live path, and remove any leftover incomings. Best-effort because we
/// are already on an error path — an aside that cannot be renamed back is
/// left on disk as a `…pre-restore…` artifact for manual recovery.
fn rollback_include_entries(
    promoted: &[PathBuf],
    asides: &[(PathBuf, PathBuf)],
    prepared: &[(PathBuf, PathBuf)],
) {
    for live_sub in promoted {
        remove_any(live_sub);
    }
    for (aside, live_sub) in asides {
        let _ = std::fs::rename(aside, live_sub);
    }
    for (incoming, _) in prepared {
        remove_any(incoming);
    }
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

    const BASE: &str = r#"schema_version = 3

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
            "schema_version = 3\nincludes = [\"custom/*.toml\"]\n\n\
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
            "schema_version = 3\nincludes = [\"extra.toml\"]\n\n\
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
            r#"schema_version = 3

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
        let rename = |from: &Path, to: &Path| -> std::io::Result<()> {
            if to.file_name().and_then(|s| s.to_str()) == Some("profiles.d") {
                return Err(std::io::Error::other("injected"));
            }
            std::fs::rename(from, to)
        };

        let res = install_include_entries(
            &mut Vec::new(),
            staged.path(),
            live.path(),
            &["devices.d".to_string(), "profiles.d".to_string()],
            copy_dir_recursive,
            rename,
        );
        assert!(
            res.is_err(),
            "injected Phase B failure must surface as an error"
        );

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

        install_include_entries(
            &mut Vec::new(),
            staged.path(),
            live.path(),
            &["devices.d".to_string()],
            copy_dir_recursive,
            |from, to| std::fs::rename(from, to),
        )
        .unwrap();

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
    fn copy_dir_recursive_rejects_symlink_member() {
        use std::os::unix::fs::PermissionsExt;
        // A symlink that reaches the copy step (e.g. slipped past the archive
        // scan) must be refused, not silently followed by fs::copy.
        let src = tempfile::tempdir().unwrap();
        std::fs::write(src.path().join("ok.toml"), "x").unwrap();
        std::os::unix::fs::symlink("/etc/passwd", src.path().join("evil")).unwrap();
        let dst = tempfile::tempdir().unwrap();
        let dst_path = dst.path().join("out");

        let err = copy_dir_recursive(src.path(), &dst_path).unwrap_err();
        assert!(
            err.to_string().contains("not a regular file or directory"),
            "symlink member must be rejected: {err}"
        );
        // It must NOT have followed the symlink (no /etc/passwd content copied).
        if let Ok(meta) = std::fs::symlink_metadata(dst_path.join("evil")) {
            assert!(
                meta.file_type().is_symlink() || !meta.is_file(),
                "symlink must not be dereferenced into a regular copy"
            );
        }
        // Sanity: the destination dir itself was created at 0o750.
        let mode = std::fs::metadata(&dst_path).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode, 0o750, "restored dir must be 0o750");
    }

    #[test]
    fn copy_dir_recursive_normalises_file_mode_to_0640() {
        use std::os::unix::fs::PermissionsExt;
        // A world-readable slice in the source (crafted or lax-umask archive)
        // must land 0o640 after restore, not inherit the source bits.
        let src = tempfile::tempdir().unwrap();
        let sub = src.path().join("devices.d");
        std::fs::create_dir(&sub).unwrap();
        let f = sub.join("auto.toml");
        std::fs::write(&f, "id='x'").unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o666)).unwrap();

        let dst = tempfile::tempdir().unwrap();
        let out = dst.path().join("out");
        copy_dir_recursive(src.path(), &out).unwrap();

        let file_mode = std::fs::metadata(out.join("devices.d").join("auto.toml"))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777;
        assert_eq!(
            file_mode, 0o640,
            "restored file must be normalised to 0o640"
        );
        let dir_mode = std::fs::metadata(out.join("devices.d"))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777;
        assert_eq!(dir_mode, 0o750, "restored .d dir must be 0o750");
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
        std::fs::write(staging.path().join("config.toml"), "schema_version = 3\n").unwrap();
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

    /// The pick must not depend on `read_dir` order, or the same archive
    /// restores on one host and fails validation on another.
    #[test]
    fn the_staged_master_fallback_is_deterministic() {
        let staging = tempfile::tempdir().unwrap();
        for name in ["zulu.toml", "alpha.toml", "mike.toml"] {
            std::fs::write(staging.path().join(name), "schema_version = 3\n").unwrap();
        }
        let live = staging.path().join("warden.toml");

        let picked = locate_staged_master(staging.path(), &live).unwrap();
        assert_eq!(picked.file_name().unwrap(), "alpha.toml");
    }

    /// The direct name match still wins — the fallback must not have
    /// become the only path.
    #[test]
    fn the_staged_master_prefers_the_live_masters_own_name() {
        let staging = tempfile::tempdir().unwrap();
        std::fs::write(staging.path().join("alpha.toml"), "schema_version = 3\n").unwrap();
        std::fs::write(staging.path().join("warden.toml"), "schema_version = 3\n").unwrap();
        let live = staging.path().join("warden.toml");

        let picked = locate_staged_master(staging.path(), &live).unwrap();
        assert_eq!(picked.file_name().unwrap(), "warden.toml");
    }

    // ── what an aborted restore claims about the tree ────────────────

    /// With no prior master there is nothing to roll back to: the new one
    /// is already installed and only its includes are missing. Saying
    /// "rolled back" there tells the operator not to look at the one tree
    /// they must now inspect.
    #[test]
    fn an_aborted_restore_onto_a_bare_host_does_not_claim_a_rollback() {
        let msg = aborted_restore_context(None);
        assert!(
            !msg.contains("rolled back"),
            "nothing was rolled back: {msg:?}"
        );
        assert!(
            msg.contains("installed") && msg.contains("NOT"),
            "the operator must be told the tree is half-swapped: {msg:?}"
        );
    }

    /// Negative control: where a rollback did happen, it is still
    /// reported as one.
    #[test]
    fn an_aborted_restore_over_an_existing_master_still_reports_the_rollback() {
        let prev = PathBuf::from("/tmp/config.toml.pre-restore-1");
        assert_eq!(
            aborted_restore_context(Some(&prev)),
            "restore aborted; live config rolled back"
        );
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
        install_include_entries(
            &mut notices,
            staged.path(),
            live.path(),
            &["devices.d".to_string()],
            copy_dir_recursive,
            |from, to| std::fs::rename(from, to),
        )
        .unwrap();

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
        install_include_entries(
            &mut notices,
            staged.path(),
            live.path(),
            &["devices.d".to_string()],
            copy_dir_recursive,
            |from, to| std::fs::rename(from, to),
        )
        .unwrap();

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

    /// The old `let Ok(meta) = … else { continue }` swallowed EACCES and
    /// ENOTDIR too, so an unreadable staged entry produced a half-restored
    /// tree reported as success. Only "absent" may be non-fatal.
    ///
    /// `staged/plain.toml` is a regular file, so `staged/plain.toml/inner`
    /// fails with ENOTDIR rather than NotFound.
    #[test]
    fn a_staged_entry_that_is_unreadable_for_any_other_reason_is_fatal() {
        let live = tempfile::tempdir().unwrap();
        let staged = tempfile::tempdir().unwrap();
        std::fs::write(staged.path().join("plain.toml"), "x").unwrap();

        let mut notices: Vec<u8> = Vec::new();
        let res = install_include_entries(
            &mut notices,
            staged.path(),
            live.path(),
            &["plain.toml/inner".to_string()],
            copy_dir_recursive,
            |from, to| std::fs::rename(from, to),
        );
        assert!(
            res.is_err(),
            "a non-NotFound stat failure must not be skipped"
        );
    }
}
