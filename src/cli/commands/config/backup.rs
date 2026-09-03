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
//! Coverage is now the UNION of two sources:
//!
//! 1. a sweep of the config directory ([`sweep_config_dir`]), and
//! 2. the include graph the loader actually resolved
//!    ([`crate::config::loader::LoadedConfig::files_loaded`], reduced to
//!    top-level entries by [`include_roots`]).
//!
//! Neither alone is right. The sweep alone misses a declared include
//! whose name begins with `.` and cannot notice a file resolved outside
//! the config directory. The graph alone drops an undeclared `devices.d/`
//! the operator would still expect back.
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
//! parent directory is created with mode 0755 if missing.

use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::config::atomic_write::{hardened_atomic_write, AtomicWriteOpts};

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
pub(crate) fn include_roots(root: &Path, files_loaded: &[PathBuf]) -> anyhow::Result<Vec<String>> {
    let root_canonical = root
        .canonicalize()
        .map_err(|e| anyhow::anyhow!("cannot resolve config directory {}: {e}", root.display()))?;

    let mut out: Vec<String> = Vec::new();
    for file in files_loaded {
        let rel = file.strip_prefix(&root_canonical).map_err(|_| {
            anyhow::anyhow!(
                "config file {} lies outside the config directory {} and cannot be \
                 captured in a backup anchored there.\n\
                 A backup that silently omits a declared include is worse than one that \
                 refuses — move the file under the config directory, or point `--config` \
                 at a directory that contains it.",
                file.display(),
                root_canonical.display()
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

/// Every top-level entry beside the master, minus the backup output
/// directory and the transient swap artifacts `restore` leaves behind.
///
/// This is the archive's BASE coverage and runs on every backup, not a
/// fallback for a config that fails to load. The include graph is added on
/// top of it, never instead of it: for a backup the failure mode is losing
/// bytes, so the set has to be a superset of what the daemon reads.
///
/// Excluding `out_dir` is not cosmetic: without it each backup would
/// capture every previous archive, so the tree would grow geometrically.
fn sweep_config_dir(
    parent: &Path,
    out_dir: &Path,
    config_name: &str,
) -> anyhow::Result<Vec<String>> {
    let out_canonical = out_dir.canonicalize().ok();
    let mut entries = vec![config_name.to_string()];
    for entry in std::fs::read_dir(parent)
        .map_err(|e| anyhow::anyhow!("cannot read config directory {}: {e}", parent.display()))?
    {
        let entry =
            entry.map_err(|e| anyhow::anyhow!("cannot read config directory entry: {e}"))?;
        let path = entry.path();
        if out_canonical.is_some() && path.canonicalize().ok() == out_canonical {
            continue;
        }
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            // Non-UTF-8 name: cannot be passed to tar as an argument.
            // Loud, because this is the sweep path whose whole job is to
            // miss nothing.
            anyhow::bail!(
                "config directory entry {:?} is not valid UTF-8 and cannot be archived",
                entry.file_name()
            );
        };
        if name == config_name {
            continue; // already added above
        }
        // `.foo.incoming-<pid>-<n>` / `.foo.pre-restore-<pid>-<n>`: a
        // concurrent restore's half-swapped state, not operator config.
        if name.starts_with('.') {
            continue;
        }
        entries.push(name);
    }
    entries.sort();
    Ok(entries)
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

/// Open `archive` at 0600 so `tar` writes into a file that is already
/// tight.
///
/// `tar -czf` truncates an existing path in place rather than re-creating
/// it, so the mode set here is the mode the bytes land under. Creating the
/// file afterwards and chmod-ing left a umask-wide window — 0644 under a
/// default shell — during which the master's `api.token_hash`, the device
/// inventory (MACs, IPs, owner names) and `secrets.toml` were group- and
/// world-readable. A process that opens the file inside that window keeps
/// its access after the chmod, because permission is checked at `open(2)`.
/// This is the same window CLAUDE.md rules on for `fs::write` on a config
/// path, reintroduced through a subprocess where
/// `scripts/check_no_raw_fs_write.sh` cannot see it.
///
/// The systemd timer sets `UMask=0077` and so was already covered; the
/// manual `warden config backup` inherits the operator's shell umask and
/// was not.
///
/// A same-second collision stays an overwrite rather than being renamed
/// aside: [`list_backups`] recognises only `config-<ts>.tar.gz` and parses
/// the timestamp out of it, so any suffixed variant would be invisible to
/// both retention pruning and `restore`'s latest-archive lookup. A
/// silently orphaned archive is worse than the overwrite it would replace.
fn create_archive_file(archive: &Path) -> anyhow::Result<()> {
    let f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(archive)
        .map_err(|e| anyhow::anyhow!("cannot create archive {}: {e}", archive.display()))?;
    // `mode()` applies only when the file is created, and it is masked by
    // the umask besides. An archive already on that path — the same-second
    // re-run — needs the tightening spelled out, on the fd rather than the
    // path so nothing can be swapped in between.
    f.set_permissions(std::fs::Permissions::from_mode(0o600))
        .map_err(|e| anyhow::anyhow!("cannot set 0600 on archive {}: {e}", archive.display()))?;
    Ok(())
}

/// Create a tar.gz snapshot of the config tree anchored at
/// `config_path`'s parent directory, WITHOUT printing — so the TUI can
/// call it inside the alternate screen. Returns the archive path plus the
/// captured entries. The CLI wrapper [`run_backup`] prints the summary.
pub fn create_backup(config_path: &Path, out: Option<&Path>) -> anyhow::Result<BackupReport> {
    if !config_path.exists() {
        anyhow::bail!(
            "cannot back up {}: file does not exist",
            config_path.display()
        );
    }

    let parent = config_path.parent().ok_or_else(|| {
        anyhow::anyhow!(
            "config path {} has no parent directory",
            config_path.display()
        )
    })?;

    let out_dir = match out {
        Some(p) => p.to_path_buf(),
        None => parent.join("backups"),
    };
    // 0750, not the umask-default 0755: archives capture the master
    // (`api.token_hash`) plus the full `*.d/` tree (device MACs/IPs/owner
    // names), so "other" must not be able to traverse into the backups dir.
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o750)
        .create(&out_dir)
        .map_err(|e| {
            anyhow::anyhow!(
                "cannot create backup directory {}: {}",
                out_dir.display(),
                e
            )
        })?;

    let ts = time::OffsetDateTime::now_utc()
        .format(&TIMESTAMP_FORMAT)
        .map_err(|e| anyhow::anyhow!("failed to format timestamp: {}", e))?;
    let archive = out_dir.join(format!("config-{ts}.tar.gz"));

    // Compose the archive entries (relative to `parent`) from what the
    // loader actually reads — see the module doc. The master's own name
    // always leads, so a single-file install still produces a one-entry
    // archive.
    let config_name = config_path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("config path {} has no file name", config_path.display()))?
        .to_string_lossy()
        .into_owned();

    // Base coverage is a sweep of the config directory: for a BACKUP the
    // failure mode is losing bytes, so the set must be a superset. An
    // undeclared `devices.d/` beside the master is inert as far as the
    // daemon is concerned, but it is still something the operator put
    // there and would expect back.
    let mut entries = sweep_config_dir(parent, &out_dir, &config_name)?;

    // Then the declared include graph, for the two things a sweep cannot
    // do: fail loudly on a loaded file that lies outside the config
    // directory (`tar -C <parent>` cannot express it, and the sweep never
    // sees it), and reach a declared entry the sweep skips — a dotfile
    // name is legal in an `includes` glob.
    match crate::config::loader::load_config(config_path, time::OffsetDateTime::now_utc()) {
        Ok(loaded) => {
            for root in include_roots(parent, &loaded.files_loaded)? {
                if !entries.contains(&root) {
                    entries.push(root);
                }
            }
        }
        Err(errs) => {
            // A config that does not load is precisely when an operator
            // most wants a backup — they are about to hand-edit a broken
            // tree — so this is not fatal. Coverage is unaffected (the
            // sweep already captured the directory); what is lost is the
            // cross-check, and saying so beats a silent best-effort.
            eprintln!(
                "warning: {} does not currently load ({} error(s)); the archive captures \
                 {} as it stands, but its coverage was not verified against the declared \
                 includes.",
                config_path.display(),
                errs.len(),
                parent.display()
            );
            eprintln!("  first error: {}", errs[0]);
        }
    }
    entries.sort();
    entries.dedup();

    create_archive_file(&archive)?;

    // Delegate to the system `tar`. `-C <parent>` anchors the archive
    // at the config directory so the extracted tree doesn't carry the
    // absolute prefix from the build host.
    let status = std::process::Command::new("tar")
        .arg("-C")
        .arg(parent)
        .arg("-czf")
        .arg(&archive)
        .args(&entries)
        .status()
        .map_err(|e| anyhow::anyhow!("failed to run tar: {}", e))?;

    if !status.success() {
        anyhow::bail!(
            "tar exited with {status}; archive {} may be incomplete",
            archive.display()
        );
    }

    // Belt and braces. `create_archive_file` already opened the path at
    // 0600 and `tar` truncates in place, so this should find nothing to do
    // — but a `tar` that ever did re-create the file would silently undo
    // that, and this archive carries `api.token_hash`, the device inventory
    // and `secrets.toml`. Best-effort: a successful backup should not fail
    // over a perms tweak, but a downgrade must be visible.
    if let Err(e) = std::fs::set_permissions(&archive, std::fs::Permissions::from_mode(0o600)) {
        // stderr, not `tracing`: no CLI dispatch installs a global
        // subscriber, so a `tracing` event here reaches nobody — and this
        // warning exists precisely because the downgrade must be seen.
        // Under the systemd timer stderr is journald.
        eprintln!(
            "warning: cannot tighten backup archive perms on {} to 0600: {e} \
             (archive may be readable by others)",
            archive.display()
        );
    }

    Ok(BackupReport { archive, entries })
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

/// True for `pre-migration-<ts>.toml` and for the `-N` variant
/// `make_unique_path` produces on a same-second collision.
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
        .map(|loaded| loaded.config.backup.resolve_dir(config_path))
        .unwrap_or_else(|_| BackupConfig::default().resolve_dir(config_path))
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

    let beside_config = config_path
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

/// Held lock guard. Drop removes the lock file (best-effort).
#[derive(Debug)]
pub struct LockGuard {
    path: PathBuf,
}

impl Drop for LockGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Errors returned by [`acquire_lock`].
#[derive(Debug, thiserror::Error)]
pub enum LockError {
    #[error("backup in progress (lock held since {since})")]
    Held { since: time::OffsetDateTime },
    #[error("cannot create lock file at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

/// Acquire the per-backup-dir concurrency lock. O_EXCL create with
/// 5-minute stale-recovery. Returns a [`LockGuard`] that releases the
/// lock on drop.
pub fn acquire_lock(backup_dir: &Path, now: time::OffsetDateTime) -> Result<LockGuard, LockError> {
    std::fs::create_dir_all(backup_dir).map_err(|e| LockError::Io {
        path: backup_dir.to_path_buf(),
        source: e,
    })?;
    let path = backup_dir.join(LOCK_FILE);

    let body = format!(
        "{}:{}\n",
        std::process::id(),
        now.format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_else(|_| "unknown".into())
    );

    match try_create_lock(&path, body.as_bytes()) {
        Ok(_) => Ok(LockGuard { path }),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            let mtime = std::fs::metadata(&path)
                .and_then(|m| m.modified())
                .map(time::OffsetDateTime::from)
                .unwrap_or(now);
            if now - mtime < STALE_LOCK_AGE {
                return Err(LockError::Held { since: mtime });
            }
            // Stale — clear it and retry exactly once.
            let _ = std::fs::remove_file(&path);
            match try_create_lock(&path, body.as_bytes()) {
                Ok(_) => Ok(LockGuard { path }),
                Err(e2) if e2.kind() == std::io::ErrorKind::AlreadyExists => {
                    // Lost the race to another process — treat as held.
                    let mtime2 = std::fs::metadata(&path)
                        .and_then(|m| m.modified())
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

fn try_create_lock(path: &Path, body: &[u8]) -> std::io::Result<()> {
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o640)
        .open(path)?;
    f.write_all(body)?;
    f.sync_all()?;
    Ok(())
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
            path.display()
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

/// Load `[backup]` from `config_path`'s master, best-effort.
/// A broken master ⇒ [`BackupConfig`](crate::config::schema::BackupConfig)`::default()`.
fn load_backup_config_best_effort(config_path: &Path) -> crate::config::schema::BackupConfig {
    use crate::config::schema::BackupConfig;
    crate::config::loader::load_config(config_path, time::OffsetDateTime::now_utc())
        .map(|loaded| loaded.config.backup)
        .unwrap_or_else(|_| BackupConfig::default())
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
    let backup_dir = match out {
        Some(p) => p.to_path_buf(),
        None => resolved_backup_dir(config_path),
    };
    // 0750 to match `create_backup` — in the auto-backup flow this is the
    // dir's first creator, so the mode set here is the one that sticks
    // (a later `create_dir_all` no-ops on the existing dir).
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o750)
        .create(&backup_dir)
        .map_err(|e| {
            anyhow::anyhow!(
                "cannot create backup directory {}: {}",
                backup_dir.display(),
                e
            )
        })?;

    let backup_cfg = load_backup_config_best_effort(config_path);
    let mut state = load_auto_state(&backup_dir);

    // ── Auto-mode pre-checks: skip without touching state.
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
        match backup_cfg.auto_interval_parsed() {
            Ok(None) => {
                let _ = writeln!(notices, "[backup] auto_interval not set; auto-backup off");
                return Ok(0);
            }
            Ok(Some(interval)) => {
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
            Err(e) => {
                let _ = writeln!(
                    notices,
                    "warning: [backup] auto_interval invalid ({e}); treating as off"
                );
                return Ok(0);
            }
        }
    }

    // ── Acquire lock (both manual and auto).
    let lock = match acquire_lock(&backup_dir, now) {
        Ok(g) => g,
        Err(LockError::Held { since }) => {
            eprintln!("backup in progress (lock held since {since})");
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

    // ── Run the backup, then update state.
    let outcome = create_backup(config_path, Some(&backup_dir));

    match outcome {
        Ok(report) => {
            println!("backup written: {}", report.archive.display());
            println!("  {} entry/entries captured:", report.entries.len());
            for e in &report.entries {
                println!("    - {e}");
            }
            apply_success_to_state(&mut state, now);
            if let Err(e) = save_auto_state(&backup_dir, &state) {
                let _ = writeln!(notices, "warning: {e}");
            }
            if let Err(e) = prune_archives(
                &backup_dir,
                backup_cfg.retention_count,
                backup_cfg.retention_days,
                now,
            ) {
                let _ = writeln!(notices, "warning: retention prune: {e}");
            }
            drop(lock);
            Ok(0)
        }
        Err(err) => {
            let just_disabled = apply_failure_to_state(
                &mut state,
                err.to_string(),
                auto_mode,
                backup_cfg.disable_threshold(),
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
            if let Err(e) = save_auto_state(&backup_dir, &state) {
                let _ = writeln!(notices, "warning: {e}");
            }
            drop(lock);
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
    let backup_dir = resolved_backup_dir(config_path);
    let mut state = load_auto_state(&backup_dir);

    // Nothing latched ⇒ idempotent no-op (don't rewrite the file).
    if !state.disabled && state.consecutive_failures == 0 {
        println!("auto-backup already enabled (0 consecutive failures); nothing to reset.");
        return Ok(());
    }

    let prior_failures = state.consecutive_failures;
    let was_disabled = state.disabled;
    state.consecutive_failures = 0;
    state.disabled = false;
    save_auto_state(&backup_dir, &state)?;

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

    fn make_single_file_config() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(
            &path,
            b"schema_version = 3\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
        )
        .unwrap();
        (dir, path)
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
    fn backup_captures_sibling_include_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config.toml");
        std::fs::write(
            &config,
            b"schema_version = 3\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
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

    // ── Lock tests ──────────────────────────────────────────────────

    #[test]
    fn acquire_lock_creates_file_with_pid_body() {
        let dir = tempfile::tempdir().unwrap();
        let now = datetime!(2026-05-28 12:00:00 UTC);
        let guard = acquire_lock(dir.path(), now).unwrap();
        let body = std::fs::read_to_string(dir.path().join(LOCK_FILE)).unwrap();
        assert!(body.starts_with(&format!("{}:", std::process::id())));
        assert!(body.contains("2026-05-28T12:00:00Z"));
        drop(guard);
    }

    #[test]
    fn acquire_lock_returns_held_when_recent_lock_present() {
        let dir = tempfile::tempdir().unwrap();
        let now = datetime!(2026-05-28 12:00:00 UTC);
        let _g1 = acquire_lock(dir.path(), now).unwrap();
        // Second attempt while the lock is still fresh.
        let err = acquire_lock(dir.path(), now + time::Duration::minutes(1)).unwrap_err();
        assert!(matches!(err, LockError::Held { .. }));
    }

    #[test]
    fn acquire_lock_clears_stale_lock_and_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        let lock_path = dir.path().join(LOCK_FILE);
        std::fs::write(&lock_path, b"99999:2020-01-01T00:00:00Z\n").unwrap();
        // Re-stat: mtime is "now-ish" because we just wrote. Advance
        // the caller's clock past the staleness window.
        let now = time::OffsetDateTime::now_utc() + time::Duration::minutes(10);
        let guard = acquire_lock(dir.path(), now).unwrap();
        let body = std::fs::read_to_string(&lock_path).unwrap();
        assert!(body.starts_with(&format!("{}:", std::process::id())));
        drop(guard);
    }

    #[test]
    fn lock_guard_drop_removes_lock_file() {
        let dir = tempfile::tempdir().unwrap();
        let now = datetime!(2026-05-28 12:00:00 UTC);
        let lock_path = dir.path().join(LOCK_FILE);
        {
            let _g = acquire_lock(dir.path(), now).unwrap();
            assert!(lock_path.exists());
        }
        assert!(!lock_path.exists(), "Drop must remove the lock file");
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
            "schema_version = 3\n[backup]\nauto_interval = \"1h\"\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
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
            "schema_version = 3\n[backup]\nauto_interval = \"24h\"\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
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
            "schema_version = 3\n[backup]\nauto_interval = \"1h\"\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
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
            "schema_version = 3\n[backup]\nauto_interval = \"1h\"\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
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
            "schema_version = 3\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
        );
        let backup_dir = dir.path().join("backups");
        let now = datetime!(2026-05-28 12:00:00 UTC);
        let code = run_backup_managed(&cfg, Some(&backup_dir), true, now).unwrap();
        assert_eq!(code, 0);
        assert!(list_backups(&backup_dir).is_empty());
    }

    #[test]
    fn manual_runs_regardless_of_disabled() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = write_config(
            dir.path(),
            "schema_version = 3\n[backup]\nauto_interval = \"1h\"\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
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
            "schema_version = 3\n[backup]\nauto_interval = \"1h\"\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
        );
        let backup_dir = dir.path().join("backups");
        std::fs::create_dir_all(&backup_dir).unwrap();
        // Hand-craft a fresh lock file owned by some "other" process.
        std::fs::write(backup_dir.join(LOCK_FILE), b"99999:2026-05-28T11:59:30Z").unwrap();
        let now = datetime!(2026-05-28 12:00:00 UTC);
        // Manual mode also exits 75 — the lock is shared with auto.
        let code = run_backup_managed(&cfg, Some(&backup_dir), false, now).unwrap();
        assert_eq!(code, 75);
        // No state update on lock-held (we never got past acquire_lock).
        // (Default AutoState since no prior save.)
        assert_eq!(load_auto_state(&backup_dir), AutoState::default());
    }

    #[test]
    fn manual_success_runs_retention_pruning() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = write_config(
            dir.path(),
            "schema_version = 3\n[backup]\nretention_count = 2\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
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
            "schema_version = 3\n[backup]\nauto_interval = \"1h\"\n\
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
            "schema_version = 3\n[backup]\nauto_interval = \"1h\"\n\n\
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
            "schema_version = 3\n[backup]\nauto_interval = \"1h\"\n\n\
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
            "schema_version = 3\n[backup]\nauto_interval = \"24h\"\n\n\
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
            "schema_version = 3\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
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

    /// `tar -czf` truncates an existing path in place rather than
    /// re-creating it, so pre-opening at 0600 is what decides the mode the
    /// bytes land under. Creating the file afterwards left a umask-wide
    /// window in which the token hash, the device inventory and
    /// `secrets.toml` were group-readable — and a reader that opened the
    /// file inside it keeps access after the chmod.
    #[test]
    fn a_fresh_archive_path_is_created_at_0600() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("config-20260528T120000Z.tar.gz");

        create_archive_file(&archive).unwrap();

        let mode = std::fs::metadata(&archive).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "archive must not be readable by group or other"
        );
    }

    /// `OpenOptions::mode` only applies when the file is created, so a
    /// same-second re-run over an existing 0644 archive would otherwise
    /// keep the loose mode for the whole of `tar`'s run.
    #[test]
    fn an_existing_loose_archive_is_tightened_before_tar_writes_to_it() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("config-20260528T120000Z.tar.gz");
        std::fs::write(&archive, b"stale").unwrap();
        std::fs::set_permissions(&archive, std::fs::Permissions::from_mode(0o644)).unwrap();

        create_archive_file(&archive).unwrap();

        let meta = std::fs::metadata(&archive).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        assert_eq!(meta.len(), 0, "the stale archive must be truncated");
    }

    /// End to end: the archive an operator actually gets is 0600, whatever
    /// umask they ran the verb under.
    #[test]
    fn a_backup_run_leaves_the_archive_at_0600() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = write_config(
            dir.path(),
            "schema_version = 3\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
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
                "schema_version = 3\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n\n\
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
