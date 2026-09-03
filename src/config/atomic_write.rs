//! Atomic write + pre-rename validation helper.
//!
//! A naive writer that touches a user-visible config file (master,
//! `.d/*.toml` slice, or restored archive) using a streaming `fs::write`
//! followed by a `rename` is vulnerable to a whole class of failures —
//! disk-full mid-write, a process kill between `fs::write` and the
//! validator, or a loader that would have rejected the new bytes — any
//! of which can leave the master in a state the daemon cannot boot from.
//!
//! [`atomic_write_and_validate`] closes that window. It writes to a
//! same-directory temp file, re-reads that temp file through a caller-
//! supplied validator, and only then atomically renames it over the
//! target. If the validator rejects the bytes, the temp is removed and
//! the target on disk is untouched. If the rename itself fails (EXDEV
//! across filesystems, EPERM, target is a directory), the temp is
//! cleaned up (best-effort) and the target is untouched.
//!
//! The contract has three further properties, enforced end-to-end:
//!
//! 1. **fsync.** The temp's bytes are flushed to the storage layer
//!    (`File::sync_all`) BEFORE rename, and the parent directory is
//!    fsynced AFTER rename — so a power loss between rename and the
//!    next kernel writeback cannot land a zero-byte target.
//! 2. **Mode preservation.** When a target already exists, its mode
//!    is captured and re-applied to the temp before the rename — so
//!    a `0o640 root:purge-warden` master survives a CLI mutation
//!    without silently widening to umask-default `0o644`.
//! 3. **Owner preservation (Unix).** When a target already exists,
//!    its uid/gid is captured and re-applied via `lchown` so a
//!    rename does not flip ownership.
//!
//! Callers needing the byte-flavoured surface (sidecars in `lists/`,
//! snapshots in `tracking/`) use [`hardened_atomic_write`] directly.
//! Callers needing the string-flavoured `&str + validator` surface
//! keep using [`atomic_write_and_validate`] — it is now a thin wrapper
//! over the bytes primitive.
//!
//! The validator is a `FnOnce(&Path) -> Result<(), E>` closure: every
//! caller plugs in the loader that is authoritative for the file shape
//! it is about to write (legacy `Settings::from_file` for the v0 writer,
//! full `loader::load_config` for v1 masters, a cheap `toml::Value`
//! parse for the `.d/*.toml` mutation path, etc.). The helper stays
//! agnostic about which schema it is guarding.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

use thiserror::Error;

/// Default mode used when the target file does not yet exist (so there
/// is no prior mode to preserve). Matches the `0o640 root:purge-warden`
/// invariant the CT systemd unit installs at first boot.
#[cfg(unix)]
const DEFAULT_TARGET_MODE: u32 = 0o640;

/// Process-local monotonic counter combined with `pid` to build unique
/// temp-file suffixes. Not cryptographic — the property we need is
/// "no two concurrent writers in the same process pick the same temp
/// name", which a plain counter provides.
static TEMP_SUFFIX_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Structured error type for the atomic-write pipeline. Each variant
/// names the stage that failed so callers can surface actionable
/// diagnostics — every failure mode is recoverable by the operator:
/// wrong perms on the config directory, the supplied content failing
/// validation, or a rename blocked by some pre-existing path conflict.
#[derive(Debug, Error)]
pub enum AtomicWriteError {
    #[error("cannot create parent directory for {target}: {source}")]
    MkDir {
        target: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("cannot write staged temp file {tmp}: {source}")]
    WriteTemp {
        tmp: PathBuf,
        #[source]
        source: std::io::Error,
    },
    /// Setting the mode (`chmod`) or owner (`lchown`) on the staged temp
    /// failed. Distinct from [`AtomicWriteError::WriteTemp`] so the
    /// operator isn't sent chasing a write error when the real problem
    /// is permission / ownership semantics. The temp is cleaned up
    /// best-effort; the target is untouched.
    #[error("cannot set mode/owner on staged temp {tmp}: {source}")]
    Metadata {
        tmp: PathBuf,
        #[source]
        source: std::io::Error,
    },
    /// Stat-ing the existing target failed for a reason other than
    /// "not found" (EACCES / ELOOP / EIO / …). Surfaced rather than
    /// swallowed: a silent fall-through to default mode + no owner
    /// preservation could change the file's mode/owner on the next
    /// write instead of letting the operator resolve the real problem.
    #[error("cannot stat existing target {path}: {source}")]
    Stat {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    /// `fsync` (or the parent-dir `fsync`) failed. The temp has been
    /// cleaned up best-effort; the target on disk is untouched. Without
    /// this the bytes hit page cache but never reach the storage layer,
    /// so a power loss before the next kernel writeback would leave a
    /// zero-byte target.
    #[error("fsync failed on {path}: {source}")]
    Fsync {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    /// The validator rejected the bytes we staged. The temp file has
    /// been removed; the target path on disk was never touched.
    #[error("validation failed on staged write for {target}: {reason}")]
    Validation { target: PathBuf, reason: String },
    /// The temp file was staged + validated, but the final rename
    /// failed. The temp is cleaned up best-effort; the target on disk
    /// is untouched.
    #[error("cannot rename {tmp} → {target}: {source}")]
    Rename {
        tmp: PathBuf,
        target: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

/// Borrowed validator closure type used by [`AtomicWriteOpts::validator`].
/// Aliased so the field type stays readable and so clippy's
/// `type_complexity` lint doesn't fire on the option-of-dyn-fn shape.
pub type AtomicWriteValidator<'a> = &'a dyn Fn(&Path) -> Result<(), String>;

/// Options controlling [`hardened_atomic_write`]. Construct via
/// [`Default::default`] for "validate nothing, preserve target mode,
/// fsync the parent dir" (the right shape for cache/snapshot sidecars).
///
/// Lifetimed because `validator` holds a borrowed closure — every
/// caller already produces the closure at the call site, and a boxed
/// `Fn` allocation per write would be wasted work on the cold mutation
/// path.
pub struct AtomicWriteOpts<'a> {
    /// Validator runs on the temp BEFORE rename. `None` skips the
    /// step — used by `lists/` sidecars and `tracking/` snapshots
    /// where there is no schema to validate.
    pub validator: Option<AtomicWriteValidator<'a>>,
    /// Mode to set on the temp before rename. `None` preserves the
    /// existing target mode when the target exists, else defaults to
    /// [`DEFAULT_TARGET_MODE`] (`0o640`).
    pub mode: Option<u32>,
    /// fsync the parent directory after rename for directory-entry
    /// durability. Default `true`; set `false` only for ephemeral test
    /// fixtures where the cost is not worth it.
    pub fsync_parent: bool,
}

impl Default for AtomicWriteOpts<'_> {
    fn default() -> Self {
        Self {
            validator: None,
            mode: None,
            fsync_parent: true,
        }
    }
}

/// Write `content` to `path` via a same-directory temp file, run
/// `validator` on the temp, then atomically rename it into place.
///
/// String-flavoured wrapper preserved for back-compat with call-sites
/// that pass a `&str` payload and a typed validator closure. Internally
/// builds an [`AtomicWriteOpts`] with the validator adapted to the
/// `Result<(), String>` shape and delegates to
/// [`hardened_atomic_write`].
///
/// Invariants:
/// - On every error path, the file at `path` is left untouched (bytes
///   identical to what was there before the call) — with ONE documented
///   exception: a parent-directory fsync failure raised *after* the
///   rename has already committed. In that case the new bytes ARE on
///   disk (the swap succeeded); only crash-durability of the directory
///   entry is unconfirmed. `AtomicWriteError::Fsync { path: <parent> }`
///   therefore means "the write LANDED but durability is unconfirmed",
///   NOT "the write failed and the target is unchanged" — callers doing
///   compensating rollback must not treat it as a no-op failure.
/// - Temp files are cleaned up on success (the rename consumes the temp)
///   and on every HANDLED failure path (best-effort `remove_file`). A hard
///   crash (SIGKILL / panic) between temp creation and the rename leaves a
///   `.{name}.tmp-{pid}-{seq}` orphan: the dot-prefix keeps it out of
///   `*.toml` include globs so it is inert, but nothing in-tree sweeps it,
///   so operators may see stale temps after a crash.
/// - `rename(2)` is atomic on POSIX when source + destination share a
///   filesystem. Placing the temp in the same directory guarantees
///   that property.
/// - The temp's bytes are `fsync`-ed before rename; the parent dir
///   is `fsync`-ed after rename.
/// - If the target already existed, its mode and (Unix) owner are
///   preserved across the rename.
///
/// The validator is invoked only after `content` is on disk in its
/// final shape, so it sees exactly what the next reader would see if
/// the rename went through. Callers that need cross-file validation
/// (e.g. `loader::load_config` on a multi-file v1 tree) can do it
/// from inside the closure.
pub fn atomic_write_and_validate<V, E>(
    path: &Path,
    content: &str,
    validator: V,
) -> Result<(), AtomicWriteError>
where
    V: FnOnce(&Path) -> Result<(), E>,
    E: std::fmt::Display,
{
    // The helper takes `&dyn Fn` (can be called any number of times in
    // principle, though in practice exactly once). The caller-supplied
    // `FnOnce + E: Display` shape is adapted via a single-use cell so a
    // closure that captures move-only state still composes.
    let validator_cell = std::cell::RefCell::new(Some(validator));
    let adapter = |staged: &Path| -> Result<(), String> {
        let v = validator_cell
            .borrow_mut()
            .take()
            .expect("validator invoked twice");
        v(staged).map_err(|e| e.to_string())
    };
    hardened_atomic_write(
        path,
        content.as_bytes(),
        AtomicWriteOpts {
            validator: Some(&adapter),
            ..Default::default()
        },
    )
}

/// Bytes-flavoured atomic-write primitive used directly by
/// `lists/` sidecars, `tracking/` snapshots, and the string-flavoured
/// [`atomic_write_and_validate`] wrapper.
///
/// See module-level doc for the full contract (fsync, mode
/// preservation, owner preservation).
pub fn hardened_atomic_write(
    path: &Path,
    content: &[u8],
    opts: AtomicWriteOpts<'_>,
) -> Result<(), AtomicWriteError> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    if !parent.as_os_str().is_empty() {
        // Create missing parents at 0o750 (matching the audit dir + the
        // 0o640 files), not the umask-default 0o755 a plain
        // `create_dir_all` would leave.
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o750)
                .create(parent)
                .map_err(|source| AtomicWriteError::MkDir {
                    target: path.to_path_buf(),
                    source,
                })?;
        }
        #[cfg(not(unix))]
        std::fs::create_dir_all(parent).map_err(|source| AtomicWriteError::MkDir {
            target: path.to_path_buf(),
            source,
        })?;
    }

    // Capture the target's existing metadata so we can preserve mode
    // and (Unix) owner across the rename. Missing target → fall back to
    // defaults; any *other* stat error is surfaced (not `.ok()`-swallowed)
    // so a permission/IO quirk cannot silently change the file's mode or
    // owner on the next write.
    let existing_meta = match std::fs::metadata(path) {
        Ok(meta) => Some(meta),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(source) => {
            return Err(AtomicWriteError::Stat {
                path: path.to_path_buf(),
                source,
            });
        }
    };

    // `metadata` above follows a symlink (capturing the TARGET's
    // mode/owner), but the `rename` below replaces the LINK itself with
    // a regular file — severing an operator's `config.toml -> checkout`
    // symlink on the first write, after which edits diverge from the
    // checkout. We don't refuse (that breaks a legitimate workflow and
    // the config-dir writer is trusted), but the severing must not be
    // silent.
    #[cfg(unix)]
    if std::fs::symlink_metadata(path)
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false)
    {
        tracing::warn!(
            path = %path.display(),
            "atomic write target is a symlink; it will be replaced by a regular file (the link is not preserved)",
        );
    }

    #[cfg(unix)]
    let target_mode = opts
        .mode
        .or_else(|| existing_meta.as_ref().map(|m| m.mode() & 0o7777))
        .unwrap_or(DEFAULT_TARGET_MODE);

    #[cfg(unix)]
    let existing_owner: Option<(u32, u32)> = existing_meta.as_ref().map(|m| (m.uid(), m.gid()));

    let tmp = staged_path(path);

    // Stage the temp with the intended mode set at open time. On Unix
    // this still goes through the umask, so the explicit
    // `set_permissions` below re-asserts the exact bits — both calls
    // together close the create-then-chmod race window that would
    // otherwise leave the file briefly at umask-default mode. Truncate
    // semantics (rather than `create_new`) so a stale temp from a prior
    // crashed write is overwritten instead of forcing the operator to
    // clean it up by hand. Process-local uniqueness on the staged name
    // is already provided by [`staged_path`].
    //
    // `O_NOFOLLOW` (Unix): the staged name is predictable
    // (`.{name}.tmp-{pid}-{seq}`), so if a symlink were planted there the
    // create+truncate would follow it and clobber the link target. With
    // `O_NOFOLLOW` the open fails (ELOOP) instead. Defence-in-depth: the
    // config-dir-write attacker is out of the threat model, but this is
    // the canonical hardened write path. `O_NOFOLLOW` does not block
    // overwriting a stale *regular* temp, so the truncate semantics
    // above are preserved.
    let open_result = {
        let mut opts_o = OpenOptions::new();
        opts_o.write(true).create(true).truncate(true);
        #[cfg(unix)]
        opts_o.mode(target_mode);
        #[cfg(unix)]
        opts_o.custom_flags(libc::O_NOFOLLOW);
        opts_o.open(&tmp)
    };
    let mut file = match open_result {
        Ok(f) => f,
        Err(source) => {
            return Err(AtomicWriteError::WriteTemp {
                tmp: tmp.clone(),
                source,
            });
        }
    };

    if let Err(source) = file.write_all(content) {
        drop(file);
        let _ = std::fs::remove_file(&tmp);
        return Err(AtomicWriteError::WriteTemp {
            tmp: tmp.clone(),
            source,
        });
    }

    // Assert the exact mode + owner on the staged temp BEFORE the fsync,
    // so the single `sync_all` below flushes the data AND the mode/owner
    // inode metadata together — fsyncing the data first and the
    // chmod/lchown after would let a crash leave the correct bytes with
    // the umask-default mode.

    // Defence-in-depth on Unix: force the exact mode bits even when
    // OpenOptions::mode was umask-bitten on the platform. chmod/lchown
    // failures get the dedicated `Metadata` variant, not the misleading
    // `WriteTemp`.
    #[cfg(unix)]
    if let Err(source) =
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(target_mode))
    {
        drop(file);
        let _ = std::fs::remove_file(&tmp);
        return Err(AtomicWriteError::Metadata {
            tmp: tmp.clone(),
            source,
        });
    }

    // Preserve owner when we captured one. On a fresh first-write
    // (`existing_owner == None`) we leave the temp owned by the
    // current process — the caller can chown afterwards if needed
    // (see init.rs).
    //
    // Gate on `geteuid() == 0`: lchown requires CAP_CHOWN when the
    // target uid/gid differs from the caller. The production daemon
    // runs under the `purge-warden` user via systemd, and its
    // SystemCallFilter (`@system-service ~@privileged @resources`)
    // excludes `@chown`, so an unconditional lchown is killed by
    // seccomp with SIGSYS. When not root the temp is already owned
    // by the daemon user (which equals the target owner in steady
    // state) — skipping the call preserves ownership de-facto.
    #[cfg(unix)]
    if let Some((uid, gid)) = existing_owner {
        // SAFETY: getuid/geteuid are async-signal-safe and always succeed.
        let euid = unsafe { libc::geteuid() };
        if euid == 0 {
            if let Err(source) = std::os::unix::fs::lchown(&tmp, Some(uid), Some(gid)) {
                drop(file);
                let _ = std::fs::remove_file(&tmp);
                return Err(AtomicWriteError::Metadata {
                    tmp: tmp.clone(),
                    source,
                });
            }
        }
    }

    // fsync the data + the just-asserted mode/owner metadata together:
    // fsync flushes the inode's data AND metadata, so the chmod/lchown
    // above are now crash-durable, not just the bytes.
    if let Err(source) = file.sync_all() {
        drop(file);
        let _ = std::fs::remove_file(&tmp);
        return Err(AtomicWriteError::Fsync {
            path: tmp.clone(),
            source,
        });
    }
    drop(file);

    if let Some(v) = opts.validator {
        if let Err(e) = v(&tmp) {
            let _ = std::fs::remove_file(&tmp);
            return Err(AtomicWriteError::Validation {
                target: path.to_path_buf(),
                reason: e,
            });
        }
    }

    if let Err(source) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(AtomicWriteError::Rename {
            tmp: tmp.clone(),
            target: path.to_path_buf(),
            source,
        });
    }

    if opts.fsync_parent {
        match File::open(parent) {
            Ok(dir) => {
                if let Err(source) = dir.sync_all() {
                    return Err(AtomicWriteError::Fsync {
                        path: parent.to_path_buf(),
                        source,
                    });
                }
            }
            Err(source) => {
                return Err(AtomicWriteError::Fsync {
                    path: parent.to_path_buf(),
                    source,
                });
            }
        }
    }

    Ok(())
}

/// Build a temp-file path in the same directory as `target`, shaped so
/// it is hidden from `*.toml` globs (N9 include discovery) and unique
/// across concurrent writers in this process.
fn staged_path(target: &Path) -> PathBuf {
    let pid = std::process::id();
    let seq = TEMP_SUFFIX_COUNTER.fetch_add(1, Ordering::Relaxed);
    let file_name = target
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("config");
    let parent = target.parent().unwrap_or_else(|| Path::new("."));
    parent.join(format!(".{file_name}.tmp-{pid}-{seq}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(_p: &Path) -> Result<(), String> {
        Ok(())
    }

    #[test]
    fn write_happy_path_replaces_file_atomically() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("config.toml");
        std::fs::write(&target, "old").unwrap();

        atomic_write_and_validate(&target, "new", ok).unwrap();
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "new");
    }

    #[test]
    fn write_creates_file_when_absent() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("fresh.toml");
        atomic_write_and_validate(&target, "hello", ok).unwrap();
        assert!(target.exists());
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "hello");
    }

    #[test]
    fn atomic_write_cleans_up_temp_on_success() {
        // After a successful write there must be no `.config.toml.tmp-*`
        // sibling in the same directory.
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("config.toml");
        atomic_write_and_validate(&target, "bytes", ok).unwrap();

        let leftover: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with(".config.toml.tmp-"))
            .collect();
        assert!(
            leftover.is_empty(),
            "temp files survived a successful write: {leftover:?}"
        );
    }

    #[test]
    fn atomic_write_leaves_original_on_validator_error() {
        // The validator rejects the staged content. The target on disk
        // must be byte-for-byte the original, and the temp must be
        // cleaned up.
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("config.toml");
        std::fs::write(&target, "pristine").unwrap();

        let err = atomic_write_and_validate(&target, "bad bytes", |_p: &Path| {
            Err::<(), _>("synthetic validator failure")
        })
        .unwrap_err();

        match &err {
            AtomicWriteError::Validation { target: t, reason } => {
                assert_eq!(t, &target);
                assert!(
                    reason.contains("synthetic validator failure"),
                    "reason must carry the validator's message: {reason}"
                );
            }
            other => panic!("expected Validation, got {other:?}"),
        }

        assert_eq!(
            std::fs::read_to_string(&target).unwrap(),
            "pristine",
            "original bytes must survive validator rejection"
        );
        let leftover: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with(".config.toml.tmp-"))
            .collect();
        assert!(
            leftover.is_empty(),
            "temp files must be removed on validator error: {leftover:?}"
        );
    }

    #[test]
    fn atomic_write_cleans_up_temp_on_rename_failure() {
        // Simulate a rename failure by pointing the target at a path
        // where a directory already exists with the target name — on
        // Linux, renaming a file to an existing non-empty directory
        // returns EISDIR / ENOTEMPTY, which the helper must surface as
        // `AtomicWriteError::Rename` and clean up the temp.
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("config.toml");
        std::fs::create_dir(&target).unwrap();
        // Put a dummy file inside so even ENOTEMPTY-returning platforms
        // fail deterministically.
        std::fs::write(target.join("occupant"), "x").unwrap();

        let err = atomic_write_and_validate(&target, "bytes", ok).unwrap_err();
        assert!(
            matches!(err, AtomicWriteError::Rename { .. }),
            "expected Rename error, got {err:?}"
        );
        // The directory at `target` is unchanged.
        assert!(target.is_dir());
        assert!(target.join("occupant").exists());

        // The temp file beside the target should be gone.
        let leftover: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with(".config.toml.tmp-"))
            .collect();
        assert!(
            leftover.is_empty(),
            "temp files must be removed on rename failure: {leftover:?}"
        );
    }

    #[test]
    fn staged_path_is_same_directory_as_target() {
        let p = Path::new("/etc/purge-warden/config.toml");
        let staged = staged_path(p);
        assert_eq!(staged.parent(), p.parent());
        let name = staged.file_name().unwrap().to_string_lossy();
        assert!(name.starts_with(".config.toml.tmp-"));
    }

    #[test]
    fn validator_sees_staged_content() {
        // The validator must be called with the path of the temp file,
        // whose content matches the bytes the caller passed in.
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("config.toml");
        atomic_write_and_validate(&target, "payload-abc", |p: &Path| {
            let read = std::fs::read_to_string(p).unwrap();
            if read == "payload-abc" {
                Ok::<(), &'static str>(())
            } else {
                Err("content mismatch")
            }
        })
        .unwrap();
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "payload-abc");
    }

    // --- hardened_atomic_write tests ---------------------------------

    #[cfg(unix)]
    #[test]
    fn hardened_atomic_write_preserves_existing_mode_0o640() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("master.toml");
        std::fs::write(&target, "old").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o640)).unwrap();

        hardened_atomic_write(&target, b"new", AtomicWriteOpts::default()).unwrap();

        let mode = std::fs::metadata(&target).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode, 0o640, "target mode must be preserved across rename");
        assert_eq!(std::fs::read(&target).unwrap(), b"new");
    }

    #[cfg(unix)]
    #[test]
    fn hardened_atomic_write_creates_parent_dir_without_world_access() {
        // A missing parent (e.g. a fresh `devices.d/`) is created at
        // 0o750, not the umask-default 0o755 — no other access.
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let parent = dir.path().join("fresh.d");
        let target = parent.join("entity.toml");
        assert!(!parent.exists());

        hardened_atomic_write(&target, b"x", AtomicWriteOpts::default()).unwrap();

        let mode = std::fs::metadata(&parent).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode & 0o007,
            0,
            "created parent dir must not be other-accessible (0o750, not 0o755), got {mode:o}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn hardened_atomic_write_replaces_symlinked_target() {
        // Writing through a symlinked config path replaces the LINK
        // with a regular file (documented severing — we warn, we don't
        // refuse). Pins the behaviour so a future "follow the link"
        // change is a conscious one.
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real.toml");
        std::fs::write(&real, "old").unwrap();
        let link = dir.path().join("config.toml");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(std::fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink());

        hardened_atomic_write(&link, b"new", AtomicWriteOpts::default()).unwrap();

        // The link path is now a regular file with the new bytes; the
        // original target is untouched (link severed, not followed).
        assert!(!std::fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(std::fs::read(&link).unwrap(), b"new");
        assert_eq!(std::fs::read(&real).unwrap(), b"old");
    }

    #[cfg(unix)]
    #[test]
    fn hardened_atomic_write_defaults_to_0o640_when_target_absent() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("fresh.toml");
        assert!(!target.exists());

        hardened_atomic_write(&target, b"first", AtomicWriteOpts::default()).unwrap();

        let mode = std::fs::metadata(&target).unwrap().permissions().mode() & 0o7777;
        assert_eq!(
            mode, 0o640,
            "first-write must default to DEFAULT_TARGET_MODE"
        );
    }

    #[cfg(unix)]
    #[test]
    fn hardened_atomic_write_explicit_mode_overrides_existing() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("config.toml");
        std::fs::write(&target, "x").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();

        hardened_atomic_write(
            &target,
            b"y",
            AtomicWriteOpts {
                mode: Some(0o600),
                ..Default::default()
            },
        )
        .unwrap();

        let mode = std::fs::metadata(&target).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn hardened_atomic_write_no_validator_writes_bytes() {
        // Byte-flavoured callers (lists, snapshots) skip validation. The
        // bytes must land on disk unchanged.
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("payload.bin");
        let bytes: &[u8] = &[0u8, 1, 2, 3, 0xFF, 0xFE, 0xAA];
        hardened_atomic_write(&target, bytes, AtomicWriteOpts::default()).unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), bytes);
    }

    #[test]
    fn hardened_atomic_write_fsyncs_parent_by_default() {
        // The parent fsync is a side-effect we can't observe directly
        // from user-space without a crash sim, but we can at least
        // exercise the code path — the call must return Ok on a healthy
        // filesystem. A future fault-injection suite can layer on top.
        // TODO: real power-loss durability test via syscall-level
        // injection.
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("durable.toml");
        hardened_atomic_write(&target, b"bytes", AtomicWriteOpts::default()).unwrap();
        assert!(target.exists());
    }

    #[test]
    fn hardened_atomic_write_validator_failure_leaves_target_intact() {
        // Helper-level mirror of `atomic_write_leaves_original_on_validator_error`.
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("config.toml");
        std::fs::write(&target, "pristine").unwrap();

        let reject = |_: &Path| -> Result<(), String> { Err("synthetic".into()) };
        let err = hardened_atomic_write(
            &target,
            b"bad",
            AtomicWriteOpts {
                validator: Some(&reject),
                ..Default::default()
            },
        )
        .unwrap_err();
        assert!(matches!(err, AtomicWriteError::Validation { .. }));
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "pristine");
    }
}
