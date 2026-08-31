//! Plaintext-token file storage for the CLI side of the IPC ACL (P0-3).
//!
//! Design goals (from the usability-first memory rule):
//!
//! - **Auto-discovery.** The CLI must find the token without the operator
//!   setting an environment variable, specifying a flag, or knowing where
//!   the file lives.
//! - **FHS-canonical location (§4.40).** The default token file lives at
//!   `/var/lib/purge-warden/token`, next to other daemon state (audit log,
//!   stats snapshots, list cache). The XDG-spec path
//!   `$XDG_CONFIG_HOME/purge-warden/token` (or `$HOME/.config/...`) is
//!   kept as a back-compat fallback for installs predating §4.40 — the
//!   daemon migrates such tokens to the FHS location on next boot.
//! - **Safe permissions.** Token files are written mode 0600 (owner-only)
//!   on unix. Parent directory is created mode 0700 only when we created
//!   it; pre-existing parent dirs (e.g. `/var/lib/purge-warden/` at 0o750)
//!   are left untouched so sibling state (audit log, lists cache) keeps
//!   its expected group-readable mode.
//! - **Plain-English errors.** The error strings exposed to callers are
//!   pre-written sentences that name the exact next command the user
//!   should run — not hex codes or RFC labels.

use std::path::{Path, PathBuf};

/// FHS canonical token path (§4.40). Lives next to other daemon state
/// (`/var/lib/purge-warden/{audit,lists,data}`) so backup / restore / SELinux
/// labelling all treat it as a single tree. Independent of `$HOME` — the
/// pre-§4.40 dependency on `/home/<daemon-user>/.config/purge-warden/token`
/// silently failed when the daemon user had no home dir (see
/// `project_4_32_ipc_peer_uid_gate` memory).
const FHS_TOKEN_PATH: &str = "/var/lib/purge-warden/token";

/// Locate the default plaintext token file.
///
/// Resolution order (§4.40):
/// 1. FHS path `/var/lib/purge-warden/token` if it exists.
/// 2. Back-compat: `$XDG_CONFIG_HOME/purge-warden/token` if it exists.
/// 3. Back-compat: `$HOME/.config/purge-warden/token` if it exists.
/// 4. Otherwise the FHS path is returned anyway — `save_token()` writes
///    there for new installs, and the daemon boot-time migration helper
///    (`ensure_fhs_token_path`) moves any straggler XDG token to FHS on
///    next start.
///
/// Returns `None` only when the FHS path is not constructable (never
/// happens on Unix; the const is a static literal) — kept as `Option`
/// for back-compat with callers that handled the pre-§4.40 "neither env
/// var set" case.
pub fn default_token_path() -> Option<PathBuf> {
    let fhs = PathBuf::from(FHS_TOKEN_PATH);
    if fhs.exists() {
        return Some(fhs);
    }
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        if !xdg.is_empty() {
            let p = PathBuf::from(xdg).join("purge-warden").join("token");
            if p.exists() {
                return Some(p);
            }
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        if !home.is_empty() {
            let p = PathBuf::from(home)
                .join(".config")
                .join("purge-warden")
                .join("token");
            if p.exists() {
                return Some(p);
            }
        }
    }
    // New install: no token file exists yet anywhere. Return the FHS
    // path so `save_token()` writes there by default.
    Some(fhs)
}

/// Resolve the XDG-spec back-compat path. Used by the boot-time
/// migration helper to find a legacy token to move into the FHS
/// location. `None` when neither `$XDG_CONFIG_HOME` nor `$HOME` is set.
pub fn legacy_xdg_token_path() -> Option<PathBuf> {
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        if !xdg.is_empty() {
            return Some(PathBuf::from(xdg).join("purge-warden").join("token"));
        }
    }
    let home = std::env::var("HOME").ok()?;
    if home.is_empty() {
        return None;
    }
    Some(
        PathBuf::from(home)
            .join(".config")
            .join("purge-warden")
            .join("token"),
    )
}

/// §4.40 boot-time migration: move a pre-§4.40 XDG token (at
/// `$HOME/.config/purge-warden/token` or `$XDG_CONFIG_HOME/...`) into
/// the FHS canonical path (`/var/lib/purge-warden/token`), then remove
/// the legacy file. Idempotent: returns early if the FHS path already
/// exists, so subsequent boots are no-ops.
///
/// **Important:** under the production systemd unit this helper is a
/// silent no-op because `ProtectHome=yes` makes `/home/purge-warden/`
/// invisible to the daemon process — `xdg_path.exists()` returns
/// false, the migration never fires, and no log entry appears. The
/// canonical migration vector is `scripts/install.sh::migrate_admin_token_to_fhs()`
/// which runs as root before the unit is enabled, has full filesystem
/// visibility, and is idempotent on re-run. This boot-time helper is
/// kept as a defensive safety net for non-hardened deploys (manual
/// `cargo run --release start`, ad-hoc test rigs, future packaging
/// formats with looser hardening). On production it does nothing.
///
/// Failure modes are non-fatal — boot continues even if the migration
/// can't read or write — because losing the migration just means the
/// operator runs `warden token regenerate` once to land a fresh token
/// at the FHS path. A panicking boot would be worse.
pub fn ensure_fhs_token_path() {
    let fhs = PathBuf::from(FHS_TOKEN_PATH);
    if fhs.exists() {
        return;
    }
    let Some(xdg) = legacy_xdg_token_path() else {
        return;
    };
    if !xdg.exists() {
        return;
    }
    match migrate_xdg_to_fhs(&xdg, &fhs) {
        Ok(()) => {
            tracing::info!(
                src = %xdg.display(),
                dst = %fhs.display(),
                "migrated admin token from XDG path to FHS path (§4.40)"
            );
        }
        Err(e) => {
            tracing::warn!(
                src = %xdg.display(),
                dst = %fhs.display(),
                error = %e,
                "failed to migrate admin token to FHS path; \
                 run `warden token regenerate` once after install to land a fresh token at /var/lib/purge-warden/token",
            );
        }
    }
}

/// Internal helper for [`ensure_fhs_token_path`] — split out so unit
/// tests can drive the migration logic against tempdir paths instead
/// of the literal FHS constant.
pub(crate) fn migrate_xdg_to_fhs(xdg: &Path, fhs: &Path) -> std::io::Result<()> {
    if fhs.exists() {
        return Ok(());
    }
    let body = std::fs::read_to_string(xdg)?;
    save_token_at(fhs, body.trim())?;
    let _ = std::fs::remove_file(xdg);
    Ok(())
}

/// Load the plaintext token from the default path.
///
/// Thin wrapper over [`load_token_at`] that resolves the default path
/// from the environment. See [`load_token_at`] for the return semantics.
pub fn load_token() -> std::io::Result<Option<String>> {
    match default_token_path() {
        Some(p) => load_token_at(&p),
        None => Ok(None),
    }
}

/// Load a plaintext token from an explicit path.
///
/// Returns `Ok(Some(token))` if the file exists and is readable,
/// `Ok(None)` if the file does not exist (so the caller can emit a
/// friendly "run `warden token generate`" message), or `Err(_)` if the
/// file exists but could not be read (permission error, I/O error).
///
/// Split from [`load_token`] so tests can pass an explicit path instead
/// of mutating process-global `$HOME` / `$XDG_CONFIG_HOME`.
pub fn load_token_at(path: &std::path::Path) -> std::io::Result<Option<String>> {
    match std::fs::read_to_string(path) {
        Ok(contents) => Ok(Some(contents.trim().to_string())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// Save the plaintext token to the default path, creating the parent
/// directory if needed and setting mode 0600 on the file (unix).
///
/// Called from `warden token generate` and `warden token regenerate`
/// so that the CLI can immediately find the token afterwards without
/// the operator copying it anywhere.
pub fn save_token(plaintext: &str) -> std::io::Result<PathBuf> {
    let path = default_token_path().ok_or_else(|| {
        std::io::Error::other(
            "cannot determine a token file location — \
             neither $XDG_CONFIG_HOME nor $HOME is set",
        )
    })?;
    save_token_at(&path, plaintext)?;
    Ok(path)
}

/// Save a plaintext token to an explicit path.
///
/// The atomic file write — staged temp + fsync + mode 0600 + rename —
/// is delegated to the shared §4.31 `hardened_atomic_write` helper, so
/// the token file gets the same crash-safety contract as every
/// config-mutation path (and the same `geteuid() == 0` lchown gate, so
/// it stays safe under the CT seccomp filter). Parent directories are
/// created as needed; a *newly created* parent is chmod'd 0700, but a
/// pre-existing one (e.g. the FHS state dir `/var/lib/purge-warden/` at
/// 0o750) is left untouched — §4.40 DISC-3.
pub fn save_token_at(path: &std::path::Path, plaintext: &str) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        // §4.40 DISC-3: only chmod the parent dir when we created it.
        // For the FHS path (`/var/lib/purge-warden/`, mode 0o750 owned
        // `purge-warden:purge-warden`), the dir already exists — and a
        // forced chmod 0o700 would break sibling state writers
        // (`audit/`, `lists/`, `data/`) that rely on group access.
        // `hardened_atomic_write` creates the parent too but never
        // chmods it, so this block stays here to keep the DISC-3 rule.
        let pre_existed = parent.exists();
        std::fs::create_dir_all(parent)?;
        #[cfg(unix)]
        if !pre_existed {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
        }
    }

    // s-4.40-disc-4: delegate the atomic file write to the shared §4.31
    // helper instead of hand-rolling tmp + fsync + chmod + rename.
    // Besides the consistency win, this picks up a process-unique
    // staged path — the old fixed `path.with_extension("tmp")` could
    // collide between two concurrent `save_token` calls. The token body
    // keeps its trailing newline for shell friendliness.
    let mut body = Vec::with_capacity(plaintext.len() + 1);
    body.extend_from_slice(plaintext.as_bytes());
    body.push(b'\n');
    crate::config::atomic_write::hardened_atomic_write(
        path,
        &body,
        crate::config::atomic_write::AtomicWriteOpts {
            mode: Some(0o600),
            ..Default::default()
        },
    )
    .map_err(std::io::Error::other)
}

/// Plain-English message for the "no token configured" case.
///
/// Shown when the daemon has no token hash (API never enabled) and the
/// CLI tries a Mutating or Admin command. The message is written to be
/// copy-pasteable: the operator should know exactly what command to run.
pub const NO_TOKEN_CONFIGURED_MSG: &str =
    "this command needs an admin token, but the daemon has no token configured. \
     Run `warden token generate` to create one — it will be saved automatically \
     to /var/lib/purge-warden/token and the CLI will use it from then on.";

/// Plain-English message for the "no token file" case (CLI side).
///
/// Shown when the CLI cannot find a token file to attach to a Mutating/
/// Admin command. May mean the operator never generated one, or they
/// generated it on a different machine.
pub const NO_TOKEN_FILE_MSG: &str =
    "this command needs an admin token and no token file was found at \
     /var/lib/purge-warden/token. Run `warden token generate` on the same \
     host as the daemon — it will save the token automatically.";

/// Plain-English message for the "wrong token" case.
///
/// Shown when a token is attached but the daemon's verify fails. Usually
/// means the token was regenerated on the daemon but the CLI is still
/// holding the old one.
pub const WRONG_TOKEN_MSG: &str =
    "the token in /var/lib/purge-warden/token does not match the daemon's. \
     This usually means the token was regenerated. Run \
     `warden token regenerate` to create a new matching pair.";

#[cfg(test)]
mod tests {
    use super::*;

    // All path-sensitive tests use `save_token_at` / `load_token_at`
    // with an explicit temp path. This avoids mutating the global
    // `$HOME` / `$XDG_CONFIG_HOME` environment variables, which would
    // race when cargo runs tests in parallel.

    /// Save + load round-trip: the token we write must be the token we read.
    #[test]
    fn save_and_load_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("token");

        save_token_at(&path, "ps_deadbeef").unwrap();
        assert!(path.exists());

        let loaded = load_token_at(&path).unwrap();
        assert_eq!(loaded.as_deref(), Some("ps_deadbeef"));
    }

    #[test]
    fn load_returns_none_when_file_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("nonexistent");

        let loaded = load_token_at(&path).unwrap();
        assert_eq!(loaded, None);
    }

    #[test]
    fn save_token_creates_parent_dir() {
        let tmp = tempfile::tempdir().unwrap();
        // Nested path that does not yet exist: save_token_at must mkdir -p.
        let path = tmp.path().join("a").join("b").join("token");

        save_token_at(&path, "ps_nested").unwrap();
        assert!(path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn saved_token_file_has_mode_0600() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("token");

        save_token_at(&path, "ps_sensitive").unwrap();
        let meta = std::fs::metadata(&path).unwrap();
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "expected 0600, got {mode:o}");
    }

    #[test]
    fn save_token_trims_trailing_newline_on_load() {
        // save_token_at writes a trailing newline for shell friendliness;
        // load_token_at must strip it so verify_token sees the clean hex.
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("token");

        save_token_at(&path, "ps_exactvalue").unwrap();
        let loaded = load_token_at(&path).unwrap().unwrap();
        assert_eq!(loaded, "ps_exactvalue");
        assert!(!loaded.ends_with('\n'));
    }

    #[test]
    fn save_overwrites_existing() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("token");

        save_token_at(&path, "ps_old").unwrap();
        save_token_at(&path, "ps_new").unwrap();

        let loaded = load_token_at(&path).unwrap().unwrap();
        assert_eq!(loaded, "ps_new");
    }

    #[test]
    fn default_path_has_correct_suffix() {
        // Regardless of which env var is set, the path must end with
        // `purge-warden/token`. We don't assert the prefix to avoid
        // depending on the process environment.
        if let Some(p) = default_token_path() {
            assert!(p.ends_with("purge-warden/token"), "got {}", p.display());
        }
    }

    /// §4.40 — fresh install (no FHS file, no XDG file) must still
    /// resolve to the FHS path so `save_token()` writes there by
    /// default. We can't fully assert this without unsetting env vars
    /// (which would race with parallel tests), but we can pin that the
    /// function always returns `Some` post-§4.40 (pre-fix it returned
    /// `None` when neither $HOME nor $XDG_CONFIG_HOME was set).
    #[test]
    fn default_token_path_is_never_none_post_4_40() {
        // Pin the §4.40 contract: even in a broken environment
        // (no $HOME, no $XDG_CONFIG_HOME, no /var/lib/purge-warden/token)
        // the function returns Some — the FHS const is unconditional.
        assert!(default_token_path().is_some());
    }

    /// §4.40 DISC-3 — `save_token_at` must NOT chmod a pre-existing
    /// parent directory. Pre-fix the unconditional `set_permissions(parent, 0o700)`
    /// would clobber `/var/lib/purge-warden/` from 0o750 to 0o700, breaking
    /// sibling state directories (`audit/`, `lists/`, `data/`) that rely
    /// on group access.
    #[cfg(unix)]
    #[test]
    fn save_token_at_preserves_pre_existing_parent_mode() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let parent = tmp.path().join("state");
        std::fs::create_dir(&parent).unwrap();
        // Set parent to 0o750 (mimics /var/lib/purge-warden/ mode).
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o750)).unwrap();

        let token_path = parent.join("token");
        save_token_at(&token_path, "ps_fhs_test").unwrap();

        // Token file still gets 0o600 (correct).
        let token_meta = std::fs::metadata(&token_path).unwrap();
        let token_mode = token_meta.permissions().mode() & 0o777;
        assert_eq!(token_mode, 0o600, "token file must be 0o600");

        // §4.40 DISC-3 contract: parent dir mode unchanged.
        let parent_meta = std::fs::metadata(&parent).unwrap();
        let parent_mode = parent_meta.permissions().mode() & 0o777;
        assert_eq!(
            parent_mode, 0o750,
            "pre-existing parent dir mode must NOT be chmodded by save_token_at"
        );
    }

    /// §4.40 — `migrate_xdg_to_fhs` copies the XDG-located token to
    /// the FHS path with mode 0o600 and unlinks the XDG file.
    #[test]
    fn migrate_xdg_to_fhs_copies_token_and_unlinks_xdg() {
        let tmp = tempfile::tempdir().unwrap();
        let xdg = tmp.path().join("xdg_token");
        let fhs = tmp.path().join("fhs_token");

        save_token_at(&xdg, "ps_legacy_token").unwrap();
        assert!(xdg.exists());
        assert!(!fhs.exists());

        migrate_xdg_to_fhs(&xdg, &fhs).unwrap();

        assert!(fhs.exists(), "FHS path must exist after migration");
        assert!(!xdg.exists(), "XDG path must be unlinked after migration");

        // Content preserved (trimmed).
        let loaded = load_token_at(&fhs).unwrap().unwrap();
        assert_eq!(loaded, "ps_legacy_token");

        // Mode 0o600 (unix only).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&fhs).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    /// §4.40 — `migrate_xdg_to_fhs` is idempotent: if the FHS path
    /// already exists, the migration is a no-op (does NOT overwrite the
    /// FHS file with the XDG content, does NOT unlink the XDG file).
    /// This guards against the operator generating a fresh FHS token
    /// while a stale XDG token sits around.
    #[test]
    fn migrate_xdg_to_fhs_skips_when_fhs_present() {
        let tmp = tempfile::tempdir().unwrap();
        let xdg = tmp.path().join("xdg_token");
        let fhs = tmp.path().join("fhs_token");

        save_token_at(&xdg, "ps_stale_xdg").unwrap();
        save_token_at(&fhs, "ps_fresh_fhs").unwrap();

        migrate_xdg_to_fhs(&xdg, &fhs).unwrap();

        // FHS content preserved (NOT overwritten with XDG).
        let loaded = load_token_at(&fhs).unwrap().unwrap();
        assert_eq!(
            loaded, "ps_fresh_fhs",
            "FHS must NOT be overwritten when present"
        );
        // XDG file left in place (caller may decide to clean it up separately).
        assert!(
            xdg.exists(),
            "XDG file must NOT be unlinked when FHS already present"
        );
    }

    /// §4.40 — `migrate_xdg_to_fhs` returns Err on read failure (e.g.
    /// XDG path doesn't exist). Callers in `ensure_fhs_token_path`
    /// must swallow this and continue booting (handled via the helper
    /// — daemon boot can't fail on a missing legacy token).
    #[test]
    fn migrate_xdg_to_fhs_errors_when_xdg_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let xdg = tmp.path().join("does_not_exist");
        let fhs = tmp.path().join("fhs_token");

        let err = migrate_xdg_to_fhs(&xdg, &fhs).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
        assert!(
            !fhs.exists(),
            "FHS must NOT be created when migration source missing"
        );
    }
}
