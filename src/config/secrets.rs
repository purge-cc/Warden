//! Secrets file loader.
//!
//! Holds API tokens, DoH credentials and any other value that must not be
//! merged into the main config output. The file is loaded separately from
//! [`super::loader::load_config`] and **never** appears in
//! `warden config show`.
//!
//! Wire-format: a flat TOML table of `name = "value"` entries. No nesting.
//!
//! ```toml
//! # /etc/purge-warden/secrets.toml (mode 0600)
//! corp-ads-token = "bearer-xxxxxxxxxxxxxxxx"
//! doh-creds       = "user:pass"
//! ```
//!
//! Loader guarantees:
//!
//! - **Permissions enforced at load time.** Anything wider than `0600` is a
//!   hard error; the operator must `chmod 0600` before the daemon will boot.
//!   Read on first open, re-checked on every reload.
//! - **Missing file is OK.** Most installs have no secrets; a missing file
//!   yields an empty [`Secrets`]. Only `auth_token_ref` lookups that resolve
//!   to an absent name produce a downstream error.
//! - **Flat table only.** Nested tables or arrays are rejected so the schema
//!   stays trivial and `secrets.toml` never accumulates structured config.
//! - **Never logged.** Values are passed through opaquely; callers fetch by
//!   name and attach to outbound HTTP without ever tracing the value.

use std::collections::BTreeMap;

use std::io::Read;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

use super::error::{ConfigError, ErrorContext};

/// Maximum permitted filesystem mode bits for `secrets.toml`. Any wider
/// permission (group or other readable/writable) is rejected. `0o600` =
/// rw-------.
pub const REQUIRED_MODE: u32 = 0o600;

/// Canonical filename for the secrets file when living next to the master
/// config. One layout keeps the whole tree monolithic in
/// `/var/lib/purge-warden/`; another keeps it under `/etc/purge-warden/`.
/// The loader accepts either via [`secrets_path_for`].
pub const SECRETS_FILENAME: &str = "secrets.toml";

/// Resolved secrets table. Opaque to callers: lookup by name, never
/// enumerated outside the module that loaded it.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Secrets {
    /// Values are [`Zeroizing<String>`], so the token
    /// bytes are overwritten when the map drops instead of being left in
    /// freed heap where a core dump or a later allocation can expose them.
    /// `Zeroizing` derefs to `String`, so every reader below is unchanged.
    entries: BTreeMap<String, Zeroizing<String>>,
    /// `true` when the file existed + was parsed, `false` when it was
    /// absent (the daemon still boots, but `auth_token_ref` lookups will
    /// fail with a clearer "secrets file missing" error instead of
    /// "unknown ref").
    loaded: bool,
}

/// Redact values in `Debug`. The derived impl
/// printed every `entries` value verbatim, so a stray `{:?}` — a
/// containing struct's derive, an error context, a
/// `tracing::debug!(?secrets)` — would dump every token, contradicting
/// the module's "Never logged" contract by construction. Mirror
/// `lists::source_key::SourceTokenMap`'s `<N tokens>` idiom: surface the
/// shape (count + loaded flag), never the material. `names()` stays the
/// sanctioned introspection for the key names.
impl std::fmt::Debug for Secrets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Secrets")
            .field("entries", &format_args!("<{} secrets>", self.entries.len()))
            .field("loaded", &self.loaded)
            .finish()
    }
}

impl Secrets {
    /// Empty table, as if `secrets.toml` did not exist.
    pub fn empty() -> Self {
        Self {
            entries: BTreeMap::new(),
            loaded: false,
        }
    }

    /// `true` when the backing file was found and parsed. `false` for a
    /// missing file. Callers use this to distinguish "no secrets configured"
    /// from "secret named `x` missing from an otherwise-populated file".
    pub fn is_loaded(&self) -> bool {
        self.loaded
    }

    /// Number of entries in the resolved table. Test / diagnostic use only.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// `true` when the table holds zero entries (independent of whether the
    /// file existed).
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Look up a secret by name. Returns `None` if the name is unknown —
    /// callers decide whether that is fatal (downloads) or tolerated
    /// (optional DoH creds).
    pub fn get(&self, name: &str) -> Option<&str> {
        self.entries.get(name).map(|s| s.as_str())
    }

    /// Produce a sorted list of known secret names. Used by the config
    /// `show --annotate` path to display which names exist without leaking
    /// values.
    pub fn names(&self) -> Vec<&str> {
        self.entries.keys().map(|s| s.as_str()).collect()
    }
}

/// Build the canonical secrets path from a master config path. On the
/// monolithic layout (`/var/lib/purge-warden/config.toml`) this
/// returns `/var/lib/purge-warden/secrets.toml`; on the split layout
/// (`/etc/purge-warden/config.toml`) it returns
/// `/etc/purge-warden/secrets.toml`.
pub fn secrets_path_for(master: &Path) -> PathBuf {
    match master.parent() {
        Some(dir) => dir.join(SECRETS_FILENAME),
        None => PathBuf::from(SECRETS_FILENAME),
    }
}

/// Load and validate `secrets.toml`. Missing file yields an empty
/// [`Secrets`] (not an error). Any other problem — wrong permissions, IO
/// failure, TOML syntax error, nested structure — surfaces a
/// [`ConfigError::ValidationFailed`] with file context so the operator
/// sees the exact next step.
pub fn load_secrets(path: &Path) -> Result<Secrets, ConfigError> {
    // Open ONCE with `O_NOFOLLOW`, then fstat +
    // read the SAME fd. The previous `metadata(path)` → `read_to_string(path)`
    // pair followed symlinks on both calls and left a TOCTOU window between
    // the 0600 mode gate and the read (the path could be swapped in between).
    // `O_NOFOLLOW` refuses a symlinked `secrets.toml` outright; the fstat and
    // the read then see the identical inode the gate approved — the same
    // posture the staged-temp write path already takes (`atomic_write.rs`).
    let mut file = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
    {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Secrets::empty()),
        Err(e) if e.raw_os_error() == Some(libc::ELOOP) => {
            return Err(ConfigError::ValidationFailed(
                ErrorContext::new("secrets path is a symlink; refusing to follow")
                    .with_file(path.to_path_buf())
                    .with_suggestion(
                        "replace the symlink at this path with a plain 0600 regular file",
                    ),
            ));
        }
        Err(e) => {
            return Err(ConfigError::ValidationFailed(
                ErrorContext::new(format!("cannot open secrets file: {e}"))
                    .with_file(path.to_path_buf())
                    .with_suggestion("ensure the path exists and the daemon user can read it"),
            ));
        }
    };

    let metadata = file.metadata().map_err(|e| {
        ConfigError::ValidationFailed(
            ErrorContext::new(format!("cannot stat secrets file: {e}"))
                .with_file(path.to_path_buf())
                .with_suggestion("ensure the path exists and the daemon user can read it"),
        )
    })?;

    if !metadata.is_file() {
        return Err(ConfigError::ValidationFailed(
            ErrorContext::new("secrets path is not a regular file")
                .with_file(path.to_path_buf())
                .with_suggestion(
                    "remove the directory or symlink at this path and create a plain file",
                ),
        ));
    }

    // Reject only group/other access; any owner-only mode passes. The
    // previous exact-equality (`!= 0o600`) also rejected a *stricter*
    // `0400`, contradicting the documented contract ("anything *wider*
    // than 0600 is a hard error" — see the module doc + `REQUIRED_MODE`).
    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(ConfigError::ValidationFailed(
            ErrorContext::new(format!(
                "secrets file has permission mode {mode:#o}, must not grant any group/other access (e.g. {REQUIRED_MODE:#o} = rw-------)"
            ))
            .with_file(path.to_path_buf())
            .with_suggestion(format!(
                "run `chmod 0600 {}` and restart the daemon",
                path.display()
            )),
        ));
    }

    // The raw buffer holds EVERY secret in cleartext, so it is
    // zeroized on drop just like the parsed values. Wrapping only the map
    // would leave the whole file's material in freed heap — the larger of
    // the two exposures, and the easier one to overlook.
    let mut raw = Zeroizing::new(String::new());
    file.read_to_string(&mut raw).map_err(|e| {
        ConfigError::ValidationFailed(
            ErrorContext::new(format!("cannot read secrets file: {e}"))
                .with_file(path.to_path_buf()),
        )
    })?;

    let mut parsed: toml::Value = toml::from_str(&raw).map_err(|e| {
        ConfigError::Parse(
            ErrorContext::new(format!("secrets.toml parse error: {}", e.message()))
                .with_file(path.to_path_buf())
                .with_suggestion("each line must be `name = \"value\"` (flat table, no nesting)"),
        )
    })?;

    Ok(Secrets {
        entries: drain_entries(&mut parsed, path)?,
        loaded: true,
    })
}

/// Move every value out of a parsed flat table into zeroizing entries.
///
/// The tree is a full cleartext copy of the file and `toml::Value` has no
/// zeroizing drop, so a clone would leave that copy in freed heap — the same
/// exposure the `raw` wrapper above exists to close, and the one the module
/// doc calls the easier to overlook. Each value is therefore **moved** out
/// and the tree left holding empty strings; the buffers end up owned by
/// `Zeroizing`, which wipes them on drop.
///
/// Best-effort like the rest of this module: temporaries the TOML parser
/// allocated on the way to building the tree are out of reach here.
///
/// Extraction and the move are one step on purpose. Wiping the tree after a
/// clone would be a second call a future edit could drop while the loader
/// still looked correct.
fn drain_entries(
    parsed: &mut toml::Value,
    path: &Path,
) -> Result<BTreeMap<String, Zeroizing<String>>, ConfigError> {
    let table = parsed.as_table_mut().ok_or_else(|| {
        ConfigError::ValidationFailed(
            ErrorContext::new("secrets file must be a flat TOML table")
                .with_file(path.to_path_buf()),
        )
    })?;

    let mut entries = BTreeMap::new();
    for (key, value) in table.iter_mut() {
        let s = match value {
            toml::Value::String(s) => s,
            other => {
                return Err(ConfigError::ValidationFailed(
                    ErrorContext::new(format!(
                        // `{key:?}` escapes control chars / ANSI escapes in a
                        // quoted TOML key so they can't reach the operator's
                        // terminal / journal raw.
                        "secret {key:?} is not a string (found {})",
                        other.type_str()
                    ))
                    .with_file(path.to_path_buf())
                    .with_suggestion(
                        "every value must be a bare string; nested tables are rejected",
                    ),
                ));
            }
        };
        if key.is_empty() {
            return Err(ConfigError::ValidationFailed(
                ErrorContext::new("secret key is empty")
                    .with_file(path.to_path_buf())
                    .with_suggestion("remove the bad line or give the entry a name"),
            ));
        }
        entries.insert(key.clone(), Zeroizing::new(std::mem::take(s)));
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;

    fn tmp_path(name: &str) -> PathBuf {
        let pid = std::process::id();
        let ctr = std::sync::atomic::AtomicU64::new(0);
        let n = ctr.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        std::env::temp_dir().join(format!("purge-secrets-{pid}-{n}-{name}"))
    }

    fn write_secrets(path: &Path, content: &str, mode: u32) {
        let mut f = fs::File::create(path).unwrap();
        f.write_all(content.as_bytes()).unwrap();
        f.sync_all().unwrap();
        drop(f);
        let mut perm = fs::metadata(path).unwrap().permissions();
        perm.set_mode(mode);
        fs::set_permissions(path, perm).unwrap();
    }

    #[test]
    fn missing_file_returns_empty() {
        let path = tmp_path("missing");
        let s = load_secrets(&path).unwrap();
        assert!(!s.is_loaded());
        assert!(s.is_empty());
        assert_eq!(s.len(), 0);
        assert!(s.get("anything").is_none());
    }

    #[test]
    fn correct_mode_and_content_parses() {
        let path = tmp_path("ok.toml");
        write_secrets(
            &path,
            "corp-ads-token = \"bearer-xxxx\"\ndoh-creds = \"u:p\"\n",
            0o600,
        );

        let s = load_secrets(&path).unwrap();
        let _ = fs::remove_file(&path);

        assert!(s.is_loaded());
        assert_eq!(s.len(), 2);
        assert_eq!(s.get("corp-ads-token"), Some("bearer-xxxx"));
        assert_eq!(s.get("doh-creds"), Some("u:p"));
        assert_eq!(s.get("missing"), None);
        let mut names = s.names();
        names.sort();
        assert_eq!(names, vec!["corp-ads-token", "doh-creds"]);
    }

    #[test]
    fn rejects_wider_mode_0644() {
        let path = tmp_path("wide.toml");
        write_secrets(&path, "x = \"y\"\n", 0o644);

        let err = load_secrets(&path).unwrap_err();
        let _ = fs::remove_file(&path);

        let ctx = err.context();
        assert!(
            ctx.reason.contains("0o644") || ctx.reason.contains("644"),
            "reason = {}",
            ctx.reason
        );
        assert!(
            ctx.suggestion
                .as_deref()
                .unwrap_or("")
                .contains("chmod 0600"),
            "suggestion = {:?}",
            ctx.suggestion
        );
    }

    #[test]
    fn rejects_wider_mode_0660() {
        let path = tmp_path("group.toml");
        write_secrets(&path, "x = \"y\"\n", 0o660);
        let err = load_secrets(&path).unwrap_err();
        let _ = fs::remove_file(&path);
        assert!(matches!(err, ConfigError::ValidationFailed(_)));
    }

    #[test]
    fn rejects_nested_table() {
        let path = tmp_path("nested.toml");
        write_secrets(&path, "[nested]\nx = \"y\"\n", 0o600);
        let err = load_secrets(&path).unwrap_err();
        let _ = fs::remove_file(&path);
        assert!(err.context().reason.contains("not a string"));
    }

    #[test]
    fn rejects_non_string_value() {
        let path = tmp_path("intval.toml");
        write_secrets(&path, "token = 42\n", 0o600);
        let err = load_secrets(&path).unwrap_err();
        let _ = fs::remove_file(&path);
        assert!(err.context().reason.contains("not a string"));
    }

    #[test]
    fn rejects_parse_error() {
        let path = tmp_path("broken.toml");
        write_secrets(&path, "not = valid = toml\n", 0o600);
        let err = load_secrets(&path).unwrap_err();
        let _ = fs::remove_file(&path);
        assert!(matches!(err, ConfigError::Parse(_)));
    }

    /// The parse tree is a full cleartext copy of the file that nothing
    /// zeroizes, so the extraction has to move the buffers out rather than
    /// clone them. An implementation that cloned leaves the secret behind
    /// here — which is exactly what this asserts against.
    #[test]
    fn draining_moves_the_secret_out_of_the_parse_tree() {
        let mut parsed: toml::Value =
            toml::from_str("corp-token = \"bearer-SUPERSECRET\"\nother = \"second\"\n").unwrap();
        let entries = drain_entries(&mut parsed, Path::new("/nonexistent")).unwrap();

        assert_eq!(entries["corp-token"].as_str(), "bearer-SUPERSECRET");
        assert_eq!(entries["other"].as_str(), "second");

        let table = parsed.as_table().unwrap();
        for (key, value) in table {
            assert_eq!(
                value.as_str(),
                Some(""),
                "the tree still holds {key}'s value: {value:?}"
            );
        }
    }

    /// The move must not cost the caller anything: escapes are still the
    /// TOML parser's job, so a value carrying one arrives decoded.
    #[test]
    fn escaped_values_survive_the_move() {
        let path = tmp_path("escaped.toml");
        write_secrets(&path, "t = \"a\\tb\\\"c\"\n", 0o600);
        let s = load_secrets(&path).unwrap();
        let _ = fs::remove_file(&path);
        assert_eq!(s.get("t"), Some("a\tb\"c"));
    }

    #[test]
    fn secrets_path_for_sibling() {
        let master = Path::new("/var/lib/purge-warden/config.toml");
        let sec = secrets_path_for(master);
        assert_eq!(sec, Path::new("/var/lib/purge-warden/secrets.toml"));
    }

    #[test]
    fn secrets_path_for_etc_layout() {
        let master = Path::new("/etc/purge-warden/config.toml");
        let sec = secrets_path_for(master);
        assert_eq!(sec, Path::new("/etc/purge-warden/secrets.toml"));
    }

    #[test]
    fn empty_secrets_is_default() {
        let s = Secrets::empty();
        assert!(s.is_empty());
        assert!(!s.is_loaded());
        assert_eq!(s, Secrets::default());
    }

    // The hand-written Debug must surface the shape, never a
    // value (or even a key name).
    #[test]
    fn debug_redacts_secret_values() {
        let path = tmp_path("redact.toml");
        write_secrets(&path, "corp-token = \"bearer-SUPERSECRET\"\n", 0o600);
        let s = load_secrets(&path).unwrap();
        let _ = fs::remove_file(&path);
        let dbg = format!("{s:?}");
        assert!(
            !dbg.contains("bearer-SUPERSECRET"),
            "Debug must not leak secret values, got: {dbg}"
        );
        assert!(
            !dbg.contains("corp-token"),
            "Debug must not leak secret key names either, got: {dbg}"
        );
        assert!(
            dbg.contains("secrets"),
            "Debug should surface the count shape, got: {dbg}"
        );
    }

    // O_NOFOLLOW refuses a symlinked secrets path.
    #[test]
    fn refuses_symlinked_secrets() {
        let target = tmp_path("real-secrets.toml");
        write_secrets(&target, "x = \"y\"\n", 0o600);
        let link = tmp_path("link-secrets.toml");
        let _ = fs::remove_file(&link);
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let err = load_secrets(&link).unwrap_err();
        let _ = fs::remove_file(&link);
        let _ = fs::remove_file(&target);
        assert!(matches!(err, ConfigError::ValidationFailed(_)));
        assert!(
            err.context().reason.contains("symlink"),
            "reason = {}",
            err.context().reason
        );
    }
}
