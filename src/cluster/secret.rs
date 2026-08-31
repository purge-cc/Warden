//! §4.11-3 — the secondary's plaintext cluster-token store (carries D1).
//!
//! CS2 verifies the cluster token as PLAINTEXT against the primary's stored
//! SHA-256 hash, so a secondary must keep the plaintext to send on every
//! poll. `cluster join` (§4.11-1) persisted only `token_hash` into the
//! master config — the §4.11-3 blocker (D1). This module adds a `0o600`
//! plaintext sidecar mirroring the API-token store
//! ([`crate::ipc::auth_token`]): `cluster join` writes it, the poll loop
//! reads it once at boot.
//!
//! The path is config-relative (`state_dir_for(config_dir)/cluster_token`)
//! rather than the FHS literal, so an isolated /tmp-scoped test rig — and
//! any non-standard install — finds its own token next to its own state
//! instead of a shared `/var/lib/purge-warden/cluster_token`.

use std::path::{Path, PathBuf};

use crate::cli::commands::start::state_dir_for;
use crate::ipc::auth_token::{load_token_at, save_token_at};

/// Resolve the plaintext cluster-token file for a given config master.
///
/// [`state_dir_for`] maps `/etc/<pkg>/` → `/var/lib/<pkg>/` (the FHS state
/// dir, daemon-writable) and returns any other config dir unchanged (dev /
/// ad-hoc /tmp rigs), so the token always lands beside the daemon's other
/// mutable state.
#[must_use]
pub fn cluster_token_path(config_path: &Path) -> PathBuf {
    let dir = config_path.parent().unwrap_or_else(|| Path::new("."));
    state_dir_for(dir).join("cluster_token")
}

/// Persist the plaintext cluster token (mode `0o600`) for `config_path`.
///
/// Delegates to the hardened [`save_token_at`] writer (atomic
/// temp + fsync + rename, `0o600`, `geteuid()==0`-gated chown) — the same
/// crash-safety contract the API token gets. Returns the path written.
pub fn save_cluster_token(config_path: &Path, plaintext: &str) -> std::io::Result<PathBuf> {
    let path = cluster_token_path(config_path);
    save_token_at(&path, plaintext)?;
    Ok(path)
}

/// Load the plaintext cluster token for `config_path`.
///
/// `Ok(None)` when the file does not exist (never joined, or the token was
/// removed); `Err` only when the file exists but cannot be read. Mirrors
/// [`load_token_at`] semantics.
pub fn load_cluster_token(config_path: &Path) -> std::io::Result<Option<String>> {
    load_token_at(&cluster_token_path(config_path))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_path_is_beside_a_dev_config() {
        // A non-/etc config dir is returned unchanged by state_dir_for, so
        // the token sits next to the master (the ad-hoc /tmp rig case).
        let cfg = Path::new("/tmp/cl-secondary/config.toml");
        assert_eq!(
            cluster_token_path(cfg),
            PathBuf::from("/tmp/cl-secondary/cluster_token"),
        );
    }

    #[test]
    fn token_path_maps_etc_to_state_dir() {
        // /etc/<pkg>/ → /var/lib/<pkg>/ so the daemon can write it under
        // ProtectSystem=strict (the FHS state dir is in ReadWritePaths).
        let cfg = Path::new("/etc/purge-warden/config.toml");
        assert_eq!(
            cluster_token_path(cfg),
            PathBuf::from("/var/lib/purge-warden/cluster_token"),
        );
    }

    #[test]
    fn save_then_load_roundtrips() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = tmp.path().join("config.toml");
        let written = save_cluster_token(&cfg, "ps_clustertoken").unwrap();
        assert_eq!(written, tmp.path().join("cluster_token"));
        assert_eq!(
            load_cluster_token(&cfg).unwrap().as_deref(),
            Some("ps_clustertoken"),
        );
    }

    #[test]
    fn load_missing_is_none() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = tmp.path().join("config.toml");
        assert_eq!(load_cluster_token(&cfg).unwrap(), None);
    }
}
