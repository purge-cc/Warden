//! Token management — generate/regenerate API authentication tokens.
//!
//! The flow avoids the legacy `Settings::from_file` + `write_config`
//! pipeline, which could corrupt the master config:
//!
//! 1. Claim the config tree, then load the master through that guard so the
//!    current v1 tree is validated before anything mutates.
//! 2. Read the master through the guarded target writer and mutate only the
//!    `[api].token_hash` field — every other top-level section (`includes`,
//!    `[[blocklists]]`, `[profiles.*]`, `[[devices]]`, etc.) is preserved,
//!    along with its comments and key order.
//!
//!    Format preservation matters here: round-tripping through
//!    `toml::Value` + `toml::to_string_pretty` deletes every comment in
//!    the file and re-sorts it, and the master is the most comment-dense
//!    file on a real install.
//! 3. Validate and promote through the guarded target writer. If the mutation
//!    produces anything the daemon could not boot, the rename never happens
//!    and the live master on disk is unchanged.
//! 4. Save the new plaintext to `~/.config/purge-warden/token`
//!    (`save_token_at`, mode `0600`).
//! 5. (regenerate only) Send `IpcCommand::Reload` to the daemon
//!    authenticated with the *old* plaintext — the daemon still has the
//!    old hash in memory until it reloads, so the new plaintext would
//!    fail auth. Once the daemon reloads, its in-memory hash updates to
//!    the new one and the token file on disk matches.
//!
//! The old contract is preserved: `generate` fails if a hash already
//! exists, `regenerate` replaces it.

use std::path::Path;

use anyhow::Context;
use toml_edit::DocumentMut;

use crate::auth::token::generate_token;
use crate::config::error::ConfigError;
use crate::config::loader;
use crate::config::schema::SCHEMA_VERSION_V1;
use crate::config::write_lock::{acquire_for_write, ConfigWriteLock};
use crate::ipc::auth_token::{load_token_at, save_token_at};
use crate::ipc::protocol::{IpcCommand, IpcResponse};
use crate::ipc::socket_client::send_command;

use super::target::{
    commit_prevalidated_single_write, prepare_raw_validated_single_locked, read_or_empty_locked,
};

/// Generate a new API token. Fails if one already exists in the v1 master.
///
/// No IPC reload is attempted: on a first-ever generate the daemon has
/// no token hash in memory and would refuse any authenticated command.
/// The operator therefore has to poke it by hand — and the right poke is
/// **SIGHUP, not a restart**. `signal_loop` handles SIGHUP by calling
/// `handle_reload`, which reaches `api_token_hash.store(...)`, and the
/// shipped unit already exposes it as `ExecReload=/bin/kill -HUP
/// $MAINPID`. SIGHUP is deliberately unauthenticated (changing the config
/// already needs write access to it, a stronger capability than sending a
/// signal), so it works precisely in this no-token-yet state.
///
/// The distinction is not cosmetic: warden binds its listener AFTER the
/// blocklists are ingested, so a restart on a box with a large corpus
/// stops answering DNS for a minute or more. Measured on a 12M-domain
/// install: ~80s. A reload costs nothing.
pub async fn run_generate(
    config_path: &Path,
    _socket_path: &Path,
    token_path: &Path,
) -> anyhow::Result<()> {
    let now = time::OffsetDateTime::now_utc();
    let plaintext = {
        let guard = acquire_for_write(config_path)?;
        let loaded =
            loader::load_config_for_schema_under_guard(&guard, config_path, SCHEMA_VERSION_V1, now)
                .map_err(format_load_errs)?;

        if loaded.config.api.token_hash.is_some() {
            anyhow::bail!("token already exists. Use `warden token regenerate` to replace it.");
        }

        let (plaintext, hash) = generate_token();

        write_token_hash_to_master(&guard, config_path, &hash)?;
        plaintext
    };

    let saved_path = match save_token_after_master_write(token_path, &plaintext) {
        Ok(()) => Some(token_path.to_path_buf()),
        Err(e) => {
            println!("Warning: could not save token to disk: {e}");
            println!(
                "You will need to keep this token somewhere safe and re-run \
                 `warden token regenerate` on the host where the daemon runs."
            );
            None
        }
    };

    println!("Token: {plaintext}");
    println!();
    if let Some(path) = saved_path {
        println!("Saved to: {}", path.display());
        println!("Every `warden` command on this host will find it automatically.");
    } else {
        println!("Save this token — it will not be shown again.");
    }
    println!();
    println!("The same token gates both the HTTP API (if enabled) and admin IPC commands");
    println!("like `warden reload` and `warden shutdown`.");
    println!();
    println!("Reload the daemon for the new token to take effect:");
    println!("  systemctl reload purge-warden");
    println!();
    println!("Reload sends SIGHUP and re-reads the config in place — DNS keeps answering.");
    println!("A restart would stop answering until the blocklists finish loading.");

    Ok(())
}

/// Regenerate the API token (replacing any existing hash).
///
/// After the new hash is safely written to the master, the old
/// plaintext (if still on disk) is used to authenticate a hot
/// [`IpcCommand::Reload`] so the daemon picks up the new hash without
/// a systemctl restart. If the old plaintext is absent or the daemon
/// cannot be reached, the caller is told to restart the daemon by hand.
pub async fn run_regenerate(
    config_path: &Path,
    socket_path: &Path,
    token_path: &Path,
) -> anyhow::Result<()> {
    let now = time::OffsetDateTime::now_utc();

    // Snapshot the old plaintext BEFORE mutation. Needed to authenticate
    // the post-write Reload — the daemon still has the old hash in
    // memory until it actually reloads.
    let old_plaintext = load_token_at(token_path).ok().flatten();

    let plaintext = {
        let guard = acquire_for_write(config_path)?;
        let _loaded =
            loader::load_config_for_schema_under_guard(&guard, config_path, SCHEMA_VERSION_V1, now)
                .map_err(format_load_errs)?;

        let (plaintext, hash) = generate_token();

        write_token_hash_to_master(&guard, config_path, &hash)?;
        plaintext
    };

    let saved_path = match save_token_after_master_write(token_path, &plaintext) {
        Ok(()) => Some(token_path.to_path_buf()),
        Err(e) => {
            println!("Warning: could not save token to disk: {e}");
            None
        }
    };

    let reload = attempt_ipc_reload(socket_path, old_plaintext.as_deref()).await;

    println!("Token: {plaintext}");
    println!();
    if let Some(path) = saved_path {
        println!("Saved to: {}", path.display());
    } else {
        println!("Save this token — it will not be shown again.");
    }
    println!("Previous token has been invalidated.");
    match reload {
        ReloadOutcome::Reloaded => {
            println!();
            println!("Daemon reloaded — the new token is now active without a restart.");
        }
        ReloadOutcome::DaemonUnreachable => {
            println!();
            println!(
                "Daemon not running — nothing to reload. The new token will be picked up \
                 when the daemon next starts."
            );
        }
        ReloadOutcome::NoOldToken => {
            println!();
            println!(
                "Could not auto-reload (no previous token on disk to authenticate the \
                 reload request). Reload the daemon to activate the new token:"
            );
            println!("  systemctl reload purge-warden");
            println!("  (SIGHUP is unauthenticated, so it works without the old token.)");
        }
        ReloadOutcome::ReloadFailed(msg) => {
            println!();
            println!("Auto-reload failed ({msg}). Reload the daemon to activate the new token:");
            println!("  systemctl reload purge-warden");
            println!("  (If that is refused too, escalate to `systemctl restart purge-warden` —");
            println!("   it costs a DNS outage for as long as the blocklists take to load.)");
        }
    }

    Ok(())
}

#[cfg(test)]
type SidecarSaveHook = Box<dyn FnMut()>;

#[cfg(test)]
std::thread_local! {
    static SIDECAR_SAVE_HOOK: std::cell::RefCell<Option<SidecarSaveHook>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
fn sidecar_save_event() {
    SIDECAR_SAVE_HOOK.with(|slot| {
        let Some(mut hook) = slot.borrow_mut().take() else {
            return;
        };
        hook();
        *slot.borrow_mut() = Some(hook);
    });
}

#[cfg(test)]
fn with_sidecar_save_hook<T>(hook: impl FnMut() + 'static, body: impl FnOnce() -> T) -> T {
    struct Reset(Option<SidecarSaveHook>);

    impl Drop for Reset {
        fn drop(&mut self) {
            SIDECAR_SAVE_HOOK.with(|slot| *slot.borrow_mut() = self.0.take());
        }
    }

    let _reset = Reset(SIDECAR_SAVE_HOOK.with(|slot| slot.replace(Some(Box::new(hook)))));
    body()
}

fn save_token_after_master_write(path: &Path, plaintext: &str) -> std::io::Result<()> {
    #[cfg(test)]
    sidecar_save_event();
    save_token_at(path, plaintext)
}

/// Result of the post-regenerate IPC reload attempt.
enum ReloadOutcome {
    /// Daemon acknowledged the reload — new hash is live.
    Reloaded,
    /// Socket does not exist; daemon is not running.
    DaemonUnreachable,
    /// No old plaintext on disk — cannot authenticate the reload.
    NoOldToken,
    /// IPC reached the daemon but the reload was rejected or errored.
    ReloadFailed(String),
}

async fn attempt_ipc_reload(socket_path: &Path, old_plaintext: Option<&str>) -> ReloadOutcome {
    let Some(old) = old_plaintext else {
        return ReloadOutcome::NoOldToken;
    };
    // Pre-attach the old plaintext; send_command honours an explicit
    // token and skips auto-discovery, so the daemon sees the old token
    // and its in-memory-hash verify succeeds.
    let cmd = IpcCommand::Reload {
        token: Some(old.to_string()),
    };
    match send_command(socket_path, &cmd).await {
        Ok(IpcResponse::Ok { .. }) => ReloadOutcome::Reloaded,
        Ok(IpcResponse::Error { message }) => ReloadOutcome::ReloadFailed(message),
        Ok(other) => ReloadOutcome::ReloadFailed(format!("unexpected response: {other:?}")),
        Err(e) => {
            // Distinguish "daemon not up" (common: first-ever generate
            // on a fresh install) from other transport failures so the
            // operator sees a friendlier message in the common case.
            // `send_command` surfaces `connection timeout`, raw OS
            // connect errors, or the "No such file or directory" from
            // an absent socket via anyhow — match on the rendered
            // string, which is stable for UnixStream::connect errors.
            let msg = e.to_string();
            // Shared classifier with ipc_reload so both reload paths agree
            // — this also picks up "response timeout", which a bespoke
            // string match here would otherwise mis-report as a hard
            // reload failure rather than a read-side stall.
            if crate::cli::commands::ipc_reload::is_unreachable_transport_msg(&msg) {
                ReloadOutcome::DaemonUnreachable
            } else {
                ReloadOutcome::ReloadFailed(msg)
            }
        }
    }
}

/// Mutate `[api].token_hash` in the master file and validate/promote it through
/// the held config-tree guard.
///
/// Every other top-level section survives the round-trip **including its
/// comments and key order**, because only the target item is changed in the
/// original format-preserving document.
fn write_token_hash_to_master(
    guard: &ConfigWriteLock,
    config_path: &Path,
    new_hash: &str,
) -> anyhow::Result<()> {
    let (_, raw) = read_or_empty_locked(guard, config_path, config_path)?;
    let raw = raw.ok_or_else(|| anyhow::anyhow!("cannot read {}", config_path.display()))?;
    let mut doc = raw
        .parse::<DocumentMut>()
        .with_context(|| format!("cannot parse {} as TOML", config_path.display()))?;
    super::toml_write::table_mut(&mut doc, "api")?
        .insert("token_hash", toml_edit::value(new_hash.to_string()));
    let prepared =
        prepare_raw_validated_single_locked(guard, config_path, config_path, doc.to_string())?;
    commit_prevalidated_single_write(prepared)?;
    Ok(())
}

fn format_load_errs(errs: Vec<ConfigError>) -> anyhow::Error {
    anyhow::anyhow!(
        "cannot load config for token operation: {}",
        format_errs_flat(errs)
    )
}

pub(crate) fn format_errs_flat(errs: Vec<ConfigError>) -> String {
    let mut s = String::new();
    for (i, e) in errs.iter().enumerate() {
        if i > 0 {
            s.push_str("; ");
        }
        s.push_str(&e.to_string());
    }
    s
}

#[cfg(test)]
mod tests {
    use super::super::target::write_value_validated_locked;
    use super::*;
    use toml::Value;

    /// Full v1 master covering every section that a legacy writer used to
    /// silently drop. The regenerate round-trip must preserve each one
    /// byte-for-byte on disk.
    const FULL_V1_MASTER: &str = r#"schema_version = 4
includes = ["devices.d/*.toml", "profiles.d/*.toml"]

[server]
listen = "127.0.0.1:15353"
default_profile = "default"
default_blocked_ttl_secs = 300

[socket]
path = "/tmp/purge-warden-cs3-test.sock"

[api]
token_hash = ""

[[blocklists]]
id = "privacy-ads"
display_name = "Privacy: ads"
url = "https://lists.purge.cc/privacy/ads.txt"

[profiles.default]
display_name = "Default"

[[devices]]
id = "edo-laptop"
display_name = "Dweller Laptop"
ip = "10.0.0.10"
profile = "default"

[[retired]]
id = "legacy-id"
type = "device"
retired_at = "2024-01-01T00:00:00Z"

[upstream]
servers = ["192.0.2.1:53"]
"#;

    fn tmpdir() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    fn write_master_to(dir: &tempfile::TempDir, body: &str) -> std::path::PathBuf {
        let path = dir.path().join("config.toml");
        std::fs::write(&path, body).unwrap();
        path
    }

    /// Model a peer writer changing the master while it owns the same tree.
    /// The token commands must load this post-lock state rather than overwrite
    /// it from a read that happened before their acquisition.
    fn peer_updates_master(
        guard: &ConfigWriteLock,
        master: &Path,
        token_hash: Option<&str>,
        default_blocked_ttl_secs: i64,
    ) {
        let (mut doc, _) = read_or_empty_locked(guard, master, master).unwrap();
        let root = doc.as_table_mut().unwrap();
        let server = root
            .get_mut("server")
            .and_then(Value::as_table_mut)
            .unwrap();
        server.insert(
            "default_blocked_ttl_secs".to_string(),
            Value::Integer(default_blocked_ttl_secs),
        );
        if let Some(token_hash) = token_hash {
            root.get_mut("api")
                .and_then(Value::as_table_mut)
                .unwrap()
                .insert(
                    "token_hash".to_string(),
                    Value::String(token_hash.to_string()),
                );
        }
        write_value_validated_locked(guard, master, master, &doc).unwrap();
    }

    fn block_until_contended(receiver: &std::sync::mpsc::Receiver<()>, operation: &str) {
        use std::time::Duration;

        receiver
            .recv_timeout(Duration::from_secs(2))
            .unwrap_or_else(|error| panic!("{operation} did not contend before loading: {error}"));
    }

    fn assert_sidecar_save_follows_released_guard(
        operation: &'static str,
        config_path: &Path,
        run: impl FnOnce() -> anyhow::Result<()>,
    ) {
        use std::sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        };

        let reached_save = Arc::new(AtomicBool::new(false));
        let reached_save_hook = Arc::clone(&reached_save);
        let config_path = config_path.to_path_buf();
        with_sidecar_save_hook(
            move || {
                reached_save_hook.store(true, Ordering::SeqCst);
                let probe = crate::config::write_lock::with_test_hook(
                    move |event| {
                        assert_ne!(
                            event,
                            crate::config::write_lock::TestEvent::Contended,
                            "{operation} retained the config-tree guard through sidecar save"
                        );
                    },
                    || {
                        acquire_for_write(&config_path)
                            .expect("sidecar save must follow a released config-tree guard")
                    },
                );
                drop(probe);
            },
            || run().unwrap(),
        );
        assert!(
            reached_save.load(Ordering::SeqCst),
            "{operation} did not reach the sidecar-save seam"
        );
    }

    // ── Regenerate on ConfigV1 ─────────────────────────────────────────

    #[tokio::test]
    async fn regenerate_preserves_v1_schema() {
        // Every top-level v1 section that a legacy writer used to
        // silently drop must survive a regenerate round-trip. We assert
        // semantic preservation via the v1 loader — `toml::to_string_pretty`
        // reformats whitespace and key order, but the structured content
        // is the authoritative comparison.
        let dir = tmpdir();
        let master = write_master_to(&dir, FULL_V1_MASTER);
        let token_path = dir.path().join("token");
        let no_socket = dir.path().join("nope.sock");

        run_regenerate(&master, &no_socket, &token_path)
            .await
            .unwrap();

        let now = time::OffsetDateTime::now_utc();
        let loaded = loader::load_config(&master, now).expect("master reloads cleanly");
        let cfg = &loaded.config;

        assert_eq!(cfg.schema_version, SCHEMA_VERSION_V1);
        assert_eq!(cfg.includes.len(), 2);
        assert!(cfg.includes.iter().any(|g| g.contains("devices.d")));
        assert!(cfg.includes.iter().any(|g| g.contains("profiles.d")));
        assert_eq!(cfg.server.default_blocked_ttl_secs, 300);
        assert!(cfg.server.default_profile.is_some());
        assert_eq!(cfg.blocklists.len(), 1);
        assert_eq!(cfg.blocklists[0].id.as_str(), "privacy-ads");
        assert!(cfg.profiles.contains_key("default"));
        assert_eq!(cfg.devices.len(), 1);
        assert_eq!(cfg.devices[0].id.as_str(), "edo-laptop");
        assert_eq!(cfg.retired.len(), 1);
        assert_eq!(cfg.retired[0].id.as_str(), "legacy-id");
        // And the new token hash landed.
        assert_eq!(cfg.api.token_hash.as_deref().unwrap().len(), 64);
    }

    #[tokio::test]
    async fn regenerate_updates_token_hash_in_master() {
        // Only `[api].token_hash` may change; every other key is stable
        // across the round-trip.
        let dir = tmpdir();
        let master = write_master_to(&dir, FULL_V1_MASTER);
        let token_path = dir.path().join("token");
        let no_socket = dir.path().join("nope.sock");

        let before: toml::Value = std::fs::read_to_string(&master).unwrap().parse().unwrap();

        run_regenerate(&master, &no_socket, &token_path)
            .await
            .unwrap();

        let after: toml::Value = std::fs::read_to_string(&master).unwrap().parse().unwrap();
        let after_api = after.get("api").unwrap().as_table().unwrap();
        let before_api = before.get("api").unwrap().as_table().unwrap();

        let new_hash = after_api.get("token_hash").unwrap().as_str().unwrap();
        assert!(!new_hash.is_empty());
        assert_ne!(
            new_hash,
            before_api.get("token_hash").unwrap().as_str().unwrap()
        );

        // Compare every other top-level key for byte-for-byte equality
        // through the round-trip.
        let before_root = before.as_table().unwrap();
        let after_root = after.as_table().unwrap();
        for (key, value) in before_root {
            if key == "api" {
                continue;
            }
            let after_value = after_root
                .get(key)
                .unwrap_or_else(|| panic!("key `{key}` vanished"));
            assert_eq!(
                value, after_value,
                "key `{key}` changed across regenerate round-trip"
            );
        }
    }

    #[tokio::test]
    async fn regenerate_bails_on_broken_config() {
        // A master that fails `load_config` (e.g. missing `schema_version`
        // on a v1 tree with `includes`) must stop the regenerate before
        // any on-disk mutation or plaintext save.
        let dir = tmpdir();
        let master = dir.path().join("config.toml");
        // Broken: references `schema_version` implicitly via `includes`
        // but never declares one. v1 loader rejects.
        let broken = r#"includes = ["devices.d/*.toml"]
[server]
default_profile = "default"
[profiles.default]
display_name = "Default"
"#;
        std::fs::write(&master, broken).unwrap();
        let token_path = dir.path().join("token");
        let no_socket = dir.path().join("nope.sock");

        let err = run_regenerate(&master, &no_socket, &token_path)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("cannot load config"),
            "error must name the load failure: {err}"
        );

        // Master is unchanged byte-for-byte.
        assert_eq!(std::fs::read_to_string(&master).unwrap(), broken);
        // Plaintext was never saved.
        assert!(
            !token_path.exists(),
            "plaintext must not hit disk when regenerate bails"
        );
    }

    #[tokio::test]
    async fn regenerate_works_when_daemon_not_running() {
        // No socket at the configured path → reload step is a no-op,
        // but the rest of the flow (hash update + plaintext save)
        // succeeds.
        let dir = tmpdir();
        let master = write_master_to(&dir, FULL_V1_MASTER);
        let token_path = dir.path().join("token");
        let absent_socket = dir.path().join("ghost.sock");
        assert!(!absent_socket.exists());

        run_regenerate(&master, &absent_socket, &token_path)
            .await
            .unwrap();

        // Master carries the new hash.
        let now = time::OffsetDateTime::now_utc();
        let loaded = loader::load_config(&master, now).unwrap();
        assert_eq!(loaded.config.api.token_hash.as_deref().unwrap().len(), 64);
        // Plaintext was saved.
        assert!(token_path.exists());
        let saved = std::fs::read_to_string(&token_path).unwrap();
        assert!(
            saved.starts_with("ps_"),
            "saved token must be plaintext format, got {saved:?}"
        );
    }

    #[tokio::test]
    async fn regenerate_triggers_ipc_reload_when_daemon_running() {
        // Stand up a minimal stub IPC server that records every command
        // it receives and always replies `Ok`. After `run_regenerate`,
        // the recorded commands must include at least one `Reload`.
        use crate::ipc::protocol::IpcResponse;
        use std::sync::{Arc, Mutex};
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        use tokio::net::UnixListener;

        let dir = tmpdir();
        let master = write_master_to(&dir, FULL_V1_MASTER);
        let token_path = dir.path().join("token");
        let socket_path = dir.path().join("stub.sock");

        // Seed an OLD token on disk so `run_regenerate` has something to
        // authenticate the Reload with.
        save_token_at(&token_path, "ps_oldoldold").unwrap();

        let received: Arc<Mutex<Vec<IpcCommand>>> = Arc::new(Mutex::new(Vec::new()));
        let listener = UnixListener::bind(&socket_path).unwrap();
        let received_bg = received.clone();
        let master_for_server = master.clone();
        let server = tokio::spawn(async move {
            if let Ok((stream, _)) = listener.accept().await {
                let (reader, mut writer) = stream.into_split();
                let mut reader = BufReader::new(reader);
                let mut line = String::new();
                if reader.read_line(&mut line).await.is_ok() {
                    if let Ok(cmd) = serde_json::from_str::<IpcCommand>(line.trim()) {
                        received_bg.lock().unwrap().push(cmd);
                    }
                }
                // This happens while `run_regenerate` awaits the reply. A
                // contended probe would mean it carried its OS guard into IPC.
                let probe = crate::config::write_lock::with_test_hook(
                    |event| {
                        assert_ne!(
                            event,
                            crate::config::write_lock::TestEvent::Contended,
                            "run_regenerate retained the config-tree guard while awaiting reload"
                        );
                    },
                    || {
                        acquire_for_write(&master_for_server)
                            .expect("reload handler must acquire the released config-tree guard")
                    },
                );
                drop(probe);
                let resp = IpcResponse::Ok {
                    message: "stub acknowledged".into(),
                };
                let mut body = serde_json::to_string(&resp).unwrap();
                body.push('\n');
                let _ = writer.write_all(body.as_bytes()).await;
                let _ = writer.shutdown().await;
            }
        });

        run_regenerate(&master, &socket_path, &token_path)
            .await
            .unwrap();
        server.await.unwrap();

        let recorded = received.lock().unwrap().clone();
        assert_eq!(recorded.len(), 1, "exactly one IPC call expected");
        match &recorded[0] {
            IpcCommand::Reload { token } => {
                assert_eq!(
                    token.as_deref(),
                    Some("ps_oldoldold"),
                    "reload must authenticate with the OLD plaintext"
                );
            }
            other => panic!("expected Reload, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn generate_fails_if_token_hash_already_set() {
        // The master has `api.token_hash = "deadbeef..."`. `run_generate`
        // must refuse with the same "already exists" error as the v0
        // path used to.
        let dir = tmpdir();
        let with_token = FULL_V1_MASTER.replace(
            "[api]\ntoken_hash = \"\"",
            "[api]\ntoken_hash = \"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"",
        );
        let master = write_master_to(&dir, &with_token);
        let token_path = dir.path().join("token");
        let no_socket = dir.path().join("nope.sock");

        let err = run_generate(&master, &no_socket, &token_path)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("already exists"),
            "unexpected error: {err}"
        );
        // Master bytes unchanged.
        assert_eq!(std::fs::read_to_string(&master).unwrap(), with_token);
        // Plaintext never saved.
        assert!(!token_path.exists());
    }

    // ── Contract tests for the v1 path ────────────────────────────────

    #[tokio::test]
    async fn generate_writes_hash_to_v1_master() {
        let dir = tmpdir();
        let master = write_master_to(&dir, FULL_V1_MASTER);
        let token_path = dir.path().join("token");
        let no_socket = dir.path().join("nope.sock");

        run_generate(&master, &no_socket, &token_path)
            .await
            .unwrap();

        let now = time::OffsetDateTime::now_utc();
        let loaded = loader::load_config(&master, now).expect("v1 master reloads");
        let hash = loaded
            .config
            .api
            .token_hash
            .expect("token_hash must be set after generate");
        assert_eq!(hash.len(), 64);
        assert!(token_path.exists());
    }

    #[tokio::test]
    async fn regenerate_replaces_existing_hash() {
        let dir = tmpdir();
        let with_token = FULL_V1_MASTER.replace(
            "[api]\ntoken_hash = \"\"",
            "[api]\ntoken_hash = \"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"",
        );
        let master = write_master_to(&dir, &with_token);
        let token_path = dir.path().join("token");
        let no_socket = dir.path().join("nope.sock");

        run_regenerate(&master, &no_socket, &token_path)
            .await
            .unwrap();

        let now = time::OffsetDateTime::now_utc();
        let loaded = loader::load_config(&master, now).unwrap();
        let new_hash = loaded
            .config
            .api
            .token_hash
            .expect("token_hash must be set after regenerate");
        assert_eq!(new_hash.len(), 64);
        assert_ne!(
            new_hash, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "token_hash must be replaced"
        );
    }

    #[tokio::test]
    async fn token_hash_edits_preserve_multiline_scalar_array_comments() {
        let includes = r#"includes = [
    "devices.d/*.toml", # device definitions
    # profile definitions
    "profiles.d/*.toml",
]
"#;
        let servers = r#"servers = [
    "192.0.2.1:53", # primary resolver
    # emergency resolver
    "192.0.2.2:53",
]
"#;
        let master_text = FULL_V1_MASTER
            .replace(
                "includes = [\"devices.d/*.toml\", \"profiles.d/*.toml\"]\n",
                includes,
            )
            .replace("servers = [\"192.0.2.1:53\"]\n", servers);
        let dir = tmpdir();
        let master = write_master_to(&dir, &master_text);
        let token_path = dir.path().join("token");
        let no_socket = dir.path().join("nope.sock");

        run_generate(&master, &no_socket, &token_path)
            .await
            .unwrap();
        let after_generate = std::fs::read_to_string(&master).unwrap();
        assert!(after_generate.contains(includes));
        assert!(after_generate.contains(servers));
        let generated_hash = after_generate.parse::<Value>().unwrap()["api"]["token_hash"]
            .as_str()
            .unwrap()
            .to_owned();

        run_regenerate(&master, &no_socket, &token_path)
            .await
            .unwrap();
        let after_regenerate = std::fs::read_to_string(&master).unwrap();
        assert!(after_regenerate.contains(includes));
        assert!(after_regenerate.contains(servers));
        let regenerated_hash = after_regenerate.parse::<Value>().unwrap()["api"]["token_hash"]
            .as_str()
            .unwrap()
            .to_owned();
        assert_ne!(generated_hash, regenerated_hash);
    }

    #[test]
    fn token_sidecar_save_follows_released_config_guard() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let generate_dir = tmpdir();
        let generate_master = write_master_to(&generate_dir, FULL_V1_MASTER);
        let generate_token = generate_dir.path().join("token");
        let generate_socket = generate_dir.path().join("nope.sock");
        assert_sidecar_save_follows_released_guard("generate", &generate_master, || {
            runtime.block_on(run_generate(
                &generate_master,
                &generate_socket,
                &generate_token,
            ))
        });

        let regenerate_dir = tmpdir();
        let regenerate_master = write_master_to(&regenerate_dir, FULL_V1_MASTER);
        let regenerate_token = regenerate_dir.path().join("token");
        let regenerate_socket = regenerate_dir.path().join("nope.sock");
        save_token_at(&regenerate_token, "ps_oldplaintext").unwrap();
        assert_sidecar_save_follows_released_guard("regenerate", &regenerate_master, || {
            runtime.block_on(run_regenerate(
                &regenerate_master,
                &regenerate_socket,
                &regenerate_token,
            ))
        });
    }

    #[tokio::test]
    async fn token_operations_refuse_a_migration_fence_before_master_or_sidecar_mutation() {
        // Generate must hit the acquisition fence before it evaluates the
        // already-exists condition, or a pre-existing hash would mask the
        // migration refusal.
        let generate_dir = tmpdir();
        let with_token = FULL_V1_MASTER.replace(
            "[api]\ntoken_hash = \"\"",
            "[api]\ntoken_hash = \"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"",
        );
        let generate_master = write_master_to(&generate_dir, &with_token);
        let generate_token = generate_dir.path().join("token");
        let migration = crate::config::write_lock::acquire_for_migration(&generate_master).unwrap();
        crate::config::migration_journal::create_fence(&migration).unwrap();
        drop(migration);

        let generate_err = run_generate(
            &generate_master,
            &generate_dir.path().join("nope.sock"),
            &generate_token,
        )
        .await
        .expect_err("a migration fence must refuse generate");
        assert!(
            generate_err.to_string().contains("migration"),
            "unexpected error: {generate_err:#}"
        );
        assert!(
            !generate_err.to_string().contains("already exists"),
            "the already-exists check must not run before the fence: {generate_err:#}"
        );
        assert_eq!(
            std::fs::read_to_string(&generate_master).unwrap(),
            with_token
        );
        assert!(
            !generate_token.exists(),
            "generate must not persist plaintext after a fence refusal"
        );

        let regenerate_dir = tmpdir();
        let regenerate_master = write_master_to(&regenerate_dir, FULL_V1_MASTER);
        let regenerate_token = regenerate_dir.path().join("token");
        save_token_at(&regenerate_token, "ps_oldplaintext").unwrap();
        let master_before = std::fs::read(&regenerate_master).unwrap();
        let token_before = std::fs::read(&regenerate_token).unwrap();
        let migration =
            crate::config::write_lock::acquire_for_migration(&regenerate_master).unwrap();
        crate::config::migration_journal::create_fence(&migration).unwrap();
        drop(migration);

        let regenerate_err = run_regenerate(
            &regenerate_master,
            &regenerate_dir.path().join("nope.sock"),
            &regenerate_token,
        )
        .await
        .expect_err("a migration fence must refuse regenerate");
        assert!(
            regenerate_err.to_string().contains("migration"),
            "unexpected error: {regenerate_err:#}"
        );
        assert_eq!(std::fs::read(&regenerate_master).unwrap(), master_before);
        assert_eq!(std::fs::read(&regenerate_token).unwrap(), token_before);
    }

    #[test]
    fn generate_observes_a_token_and_peer_edit_landed_before_its_acquisition() {
        let dir = tmpdir();
        let master = write_master_to(&dir, FULL_V1_MASTER);
        let token_path = dir.path().join("token");
        let socket_path = dir.path().join("nope.sock");
        let held = acquire_for_write(&master).unwrap();
        let (contended_tx, contended_rx) = std::sync::mpsc::channel();

        let result = std::thread::scope(|scope| {
            let worker_master = master.clone();
            let worker_token = token_path.clone();
            let worker_socket = socket_path.clone();
            let worker = scope.spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                crate::config::write_lock::with_test_hook(
                    move |event| {
                        if event == crate::config::write_lock::TestEvent::Contended {
                            let _ = contended_tx.send(());
                        }
                    },
                    || {
                        runtime.block_on(run_generate(
                            &worker_master,
                            &worker_socket,
                            &worker_token,
                        ))
                    },
                )
            });

            block_until_contended(&contended_rx, "generate");
            peer_updates_master(
                &held,
                &master,
                Some("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
                301,
            );
            let peer_bytes = std::fs::read(&master).unwrap();
            drop(held);
            (worker.join().unwrap(), peer_bytes)
        });

        let (error, peer_bytes) = result;
        assert!(error
            .expect_err("generate must see the peer's token")
            .to_string()
            .contains("already exists"));
        assert_eq!(
            std::fs::read(&master).unwrap(),
            peer_bytes,
            "the stale generate must not lose the peer's unrelated master edit"
        );
        assert!(
            !token_path.exists(),
            "the rejected stale generate must not save plaintext"
        );
    }

    #[test]
    fn regenerate_preserves_a_peer_edit_landed_before_its_acquisition() {
        let dir = tmpdir();
        let master = write_master_to(&dir, FULL_V1_MASTER);
        let token_path = dir.path().join("token");
        let socket_path = dir.path().join("nope.sock");
        save_token_at(&token_path, "ps_oldplaintext").unwrap();
        let held = acquire_for_write(&master).unwrap();
        let (contended_tx, contended_rx) = std::sync::mpsc::channel();

        let peer_value = std::thread::scope(|scope| {
            let worker_master = master.clone();
            let worker_token = token_path.clone();
            let worker_socket = socket_path.clone();
            let worker = scope.spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                crate::config::write_lock::with_test_hook(
                    move |event| {
                        if event == crate::config::write_lock::TestEvent::Contended {
                            let _ = contended_tx.send(());
                        }
                    },
                    || {
                        runtime.block_on(run_regenerate(
                            &worker_master,
                            &worker_socket,
                            &worker_token,
                        ))
                    },
                )
            });

            block_until_contended(&contended_rx, "regenerate");
            peer_updates_master(&held, &master, None, 301);
            let peer_value = std::fs::read_to_string(&master)
                .unwrap()
                .parse::<Value>()
                .unwrap();
            drop(held);
            worker.join().unwrap().unwrap();
            peer_value
        });

        let after: Value = std::fs::read_to_string(&master).unwrap().parse().unwrap();
        assert_eq!(
            after.get("server"),
            peer_value.get("server"),
            "regenerate must preserve the peer's unrelated master field"
        );
        assert_eq!(
            after
                .get("api")
                .and_then(Value::as_table)
                .and_then(|api| api.get("token_hash"))
                .and_then(Value::as_str)
                .unwrap()
                .len(),
            64,
            "regenerate must update only the token hash"
        );
    }

    #[tokio::test]
    async fn generate_through_master_alias_writes_only_in_the_canonical_tree() {
        let canonical_dir = tmpdir();
        let master = write_master_to(&canonical_dir, FULL_V1_MASTER);
        let alias_dir = tmpdir();
        let alias = alias_dir.path().join("dashboard.toml");
        std::os::unix::fs::symlink(&master, &alias).unwrap();
        let token_path = canonical_dir.path().join("token");

        run_generate(&alias, &alias_dir.path().join("nope.sock"), &token_path)
            .await
            .unwrap();

        assert!(
            std::fs::symlink_metadata(&alias)
                .unwrap()
                .file_type()
                .is_symlink(),
            "the alias itself must remain a symlink"
        );
        assert_eq!(
            loader::load_config(&master, time::OffsetDateTime::now_utc())
                .unwrap()
                .config
                .api
                .token_hash
                .as_deref()
                .unwrap()
                .len(),
            64
        );
        assert!(
            !alias_dir.path().join(".warden-config.lock").exists(),
            "the alias directory must not receive a config lock"
        );
        let alias_entries: Vec<_> = std::fs::read_dir(alias_dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(
            alias_entries,
            vec![std::ffi::OsString::from("dashboard.toml")],
            "no config artifact may be created beside the alias"
        );
    }

    #[test]
    fn token_hash_writer_refuses_a_guard_from_another_tree_before_bytes_change() {
        let left = tmpdir();
        let right = tmpdir();
        let left_master = write_master_to(&left, FULL_V1_MASTER);
        let right_master = write_master_to(&right, FULL_V1_MASTER);
        let before = std::fs::read(&right_master).unwrap();
        let guard = acquire_for_write(&left_master).unwrap();

        let error = write_token_hash_to_master(
            &guard,
            &right_master,
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .expect_err("a guard must not write another config tree");
        assert!(
            error.to_string().contains("config guard belongs"),
            "got: {error:#}"
        );
        assert_eq!(std::fs::read(&right_master).unwrap(), before);
    }

    #[test]
    fn token_writers_keep_one_guarded_acquire_load_write_drop_pipeline() {
        let source = include_str!("token.rs");
        let operations = [
            (
                "run_generate",
                "pub async fn run_generate",
                "/// Regenerate",
            ),
            (
                "run_regenerate",
                "pub async fn run_regenerate",
                "/// Result of the post-regenerate IPC reload attempt.",
            ),
        ];

        for (name, start_marker, end_marker) in operations {
            let start = source.find(start_marker).unwrap();
            let end = source[start..]
                .find(end_marker)
                .map(|offset| start + offset)
                .unwrap();
            let body = &source[start..end];
            assert_eq!(
                body.match_indices("acquire_for_write(config_path)").count(),
                1,
                "{name} must acquire exactly one config-tree guard"
            );
            let acquire = body.find("acquire_for_write(config_path)").unwrap();
            let load = body
                .find("load_config_for_schema_under_guard")
                .unwrap_or_else(|| panic!("{name} does not load under its guard"));
            let write = body
                .find("write_token_hash_to_master(&guard")
                .unwrap_or_else(|| panic!("{name} does not write through its guard"));
            let sidecar = body
                .find("let saved_path")
                .unwrap_or_else(|| panic!("{name} has no post-guard sidecar save"));
            let guarded = &body[acquire..sidecar];
            assert!(acquire < load && load < write && write < sidecar);
            assert!(
                !guarded.contains(".await"),
                "{name} awaits while holding the OS guard"
            );
            assert!(
                !guarded.contains("loader::load_config("),
                "{name} uses the normal loader inside its guarded region"
            );
            assert!(
                !guarded.contains("atomic_write_and_validate")
                    && !guarded.contains("toml_write::edit_document"),
                "{name} uses a retired path-based writer inside its guarded region"
            );
        }

        let helper_start = source.find("fn write_token_hash_to_master").unwrap();
        let helper_end = source[helper_start..]
            .find("fn format_load_errs")
            .map(|offset| helper_start + offset)
            .unwrap();
        let helper = &source[helper_start..helper_end];
        assert!(helper.contains("read_or_empty_locked(guard"));
        assert!(helper.contains("parse::<DocumentMut>()"));
        assert!(helper.contains("super::toml_write::table_mut"));
        assert!(helper.contains("prepare_raw_validated_single_locked"));
        assert!(helper.contains("commit_prevalidated_single_write"));
        assert!(!helper.contains("acquire_for_write"));
        assert!(!helper.contains("write_value_validated_locked"));
        assert!(!helper.contains("atomic_write"));
    }
}
