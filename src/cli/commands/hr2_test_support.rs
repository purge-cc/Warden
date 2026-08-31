//! Sprint 36 HR2 — shared test fixtures for hot-reload wiring tests.
//!
//! Not used in the production build. Exposed only under `#[cfg(test)]`
//! so the five per-module HR2 tests (devices, groups, subnets,
//! blocklists, schedules) reuse the same stub IPC server and `$HOME`-
//! sandboxing scaffolding without duplicating ~80 lines per module.
//!
//! # Why `$HOME` mutation instead of loader injection?
//!
//! The HR1 unit tests in `ipc_reload` inject a synthetic token loader
//! to avoid mutating process-global env. The HR2 tests here have a
//! different goal: exercise the full production stack end-to-end
//! (`run_add` → `attempt_reload` → `load_token` → `send_command` →
//! stub daemon). Loader injection would require plumbing a test hook
//! through every editor signature, which bleeds test concerns into
//! production surface. The env mutation is hermetic per-test via the
//! guard returned below, and serialised through a tokio mutex so
//! parallel `cargo test` doesn't interleave.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use tokio::sync::{Mutex, MutexGuard};

use crate::ipc::auth_token::save_token_at;
use crate::ipc::protocol::{IpcCommand, IpcResponse};

/// Recorded commands received by [`stub_reload_ok`] — one `Reload`
/// per successful editor call.
pub type Recorded = Arc<std::sync::Mutex<Vec<IpcCommand>>>;

/// Bind a stub IPC server at `sock` that records the first command it
/// receives and responds with `IpcResponse::Ok`. Returns the server
/// handle (await it at the end of the test) and the recorded-commands
/// buffer.
pub async fn stub_reload_ok(sock: PathBuf) -> (tokio::task::JoinHandle<()>, Recorded) {
    let listener = UnixListener::bind(&sock).unwrap();
    let recorded: Recorded = Arc::new(std::sync::Mutex::new(Vec::new()));
    let record_bg = recorded.clone();
    let handle = tokio::spawn(async move {
        if let Ok((stream, _)) = listener.accept().await {
            let (reader, mut writer) = stream.into_split();
            let mut reader = BufReader::new(reader);
            let mut line = String::new();
            if reader.read_line(&mut line).await.is_ok() {
                if let Ok(cmd) = serde_json::from_str::<IpcCommand>(line.trim()) {
                    record_bg.lock().unwrap().push(cmd);
                }
            }
            let resp = IpcResponse::Ok {
                message: "stub acknowledged".into(),
            };
            let mut body = serde_json::to_string(&resp).unwrap();
            body.push('\n');
            let _ = writer.write_all(body.as_bytes()).await;
            let _ = writer.shutdown().await;
        }
    });
    (handle, recorded)
}

/// Seed the plaintext token under `$HOME/.config/purge-warden/token`
/// so [`attempt_reload`]'s `load_token()` finds it. Call this INSIDE
/// the [`env_home`] guard.
///
/// [`attempt_reload`]: super::ipc_reload::attempt_reload
pub fn seed_token_for_test(home: &Path) {
    let token_path = home.join(".config/purge-warden/token");
    save_token_at(&token_path, SEEDED_TOKEN).unwrap();
}

/// Constant token string that [`seed_token_for_test`] writes — tests
/// can assert it on the recorded `Reload` command without hard-coding
/// the literal twice.
pub const SEEDED_TOKEN: &str = "ps_hr2-test-token";

/// Process-global mutex for HR2 tests that mutate `$HOME` /
/// `$XDG_CONFIG_HOME`. Shared across all five module test suites.
static ENV_LOCK: Mutex<()> = Mutex::const_new(());

/// Guard returned by [`env_home`]: restores the prior env on drop.
///
/// The tokio [`MutexGuard`] field keeps `$HOME` exclusive for the
/// duration of the test; since tokio mutex guards are `Send`, they can
/// legally cross `.await` points — which unlocks the end-to-end stub
/// server flow that `std::sync::Mutex` would have forbidden under
/// clippy's `await_holding_lock` lint.
pub struct EnvHomeGuard {
    prev_home: Option<std::ffi::OsString>,
    prev_xdg: Option<std::ffi::OsString>,
    _lock: MutexGuard<'static, ()>,
}

impl Drop for EnvHomeGuard {
    fn drop(&mut self) {
        match &self.prev_home {
            Some(v) => std::env::set_var("HOME", v),
            None => std::env::remove_var("HOME"),
        }
        match &self.prev_xdg {
            Some(v) => std::env::set_var("XDG_CONFIG_HOME", v),
            None => std::env::remove_var("XDG_CONFIG_HOME"),
        }
    }
}

/// Take the global env mutex and pin `$HOME` to `home`, unsetting
/// `$XDG_CONFIG_HOME` so [`crate::ipc::auth_token::default_token_path`]
/// resolves to `$HOME/.config/purge-warden/token`.
pub async fn env_home(home: &Path) -> EnvHomeGuard {
    // A panicking test panics through `.await`, which drops the
    // MutexGuard and releases the lock — no poisoning semantics on
    // tokio::sync::Mutex. Other tests just wait, then proceed.
    let lock = ENV_LOCK.lock().await;
    let prev_home = std::env::var_os("HOME");
    let prev_xdg = std::env::var_os("XDG_CONFIG_HOME");
    std::env::set_var("HOME", home);
    std::env::remove_var("XDG_CONFIG_HOME");
    EnvHomeGuard {
        prev_home,
        prev_xdg,
        _lock: lock,
    }
}

/// Assert that `recorded` contains exactly one `Reload` carrying the token the
/// production resolver yields — NOT the literal seed.
///
/// `s-rev2606-hr2-tests-fhs-token-collision`: token resolution is FHS-first
/// (`auth_token::default_token_path` tries `/var/lib/purge-warden/token` before
/// the `$HOME/.config` seed). On a host that has that FHS file (e.g. the Debian
/// CT), the CLI's `attempt_reload` → `load_token()` sends the LIVE token, so the
/// stub records the live token, not the seed — asserting the literal seed
/// spuriously fails there. Resolving the expected value through the SAME
/// `load_token()` chain (under the still-active [`env_home`] guard) makes the
/// test observe exactly what prod observes: the two agree on an FHS host (both =
/// live token) and on a dev box (both = the seed). No production-path change,
/// and no env override on the security-critical token path.
pub fn assert_single_reload_with_resolved_token(recorded: &Recorded) {
    let expected = crate::ipc::auth_token::load_token()
        .expect("load_token() IO error")
        .expect("token must resolve (seed_token_for_test wrote one, or an FHS token exists)");
    let cmds = recorded.lock().unwrap();
    assert_eq!(cmds.len(), 1, "exactly one Reload expected");
    match &cmds[0] {
        IpcCommand::Reload { token } => {
            assert_eq!(
                token.as_deref(),
                Some(expected.as_str()),
                "Reload must carry the token the resolver yields (FHS-first)"
            );
        }
        other => panic!("expected Reload, got {other:?}"),
    }
}
