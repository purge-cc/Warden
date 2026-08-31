//! Sprint 36 HR1 — Shared IPC-reload helper for post-write hot reload.
//!
//! Every `warden` subcommand that mutates the v1 master on disk (Sprint
//! 34's `devices`/`groups`/`subnets`/`schedules`/`blocklists` editors,
//! plus `profiles set block-response` from Sprint 23) calls
//! [`attempt_reload`] after the write lands atomically via CS2. The
//! result is classified into a [`ReloadOutcome`] and surfaced to the
//! operator through [`report_reload_outcome`] with the four frozen
//! strings documented in `_docs/features/config_safety_v12.md` §2 HR1.
//!
//! # Why not reuse `token::attempt_ipc_reload`?
//!
//! The token-rotation path in [`crate::cli::commands::token`]
//! pre-attaches the *old* plaintext to `IpcCommand::Reload` because the
//! daemon still holds the old hash in memory until the reload completes.
//! Every other post-write reload authenticates with the *current* token
//! from disk — which is the same string the daemon already accepts.
//! Unifying the two would muddy both contracts, so `token.rs` keeps its
//! specialised helper and this module owns the generic "post-write" one.
//!
//! # Panel refinements (review 2026-04-23)
//!
//! - `"response timeout"` from `send_command` is classified as
//!   [`ReloadOutcome::DaemonUnreachable`]. The design doc §2 HR1 only
//!   listed the three connect-side errors; a read-side stall is
//!   operationally equivalent (daemon can't tell us it reloaded).
//! - [`load_token`] returning `Err(io::Error)` — file present but
//!   unreadable — maps to [`ReloadOutcome::NoToken`] with an extra
//!   diagnostic line on stderr naming the I/O error. The design doc
//!   §2 HR1 did not distinguish "absent" from "unreadable"; both yield
//!   the same operator action (regenerate or restart), so the shared
//!   variant is correct and the extra line resolves the ambiguity.
//! - One-shot retry after 50 ms on `ReloadFailed` whose message looks
//!   like an authentication mismatch. Mitigates the known Sprint 35
//!   race between a concurrent `warden token regenerate` and any
//!   entity-editor command (see `config_safety_v11.md` §8.3 pitfall
//!   3). A single retry is enough because the rotation window is
//!   bounded by a single daemon reload; more retries would only mask
//!   genuine auth failures.

use std::io;
use std::path::Path;
use std::time::Duration;

use crate::ipc::auth_token::load_token;
use crate::ipc::protocol::{IpcCommand, IpcResponse};
use crate::ipc::socket_client::send_command;

/// A pluggable token loader — returns `Ok(Some(t))` for a present token,
/// `Ok(None)` for an absent one, or `Err(io)` for an unreadable file.
/// Matches the contract of [`crate::ipc::auth_token::load_token`].
///
/// Injected only in tests so they can avoid mutating process-global
/// `$HOME` / `$XDG_CONFIG_HOME` (which would race under parallel
/// `cargo test`). Production call-sites use [`attempt_reload`], which
/// pins the loader to the real default-path discovery.
type TokenLoader = dyn Fn() -> io::Result<Option<String>> + Send + Sync;

/// Outcome of a post-write IPC reload request.
///
/// Produced by [`attempt_reload`] and consumed by [`report_reload_outcome`].
/// Call-sites never construct variants directly — the helper is the sole
/// entry point so the four frozen operator-facing strings stay consistent
/// across every editor subcommand.
#[derive(Debug)]
pub enum ReloadOutcome {
    /// Daemon accepted the reload — the on-disk change is now live in
    /// memory without a restart.
    Reloaded,
    /// Daemon is not running (no socket, connection refused, connect or
    /// read timeout). The change stays on disk and takes effect at the
    /// next daemon start.
    DaemonUnreachable,
    /// No token could be loaded from the default path
    /// (`~/.config/purge-warden/token`) — either because it does not
    /// exist or because the calling user lacks read permission. The
    /// operator must regenerate the token or restart the daemon.
    ///
    /// When the token file exists but cannot be read, [`attempt_reload`]
    /// attaches the underlying I/O error so [`report_reload_outcome`]
    /// can surface it alongside the frozen message.
    NoToken {
        /// The underlying I/O error, present when the token file exists
        /// but is unreadable (e.g. permission denied). `None` when the
        /// file is simply absent.
        io_error: Option<String>,
    },
    /// Transport succeeded but the daemon rejected the reload. The
    /// message is whatever the daemon returned (or a formatted transport
    /// failure that did not match the "unreachable" classifier).
    ReloadFailed(String),
}

/// Attempt a hot daemon reload after a successful on-disk mutation.
///
/// Never returns an error from the CLI's perspective: the mutation has
/// already landed, so even `ReloadFailed` is information, not a failure
/// the command should propagate. Call-sites invoke this AFTER
/// `validate_or_revert` returns Ok and pass the result straight to
/// [`report_reload_outcome`].
///
/// The helper auto-discovers the current token from the default path.
/// Callers that need to pre-attach a specific token (only the token-
/// rotation path does today) must keep their specialised helper — this
/// one uses the simpler "token from disk" contract.
pub async fn attempt_reload(socket_path: &Path) -> ReloadOutcome {
    attempt_reload_with(socket_path, &|| load_token()).await
}

/// Implementation of [`attempt_reload`] parameterised by the token
/// loader. Extracted so tests can inject an explicit loader instead of
/// mutating process-global `$HOME` / `$XDG_CONFIG_HOME`.
async fn attempt_reload_with(socket_path: &Path, load: &TokenLoader) -> ReloadOutcome {
    let token = match load() {
        Ok(Some(t)) if !t.is_empty() => t,
        Ok(_) => return ReloadOutcome::NoToken { io_error: None },
        Err(e) => {
            return ReloadOutcome::NoToken {
                io_error: Some(e.to_string()),
            };
        }
    };

    let outcome = send_reload(socket_path, &token).await;

    // Panel refinement: one-shot retry on authentication-like failures.
    // A concurrent `warden token regenerate` can swap the daemon's
    // token_hash between our token load and the daemon's verify. The
    // window is microseconds on a local socket and bounded by a single
    // daemon reload — a single retry after 50 ms is enough.
    if looks_like_auth_mismatch(&outcome) {
        tokio::time::sleep(Duration::from_millis(50)).await;
        // Re-load the token too: if the rotation completed, disk now
        // holds the NEW plaintext and the daemon now holds the NEW
        // hash, so the retry must read the freshest token.
        let fresh = load().ok().flatten().unwrap_or(token);
        return send_reload(socket_path, &fresh).await;
    }

    outcome
}

async fn send_reload(socket_path: &Path, token: &str) -> ReloadOutcome {
    let cmd = IpcCommand::Reload {
        token: Some(token.to_string()),
    };
    match send_command(socket_path, &cmd).await {
        Ok(IpcResponse::Ok { .. }) => ReloadOutcome::Reloaded,
        Ok(IpcResponse::Error { message }) => ReloadOutcome::ReloadFailed(message),
        Ok(other) => ReloadOutcome::ReloadFailed(format!("unexpected response: {other:?}")),
        Err(e) => classify_transport_error(e.to_string()),
    }
}

/// True when a transport-error `Display` string indicates the daemon is
/// unreachable (no socket, connection refused, or a connect/read timeout)
/// rather than a daemon that accepted the connection and rejected the reload.
///
/// Matches on the rendered string because `socket_client::send_command`
/// collapses its transport failures into `anyhow` — a typed `io::ErrorKind`
/// match would be sturdier but needs a return-type change in `ipc/`
/// (cross-section, not chased here). Shared with `token::attempt_ipc_reload`
/// so both post-write reload paths classify identically. cli §9 #7.
pub(crate) fn is_unreachable_transport_msg(msg: &str) -> bool {
    // "response timeout" (read-side stall) joins the connect-side errors: a
    // daemon that accepted the connection but never wrote a response line is,
    // from the CLI's point of view, the same as one that never accepted it —
    // we cannot know whether the reload succeeded.
    msg.contains("No such file or directory")
        || msg.contains("Connection refused")
        || msg.contains("connection timeout")
        || msg.contains("response timeout")
}

fn classify_transport_error(msg: String) -> ReloadOutcome {
    if is_unreachable_transport_msg(&msg) {
        ReloadOutcome::DaemonUnreachable
    } else {
        ReloadOutcome::ReloadFailed(msg)
    }
}

fn looks_like_auth_mismatch(outcome: &ReloadOutcome) -> bool {
    match outcome {
        ReloadOutcome::ReloadFailed(msg) => {
            let lc = msg.to_ascii_lowercase();
            lc.contains("unauthorized") || lc.contains("token")
        }
        _ => false,
    }
}

/// Print the operator-facing feedback for a reload attempt.
///
/// `stdout` for the benign outcomes (`Reloaded`, `DaemonUnreachable`),
/// `stderr` for the ones the operator may need to act on (`NoToken`,
/// `ReloadFailed`). The strings themselves are frozen in
/// `_docs/features/config_safety_v12.md` §2 HR1 so every editor speaks the
/// same vocabulary.
pub fn report_reload_outcome(outcome: &ReloadOutcome) {
    match outcome {
        ReloadOutcome::Reloaded => {
            println!("daemon reloaded — change is live");
        }
        ReloadOutcome::DaemonUnreachable => {
            println!("daemon not running — change will take effect on next start");
        }
        ReloadOutcome::NoToken { io_error } => {
            eprintln!(
                "note: change landed on disk but no admin token is available to \
                 request a daemon reload. Run `warden token generate`, or \
                 `systemctl reload purge-warden` to activate now (SIGHUP is \
                 unauthenticated, so it works without a token)."
            );
            if let Some(e) = io_error {
                eprintln!("  (token file present but unreadable: {e})");
            }
        }
        ReloadOutcome::ReloadFailed(msg) => {
            eprintln!(
                "warning: change landed on disk but the daemon rejected the reload \
                 ({msg}). Check `journalctl -u purge-warden`, then try \
                 `systemctl reload purge-warden` — it enters the same reload \
                 through SIGHUP instead of IPC. Escalate to `restart` only if \
                 that fails too: it stops DNS until the lists reload."
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixListener;

    // Tests inject a synthetic token loader via `attempt_reload_with`
    // instead of mutating process-global `$HOME` / `$XDG_CONFIG_HOME`.
    // That keeps each test hermetic and lets cargo test parallelise
    // without a global env-mutex (which would have tripped clippy's
    // `await_holding_lock` across the stub-server await points).
    fn loader_from(result: io::Result<Option<String>>) -> Arc<TokenLoader> {
        // io::Error is not Clone, so we pre-render the error string
        // once and return a fresh error per call.
        match result {
            Ok(v) => {
                let v = v.clone();
                Arc::new(move || Ok(v.clone()))
            }
            Err(e) => {
                let kind = e.kind();
                let msg = e.to_string();
                Arc::new(move || Err(io::Error::new(kind, msg.clone())))
            }
        }
    }

    /// Minimal stub IPC server: reads one command line, pushes it into
    /// a shared buffer, writes one response line. Reused across tests.
    async fn stub_server(
        socket_path: std::path::PathBuf,
        response: IpcResponse,
        record: Arc<Mutex<Vec<IpcCommand>>>,
    ) -> tokio::task::JoinHandle<()> {
        let listener = UnixListener::bind(&socket_path).unwrap();
        tokio::spawn(async move {
            if let Ok((stream, _)) = listener.accept().await {
                let (reader, mut writer) = stream.into_split();
                let mut reader = BufReader::new(reader);
                let mut line = String::new();
                if reader.read_line(&mut line).await.is_ok() {
                    if let Ok(cmd) = serde_json::from_str::<IpcCommand>(line.trim()) {
                        record.lock().unwrap().push(cmd);
                    }
                }
                let mut body = serde_json::to_string(&response).unwrap();
                body.push('\n');
                let _ = writer.write_all(body.as_bytes()).await;
                let _ = writer.shutdown().await;
            }
        })
    }

    #[tokio::test]
    async fn attempt_reload_returns_reloaded_on_stub_daemon_ok() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("ok.sock");
        let recorded: Arc<Mutex<Vec<IpcCommand>>> = Arc::new(Mutex::new(Vec::new()));
        let server = stub_server(
            sock.clone(),
            IpcResponse::Ok {
                message: "stub ok".into(),
            },
            recorded.clone(),
        )
        .await;

        let loader = loader_from(Ok(Some("ps_live-token".into())));
        let outcome = attempt_reload_with(&sock, loader.as_ref()).await;
        server.await.unwrap();

        assert!(matches!(outcome, ReloadOutcome::Reloaded), "{outcome:?}");
        let cmds = recorded.lock().unwrap();
        assert_eq!(cmds.len(), 1);
        match &cmds[0] {
            IpcCommand::Reload { token } => {
                assert_eq!(token.as_deref(), Some("ps_live-token"));
            }
            other => panic!("expected Reload, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn attempt_reload_returns_daemon_unreachable_when_socket_absent() {
        let dir = tempfile::tempdir().unwrap();
        let ghost = dir.path().join("ghost.sock");
        assert!(!ghost.exists());

        let loader = loader_from(Ok(Some("ps_live-token".into())));
        let outcome = attempt_reload_with(&ghost, loader.as_ref()).await;
        assert!(
            matches!(outcome, ReloadOutcome::DaemonUnreachable),
            "{outcome:?}"
        );
    }

    #[tokio::test]
    async fn attempt_reload_returns_reload_failed_on_error_response() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("err.sock");
        let recorded: Arc<Mutex<Vec<IpcCommand>>> = Arc::new(Mutex::new(Vec::new()));
        let server = stub_server(
            sock.clone(),
            IpcResponse::Error {
                message: "boom".into(),
            },
            recorded.clone(),
        )
        .await;

        let loader = loader_from(Ok(Some("ps_live-token".into())));
        let outcome = attempt_reload_with(&sock, loader.as_ref()).await;
        server.await.unwrap();

        match outcome {
            ReloadOutcome::ReloadFailed(msg) => assert_eq!(msg, "boom"),
            other => panic!("expected ReloadFailed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn attempt_reload_returns_no_token_when_file_absent() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("unused.sock");

        let loader = loader_from(Ok(None));
        let outcome = attempt_reload_with(&sock, loader.as_ref()).await;
        match outcome {
            ReloadOutcome::NoToken { io_error } => assert!(
                io_error.is_none(),
                "absent file must not carry an io_error: {io_error:?}"
            ),
            other => panic!("expected NoToken, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn attempt_reload_returns_no_token_with_io_error_when_unreadable() {
        // Panel refinement (review 2026-04-23): a token file that exists
        // but can't be read (e.g. permission denied for the calling
        // user) must carry the I/O error forward so the operator sees
        // it alongside the frozen message.
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("unused.sock");

        let loader = loader_from(Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "permission denied (os error 13)",
        )));
        let outcome = attempt_reload_with(&sock, loader.as_ref()).await;
        match outcome {
            ReloadOutcome::NoToken { io_error } => {
                let msg = io_error.expect("unreadable token must carry an io_error");
                assert!(
                    msg.contains("permission denied"),
                    "io_error must name the cause: {msg}"
                );
            }
            other => panic!("expected NoToken, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn attempt_reload_retries_once_on_auth_mismatch() {
        // Two-accept stub: first connection returns a token-mismatch
        // error, second returns Ok. The helper must retry and land on
        // Reloaded.
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("retry.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        let attempts: Arc<Mutex<u32>> = Arc::new(Mutex::new(0));
        let attempts_bg = attempts.clone();
        let server = tokio::spawn(async move {
            for _ in 0..2 {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let attempt = {
                    let mut a = attempts_bg.lock().unwrap();
                    *a += 1;
                    *a
                };
                let (reader, mut writer) = stream.into_split();
                let mut reader = BufReader::new(reader);
                let mut line = String::new();
                let _ = reader.read_line(&mut line).await;
                let resp = if attempt == 1 {
                    IpcResponse::Error {
                        message: "unauthorized: token mismatch".into(),
                    }
                } else {
                    IpcResponse::Ok {
                        message: "stub ok".into(),
                    }
                };
                let mut body = serde_json::to_string(&resp).unwrap();
                body.push('\n');
                let _ = writer.write_all(body.as_bytes()).await;
                let _ = writer.shutdown().await;
            }
        });

        let loader = loader_from(Ok(Some("ps_retry-token".into())));
        let outcome = attempt_reload_with(&sock, loader.as_ref()).await;
        server.await.unwrap();

        assert!(matches!(outcome, ReloadOutcome::Reloaded), "{outcome:?}");
        assert_eq!(*attempts.lock().unwrap(), 2, "retry must fire exactly once");
    }

    #[tokio::test]
    async fn report_reload_outcome_all_variants_do_not_panic() {
        // Golden-behaviour check: every variant must format without
        // panicking. We do not capture stdout/stderr here because
        // redirecting them portably requires extra plumbing; the
        // behavioural guarantee (channel correctness) is documented
        // in the frozen-strings table and covered in operator smoke.
        report_reload_outcome(&ReloadOutcome::Reloaded);
        report_reload_outcome(&ReloadOutcome::DaemonUnreachable);
        report_reload_outcome(&ReloadOutcome::NoToken { io_error: None });
        report_reload_outcome(&ReloadOutcome::NoToken {
            io_error: Some("permission denied".into()),
        });
        report_reload_outcome(&ReloadOutcome::ReloadFailed("boom".into()));
    }

    #[test]
    fn classify_transport_error_maps_response_timeout_to_unreachable() {
        // Design doc §2 HR1 listed only the three connect-side errors
        // ("No such file or directory", "Connection refused",
        // "connection timeout"). Panel refinement: "response timeout"
        // from `send_command`'s read-side must also map to
        // DaemonUnreachable because from the CLI's perspective the
        // daemon hasn't confirmed the reload — same outcome class.
        assert!(matches!(
            classify_transport_error("response timeout".into()),
            ReloadOutcome::DaemonUnreachable
        ));
        assert!(matches!(
            classify_transport_error("connection timeout".into()),
            ReloadOutcome::DaemonUnreachable
        ));
        assert!(matches!(
            classify_transport_error("No such file or directory (os error 2)".into()),
            ReloadOutcome::DaemonUnreachable
        ));
        assert!(matches!(
            classify_transport_error("Connection refused (os error 111)".into()),
            ReloadOutcome::DaemonUnreachable
        ));
        match classify_transport_error("random transport panic".into()) {
            ReloadOutcome::ReloadFailed(msg) => assert_eq!(msg, "random transport panic"),
            other => panic!("expected ReloadFailed, got {other:?}"),
        }
    }

    #[test]
    fn looks_like_auth_mismatch_matches_expected_patterns() {
        assert!(looks_like_auth_mismatch(&ReloadOutcome::ReloadFailed(
            "token mismatch".into()
        )));
        assert!(looks_like_auth_mismatch(&ReloadOutcome::ReloadFailed(
            "UNAUTHORIZED".into()
        )));
        assert!(looks_like_auth_mismatch(&ReloadOutcome::ReloadFailed(
            "auth failed: token required".into()
        )));
        assert!(!looks_like_auth_mismatch(&ReloadOutcome::ReloadFailed(
            "unrelated crash".into()
        )));
        assert!(!looks_like_auth_mismatch(&ReloadOutcome::Reloaded));
        assert!(!looks_like_auth_mismatch(&ReloadOutcome::DaemonUnreachable));
        assert!(!looks_like_auth_mismatch(&ReloadOutcome::NoToken {
            io_error: None
        }));
    }
}
