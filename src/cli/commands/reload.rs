//! Sprint 38 QLP8 — `warden reload` standalone subcommand.
//!
//! Shares the Sprint 36 HR1 *classifier* ([`super::ipc_reload::attempt_reload`])
//! but **not** its reporter. Makes the forward-referenced S37 §3 D4 frozen
//! message ("run `warden reload`") honest — operators can drive an IPC
//! reload without a dummy mutating command.
//!
//! The command auto-discovers the current token via the shared helper, so
//! an operator whose IPC auth gate is correctly set up only ever types
//! `warden reload`.
//!
//! # Why this command does not use `report_reload_outcome`
//!
//! [`super::ipc_reload::report_reload_outcome`] is the **post-write tail**:
//! roughly forty mutating verbs (`warden device set …`, every S34 entity
//! editor) call it *after* an atomic write has already landed on disk. For
//! those, the reload is a courtesy — so `DaemonUnreachable` is a legitimate
//! success ("change will take effect on next start", exit 0) and all four
//! of its strings open with "change landed on disk".
//!
//! For `warden reload` the reload **is** the operation. No change landed on
//! disk; there is no next-start consolation. Every one of the four shared
//! strings is factually wrong here — before this sprint, `warden reload`
//! with no token printed *"change landed on disk but no admin token is
//! available"*, describing a write that never happened.
//!
//! So the split is by **meaning, not by mechanism**: the classifier is
//! shared because "did the daemon accept the reload?" is one question with
//! one answer; the reporting and the exit code are local because the same
//! answer means opposite things to the two callers. The shared strings are
//! frozen and untouched — see `_docs/features/config_safety_v12.md` §2 HR1.
//!
//! Exit codes: [`SUCCESS`] when the daemon reloaded, [`FAILURE`] otherwise
//! (unreachable, no token, or refused) — a reload that did not happen is a
//! failed operation, not information.

use std::path::Path;

use super::ipc_reload::{attempt_reload, ReloadOutcome};
use crate::cli::exit_codes::{FAILURE, SUCCESS};

/// Entry point for the `warden reload` subcommand. Returns the intended
/// process exit code; `main.rs` translates it via
/// [`crate::cli::exit_codes::exit_with`].
pub async fn run(socket_path: &Path) -> anyhow::Result<i32> {
    let outcome = attempt_reload(socket_path).await;
    report_standalone_reload(&outcome);
    Ok(exit_code_for(&outcome))
}

/// Map a reload outcome to this command's exit code.
///
/// Only [`ReloadOutcome::Reloaded`] is success. Split out from [`run`] so
/// the mapping is testable without a live socket — the pairing of code and
/// message is the whole contract here.
fn exit_code_for(outcome: &ReloadOutcome) -> i32 {
    match outcome {
        ReloadOutcome::Reloaded => SUCCESS,
        ReloadOutcome::DaemonUnreachable
        | ReloadOutcome::NoToken { .. }
        | ReloadOutcome::ReloadFailed(_) => FAILURE,
    }
}

/// Operator feedback for a *standalone* reload.
///
/// Deliberately NOT [`super::ipc_reload::report_reload_outcome`]: these
/// four strings describe a reload that was the whole operation, where that
/// one describes a courtesy reload after a write. See the module docs.
/// Failures go to stderr so `warden reload >/dev/null` still shows them.
fn report_standalone_reload(outcome: &ReloadOutcome) {
    match outcome {
        ReloadOutcome::Reloaded => {
            println!("daemon reloaded — config and lists are live");
        }
        ReloadOutcome::DaemonUnreachable => {
            eprintln!(
                "cannot reload: the daemon is not running. Nothing was reloaded — \
                 start it with `systemctl start purge-warden` (or `warden start`)."
            );
        }
        ReloadOutcome::NoToken { io_error } => {
            eprintln!(
                "cannot reload: no admin token is available to authenticate the \
                 request. Run `warden token generate`, or `systemctl reload \
                 purge-warden` to pick up the on-disk config (SIGHUP is \
                 unauthenticated, so it works without a token)."
            );
            if let Some(e) = io_error {
                eprintln!("  (token file present but unreadable: {e})");
            }
        }
        ReloadOutcome::ReloadFailed(msg) => {
            eprintln!(
                "reload refused by the daemon ({msg}). The running config is \
                 unchanged. Check `journalctl -u purge-warden`, then try \
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
    use std::path::PathBuf;

    /// The headline fix: a reload that did not happen must not exit 0.
    ///
    /// The socket is absent, so the S36 classifier yields
    /// `DaemonUnreachable` (or `NoToken`, if the running user has no
    /// token file — either way the reload did not happen). Both map to
    /// [`FAILURE`]. Before this sprint the wrapper returned `Ok(())`
    /// unconditionally and a systemd `ExecReload=` or a deploy script
    /// read "reloaded" from a daemon that was not running.
    #[tokio::test]
    async fn reload_exits_non_zero_when_the_daemon_is_not_running() {
        let dir = tempfile::tempdir().unwrap();
        let fake_socket: PathBuf = dir.path().join("absent.sock");
        assert!(!fake_socket.exists());

        let code = run(&fake_socket).await.expect("wrapper must not error");
        assert_eq!(
            code, FAILURE,
            "a reload against a dead daemon reported success"
        );
    }

    /// Sprint 38 QLP8: the wrapper dispatches through the same
    /// `attempt_reload` classifier every S36 editor uses. Pinning this
    /// keeps the *detection* of the daemon state in one place even
    /// though the reporting has deliberately diverged.
    #[tokio::test]
    async fn reload_dispatches_via_shared_classifier() {
        let dir = tempfile::tempdir().unwrap();
        let fake_socket = dir.path().join("missing.sock");
        let direct = attempt_reload(&fake_socket).await;
        assert!(matches!(
            direct,
            ReloadOutcome::DaemonUnreachable | ReloadOutcome::NoToken { .. }
        ));
        // ...and the wrapper agrees with the classifier it delegates to.
        assert_eq!(run(&fake_socket).await.unwrap(), exit_code_for(&direct));
    }

    /// The whole point of the split: only an actual reload is success.
    /// A table test rather than three asserts, so a future variant
    /// added to `ReloadOutcome` shows up here as a non-exhaustive match
    /// rather than silently defaulting to some code.
    #[test]
    fn only_an_actual_reload_is_success() {
        assert_eq!(exit_code_for(&ReloadOutcome::Reloaded), SUCCESS);
        assert_eq!(exit_code_for(&ReloadOutcome::DaemonUnreachable), FAILURE);
        assert_eq!(
            exit_code_for(&ReloadOutcome::NoToken { io_error: None }),
            FAILURE
        );
        assert_eq!(
            exit_code_for(&ReloadOutcome::ReloadFailed("boom".into())),
            FAILURE
        );
    }

    /// The separation this sprint had to protect. `warden reload` must
    /// NOT speak the post-write family's vocabulary: for those forty
    /// callers a write already landed, so "change will take effect on
    /// next start" is a legitimate success. Here nothing was written,
    /// and that sentence would be a lie.
    ///
    /// Asserting the *shared* strings are absent from this module is
    /// what keeps the two apart — a future refactor that "helpfully"
    /// re-points this command at `report_reload_outcome` fails here.
    #[test]
    fn standalone_reload_does_not_borrow_the_post_write_vocabulary() {
        let source = include_str!("reload.rs");
        // Scope strictly to the reporter's body: from its `fn` line to the
        // first column-0 `}` that closes it. Taking "everything after the
        // fn" would swallow this test's own needle list and fail for the
        // wrong reason — and the module docs deliberately *quote* the
        // post-write strings to explain why they are wrong here.
        let body = source
            .split_once("fn report_standalone_reload")
            .expect("reporter must exist")
            .1
            .split_once("\n}\n")
            .expect("reporter must be a closed fn")
            .0;
        for frozen in [
            "change will take effect on next start",
            "change landed on disk",
            "daemon reloaded — change is live",
        ] {
            assert!(
                !body.contains(frozen),
                "standalone reload emits the post-write string {frozen:?} — \
                 that vocabulary presumes a write that did not happen here"
            );
        }
    }
}
