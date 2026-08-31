//! Stop a running purge-warden daemon.
//!
//! # Behavior (post-2026-04-09 smoke-test fix #3)
//!
//! Before Sprint 19's post-smoke cleanup, this command sent SIGTERM
//! directly to the PID. That bypassed the P0-3 IPC auth gate entirely
//! — any local user with kill permission on the PID could shut the
//! daemon down without a token.
//!
//! The default path is now:
//!
//! 1. Try `IpcCommand::Shutdown` over the Unix socket. This goes through
//!    the P0-3 Admin-tier auth gate: the CLI auto-attaches the plaintext
//!    token from `~/.config/purge-warden/token`, and the daemon verifies
//!    it in constant time.
//! 2. On success, wait briefly for the daemon to exit and clean up
//!    the PID file.
//! 3. On IPC failure, surface a plain-English error suggesting either
//!    fixing the auth state or using `--force`.
//!
//! `--force` is an explicit opt-in for the old signal-direct path. It
//! exists because *legitimate* emergencies can make IPC unreachable
//! (daemon hung, socket permissions broken, stale token, etc.) and
//! operators need a recovery path. `--force` requires the operator to
//! type the flag deliberately, which is the minimum ceremony to turn
//! an accidental bypass into a deliberate one.

use std::path::Path;
use std::time::Duration;

use crate::ipc::protocol::{IpcCommand, IpcResponse};
use crate::ipc::socket_client;

use super::pid;

/// Stop a running daemon.
///
/// `force`: if `true`, skip the IPC path and send SIGTERM directly.
///
/// # Exit codes
///
/// Every failure path here already propagated an `Err` (which `main`
/// renders as exit 1) *except one*: the daemon accepted the shutdown but
/// was still alive 2 s later. That printed "still running" and returned
/// `Ok(())`, so a script sequencing `warden stop && <swap the binary>`
/// proceeded to swap a binary out from under a live daemon. That tail now
/// returns an error too — the operator asked for the process to stop, and
/// it did not stop.
pub async fn run_stop(pid_file: &Path, socket_path: &Path, force: bool) -> anyhow::Result<()> {
    // "I never started it" and "it already exited" are the two most common
    // states a new operator runs `stop` in, and both land here. Answering
    // them with `read_pid_file`'s raw errno — "cannot read PID file
    // /run/purge-warden/purge-warden.pid: No such file or directory (os
    // error 2)" — names an implementation detail the operator has never
    // heard of and describes it as unreadable rather than absent.
    //
    // `status` and `lists refresh` both meet the identical state and both
    // say so plainly; this verb is the one that did not.
    if !pid_file.exists() {
        anyhow::bail!(
            "purge-warden is not running (no PID file at {}).\n\n\
             If you expected a daemon here, it is probably running against a \
             different config: the PID file location is derived from the config \
             path unless `--pid-file` overrides it. `warden status` reports which \
             one this invocation is looking at.",
            pid_file.display()
        );
    }

    let daemon_pid = pid::read_pid_file(pid_file)?;

    // `is_process_alive` alone cannot tell a running daemon from a stale
    // PID file whose number the kernel has since recycled onto an unrelated
    // process. `daemon_is_live` requires the advisory lock too — only a live
    // daemon holds it — so `--force` can no longer SIGTERM a stranger that
    // merely inherited the daemon's old PID.
    if !pid::daemon_is_live(pid_file, daemon_pid) {
        pid::remove_pid_file(pid_file);
        anyhow::bail!(
            "PID file exists but process {} is not running (stale PID file removed)",
            daemon_pid
        );
    }

    if !force {
        // `Shutdown` is Admin-tier, so `send_command` will look for a token
        // before it opens the socket. Check for one HERE so a missing token
        // is reported AS a missing token: send_command's own refusal is
        // accurate but comes back as an `Err`, and the arm below frames every
        // `Err` as "could not reach the daemon over IPC … check that the
        // daemon is running and the socket path matches your config". Both
        // sentences are false in this case — nothing was ever sent, and the
        // daemon whose PID file we just found locked is plainly running.
        //
        // Gated on the typed `Ok(None)`, not on a substring of the error
        // text, so the check cannot start matching some unrelated failure.
        require_admin_token()?;

        // Default path: go through IPC so the P0-3 auth gate applies.
        // send_command auto-attaches the plaintext token from
        // the resolved token path for Admin-tier commands.
        let cmd = IpcCommand::Shutdown { token: None };
        match socket_client::send_command(socket_path, &cmd).await {
            Ok(IpcResponse::Ok { message }) => {
                println!("{message}");
            }
            Ok(IpcResponse::Error { message }) => {
                anyhow::bail!(
                    "daemon refused shutdown: {message}\n\n\
                     If this is an emergency (daemon hung, IPC broken, lost \
                     token), re-run with `warden stop --force` to send \
                     SIGTERM directly. That path skips the token check."
                );
            }
            Ok(_) => {
                anyhow::bail!("unexpected response from daemon");
            }
            Err(e) => {
                anyhow::bail!(
                    "could not reach the daemon over IPC: {e}\n\n\
                     Check that the daemon is running and the socket path \
                     matches your config. If you need to stop it anyway \
                     (emergency recovery), re-run with `warden stop --force`."
                );
            }
        }
    } else {
        // Explicit bypass — emergency recovery path.
        eprintln!(
            "WARNING: --force skips the IPC auth gate and sends SIGTERM directly to PID {daemon_pid}"
        );
        pid::send_signal(daemon_pid, "TERM")?;
        println!("sent SIGTERM to purge-warden (PID {daemon_pid})");
    }

    // Wait briefly for process to exit, then clean up PID file.
    for _ in 0..20 {
        std::thread::sleep(Duration::from_millis(100));
        if !pid::is_process_alive(daemon_pid) {
            pid::remove_pid_file(pid_file);
            println!("purge-warden stopped");
            return Ok(());
        }
    }

    anyhow::bail!(
        "process {} still running after 2s, PID file retained\n\n\
         The shutdown request was accepted but the daemon has not exited. \
         Do not assume the port is free. Re-check with `warden status`, and \
         if it is wedged use `warden stop --force` to send SIGTERM directly.",
        daemon_pid
    );
}

/// Refuse early, and by name, when the admin token the IPC path needs is
/// missing or unreadable.
///
/// The remedy differs from every other `stop` failure: nothing about the
/// daemon, the socket, or the config is wrong, so the operator must create
/// a token rather than go looking for a connectivity fault. Naming that is
/// the whole point — this is the first mutating command a new operator runs
/// after `init`, and `init` does not create a token.
fn require_admin_token() -> anyhow::Result<()> {
    let where_it_looked = crate::ipc::auth_token::default_token_path()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "the default token path".to_string());
    token_gate(crate::ipc::auth_token::load_token(), &where_it_looked)
}

/// The decision half of [`require_admin_token`], split from the lookup so
/// the operator-facing text can be tested without mutating process-global
/// `$HOME` / `$XDG_CONFIG_HOME` (which races under parallel test runs).
fn token_gate(found: std::io::Result<Option<String>>, where_it_looked: &str) -> anyhow::Result<()> {
    match found {
        Ok(Some(_)) => Ok(()),
        Ok(None) => anyhow::bail!(
            "`warden stop` needs an admin token and none was found at {where_it_looked}.\n\n\
             Nothing was sent to the daemon, so this is an authentication problem \
             rather than a connectivity one — checking the socket path will not \
             help. Create a token on this host:\n  \
             warden token generate\n\n\
             A daemon only picks up a new token when it restarts, so to stop the \
             instance running right now, use the emergency path:\n  \
             warden stop --force"
        ),
        Err(e) => anyhow::bail!(
            "`warden stop` needs an admin token. A token file exists at \
             {where_it_looked} but could not be read: {e}\n\n\
             Nothing was sent to the daemon. Fix the file's permissions (it must \
             be readable by the user running `warden`), or recreate it with \
             `warden token regenerate`. To stop the daemon now without a token, \
             use `warden stop --force`."
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// cli-h9 defect 6. Pre-fix, a missing token surfaced through the
    /// `Err(e)` arm of the IPC match and was framed as:
    ///
    /// > could not reach the daemon over IPC: … Check that the daemon is
    /// > running and the socket path matches your config.
    ///
    /// Both claims are false — the command never left the process, and the
    /// daemon whose PID file we just found locked is running. Asserting only
    /// `is_err()` would pass on the old text, so the assertions below are on
    /// what the message must NOT say and what it must name instead.
    #[test]
    fn missing_token_names_the_token_not_the_daemon() {
        let err = token_gate(Ok(None), "/var/lib/purge-warden/token")
            .expect_err("no token must refuse")
            .to_string();

        assert!(
            err.contains("admin token"),
            "must name the real cause: {err}"
        );
        assert!(
            err.contains("/var/lib/purge-warden/token"),
            "must say where it looked: {err}"
        );
        assert!(
            err.contains("warden token generate"),
            "must give the fix command: {err}"
        );
        assert!(
            err.contains("warden stop --force"),
            "must keep the emergency path: {err}"
        );

        // The false framing that made this a defect.
        assert!(
            !err.contains("could not reach the daemon"),
            "must not blame connectivity: {err}"
        );
        assert!(
            !err.contains("socket path matches"),
            "must not send the operator to check the socket: {err}"
        );
    }

    /// An unreadable token file is a different fault with a different fix
    /// (permissions), and must not be folded into the missing-file text.
    #[test]
    fn unreadable_token_names_permissions_not_absence() {
        let io_err = std::io::Error::from(std::io::ErrorKind::PermissionDenied);
        let err = token_gate(Err(io_err), "/var/lib/purge-warden/token")
            .expect_err("unreadable token must refuse")
            .to_string();

        assert!(
            err.contains("could not be read"),
            "must name the read failure: {err}"
        );
        assert!(
            err.contains("permissions"),
            "must point at the actual remedy: {err}"
        );
        assert!(
            !err.contains("none was found"),
            "an unreadable file is not a missing one: {err}"
        );
    }

    /// The gate must be transparent when a token exists, or every `warden
    /// stop` on a correctly configured host would refuse.
    #[test]
    fn present_token_passes_the_gate() {
        assert!(token_gate(Ok(Some("ps_deadbeef".to_string())), "/x").is_ok());
    }

    /// cli-h9: "I never started it" is the commonest state a new operator
    /// runs `stop` in, and it was answered with `read_pid_file`'s raw errno
    /// — an implementation detail described as unreadable rather than
    /// absent. `status` and `lists refresh` both meet the same state and
    /// both say so plainly.
    ///
    /// Bails before the socket is touched, so no listener is involved.
    #[tokio::test]
    async fn missing_pid_file_says_not_running_not_cannot_read() {
        let dir = tempfile::tempdir().unwrap();
        let absent_pid = dir.path().join("absent.pid");
        let absent_sock = dir.path().join("nothing.sock");

        for force in [false, true] {
            let err = run_stop(&absent_pid, &absent_sock, force)
                .await
                .expect_err("no PID file must refuse")
                .to_string();

            assert!(
                err.contains("is not running"),
                "must state the daemon is not running (force={force}): {err}"
            );
            assert!(
                err.contains("warden status"),
                "must point at the verb that reports the resolved paths: {err}"
            );
            assert!(
                !err.contains("cannot read PID file"),
                "the raw errno framing is the defect (force={force}): {err}"
            );
            assert!(
                !err.contains("os error"),
                "must not surface a bare errno (force={force}): {err}"
            );
        }
    }
}
