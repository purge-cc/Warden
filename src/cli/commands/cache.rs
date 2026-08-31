//! Cache management — flush via the authenticated IPC socket.
//!
//! **Previously** (pre-2026-04-09 smoke test): if IPC was unavailable or
//! rejected the call, the CLI fell back to sending SIGUSR1 directly to the
//! daemon's PID, which the daemon handled by clearing the cache. After
//! P0-3 added an authenticated IPC gate, that fallback became a local
//! auth bypass: any user with kill permission on the PID could flush
//! the cache without a token.
//!
//! **Now:** the IPC call is the only path. If it fails, the user gets a
//! clear error and no flush happens. The daemon-side SIGUSR1 handler was
//! also removed (see `cli/commands/start.rs`) so killing the process with
//! SIGUSR1 no longer triggers a flush. Cache flushing is a token-gated
//! Mutating command, period.

use std::path::Path;

use crate::ipc::protocol::{IpcCommand, IpcResponse};
use crate::ipc::socket_client;

/// Flush the daemon's DNS cache over authenticated IPC.
///
/// `_pid_file` is deliberately unused: it is the vestige of the removed
/// SIGUSR1 fallback described above, kept so the dispatch arm in `main.rs`
/// reads like its neighbours. It is NOT a discarded operator argument that
/// should take effect — reinstating a PID-based path here would restore
/// the auth bypass. cli-h5 corrected the global `--pid-file` help, which
/// still listed `cache` among the verbs that consume it.
pub async fn run_flush(
    _pid_file: &Path,
    socket_path: &Path,
    domain: Option<&str>,
) -> anyhow::Result<()> {
    // P0-3: token is auto-attached by socket_client::send_command from
    // ~/.config/purge-warden/token. Call site passes None here.
    let cmd = IpcCommand::CacheFlush {
        domain: domain.map(String::from),
        token: None,
    };

    match socket_client::send_command(socket_path, &cmd).await {
        Ok(IpcResponse::Ok { message }) => {
            println!("{message}");
            Ok(())
        }
        Ok(IpcResponse::Error { message }) => {
            anyhow::bail!("daemon refused cache flush: {message}");
        }
        Ok(_) => {
            anyhow::bail!("unexpected response from daemon");
        }
        Err(e) => {
            // Previously this fell through to SIGUSR1, bypassing the
            // P0-3 token gate. That path is gone. Surface the error
            // directly so the operator knows what to fix.
            anyhow::bail!(
                "could not reach the daemon over IPC: {e}\n\n\
                 Cache flushing goes through the authenticated IPC socket — \
                 there is no signal-based fallback. Check that:\n  \
                 • the daemon is running (`warden status`)\n  \
                 • the socket path matches your config\n  \
                 • you have a valid token (`warden token generate` if not)"
            );
        }
    }
}
