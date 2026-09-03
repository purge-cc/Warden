//! CLI-side Unix socket client for IPC commands.
//!
//! Connect to the daemon's Unix socket, send one JSON command, read one JSON
//! response, disconnect. Designed for short-lived request/response exchanges.

use std::path::Path;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

use super::auth_token::{load_token, NO_TOKEN_FILE_MSG};
use super::protocol::{CommandTier, IpcCommand, IpcResponse};

/// Deadline applied to every phase of an IPC exchange — connect, write,
/// read. One constant so [`send_command`]'s documented bound cannot drift
/// away from the number the code actually enforces.
pub const IPC_TIMEOUT: Duration = Duration::from_secs(5);

/// Write one JSON command line and close the write half, under `deadline`.
///
/// A Unix stream socket blocks in `write_all` once the peer's receive queue
/// fills and the peer stops reading — reachable while the daemon is still
/// accepting connections, with a wedged per-connection task behind it. Left
/// unbounded that hangs the operator's terminal with no output and no error,
/// and takes any script or unit wrapping it down too.
async fn write_command_line<W>(writer: &mut W, line: &str, deadline: Duration) -> anyhow::Result<()>
where
    W: AsyncWriteExt + Unpin,
{
    tokio::time::timeout(deadline, async {
        writer.write_all(line.as_bytes()).await?;
        writer.shutdown().await
    })
    .await
    .map_err(|_| anyhow::anyhow!("request timeout"))??;
    Ok(())
}

/// Send an IPC command to the daemon and return the response.
///
/// - Connects to the Unix socket, writes the command as a JSON line,
///   reads the response JSON line, and returns the parsed response.
/// - For `Mutating` and `Admin` commands (see `CommandTier`), the
///   plaintext token is auto-discovered from the standard location
///   (`/var/lib/purge-warden/token`) and attached before serialization.
///   If no token file is present, the call fails up-front with a plain-
///   English error telling the operator to run `warden token generate`
///   — the command is never sent in that state.
/// - `ReadOnly` commands are sent as-is. No token lookup happens, so
///   `warden status` works even on a fresh install with no token.
/// - Connect, write and read each carry their own [`IPC_TIMEOUT`]
///   deadline. The bound is per phase, not a total for the exchange:
///   a large response that is still arriving must not be cut off by
///   time the connect already spent.
pub async fn send_command(socket_path: &Path, command: &IpcCommand) -> anyhow::Result<IpcResponse> {
    // Clone the command so we can attach a token without requiring the
    // caller to pass a mutable reference. IpcCommand is cheap to clone.
    let command = command.clone();

    let command = match command.tier() {
        CommandTier::ReadOnly => command,
        CommandTier::Mutating | CommandTier::Admin if command.token().is_some() => {
            // Caller already attached a token explicitly — do not override.
            // `warden token regenerate` relies on this: it must authenticate
            // its post-write `IpcCommand::Reload` with the *old* plaintext
            // (still valid against the daemon's in-memory hash), not the
            // new plaintext that it is about to persist.
            command
        }
        CommandTier::Mutating | CommandTier::Admin => {
            // Auto-discover the token. If the file does not exist, refuse
            // to send the command — a plain error up-front is much friendlier
            // than letting the daemon bounce us with "missing token".
            match load_token() {
                Ok(Some(tok)) => command.with_token(Some(tok)),
                Ok(None) => anyhow::bail!("{NO_TOKEN_FILE_MSG}"),
                Err(e) => anyhow::bail!(
                    "could not read the token file at /var/lib/purge-warden/token: {e}. \
                     Run `warden token regenerate` to recreate it."
                ),
            }
        }
    };

    let stream = tokio::time::timeout(IPC_TIMEOUT, UnixStream::connect(socket_path))
        .await
        .map_err(|_| anyhow::anyhow!("connection timeout"))??;

    let (reader, mut writer) = stream.into_split();

    // Send command as JSON line
    let mut cmd_json = serde_json::to_string(&command)?;
    cmd_json.push('\n');
    write_command_line(&mut writer, &cmd_json, IPC_TIMEOUT).await?;

    // Read response line
    let mut reader = BufReader::new(reader);
    let mut line = String::new();
    tokio::time::timeout(IPC_TIMEOUT, reader.read_line(&mut line))
        .await
        .map_err(|_| anyhow::anyhow!("response timeout"))??;

    if line.is_empty() {
        anyhow::bail!("daemon closed connection without response");
    }

    let response: IpcResponse = serde_json::from_str(line.trim())?;
    Ok(response)
}

#[cfg(test)]
/// Check if the daemon's IPC socket exists and is connectable.
/// Returns true if we can establish a connection (daemon is alive).
pub async fn is_daemon_reachable(socket_path: &Path) -> bool {
    if !socket_path.exists() {
        return false;
    }
    tokio::time::timeout(Duration::from_secs(1), UnixStream::connect(socket_path))
        .await
        .map(|r| r.is_ok())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::socket_server::{spawn_ipc_server, DaemonState};
    use std::sync::Arc;
    use std::time::Instant;

    /// The write half must honour the same deadline connect and read do.
    ///
    /// The payload has to exceed the socket buffers for `write_all` to
    /// block at all: a command-sized line is absorbed by the kernel and
    /// returns immediately, so a realistic payload here would pass
    /// without ever reaching the deadline.
    #[tokio::test]
    async fn write_command_line_times_out_against_a_peer_that_never_reads() {
        // `_peer` stays bound: dropping it turns the block into EPIPE,
        // which would pass the assertion for the wrong reason.
        let (mut writer, _peer) = UnixStream::pair().unwrap();
        let payload = "x".repeat(8 * 1024 * 1024);
        let err = write_command_line(&mut writer, &payload, Duration::from_millis(50))
            .await
            .expect_err("a peer that never reads must not let the write complete");
        assert_eq!(err.to_string(), "request timeout");
    }

    /// Negative control for the test above. Without it a
    /// `write_command_line` that timed out unconditionally would look
    /// correct.
    #[tokio::test]
    async fn write_command_line_completes_when_the_write_fits() {
        let (mut writer, _peer) = UnixStream::pair().unwrap();
        write_command_line(
            &mut writer,
            "{\"cmd\":\"status\"}\n",
            Duration::from_millis(50),
        )
        .await
        .expect("a command-sized line must not reach the deadline");
    }

    /// `send_command`'s rustdoc names a number; this is what makes the
    /// number true rather than aspirational.
    #[test]
    fn ipc_timeout_is_the_five_seconds_the_docs_promise() {
        assert_eq!(IPC_TIMEOUT, Duration::from_secs(5));
    }

    #[tokio::test]
    async fn client_send_status() {
        let state = Arc::new(test_state());
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("test.sock");

        let server = spawn_ipc_server(sock_path.clone(), state).await.unwrap();

        let resp = send_command(&sock_path, &IpcCommand::Status).await.unwrap();
        match resp {
            IpcResponse::Status {
                listen,
                upstream_mode,
                ..
            } => {
                assert_eq!(listen, "127.0.0.1:15353");
                assert_eq!(upstream_mode, "plain");
            }
            other => panic!("unexpected response: {other:?}"),
        }

        server.abort();
    }

    #[tokio::test]
    async fn client_send_query() {
        let state = Arc::new(test_state());
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("test.sock");

        let server = spawn_ipc_server(sock_path.clone(), state).await.unwrap();

        let resp = send_command(
            &sock_path,
            &IpcCommand::Query {
                domain: "example.com".into(),
            },
        )
        .await
        .unwrap();

        match resp {
            IpcResponse::QueryResult {
                domain,
                blocked,
                blocked_by,
            } => {
                assert_eq!(domain, "example.com");
                assert!(!blocked);
                assert!(blocked_by.is_none(), "allowed domain carries no source");
            }
            other => panic!("unexpected response: {other:?}"),
        }

        server.abort();
    }

    #[tokio::test]
    async fn client_connection_refused() {
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("nonexistent.sock");
        let result = send_command(&sock_path, &IpcCommand::Status).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn is_daemon_reachable_when_running() {
        let state = Arc::new(test_state());
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("test.sock");

        let server = spawn_ipc_server(sock_path.clone(), state).await.unwrap();

        assert!(is_daemon_reachable(&sock_path).await);

        server.abort();
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    #[tokio::test]
    async fn is_daemon_reachable_when_not_running() {
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("nonexistent.sock");
        assert!(!is_daemon_reachable(&sock_path).await);
    }

    fn test_state() -> DaemonState {
        use crate::dns::cache::DnsCache;
        use crate::filter::FilterEngine;

        let cache_config = crate::config::settings::CacheConfig::default();
        DaemonState {
            filter: Arc::new(FilterEngine::new()),
            cache: DnsCache::new(&cache_config),
            profiles: None,
            stats: None,
            listen_addr: "127.0.0.1:15353".into(),
            upstream_mode: "plain".into(),
            upstream_count: 2,
            upstream_servers: Vec::new(),
            list_count: 0,
            started_at: Instant::now(),
            shutdown_tx: None,
            reload_tx: None,
            reload_coalescer: None,
            oui_table: None,
            api_token_hash: Arc::new(arc_swap::ArcSwap::from_pointee(None)),
            config_path: None,
            config_write_lock: Arc::new(tokio::sync::Mutex::new(())),
            list_statuses: None,
            list_state: None,
            local_records_hits: None,
            log_ring: None,
            notification_tx: None,
            list_labels: Arc::new(vec![None; 64]),
            list_cmd_tx: Arc::new(arc_swap::ArcSwap::from_pointee(None)),
            daemon_uid: crate::ipc::socket_server::current_euid(),
            resource_budget_store: crate::resource_budget::types::new_store(),
            #[cfg(feature = "cluster")]
            cluster_observe: None,
        }
    }
}
