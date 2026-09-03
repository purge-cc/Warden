use super::*;

#[tokio::test]
async fn server_handles_status_command() {
    let state = Arc::new(test_state());
    let dir = tempfile::tempdir().unwrap();
    let sock_path = dir.path().join("test.sock");

    // Start server
    let server_handle = spawn_ipc_server(sock_path.clone(), state).await.unwrap();

    // Connect as client
    let stream = tokio::net::UnixStream::connect(&sock_path).await.unwrap();
    let (reader, mut writer) = stream.into_split();

    let cmd = serde_json::to_string(&IpcCommand::Status).unwrap();
    writer
        .write_all(format!("{cmd}\n").as_bytes())
        .await
        .unwrap();
    writer.shutdown().await.unwrap();

    let mut reader = BufReader::new(reader);
    let mut line = String::new();
    reader.read_line(&mut line).await.unwrap();

    let resp: IpcResponse = serde_json::from_str(line.trim()).unwrap();
    match resp {
        IpcResponse::Status { listen, .. } => {
            assert_eq!(listen, "127.0.0.1:15353");
        }
        other => panic!("unexpected response: {other:?}"),
    }

    server_handle.abort();
}

#[tokio::test]
async fn server_handles_query_command() {
    let state = Arc::new(test_state());
    let dir = tempfile::tempdir().unwrap();
    let sock_path = dir.path().join("test.sock");

    let server_handle = spawn_ipc_server(sock_path.clone(), state).await.unwrap();

    let stream = tokio::net::UnixStream::connect(&sock_path).await.unwrap();
    let (reader, mut writer) = stream.into_split();

    let cmd = serde_json::to_string(&IpcCommand::Query {
        domain: "test.com".into(),
    })
    .unwrap();
    writer
        .write_all(format!("{cmd}\n").as_bytes())
        .await
        .unwrap();
    writer.shutdown().await.unwrap();

    let mut reader = BufReader::new(reader);
    let mut line = String::new();
    reader.read_line(&mut line).await.unwrap();

    let resp: IpcResponse = serde_json::from_str(line.trim()).unwrap();
    match resp {
        IpcResponse::QueryResult {
            domain,
            blocked,
            blocked_by,
        } => {
            assert_eq!(domain, "test.com");
            assert!(!blocked);
            assert!(blocked_by.is_none(), "allowed domain carries no source");
        }
        other => panic!("unexpected response: {other:?}"),
    }

    server_handle.abort();
}

/// §4.2 G1a — a blocked domain carries its attribution. A default
/// profile with `block_all` blocks via the admin layer, so
/// `evaluate_attributed` reports `BlockSource::AdminBlock` →
/// `blocked_by = "admin_block"`.
#[test]
fn handle_query_attributes_admin_block() {
    use crate::config::schema::{ConfigV1, Id, Profile};
    use crate::profiles::ProfileResolver;

    let mut config = ConfigV1::test_scaffold();
    config.schema_version = 3;
    config.profiles.insert(
        "strict".into(),
        Profile {
            block_all: true,
            ..Default::default()
        },
    );
    config.server.default_profile = Some(Id::new("strict").unwrap());
    let bit_map = crate::lists::source_key::SourceBitMap::default();

    let mut state = test_state();
    state.profiles = Some(Arc::new(ProfileResolver::build(
        &config,
        &bit_map,
        &crate::config::custom_list::CustomListStore::new(),
    )));

    match handle_query("anything.example", &state) {
        IpcResponse::QueryResult {
            blocked,
            blocked_by,
            ..
        } => {
            assert!(blocked);
            assert_eq!(blocked_by.as_deref(), Some("admin_block"));
        }
        other => panic!("expected QueryResult, got {other:?}"),
    }
}

/// rev-2606 api-auth-07-04: the IPC probe validates at the trust
/// boundary like its HTTP twin. Garbage gets the frozen
/// InvalidArgument wire string (no input echo, no internal detail),
/// not a meaningless "not blocked" verdict.
#[test]
fn handle_query_rejects_invalid_domain() {
    let state = test_state();
    for bad in [
        "not a domain!",
        "..",
        "localhost", // single-label — HTTP twin rejects it too
        "exa_mple.com",
        "",
    ] {
        match handle_query(bad, &state) {
            IpcResponse::Error { message } => {
                assert_eq!(
                    message,
                    crate::ipc::errors::IPC_ERROR_INVALID_ARGUMENT,
                    "frozen generic on the wire for {bad:?}"
                );
            }
            other => panic!("expected Error for {bad:?}, got {other:?}"),
        }
    }
}

/// Valid input still resolves — case-normalised, trailing dot
/// stripped, same canonical form the HTTP twin produces.
#[test]
fn handle_query_accepts_valid_domain() {
    let state = test_state();
    match handle_query("Example.COM.", &state) {
        IpcResponse::QueryResult { domain, .. } => {
            assert_eq!(domain, "example.com");
        }
        other => panic!("expected QueryResult, got {other:?}"),
    }
}

#[tokio::test]
async fn server_handles_cache_flush() {
    // P0-3: CacheFlush is Mutating, so we need a state with a token
    // configured and the command must carry the matching token.
    let state = Arc::new(test_state_with_token("ps_cacheflush_test"));
    let dir = tempfile::tempdir().unwrap();
    let sock_path = dir.path().join("test.sock");

    let server_handle = spawn_ipc_server(sock_path.clone(), state).await.unwrap();

    let stream = tokio::net::UnixStream::connect(&sock_path).await.unwrap();
    let (reader, mut writer) = stream.into_split();

    let cmd = serde_json::to_string(&IpcCommand::CacheFlush {
        domain: None,
        token: Some("ps_cacheflush_test".into()),
    })
    .unwrap();
    writer
        .write_all(format!("{cmd}\n").as_bytes())
        .await
        .unwrap();
    writer.shutdown().await.unwrap();

    let mut reader = BufReader::new(reader);
    let mut line = String::new();
    reader.read_line(&mut line).await.unwrap();

    let resp: IpcResponse = serde_json::from_str(line.trim()).unwrap();
    match resp {
        IpcResponse::Ok { message } => {
            assert!(message.contains("flushed"));
        }
        other => panic!("unexpected response: {other:?}"),
    }

    server_handle.abort();
}

#[tokio::test]
async fn server_handles_domain_count() {
    let state = Arc::new(test_state());
    let dir = tempfile::tempdir().unwrap();
    let sock_path = dir.path().join("test.sock");

    let server_handle = spawn_ipc_server(sock_path.clone(), state).await.unwrap();

    let stream = tokio::net::UnixStream::connect(&sock_path).await.unwrap();
    let (reader, mut writer) = stream.into_split();

    let cmd = serde_json::to_string(&IpcCommand::DomainCount).unwrap();
    writer
        .write_all(format!("{cmd}\n").as_bytes())
        .await
        .unwrap();
    writer.shutdown().await.unwrap();

    let mut reader = BufReader::new(reader);
    let mut line = String::new();
    reader.read_line(&mut line).await.unwrap();

    let resp: IpcResponse = serde_json::from_str(line.trim()).unwrap();
    match resp {
        IpcResponse::DomainCount { count } => {
            assert_eq!(count, 0);
        }
        other => panic!("unexpected response: {other:?}"),
    }

    server_handle.abort();
}

#[tokio::test]
async fn server_handles_invalid_json() {
    let state = Arc::new(test_state());
    let dir = tempfile::tempdir().unwrap();
    let sock_path = dir.path().join("test.sock");

    let server_handle = spawn_ipc_server(sock_path.clone(), state).await.unwrap();

    let stream = tokio::net::UnixStream::connect(&sock_path).await.unwrap();
    let (reader, mut writer) = stream.into_split();

    writer.write_all(b"not json\n").await.unwrap();
    writer.shutdown().await.unwrap();

    let mut reader = BufReader::new(reader);
    let mut line = String::new();
    reader.read_line(&mut line).await.unwrap();

    let resp: IpcResponse = serde_json::from_str(line.trim()).unwrap();
    match resp {
        IpcResponse::Error { message } => {
            assert!(message.contains("invalid command"));
        }
        other => panic!("unexpected response: {other:?}"),
    }

    server_handle.abort();
}

#[test]
fn accept_backoff_doubles_then_caps_at_5s() {
    // M-27: the schedule must double from 100 ms and saturate at
    // 5 s. Pin every step so a future tweak that drops the cap or
    // changes the base must update this test deliberately.
    use std::time::Duration;
    assert_eq!(accept_backoff_for(0), Duration::from_millis(100));
    assert_eq!(accept_backoff_for(1), Duration::from_millis(200));
    assert_eq!(accept_backoff_for(2), Duration::from_millis(400));
    assert_eq!(accept_backoff_for(3), Duration::from_millis(800));
    assert_eq!(accept_backoff_for(4), Duration::from_millis(1_600));
    assert_eq!(accept_backoff_for(5), Duration::from_millis(3_200));
    // 100 ms * 64 = 6400 ms → clamped to cap.
    assert_eq!(accept_backoff_for(6), Duration::from_secs(5));
    // Far beyond doubling range — must still cap, not overflow.
    assert_eq!(accept_backoff_for(31), Duration::from_secs(5));
    assert_eq!(accept_backoff_for(32), Duration::from_secs(5));
    assert_eq!(accept_backoff_for(u32::MAX), Duration::from_secs(5));
}

#[test]
fn ipc_write_timeout_constant_matches_read_timeout() {
    // M-25: the write-side timeout is intentionally identical to
    // the read-side timeout (5 s, hard-coded inside read_line's
    // tokio::time::timeout call). Pinning the constant here
    // protects against accidental drift if either side is later
    // tuned without the other.
    assert_eq!(IPC_WRITE_TIMEOUT, std::time::Duration::from_secs(5));
}

#[tokio::test]
async fn write_all_with_timeout_returns_elapsed_when_peer_buffer_stays_full() {
    // M-25: prove the timeout primitive used by handle_connection
    // returns Err(Elapsed) when the underlying write_all cannot
    // make progress. A real Unix socket has a kernel-side
    // ~200 KiB receive buffer that absorbs our small JSON
    // responses, so reproducing slow-loris through it would
    // require bytes we don't otherwise need to write. Using
    // `tokio::io::duplex(8)` pairs two streams sharing an 8-byte
    // ring: with `_hold_reader` parked and a 1 KiB payload, the
    // writer fills the ring then blocks until the reader drains.
    // We use a 50 ms test timeout so the assertion runs quickly
    // — the production constant (5 s) is pinned by the sibling
    // `ipc_write_timeout_constant_matches_read_timeout` test.
    use tokio::io::AsyncWriteExt;

    let (mut writer, _hold_reader) = tokio::io::duplex(8);
    let payload = vec![0u8; 1024];

    let res = tokio::time::timeout(
        std::time::Duration::from_millis(50),
        writer.write_all(&payload),
    )
    .await;

    assert!(
        res.is_err(),
        "write_all must time out when peer never drains the buffer, got {res:?}"
    );
}

#[tokio::test]
async fn server_handles_oversize_command_with_clean_shutdown() {
    // M-26: the "command too large" early-return path used to skip
    // writer.shutdown(), so the peer saw ECONNRESET instead of EOF.
    // After unification, both paths half-close cleanly. We assert
    // the peer reads ONE JSON line then EOF (read returns 0).
    let state = Arc::new(test_state());
    let dir = tempfile::tempdir().unwrap();
    let sock_path = dir.path().join("oversize.sock");

    let server_handle = spawn_ipc_server(sock_path.clone(), state).await.unwrap();

    let stream = tokio::net::UnixStream::connect(&sock_path).await.unwrap();
    let (reader, mut writer) = stream.into_split();

    // Exactly MAX_COMMAND_SIZE + 1 bytes total (65 KiB of 'a' + '\n').
    // line.len() = MAX_COMMAND_SIZE + 1 trips the oversize branch.
    // Sized so the daemon's `take(MAX_COMMAND_SIZE + 1)` consumes
    // every byte — leaving unread bytes in the kernel buffer would
    // cause RST-on-close instead of clean FIN, masking the bug we
    // are testing for.
    let mut payload = vec![b'a'; MAX_COMMAND_SIZE as usize];
    payload.push(b'\n');
    writer.write_all(&payload).await.unwrap();
    writer.shutdown().await.unwrap();

    let mut reader = BufReader::new(reader);
    let mut line = String::new();
    reader.read_line(&mut line).await.unwrap();
    let resp: IpcResponse = serde_json::from_str(line.trim()).unwrap();
    match resp {
        IpcResponse::Error { message } => {
            assert_eq!(message, "command too large");
        }
        other => panic!("unexpected response: {other:?}"),
    }

    // Daemon must half-close after the error response so the peer
    // sees EOF on the next read, not a hung socket.
    let mut tail = Vec::new();
    let trailing = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        tokio::io::AsyncReadExt::read_to_end(&mut reader, &mut tail),
    )
    .await
    .expect("daemon must half-close after oversize-command response")
    .unwrap();
    assert_eq!(
        trailing, 0,
        "expected clean EOF after oversize response, got {trailing} extra bytes"
    );

    server_handle.abort();
}

#[tokio::test]
async fn socket_permissions_are_0600() {
    use std::os::unix::fs::PermissionsExt;

    let state = Arc::new(test_state());
    let dir = tempfile::tempdir().unwrap();
    let sock_path = dir.path().join("test.sock");

    let server_handle = spawn_ipc_server(sock_path.clone(), state).await.unwrap();

    let meta = std::fs::metadata(&sock_path).unwrap();
    let mode = meta.permissions().mode() & 0o777;
    // §4.32 P0: tightened from 0o660 to 0o600 — owner-only. Group
    // members can no longer reach the IPC bus.
    assert_eq!(mode, 0o600, "socket should be mode 0600, got {:o}", mode);

    server_handle.abort();
}

#[tokio::test]
async fn accept_loop_drops_connections_beyond_cap() {
    // H-07: peers beyond the concurrency cap must see their
    // connection dropped immediately rather than queued, otherwise
    // a local spawn-flood DoS can exhaust FDs / heap / tokio task
    // slots on the runtime that also services DNS queries.
    //
    // Setup: spawn the server with cap=2, then open three clients
    // that connect but never write. The first two are accepted
    // and their handlers block in `read_line` (5s read timeout).
    // The third must be accepted-then-dropped, which the client
    // observes as immediate EOF on read.

    let state = Arc::new(test_state());
    let dir = tempfile::tempdir().unwrap();
    let sock_path = dir.path().join("cap-test.sock");

    let server = spawn_ipc_server_with_cap(sock_path.clone(), state, 2)
        .await
        .unwrap();

    // Open two connections that hold their permits open. We keep
    // the streams alive; the daemon-side handlers are blocked
    // reading.
    let _hold_a = tokio::net::UnixStream::connect(&sock_path).await.unwrap();
    let _hold_b = tokio::net::UnixStream::connect(&sock_path).await.unwrap();

    // Brief yield so the accept loop spawns the two handlers and
    // they each grab a permit before the next connect.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Third connection: accept happens, but try_acquire_owned
    // fails and the daemon drops the stream. The client sees
    // EOF (read returns 0) on its read end.
    let mut probe = tokio::net::UnixStream::connect(&sock_path).await.unwrap();
    let mut buf = [0u8; 1];
    let read_n = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        tokio::io::AsyncReadExt::read(&mut probe, &mut buf),
    )
    .await
    .expect("daemon must close the over-cap connection within timeout")
    .unwrap();
    assert_eq!(
        read_n, 0,
        "over-cap connection must be closed by daemon, got {read_n} bytes"
    );

    server.abort();
}

#[tokio::test]
async fn accept_loop_recovers_capacity_after_drop() {
    // H-07: a permit released by handler exit must let the next
    // connection through. Validates the semaphore's release path
    // (tokio's `OwnedSemaphorePermit::drop`) is wired correctly.
    let state = Arc::new(test_state());
    let dir = tempfile::tempdir().unwrap();
    let sock_path = dir.path().join("cap-recovery.sock");

    let server = spawn_ipc_server_with_cap(sock_path.clone(), state, 1)
        .await
        .unwrap();

    // Take the only permit, then close immediately so the handler
    // exits and releases.
    {
        let mut hold = tokio::net::UnixStream::connect(&sock_path).await.unwrap();
        // Send an invalid command so the handler completes quickly
        // (writes error response, releases permit).
        tokio::io::AsyncWriteExt::write_all(&mut hold, b"not-json\n")
            .await
            .unwrap();
        tokio::io::AsyncWriteExt::shutdown(&mut hold).await.unwrap();
        // Drain the response so the handler can finish writing.
        let mut sink = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut hold, &mut sink)
            .await
            .ok();
        drop(hold);
    }

    // Brief yield so the server-side handler completes and
    // releases its permit.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Next connection should succeed (cap recovered).
    let mut next = tokio::net::UnixStream::connect(&sock_path).await.unwrap();
    let cmd = serde_json::to_string(&IpcCommand::Status).unwrap();
    tokio::io::AsyncWriteExt::write_all(&mut next, format!("{cmd}\n").as_bytes())
        .await
        .unwrap();
    tokio::io::AsyncWriteExt::shutdown(&mut next).await.unwrap();

    let mut reader = BufReader::new(next);
    let mut line = String::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        reader.read_line(&mut line),
    )
    .await
    .expect("post-recovery connection must respond within timeout")
    .unwrap();
    assert!(
        line.contains("\"Status\"") || line.contains("\"status\""),
        "expected Status response, got: {line}"
    );

    server.abort();
}

#[tokio::test]
async fn bind_with_atomic_perms_produces_0600_at_canonical_path() {
    // H-06 / §4.32 P0: pin the atomic-rename path. The previous
    // design did bind→chmod, exposing a TOCTOU window where the
    // canonical socket path was visible at `0o666 & ~umask`
    // (typically `0o644`) until chmod tightened it. The atomic-
    // rename approach binds to a temp path, chmods, then
    // atomically renames into place — peers resolving the
    // canonical path see `0o600` from the first syscall. §4.32
    // tightened the chmod target from `0o660` to `0o600`.
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let sock_path = dir.path().join("atomic-perms.sock");

    let listener = bind_with_atomic_perms(&sock_path).unwrap();
    let mode = std::fs::metadata(&sock_path).unwrap().permissions().mode() & 0o777;
    drop(listener);

    assert_eq!(
        mode, 0o600,
        "atomic-perms bind must produce 0o600 at canonical path, got 0o{mode:o}"
    );
    // After bind, no `.bind.<pid>.<nanos>` temp leftover should
    // remain in the parent directory.
    for entry in std::fs::read_dir(dir.path()).unwrap() {
        let name = entry.unwrap().file_name();
        let name_str = name.to_string_lossy();
        assert!(
            !name_str.contains(".bind."),
            "stale bind temp left behind: {name_str}"
        );
    }
}

#[tokio::test]
async fn handle_connection_refuses_uid_mismatch() {
    // §4.32 P0: peer-uid gate. When the connecting peer's SO_PEERCRED
    // uid does not equal `state.daemon_uid`, the daemon must drop the
    // stream silently — no IpcResponse body — and emit an audit warn.
    // Peer observes EOF on read.
    let mut state = test_state();
    // Force daemon_uid to a value that cannot match the test process's
    // own euid. Saturating-add avoids u32 overflow on `geteuid()=u32::MAX`
    // (unreachable on Linux but cheap to defend).
    state.daemon_uid = current_euid().saturating_add(1);
    let state = Arc::new(state);

    let dir = tempfile::tempdir().unwrap();
    let sock_path = dir.path().join("uid-mismatch.sock");
    let server_handle = spawn_ipc_server(sock_path.clone(), state).await.unwrap();

    let mut probe = tokio::net::UnixStream::connect(&sock_path).await.unwrap();
    // Send a valid Status command. If the gate were absent the
    // daemon would write a Status response back; with the gate it
    // closes the stream before reading.
    let cmd = serde_json::to_string(&IpcCommand::Status).unwrap();
    let _ = tokio::io::AsyncWriteExt::write_all(&mut probe, format!("{cmd}\n").as_bytes()).await;
    let _ = tokio::io::AsyncWriteExt::shutdown(&mut probe).await;

    let mut buf = Vec::new();
    // Daemon may either:
    //  - close cleanly → read_to_end returns Ok(0) and `buf` is empty.
    //  - return ConnectionReset (ECONNRESET) before our write fully
    //    drained → read_to_end returns Err. Either outcome means
    //    "no IpcResponse landed on the wire", which is the contract.
    let read_outcome = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        tokio::io::AsyncReadExt::read_to_end(&mut probe, &mut buf),
    )
    .await
    .expect("daemon must close uid-mismatch stream within timeout");
    match read_outcome {
        Ok(n) => assert_eq!(
            n,
            0,
            "uid-mismatch must close with no body, got {n} bytes: {:?}",
            String::from_utf8_lossy(&buf)
        ),
        Err(e) => assert_eq!(
            e.kind(),
            std::io::ErrorKind::ConnectionReset,
            "expected ConnectionReset on uid-mismatch close, got {e:?}"
        ),
    }
    assert!(
        buf.is_empty(),
        "uid-mismatch path must never write a response body, got {:?}",
        String::from_utf8_lossy(&buf)
    );

    server_handle.abort();
}

#[tokio::test]
async fn handle_connection_accepts_uid_match() {
    // §4.32 P0: the gate must NOT reject the daemon-uid peer (the
    // happy path). Defaulting `state.daemon_uid` to `current_euid()`
    // matches the test process's own uid, so the connection should
    // proceed and a Status response should land on the wire.
    let state = Arc::new(test_state());
    let dir = tempfile::tempdir().unwrap();
    let sock_path = dir.path().join("uid-match.sock");
    let server_handle = spawn_ipc_server(sock_path.clone(), state).await.unwrap();

    let stream = tokio::net::UnixStream::connect(&sock_path).await.unwrap();
    let (reader, mut writer) = stream.into_split();
    let cmd = serde_json::to_string(&IpcCommand::Status).unwrap();
    tokio::io::AsyncWriteExt::write_all(&mut writer, format!("{cmd}\n").as_bytes())
        .await
        .unwrap();
    tokio::io::AsyncWriteExt::shutdown(&mut writer)
        .await
        .unwrap();

    let mut reader = BufReader::new(reader);
    let mut line = String::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        reader.read_line(&mut line),
    )
    .await
    .expect("uid-match connection must produce a response within timeout")
    .unwrap();
    assert!(
        line.contains("\"status\"") || line.contains("\"Status\""),
        "expected Status response on uid-match path, got: {line}"
    );

    server_handle.abort();
}

#[tokio::test]
async fn handle_connection_refuses_none_peer_uid() {
    // §4.32 P0 / DISC-7: if `SO_PEERCRED` ever fails (extremely
    // unlikely on Linux for an accepted AF_UNIX stream), `peer_uid`
    // returns `None`. The gate must treat None as a refusal —
    // fail-closed — because the daemon cannot prove the peer is
    // its own user without a valid cred. We exercise the branch
    // by calling `handle_connection` directly with a
    // `tokio::net::UnixStream` and `peer_uid = None`.
    let state = Arc::new(test_state());

    // socketpair gives us two halves we can pass to handle_connection
    // without going through accept_loop (which would re-derive
    // peer_uid via SO_PEERCRED).
    let (a, _b) = tokio::net::UnixStream::pair().unwrap();
    let result = handle_connection(a, None, &state).await;
    assert!(
        result.is_ok(),
        "None-uid refusal path must return Ok (silent drop), got {result:?}"
    );
}

#[test]
fn current_euid_matches_libc_geteuid() {
    // §4.32 P0: trivial smoke that `current_euid()` returns the
    // same value as `libc::geteuid()`. Acts as a regression catch
    // if a refactor swaps the syscall (e.g. to `getuid`) which
    // would silently break the daemon-uid gate when the daemon
    // runs setuid.
    // SAFETY: same justification as in `current_euid()` itself.
    let direct = unsafe { libc::geteuid() };
    assert_eq!(current_euid(), direct);
}

#[test]
fn bind_socket_refuses_to_clobber_regular_file() {
    // H-09: a regular file at the socket path must NOT be silently
    // unlinked. The daemon should refuse to bind and surface a plain-
    // English error so the operator can inspect the planted file.
    let dir = tempfile::tempdir().unwrap();
    let sock_path = dir.path().join("not-a-socket");
    std::fs::write(&sock_path, b"operator marker").unwrap();

    let err = bind_socket(&sock_path).unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("not a socket"),
        "expected 'not a socket' in error, got: {msg}"
    );
    // The marker file must still be on disk — the bail path must not
    // unlink before reporting the error.
    assert!(sock_path.exists(), "regular file was clobbered");
    let body = std::fs::read(&sock_path).unwrap();
    assert_eq!(body, b"operator marker");
}

#[test]
fn bind_socket_refuses_to_follow_planted_symlink() {
    // H-09: a symlink at the socket path must trip the "not a socket"
    // branch — `symlink_metadata` does not follow, so the link target
    // is never inspected and never unlinked.
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("victim");
    std::fs::write(&target, b"do not delete me").unwrap();
    let sock_path = dir.path().join("link.sock");
    std::os::unix::fs::symlink(&target, &sock_path).unwrap();

    let err = bind_socket(&sock_path).unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("not a socket"),
        "expected 'not a socket' in error, got: {msg}"
    );
    // Both the symlink and its target must still be intact.
    assert!(sock_path.is_symlink(), "symlink was unlinked");
    assert!(target.exists(), "symlink target was unlinked");
    let body = std::fs::read(&target).unwrap();
    assert_eq!(body, b"do not delete me");
}

#[tokio::test]
async fn bind_socket_removes_stale_socket() {
    // H-09: the legitimate stale-socket case must still work — an
    // actual socket left by a prior run is unlinked before bind.
    // Tokio runtime is required because `tokio::net::UnixListener::bind`
    // registers the FD with the reactor.
    let dir = tempfile::tempdir().unwrap();
    let sock_path = dir.path().join("stale.sock");
    // Create a real socket at the path, then drop the listener so
    // the inode lingers as a stale socket file.
    let stale = std::os::unix::net::UnixListener::bind(&sock_path).unwrap();
    drop(stale);
    assert!(sock_path.exists());

    // bind_socket should unlink the stale socket and bind a fresh one.
    let listener = bind_socket(&sock_path).unwrap();
    drop(listener);
    // After bind, the path is again a socket file.
    assert!(sock_path.exists());
}

/// rev-2606 api-auth-07-05: a parent directory bind_socket CREATES
/// must land at 0o700 regardless of umask (was `0o777 & ~umask`).
#[tokio::test]
async fn bind_socket_fresh_parent_dir_is_0o700() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let sock_path = dir.path().join("fresh-sub").join("control.sock");
    assert!(!sock_path.parent().unwrap().exists());

    let listener = bind_socket(&sock_path).unwrap();
    drop(listener);

    let mode = std::fs::metadata(sock_path.parent().unwrap())
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o700, "freshly-created parent must be 0o700");
}

/// DISC-3 symmetry: a PRE-EXISTING parent (production `/run/...`,
/// systemd-owned) is never re-chmodded.
#[tokio::test]
async fn bind_socket_preexisting_parent_mode_untouched() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let parent = dir.path().join("owned-by-systemd");
    std::fs::create_dir(&parent).unwrap();
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o755)).unwrap();

    let sock_path = parent.join("control.sock");
    let listener = bind_socket(&sock_path).unwrap();
    drop(listener);

    let mode = std::fs::metadata(&parent).unwrap().permissions().mode();
    assert_eq!(
        mode & 0o777,
        0o755,
        "pre-existing parent must keep its mode"
    );
}

fn test_state() -> DaemonState {
    use crate::dns::cache::DnsCache;

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
        api_token_hash: Arc::new(arc_swap::ArcSwap::from_pointee(None)),
        config_path: None,
        config_write_lock: Arc::new(tokio::sync::Mutex::new(())),
        list_statuses: None,
        list_state: None,
        local_records_hits: None,
        log_ring: None,
        notification_tx: None,
        reload_coalescer: None,
        oui_table: None,
        list_labels: Arc::new(vec![None; 64]),
        list_cmd_tx: Arc::new(arc_swap::ArcSwap::from_pointee(None)),
        daemon_uid: current_euid(),
        resource_budget_store: crate::resource_budget::types::new_store(),
        #[cfg(feature = "cluster")]
        cluster_observe: None,
    }
}

/// Build a state with a configured token hash for auth tests.
fn test_state_with_token(token_plaintext: &str) -> DaemonState {
    use crate::auth::token::hash_token;
    use crate::dns::cache::DnsCache;

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
        api_token_hash: Arc::new(arc_swap::ArcSwap::from_pointee(Some(hash_token(
            token_plaintext,
        )))),
        config_path: None,
        config_write_lock: Arc::new(tokio::sync::Mutex::new(())),
        list_statuses: None,
        list_state: None,
        local_records_hits: None,
        log_ring: None,
        notification_tx: None,
        reload_coalescer: None,
        oui_table: None,
        list_labels: Arc::new(vec![None; 64]),
        list_cmd_tx: Arc::new(arc_swap::ArcSwap::from_pointee(None)),
        daemon_uid: current_euid(),
        resource_budget_store: crate::resource_budget::types::new_store(),
        #[cfg(feature = "cluster")]
        cluster_observe: None,
    }
}

// --- Sprint 37 QL2: handle_query_logs status fields ---

fn test_state_with_query_log(
    log_path: &std::path::Path,
    config_dir: &std::path::Path,
    query_log_enabled: bool,
) -> DaemonState {
    use crate::dns::cache::DnsCache;
    use crate::tracking::engine::StatsEngine;

    let mut tracking = crate::config::settings::TrackingConfig::default();
    tracking.query_log_enabled = query_log_enabled;
    tracking.query_log_path = log_path.to_path_buf();
    let engine = Arc::new(StatsEngine::new(&tracking));

    let cache_config = crate::config::settings::CacheConfig::default();
    DaemonState {
        filter: Arc::new(FilterEngine::new()),
        cache: DnsCache::new(&cache_config),
        profiles: None,
        stats: Some(engine),
        listen_addr: "127.0.0.1:15353".into(),
        upstream_mode: "plain".into(),
        upstream_count: 2,
        upstream_servers: Vec::new(),
        list_count: 0,
        started_at: Instant::now(),
        shutdown_tx: None,
        reload_tx: None,
        api_token_hash: Arc::new(arc_swap::ArcSwap::from_pointee(None)),
        config_path: Some(config_dir.join("config.toml")),
        config_write_lock: Arc::new(tokio::sync::Mutex::new(())),
        list_statuses: None,
        list_state: None,
        local_records_hits: None,
        log_ring: None,
        notification_tx: None,
        reload_coalescer: None,
        oui_table: None,
        list_labels: Arc::new(vec![None; 64]),
        list_cmd_tx: Arc::new(arc_swap::ArcSwap::from_pointee(None)),
        daemon_uid: current_euid(),
        resource_budget_store: crate::resource_budget::types::new_store(),
        #[cfg(feature = "cluster")]
        cluster_observe: None,
    }
}

/// Write `n` parseable entries and return the blob, so every log
/// file in the m2 test below is large enough that the read is
/// unambiguously still in flight when the canary is polled.
fn bulk_log_blob(n: usize) -> String {
    let mut s = String::new();
    for i in 0..n {
        let entry = crate::tracking::query_log::QueryLogEntry {
            timestamp: "2026-04-23T10:00:00Z".into(),
            client_ip: "10.0.0.1".parse().unwrap(),
            client_name: None,
            domain: format!("d{i}.example.com"),
            query_type: "A".into(),
            result: "ALLOWED".into(),
            response_time_us: 100,
            cname_chain_via: None,
            rewrote_from: None,
        };
        s.push_str(&serde_json::to_string(&entry).unwrap());
        s.push('\n');
    }
    s
}

/// `s-review-2605-ipc-m2`: a `QueryLogs` request must not park a
/// tokio worker for the duration of its multi-file disk read.
///
/// **The observable is ordering, not latency.** On a single-worker
/// runtime a task spawned before the read can only make progress if
/// the handler yields the worker. When the read runs inline in
/// `poll()` the canary gets zero CPU *no matter how slow the read
/// is*, so the assertion needs no timing threshold and cannot flake
/// — which matters in a suite with known environment races.
///
/// The oversized corpus is a robustness aid, not the mechanism: the
/// domain filter matches nothing, so
/// `read_log_entries_with_state` never reaches its
/// `entries.len() >= limit` early break and walks every retained
/// sibling. That guarantees the `spawn_blocking` join handle is
/// still pending on its first poll in the fixed build.
///
/// Driven through `dispatch_command` (async in both builds) rather
/// than `handle_query_logs`, so this test compiles unchanged across
/// the signature change it is pinning.
///
/// **The read must be `tokio::spawn`ed, not awaited in the test
/// body.** `#[tokio::test]` drives the body with `block_on` on the
/// *main* thread, which is not a worker: an earlier version of this
/// test awaited the dispatch directly, so the inline read parked the
/// main thread while the worker stayed free to run the canary — and
/// it **passed against the unfixed handler**. Spawning the read puts
/// it on the same single worker the canary needs, which is the whole
/// point. Both tasks are spawned from the block_on thread and land
/// on the injection queue in FIFO order, so the read is picked up
/// first.
///
/// **If a future tokio changes that scheduling order, this test
/// degrades to a false negative, not a flake** — it would go green
/// while the defect is live, which is the failure mode above and the
/// one this repo has shipped before. Anyone touching the handler or
/// bumping tokio should re-confirm it goes *red* against an inline
/// read before trusting a green run.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn query_logs_read_does_not_park_the_runtime_worker() {
    use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};

    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("query.log");
    let blob = bulk_log_blob(8_000);
    std::fs::write(&log, &blob).unwrap();
    // Seven dated siblings — `retention_days` defaults to 7, so all
    // of them are walked.
    for d in 1..=7 {
        std::fs::write(
            dir.path().join(format!("query.log.2026-04-{:02}", 10 + d)),
            &blob,
        )
        .unwrap();
    }

    // `QueryLogs` is not a ReadOnly-tier command — it passes the
    // admin-token gate before reaching the handler.
    let mut state = test_state_with_query_log(&log, dir.path(), true);
    state.api_token_hash = Arc::new(arc_swap::ArcSwap::from_pointee(Some(
        crate::auth::token::hash_token("m2-test-token"),
    )));
    let state = Arc::new(state);

    let canary = Arc::new(AtomicBool::new(false));
    // Captured *inside* the read task, at the instant the read
    // returns: "had the canary already run?"
    let observed = Arc::new(AtomicBool::new(false));

    // Spawned FIRST, so the single worker picks it off the injection
    // queue before the canary. This task — not the test body — is
    // what must be prevented from parking the worker.
    let read_task = tokio::spawn({
        let state = Arc::clone(&state);
        let canary = Arc::clone(&canary);
        let observed = Arc::clone(&observed);
        async move {
            let resp = dispatch_command(
                IpcCommand::QueryLogs {
                    limit: 1000,
                    client: None,
                    blocked_only: false,
                    // Matches nothing → the limit is never satisfied
                    // → the sibling walk runs to completion.
                    domain: Some("zz-matches-nothing".into()),
                    since_secs: None,
                    cursor: None,
                    advanced: None,
                    token: Some("m2-test-token".into()),
                },
                None,
                &state,
            )
            .await;
            observed.store(canary.load(AtomicOrdering::SeqCst), AtomicOrdering::SeqCst);
            resp
        }
    });

    tokio::spawn({
        let flag = Arc::clone(&canary);
        async move {
            flag.store(true, AtomicOrdering::SeqCst);
        }
    });

    let resp = read_task.await.expect("read task must not panic");

    assert!(
        matches!(resp, IpcResponse::QueryLogs { .. }),
        "handler must still answer a well-formed response: {resp:?}"
    );
    assert!(
        observed.load(AtomicOrdering::SeqCst),
        "a task queued behind the query-log read had still not run by the time the read \
         returned — the read ran inline and parked the runtime worker"
    );
}

#[tokio::test]
async fn query_logs_response_reports_disabled_when_flag_false() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("query.log");
    // File exists with a valid entry — the daemon must still return
    // `logging_enabled = false` when the flag is off, even though
    // the read succeeds.
    let entry = crate::tracking::query_log::QueryLogEntry {
        timestamp: "2026-04-23T10:00:00Z".into(),
        client_ip: "10.0.0.1".parse().unwrap(),
        client_name: None,
        domain: "example.com".into(),
        query_type: "A".into(),
        result: "ALLOWED".into(),
        response_time_us: 100,
        cname_chain_via: None,
        rewrote_from: None,
    };
    std::fs::write(&log, serde_json::to_string(&entry).unwrap() + "\n").unwrap();
    let state = test_state_with_query_log(&log, dir.path(), false);

    let resp = handle_query_logs(
        &state,
        crate::ipc::protocol::QueryLogRequest {
            limit: 10,
            ..Default::default()
        },
    )
    .await;
    match resp {
        IpcResponse::QueryLogs {
            entries,
            logging_enabled,
            file_state,
            ..
        } => {
            assert!(!logging_enabled, "expected logging_enabled=false");
            assert_eq!(file_state, crate::ipc::protocol::QueryLogFileState::Ok);
            assert_eq!(entries.len(), 1);
        }
        other => panic!("expected QueryLogs, got {other:?}"),
    }
}

#[tokio::test]
async fn query_logs_response_reports_missing_when_file_absent() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("query.log"); // deliberately not created
    let state = test_state_with_query_log(&log, dir.path(), true);

    let resp = handle_query_logs(
        &state,
        crate::ipc::protocol::QueryLogRequest {
            limit: 10,
            ..Default::default()
        },
    )
    .await;
    match resp {
        IpcResponse::QueryLogs {
            entries,
            logging_enabled,
            file_state,
            ..
        } => {
            assert!(logging_enabled);
            assert_eq!(file_state, crate::ipc::protocol::QueryLogFileState::Missing);
            assert!(entries.is_empty());
        }
        other => panic!("expected QueryLogs, got {other:?}"),
    }
}

#[cfg(unix)]
#[tokio::test]
async fn query_logs_response_reports_unreadable_on_permission_error() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("query.log");
    std::fs::write(&log, "{}\n").unwrap();
    // chmod 000 — root can still read on Linux, so skip the assertion
    // for uid 0 (CI runs as a regular user; the Debian CI container
    // doesn't run `cargo test`).
    let mut perms = std::fs::metadata(&log).unwrap().permissions();
    perms.set_mode(0o000);
    std::fs::set_permissions(&log, perms).unwrap();

    if nix_uid_is_zero() {
        return;
    }

    let state = test_state_with_query_log(&log, dir.path(), true);
    let resp = handle_query_logs(
        &state,
        crate::ipc::protocol::QueryLogRequest {
            limit: 10,
            ..Default::default()
        },
    )
    .await;

    // Restore perms so tempdir cleanup succeeds.
    let mut perms = std::fs::metadata(&log).unwrap().permissions();
    perms.set_mode(0o600);
    std::fs::set_permissions(&log, perms).unwrap();

    match resp {
        IpcResponse::QueryLogs {
            entries,
            logging_enabled,
            file_state,
            ..
        } => {
            assert!(logging_enabled);
            assert_eq!(
                file_state,
                crate::ipc::protocol::QueryLogFileState::Unreadable
            );
            assert!(entries.is_empty());
        }
        other => panic!("expected QueryLogs, got {other:?}"),
    }
}

#[cfg(unix)]
fn nix_uid_is_zero() -> bool {
    // SAFETY: `libc::getuid` is a plain syscall with no arguments
    // and no cross-thread aliasing hazards.
    unsafe { libc::getuid() == 0 }
}

#[tokio::test]
async fn query_logs_response_reports_ok_on_happy_path() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("query.log");
    let entry = crate::tracking::query_log::QueryLogEntry {
        timestamp: "2026-04-23T10:00:00Z".into(),
        client_ip: "10.0.0.1".parse().unwrap(),
        client_name: Some("laptop".into()),
        domain: "google.com".into(),
        query_type: "A".into(),
        result: "ALLOWED".into(),
        response_time_us: 100,
        cname_chain_via: None,
        rewrote_from: None,
    };
    std::fs::write(&log, serde_json::to_string(&entry).unwrap() + "\n").unwrap();

    let state = test_state_with_query_log(&log, dir.path(), true);
    let resp = handle_query_logs(
        &state,
        crate::ipc::protocol::QueryLogRequest {
            limit: 10,
            ..Default::default()
        },
    )
    .await;
    match resp {
        IpcResponse::QueryLogs {
            entries,
            logging_enabled,
            file_state,
            ..
        } => {
            assert!(logging_enabled);
            assert_eq!(file_state, crate::ipc::protocol::QueryLogFileState::Ok);
            assert_eq!(entries.len(), 1);
            assert_eq!(entries[0].domain, "google.com");
        }
        other => panic!("expected QueryLogs, got {other:?}"),
    }
}

// --- P0-3: IPC authorization tests ---

/// ReadOnly command (Status) works without any token, even when the
/// daemon has no token configured. This is the "fresh install, no
/// auth yet" path — warden status must still work.
#[tokio::test]
async fn readonly_command_works_without_token() {
    let state = Arc::new(test_state());
    let resp = dispatch_command(IpcCommand::Status, None, &state).await;
    match resp {
        IpcResponse::Status { .. } => {}
        other => panic!("expected Status, got {other:?}"),
    }
}

/// mem2608-s3 / F-E — the discriminating regression test. No explicit
/// flush anywhere in this body: the insert calls `DnsCache::insert`
/// directly, and the read goes through the full
/// `dispatch_command` → `handle_status` path exactly as the real
/// `warden status` IPC round-trip does. Against the pre-fix (sync
/// `handle_status`, cold `entry_count()`/`weighted_size()` read) this
/// is flaky-to-failing; against the fix it is deterministic, because
/// `handle_status` flushes internally before reading.
#[tokio::test]
async fn status_reports_cache_occupancy_without_a_manual_flush() {
    let state = Arc::new(test_state());
    state
        .cache
        .insert(
            "nonexistent.example",
            hickory_proto::rr::RecordType::A,
            hickory_proto::rr::DNSClass::IN,
            Vec::new(),
            hickory_proto::op::ResponseCode::NXDomain,
            None,
            None,
        )
        .await;

    let resp = dispatch_command(IpcCommand::Status, None, &state).await;
    match resp {
        IpcResponse::Status {
            cache_entries,
            cache_weighted_size,
            ..
        } => {
            assert_eq!(cache_entries, 1);
            assert_eq!(cache_weighted_size, 1);
        }
        other => panic!("expected Status, got {other:?}"),
    }
}

/// mem2608-s3 / F-P — the discriminating denominator test. 4 blocked
/// queries (never reach the cache, per `evaluate_with_overlay` running
/// before `cache.lookup_keyed`), 3 non-blocked cache hits, 3 non-blocked
/// misses: 10 total, 6 cacheable. Under the pre-fix `hits / total`
/// formula this reads 30%; under `hits / (total - blocked)` it reads
/// 50%. The two are far enough apart that no rounding ambiguity can
/// paper over a regression back to the old denominator. Calls
/// `handle_tracking_stats` directly — it's `Admin`-tier over IPC and
/// the auth gate is not what this test is about.
#[test]
fn tracking_stats_cache_rate_excludes_blocked_from_denominator() {
    use crate::config::settings::TrackingConfig;
    use std::net::{IpAddr, Ipv4Addr};

    let stats = Arc::new(StatsEngine::new(&TrackingConfig::default()));
    let ip: IpAddr = Ipv4Addr::new(10, 0, 0, 1).into();
    for _ in 0..4 {
        stats.record_query(
            ip,
            "blocked.example",
            None,
            None,
            hickory_proto::rr::RecordType::A,
            true,
            false,
            None,
        );
    }
    for _ in 0..3 {
        stats.record_query(
            ip,
            "cached.example",
            None,
            None,
            hickory_proto::rr::RecordType::A,
            false,
            true,
            None,
        );
    }
    for _ in 0..3 {
        stats.record_query(
            ip,
            "miss.example",
            None,
            None,
            hickory_proto::rr::RecordType::A,
            false,
            false,
            None,
        );
    }
    let state = DaemonState {
        stats: Some(stats),
        ..test_state()
    };

    let resp = handle_tracking_stats(&state);
    match resp {
        IpcResponse::TrackingStats {
            cache_hit_rate,
            blocked_pct,
            ..
        } => {
            assert!((cache_hit_rate - 50.0).abs() < 1e-9, "got {cache_hit_rate}");
            // blocked_pct is deliberately unaffected — 4/10, all queries.
            assert!((blocked_pct - 40.0).abs() < 1e-9, "got {blocked_pct}");
        }
        other => panic!("expected TrackingStats, got {other:?}"),
    }
}

/// Build a coalescer whose worker is alive, plus the receiver that
/// keeps it that way. Dropping the receiver is the only route out of
/// the worker's loop, so the caller decides which case it wants.
fn coalescer_with_worker(
    window: std::time::Duration,
) -> (
    Arc<crate::ipc::ReloadCoalescer>,
    tokio::sync::mpsc::Receiver<Option<u32>>,
) {
    let (tx, rx) = tokio::sync::mpsc::channel::<Option<u32>>(1);
    let coalescer = Arc::new(crate::ipc::ReloadCoalescer::with_window(tx, window));
    let _worker = coalescer.clone().spawn_worker();
    (coalescer, rx)
}

/// The production path — a coalescer is wired — must be able to
/// report failure. It could not: `request` returned a bare count, so
/// `IpcError::ReloadChannelClosed` was structurally unreachable and
/// every write verb ending in a reload printed success against a
/// daemon that would never apply it.
#[tokio::test]
async fn reload_reports_failure_once_the_coalescer_worker_is_gone() {
    let window = std::time::Duration::from_millis(20);
    let (coalescer, rx) = coalescer_with_worker(window);
    let mut state = test_state();
    state.reload_coalescer = Some(coalescer.clone());

    // Kill the worker: drop the receiver, then let one request drive
    // it through a failing send.
    drop(rx);
    assert!(matches!(
        handle_reload(None, &state).await,
        IpcResponse::Ok { .. }
    ));
    tokio::time::sleep(window * 5).await;

    match handle_reload(None, &state).await {
        IpcResponse::Error { message } => assert_eq!(
            message,
            crate::ipc::errors::IPC_ERROR_RELOAD_CHANNEL_CLOSED,
            "the refusal must reach the operator as the existing \
             reload-channel error, not a new string"
        ),
        other => panic!("expected Error once the worker is gone, got {other:?}"),
    }
}

/// Positive control for the test above. A `request` wired to refuse
/// unconditionally would satisfy it; this pins that a live worker
/// still queues.
#[tokio::test]
async fn reload_still_queues_while_the_coalescer_worker_lives() {
    let window = std::time::Duration::from_millis(20);
    let (coalescer, _rx) = coalescer_with_worker(window);
    let mut state = test_state();
    state.reload_coalescer = Some(coalescer);

    match handle_reload(None, &state).await {
        IpcResponse::Ok { message } => {
            assert!(
                message.contains("reload queued"),
                "expected the queued message, got: {message}"
            );
        }
        other => panic!("expected Ok from a live coalescer, got {other:?}"),
    }
}

/// Mutating command (Reload) without any token configured on the
/// daemon is refused with the "run `warden token generate`" message.
#[tokio::test]
async fn mutating_rejected_when_no_token_configured() {
    let state = Arc::new(test_state()); // api_token_hash = None
    let resp = dispatch_command(IpcCommand::Reload { token: None }, None, &state).await;
    match resp {
        IpcResponse::Error { message } => {
            assert!(
                message.contains("warden token generate"),
                "error should point the user at the exact fix command, got: {message}"
            );
        }
        other => panic!("expected Error, got {other:?}"),
    }
}

/// Admin command (Shutdown) without any token configured is refused.
/// This is the critical case — we must not silently shut the daemon
/// down in an unauth state.
#[tokio::test]
async fn admin_rejected_when_no_token_configured() {
    let state = Arc::new(test_state());
    let resp = dispatch_command(IpcCommand::Shutdown { token: None }, None, &state).await;
    assert!(matches!(resp, IpcResponse::Error { .. }));
}

/// Daemon has a token configured, but the client didn't attach one.
/// The CLI would normally auto-attach; this path catches raw socket
/// writers or stale clients.
#[tokio::test]
async fn mutating_rejected_when_token_missing_but_configured() {
    let state = Arc::new(test_state_with_token("ps_correctvalue"));
    let resp = dispatch_command(IpcCommand::Reload { token: None }, None, &state).await;
    match resp {
        IpcResponse::Error { message } => {
            assert!(
                message.contains("warden") && message.contains("auto-discover"),
                "expected plain-English 'use warden CLI' message, got: {message}"
            );
        }
        other => panic!("expected Error, got {other:?}"),
    }
}

/// Daemon has a token configured; client attaches the wrong token.
/// Rejection message must point the user at `warden token regenerate`.
#[tokio::test]
async fn mutating_rejected_when_token_wrong() {
    let state = Arc::new(test_state_with_token("ps_correctvalue"));
    let resp = dispatch_command(
        IpcCommand::Reload {
            token: Some("ps_wrongvalue".into()),
        },
        None,
        &state,
    )
    .await;
    match resp {
        IpcResponse::Error { message } => {
            assert!(
                message.contains("warden token regenerate"),
                "expected regenerate hint, got: {message}"
            );
        }
        other => panic!("expected Error, got {other:?}"),
    }
}

/// Daemon has a token configured; client attaches the correct token.
/// The command is authorized and dispatched. We can't check actual
/// reload behavior here (reload_tx is None in test_state), so we
/// confirm the response is NOT an auth error.
#[tokio::test]
async fn mutating_accepted_when_token_correct() {
    let state = Arc::new(test_state_with_token("ps_correctvalue"));
    let resp = dispatch_command(
        IpcCommand::Reload {
            token: Some("ps_correctvalue".into()),
        },
        None,
        &state,
    )
    .await;
    // handle_reload returns Error{message: "reload not available"}
    // when reload_tx is None — confirm the failure is about reload,
    // not about auth.
    match resp {
        IpcResponse::Error { message } => {
            assert!(
                !message.contains("token"),
                "auth error leaked through to dispatch, got: {message}"
            );
            assert!(
                message.contains("reload") || message.contains("channel"),
                "expected reload/channel error, got: {message}"
            );
        }
        IpcResponse::Ok { .. } => {} // acceptable too
        other => panic!("unexpected response: {other:?}"),
    }
}

/// Admin command with the correct token is authorized. QueryLogs
/// fails early on missing stats engine, but the failure must not be
/// an auth failure.
#[tokio::test]
async fn admin_accepted_when_token_correct() {
    let state = Arc::new(test_state_with_token("ps_correctvalue"));
    let resp = dispatch_command(
        IpcCommand::QueryLogs {
            limit: 10,
            client: None,
            blocked_only: false,
            domain: None,
            since_secs: None,
            cursor: None,
            advanced: None,
            token: Some("ps_correctvalue".into()),
        },
        None,
        &state,
    )
    .await;
    match resp {
        IpcResponse::Error { message } => {
            assert!(
                !message.contains("token") && !message.contains("admin token"),
                "auth error leaked through to dispatch, got: {message}"
            );
        }
        IpcResponse::QueryLogs { .. } => {}
        other => panic!("unexpected response: {other:?}"),
    }
}

// --- Sprint 22: GetAllDevices ---

/// GetAllDevices is ReadOnly — no token required even when one is
/// configured. Footgun escape path depends on this: the operator
/// who just locked themselves out must be able to see the view
/// without reading a token file.
#[test]
fn get_all_clients_is_readonly() {
    use super::super::protocol::CommandTier;
    assert_eq!(IpcCommand::GetAllDevices.tier(), CommandTier::ReadOnly);
}

/// Missing profile resolver is a config/wiring bug, not "no clients
/// yet" — the handler returns an explicit Error so the TUI renders a
/// banner instead of silently showing zeros.
#[tokio::test]
async fn get_all_clients_errors_when_no_profile_resolver() {
    let state = Arc::new(test_state()); // profiles: None
    let resp = dispatch_command(IpcCommand::GetAllDevices, None, &state).await;
    match resp {
        IpcResponse::Error { message } => {
            assert!(
                message.contains("profile resolver"),
                "error should name the missing component, got: {message}"
            );
        }
        other => panic!("expected Error, got {other:?}"),
    }
}

/// When ProfileResolver is present but empty and no client has ever
/// been observed, the view is legitimately empty (not an error).
#[tokio::test]
async fn get_all_clients_empty_view_on_zero_clients() {
    use crate::config::schema::ConfigV1;
    use crate::profiles::ProfileResolver;

    let mut config = ConfigV1::test_scaffold();
    config.schema_version = 3;
    let bit_map = crate::lists::source_key::SourceBitMap::default();
    let profiles = Arc::new(ProfileResolver::build(
        &config,
        &bit_map,
        &crate::config::custom_list::CustomListStore::new(),
    ));

    let cache_config = crate::config::settings::CacheConfig::default();
    let state = Arc::new(DaemonState {
        filter: Arc::new(FilterEngine::new()),
        cache: DnsCache::new(&cache_config),
        profiles: Some(profiles),
        stats: None,
        listen_addr: "127.0.0.1:15353".into(),
        upstream_mode: "plain".into(),
        upstream_count: 2,
        upstream_servers: Vec::new(),
        list_count: 0,
        started_at: Instant::now(),
        shutdown_tx: None,
        reload_tx: None,
        api_token_hash: Arc::new(arc_swap::ArcSwap::from_pointee(None)),
        config_path: None,
        config_write_lock: Arc::new(tokio::sync::Mutex::new(())),
        list_statuses: None,
        list_state: None,
        local_records_hits: None,
        log_ring: None,
        notification_tx: None,
        reload_coalescer: None,
        oui_table: None,
        list_labels: Arc::new(vec![None; 64]),
        list_cmd_tx: Arc::new(arc_swap::ArcSwap::from_pointee(None)),
        daemon_uid: current_euid(),
        resource_budget_store: crate::resource_budget::types::new_store(),
        #[cfg(feature = "cluster")]
        cluster_observe: None,
    });

    let resp = dispatch_command(IpcCommand::GetAllDevices, None, &state).await;
    match resp {
        IpcResponse::DeviceView(view) => {
            assert!(view.mapped.is_empty());
            assert!(view.unmapped.is_empty());
        }
        other => panic!("expected DeviceView, got {other:?}"),
    }
}

/// With a profile resolver containing a mapped device and a stats
/// engine that observed both that mapped device and an unknown IP,
/// the response must split them correctly and carry the metadata
/// from v1 `[[devices]]`.
#[tokio::test]
async fn get_all_clients_splits_mapped_and_unmapped() {
    use crate::config::schema::{ConfigV1, Device, Id, Profile};
    use crate::config::settings::TrackingConfig;
    use crate::profiles::ProfileResolver;
    use crate::tracking::StatsEngine;
    use std::net::{IpAddr, Ipv4Addr};

    let mut config = ConfigV1::test_scaffold();
    config.schema_version = 3;
    config.profiles.insert(
        "default".into(),
        Profile {
            display_name: "Default".into(),
            ..Default::default()
        },
    );
    config.devices.push(Device {
        id: Id::new("edo-laptop").unwrap(),
        display_name: "edo-laptop".into(),
        ip: Some("192.168.1.42".parse().unwrap()),
        mac: None,
        mac_aliases: vec![],
        profile: Some(Id::new("default").unwrap()),
        groups: vec![],
        owner: Some("Operator".into()),
        device_type: Some("ThinkPad T14".into()),
        department: Some("home".into()),
        notes: None,
        allow_rules: vec![],
        deny_rules: vec![],
        override_profile_deny: false,
        unfiltered: false,
        network_name: None,
        network_name_wildcard: false,
    });

    let bit_map = crate::lists::source_key::SourceBitMap::default();
    let profiles = Arc::new(ProfileResolver::build(
        &config,
        &bit_map,
        &crate::config::custom_list::CustomListStore::new(),
    ));

    let stats = Arc::new(StatsEngine::new(&TrackingConfig::default()));
    let mapped_ip: IpAddr = Ipv4Addr::new(192, 168, 1, 42).into();
    let unmapped_ip: IpAddr = Ipv4Addr::new(10, 0, 0, 99).into();
    stats.record_query(
        mapped_ip,
        "good.com",
        Some("edo-laptop"),
        Some("default"),
        hickory_proto::rr::RecordType::A,
        false,
        false,
        None,
    );
    stats.record_query(
        mapped_ip,
        "ads.example",
        None,
        None,
        hickory_proto::rr::RecordType::A,
        true,
        false,
        None,
    );
    stats.record_query(
        unmapped_ip,
        "random.example",
        None,
        None,
        hickory_proto::rr::RecordType::A,
        false,
        false,
        None,
    );

    let cache_config = crate::config::settings::CacheConfig::default();
    let state = Arc::new(DaemonState {
        filter: Arc::new(FilterEngine::new()),
        cache: DnsCache::new(&cache_config),
        profiles: Some(profiles),
        stats: Some(stats),
        listen_addr: "127.0.0.1:15353".into(),
        upstream_mode: "plain".into(),
        upstream_count: 2,
        upstream_servers: Vec::new(),
        list_count: 0,
        started_at: Instant::now(),
        shutdown_tx: None,
        reload_tx: None,
        api_token_hash: Arc::new(arc_swap::ArcSwap::from_pointee(None)),
        config_path: None,
        config_write_lock: Arc::new(tokio::sync::Mutex::new(())),
        list_statuses: None,
        list_state: None,
        local_records_hits: None,
        log_ring: None,
        notification_tx: None,
        reload_coalescer: None,
        oui_table: None,
        list_labels: Arc::new(vec![None; 64]),
        list_cmd_tx: Arc::new(arc_swap::ArcSwap::from_pointee(None)),
        daemon_uid: current_euid(),
        resource_budget_store: crate::resource_budget::types::new_store(),
        #[cfg(feature = "cluster")]
        cluster_observe: None,
    });

    let resp = dispatch_command(IpcCommand::GetAllDevices, None, &state).await;
    match resp {
        IpcResponse::DeviceView(view) => {
            assert_eq!(view.mapped.len(), 1);
            let m = &view.mapped[0];
            assert_eq!(m.name, "edo-laptop");
            assert_eq!(m.ip, "192.168.1.42");
            assert_eq!(m.owner.as_deref(), Some("Operator"));
            assert_eq!(m.device_type.as_deref(), Some("ThinkPad T14"));
            assert_eq!(m.department.as_deref(), Some("home"));
            assert_eq!(m.queries, 2);
            assert_eq!(m.blocked, 1);
            assert!(m.online);

            assert_eq!(view.unmapped.len(), 1);
            let u = &view.unmapped[0];
            assert_eq!(u.ip, "10.0.0.99");
            assert_eq!(u.queries, 1);
            assert!(u.online);
        }
        other => panic!("expected DeviceView, got {other:?}"),
    }
}

// ── s23-ipc-client-mutations: DeviceAdd handler tests ──────────

/// Build a DaemonState wired to a temp config file + auth token,
/// suitable for exercising client mutation handlers end-to-end
/// (including the validator + atomic write path).
fn test_state_with_config_path(
    token_plaintext: &str,
    config_path: PathBuf,
) -> (DaemonState, tokio::sync::mpsc::Receiver<Option<u32>>) {
    use crate::auth::token::hash_token;
    use crate::dns::cache::DnsCache;

    let cache_config = crate::config::settings::CacheConfig::default();
    let (reload_tx, reload_rx) = tokio::sync::mpsc::channel::<Option<u32>>(1);
    let state = DaemonState {
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
        reload_tx: Some(reload_tx),
        api_token_hash: Arc::new(arc_swap::ArcSwap::from_pointee(Some(hash_token(
            token_plaintext,
        )))),
        config_path: Some(config_path),
        config_write_lock: Arc::new(tokio::sync::Mutex::new(())),
        list_statuses: None,
        list_state: None,
        local_records_hits: None,
        log_ring: None,
        notification_tx: None,
        reload_coalescer: None,
        oui_table: None,
        list_labels: Arc::new(vec![None; 64]),
        list_cmd_tx: Arc::new(arc_swap::ArcSwap::from_pointee(None)),
        daemon_uid: current_euid(),
        resource_budget_store: crate::resource_budget::types::new_store(),
        #[cfg(feature = "cluster")]
        cluster_observe: None,
    };
    (state, reload_rx)
}

/// Returns a `(TempDir, PathBuf)` pair so the tempdir's Drop cleans
/// up automatically when the caller's binding (typically `_dir`)
/// goes out of scope. Avoids the previous `/tmp/purge-warden-test-…`
/// fixtures that two parallel tests with the same suffix could
/// collide on.
fn client_mutation_temp_config(content: &str, suffix: &str) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(format!("config-{suffix}.toml"));
    std::fs::write(&path, content).unwrap();
    (dir, path)
}

/// §4.27-A: load the v1 config and return its devices for
/// post-mutation assertions. Replaces the pre-migration
/// `Settings::from_file(&path).clients` verification — the IPC
/// device handlers are now v1-native and write `[[devices]]`.
fn load_devices(path: &std::path::Path) -> Vec<crate::config::schema::Device> {
    crate::config::loader::load_config(path, time::OffsetDateTime::now_utc())
        .expect("v1 config must load")
        .config
        .devices
}

#[tokio::test]
async fn client_add_happy_path_writes_and_reloads() {
    let initial = r#"
schema_version = 3

[profiles.default]
display_name = "Default"

[upstream]
servers = ["192.0.2.1:53"]
"#;
    let (_dir, path) = client_mutation_temp_config(initial, "happy");
    let (state, mut reload_rx) = test_state_with_config_path("tok-happy", path.clone());
    let state = Arc::new(state);

    let client = crate::config::settings::ClientConfig {
        name: "edo-laptop".into(),
        ip: "192.168.1.42".parse().unwrap(),
        mac: None,
        mac_aliases: Vec::new(),
        profile: "default".into(),
        owner: Some("Operator".into()),
        device_type: Some("ThinkPad".into()),
        department: None,
        group: None,
        notes: None,
    };
    let cmd = IpcCommand::DeviceAdd {
        client,
        token: Some("tok-happy".into()),
    };

    let resp = dispatch_command(cmd, None, &state).await;
    match &resp {
        IpcResponse::Ok { message } => {
            assert!(message.contains("edo-laptop"), "got {message}");
        }
        other => panic!("expected Ok, got {other:?}"),
    }

    // Verify the file was actually rewritten with the v1 device.
    let devices = load_devices(&path);
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0].id.as_str(), "edo-laptop");
    assert_eq!(devices[0].owner.as_deref(), Some("Operator"));

    // Verify the reload signal fired (drains the channel).
    assert!(reload_rx.try_recv().is_ok(), "reload signal must be sent");
}

#[tokio::test]
async fn client_add_rejects_duplicate_name_with_named_error() {
    let initial = r#"
schema_version = 3

[profiles.default]
display_name = "Default"

[[devices]]
id = "laptop"
display_name = "laptop"
ip = "192.168.1.42"
profile = "default"

[upstream]
servers = ["192.0.2.1:53"]
"#;
    let (_dir, path) = client_mutation_temp_config(initial, "dup-name");
    let (state, _rx) = test_state_with_config_path("tok-dup-name", path.clone());
    let state = Arc::new(state);

    let dup = crate::config::settings::ClientConfig {
        name: "laptop".into(),
        ip: "192.168.1.99".parse().unwrap(),
        mac: None,
        mac_aliases: Vec::new(),
        profile: "default".into(),
        owner: None,
        device_type: None,
        department: None,
        group: None,
        notes: None,
    };
    let cmd = IpcCommand::DeviceAdd {
        client: dup,
        token: Some("tok-dup-name".into()),
    };

    let resp = dispatch_command(cmd, None, &state).await;
    match resp {
        IpcResponse::Error { message } => {
            assert!(
                message.contains("\"laptop\""),
                "error must name the offending client: {message}"
            );
        }
        other => panic!("expected Error, got {other:?}"),
    }

    // File must NOT have been mutated.
    let devices = load_devices(&path);
    assert_eq!(devices.len(), 1, "duplicate add must not append");
}

#[tokio::test]
async fn client_add_rejects_duplicate_ip_with_named_error() {
    let initial = r#"
schema_version = 3

[profiles.default]
display_name = "Default"

[[devices]]
id = "laptop"
display_name = "laptop"
ip = "192.168.1.42"
profile = "default"

[upstream]
servers = ["192.0.2.1:53"]
"#;
    let (_dir, path) = client_mutation_temp_config(initial, "dup-ip");
    let (state, _rx) = test_state_with_config_path("tok-dup-ip", path.clone());
    let state = Arc::new(state);

    let dup = crate::config::settings::ClientConfig {
        name: "phone".into(),
        ip: "192.168.1.42".parse().unwrap(), // same IP
        mac: None,
        mac_aliases: Vec::new(),
        profile: "default".into(),
        owner: None,
        device_type: None,
        department: None,
        group: None,
        notes: None,
    };
    let cmd = IpcCommand::DeviceAdd {
        client: dup,
        token: Some("tok-dup-ip".into()),
    };

    let resp = dispatch_command(cmd, None, &state).await;
    match resp {
        IpcResponse::Error { message } => {
            assert!(
                message.contains("192.168.1.42"),
                "error must name the offending IP: {message}"
            );
        }
        other => panic!("expected Error, got {other:?}"),
    }
}

#[tokio::test]
async fn client_add_requires_admin_token() {
    let (_dir, path) = client_mutation_temp_config(
        "schema_version = 3\n\n[profiles.default]\ndisplay_name = \"Default\"\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
        "auth",
    );
    let (state, _rx) = test_state_with_config_path("tok-auth", path.clone());
    let state = Arc::new(state);

    let client = crate::config::settings::ClientConfig {
        name: "x".into(),
        ip: "192.168.1.42".parse().unwrap(),
        mac: None,
        mac_aliases: Vec::new(),
        profile: "default".into(),
        owner: None,
        device_type: None,
        department: None,
        group: None,
        notes: None,
    };
    // No token attached — admin gate must reject.
    let cmd = IpcCommand::DeviceAdd {
        client,
        token: None,
    };
    let resp = dispatch_command(cmd, None, &state).await;
    match resp {
        IpcResponse::Error { message } => {
            assert!(
                message.contains("admin token") || message.contains("token"),
                "auth error must mention token: {message}"
            );
        }
        other => panic!("expected auth Error, got {other:?}"),
    }

    // Verify file was NOT mutated by an unauthenticated request.
    assert!(
        load_devices(&path).is_empty(),
        "unauthenticated add must not write"
    );
}

#[tokio::test]
async fn client_add_validator_catches_unknown_profile() {
    let (_dir, path) = client_mutation_temp_config(
        "schema_version = 3\n\n[profiles.default]\ndisplay_name = \"Default\"\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
        "validator",
    );
    let (state, _rx) = test_state_with_config_path("tok-val", path.clone());
    let state = Arc::new(state);

    let client = crate::config::settings::ClientConfig {
        name: "tablet".into(),
        ip: "10.0.0.50".parse().unwrap(),
        mac: None,
        mac_aliases: Vec::new(),
        profile: "ghost-profile".into(), // not configured
        owner: None,
        device_type: None,
        department: None,
        group: None,
        notes: None,
    };
    let cmd = IpcCommand::DeviceAdd {
        client,
        token: Some("tok-val".into()),
    };
    let resp = dispatch_command(cmd, None, &state).await;
    match resp {
        IpcResponse::Error { message } => {
            assert!(
                message.contains("ghost-profile") || message.contains("validation"),
                "validator error must surface the unknown profile: {message}"
            );
        }
        other => panic!("expected validation Error, got {other:?}"),
    }
}

#[tokio::test]
async fn client_add_concurrent_calls_serialize_through_write_lock() {
    // Two concurrent DeviceAdds must both succeed and both rows
    // must end up on disk — without the write lock the second
    // would overwrite the first's append.
    let (_dir, path) = client_mutation_temp_config(
        "schema_version = 3\n\n[profiles.default]\ndisplay_name = \"Default\"\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
        "concurrent",
    );
    let (state, _rx) = test_state_with_config_path("tok-conc", path.clone());
    let state = Arc::new(state);

    let mk_client = |name: &str, ip: &str| crate::config::settings::ClientConfig {
        name: name.into(),
        ip: ip.parse().unwrap(),
        mac: None,
        mac_aliases: Vec::new(),
        profile: "default".into(),
        owner: None,
        device_type: None,
        department: None,
        group: None,
        notes: None,
    };

    let s1 = state.clone();
    let s2 = state.clone();
    let c1 = mk_client("one", "192.168.1.1");
    let c2 = mk_client("two", "192.168.1.2");

    let h1 = tokio::spawn(async move {
        dispatch_command(
            IpcCommand::DeviceAdd {
                client: c1,
                token: Some("tok-conc".into()),
            },
            None,
            &s1,
        )
        .await
    });
    let h2 = tokio::spawn(async move {
        dispatch_command(
            IpcCommand::DeviceAdd {
                client: c2,
                token: Some("tok-conc".into()),
            },
            None,
            &s2,
        )
        .await
    });

    let r1 = h1.await.unwrap();
    let r2 = h2.await.unwrap();
    assert!(matches!(r1, IpcResponse::Ok { .. }));
    assert!(matches!(r2, IpcResponse::Ok { .. }));

    // Both must be on disk — no clobbering.
    let devices = load_devices(&path);
    assert_eq!(
        devices.len(),
        2,
        "both concurrent adds must persist (write lock works)"
    );
    let ids: Vec<&str> = devices.iter().map(|d| d.id.as_str()).collect();
    assert!(ids.contains(&"one"));
    assert!(ids.contains(&"two"));
}

// ── s23-ipc-client-mutations: DeviceUpdate handler tests ──────

#[tokio::test]
async fn client_update_partial_patch_only_touches_provided_fields() {
    let initial = r#"
schema_version = 3

[profiles.default]
display_name = "Default"

[[devices]]
id = "edo-laptop"
display_name = "edo-laptop"
ip = "192.168.1.42"
mac = "AA:BB:CC:DD:EE:FF"
profile = "default"
owner = "Operator"
device_type = "ThinkPad"
department = "home"
tags = ["trusted"]

[upstream]
servers = ["192.0.2.1:53"]
"#;
    let (_dir, path) = client_mutation_temp_config(initial, "update-partial");
    let (state, mut reload_rx) = test_state_with_config_path("tok-up", path.clone());
    let state = Arc::new(state);

    // Patch only `owner` and leave everything else alone.
    let patch = super::super::protocol::DevicePatch {
        owner: Some(Some("Casey".into())),
        ..Default::default()
    };
    let cmd = IpcCommand::DeviceUpdate {
        name: "edo-laptop".into(),
        patch,
        token: Some("tok-up".into()),
    };
    let resp = dispatch_command(cmd, None, &state).await;
    assert!(matches!(resp, IpcResponse::Ok { .. }), "got {resp:?}");

    let devices = load_devices(&path);
    let d = &devices[0];
    assert_eq!(d.id.as_str(), "edo-laptop", "id unchanged");
    assert_eq!(
        d.ip.map(|ip| ip.to_string()).as_deref(),
        Some("192.168.1.42"),
        "ip unchanged"
    );
    assert_eq!(d.mac.as_deref(), Some("AA:BB:CC:DD:EE:FF"), "mac unchanged");
    assert_eq!(
        d.profile.as_ref().map(|p| p.as_str()),
        Some("default"),
        "profile unchanged"
    );
    assert_eq!(d.owner.as_deref(), Some("Casey"), "owner patched");
    assert_eq!(
        d.device_type.as_deref(),
        Some("ThinkPad"),
        "device unchanged"
    );
    assert!(reload_rx.try_recv().is_ok());
}

// ── device-network-name (2026-08-10 design spec), Task 9: DevicePatch
// write side ─────────────────────────────────────────────────────

#[tokio::test]
async fn device_update_sets_network_name() {
    let initial = r#"
schema_version = 3

[profiles.default]
display_name = "Default"

[[devices]]
id = "edo-laptop"
display_name = "edo-laptop"
ip = "192.168.1.42"
profile = "default"

[upstream]
servers = ["192.0.2.1:53"]
"#;
    let (_dir, path) = client_mutation_temp_config(initial, "update-netname-set");
    let (state, _reload_rx) = test_state_with_config_path("tok-up", path.clone());
    let state = Arc::new(state);

    let patch = super::super::protocol::DevicePatch {
        network_name: Some(Some("desktop-1".into())),
        ..Default::default()
    };
    let cmd = IpcCommand::DeviceUpdate {
        name: "edo-laptop".into(),
        patch,
        token: Some("tok-up".into()),
    };
    let resp = dispatch_command(cmd, None, &state).await;
    assert!(matches!(resp, IpcResponse::Ok { .. }), "got {resp:?}");

    let row = raw_device(&path, "edo-laptop");
    assert_eq!(
        row.get("network_name").and_then(|v| v.as_str()),
        Some("desktop-1")
    );
}

#[tokio::test]
async fn device_update_clears_network_name_on_some_none() {
    let initial = r#"
schema_version = 3

[profiles.default]
display_name = "Default"

[[devices]]
id = "edo-laptop"
display_name = "edo-laptop"
ip = "192.168.1.42"
profile = "default"
network_name = "desktop-1"

[upstream]
servers = ["192.0.2.1:53"]
"#;
    let (_dir, path) = client_mutation_temp_config(initial, "update-netname-clear");
    let (state, _reload_rx) = test_state_with_config_path("tok-up", path.clone());
    let state = Arc::new(state);

    let patch = super::super::protocol::DevicePatch {
        network_name: Some(None),
        ..Default::default()
    };
    let cmd = IpcCommand::DeviceUpdate {
        name: "edo-laptop".into(),
        patch,
        token: Some("tok-up".into()),
    };
    let resp = dispatch_command(cmd, None, &state).await;
    assert!(matches!(resp, IpcResponse::Ok { .. }), "got {resp:?}");

    let row = raw_device(&path, "edo-laptop");
    assert!(row.get("network_name").is_none());
}

/// **DoD 3 of `plp-s5e`.** `DevicePatch` has no `tags` field any more.
///
/// This replaces `device_update_refuses_a_tag_change_but_not_a_tag_echo`,
/// whose two arms both built a `DevicePatch { tags: … }` and cannot
/// compile now. Arm 2's property is the one that survives — a rename must
/// not be blocked by a tag field riding along — and a pre-S5 client is
/// exactly what exercises it today, so that is what is asserted here.
///
/// **Arm 1's guarantee CHANGED SHAPE rather than exiting.** A tag *change*
/// used to be refused loudly (`TAGS_RETIRED`, `ValidatorRejected`). There
/// is no field left to change and `DevicePatch` carries no
/// `#[serde(deny_unknown_fields)]`, so serde would drop the key in silence
/// — the operator's rename landing while their tag vanished with no
/// diagnostic, which is precisely how the tag model died in the first
/// place. `retired_tags` captures the key so the daemon can WARN instead,
/// and this test pins BOTH halves: the other fields land, and the retired
/// key is observed rather than swallowed.
///
/// Strip-and-report, not refuse — the `ip_denylists` precedent in
/// `normalise_deprecated_keys`. Refusing would cost the operator a
/// legitimate rename to punish a key they did not know was dead.
#[tokio::test]
async fn a_pre_s5_payload_still_carrying_tags_applies_its_other_fields() {
    let initial = r#"
schema_version = 3

[profiles.default]
display_name = "Default"

[[devices]]
id = "edo-laptop"
display_name = "edo-laptop"
ip = "192.168.1.42"
profile = "default"
tags = ["work"]

[upstream]
servers = ["192.0.2.1:53"]
"#;
    let (_dir, path) = client_mutation_temp_config(initial, "pre-s5-tags");
    let (state, _reload_rx) = test_state_with_config_path("tok-t", path.clone());
    let state = Arc::new(state);

    // The payload a pre-S5 CLI/TUI still puts on the wire. Built from raw
    // JSON on purpose: the whole point is that `tags` is a key the struct
    // no longer has, so it cannot be expressed as a struct literal.
    let patch: super::super::protocol::DevicePatch =
        serde_json::from_str(r#"{"tags":["kids"],"new_name":"work-thinkpad","owner":"Casey"}"#)
            .expect("a pre-S5 payload carrying `tags` must still deserialize");

    // The retired key is CAPTURED, not dropped. Without this the daemon
    // cannot tell a pre-S5 client from a current one and the WARN never
    // fires. Deleting `rename = "tags"` from the field turns this red
    // while every other assertion below stays green — which is the point:
    // those assertions pass just as well when the key is silently lost.
    assert_eq!(
        patch.retired_tags.as_deref(),
        Some(&["kids".to_string()][..]),
        "a retired `tags` key must be observed so it can be reported"
    );

    let resp = dispatch_command(
        IpcCommand::DeviceUpdate {
            name: "edo-laptop".into(),
            patch,
            token: Some("tok-t".into()),
        },
        None,
        &state,
    )
    .await;
    assert!(
        matches!(resp, IpcResponse::Ok { .. }),
        "a retired key must not cost the operator the rest of the patch, got {resp:?}"
    );

    // Load-bearing: BOTH live fields landed. Mutate the `new_name` or the
    // `owner` arm of `apply_device_patch` and this goes red — which is
    // what separates it from a test that only proves serde didn't panic.
    let row = raw_device(&path, "edo-laptop");
    assert_eq!(
        row.get("display_name").and_then(|v| v.as_str()),
        Some("work-thinkpad"),
        "the rename must land"
    );
    assert_eq!(
        row.get("owner").and_then(|v| v.as_str()),
        Some("Casey"),
        "the scalar edit must land"
    );
    // Weaker by construction — no code path can write `tags` any more — but
    // it is the statement that the ignored key did not leak to disk.
    assert_eq!(
        row.get("tags")
            .and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>()),
        Some(vec!["work"]),
        "the retired key must not be written through"
    );
}

#[tokio::test]
async fn device_update_leaves_network_name_alone_when_patch_field_is_none() {
    let initial = r#"
schema_version = 3

[profiles.default]
display_name = "Default"

[[devices]]
id = "edo-laptop"
display_name = "edo-laptop"
ip = "192.168.1.42"
profile = "default"
network_name = "desktop-1"

[upstream]
servers = ["192.0.2.1:53"]
"#;
    let (_dir, path) = client_mutation_temp_config(initial, "update-netname-untouched");
    let (state, _reload_rx) = test_state_with_config_path("tok-up", path.clone());
    let state = Arc::new(state);

    // network_name omitted from the patch entirely (outer None).
    let patch = super::super::protocol::DevicePatch {
        owner: Some(Some("Casey".into())),
        ..Default::default()
    };
    let cmd = IpcCommand::DeviceUpdate {
        name: "edo-laptop".into(),
        patch,
        token: Some("tok-up".into()),
    };
    let resp = dispatch_command(cmd, None, &state).await;
    assert!(matches!(resp, IpcResponse::Ok { .. }), "got {resp:?}");

    let row = raw_device(&path, "edo-laptop");
    assert_eq!(
        row.get("network_name").and_then(|v| v.as_str()),
        Some("desktop-1"),
        "network_name must survive an unrelated patch"
    );
}

/// Clearing `network_name` while the patch also (re)asserts
/// `network_name_wildcard = true` collides with the validator's
/// wildcard-without-name mutex (`0edbd49d`) — the wildcard flag is a
/// plain bool on `DevicePatch` (no "clear" state), so a form that
/// always resends its current buffer value, as Task 10's
/// `edit_patch_from` does, ends up asking for a name-less wildcard.
/// This documents the resulting behavior at the IPC layer rather
/// than papering over it: the staged write is validator-refused and
/// the on-disk row is untouched (not partially written).
#[tokio::test]
async fn device_update_clear_name_with_wildcard_still_set_is_validator_refused() {
    let initial = r#"
schema_version = 3

[profiles.default]
display_name = "Default"

[[devices]]
id = "edo-laptop"
display_name = "edo-laptop"
ip = "192.168.1.42"
profile = "default"
network_name = "desktop-1"
network_name_wildcard = true

[upstream]
servers = ["192.0.2.1:53"]
"#;
    let (_dir, path) = client_mutation_temp_config(initial, "update-netname-wildcard-mutex");
    let (state, _reload_rx) = test_state_with_config_path("tok-up", path.clone());
    let state = Arc::new(state);

    let patch = super::super::protocol::DevicePatch {
        network_name: Some(None),
        network_name_wildcard: Some(true),
        ..Default::default()
    };
    let cmd = IpcCommand::DeviceUpdate {
        name: "edo-laptop".into(),
        patch,
        token: Some("tok-up".into()),
    };
    let resp = dispatch_command(cmd, None, &state).await;
    assert!(
        matches!(resp, IpcResponse::Error { .. }),
        "expected validator refusal, got {resp:?}"
    );

    let row = raw_device(&path, "edo-laptop");
    assert_eq!(
        row.get("network_name").and_then(|v| v.as_str()),
        Some("desktop-1"),
        "refused write must leave the file untouched"
    );
    assert_eq!(
        row.get("network_name_wildcard").and_then(|v| v.as_bool()),
        Some(true),
        "refused write must leave the file untouched"
    );
}

/// Read one `[[devices]]` row straight out of the **file**.
///
/// Not `load_devices`: a struct-level read passes on a file that lost
/// a key and got it back from a `serde` default — the exact shape of
/// the `accept_unsigned_allow` scar. §4.64 G2 made the same call for
/// `[[groups]]` (`raw_group` in `tui/mod.rs`).
fn raw_device(config_path: &std::path::Path, id: &str) -> toml::value::Table {
    let text = std::fs::read_to_string(config_path).unwrap();
    let doc: toml::Value = toml::from_str(&text).unwrap();
    doc.get("devices")
        .and_then(|v| v.as_array())
        .expect("[[devices]] array must exist in the file")
        .iter()
        .find(|item| item.get("id").and_then(|v| v.as_str()) == Some(id))
        .unwrap_or_else(|| panic!("device {id} not in the file"))
        .as_table()
        .unwrap()
        .clone()
}

/// A `MappedDeviceDto` shaped like the one `handle_get_all_devices`
/// serves for the fixture below — the value the TUI's Edit modal is
/// actually seeded from.
fn two_group_dto() -> super::super::protocol::MappedDeviceDto {
    super::super::protocol::MappedDeviceDto {
        ip: "192.168.1.42".into(),
        name: "edo-laptop".into(),
        mac: Some("AA:BB:CC:DD:EE:FF".into()),
        mac_aliases: Vec::new(),
        profile: "default".into(),
        owner: None,
        device_type: None,
        department: None,
        queries: 0,
        queries_today: 0,
        blocked: 0,
        blocked_24h: 0,
        cache_hits: 0,
        last_seen: 0,
        online: false,
        vendor: None,
        groups: vec!["phones".into(), "kids".into()],
        notes: None,
        network_name: None,
        network_name_wildcard: false,
        id: Some("edo-laptop".into()),
        hourly_queries: Vec::new(),
        unfiltered: false,
    }
}

const TWO_GROUP_CONFIG: &str = r#"
schema_version = 3

[profiles.default]
display_name = "Default"

[[groups]]
id = "phones"
display_name = "Phones"
profile = "default"
priority = 7

[[groups]]
id = "kids"
display_name = "Kids"
profile = "default"
priority = 3

[[devices]]
id = "edo-laptop"
display_name = "edo-laptop"
ip = "192.168.1.42"
mac = "AA:BB:CC:DD:EE:FF"
profile = "default"
groups = ["phones", "kids"]
tags = ["trusted"]

[upstream]
servers = ["192.0.2.1:53"]
"#;

/// **The §4.64 G4 gate.** A device in TWO groups, edited from the TUI
/// in a way that touches only the name, must come out of the file
/// still carrying BOTH memberships, in the file's own order.
///
/// Drives the real chain and nothing hand-rolled: `edit_form_from`
/// (the DTO → form seed the modal-open path uses) → typing in the
/// name field → `device_update_patch` (the builder `submit_form`
/// calls) → `dispatch_command` (the daemon's write). A rebuilt patch
/// here would test the test, not the TUI.
#[tokio::test]
async fn tui_edit_of_a_two_group_device_keeps_both_memberships_in_the_file() {
    let (_dir, path) = client_mutation_temp_config(TWO_GROUP_CONFIG, "multigroup");
    let (state, mut reload_rx) = test_state_with_config_path("tok-mg", path.clone());
    let state = Arc::new(state);

    // Open the modal on the device, change the NAME and nothing
    // else, save.
    let mut form = crate::tui::edit_form_from(&two_group_dto());
    form.name = "work-thinkpad".into();
    let patch = crate::tui::device_update_patch(&form).expect("form must parse");

    let cmd = IpcCommand::DeviceUpdate {
        name: "edo-laptop".into(),
        patch,
        token: Some("tok-mg".into()),
    };
    let resp = dispatch_command(cmd, None, &state).await;
    assert!(matches!(resp, IpcResponse::Ok { .. }), "got {resp:?}");

    let row = raw_device(&path, "edo-laptop");
    let groups: Vec<String> = row
        .get("groups")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().map(|v| v.as_str().unwrap().to_string()).collect())
        .unwrap_or_default();
    assert_eq!(
        groups,
        vec!["phones".to_string(), "kids".to_string()],
        "a rename must not reduce membership, and must not reorder it either \
         — the file said [phones, kids]"
    );
    assert_eq!(
        row.get("display_name").and_then(|v| v.as_str()),
        Some("work-thinkpad"),
        "the one field the operator DID touch must have landed"
    );
    assert!(reload_rx.try_recv().is_ok());
}

#[tokio::test]
async fn client_update_some_none_clears_nullable_field() {
    // Wire-level `Some(None)` distinguishes "explicitly clear" from
    // "leave alone" (which would be outer `None`). This is the
    // load-bearing reason DevicePatch uses Option<Option<T>>.
    let initial = r#"
schema_version = 3

[profiles.default]
display_name = "Default"

[[devices]]
id = "tablet"
display_name = "tablet"
ip = "192.168.1.50"
mac = "AA:BB:CC:DD:EE:01"
profile = "default"
owner = "Operator"

[upstream]
servers = ["192.0.2.1:53"]
"#;
    let (_dir, path) = client_mutation_temp_config(initial, "update-clear");
    let (state, _rx) = test_state_with_config_path("tok-clear", path.clone());
    let state = Arc::new(state);

    // Clear both mac and owner.
    let patch = super::super::protocol::DevicePatch {
        mac: Some(None),
        owner: Some(None),
        ..Default::default()
    };
    let cmd = IpcCommand::DeviceUpdate {
        name: "tablet".into(),
        patch,
        token: Some("tok-clear".into()),
    };
    let resp = dispatch_command(cmd, None, &state).await;
    assert!(matches!(resp, IpcResponse::Ok { .. }));

    let devices = load_devices(&path);
    let d = &devices[0];
    assert!(d.mac.is_none(), "mac must be cleared");
    assert!(d.owner.is_none(), "owner must be cleared");
}

#[tokio::test]
async fn client_update_unknown_name_returns_friendly_error() {
    let (_dir, path) = client_mutation_temp_config(
        "schema_version = 3\n\n[profiles.default]\ndisplay_name = \"Default\"\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
        "update-unknown",
    );
    let (state, _rx) = test_state_with_config_path("tok-unk", path.clone());
    let state = Arc::new(state);

    let cmd = IpcCommand::DeviceUpdate {
        name: "ghost".into(),
        patch: super::super::protocol::DevicePatch::default(),
        token: Some("tok-unk".into()),
    };
    let resp = dispatch_command(cmd, None, &state).await;
    match resp {
        IpcResponse::Error { message } => {
            assert!(
                message.contains("ghost"),
                "error must name the missing client: {message}"
            );
            assert!(
                message.contains("warden device list"),
                "error must hint at how to discover existing names: {message}"
            );
        }
        other => panic!("expected Error, got {other:?}"),
    }
}

#[tokio::test]
async fn client_update_to_duplicate_ip_caught_by_validator() {
    // §4.27-A: the v1 IPC update path stages the patch onto the
    // entity file then runs `validate_or_revert`. A patch that
    // moves a device onto another device's IP produces a
    // duplicate-IP config — the validator rejects it and the
    // touched file is rolled back to its pre-edit content.
    //
    // (Pre-§4.27-A this test exercised rename-collision: the v0
    // update path mutated `name`, so renaming to an existing name
    // tripped the v0 validator's name-uniqueness check. The v1 IPC
    // update path only changes `display_name` — not unique-
    // constrained — so the rename-collision case no longer exists.
    // Duplicate-IP is the v1-relevant validate-or-revert case in
    // its place.)
    let initial = r#"
schema_version = 3

[profiles.default]
display_name = "Default"

[[devices]]
id = "alpha"
display_name = "alpha"
ip = "192.168.1.10"
profile = "default"

[[devices]]
id = "bravo"
display_name = "bravo"
ip = "192.168.1.11"
profile = "default"

[upstream]
servers = ["192.0.2.1:53"]
"#;
    let (_dir, path) = client_mutation_temp_config(initial, "update-dup-ip");
    let (state, _rx) = test_state_with_config_path("tok-dupip", path.clone());
    let state = Arc::new(state);

    // Move "alpha" onto bravo's IP — must fail.
    let patch = super::super::protocol::DevicePatch {
        ip: Some("192.168.1.11".parse().unwrap()),
        ..Default::default()
    };
    let cmd = IpcCommand::DeviceUpdate {
        name: "alpha".into(),
        patch,
        token: Some("tok-dupip".into()),
    };
    let resp = dispatch_command(cmd, None, &state).await;
    assert!(matches!(resp, IpcResponse::Error { .. }), "got {resp:?}");

    // Validator rejected before the change stuck — alpha's IP intact.
    let devices = load_devices(&path);
    assert_eq!(devices.len(), 2);
    let alpha = devices
        .iter()
        .find(|d| d.id.as_str() == "alpha")
        .expect("alpha must still be present");
    assert_eq!(
        alpha.ip.map(|ip| ip.to_string()).as_deref(),
        Some("192.168.1.10"),
        "alpha's IP must be reverted"
    );
}

#[tokio::test]
async fn client_update_requires_admin_token() {
    let (_dir, path) = client_mutation_temp_config(
        "schema_version = 3\n\n[profiles.default]\ndisplay_name = \"Default\"\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
        "update-auth",
    );
    let (state, _rx) = test_state_with_config_path("tok-uauth", path.clone());
    let state = Arc::new(state);

    let cmd = IpcCommand::DeviceUpdate {
        name: "x".into(),
        patch: super::super::protocol::DevicePatch::default(),
        token: None,
    };
    let resp = dispatch_command(cmd, None, &state).await;
    assert!(matches!(resp, IpcResponse::Error { .. }));
}

// ── s23-ipc-client-mutations: DeviceRemove handler tests ──────

#[tokio::test]
async fn client_remove_happy_path_drops_client_and_reloads() {
    let initial = r#"
schema_version = 3

[profiles.default]
display_name = "Default"

[[devices]]
id = "edo-laptop"
display_name = "edo-laptop"
ip = "192.168.1.42"
profile = "default"

[[devices]]
id = "tablet"
display_name = "tablet"
ip = "192.168.1.50"
profile = "default"

[upstream]
servers = ["192.0.2.1:53"]
"#;
    let (_dir, path) = client_mutation_temp_config(initial, "remove-happy");
    let (state, mut reload_rx) = test_state_with_config_path("tok-rm", path.clone());
    let state = Arc::new(state);

    let cmd = IpcCommand::DeviceRemove {
        name: "edo-laptop".into(),
        token: Some("tok-rm".into()),
    };
    let resp = dispatch_command(cmd, None, &state).await;
    match &resp {
        IpcResponse::Ok { message } => {
            assert!(message.contains("edo-laptop"));
        }
        other => panic!("expected Ok, got {other:?}"),
    }

    let devices = load_devices(&path);
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0].id.as_str(), "tablet");
    assert!(reload_rx.try_recv().is_ok());
}

#[tokio::test]
async fn client_remove_unknown_name_returns_friendly_error() {
    let (_dir, path) = client_mutation_temp_config(
        "schema_version = 3\n\n[profiles.default]\ndisplay_name = \"Default\"\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
        "remove-unknown",
    );
    let (state, _rx) = test_state_with_config_path("tok-rmx", path.clone());
    let state = Arc::new(state);

    let cmd = IpcCommand::DeviceRemove {
        name: "ghost".into(),
        token: Some("tok-rmx".into()),
    };
    let resp = dispatch_command(cmd, None, &state).await;
    match resp {
        IpcResponse::Error { message } => {
            assert!(
                message.contains("ghost"),
                "error must name missing client: {message}"
            );
            assert!(
                message.contains("warden device list"),
                "error must hint at how to discover names: {message}"
            );
        }
        other => panic!("expected Error, got {other:?}"),
    }
}

#[tokio::test]
async fn client_remove_dangling_schedule_blocked_by_validator() {
    // Removing a device referenced by a [[schedules]] entry must
    // NOT proceed — the v1 validator (run via `validate_or_revert`
    // after the staged removal) catches the dangling `target_id`
    // and the touched file is rolled back. A sibling "laptop"
    // device is kept so the removal is an ordinary 2→1 case.
    let initial = r#"
schema_version = 3

[profiles.default]
display_name = "Default"

[profiles.kids]
display_name = "Kids"

[[devices]]
id = "laptop"
display_name = "laptop"
ip = "192.168.1.42"
profile = "default"

[[devices]]
id = "tablet"
display_name = "tablet"
ip = "192.168.1.50"
profile = "default"

[[schedules]]
id = "tablet-quiet"
display_name = "Tablet quiet hours"
target_type = "device"
target_id = "tablet"
profile = "kids"
days = ["all"]
hours = "21:00-07:00"

[upstream]
servers = ["192.0.2.1:53"]
"#;
    let (_dir, path) = client_mutation_temp_config(initial, "remove-dangle");
    let (state, _rx) = test_state_with_config_path("tok-dangle", path.clone());
    let state = Arc::new(state);

    let cmd = IpcCommand::DeviceRemove {
        name: "tablet".into(),
        token: Some("tok-dangle".into()),
    };
    // §4.32 sets state.daemon_uid to the test process's euid by
    // default, but `dispatch_command` is called inline (not via
    // `handle_connection`) so the peer-uid gate is not exercised
    // here.
    let resp = dispatch_command(cmd, None, &state).await;
    // §4.33: the wire payload now carries the frozen
    // ValidatorRejected message; the validator's full detail
    // (which named the dangling schedule and hinted `warden
    // schedule remove`) moved to the daemon log via
    // `tracing::warn!(target: "ipc.error", ...)`. The proof that
    // the validator correctly caught the dangling reference is
    // (a) the Error response and (b) the file being unchanged on
    // disk.
    match resp {
        IpcResponse::Error { message } => {
            assert_eq!(
                message,
                crate::ipc::errors::IPC_ERROR_VALIDATOR_REJECTED,
                "expected frozen ValidatorRejected message, got: {message}"
            );
        }
        other => panic!("expected Error, got {other:?}"),
    }

    // File must NOT have been mutated — validator reverted the removal.
    let devices = load_devices(&path);
    assert_eq!(devices.len(), 2, "tablet must still be present");
}

#[tokio::test]
async fn client_remove_requires_admin_token() {
    let (_dir, path) = client_mutation_temp_config(
        "schema_version = 3\n\n[profiles.default]\ndisplay_name = \"Default\"\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
        "remove-auth",
    );
    let (state, _rx) = test_state_with_config_path("tok-rmauth", path.clone());
    let state = Arc::new(state);

    let cmd = IpcCommand::DeviceRemove {
        name: "x".into(),
        token: None,
    };
    let resp = dispatch_command(cmd, None, &state).await;
    assert!(matches!(resp, IpcResponse::Error { .. }));
}

// ── s23-ipc-client-mutations: DevicePromote handler tests ──────

/// Build a state wired to a config file AND a real ProfileResolver
/// so DevicePromote can hit `snapshot_for_ipc` for the ARP lookup.
/// The resolver's ARP snapshot is then overridden via the
/// test-only setter so tests don't depend on the host's
/// `/proc/net/arp`.
fn test_state_with_resolver(
    token_plaintext: &str,
    config_path: PathBuf,
    arp_entries: &[(std::net::IpAddr, &str)],
) -> (DaemonState, tokio::sync::mpsc::Receiver<Option<u32>>) {
    use crate::auth::token::hash_token;
    use crate::config::loader;
    use crate::dns::cache::DnsCache;
    use crate::profiles::ProfileResolver;

    let loaded = loader::load_config(&config_path, time::OffsetDateTime::now_utc())
        .unwrap_or_else(|errs| panic!("test fixture config must load: {errs:?}"));
    let bit_map = crate::lists::source_key::SourceBitMap::default();
    let resolver = Arc::new(ProfileResolver::build(
        &loaded.config,
        &bit_map,
        &loaded.custom_lists,
    ));
    resolver.test_only_set_arp_snapshot(arp_entries);

    let cache_config = crate::config::settings::CacheConfig::default();
    let (reload_tx, reload_rx) = tokio::sync::mpsc::channel::<Option<u32>>(1);
    let state = DaemonState {
        filter: Arc::new(FilterEngine::new()),
        cache: DnsCache::new(&cache_config),
        profiles: Some(resolver),
        stats: None,
        listen_addr: "127.0.0.1:15353".into(),
        upstream_mode: "plain".into(),
        upstream_count: 2,
        upstream_servers: Vec::new(),
        list_count: 0,
        started_at: Instant::now(),
        shutdown_tx: None,
        reload_tx: Some(reload_tx),
        api_token_hash: Arc::new(arc_swap::ArcSwap::from_pointee(Some(hash_token(
            token_plaintext,
        )))),
        config_path: Some(config_path),
        config_write_lock: Arc::new(tokio::sync::Mutex::new(())),
        list_statuses: None,
        list_state: None,
        local_records_hits: None,
        log_ring: None,
        notification_tx: None,
        reload_coalescer: None,
        oui_table: None,
        list_labels: Arc::new(vec![None; 64]),
        list_cmd_tx: Arc::new(arc_swap::ArcSwap::from_pointee(None)),
        daemon_uid: current_euid(),
        resource_budget_store: crate::resource_budget::types::new_store(),
        #[cfg(feature = "cluster")]
        cluster_observe: None,
    };
    (state, reload_rx)
}

#[tokio::test]
async fn client_promote_happy_path_pins_arp_mac() {
    // Sprint S44 (this commit) retires the Sprint 35 CS1 stub: the
    // IPC mutation handlers are now v1-native via the entity API
    // (resolve_target_file + upsert_id_keyed + validate_or_revert).
    // DevicePromote against a v1 master succeeds, the new device
    // is appended (master has no devices.d/ in this fixture so the
    // entry lands in the master itself), and the reload channel
    // fires. The previous test that asserted Sprint-35-style
    // refusal is inverted here.
    let initial = r#"
schema_version = 3

[profiles.default]
display_name = "Default"

[upstream]
servers = ["192.0.2.1:53"]
"#;
    let (_dir, path) = client_mutation_temp_config(initial, "promote-happy");
    let unmapped: std::net::IpAddr = "10.0.0.99".parse().unwrap();
    let (state, mut reload_rx) =
        test_state_with_resolver("tok-prom", path.clone(), &[(unmapped, "AA:BB:CC:DD:EE:99")]);
    let state = Arc::new(state);

    let cmd = IpcCommand::DevicePromote {
        ip: unmapped,
        name: "phone".into(),
        profile: "default".into(),
        owner: Some("Casey".into()),
        device_type: Some("iPhone".into()),
        department: None,
        token: Some("tok-prom".into()),
    };

    let resp = dispatch_command(cmd, None, &state).await;
    match &resp {
        IpcResponse::Ok { message } => {
            assert!(
                message.contains("phone"),
                "Ok message must name the promoted device: {message}"
            );
        }
        other => panic!("expected Ok, got {other:?}"),
    }

    // Verify the master was rewritten with the new [[devices]]
    // block. The entry lands in the master because no devices.d/
    // directory was created for this fixture.
    let now = time::OffsetDateTime::now_utc();
    let loaded = crate::config::loader::load_config(&path, now)
        .expect("master must reload as v1 after promote");
    let devices = &loaded.config.devices;
    assert_eq!(devices.len(), 1, "exactly one device after promote");
    assert_eq!(devices[0].id.as_str(), "phone");
    assert_eq!(devices[0].display_name, "phone");
    assert_eq!(devices[0].ip, Some(unmapped));
    assert_eq!(
        devices[0].mac.as_deref(),
        Some("AA:BB:CC:DD:EE:99"),
        "MAC pinned from ARP snapshot"
    );

    assert!(
        reload_rx.try_recv().is_ok(),
        "successful mutation must fire the reload signal"
    );
}

#[tokio::test]
async fn client_promote_rejects_when_arp_has_no_entry() {
    // The ARP table doesn't have the requested IP. Promotion
    // must be refused with the "wait for ARP" hint, NOT silently
    // succeed with mac=None — that would break the MAC-pin
    // requirement and reintroduce the IP-only-identification
    // foot-gun documented in CLAUDE.md.
    let (_dir, path) = client_mutation_temp_config(
        "schema_version = 3\n\n[profiles.default]\ndisplay_name = \"Default\"\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
        "promote-no-arp",
    );
    let target_ip: std::net::IpAddr = "10.0.0.50".parse().unwrap();
    let (state, _rx) =
        test_state_with_resolver("tok-noarp", path.clone(), &[/* arp empty for 10.0.0.50 */]);
    let state = Arc::new(state);

    let cmd = IpcCommand::DevicePromote {
        ip: target_ip,
        name: "tablet".into(),
        profile: "default".into(),
        owner: None,
        device_type: None,
        department: None,
        token: Some("tok-noarp".into()),
    };

    let resp = dispatch_command(cmd, None, &state).await;
    match resp {
        IpcResponse::Error { message } => {
            assert!(
                message.contains("MAC") || message.contains("ARP"),
                "error must explain why: {message}"
            );
            assert!(
                message.contains("10.0.0.50"),
                "error must name the IP: {message}"
            );
            assert!(
                message.contains("ping") || message.contains("retry"),
                "error must give a recovery hint: {message}"
            );
        }
        other => panic!("expected Error, got {other:?}"),
    }

    // No client must have been added.
    assert!(load_devices(&path).is_empty());
}

#[tokio::test]
async fn client_promote_validator_runs_via_delegated_add_path() {
    // DevicePromote delegates to handle_device_add, so all the
    // validator-level guarantees from DeviceAdd apply here too:
    // duplicate name, duplicate IP, unknown profile, etc. This
    // test pins the unknown-profile case to confirm delegation
    // didn't bypass validation.
    let (_dir, path) = client_mutation_temp_config(
        "schema_version = 3\n\n[profiles.default]\ndisplay_name = \"Default\"\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
        "promote-validator",
    );
    let unmapped: std::net::IpAddr = "10.0.0.42".parse().unwrap();
    let (state, _rx) = test_state_with_resolver(
        "tok-promval",
        path.clone(),
        &[(unmapped, "AA:BB:CC:DD:EE:42")],
    );
    let state = Arc::new(state);

    let cmd = IpcCommand::DevicePromote {
        ip: unmapped,
        name: "x".into(),
        profile: "ghost".into(), // not configured
        owner: None,
        device_type: None,
        department: None,
        token: Some("tok-promval".into()),
    };

    let resp = dispatch_command(cmd, None, &state).await;
    assert!(matches!(resp, IpcResponse::Error { .. }));
    assert!(load_devices(&path).is_empty());
}

#[tokio::test]
async fn client_promote_requires_admin_token() {
    let (_dir, path) = client_mutation_temp_config(
        "schema_version = 3\n\n[profiles.default]\ndisplay_name = \"Default\"\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
        "promote-auth",
    );
    let target_ip: std::net::IpAddr = "10.0.0.42".parse().unwrap();
    let (state, _rx) =
        test_state_with_resolver("tok-promauth", path.clone(), &[(target_ip, "MAC")]);
    let state = Arc::new(state);

    let cmd = IpcCommand::DevicePromote {
        ip: target_ip,
        name: "x".into(),
        profile: "default".into(),
        owner: None,
        device_type: None,
        department: None,
        token: None, // missing
    };
    let resp = dispatch_command(cmd, None, &state).await;
    assert!(matches!(resp, IpcResponse::Error { .. }));
}

// ── Sprint 38 QLP5: TrackingConfigUpdate ────────────────

fn tracking_v1_master() -> String {
    r#"
schema_version = 3

[server]
listen = "127.0.0.1:15353"
default_profile = "default"
default_blocked_ttl_secs = 60

[profiles.default]
display_name = "Default"

[tracking]
enabled = true
query_log_enabled = true
retention_days = 7
log_mode = "all"

[upstream]
servers = ["192.0.2.1:53"]
"#
    .to_string()
}

#[test]
fn tracking_patch_merges_partial_fields() {
    // Pure patch-apply semantics — no file I/O. Pin that leaving a
    // field None doesn't disturb the baseline and that each field
    // assigns independently.
    use crate::config::settings::{LogMode, TrackingConfig};
    use crate::ipc::protocol::TrackingPatch;

    let baseline = TrackingConfig::default();
    let patch = TrackingPatch {
        query_log_enabled: Some(false),
        retention_days: None,
        log_mode: None,
    };
    let mut merged = baseline.clone();
    if let Some(f) = patch.query_log_enabled {
        merged.query_log_enabled = f;
    }
    if let Some(rd) = patch.retention_days {
        merged.retention_days = rd;
    }
    if let Some(mode) = patch.log_mode.clone() {
        merged.log_mode = mode;
    }
    assert!(!merged.query_log_enabled, "flag flipped");
    assert_eq!(merged.retention_days, baseline.retention_days);
    assert!(matches!(merged.log_mode, LogMode::All));
}

#[tokio::test]
async fn handle_tracking_config_update_is_admin_tier() {
    // Belt-and-suspenders for the tier() mapping — QLP5 put the
    // new variant in the Admin arm alongside the other PII-
    // exposing / config-mutating commands.
    use crate::ipc::protocol::{CommandTier, IpcCommand, TrackingPatch};

    let cmd = IpcCommand::TrackingConfigUpdate {
        patch: TrackingPatch::default(),
        token: Some("t".into()),
    };
    assert_eq!(cmd.tier(), CommandTier::Admin);
}

#[tokio::test]
async fn handle_tracking_config_update_happy_path() {
    use crate::ipc::protocol::{IpcCommand, TrackingPatch};

    let (_dir, path) = client_mutation_temp_config(&tracking_v1_master(), "trk-happy");
    let (state, _rx) = test_state_with_config_path("tok-trk", path.clone());
    let state = Arc::new(state);

    let cmd = IpcCommand::TrackingConfigUpdate {
        patch: TrackingPatch {
            query_log_enabled: Some(false),
            retention_days: Some(14),
            log_mode: None,
        },
        token: Some("tok-trk".into()),
    };
    let resp = dispatch_command(cmd, None, &state).await;
    match resp {
        IpcResponse::Ok { .. } => {}
        other => panic!("expected Ok, got {other:?}"),
    }

    // Re-read and assert the mutation landed.
    let reloaded = crate::config::loader::load_config(&path, time::OffsetDateTime::now_utc())
        .expect("reload after patch");
    assert!(!reloaded.config.tracking.query_log_enabled);
    assert_eq!(reloaded.config.tracking.retention_days, 14);
}

#[tokio::test]
async fn handle_tracking_config_update_refuses_invalid_retention() {
    use crate::ipc::protocol::{IpcCommand, TrackingPatch};

    let (_dir, path) = client_mutation_temp_config(&tracking_v1_master(), "trk-bad");
    let (state, _rx) = test_state_with_config_path("tok-trk2", path.clone());
    let state = Arc::new(state);

    let cmd = IpcCommand::TrackingConfigUpdate {
        patch: TrackingPatch {
            query_log_enabled: None,
            retention_days: Some(500),
            log_mode: None,
        },
        token: Some("tok-trk2".into()),
    };
    let resp = dispatch_command(cmd, None, &state).await;
    match resp {
        IpcResponse::Error { message } => {
            assert!(
                message.contains("retention_days must be between 1 and 365"),
                "frozen operator string must surface verbatim: {message}"
            );
        }
        other => panic!("expected Error, got {other:?}"),
    }

    // Master unchanged on disk.
    let reloaded = crate::config::loader::load_config(&path, time::OffsetDateTime::now_utc())
        .expect("reload after reject");
    assert_eq!(reloaded.config.tracking.retention_days, 7);
}

#[tokio::test]
async fn handle_tracking_config_update_without_token_is_rejected() {
    // Auth gate sanity: Admin tier → token required. Covered by
    // the shared `auth_error_for` path, but pinned explicitly here
    // so a future refactor that moves TrackingConfigUpdate out of
    // Admin fails loudly.
    use crate::ipc::protocol::{IpcCommand, TrackingPatch};

    let (_dir, path) = client_mutation_temp_config(&tracking_v1_master(), "trk-noauth");
    let (state, _rx) = test_state_with_config_path("tok-trk3", path.clone());
    let state = Arc::new(state);

    let cmd = IpcCommand::TrackingConfigUpdate {
        patch: TrackingPatch {
            query_log_enabled: Some(false),
            retention_days: None,
            log_mode: None,
        },
        token: None,
    };
    let resp = dispatch_command(cmd, None, &state).await;
    assert!(matches!(resp, IpcResponse::Error { .. }));
}

// ── BlocklistStats (s43-t1) ─────────────────────────────────

/// Build a state pre-seeded with a `ListStatusRegistry` covering
/// two sources, both freshly refreshed. Used by the
/// `IpcCommand::BlocklistStats` test cases below.
fn test_state_with_list_statuses() -> DaemonState {
    use crate::dns::cache::DnsCache;
    use crate::lists::status::{ListStatus, ListStatusRegistry, ParsedCounts};
    use time::OffsetDateTime;

    let cache_config = crate::config::settings::CacheConfig::default();
    let registry = Arc::new(ListStatusRegistry::new(&[
        "privacy/ads".into(),
        "security/malicious".into(),
    ]));
    let now = OffsetDateTime::now_utc();
    registry.update_for_url(
        "privacy/ads",
        ListStatus::from_refresh(
            42,
            ParsedCounts {
                parsed_ok: 42,
                unique_domains: 42,
                parsed_skipped: 1,
                parsed_skipped_samples: vec!["bad-line".into()],
                parsed_truncated: 0,
            },
            None,
            now,
        ),
    );
    registry.update_for_url(
        "security/malicious",
        ListStatus::from_refresh(7, ParsedCounts::default(), None, now),
    );

    DaemonState {
        filter: Arc::new(FilterEngine::new()),
        cache: DnsCache::new(&cache_config),
        profiles: None,
        stats: None,
        listen_addr: "127.0.0.1:15353".into(),
        upstream_mode: "plain".into(),
        upstream_count: 2,
        upstream_servers: Vec::new(),
        list_count: 2,
        started_at: Instant::now(),
        shutdown_tx: None,
        reload_tx: None,
        api_token_hash: Arc::new(arc_swap::ArcSwap::from_pointee(None)),
        config_path: None,
        config_write_lock: Arc::new(tokio::sync::Mutex::new(())),
        list_statuses: Some(registry),
        list_state: None,
        local_records_hits: None,
        log_ring: None,
        notification_tx: None,
        reload_coalescer: None,
        oui_table: None,
        list_labels: Arc::new(vec![None; 64]),
        list_cmd_tx: Arc::new(arc_swap::ArcSwap::from_pointee(None)),
        daemon_uid: current_euid(),
        resource_budget_store: crate::resource_budget::types::new_store(),
        #[cfg(feature = "cluster")]
        cluster_observe: None,
    }
}

#[tokio::test]
async fn blocklist_stats_no_filter_returns_every_source() {
    let state = Arc::new(test_state_with_list_statuses());
    let resp = dispatch_command(IpcCommand::BlocklistStats { source_id: None }, None, &state).await;
    match resp {
        IpcResponse::BlocklistStatsList { stats } => {
            assert_eq!(stats.len(), 2);
            let keys: std::collections::HashSet<_> =
                stats.iter().map(|s| s.source.clone()).collect();
            assert!(keys.contains("privacy/ads"));
            assert!(keys.contains("security/malicious"));
            let ads = stats.iter().find(|s| s.source == "privacy/ads").unwrap();
            assert_eq!(ads.entries, 42);
            assert_eq!(ads.parsed_ok, 42);
            assert_eq!(ads.parsed_skipped, 1);
            assert_eq!(ads.last_outcome, "ok");
        }
        other => panic!("expected BlocklistStatsList, got {other:?}"),
    }
}

/// End to end over the real dispatch: the freeze has to reach the WIRE,
/// not merely exist on the registry. Every daemon-side surface that names
/// it — `warden status`, its `--json`, the TUI — reads this one response,
/// so a `handle_status` that forgets the field silences all of them at
/// once while the registry still holds the truth.
#[tokio::test]
async fn status_carries_the_corpus_freeze_over_ipc() {
    let state = Arc::new(test_state_with_list_statuses());
    let reg = state.list_statuses.clone().expect("registry wired");
    let t0 = time::macros::datetime!(2026-08-04 03:00:00 UTC);
    reg.note_refused_cycle(t0);
    reg.note_refused_cycle(t0 + time::Duration::hours(24));

    let resp = dispatch_command(IpcCommand::Status, None, &state).await;
    let carried = match &resp {
        IpcResponse::Status {
            lists_corpus_freeze,
            ..
        } => lists_corpus_freeze.clone(),
        other => panic!("expected Status, got {other:?}"),
    };
    let f = carried.expect("the freeze must reach the response");
    assert_eq!(
        f.since,
        Some(t0),
        "the streak must date from its first refusal"
    );
    assert_eq!(f.consecutive, 2);

    // The encode too: this response is what `--json` and `/api/status`
    // serialise, so a field that never makes it into the payload is the
    // same defect as never publishing it.
    let json = serde_json::to_string(&resp).expect("serialise Status");
    assert!(
        json.contains("\"lists_corpus_freeze\""),
        "the field is missing from the wire payload: {json}"
    );
    assert!(
        json.contains("2026-08-04T03:00:00Z"),
        "the freeze start must go over the wire as RFC3339: {json}"
    );

    // The recovery arm over the same path: an install clears it, so a
    // consumer polling `Status` sees the freeze end rather than having to
    // infer it from a field that stopped changing.
    reg.note_installed_cycle();
    match dispatch_command(IpcCommand::Status, None, &state).await {
        IpcResponse::Status {
            lists_corpus_freeze,
            ..
        } => assert!(
            lists_corpus_freeze.is_none(),
            "an install must clear the freeze on the wire too"
        ),
        other => panic!("expected Status, got {other:?}"),
    }
}

#[tokio::test]
async fn blocklist_stats_exact_match_returns_one_entry() {
    let state = Arc::new(test_state_with_list_statuses());
    let resp = dispatch_command(
        IpcCommand::BlocklistStats {
            source_id: Some("privacy/ads".into()),
        },
        None,
        &state,
    )
    .await;
    match resp {
        IpcResponse::BlocklistStatsList { stats } => {
            assert_eq!(stats.len(), 1);
            assert_eq!(stats[0].source, "privacy/ads");
            assert_eq!(stats[0].entries, 42);
        }
        other => panic!("expected BlocklistStatsList, got {other:?}"),
    }
}

#[tokio::test]
async fn blocklist_stats_substring_fallback_resolves() {
    // Operator types `"ads"` (no exact / no slug match) — the
    // case-insensitive substring fallback hits `privacy/ads`.
    let state = Arc::new(test_state_with_list_statuses());
    let resp = dispatch_command(
        IpcCommand::BlocklistStats {
            source_id: Some("ads".into()),
        },
        None,
        &state,
    )
    .await;
    match resp {
        IpcResponse::BlocklistStatsList { stats } => {
            assert_eq!(stats.len(), 1);
            assert_eq!(stats[0].source, "privacy/ads");
        }
        other => panic!("expected BlocklistStatsList, got {other:?}"),
    }
}

#[tokio::test]
async fn blocklist_stats_unknown_source_returns_empty_list() {
    let state = Arc::new(test_state_with_list_statuses());
    let resp = dispatch_command(
        IpcCommand::BlocklistStats {
            source_id: Some("nonexistent".into()),
        },
        None,
        &state,
    )
    .await;
    match resp {
        IpcResponse::BlocklistStatsList { stats } => {
            assert!(stats.is_empty());
        }
        other => panic!("expected BlocklistStatsList, got {other:?}"),
    }
}

#[tokio::test]
async fn blocklist_stats_no_registry_returns_empty_list() {
    // Daemon started without [lists].sources: list_statuses = None.
    // Command must NOT error — the TUI polls this on startup before
    // it knows whether the daemon was configured with any sources.
    let state = Arc::new(test_state());
    let resp = dispatch_command(IpcCommand::BlocklistStats { source_id: None }, None, &state).await;
    match resp {
        IpcResponse::BlocklistStatsList { stats } => assert!(stats.is_empty()),
        other => panic!("expected empty BlocklistStatsList, got {other:?}"),
    }
}

#[tokio::test]
async fn blocklist_stats_is_read_only_tier_no_token_needed() {
    // Tier gate: ReadOnly. The command must succeed without any
    // token — the test_state_with_list_statuses fixture has
    // `api_token_hash = None`, which would reject any tier above
    // ReadOnly. If this test fails the dispatch returned an Error
    // (NO_TOKEN_CONFIGURED_MSG).
    let state = Arc::new(test_state_with_list_statuses());
    let resp = dispatch_command(IpcCommand::BlocklistStats { source_id: None }, None, &state).await;
    assert!(
        matches!(resp, IpcResponse::BlocklistStatsList { .. }),
        "expected stats list, got {resp:?}"
    );
    // Tier check at the type level — pinned in case a future
    // refactor accidentally moves the variant out of ReadOnly.
    let cmd = IpcCommand::BlocklistStats { source_id: None };
    assert_eq!(cmd.tier(), CommandTier::ReadOnly);
    assert_eq!(cmd.token(), None);
}

// ── DaemonLogs (`logs-tab`) ──────────────────────────────────────

/// A `DaemonState` wired to a ring holding three events of three
/// different levels, so the handler exercises the filter walk and the
/// DTO mapping rather than just the empty path.
fn test_state_with_log_ring() -> DaemonState {
    use crate::tracking::log_ring::{LogEntry, LogLevel, LogRing};

    let ring = Arc::new(LogRing::new(64));
    for (level, message) in [
        (LogLevel::Error, "upstream timeout"),
        (LogLevel::Warn, "refresh failed"),
        (LogLevel::Info, "listening on 0.0.0.0:53"),
    ] {
        ring.push(LogEntry {
            ts: time::OffsetDateTime::UNIX_EPOCH,
            level,
            target: "purge_warden::test",
            message: message.to_string(),
        });
    }
    let mut state = test_state_with_token("ps_correctvalue");
    state.log_ring = Some(ring);
    state
}

#[tokio::test]
async fn daemon_logs_is_admin_gated() {
    // Log text carries client IPs and query names. An unauthenticated
    // reader of this verb would be an unauthenticated reader of a
    // slice of the query stream.
    let cmd = IpcCommand::DaemonLogs {
        limit: 10,
        level: None,
        contains: None,
        token: None,
    };
    assert_eq!(cmd.tier(), CommandTier::Admin);

    let state = Arc::new(test_state_with_log_ring());
    let resp = dispatch_command(cmd, None, &state).await;
    match resp {
        IpcResponse::Error { message } => {
            assert!(
                message.to_lowercase().contains("token"),
                "expected a token refusal, got: {message}"
            );
        }
        other => panic!("an untokened DaemonLogs must be refused, got {other:?}"),
    }
}

#[tokio::test]
async fn daemon_logs_returns_newest_first_with_the_ring_bound() {
    let state = Arc::new(test_state_with_log_ring());
    let resp = dispatch_command(
        IpcCommand::DaemonLogs {
            limit: 10,
            level: None,
            contains: None,
            token: Some("ps_correctvalue".into()),
        },
        None,
        &state,
    )
    .await;
    match resp {
        IpcResponse::DaemonLogs {
            entries,
            dropped,
            capacity,
        } => {
            assert_eq!(entries.len(), 3);
            assert_eq!(entries[0].message, "listening on 0.0.0.0:53");
            assert_eq!(entries[2].message, "upstream timeout");
            // Formatted daemon-side in the QueryLogDto shape.
            assert_eq!(entries[0].timestamp, "1970-01-01T00:00:00Z");
            assert_eq!(entries[0].target, "purge_warden::test");
            assert_eq!(dropped, 0);
            assert_eq!(capacity, 64, "the bound must travel with the page");
        }
        other => panic!("expected DaemonLogs, got {other:?}"),
    }
}

#[tokio::test]
async fn daemon_logs_filters_are_applied_by_the_daemon() {
    // The point of sending the filters down: the walk applies them,
    // so the TUI never has to search a page it was already handed.
    let state = Arc::new(test_state_with_log_ring());
    let resp = dispatch_command(
        IpcCommand::DaemonLogs {
            limit: 10,
            level: Some(crate::tracking::log_ring::LogLevel::Error),
            contains: None,
            token: Some("ps_correctvalue".into()),
        },
        None,
        &state,
    )
    .await;
    match resp {
        IpcResponse::DaemonLogs { entries, .. } => {
            assert_eq!(entries.len(), 1);
            assert_eq!(entries[0].message, "upstream timeout");
        }
        other => panic!("expected DaemonLogs, got {other:?}"),
    }

    let resp = dispatch_command(
        IpcCommand::DaemonLogs {
            limit: 10,
            level: None,
            contains: Some("FAILED".into()),
            token: Some("ps_correctvalue".into()),
        },
        None,
        &state,
    )
    .await;
    match resp {
        IpcResponse::DaemonLogs { entries, .. } => {
            assert_eq!(entries.len(), 1, "case-insensitive substring");
            assert_eq!(entries[0].message, "refresh failed");
        }
        other => panic!("expected DaemonLogs, got {other:?}"),
    }
}

#[tokio::test]
async fn daemon_logs_without_a_ring_answers_empty_not_error() {
    // Same degradation contract as LocalRecordsHits: a test-seam
    // state must not fail the whole tab poll.
    let mut state = test_state_with_token("ps_correctvalue");
    state.log_ring = None;
    let state = Arc::new(state);
    let resp = dispatch_command(
        IpcCommand::DaemonLogs {
            limit: 10,
            level: None,
            contains: None,
            token: Some("ps_correctvalue".into()),
        },
        None,
        &state,
    )
    .await;
    match resp {
        IpcResponse::DaemonLogs {
            entries, capacity, ..
        } => {
            assert!(entries.is_empty());
            assert_eq!(capacity, 0);
        }
        other => panic!("expected an empty DaemonLogs, got {other:?}"),
    }
}

// ── LocalRecordsHits (s44-hits-ipc-verb) ─────────────────────────

/// Build a DaemonState wired with a populated `LocalRecordsHits`
/// fixture so the IPC handler exercises the full snapshot →
/// `LocalRecordsHitEntry` mapping path.
fn test_state_with_local_records_hits() -> DaemonState {
    use crate::dns::cache::DnsCache;
    use crate::tracking::{LocalRecordsHits, LocalRecordsScopeKey};
    use compact_str::CompactString;

    let hits = Arc::new(LocalRecordsHits::new());
    // 2 global hits on nas.home, 1 global on intranet.home, 5
    // profile-scoped hits on example.test under `kids`.
    for _ in 0..2 {
        hits.record_hit(LocalRecordsScopeKey::Global, "nas.home");
    }
    hits.record_hit(LocalRecordsScopeKey::Global, "intranet.home");
    for _ in 0..5 {
        hits.record_hit(
            LocalRecordsScopeKey::Profile(CompactString::new("kids")),
            "example.test",
        );
    }

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
        api_token_hash: Arc::new(arc_swap::ArcSwap::from_pointee(None)),
        config_path: None,
        config_write_lock: Arc::new(tokio::sync::Mutex::new(())),
        list_statuses: None,
        list_state: None,
        local_records_hits: Some(hits),
        log_ring: None,
        notification_tx: None,
        reload_coalescer: None,
        oui_table: None,
        list_labels: Arc::new(vec![None; 64]),
        list_cmd_tx: Arc::new(arc_swap::ArcSwap::from_pointee(None)),
        daemon_uid: current_euid(),
        resource_budget_store: crate::resource_budget::types::new_store(),
        #[cfg(feature = "cluster")]
        cluster_observe: None,
    }
}

#[tokio::test]
async fn local_records_hits_returns_empty_list_when_state_has_none() {
    // DaemonState without a wired counter (test seam) must respond
    // with an empty list — never an Error — so the TUI degrades to
    // "no hits known yet" instead of failing the whole tab poll.
    let state = Arc::new(test_state());
    assert!(state.local_records_hits.is_none());
    let resp = dispatch_command(IpcCommand::LocalRecordsHits, None, &state).await;
    match resp {
        IpcResponse::LocalRecordsHitsList { entries } => {
            assert!(entries.is_empty(), "expected empty list, got {entries:?}");
        }
        other => panic!("expected LocalRecordsHitsList, got {other:?}"),
    }
}

#[tokio::test]
async fn local_records_hits_returns_global_and_profile_entries() {
    // Counter has 3 keys (2 global + 1 profile). The handler must
    // surface every key with its count + the operator-facing scope
    // tag (`global` / `profile:<id>`).
    let state = Arc::new(test_state_with_local_records_hits());
    let resp = dispatch_command(IpcCommand::LocalRecordsHits, None, &state).await;
    let entries = match resp {
        IpcResponse::LocalRecordsHitsList { entries } => entries,
        other => panic!("expected LocalRecordsHitsList, got {other:?}"),
    };
    assert_eq!(entries.len(), 3, "expected 3 distinct keys");

    let by_key: std::collections::HashMap<(String, String), u64> = entries
        .iter()
        .map(|e| ((e.scope.clone(), e.domain.clone()), e.count))
        .collect();
    assert_eq!(by_key.get(&("global".into(), "nas.home".into())), Some(&2));
    assert_eq!(
        by_key.get(&("global".into(), "intranet.home".into())),
        Some(&1)
    );
    assert_eq!(
        by_key.get(&("profile:kids".into(), "example.test".into())),
        Some(&5),
        "profile-scoped key must serialise as `profile:<id>`",
    );
}

#[tokio::test]
async fn local_records_hits_is_read_only_tier_no_token_needed() {
    // Same gating contract as BlocklistStats — counts + names the
    // operator already configured aren't PII, the TUI polls on a
    // slow tick, and a token gate would defeat the read loop.
    let state = Arc::new(test_state_with_local_records_hits());
    let resp = dispatch_command(IpcCommand::LocalRecordsHits, None, &state).await;
    assert!(
        matches!(resp, IpcResponse::LocalRecordsHitsList { .. }),
        "expected LocalRecordsHitsList, got {resp:?}"
    );
    assert_eq!(IpcCommand::LocalRecordsHits.tier(), CommandTier::ReadOnly);
    assert_eq!(IpcCommand::LocalRecordsHits.token(), None);
}

#[test]
fn local_records_hits_with_token_is_identity() {
    // ReadOnly variants are returned unchanged by `with_token` —
    // the CLI wrapper still calls it on every send. A future
    // refactor that accidentally drops the variant from the
    // `other @ (...)` arm would silently lose the command on the
    // wire; this pin catches that.
    let cmd = IpcCommand::LocalRecordsHits;
    let with = cmd.clone().with_token(Some("ignored".into()));
    assert_eq!(with, cmd);
}

// ── ProfileUpdate: the custom-list mount delta ────────────────────

/// A config declaring two `[[custom_lists]]`, with the pack files on
/// disk beside it.
///
/// The files are not optional scaffolding: a declared pack that is not
/// readable fails the whole load, so a fixture without them would make
/// every assertion below fail for a reason that has nothing to do with
/// mounting.
fn mount_fixture(suffix: &str, mounted: &str) -> (tempfile::TempDir, std::path::PathBuf) {
    let initial = format!(
        r#"
schema_version = 3

[profiles.default]
display_name = "Default"
{mounted}

[[custom_lists]]
id = "home-exceptions"
display_name = "Home exceptions"

[[custom_lists]]
id = "handheld"
display_name = "Handheld"

[upstream]
servers = ["192.0.2.1:53"]
"#
    );
    let (dir, path) = client_mutation_temp_config(&initial, suffix);
    let packs = dir.path().join("packs");
    std::fs::create_dir_all(&packs).unwrap();
    for id in ["home-exceptions", "handheld"] {
        std::fs::write(packs.join(format!("{id}.txt")), "||blocked.invalid^\n").unwrap();
    }
    (dir, path)
}

/// The mounts a profile carries after a mutation, read back off disk.
fn load_profile_mounts(path: &std::path::Path, id: &str) -> Vec<String> {
    crate::config::loader::load_config(path, time::OffsetDateTime::now_utc())
        .expect("v1 config must load")
        .config
        .profiles
        .get(id)
        .expect("profile must exist")
        .custom_lists
        .iter()
        .map(|i| i.as_str().to_string())
        .collect()
}

/// The raw `[profiles.<id>]` table as the operator's file has it —
/// needed where the question is whether a KEY is present, which the
/// typed value cannot answer.
fn raw_profile_table(path: &std::path::Path, id: &str) -> toml::value::Table {
    let text = std::fs::read_to_string(path).unwrap();
    text.parse::<toml::Value>()
        .unwrap()
        .get("profiles")
        .and_then(|v| v.get(id))
        .and_then(|v| v.as_table())
        .cloned()
        .expect("profile table must exist")
}

#[tokio::test]
async fn profile_update_mounts_a_custom_list() {
    let (_dir, path) = mount_fixture("mount", "");
    let (state, mut reload_rx) = test_state_with_config_path("tok-mount", path.clone());
    let state = Arc::new(state);

    let resp = dispatch_command(
        IpcCommand::ProfileUpdate {
            id: "default".into(),
            patch: crate::ipc::protocol::ProfileUpdatePatch {
                custom_lists: Some(crate::ipc::protocol::CustomListMountPatch {
                    mount: vec!["home-exceptions".into()],
                    unmount: vec![],
                }),
                ..Default::default()
            },
            token: Some("tok-mount".into()),
        },
        None,
        &state,
    )
    .await;
    assert!(
        matches!(resp, IpcResponse::Ok { .. }),
        "expected Ok, got {resp:?}"
    );
    assert_eq!(load_profile_mounts(&path, "default"), ["home-exceptions"]);
    assert!(reload_rx.try_recv().is_ok(), "reload signal must be sent");
}

/// Unmounting the last one REMOVES the key rather than leaving
/// `custom_lists = []` behind. `Profile::custom_lists` skips an empty
/// vector on serialisation for exactly that reason, and a handler that
/// wrote one would put back what that attribute exists to keep out.
#[tokio::test]
async fn profile_update_unmount_removes_the_key_rather_than_emptying_it() {
    let (_dir, path) = mount_fixture("unmount", "custom_lists = [\"home-exceptions\"]");
    let (state, _rx) = test_state_with_config_path("tok-unmount", path.clone());
    let state = Arc::new(state);

    let resp = dispatch_command(
        IpcCommand::ProfileUpdate {
            id: "default".into(),
            patch: crate::ipc::protocol::ProfileUpdatePatch {
                custom_lists: Some(crate::ipc::protocol::CustomListMountPatch {
                    mount: vec![],
                    unmount: vec!["home-exceptions".into()],
                }),
                ..Default::default()
            },
            token: Some("tok-unmount".into()),
        },
        None,
        &state,
    )
    .await;
    assert!(
        matches!(resp, IpcResponse::Ok { .. }),
        "expected Ok, got {resp:?}"
    );
    assert!(load_profile_mounts(&path, "default").is_empty());
    assert!(
        !raw_profile_table(&path, "default").contains_key("custom_lists"),
        "an empty mount list is removed, never written as []",
    );
}

/// `mount` is applied BEFORE `unmount`, frozen: an id named by both
/// halves ends unmounted. Stated on the wire type so the two sibling
/// deltas read the same way; pinned here because prose does not fail a
/// build.
#[tokio::test]
async fn an_id_in_both_halves_of_the_mount_patch_ends_unmounted() {
    let (_dir, path) = mount_fixture("both", "custom_lists = [\"handheld\"]");
    let (state, _rx) = test_state_with_config_path("tok-both", path.clone());
    let state = Arc::new(state);

    let resp = dispatch_command(
        IpcCommand::ProfileUpdate {
            id: "default".into(),
            patch: crate::ipc::protocol::ProfileUpdatePatch {
                custom_lists: Some(crate::ipc::protocol::CustomListMountPatch {
                    mount: vec!["home-exceptions".into()],
                    unmount: vec!["home-exceptions".into()],
                }),
                ..Default::default()
            },
            token: Some("tok-both".into()),
        },
        None,
        &state,
    )
    .await;
    assert!(
        matches!(resp, IpcResponse::Ok { .. }),
        "expected Ok, got {resp:?}"
    );
    assert_eq!(
        load_profile_mounts(&path, "default"),
        ["handheld"],
        "the untouched mount survives and the contested one does not land",
    );
}

/// Mounting an id no `[[custom_lists]]` declares is refused — by the
/// validator running over the staged tree, which is the refusal the
/// handler EXPOSES rather than re-implements. Nothing is written.
#[tokio::test]
async fn mounting_an_undeclared_custom_list_is_refused_and_writes_nothing() {
    let (_dir, path) = mount_fixture("ghost", "");
    let before = std::fs::read_to_string(&path).unwrap();
    let (state, _rx) = test_state_with_config_path("tok-ghost", path.clone());
    let state = Arc::new(state);

    let resp = dispatch_command(
        IpcCommand::ProfileUpdate {
            id: "default".into(),
            patch: crate::ipc::protocol::ProfileUpdatePatch {
                custom_lists: Some(crate::ipc::protocol::CustomListMountPatch {
                    mount: vec!["ghost-list".into()],
                    unmount: vec![],
                }),
                ..Default::default()
            },
            token: Some("tok-ghost".into()),
        },
        None,
        &state,
    )
    .await;
    assert!(
        matches!(resp, IpcResponse::Error { .. }),
        "expected Error, got {resp:?}"
    );
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        before,
        "a refused mount leaves the file byte-identical",
    );
}

/// A malformed id is refused BEFORE anything is staged, so the sibling
/// field of the same patch does not land either. The whole-file
/// validator is what makes that necessary: one bad id would otherwise
/// take the operator's rename down with it, after the rename had been
/// written into the staged document.
#[tokio::test]
async fn an_invalid_mount_id_refuses_the_whole_patch() {
    let (_dir, path) = mount_fixture("badid", "");
    let (state, _rx) = test_state_with_config_path("tok-badid", path.clone());
    let state = Arc::new(state);

    let resp = dispatch_command(
        IpcCommand::ProfileUpdate {
            id: "default".into(),
            patch: crate::ipc::protocol::ProfileUpdatePatch {
                display_name: Some("Renamed".into()),
                custom_lists: Some(crate::ipc::protocol::CustomListMountPatch {
                    mount: vec!["not a valid id".into()],
                    unmount: vec![],
                }),
                ..Default::default()
            },
            token: Some("tok-badid".into()),
        },
        None,
        &state,
    )
    .await;
    assert!(
        matches!(resp, IpcResponse::Error { .. }),
        "expected Error, got {resp:?}"
    );
    let table = raw_profile_table(&path, "default");
    assert_eq!(
        table.get("display_name").and_then(|v| v.as_str()),
        Some("Default"),
        "the sibling field of a refused patch must not land",
    );
}
