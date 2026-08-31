//! `warden lists set <key> <same-value>` must not reload the daemon.
//!
//! A reload on a live resolver is not free, so `set` short-circuits when
//! the new value already equals the one on disk. Asserting that from the
//! outside means counting connections to the IPC socket.
//!
//! **This test only means anything if a reload is reachable at all.**
//! `attempt_reload` resolves the admin token from the environment and
//! returns `NoToken` *without opening a socket* when it finds none — on a
//! box with no token file, a naive "0 connections after the no-op" test
//! passes while proving nothing. So this plants a token, and asserts the
//! FIRST set produced exactly one connection before asserting the second
//! produced none. A broken harness fails on that first assertion instead
//! of quietly succeeding.
//!
//! Lives in its own test binary because it mutates the process-global
//! `XDG_CONFIG_HOME`, which would race sibling tests sharing a process.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use purge_warden::cli::commands::lists_knobs;
use purge_warden::ipc::protocol::IpcResponse;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;

const MASTER: &str = r#"schema_version = 3

[server]
default_profile = "default"

[profiles.default]
display_name = "Default"

[lists]
max_total_domains = 14000000

[upstream]
servers = ["192.0.2.1:53"]
"#;

/// Accept connections forever, counting each one and replying `Ok` so
/// `attempt_reload` classifies the outcome as `Reloaded` and does not
/// take its auth-mismatch retry path (which would double the count).
fn spawn_counting_stub(path: PathBuf, count: Arc<AtomicU32>) -> tokio::task::JoinHandle<()> {
    let listener = UnixListener::bind(&path).expect("bind stub socket");
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            count.fetch_add(1, Ordering::SeqCst);
            let (reader, mut writer) = stream.into_split();
            let mut reader = BufReader::new(reader);
            let mut line = String::new();
            let _ = reader.read_line(&mut line).await;
            let mut body = serde_json::to_string(&IpcResponse::Ok {
                message: "stub ok".into(),
            })
            .expect("encode stub response");
            body.push('\n');
            let _ = writer.write_all(body.as_bytes()).await;
            let _ = writer.shutdown().await;
        }
    })
}

#[tokio::test]
async fn a_no_op_set_does_not_reload_the_daemon() {
    let tmp = tempfile::tempdir().expect("tempdir");

    // Plant a token where `default_token_path` will find it. XDG is
    // consulted before $HOME, and only when the file actually exists.
    let xdg = tmp.path().join("xdg");
    let token_dir = xdg.join("purge-warden");
    std::fs::create_dir_all(&token_dir).expect("mk token dir");
    std::fs::write(token_dir.join("token"), "ps_stub-token\n").expect("write token");
    std::env::set_var("XDG_CONFIG_HOME", &xdg);

    let master = tmp.path().join("config.toml");
    std::fs::write(&master, MASTER).expect("seed master");

    let socket = tmp.path().join("control.sock");
    let count = Arc::new(AtomicU32::new(0));
    let server = spawn_counting_stub(socket.clone(), count.clone());

    // First set: a real change, so it must reload.
    lists_knobs::run_set(&master, &socket, "max_total_domains", "15000000")
        .await
        .expect("first set");
    assert_eq!(
        count.load(Ordering::SeqCst),
        1,
        "a real change must reload exactly once — if this is 0 the token \
         plumbing is broken and the no-op assertion below proves nothing"
    );

    // Second set: same value, so the short-circuit must fire before any
    // reload is attempted.
    lists_knobs::run_set(&master, &socket, "max_total_domains", "15000000")
        .await
        .expect("second set");
    assert_eq!(
        count.load(Ordering::SeqCst),
        1,
        "a no-op set must not open a second connection"
    );

    server.abort();
}
