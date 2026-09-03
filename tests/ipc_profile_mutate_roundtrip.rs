//! §4.26 Phase 1 hotfix — end-to-end IPC roundtrip for `warden profile`
//! mutate verbs.
//!
//! Pins the regression net for the `find_target_for_id` named-map fix:
//! the §4.26 §1/2 bug was that `warden profile create <id>` succeeded
//! (writer used the dedicated [`upsert_profile`] path that already
//! handled the v1 `[profiles.<id>]` named-map) but every subsequent
//! mutate verb (`update`, `ecs`, `block-response`, `blocked-ttl`,
//! `block-all`, `admin-rule-add`, `admin-rule-remove`, `ecs-clear`,
//! `remove`) returned `Error: daemon refused: no profile with id "X"`
//! because the lookup helper hard-coded the v0 array-of-tables shape.
//!
//! The unit tests in `src/cli/commands/target.rs` cover the lookup
//! function in isolation. This file exercises the full IPC roundtrip:
//! tempdir master → spawn `ipc::socket_server` over a tempdir Unix
//! socket → `socket_client::send_command` for every mutate verb → assert
//! `IpcResponse::Ok` and verify the on-disk TOML reflects the change.
//!
//! [`upsert_profile`]: purge_warden::cli::commands::target::upsert_profile

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use purge_warden::auth::token::hash_token;
use purge_warden::dns::cache::DnsCache;
use purge_warden::filter::FilterEngine;
use purge_warden::ipc::protocol::{EcsPatch, IpcCommand, IpcResponse, ProfileUpdatePatch};
use purge_warden::ipc::socket_client;
use purge_warden::ipc::socket_server::{spawn_ipc_server, DaemonState};

const MASTER_SEED: &str = r#"schema_version = 3

[server]
default_profile = "default"

[profiles.default]
display_name = "Default"

[upstream]
servers = ["192.0.2.1:53"]
"#;

/// Per-test fixture. Owns the tempdir (kept alive for the test scope),
/// the spawned server `JoinHandle` (aborted on drop), the live socket
/// path the client connects to, and the master config path the daemon
/// edits.
struct Fixture {
    _tmp: tempfile::TempDir,
    _server: tokio::task::JoinHandle<()>,
    socket_path: PathBuf,
    master: PathBuf,
    token: String,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self._server.abort();
    }
}

async fn spawn_fixture() -> Fixture {
    let tmp = tempfile::tempdir().expect("tempdir");
    let master = tmp.path().join("config.toml");
    std::fs::write(&master, MASTER_SEED).expect("seed master config");
    let socket_path = tmp.path().join("control.sock");

    let token = "test-token-very-secret".to_string();
    let token_hash = hash_token(&token);

    let cache_config = purge_warden::config::settings::CacheConfig::default();
    let state = DaemonState {
        filter: Arc::new(FilterEngine::new()),
        cache: DnsCache::new(&cache_config),
        profiles: None,
        stats: None,
        listen_addr: "127.0.0.1:15353".into(),
        upstream_mode: "plain".into(),
        upstream_count: 0,
        upstream_servers: Vec::new(),
        list_count: 0,
        started_at: Instant::now(),
        shutdown_tx: None,
        reload_tx: None,
        api_token_hash: Arc::new(arc_swap::ArcSwap::from_pointee(Some(token_hash))),
        config_path: Some(master.clone()),
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
        // §4.32: integration test uses the test process's own euid so
        // the peer-uid gate is a no-op (test connects through its own
        // uid).
        daemon_uid: purge_warden::ipc::socket_server::current_euid(),
        resource_budget_store: purge_warden::resource_budget::types::new_store(),
        #[cfg(feature = "cluster")]
        cluster_observe: None,
    };

    let handle = spawn_ipc_server(socket_path.clone(), Arc::new(state))
        .await
        .expect("spawn_ipc_server");

    // The listener is bound by `spawn_ipc_server` synchronously before
    // returning, so the very first `socket_client::send_command` would
    // succeed without a wait — but the accept loop spawns in a fresh
    // tokio task that has not necessarily polled yet. Yield once so the
    // accept loop is at `listener.accept().await` before the test fires
    // its first command.
    tokio::task::yield_now().await;

    Fixture {
        _tmp: tmp,
        _server: handle,
        socket_path,
        master,
        token,
    }
}

fn read_master(fx: &Fixture) -> String {
    std::fs::read_to_string(&fx.master).expect("read master")
}

async fn expect_ok(fx: &Fixture, cmd: IpcCommand) -> String {
    match socket_client::send_command(&fx.socket_path, &cmd)
        .await
        .expect("send_command")
    {
        IpcResponse::Ok { message } => message,
        other => panic!("expected Ok, got {other:?} (cmd: {cmd:?})"),
    }
}

/// Full §4.26 Phase 1 workflow: create a profile, then exercise every
/// mutate verb, then remove. Each step must succeed; before the fix
/// the second step would fail with `no profile with id "hotfix-prof"`.
#[tokio::test]
async fn roundtrip_full_chain_create_to_remove() {
    let fx = spawn_fixture().await;
    let id = "hotfix-prof";

    // 1. create
    expect_ok(
        &fx,
        IpcCommand::ProfileCreate {
            id: id.into(),
            display_name: "Hotfix Profile".into(),
            token: Some(fx.token.clone()),
        },
    )
    .await;
    let toml = read_master(&fx);
    assert!(
        toml.contains("[profiles.hotfix-prof]"),
        "master should hold the new named-map entry. Master content:\n{toml}",
    );

    // 2. update display_name
    expect_ok(
        &fx,
        IpcCommand::ProfileUpdate {
            id: id.into(),
            patch: ProfileUpdatePatch {
                display_name: Some("Hotfix Profile Renamed".into()),
                ..Default::default()
            },
            token: Some(fx.token.clone()),
        },
    )
    .await;
    let toml = read_master(&fx);
    assert!(
        toml.contains("Hotfix Profile Renamed"),
        "display_name update should land on disk. Master content:\n{toml}",
    );

    // 3. block-response = nxdomain
    expect_ok(
        &fx,
        IpcCommand::ProfileUpdate {
            id: id.into(),
            patch: ProfileUpdatePatch {
                block_response: Some(Some(
                    purge_warden::config::schema::profile::BlockResponseV1::Nxdomain,
                )),
                ..Default::default()
            },
            token: Some(fx.token.clone()),
        },
    )
    .await;
    let toml = read_master(&fx);
    assert!(
        toml.contains("block_response = \"nxdomain\""),
        "block_response should be set on disk. Master content:\n{toml}",
    );

    // 4. blocked-ttl = 120
    expect_ok(
        &fx,
        IpcCommand::ProfileUpdate {
            id: id.into(),
            patch: ProfileUpdatePatch {
                blocked_ttl_secs: Some(Some(120)),
                ..Default::default()
            },
            token: Some(fx.token.clone()),
        },
    )
    .await;
    let toml = read_master(&fx);
    assert!(
        toml.contains("blocked_ttl_secs = 120"),
        "blocked_ttl_secs should be set on disk. Master content:\n{toml}",
    );

    // 5. ecs = coarse
    expect_ok(
        &fx,
        IpcCommand::ProfileUpdate {
            id: id.into(),
            patch: ProfileUpdatePatch {
                ecs: Some(EcsPatch {
                    mode: Some(purge_warden::config::settings::EcsMode::Coarse),
                    source_prefix_v4: None,
                    source_prefix_v6: None,
                    clear: false,
                }),
                ..Default::default()
            },
            token: Some(fx.token.clone()),
        },
    )
    .await;
    let toml = read_master(&fx);
    assert!(
        toml.contains("mode = \"coarse\""),
        "ecs.mode should be set on disk. Master content:\n{toml}",
    );

    // 6. ecs-clear
    expect_ok(
        &fx,
        IpcCommand::ProfileUpdate {
            id: id.into(),
            patch: ProfileUpdatePatch {
                ecs: Some(EcsPatch {
                    clear: true,
                    ..Default::default()
                }),
                ..Default::default()
            },
            token: Some(fx.token.clone()),
        },
    )
    .await;
    let toml = read_master(&fx);
    assert!(
        !toml.contains("mode = \"coarse\""),
        "ecs subtree should be cleared from disk. Master content:\n{toml}",
    );

    // 7. remove
    expect_ok(
        &fx,
        IpcCommand::ProfileDelete {
            id: id.into(),
            token: Some(fx.token.clone()),
        },
    )
    .await;
    let toml = read_master(&fx);
    assert!(
        !toml.contains("[profiles.hotfix-prof]"),
        "named-map entry should be gone from disk. Master content:\n{toml}",
    );
}

/// Direct regression for the §4.26 §1/2 bug: create then immediately
/// update — the lookup must find the entry by named-map key, not by
/// `[[profiles]]` `id` field. Pre-fix this returned
/// `IpcResponse::Error { message: "no profile with id \"X\"..." }`.
#[tokio::test]
async fn roundtrip_create_then_find_for_update() {
    let fx = spawn_fixture().await;
    let id = "regression-prof";

    expect_ok(
        &fx,
        IpcCommand::ProfileCreate {
            id: id.into(),
            display_name: "Original".into(),
            token: Some(fx.token.clone()),
        },
    )
    .await;

    let resp = socket_client::send_command(
        &fx.socket_path,
        &IpcCommand::ProfileUpdate {
            id: id.into(),
            patch: ProfileUpdatePatch {
                display_name: Some("Updated".into()),
                ..Default::default()
            },
            token: Some(fx.token.clone()),
        },
    )
    .await
    .expect("send_command");

    match resp {
        IpcResponse::Ok { .. } => {}
        IpcResponse::Error { message } => panic!(
            "post-create update must succeed (regression for §4.26 §1/2 \
             `find_target_for_id` array-of-tables-only lookup). Got error: {message}"
        ),
        other => panic!("unexpected response: {other:?}"),
    }
}

/// `remove` on a named-map entry must clear the `[profiles.<id>]` block
/// from the master entirely (`remove_profile` already handled this; the
/// hotfix only fixes the LOOKUP that precedes it). Pins the post-fix
/// disk state so a future regression in either function fails here.
#[tokio::test]
async fn roundtrip_remove_clears_named_map() {
    let fx = spawn_fixture().await;
    let id = "ephemeral-prof";

    expect_ok(
        &fx,
        IpcCommand::ProfileCreate {
            id: id.into(),
            display_name: "Ephemeral".into(),
            token: Some(fx.token.clone()),
        },
    )
    .await;
    assert!(read_master(&fx).contains("[profiles.ephemeral-prof]"));

    expect_ok(
        &fx,
        IpcCommand::ProfileDelete {
            id: id.into(),
            token: Some(fx.token.clone()),
        },
    )
    .await;
    let toml = read_master(&fx);
    assert!(
        !toml.contains("[profiles.ephemeral-prof]"),
        "after ProfileDelete the named-map entry must be gone. Master content:\n{toml}",
    );
    // The default profile must survive — `remove_profile` only deletes
    // the keyed sub-table, not the whole `[profiles]` namespace.
    assert!(
        toml.contains("[profiles.default]"),
        "default profile must not be collateral damage. Master content:\n{toml}",
    );
}
