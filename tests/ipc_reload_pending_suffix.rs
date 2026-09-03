//! §4.45 (Hermes T1.8) — pin the `RELOAD_PENDING_SUFFIX` UX contract.
//!
//! All five mutation handlers in `src/ipc/socket_server.rs` that fire a
//! best-effort reload via `reload_tx.try_send(peer_uid)` must
//! differentiate the `Ok` arm (sent, reload live on next coalescer
//! drain) from the `Full` arm (slot already occupied by a prior
//! mutation's signal, on-disk change won't appear in-memory until that
//! pending reload drains). The pre-§4.45 code swallowed both arms with
//! `Ok(()) | Err(Full(_)) => {}` and returned the same bare
//! `IpcResponse::Ok` either way, leaving operators with no signal that
//! their burst of `warden client add` calls was racing the coalescer.
//!
//! Fixture shape: wires `reload_tx: Some(_)` with capacity 1 and keeps
//! the receiver alive but never drains it. Once any one mutation
//! succeeds the slot stays full for the test's lifetime, so the second
//! mutation onwards must observe `Full`.
//!
//! Coverage map (one test per `try_send(peer_uid)` site):
//! - `handle_device_add`         → `device_add_full_appends_suffix`
//! - `handle_device_update`      → `device_update_full_appends_suffix`
//! - `handle_device_remove`      → `device_remove_full_appends_suffix`
//! - `handle_tracking_config_update` → `tracking_config_update_full_appends_suffix`
//! - `notify_reload` helper (profile_*) → `profile_create_full_appends_suffix`

use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use purge_warden::auth::token::hash_token;
use purge_warden::config::settings::ClientConfig;
use purge_warden::dns::cache::DnsCache;
use purge_warden::filter::FilterEngine;
use purge_warden::ipc::protocol::{
    DevicePatch, IpcCommand, IpcResponse, TrackingPatch, RELOAD_PENDING_SUFFIX,
};
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

/// Per-test fixture. Owns the tempdir, the spawned IPC server, the
/// live socket path, the master config path, the auth token — and the
/// receiver end of the capacity-1 reload channel, kept alive so the
/// channel doesn't close (which would route mutations into the Closed
/// branch instead of Full).
struct Fixture {
    _tmp: tempfile::TempDir,
    _server: tokio::task::JoinHandle<()>,
    _reload_rx: tokio::sync::mpsc::Receiver<Option<u32>>,
    socket_path: PathBuf,
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

    let (reload_tx, reload_rx) = tokio::sync::mpsc::channel::<Option<u32>>(1);

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
        reload_tx: Some(reload_tx),
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
        daemon_uid: purge_warden::ipc::socket_server::current_euid(),
        resource_budget_store: purge_warden::resource_budget::types::new_store(),
        #[cfg(feature = "cluster")]
        cluster_observe: None,
    };

    let handle = spawn_ipc_server(socket_path.clone(), Arc::new(state))
        .await
        .expect("spawn_ipc_server");

    tokio::task::yield_now().await;

    Fixture {
        _tmp: tmp,
        _server: handle,
        _reload_rx: reload_rx,
        socket_path,
        token,
    }
}

async fn send(fx: &Fixture, cmd: IpcCommand) -> IpcResponse {
    socket_client::send_command(&fx.socket_path, &cmd)
        .await
        .expect("send_command")
}

fn expect_ok_message(resp: IpcResponse) -> String {
    match resp {
        IpcResponse::Ok { message } => message,
        other => panic!("expected Ok, got {other:?}"),
    }
}

fn minimal_client(name: &str, ip: &str) -> ClientConfig {
    ClientConfig {
        name: name.into(),
        ip: ip.parse().expect("parse ip"),
        mac: None,
        mac_aliases: Vec::new(),
        profile: "default".into(),
        owner: None,
        device_type: None,
        department: None,
        group: None,
        notes: None,
    }
}

/// Add a client. Used both as a primer (fills the reload slot) and as
/// the verb under test.
fn add_cmd(fx: &Fixture, name: &str, ip: &str) -> IpcCommand {
    IpcCommand::DeviceAdd {
        client: minimal_client(name, ip),
        token: Some(fx.token.clone()),
    }
}

// ── site 1: handle_device_add ──────────────────────────────────────

#[tokio::test]
async fn device_add_full_appends_suffix() {
    let fx = spawn_fixture().await;

    let first = expect_ok_message(send(&fx, add_cmd(&fx, "alpha", "10.0.0.5")).await);
    assert!(
        !first.contains(RELOAD_PENDING_SUFFIX),
        "first add must NOT carry suffix (channel was empty). got: {first:?}",
    );

    let second = expect_ok_message(send(&fx, add_cmd(&fx, "beta", "10.0.0.6")).await);
    assert!(
        second.contains(RELOAD_PENDING_SUFFIX),
        "second add MUST carry suffix (channel slot still full). got: {second:?}",
    );
}

// ── site 2: handle_device_update ───────────────────────────────────

#[tokio::test]
async fn device_update_full_appends_suffix() {
    let fx = spawn_fixture().await;

    // primer: add fills the slot. Caller ignores its suffix status.
    let _ = send(&fx, add_cmd(&fx, "gamma", "10.0.0.7")).await;

    let update_cmd = IpcCommand::DeviceUpdate {
        name: "gamma".into(),
        patch: DevicePatch {
            ip: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 8))),
            ..Default::default()
        },
        token: Some(fx.token.clone()),
    };
    let msg = expect_ok_message(send(&fx, update_cmd).await);
    assert!(
        msg.contains(RELOAD_PENDING_SUFFIX),
        "device_update with pending reload MUST carry suffix. got: {msg:?}",
    );
}

// ── site 3: handle_device_remove ───────────────────────────────────

#[tokio::test]
async fn device_remove_full_appends_suffix() {
    let fx = spawn_fixture().await;

    let _ = send(&fx, add_cmd(&fx, "delta", "10.0.0.9")).await;

    let remove_cmd = IpcCommand::DeviceRemove {
        name: "delta".into(),
        token: Some(fx.token.clone()),
    };
    let msg = expect_ok_message(send(&fx, remove_cmd).await);
    assert!(
        msg.contains(RELOAD_PENDING_SUFFIX),
        "device_remove with pending reload MUST carry suffix. got: {msg:?}",
    );
}

// ── site 4: handle_tracking_config_update ──────────────────────────

#[tokio::test]
async fn tracking_config_update_full_appends_suffix() {
    let fx = spawn_fixture().await;

    let primer = IpcCommand::TrackingConfigUpdate {
        patch: TrackingPatch {
            retention_days: Some(7),
            ..Default::default()
        },
        token: Some(fx.token.clone()),
    };
    let _ = send(&fx, primer).await;

    let target = IpcCommand::TrackingConfigUpdate {
        patch: TrackingPatch {
            retention_days: Some(14),
            ..Default::default()
        },
        token: Some(fx.token.clone()),
    };
    let msg = expect_ok_message(send(&fx, target).await);
    assert!(
        msg.contains(RELOAD_PENDING_SUFFIX),
        "tracking_config_update with pending reload MUST carry suffix. got: {msg:?}",
    );
}

// ── site 5: notify_reload helper (profile_*) ───────────────────────

#[tokio::test]
async fn profile_create_full_appends_suffix() {
    let fx = spawn_fixture().await;

    let primer = IpcCommand::ProfileCreate {
        id: "primer".into(),
        display_name: "Primer".into(),
        token: Some(fx.token.clone()),
    };
    let first = expect_ok_message(send(&fx, primer).await);
    assert!(
        !first.contains(RELOAD_PENDING_SUFFIX),
        "first profile_create must NOT carry suffix. got: {first:?}",
    );

    let target = IpcCommand::ProfileCreate {
        id: "target".into(),
        display_name: "Target".into(),
        token: Some(fx.token.clone()),
    };
    let second = expect_ok_message(send(&fx, target).await);
    assert!(
        second.contains(RELOAD_PENDING_SUFFIX),
        "second profile_create MUST carry suffix (notify_reload helper path). got: {second:?}",
    );
}
