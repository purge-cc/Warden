//! rev-2606 writer-01 — the IPC tracking-config handler must preserve a
//! multi-file include layout.
//!
//! The pre-fix handler loaded the MERGED `ConfigV1` and re-serialised the
//! whole tree onto the master via `write_config_v1` — flattening every
//! `.d/` entity onto the master (and, with a non-empty include set,
//! getting refused by staged validation as duplicate singletons). The fix
//! edits only the master's own `[tracking]` table via `toml::Value`
//! surgery and promotes through the overlay-validating
//! `write_value_validated`, so the include slices are never touched.
//!
//! This plants a master + a `blocklists.d/` include, runs a REAL
//! `TrackingConfigUpdate` through the spawned IPC server, and asserts the
//! include slice is byte-identical and the master never absorbed the
//! entity.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use purge_warden::auth::token::hash_token;
use purge_warden::config::loader::load_config;
use purge_warden::dns::cache::DnsCache;
use purge_warden::filter::FilterEngine;
use purge_warden::ipc::protocol::{IpcCommand, IpcResponse, TrackingPatch};
use purge_warden::ipc::socket_client;
use purge_warden::ipc::socket_server::{spawn_ipc_server, DaemonState};

const MASTER: &str = r#"schema_version = 3
includes = ["blocklists.d/*.toml"]

[server]
default_profile = "default"

[tracking]
query_log_enabled = true
retention_days = 7

[profiles.default]
display_name = "Default"

[upstream]
servers = ["192.0.2.1:53"]
"#;

const INCLUDE_BLOCKLIST: &str = r#"[[blocklists]]
id = "privacy-ads"
display_name = "Privacy: ads"
url = "https://lists.purge.cc/privacy/ads.txt"
"#;

struct Fixture {
    _tmp: tempfile::TempDir,
    _server: tokio::task::JoinHandle<()>,
    _reload_rx: tokio::sync::mpsc::Receiver<Option<u32>>,
    socket_path: PathBuf,
    master: PathBuf,
    include: PathBuf,
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
    std::fs::write(&master, MASTER).expect("seed master");
    let include_dir = tmp.path().join("blocklists.d");
    std::fs::create_dir_all(&include_dir).expect("mk include dir");
    let include = include_dir.join("ads.toml");
    std::fs::write(&include, INCLUDE_BLOCKLIST).expect("seed include");
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
        master,
        include,
        token,
    }
}

#[tokio::test]
async fn tracking_update_preserves_include_layout() {
    let fx = spawn_fixture().await;
    let include_before = std::fs::read_to_string(&fx.include).expect("read include");

    let cmd = IpcCommand::TrackingConfigUpdate {
        patch: TrackingPatch {
            retention_days: Some(30),
            ..Default::default()
        },
        token: Some(fx.token.clone()),
    };
    let resp = socket_client::send_command(&fx.socket_path, &cmd)
        .await
        .expect("send_command");
    assert!(
        matches!(resp, IpcResponse::Ok { .. }),
        "tracking update must succeed on a multi-file layout, got {resp:?}",
    );

    // 1. The include slice is byte-identical — the entity was NOT moved.
    let include_after = std::fs::read_to_string(&fx.include).expect("read include after");
    assert_eq!(
        include_before, include_after,
        "include slice must be untouched by a [tracking] edit",
    );

    // 2. The master never absorbed the blocklist (no flatten), and kept
    //    its includes array.
    let master_after = std::fs::read_to_string(&fx.master).expect("read master after");
    assert!(
        !master_after.contains("privacy-ads"),
        "master must not absorb the .d/ entity (flatten regression). got:\n{master_after}",
    );
    assert!(
        master_after.contains("includes"),
        "master must keep its includes array. got:\n{master_after}",
    );

    // 3. The merged tree still loads and carries the patched value
    //    (Ok above already proves overlay validation passed pre-rename).
    let now = time::OffsetDateTime::now_utc();
    let loaded = load_config(&fx.master, now).expect("merged config still loads");
    assert_eq!(
        loaded.config.tracking.retention_days, 30,
        "the patched retention_days must apply",
    );
}
