//! `ProfileUpdatePatch.tags` is **refused** over IPC —
//! `_docs/features/profile_list_policy.md` §4 S3.
//!
//! # What this file used to prove
//!
//! `tag_model_consolidation` §3.5's IPC roundtrip: seven tests over the
//! delta semantics (add, remove, remove-wins, idempotence, array creation,
//! slug validation). The patch field is the **TUI's** path — the CLI verbs
//! edit TOML directly — which made it the one piece of that sprint with no
//! CLI test behind it.
//!
//! `plp-s3` cut tags out of the filtering path, so a successful write here
//! would move bytes on disk and change no verdict: defect E2, the silent
//! acceptance-and-discard, arriving through the surface with the least
//! operator visibility. The three tests below keep the roundtrip — real
//! server, real socket, real command — and assert the refusal and that the
//! file did not move.
//!
//! The CLI verbs (`warden profile tag add|remove`) do not go through
//! IPC — they edit the TOML directly, like `warden device tag add`. The
//! patch field is the **TUI's** path, and lane `tui-surfaces` builds its
//! profile-modal tags field on it. That makes this the one piece of new
//! behaviour with no CLI test behind it, so it gets its own roundtrip:
//! spawn the real `socket_server` over a tempdir socket, send a real
//! `IpcCommand::ProfileUpdate`, and assert the master on disk.
//!
//! Fixture shape mirrors `tests/ipc_profile_mutate_roundtrip.rs` (a
//! file this lane does not own, hence the local copy rather than an
//! import).

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use purge_warden::auth::token::hash_token;
use purge_warden::dns::cache::DnsCache;
use purge_warden::filter::FilterEngine;
use purge_warden::ipc::protocol::{IpcCommand, IpcResponse, ProfileUpdatePatch, TagsPatch};
use purge_warden::ipc::socket_client;
use purge_warden::ipc::socket_server::{spawn_ipc_server, DaemonState};

const MASTER_SEED: &str = r#"schema_version = 3

[server]
default_profile = "default"

[profiles.default]
display_name = "Default"

[profiles.kids]
display_name = "Kids"
tags = ["ads"]

[upstream]
servers = ["192.0.2.1:53"]
"#;

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
        socket_path,
        master,
        token,
    }
}

async fn send_tags_patch(fx: &Fixture, id: &str, add: &[&str], remove: &[&str]) -> IpcResponse {
    let cmd = IpcCommand::ProfileUpdate {
        id: id.to_string(),
        patch: ProfileUpdatePatch {
            // `plp-s5a` renamed the field to `retired_tags` (still `tags`
            // on the wire) when it removed `Profile.tags`. The field is
            // KEPT precisely so this refusal stays reachable: dropping it
            // would let an old client's delta vanish into serde with an OK.
            retired_tags: Some(TagsPatch {
                add: add.iter().map(|s| s.to_string()).collect(),
                remove: remove.iter().map(|s| s.to_string()).collect(),
            }),
            ..Default::default()
        },
        token: Some(fx.token.clone()),
    };
    socket_client::send_command(&fx.socket_path, &cmd)
        .await
        .expect("send_command")
}

fn tags_on_disk(fx: &Fixture, id: &str) -> Vec<String> {
    let raw = std::fs::read_to_string(&fx.master).expect("read master");
    let doc: toml::Value = raw.parse().expect("master parses");
    doc.get("profiles")
        .and_then(|v| v.get(id))
        .and_then(|v| v.get("tags"))
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

/// The delta is refused, the file does not move, and the message names the
/// replacement.
///
/// Still a full roundtrip rather than a unit call: a refusal that only held
/// in-process would say nothing about what the TUI's socket client sees.
#[tokio::test]
async fn a_profile_tags_delta_is_refused_over_ipc_and_writes_nothing() {
    let fx = spawn_fixture().await;
    let before = std::fs::read_to_string(&fx.master).unwrap();

    for (add, remove) in [
        (&["fresh"][..], &[][..]),
        (&[][..], &["ads"][..]),
        (&["fresh"][..], &["ads"][..]),
    ] {
        let resp = send_tags_patch(&fx, "default", add, remove).await;
        assert!(
            matches!(resp, IpcResponse::Error { .. }),
            "add={add:?} remove={remove:?} must be refused, got {resp:?}"
        );
    }

    assert_eq!(
        std::fs::read_to_string(&fx.master).unwrap(),
        before,
        "three refusals must leave the master byte-identical"
    );
}

/// An empty delta is not a tag write.
///
/// The TUI's profile modal submits its whole patch on every save, so a form
/// that changed only a scalar can carry `TagsPatch { add: [], remove: [] }`.
/// Refusing that would make unrelated fields unwritable through a rule about
/// tags — the refusal-that-cannot-be-satisfied shape CLAUDE.md records for
/// the old TUI consent gate.
#[tokio::test]
async fn an_empty_tags_delta_is_not_refused() {
    let fx = spawn_fixture().await;
    let resp = send_tags_patch(&fx, "default", &[], &[]).await;
    assert!(
        matches!(resp, IpcResponse::Ok { .. }),
        "an empty delta must pass through, got {resp:?}"
    );
}

/// The tags already in the file still load and still round-trip.
///
/// `plp-s3` retires the writers, not the schema — S5 removes the field.
#[tokio::test]
async fn existing_profile_tags_are_left_alone() {
    let fx = spawn_fixture().await;
    assert_eq!(tags_on_disk(&fx, "kids"), vec!["ads".to_string()]);
}
