//! §4.13 Sprint 1 — end-to-end integration: the resource-budget sampler
//! publishes a snapshot through the shared `ArcSwap` and the IPC `Status`
//! handler reports it back over a Unix socket.
//!
//! Spawns a minimal `DaemonState` (no DNS, no upstream, no real config —
//! just enough to drive `spawn_ipc_server`), wires the sampler against
//! the same `ResourceBudgetStore` the state holds, then sends
//! `IpcCommand::Status` from a client and inspects the reply.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use purge_warden::dns::cache::DnsCache;
use purge_warden::filter::FilterEngine;
use purge_warden::ipc::protocol::{IpcCommand, IpcResponse};
use purge_warden::ipc::socket_client;
use purge_warden::ipc::socket_server::{spawn_ipc_server, DaemonState};
use purge_warden::resource_budget::{ResourceBudgetSnapshot, ResourceBudgetStore};

/// Per-test fixture. The tempdir holds the socket; aborting the handle
/// shuts down the accept loop cleanly.
struct Fixture {
    _tmp: tempfile::TempDir,
    _server: tokio::task::JoinHandle<()>,
    _sampler: tokio::task::JoinHandle<()>,
    socket_path: PathBuf,
    /// The very store `DaemonState` reads on `Status`, so a test can seed it
    /// directly instead of waiting on the sampler's cadence.
    store: ResourceBudgetStore,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self._server.abort();
        self._sampler.abort();
    }
}

/// Spawn the IPC server and the resource-budget sampler against a shared
/// store. `tick` controls the sampler cadence; pass a short interval to
/// observe a sample, or a long one to test the "before first tick" path.
async fn spawn_fixture(tick: Duration, rss_warn_mb: u64) -> Fixture {
    let tmp = tempfile::tempdir().expect("tempdir");
    let socket_path = tmp.path().join("control.sock");
    let cache_config = purge_warden::config::settings::CacheConfig::default();

    let resource_budget_store = purge_warden::resource_budget::types::new_store();
    let sampler = purge_warden::resource_budget::spawn_sampler(
        resource_budget_store.clone(),
        tick,
        rss_warn_mb,
    );

    let state = DaemonState {
        filter: Arc::new(FilterEngine::new()),
        cache: DnsCache::new(&cache_config),
        profiles: None,
        stats: None,
        listen_addr: "127.0.0.1:15353".into(),
        upstream_mode: "plain".into(),
        upstream_count: 0,
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
        daemon_uid: purge_warden::ipc::socket_server::current_euid(),
        resource_budget_store: resource_budget_store.clone(),
        #[cfg(feature = "cluster")]
        cluster_observe: None,
    };

    let server = spawn_ipc_server(socket_path.clone(), Arc::new(state))
        .await
        .expect("spawn_ipc_server");

    Fixture {
        _tmp: tmp,
        _server: server,
        _sampler: sampler,
        socket_path,
        store: resource_budget_store,
    }
}

/// One `Status` round trip, reduced to the field under test.
async fn status_resource_budget(
    socket_path: &Path,
) -> Result<Option<ResourceBudgetSnapshot>, String> {
    match socket_client::send_command(socket_path, &IpcCommand::Status).await {
        Ok(IpcResponse::Status {
            resource_budget, ..
        }) => Ok(resource_budget),
        Ok(other) => Err(format!("expected Status, got {other:?}")),
        Err(e) => Err(format!("Status IPC failed: {e}")),
    }
}

/// Poll `Status` until the daemon reports a resource-budget snapshot, or
/// `budget` elapses.
///
/// This replaces a fixed `sleep`, which was the flake. The sampler is a task
/// on this test's `current_thread` runtime (the `#[tokio::test]` default), so
/// the test body, the sampler and the IPC server all share **one** OS thread —
/// starve it and every timer on it slips together. Measured with 300 competing
/// threads pinned to one core: a nominal 200 ms sleep returned after 385-610 ms
/// and the first snapshot landed at 660-713 ms, so the old fixed budget failed
/// 20 times out of 20. The same probe showed the store never regressed from
/// `Some` back to `None`, i.e. the `/proc` reads were fine — the budget alone
/// was the defect.
///
/// Widening this bound surrenders no real coverage: nothing in the product
/// promises a snapshot inside 200 ms (production `tick_secs` defaults to 5), so
/// that number asserted a latency property the code never owned. What the test
/// is actually for — a snapshot reaching the IPC `Status` response — is
/// asserted unchanged, and every real regression still fails: an unspawned
/// sampler, a store not shared with `DaemonState`, an unpopulated IPC field or
/// broken `/proc` reads all leave the value `None` *forever*, so the loop runs
/// out and reports. The deadline only bounds how long that takes. The elapsed
/// time rides along in the error so a genuine latency regression stays visible
/// rather than being silently absorbed.
async fn await_resource_budget(
    socket_path: &Path,
    budget: Duration,
) -> Result<ResourceBudgetSnapshot, String> {
    let start = Instant::now();
    loop {
        let last = match status_resource_budget(socket_path).await {
            Ok(Some(snap)) => return Ok(snap),
            Ok(None) => "IPC reported `None`".to_string(),
            Err(e) => e,
        };
        if start.elapsed() >= budget {
            return Err(format!(
                "no resource-budget snapshot after {:?} (budget {budget:?}); last outcome: {last}",
                start.elapsed()
            ));
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

/// End-to-end arm: the **real sampler** reads `/proc`, publishes through the
/// shared `ArcSwap`, and the IPC `Status` handler hands it back.
#[tokio::test]
async fn daemon_status_carries_resource_budget_after_sample() {
    // 40 ms tick — sampler skips its first tick, so two ticks ≈ 80 ms on an
    // idle box. `await_resource_budget` is what makes this deterministic on a
    // loaded one; see the rationale there.
    let fx = spawn_fixture(Duration::from_millis(40), 512).await;

    let snap = await_resource_budget(&fx.socket_path, Duration::from_secs(30))
        .await
        .unwrap_or_else(|e| panic!("{e}"));

    assert!(
        snap.rss_mb > 0,
        "running test process always has a nonzero RSS"
    );
    assert!(snap.fd_count > 0, "every process has at least stdin/stdout");
    assert_eq!(
        snap.rss_warn_mb, 512,
        "snapshot must mirror the configured warn threshold"
    );
}

/// Clock-free arm: seed the store the daemon reads and prove `Status` mirrors
/// it field for field.
///
/// Complements the sampler arm above rather than replacing it — that one keeps
/// the real `/proc` sampler in the chain, this one pins the transport with
/// exact values and no timing dependency whatsoever, so a serialisation or
/// field-wiring regression is caught even on a box too loaded to sample.
#[tokio::test]
async fn daemon_status_mirrors_injected_resource_budget_exactly() {
    // 60 s tick — the sampler cannot fire during the test, so the only value
    // that can reach IPC is the one seeded here.
    let fx = spawn_fixture(Duration::from_secs(60), 256).await;

    let injected = ResourceBudgetSnapshot {
        rss_mb: 123,
        vsz_mb: 4567,
        fd_count: 42,
        cpu_user_pct: 7,
        rss_warn_mb: 256,
    };
    fx.store.store(Arc::new(Some(injected)));

    let got = status_resource_budget(&fx.socket_path)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        got,
        Some(injected),
        "IPC must mirror the stored snapshot field for field"
    );
}

#[tokio::test]
async fn daemon_status_resource_budget_is_none_before_first_tick() {
    // 60 s tick — by the time we poll, the sampler hasn't fired its
    // first real tick yet (it skips the initial one too), so the store
    // still holds `None`.
    let fx = spawn_fixture(Duration::from_secs(60), 256).await;

    let resp = socket_client::send_command(&fx.socket_path, &IpcCommand::Status)
        .await
        .expect("Status IPC");
    match resp {
        IpcResponse::Status {
            resource_budget, ..
        } => assert!(
            resource_budget.is_none(),
            "before the first sampler tick, IPC must report `None`"
        ),
        other => panic!("expected Status, got {other:?}"),
    }
}
