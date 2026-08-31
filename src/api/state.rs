//! Shared state for all API handlers.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use crate::auth::middleware::AuthRateLimiter;
use crate::dns::cache::DnsCache;
use crate::filter::FilterEngine;
use crate::lists::status::ListStatusRegistry;
use crate::profiles::ProfileResolver;
use crate::tracking::StatsEngine;
use crate::upstream::resolver::UpstreamResolver;

/// State shared across all API routes via `axum::extract::State`.
pub struct ApiState {
    pub filter: Arc<FilterEngine>,
    pub cache: DnsCache,
    pub profiles: Option<Arc<ProfileResolver>>,
    pub stats: Option<Arc<StatsEngine>>,
    /// Path to config.toml (for mutation endpoints).
    pub config_path: PathBuf,
    /// SHA-256 hash of the valid API token.
    pub token_hash: String,
    /// Auth failure rate limiter.
    pub rate_limiter: AuthRateLimiter,
    /// Per-IP request-rate limiter for authed `/api/*` routes (wires
    /// `api.rate_limit_per_minute`, rev-2606 `api-auth-07-03`). Disjoint
    /// from `rate_limiter` (auth-failure lockout, §4.48) by design —
    /// separate map, separate concern, zero shared state.
    pub api_rate_limiter: crate::api::rate_limit::ApiRateLimiter,
    /// Channel to trigger config+list reload (shared with signal loop).
    /// Payload is the invoker uid from `SO_PEERCRED`; API callers have no
    /// peer-cred (they come via HTTP), so they send `None` — the audit log
    /// records the reload as signal-like, while the API mutation itself is
    /// separately audited via the `tracing::info!(target: "audit")` line.
    pub reload_tx: tokio::sync::mpsc::Sender<Option<u32>>,
    /// Daemon start time (for uptime calculation).
    pub started_at: Instant,
    /// Upstream resolver for health checks.
    pub upstream: Option<Arc<UpstreamResolver>>,
    // Metadata for /api/status
    pub listen_addr: String,
    pub upstream_mode: String,
    pub upstream_count: usize,
    pub list_count: usize,
    /// Sprint 43 T2: shared handle to per-source `ListStatus`. `None`
    /// when the daemon was started with no `[lists].sources` (filter
    /// disabled). The `GET /api/blocklists/:id/stats` handler reads
    /// through this Arc; the list manager updates it atomically on
    /// each refresh cycle. Mirrors the `DaemonState.list_statuses`
    /// field T1 added — same registry, two readers (IPC + HTTP).
    pub list_statuses: Option<Arc<ListStatusRegistry>>,
    /// §4.2 G1a — bit → blocklist-label snapshot, cloned from the same
    /// `Arc` as `DaemonState.list_labels`. Lets `GET /api/query/{domain}`
    /// render block attribution (`BlockSource::List(bit)` → `list:<name>`)
    /// without re-reading the catalog. Same data, two readers (IPC +
    /// HTTP) — mirrors `list_statuses` above.
    pub list_labels: Arc<Vec<Option<String>>>,
    /// Serialise concurrent config-mutating handlers against each other
    /// AND against the IPC mutation path. Cloned from the same `Arc` that
    /// `DaemonState.config_write_lock` holds, so an IPC `warden blocklist
    /// add` and an API `POST /api/lists/add` cannot observe each other's
    /// read-modify-write window. Acquired only by
    /// [`ApiState::mutate_config`] — see there for why the guard never
    /// reaches a handler.
    pub config_write_lock: Arc<tokio::sync::Mutex<()>>,
    /// §4.11-2 — cluster serve-state (CS4): generations, content hashes, and the
    /// pre-serialised policy / domain-map artifacts the `/api/cluster/*`
    /// handlers return, plus the cluster bearer token + `allow_peer` gate. `Some`
    /// only when `cluster.enabled && role == primary && api.enabled` at boot —
    /// the cluster routes mount iff this is `Some` (`api::routes::build_router`).
    /// Behind the `cluster` feature so the default build is byte-identical.
    #[cfg(feature = "cluster")]
    pub cluster: Option<Arc<crate::cluster::ClusterState>>,
    /// §4.11-4 — shared cluster observability handle (CS9). The heartbeat
    /// handler WRITES the per-peer roster through this; the IPC `ClusterStatus`
    /// reader (on `DaemonState`) reads the same `Arc`. `Some` only on an
    /// enabled primary (mirrors `cluster` above). Same handle, two readers —
    /// the `list_statuses` "one registry, IPC + HTTP" pattern.
    #[cfg(feature = "cluster")]
    pub cluster_observe: Option<Arc<crate::cluster::ClusterObserve>>,
}

impl ApiState {
    /// Run one config mutation while holding the config write lock.
    ///
    /// The guard is taken and released inside this function, so a handler
    /// cannot hold it across the reload notification and deadlock the
    /// capacity-1 reload channel: that half of the contract is a property
    /// of this scope, not a rule each handler has to restate. Sending the
    /// notification stays with the caller, because only the caller knows
    /// whether its own outcome is a change worth reloading for.
    ///
    /// Takes a closure rather than a ready-made future on purpose:
    /// `tokio::task::spawn_blocking` starts its work at call time, so a
    /// future built by the caller would run the mutation before the lock
    /// had been acquired.
    pub async fn mutate_config<F, Fut, T>(&self, mutate: F) -> T
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = T>,
    {
        let _guard = self.config_write_lock.lock().await;
        mutate().await
    }
}
