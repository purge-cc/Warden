//! Start the DNS filtering server — foreground or daemon mode.
//!
//! When started, the server:
//! 1. Loads and validates the config file
//! 2. Builds list→bit mapping and profile resolver
//! 3. Optionally downloads blocklists from configured sources
//! 4. Starts the DNS server on the configured listen address
//! 5. Enters a signal loop: SIGTERM/SIGINT→shutdown, SIGHUP→reload
//!    (cache flush is NOT signal-based; use the authenticated IPC command)
//! 6. On shutdown: retires background tasks, removes PID file, exits cleanly

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context;
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

use crate::config::audit::{self, AuditEvent, AuditRecord, AuditResult, AuditWriter};
use crate::config::custom_list::CustomListStore;
use crate::config::secrets;
use crate::dns::cache::DnsCache;
use crate::dns::handler::{ForwardHandler, SecurityLayer};
use crate::dns::local::LocalRecords;
use crate::dns::server::DnsServer;
use crate::filter::engine::FilterEngine;
use crate::filter::ip_filter::{parse_ip_blocklist, IpFilter};
use crate::filter::operator_rules::{CompiledOperatorRules, RuleCompileLimits};
use crate::ipc::socket_server::{spawn_ipc_server, DaemonState, ListManagerEndpoint};
use crate::lists::catalog::Catalog;
use crate::lists::manager::{ListManager, ListManagerTask, RefreshMode};
use crate::lists::readiness::ReadinessGate;
use crate::lists::source_key::{ResolvedSourcePlan, SourceBitMap, SourceTokenMap, SourceTrustMap};
use crate::lists::status::{CycleOutcome, ListStatusRegistry};
use crate::operator_rules::activation::{
    new_daemon_instance_id, ActivationRequest, ActivationResult, ActivePolicyIdentity,
};
use crate::profiles::ProfileResolver;
use crate::tracking::StatsEngine;
use crate::upstream::ReloadableUpstream;

use super::pid;

#[cfg(feature = "cluster")]
mod nodes_runtime;

#[cfg(feature = "cluster")]
pub(crate) use nodes_runtime::preflight_received as preflight_received_corpus;
#[cfg(feature = "cluster")]
pub(crate) use nodes_runtime::preflight_received_manifest;

/// Build the hardcoded safe-mode configuration.
///
/// The returned [`ConfigV1`](crate::config::schema::ConfigV1) ignores every on-disk file under
/// `/etc/purge-warden/` (or the operator's `--config` target). Its
/// purpose is to regain control of a daemon whose on-disk config is
/// broken or malicious:
///
/// - **Listen** on `127.0.0.1:5335` — unprivileged port, loopback-only
///   so a misconfigured open-resolver posture cannot be triggered from
///   the LAN while recovering.
/// - **Upstream** a reserved, unroutable documentation address
///   (RFC 5737 TEST-NET-1) — never dialled, because every query is
///   REFUSED before forwarding. Any system-resolver path is bypassed so a
///   poisoned `/etc/resolv.conf` can't reinfect the recovery session, and
///   warden names no provider of its own.
/// - **Source ACL** restricted to `127.0.0.1/32` via
///   `server.allow_from` — belt-and-suspenders with the loopback bind.
/// - **No filtering** — empty blocklists, empty profile map,
///   `default_profile = None`. Every query is REFUSED at level 5 so the
///   operator sees exactly which sources would have reached the
///   daemon, with zero filtering behaviour to misdiagnose.
/// - **Cache disabled, tracking disabled, API disabled** — nothing
///   writes to disk, nothing listens on the network except the DNS
///   recovery socket.
/// - **IPC enabled** on the standard socket so the operator can
///   `warden status` / `warden config …` against the running safe-mode
///   daemon and repair the live config.
pub fn safe_mode_config() -> crate::config::schema::ConfigV1 {
    use crate::config::schema::{
        ConfigV1, ResourceBudgetConfig, ServerGlobals, TARGET_SCHEMA_VERSION_V5,
    };
    use crate::config::settings::{
        AntiBypassConfig, ApiConfig, CacheConfig, DnssecConfig, IpBlocklistConfig, ListsConfig,
        LocalDnsConfig, SecurityConfig, SocketConfig, TrackingConfig, UpstreamConfig, UpstreamMode,
    };

    ConfigV1 {
        schema_version: TARGET_SCHEMA_VERSION_V5,
        includes: Vec::new(),
        server: ServerGlobals {
            listen: "127.0.0.1:5335"
                .parse()
                .expect("hardcoded literal is valid"),
            log_level: "info".to_string(),
            tcp_timeout_secs: 10,
            enforce_device_mac: false,
            allow_from: vec!["127.0.0.1/32".to_string(), "::1/128".to_string()],
            default_profile: None, // REFUSED at level 5
            default_block_response: Default::default(),
            default_blocked_ttl_secs: 60,
        },
        retired: Vec::new(),
        blocklists: Vec::new(),
        profiles: Default::default(),
        devices: Vec::new(),
        groups: Vec::new(),
        subnets: Vec::new(),
        schedules: Vec::new(),
        admin_rules: Vec::new(),
        custom_lists: Vec::new(),
        custom_list_limits: Default::default(),
        labels: Vec::new(),
        upstream: UpstreamConfig {
            mode: UpstreamMode::Plain,
            // RFC 5737 TEST-NET-1 — reserved for documentation, unroutable,
            // and names no provider. Safe mode REFUSEs every query
            // (`default_profile: None`), so this is never dialled; it exists
            // only because the validator refuses an empty server list.
            servers: vec!["192.0.2.1:53".to_string()],
            timeout_ms: 5000,
            fallback: None,
            dot: Default::default(),
            ecs: Default::default(),
        },
        // Cache defaults are fine — it's a best-effort, purely in-memory
        // LRU; nothing persists to disk. Leaving it on avoids any
        // surprising misses during the recovery session.
        cache: CacheConfig::default(),
        tracking: TrackingConfig {
            enabled: false,
            ..Default::default()
        },
        security: SecurityConfig {
            enabled: false,
            ..Default::default()
        },
        anti_bypass: AntiBypassConfig::default(),
        socket: SocketConfig::default(),
        api: ApiConfig::default(),
        forwarding: Vec::new(),
        local_dns: LocalDnsConfig::default(),
        ip_blocklists: IpBlocklistConfig::default(),
        // Empty sources → the download path is short-circuited in
        // `run_server`, so no network traffic at all.
        lists: ListsConfig::default(),
        // Defaults inherit `tick_secs = 5` and the meminfo-derived RSS warn
        // threshold. Safe-mode keeps the sampler active so the operator
        // still sees daemon RSS while debugging.
        resource_budget: ResourceBudgetConfig::default(),
        // DNSSEC off by default; safe mode performs no validation.
        dnssec: DnssecConfig::default(),
        // `[backup]` is tooling-only; safe mode inherits the default dir.
        backup: Default::default(),
        // Clustering off in safe mode; the section is inert.
        cluster: Default::default(),
        node: Default::default(),
    }
}

/// Refuse to start when a DNSSEC validation mode is configured on a binary
/// built without the `dnssec` feature.
///
/// The [`DnssecMode`](crate::config::settings::DnssecMode) variants deserialize
/// on any build (mirroring `UpstreamMode::Doq`), so a config can request
/// validation that a feature-less binary cannot perform. Fail here with an
/// actionable error rather than silently ignoring the setting — the same
/// contract as the DoQ `build_upstream` feature bail. When the feature *is*
/// built in, the mode is accepted and DNSSEC validation runs on the response
/// path.
pub(crate) fn check_dnssec_build(config: &crate::config::schema::ConfigV1) -> anyhow::Result<()> {
    #[cfg(not(feature = "dnssec"))]
    if config.dnssec.mode != crate::config::settings::DnssecMode::Off {
        anyhow::bail!(
            "DNSSEC validation (dnssec.mode = \"{}\") requires building with `--features dnssec`",
            config.dnssec.mode
        );
    }
    #[cfg(feature = "dnssec")]
    if config.dnssec.mode != crate::config::settings::DnssecMode::Off {
        tracing::info!(
            mode = %config.dnssec.mode,
            "DNSSEC validation active (§4.10-4b): upstream answers are validated against the IANA root trust anchors"
        );
    }
    Ok(())
}

/// Handle to the cluster serve-state threaded through the reload path. A
/// zero-sized `PhantomData` when the `cluster` feature is off, so
/// [`signal_loop`] / [`handle_reload`] keep ONE signature on every build.
#[cfg(feature = "cluster")]
type ClusterReloadHandle<'a> = Option<&'a Arc<crate::cluster::ClusterState>>;
#[cfg(not(feature = "cluster"))]
type ClusterReloadHandle<'a> = std::marker::PhantomData<&'a ()>;

#[derive(Debug, Clone, PartialEq, Eq)]
struct RestartOnlyRuntimeFingerprint {
    server: String,
    custom_list_limits: String,
    cache: String,
    tracking: String,
    socket: String,
    api: String,
    local_dns: String,
    ip_blocklists: String,
    anti_bypass: String,
    security_topology: String,
    resource_budget: String,
    cluster: String,
    node_identity: Option<String>,
    node_control_listen: Option<std::net::SocketAddr>,
}

impl RestartOnlyRuntimeFingerprint {
    fn from_config(config: &crate::config::schema::ConfigV1) -> anyhow::Result<Self> {
        #[derive(serde::Serialize)]
        struct ServerRuntime<'a> {
            listen: std::net::SocketAddr,
            log_level: &'a str,
            tcp_timeout_secs: u64,
        }

        #[derive(serde::Serialize)]
        struct TrackingRuntime<'a> {
            enabled: bool,
            snapshot_interval_secs: u64,
            top_n_limit: usize,
            top_n_interval_secs: u64,
            max_devices: usize,
            query_log_path: &'a Path,
            query_log_max_size_mb: u64,
            query_log_max_files: usize,
            retention_days: u32,
            log_mode: &'a crate::config::settings::LogMode,
        }

        #[derive(serde::Serialize)]
        struct ApiRuntime<'a> {
            enabled: bool,
            metrics_enabled: bool,
            listen: std::net::SocketAddr,
            tls_cert: &'a Option<PathBuf>,
            tls_key: &'a Option<PathBuf>,
            rate_limit_per_minute: u32,
        }

        #[derive(serde::Serialize)]
        struct SecurityTopology {
            enabled: bool,
            rrl_enabled: bool,
            rate_limit_enabled: bool,
            tunneling_enabled: bool,
        }

        Ok(Self {
            server: toml::to_string(&ServerRuntime {
                listen: config.server.listen,
                log_level: &config.server.log_level,
                tcp_timeout_secs: config.server.tcp_timeout_secs,
            })?,
            custom_list_limits: toml::to_string(&config.custom_list_limits)?,
            cache: toml::to_string(&config.cache)?,
            tracking: toml::to_string(&TrackingRuntime {
                enabled: config.tracking.enabled,
                snapshot_interval_secs: config.tracking.snapshot_interval_secs,
                top_n_limit: config.tracking.top_n_limit,
                top_n_interval_secs: config.tracking.top_n_interval_secs,
                max_devices: config.tracking.max_devices,
                query_log_path: &config.tracking.query_log_path,
                query_log_max_size_mb: config.tracking.query_log_max_size_mb,
                query_log_max_files: config.tracking.query_log_max_files,
                retention_days: config.tracking.retention_days,
                log_mode: &config.tracking.log_mode,
            })?,
            socket: toml::to_string(&config.socket)?,
            api: toml::to_string(&ApiRuntime {
                enabled: config.api.enabled,
                metrics_enabled: config.api.metrics_enabled,
                listen: config.api.listen,
                tls_cert: &config.api.tls_cert,
                tls_key: &config.api.tls_key,
                rate_limit_per_minute: config.api.rate_limit_per_minute,
            })?,
            local_dns: toml::to_string(&config.local_dns)?,
            ip_blocklists: if config.cluster.enabled && config.cluster.membership_version == Some(1)
            {
                String::new()
            } else {
                toml::to_string(&config.ip_blocklists)?
            },
            anti_bypass: toml::to_string(&config.anti_bypass)?,
            security_topology: toml::to_string(&SecurityTopology {
                enabled: config.security.enabled,
                rrl_enabled: config.security.rrl.enabled,
                rate_limit_enabled: config.security.rate_limit.enabled,
                tunneling_enabled: config.security.tunneling.enabled,
            })?,
            resource_budget: toml::to_string(&config.resource_budget)?,
            cluster: toml::to_string(&config.cluster)?,
            node_identity: config.node.id.clone(),
            node_control_listen: config.node.control_listen,
        })
    }

    fn changed_sections(&self, candidate: &Self) -> Vec<&'static str> {
        let mut changed = Vec::new();
        if self.node_identity != candidate.node_identity {
            changed.push("node identity");
        }
        if self.node_control_listen != candidate.node_control_listen {
            changed.push("node control listener");
        }
        if self.server != candidate.server {
            changed.push("server startup fields");
        }
        if self.custom_list_limits != candidate.custom_list_limits {
            changed.push("custom_list_limits");
        }
        if self.cache != candidate.cache {
            changed.push("cache");
        }
        if self.tracking != candidate.tracking {
            changed.push("tracking runtime");
        }
        if self.socket != candidate.socket {
            changed.push("socket");
        }
        if self.api != candidate.api {
            changed.push("api runtime");
        }
        if self.local_dns != candidate.local_dns {
            changed.push("local_dns");
        }
        if self.ip_blocklists != candidate.ip_blocklists {
            changed.push("ip_blocklists");
        }
        if self.anti_bypass != candidate.anti_bypass {
            changed.push("anti_bypass");
        }
        if self.security_topology != candidate.security_topology {
            changed.push("security enabled flags");
        }
        if self.resource_budget != candidate.resource_budget {
            changed.push("resource_budget");
        }
        if self.cluster != candidate.cluster {
            changed.push("cluster");
        }
        changed
    }
}

#[derive(Clone, Copy)]
struct RuntimeReloadContext<'a> {
    client: &'a reqwest::Client,
    upstream: &'a Arc<ReloadableUpstream>,
    cache: &'a DnsCache,
    restart_only: &'a RestartOnlyRuntimeFingerprint,
    #[cfg(feature = "cluster")]
    node_ip_filter: Option<&'a Arc<crate::filter::ip_filter::IpFilter>>,
    #[cfg(feature = "cluster")]
    node_observe: Option<&'a Arc<crate::cluster::ClusterObserve>>,
}

fn modern_primary_auxiliary(config: &crate::config::schema::ConfigV1) -> bool {
    cfg!(feature = "cluster")
        && config.cluster.enabled
        && config.cluster.membership_version == Some(1)
        && config.cluster.role == crate::config::schema::ClusterRole::Primary
        && config.ip_blocklists.enabled
        && !config.ip_blocklists.sources.is_empty()
}

/// Refuse to start when clustering is enabled on a binary built without the
/// `cluster` feature (mirrors [`check_dnssec_build`]). The `[cluster]` section
/// deserialises on any build, so a config can request a serve role a
/// feature-less binary cannot perform — fail with an actionable error rather
/// than silently ignoring it.
pub(crate) fn check_cluster_build(config: &crate::config::schema::ConfigV1) -> anyhow::Result<()> {
    #[cfg(not(feature = "cluster"))]
    if config.cluster.enabled {
        anyhow::bail!(
            "cluster replication (cluster.enabled = true) requires building with \
             `--features cluster`"
        );
    }
    #[cfg(feature = "cluster")]
    let _ = config; // serve-side compiled in; activation is in `build_cluster_state`
    Ok(())
}

/// Build the replication serve-state when this node is an enabled primary.
/// Returns `None` for a standalone node or a secondary. The state serves on
/// the administrative API when enabled and on an active Nodes listener in all
/// cases. Seeds `config_generation = 1`; the map artifact is seeded by the
/// first refresh.
#[cfg(feature = "cluster")]
fn build_cluster_state(
    config: &crate::config::schema::ConfigV1,
    config_path: &Path,
    snapshot: Option<Arc<crate::cluster::artifact::PolicySnapshot>>,
    active: Option<ActivePolicyIdentity>,
) -> anyhow::Result<Option<Arc<crate::cluster::ClusterState>>> {
    use crate::config::schema::ClusterRole;

    let c = &config.cluster;
    if !c.enabled || c.role != ClusterRole::Primary {
        return Ok(None);
    }
    // `token_hash` is validator-guaranteed `Some` when `enabled`; the
    // unwrap_or_default fail-closes (an empty hash never verifies). Each
    // `allow_peer` entry is validator-guaranteed parseable.
    let token_hash = c.token_hash.clone().unwrap_or_default();
    let allow_peer: Vec<crate::config::cidr::Cidr> = c
        .allow_peer
        .iter()
        .filter_map(|s| crate::config::cidr::Cidr::parse(s).ok())
        .collect();
    let mut state = crate::cluster::ClusterState::new(c.role, c.priority, token_hash, allow_peer);
    if c.membership_version == Some(1) {
        state.configure_membership(
            config_path.to_path_buf(),
            c.cluster_id.clone().context("cluster identity missing")?,
            c.primary_node_id
                .clone()
                .context("primary node identity missing")?,
        )?;
    }
    let snapshot = snapshot.ok_or_else(|| {
        anyhow::anyhow!("cluster publication requires a coherent active policy capture")
    })?;
    let guard = crate::config::write_lock::acquire_for_migration(config_path)?;
    if state.membership_context().is_some() {
        state.record_membership_roster(
            crate::cluster::membership::MembershipStore::open(&guard)?
                .views(crate::cluster::membership::now()?),
        );
    }
    state.update_policy(&guard, snapshot)?;
    if let Some(active) = active {
        state.set_primary_active_identity(active);
    }
    tracing::info!(
        priority = c.priority,
        allow_peer = c.allow_peer.len(),
        "cluster: primary replication state ready"
    );
    Ok(Some(Arc::new(state)))
}

/// True when this node is an enabled cluster secondary. Gates the one
/// secondary-specific behaviour: running the poll loop, and handing it the
/// reload channel it signals after installing a bundle. A secondary
/// downloads and builds its own lists like any other node — nothing ships
/// it a map to protect.
///
/// Feature-gated: a feature-less binary bails at startup when
/// `cluster.enabled`, so it never reaches this path, and the default build
/// does not compile the call site.
#[cfg(feature = "cluster")]
fn is_cluster_secondary(config: &crate::config::schema::ConfigV1) -> bool {
    use crate::config::schema::ClusterRole;
    config.cluster.enabled && config.cluster.role == ClusterRole::Secondary
}

/// Does this node build its own Tier-1 filter map?
///
/// One predicate with three consumers that MUST agree, or the daemon either
/// refuses to bind on a node that never needed a map or answers queries on a
/// node that does:
///
/// 1. whether to construct and run a [`ListManager`] at all,
/// 2. the seed of the readiness gate — closed iff this returns `true`,
/// 3. which side of the bind branches (b) and (c) live on.
///
/// **Not "are any blocklists configured".** The resolved source plan combines
/// legacy entries and enabled rows, so either configuration shape can start a
/// manager.
///
/// **A cluster secondary is not an exception.** Replication is policy only —
/// a secondary derives its own bitmask from the replicated policy exactly as
/// a standalone node does, so it always builds its own map.
///
/// `config` is therefore unused today. It stays in the signature because the
/// question "does this node build its own map?" is a property of the node,
/// not of its source list, and the tests pinning that answer are written
/// against a config.
fn boot_spawns_list_manager(
    merged_sources: &[String],
    config: &crate::config::schema::ConfigV1,
) -> bool {
    let _ = config;
    !merged_sources.is_empty()
}

/// True when the operator declared any source, before catalog resolution.
/// This distinguishes an intentional clear from a broken/empty catalog.
pub(crate) fn config_declares_list_sources(config: &crate::config::schema::ConfigV1) -> bool {
    !config.lists.sources.is_empty() || config.blocklists.iter().any(|blocklist| blocklist.enabled)
}

/// Reject only the ambiguity where declared sources resolve to nothing.
/// A partially resolved legacy set keeps the established warning-only
/// behavior; an actually empty configuration remains an intentional clear.
fn rejects_declared_empty_plan(
    config: &crate::config::schema::ConfigV1,
    plan: &ResolvedSourcePlan,
) -> bool {
    config_declares_list_sources(config) && plan.is_empty()
}

/// Refusal shown when `warden start --blocklist <file>` is used.
///
/// The flag read the file into the first of the filter engine's list
/// slots without registering a list to own that slot. Whether those
/// domains were ever blocked therefore depended on whether some
/// unrelated subscribed list happened to occupy the same slot: with no
/// lists configured they were silently ignored, and with lists
/// configured they were filtered for exactly the clients that the first
/// of those lists applied to. Neither is something an operator can
/// predict from the command they typed, so the flag now names the verb
/// that imports a local file properly.
const START_BLOCKLIST_FLAG_RETIRED: &str = "\
`--blocklist` cannot load a blocklist. Whether its domains were blocked depended on \
which other lists were configured, so the same command filtered differently on two \
machines and silently did nothing on a machine with no lists at all.

Import the file as a list, then start:
  warden blocklist import-local <file> --id <name> --kind deny
  warden start

The imported list is filtered for a client whose tags match it, the same as any other.";

/// Whether DNS readiness attests that the authoritative schema-5 tree was loaded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeCapabilityAttestation {
    /// The in-memory config did not come from the authoritative tree.
    Disabled,
    /// The in-memory config is a validated schema-5 load of that tree.
    AuthoritativeSchema5Tree,
}

/// Why the foreground daemon returned after completing graceful cleanup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StartOutcome {
    /// An operator or process signal stopped the daemon.
    Stopped,
    /// A durable node operation requested a fresh supervised process.
    #[cfg(feature = "cluster")]
    ManagedRestart(crate::cluster::managed_restart::ManagedRestartRequest),
}

/// Start the DNS filtering server from a validated v1 [`ConfigV1`](crate::config::schema::ConfigV1).
pub async fn run_start(
    config: &crate::config::schema::ConfigV1,
    custom_lists: &CustomListStore,
    config_path: &Path,
    pid_file: &Path,
    blocklist_path: Option<&str>,
    runtime_lease: crate::config::runtime_lease::RuntimeLease,
    runtime_attestation: RuntimeCapabilityAttestation,
) -> anyhow::Result<StartOutcome> {
    // Refuse a DNSSEC mode the binary cannot honor before binding sockets.
    check_dnssec_build(config)?;
    // Refuse clustering on a feature-less binary before binding sockets.
    check_cluster_build(config)?;

    tracing::info!(
        listen = %config.server.listen,
        upstream_mode = %config.upstream.mode,
        upstream = ?config.upstream.servers,
        "starting purge-warden"
    );

    // Acquire an exclusive flock on the PID file. The kernel enforces
    // mutual exclusion — no TOCTOU race. A stale file from a crashed
    // instance is harmless: the lock was released when the process died,
    // so we re-acquire it and overwrite the contents.
    let _pid_lock = match pid::acquire_pid_lock(pid_file) {
        Ok(lock) => lock,
        Err(pid::PidLockError::AlreadyRunning(pid)) => {
            let msg = match pid {
                Some(p) => format!(
                    "purge-warden is already running (PID {p}). \
                     Stop it first with `warden stop`."
                ),
                None => "another purge-warden instance holds the PID file lock. \
                         Stop it first with `warden stop`."
                    .to_string(),
            };
            anyhow::bail!(msg);
        }
        Err(pid::PidLockError::Io(e)) => {
            return Err(anyhow::anyhow!("PID file {}: {e}", pid_file.display()));
        }
    };

    // _pid_lock is held for the entire server lifetime. On exit (normal
    // or panic), dropping the File releases the flock. We still remove
    // the PID file as a courtesy so `warden status` doesn't see a stale
    // file, but the lock is what actually prevents double-start.
    let result = run_server(
        config,
        custom_lists,
        config_path,
        blocklist_path,
        &runtime_lease,
        runtime_attestation,
    )
    .await;

    pid::remove_pid_file(pid_file);

    if result.is_err() {
        tracing::error!("startup failed, PID file cleaned up");
    } else {
        tracing::info!("purge-warden stopped");
    }

    result
}

/// Publish retirement before any asynchronous shutdown work can leave a
/// previously accepted IPC handler looking at a running list manager.
fn publish_list_manager_transitioning(endpoint: &Arc<arc_swap::ArcSwap<ListManagerEndpoint>>) {
    endpoint.store(Arc::new(ListManagerEndpoint::Transitioning));
}

/// Core server startup + signal loop. Separated so the caller can
/// guarantee PID file cleanup regardless of how this returns.
async fn run_server(
    config: &crate::config::schema::ConfigV1,
    custom_lists: &CustomListStore,
    config_path: &Path,
    blocklist_path: Option<&str>,
    runtime_lease: &crate::config::runtime_lease::RuntimeLease,
    runtime_attestation: RuntimeCapabilityAttestation,
) -> anyhow::Result<StartOutcome> {
    let started_at = Instant::now();
    let daemon_instance_id = new_daemon_instance_id()?;
    let compile_admission_bytes = RuleCompileLimits::HARD_CEILINGS
        .max_compiled_bytes_total
        .checked_mul(2)
        .context("operator-rule admission ceiling overflow")?;
    let candidate_runtime = Arc::new(crate::operator_rules::PolicyCandidateRuntime::new(
        crate::filter::operator_rules::CompileAdmission::new(compile_admission_bytes, 1)?,
    ));

    // Load the separate secrets file BEFORE anything else
    // binds a port or touches the network. The loader hard-refuses any
    // mode wider than 0600, so a misplaced `chmod 0644` means the daemon
    // never binds port 53 — the operator sees a plain-English error and
    // fixes the permission before retrying. A missing file is treated
    // as "no secrets configured" (empty `Secrets`), which downgrades
    // `auth_token_ref` lookups on blocklists to a later, clearer error
    // instead of a cryptic boot failure.
    let secrets_path = secrets::secrets_path_for(config_path);
    let secrets = match secrets::load_secrets(&secrets_path) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = %e, "secrets file rejected");
            anyhow::bail!("secrets file rejected: {e}");
        }
    };
    if secrets.is_loaded() {
        tracing::info!(
            path = %secrets_path.display(),
            count = secrets.len(),
            "secrets file loaded"
        );
    }

    // Open the audit log writer before any state change so the Boot
    // record is the first line in the file for this
    // lifetime. The directory is created with mode 0750 and the file
    // with mode 0640 on first open. Failure to open the audit log
    // surfaces as a daemon-start failure (no silent drops) — audit
    // integrity is a boot-critical invariant, not an optional extra.
    let audit_path = audit_log_path(config_path);
    let audit_writer = match AuditWriter::open(audit_path.clone()) {
        Ok(w) => w,
        Err(e) => {
            tracing::error!(
                path = %audit_path.display(),
                error = %e,
                "cannot open audit log"
            );
            anyhow::bail!("cannot open audit log at {}: {}", audit_path.display(), e);
        }
    };

    // This is the boot lifecycle owner for validator audit warnings. The
    // first config read precedes tracing setup, while later policy capture is
    // intentionally quiet to avoid reporting the same configuration twice.
    let boot_files = collect_loaded_files(config_path);
    let boot_hash = audit::tree_hash(boot_files.iter());
    let _ = audit_writer.append(
        &AuditRecord::new(AuditEvent::Boot, AuditResult::Ok)
            .with_uid(None)
            .with_files(boot_files.iter())
            .with_post_hash(boot_hash.clone()),
    );

    // One-shot migration of the admin token from the legacy XDG-spec path
    // (`$HOME/.config/purge-warden/token` or
    // `$XDG_CONFIG_HOME/purge-warden/token`) to the FHS canonical path
    // (`/var/lib/purge-warden/token`). Idempotent: if the FHS path
    // already exists, the call is a no-op. Failure modes are non-fatal
    // — the helper logs a warning and boot continues, since losing the
    // migration only means the operator runs `warden token regenerate`
    // once to land a fresh token at the new path. Without this, a daemon
    // user whose `$HOME` is missing (`/home/purge-warden` not created at
    // install) silently breaks Admin-tier IPC verbs and renders TUI
    // graphs empty.
    crate::ipc::auth_token::ensure_fhs_token_path();

    // Two HTTP clients with different trust models:
    //
    // - `list_client` is hardened: HTTPS-only, literal private/loopback
    //   hosts rejected, redirects capped. Used for blocklist and catalog
    //   downloads, which reach external servers we do not control.
    //
    //   It is the tight one, and it is NO LONGER on the boot path for list
    //   bodies: `load_corpus_before_bind` runs `refresh_with_mode(CacheOnly)`,
    //   which reaches no network at all, and hands the manager
    //   `build_bulk_list_client` before its first cycle of any mode. What
    //   still uses this client pre-bind is the catalog fetch and the
    //   IP-blocklist source loop. A total deadline is a bandwidth-dependent
    //   size cap (see `http_client`'s module docs) — appropriate for those
    //   two, which fetch small bodies, and precisely the reason it must NOT
    //   be given to list downloads: 30s at the measured ~1 MB/s is a 30 MB
    //   ceiling, and the lists that matter are 100-180 MB.
    // - `upstream_client` is permissive. Used for DoH upstreams and the
    //   forwarding router, where the operator deliberately chose the endpoint
    //   and may legitimately point at their own (private) DoH resolver.
    let list_client = crate::lists::http_client::build_list_client(Duration::from_secs(30))?;
    // `.no_gzip()` is deliberate and it is NOT redundant.
    //
    // reqwest's gzip default is per-*client*, not per-call: once the `gzip`
    // feature compiles, every `Client::builder()` in the process advertises
    // `Accept-Encoding: gzip` unless it opts out here. That feature was enabled
    // for blocklist downloads, where it is worth ~3.3x; this client answers DoH
    // queries, where it is worth nothing — responses are small binary
    // `application/dns-message` that no resolver compresses.
    //
    // So the choice is between a free header on every DNS query and no delta at
    // all on the upstream path. Take no delta: warden's DoH path has failed
    // *closed* on a protocol-negotiation change before (HTTP/1.1-only
    // negotiation drew a 505 from Quad9 and blocked every query), and a change
    // nobody asked for on the path that answers every lookup is not the place to
    // spend that risk. Note `.no_gzip()` exists whether or not the feature is on,
    // so this line keeps compiling if the feature is ever dropped.
    let upstream_client = reqwest::Client::builder()
        .user_agent("purge-warden/0.1")
        .timeout(Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::limited(3))
        .no_gzip()
        .build()?;

    let upstream_runtime = Arc::new(ReloadableUpstream::from_config(
        &config.upstream,
        &config.forwarding,
        &upstream_client,
        &config.dnssec,
    )?);
    let upstream: Arc<dyn crate::upstream::Upstream> = upstream_runtime.clone();

    // `--blocklist` is refused rather than honoured — see
    // [`START_BLOCKLIST_FLAG_RETIRED`] for why loading the file was worse
    // than not having the flag.
    if blocklist_path.is_some() {
        anyhow::bail!("{START_BLOCKLIST_FLAG_RETIRED}");
    }
    let filter = Arc::new(FilterEngine::new());

    #[cfg(feature = "cluster")]
    let node_corpus = nodes_runtime::NodeCorpusRuntime::load(
        config_path,
        config,
        runtime_attestation == RuntimeCapabilityAttestation::AuthoritativeSchema5Tree,
    )?;
    #[cfg(feature = "cluster")]
    let (node_ip_filter, node_auxiliary) = match &node_corpus {
        Some(context) => nodes_runtime::prepare_ip_filter(config, &list_client, context).await?,
        None => (None, Vec::new()),
    };

    let has_enabled_sources =
        config_declares_list_sources(config) || modern_primary_auxiliary(config);
    let lists_dir = has_enabled_sources.then(|| lists_cache_dir(config_path, config));
    #[cfg(feature = "cluster")]
    let received_catalog = node_corpus.as_ref().and_then(|context| {
        context
            .secondary
            .as_ref()
            .map(|manifest| manifest.catalog())
    });
    #[cfg(not(feature = "cluster"))]
    let received_catalog: Option<Catalog> = None;
    let catalog = match received_catalog {
        Some(catalog) => catalog,
        None => match &lists_dir {
            Some(dir) => {
                fetch_catalog_or_fallback(&list_client, dir, CatalogPreference::Disk).await
            }
            None => Catalog::fallback(),
        },
    };
    let source_plan = ResolvedSourcePlan::build_for_schema(
        &catalog,
        &config.lists.sources,
        &config.blocklists,
        &config.profiles,
        crate::lists::source_key::RowControlDefaults {
            max_entries: config.lists.max_entries,
            update_interval_secs: config.lists.update_interval_secs,
        },
        config.schema_version,
    )
    .map_err(|e| anyhow::anyhow!("lists.sources: {e}"))?;
    if rejects_declared_empty_plan(config, &source_plan) {
        anyhow::bail!("configured list sources resolved to no usable catalog entries");
    }
    let merged_sources = source_plan.representatives();

    // Bits, fetches, cache keys, and status aliases all derive from this
    // catalog-resolved plan so one URL cannot acquire two identities.
    let source_bits =
        SourceBitMap::from_plan(&source_plan).map_err(|e| anyhow::anyhow!("lists.sources: {e}"))?;

    // The operator's per-profile list policy, projected onto the bit
    // assignment `source_bits` just made. Computed here because
    // `source_bits` is moved into the manager below — and it is the ONLY
    // place ids become bits, which is what keeps a positional mask from
    // travelling on its own.
    let policy_masks = source_bits.project_policy(&config.blocklists, &config.profiles);

    // Tokens follow the representative that owns each fetch.
    let source_tokens = SourceTokenMap::from_plan(&source_plan, &secrets);

    // Overrides and safe mode may intentionally differ from disk. Such a boot
    // must not certify the disk revision as the policy it actually serves.
    let captured = match runtime_attestation {
        RuntimeCapabilityAttestation::Disabled => None,
        RuntimeCapabilityAttestation::AuthoritativeSchema5Tree => Some(capture_operator_policy(
            config_path,
            &daemon_instance_id,
            &candidate_runtime,
            AuditWarningEmission::Quiet,
        )?),
    };
    let boot_capture = admit_boot_capture(captured, config, runtime_attestation)?;
    let boot_identity = boot_capture
        .as_ref()
        .map(|captured| captured.identity.clone())
        .unwrap_or_else(|| ActivePolicyIdentity {
            daemon_instance_id: daemon_instance_id.clone(),
            ..ActivePolicyIdentity::default()
        });
    let profiles = Some(Arc::new(match boot_capture.as_ref() {
        Some(captured) => ProfileResolver::build_with_operator_rules_and_policy_identity(
            config,
            Arc::clone(&captured.compiled),
            boot_identity,
        ),
        None => ProfileResolver::build_with_policy_identity(config, custom_lists, boot_identity),
    }));

    // Initial list download
    let mut refresh_handle: Option<ListManagerTask> = None;
    // Fingerprints the list pipeline the manager below is built from, so
    // the FIRST reload can already skip a rebuild it does not need.
    // Stays `None` when no manager is spawned — the gate then falls
    // through to a rebuild, which is the safe direction.
    let mut lists_fingerprint: Option<ListsFingerprint> = None;
    // ArcSwap-wrapped lifecycle endpoint for list IPC. Transitioning is
    // observable while a reload retires or replaces a manager generation.
    let list_cmd_tx_swap: Arc<arc_swap::ArcSwap<ListManagerEndpoint>> = Arc::new(
        arc_swap::ArcSwap::from_pointee(ListManagerEndpoint::EmptyStable),
    );
    // This Arc exists even for an intentionally empty configuration. Reload
    // attaches every manager generation to it, so IPC sees a source added
    // after an empty boot without replacing the daemon-owned handle.
    let list_status_registry = Arc::new(ListStatusRegistry::from_plan(&source_plan));
    // Capture the list_state handle BEFORE `spawn_refresh_loop` consumes
    // the manager so `DaemonState` can plumb it into the
    // `ListDiagnostics` walk that backs `warden status`.
    let mut list_state_handle: Option<Arc<std::sync::Mutex<crate::config::list_state::ListState>>> =
        None;
    // Broadcast channel for `IpcNotification::ListStatsUpdated`. Created
    // up-front so both the manager (publisher) and DaemonState
    // (future-subscriber-endpoint anchor) clone the same `Sender`. Capacity
    // 64 covers a reasonable burst — at most 64 sources can be configured
    // (`build_source_bit_map` bound), so one full refresh cycle never
    // overflows the channel.
    let notification_tx: tokio::sync::broadcast::Sender<crate::ipc::protocol::IpcNotification> =
        tokio::sync::broadcast::channel(64).0;
    // Bit → "scope/topic" label snapshot for the `top_blocked_lists` IPC
    // field. Populated inside the
    // `if !merged_sources.is_empty()` block (where `catalog` lives)
    // before the manager consumes the catalog. Exposed to
    // `DaemonState` afterwards. All-None when no lists are
    // configured — the IPC handler then emits an empty
    // `top_blocked_lists` vec.
    let mut list_labels_vec: Vec<Option<String>> = vec![None; 64];

    // Cluster serve-state for an enabled primary. Bound before the
    // list-manager block so the boot manager can arm the map-refresh hook and
    // every replication listener plus the reload path can share it.
    #[cfg(feature = "cluster")]
    let cluster_state = build_cluster_state(
        config,
        config_path,
        boot_capture
            .as_ref()
            .and_then(|captured| captured.cluster_snapshot.clone()),
        profiles
            .as_ref()
            .map(|resolver| resolver.active_policy_identity()),
    )?;

    #[cfg(feature = "cluster")]
    let enrollment_artifact = match &node_corpus {
        Some(context) => match &context.secondary {
            Some(manifest) => Some(manifest.artifact.clone()),
            None => {
                let snapshot = boot_capture
                    .as_ref()
                    .and_then(|captured| captured.cluster_snapshot.clone())
                    .context("authoritative runtime has no enrollment policy snapshot")?;
                Some(crate::cluster::node_control::capture_enrollment_policy(
                    config_path,
                    snapshot,
                )?)
            }
        },
        None => None,
    };

    #[cfg(feature = "cluster")]
    let node_active_provider: Arc<dyn crate::cluster::node_control::ActivePairProvider> =
        match &node_corpus {
            Some(context) => context.active_pair_provider(
                config.cluster.enabled && config.cluster.membership_version == Some(1),
            ),
            None => nodes_runtime::RuntimeActivePairProvider::unavailable(),
        };

    // Build the shared cluster observability handle ONCE, before
    // DaemonState, so the same `Arc` can be cloned into the IPC state (the
    // `ClusterStatus` reader), the API server's heartbeat handler (the roster
    // writer), and the secondary poll loop (the sync-telemetry writer). Only the
    // active role's half is populated.
    #[cfg(feature = "cluster")]
    let cluster_observe: Option<Arc<crate::cluster::ClusterObserve>> = {
        use crate::config::schema::ClusterRole;
        // A peer is stale once its last sample is older than 3 poll intervals.
        let stale_secs = config.cluster.poll_interval_secs.saturating_mul(3);
        let node_name = config
            .node
            .name
            .clone()
            .or_else(|| config.cluster.node_name.clone());
        match (config.cluster.enabled, config.cluster.role) {
            (false, _) => None,
            // Primary: needs the serve-state for generations/hashes. Roster cap
            // 64 is far beyond any realistic LAN cluster; eviction is logged
            // (observe::Roster).
            (true, ClusterRole::Primary) => cluster_state.as_ref().map(|cs| {
                Arc::new(crate::cluster::ClusterObserve::new_primary(
                    node_name,
                    cs.clone(),
                    stale_secs,
                    64,
                ))
            }),
            (true, ClusterRole::Secondary) => {
                Some(Arc::new(crate::cluster::ClusterObserve::new_secondary(
                    node_name,
                    config.cluster.peer.clone().unwrap_or_default(),
                    stale_secs,
                )))
            }
        }
    };

    // Secondaries derive process-local filter bits from verified primary bytes.
    // An IP-only primary still needs a manager to drive periodic acquisition.
    let spawn_lists =
        boot_spawns_list_manager(&merged_sources, config) || modern_primary_auxiliary(config);

    // Readiness gate. Seeded CLOSED exactly when this node will build its
    // own filter map, and OPEN
    // otherwise — the manager is the only thing that opens it, so
    // seeding it closed on a node whose manager never runs would refuse
    // every query forever.
    //
    // `spawn_lists` is that predicate. It is NOT
    // `config.blocklists.is_empty()`: sources arrive through two
    // channels (`[lists].sources` and enabled `[[blocklists]]` rows), so a node configured entirely
    // through `[lists].sources` would read as "no lists" and seed the
    // gate open with no map built yet.
    //
    // This is the only place the seed is decided — and, since the gate
    // is a `ReadinessGate`, the only place in the whole tree where a
    // `false` can enter it at all. Nothing downstream can close it.
    let filter_ready = ReadinessGate::new(!spawn_lists);

    if spawn_lists {
        // Build labels from the catalog selected for this source plan.
        // Bits not present in the catalog (e.g. operator-pinned URLs)
        // fall back to the URL filename stem.
        for (url, bit) in source_bits.iter_urls() {
            if (bit as usize) < 64 {
                let label = catalog
                    .entries()
                    .iter()
                    .find(|e| e.url == url)
                    .map(|e| e.id())
                    .unwrap_or_else(|| url_stem_fallback(url));
                list_labels_vec[bit as usize] = Some(label);
            }
        }
        let interval = Duration::from_secs(config.lists.update_interval_secs);
        let bridge_config_dir = config_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf();

        // Pin what this manager is built from so a reload that changes
        // none of it can reuse the manager instead
        // of re-parsing 9.9 M domains. Goes through `from_config` — the
        // same plan fields reload compares, so boot and reload cannot drift.
        lists_fingerprint = Some(ListsFingerprint::compute(
            config,
            &source_plan,
            &source_tokens,
            &bridge_config_dir,
        ));

        let mut mgr = ListManager::with_plan_and_tokens(
            list_client.clone(),
            filter.clone(),
            source_plan.clone(),
            interval,
            source_bits.clone(),
            source_tokens.clone(),
            config.lists.max_body_bytes,
            config.lists.max_entries,
            Some(lists_dir.expect("enabled sources selected a cache directory")),
        );

        // The daemon owns `list_state.json`, so this manager records its
        // refresh transitions into it.
        ManagerWiring::from_config(
            config,
            config_path,
            &source_plan,
            bridge_config_dir,
            policy_masks,
            ListStateWriteback::Persist,
        )
        .apply(&mut mgr);

        // Daemon-only persistence stays outside shared wiring. Attach the
        // boot-owned registry before loading baselines so IPC and every
        // manager generation retain one stable Arc.
        mgr.attach_status_registry(list_status_registry.clone());
        #[cfg(feature = "cluster")]
        if let Some(context) = &node_corpus {
            nodes_runtime::wire_live_manager(
                &mut mgr,
                config,
                node_ip_filter.as_ref(),
                cluster_observe.as_ref(),
                cluster_state.as_ref(),
            );
            context.configure_secondary(&mut mgr)?;
            if context.secondary.is_none() {
                mgr.set_node_corpus_primary(
                    Arc::clone(&context.store),
                    enrollment_artifact
                        .clone()
                        .context("enrollment artifact unavailable")?,
                    node_auxiliary.clone(),
                )?;
            }
        }
        mgr.set_status_persistence_path(list_stats_path(config_path));
        list_status_registry.sync_plan(&source_plan);

        // Wire the broadcast publisher so each refresh cycle emits one
        // `ListStatsUpdated` per source. The Sender lives in
        // `DaemonState` for future subscriber-endpoint resubscription.
        mgr.set_notification_channel(notification_tx.clone());

        // Clone the list_state Arc before the manager moves into
        // spawn_refresh_loop. Same Arc backs the refresh loop's
        // transition writes AND the IPC handler's diagnostics walk —
        // single source of truth.
        list_state_handle = Some(mgr.list_state_handle());

        // Wire the out-of-band command channel so the IPC `ForgetList`
        // handler can reach the refresh loop. Channel
        // depth 16 covers a burst of operator forgets without blocking
        // the IPC task (each send is fire-and-forget from the loop's
        // perspective once acked).
        let (list_cmd_tx, list_cmd_rx) = tokio::sync::mpsc::channel(16);
        mgr.set_command_channel(list_cmd_rx);
        list_cmd_tx_swap.store(Arc::new(ListManagerEndpoint::running(list_cmd_tx)));

        // The manager is the only thing that opens the gate. Handed over
        // before the first cycle of any mode so the CacheOnly load below
        // is what unlatches it on a healthy boot.
        mgr.set_filter_ready_gate(filter_ready.clone());

        // `load_corpus_before_bind` performs the `load_disk_cache` +
        // `cleanup_stale_caches` pair itself before its first cycle, so the
        // two calls this replaced are inside it, not dropped.
        let count = load_corpus_before_bind(&mut mgr, BIND_RETRY_INITIAL_BACKOFF).await;
        tracing::info!(count, "initial blocklist loaded");
        #[cfg(feature = "cluster")]
        if let Some(context) = &node_corpus {
            mgr.verify_node_corpus()?;
            context.mark_secondary_active()?;
            context.record_active(cluster_observe.as_ref(), cluster_state.as_ref())?;
        }
        refresh_handle = Some(mgr.spawn_refresh_loop());
    } else {
        tracing::info!("no lists configured, filtering disabled");
        #[cfg(feature = "cluster")]
        if let Some(context) = &node_corpus {
            context.mark_secondary_active()?;
            if context.secondary.is_none() {
                context.publish_primary(
                    None,
                    enrollment_artifact
                        .as_ref()
                        .context("enrollment artifact unavailable")?,
                    node_auxiliary.clone(),
                )?;
            }
        }
    }
    #[cfg(feature = "cluster")]
    if let Some(context) = &node_corpus {
        context.record_active(cluster_observe.as_ref(), cluster_state.as_ref())?;
    }
    // Build stats engine (if tracking enabled)
    let stats: Option<Arc<StatsEngine>> = if config.tracking.enabled {
        // Wire the prefetch hit-frequency tracker. The tracker is itself
        // default-disabled (`prefetch_tracker_enabled` = false), so a
        // deploy that doesn't opt in stays behaviour-identical.
        let prefetch_tracker_cfg = crate::tracking::PrefetchTrackerConfig {
            enabled: config.cache.prefetch_tracker_enabled,
            window_secs: config.cache.prefetch_tracker_window_secs,
            min_hits: config.cache.prefetch_tracker_min_hits,
            max_pool_size: config.cache.prefetch_tracker_max_pool_size,
        };
        let engine = Arc::new(StatsEngine::with_prefetch_config(
            &config.tracking,
            &prefetch_tracker_cfg,
        ));

        // Pre-seed `list_blocked` slots for every configured Tier 1
        // source bit so the steady-state DNS
        // hot path is `DashMap::get` + `Relaxed::fetch_add` (no
        // `entry().or_insert_with()` shard-lock). Mirrors the
        // `domain_blocked` discipline; one-time cost at startup.
        //
        // `list_blocked_hourly` is seeded symmetrically here so the 24h
        // ring stays in lock-step with the lifetime counter — a bit
        // missing from either map silently drops on the hot path, so
        // asymmetry would manifest as a half-counted bucket.
        for (_url, bit) in source_bits.iter_urls() {
            if bit < 64 {
                engine
                    .list_blocked
                    .entry(bit)
                    .or_insert_with(|| std::sync::atomic::AtomicU64::new(0));
                engine.list_blocked_hourly.entry(bit).or_default();
            }
        }

        // One-shot migration of legacy size-rotated siblings
        // (`query.log.1` … `.9`) to the new calendar naming.
        // Idempotent: if no legacy files exist, this is a silent
        // no-op. Runs regardless of `query_log_enabled` so flipping
        // the flag later still finds the migrated history.
        {
            let resolved = crate::tracking::query_log::resolved_query_log_path(
                &config.tracking.query_log_path,
                config_path,
            );
            crate::tracking::query_log::migrate_legacy_rotated_files(&resolved);
        }

        // Attach file-based query log if enabled. The writer slot is an
        // `ArcSwap`, so `attach_query_log` takes `&self`
        // and `handle_reload` can attach / detach the writer at runtime
        // without rebuilding the engine.
        if config.tracking.query_log_enabled {
            attach_query_log_writer(&engine, &config.tracking, config_path);
        }

        // Load snapshot from previous run
        let snapshot_path = snapshot_path(config_path);
        match crate::tracking::snapshot::StatsSnapshot::load_from_file(&snapshot_path) {
            Ok(Some(snap)) => {
                snap.merge_into(&engine);
                tracing::info!(path = %snapshot_path.display(), "stats snapshot loaded");
            }
            Ok(None) => {}
            Err(e) => {
                tracing::warn!(error = %e, "failed to load stats snapshot, starting fresh");
            }
        }

        Some(engine)
    } else {
        None
    };

    // Build DNS cache and handler
    let cache = DnsCache::new(&config.cache);
    tracing::info!(
        max_entries = config.cache.max_entries,
        "DNS cache initialized"
    );

    // Build security layer
    let security: Option<Arc<SecurityLayer>> = if config.security.enabled {
        let layer = SecurityLayer::from_config(&config.security, &config.anti_bypass);
        tracing::info!(
            rrl = config.security.rrl.enabled,
            rate_limit = config.security.rate_limit.enabled,
            tunneling = config.security.tunneling.enabled,
            anti_bypass = config.anti_bypass.enabled,
            "security layer initialized"
        );
        Some(Arc::new(layer))
    } else {
        tracing::info!("security layer disabled");
        None
    };

    // Build local DNS records (if configured)
    let local_records: Option<Arc<LocalRecords>> = if !config.local_dns.records.is_empty() {
        let local = LocalRecords::build(&config.local_dns);
        tracing::info!(
            count = config.local_dns.records.len(),
            "local DNS records loaded"
        );
        Some(Arc::new(local))
    } else {
        None
    };

    // Build IP blocklist filter (if configured).
    //
    // IP blocklist sources are external HTTP fetches of user-configured URLs —
    // same threat model as blocklist downloads. Reuse the hardened list_client
    // and the bounded-body reader: HTTPS-only, literal private hosts
    // rejected, body capped at MAX_BODY_SIZE to prevent OOM from servers that
    // omit Content-Length.
    #[cfg(not(feature = "cluster"))]
    let node_ip_filter: Option<Arc<IpFilter>> = None;
    #[cfg(feature = "cluster")]
    let ip_is_cluster_managed = node_corpus.is_some();
    #[cfg(not(feature = "cluster"))]
    let ip_is_cluster_managed = false;
    let ip_filter: Option<Arc<IpFilter>> = if ip_is_cluster_managed {
        node_ip_filter.clone()
    } else if config.ip_blocklists.enabled {
        // ahash-keyed to match `IpFilter`'s hot-path set (filter/ip_filter.rs).
        let mut ips: std::collections::HashSet<std::net::IpAddr, ahash::RandomState> =
            std::collections::HashSet::default();
        // Parse inline IPs
        for ip_str in &config.ip_blocklists.inline {
            if let Ok(ip) = ip_str.parse::<std::net::IpAddr>() {
                ips.insert(ip);
            }
        }
        // Download IP blocklist sources via the hardened client
        for src in &config.ip_blocklists.sources {
            if let Err(e) = crate::lists::http_client::validate_list_url(src) {
                tracing::warn!(source = %src, error = %e, "IP blocklist URL rejected");
                continue;
            }
            match list_client.get(src).send().await {
                Ok(resp) => {
                    if !resp.status().is_success() {
                        tracing::warn!(
                            source = %src,
                            status = %resp.status(),
                            "IP blocklist download failed"
                        );
                        continue;
                    }
                    match crate::lists::manager::read_bounded_body(
                        resp,
                        src,
                        config.lists.max_body_bytes,
                    )
                    .await
                    {
                        Ok(body) => {
                            let parsed = parse_ip_blocklist(&body);
                            tracing::info!(source = %src, count = parsed.len(), "IP blocklist loaded");
                            ips.extend(parsed);
                        }
                        Err(e) => {
                            tracing::warn!(source = %src, error = %e, "IP blocklist body read failed")
                        }
                    }
                }
                Err(e) => tracing::warn!(source = %src, error = %e, "IP blocklist download failed"),
            }
        }
        tracing::info!(total = ips.len(), "response IP blocking enabled");
        Some(Arc::new(IpFilter::with_ips(ips)))
    } else {
        None
    };

    // Share the semaphore with the background refresh worker. Allocate
    // when EITHER Approach A (`cache.prefetch`)
    // or Approach B (`prefetch_tracker_enabled`) is on, so the two
    // coexist on the same concurrency budget without fighting.
    let prefetch_semaphore = if config.cache.prefetch || config.cache.prefetch_tracker_enabled {
        tracing::info!(
            threshold = config.cache.prefetch_threshold,
            max_concurrent = config.cache.prefetch_max_concurrent,
            approach_a = config.cache.prefetch,
            approach_b = config.cache.prefetch_tracker_enabled,
            "cache prefetching enabled"
        );
        Some(Arc::new(tokio::sync::Semaphore::new(
            config.cache.prefetch_max_concurrent,
        )))
    } else {
        None
    };

    // Spawn the background refresh worker when the tracker is enabled
    // AND the shared semaphore is live AND stats
    // are wired (the tracker lives inside StatsEngine). The worker
    // outlives main; it dies with the tokio runtime when the daemon
    // shuts down. Sharing the semaphore with Approach A means the two
    // approaches cap their combined in-flight refreshes at
    // `prefetch_max_concurrent` instead of doubling it.
    if config.cache.prefetch_tracker_enabled {
        if let (Some(sem), Some(stats_engine)) = (prefetch_semaphore.as_ref(), stats.as_ref()) {
            let upstream_w = upstream.clone();
            let cache_w = cache.clone();
            let filter_w = filter.clone();
            // Worker refreshes pass the same IP-blocklist gate as the
            // request-path serve guards.
            let ip_filter_w = ip_filter.clone();
            let tracker_w = stats_engine.prefetch_tracker.clone();
            let sem_w = sem.clone();
            let tick = config.cache.prefetch_tracker_tick_secs;
            let lead = config.cache.prefetch_tracker_lead_secs;
            let depth = config.cache.cname_max_depth;
            tokio::spawn(async move {
                crate::tracking::prefetch_worker::run(
                    upstream_w,
                    cache_w,
                    filter_w,
                    ip_filter_w,
                    tracker_w,
                    sem_w,
                    tick,
                    lead,
                    depth,
                )
                .await;
            });
        }
    }

    // Parse server.allow_from CIDRs. The load-time validator already
    // checked each entry parses, so a failure here would be a bug — surface
    // it as a startup error rather than silently ignore.
    //
    // The handler stores this behind an `Arc<ArcSwapOption<Vec<Cidr>>>`, so
    // it is re-derived and live-swapped on SIGHUP / IPC reload (see
    // `handle_reload` — it holds a clone of the same cell via
    // `handler.allow_from_handle()`). Tightening `server.allow_from` in
    // config.toml + `systemctl reload` now applies WITHOUT a daemon restart;
    // the per-query read stays lock-free.
    let allow_from = parse_allow_from(&config.server.allow_from)?;
    if let Some(ref cidrs) = allow_from {
        tracing::info!(count = cidrs.len(), "server.allow_from ACL active");
    }

    // Loud warning if the bind address is publicly routable. The validator
    // already refuses 0.0.0.0/:: with empty allow_from, so anything we
    // reach here with is at least gated — but a public-IP bind is still a
    // configuration the operator should be deliberate about.
    log_public_bind_warning(config.server.listen.ip(), allow_from.is_some());
    log_empty_profile_lists_warning(config);
    log_inert_custom_lists(config, custom_lists);

    // Per-record hit counter for local DNS records. Owned by the
    // handler via Arc; the TUI's `Leaf::LocalDns` hits column reads via
    // `IpcCommand::LocalRecordsHits`, which clones the same Arc through
    // `DaemonState`.
    let local_records_hits = Arc::new(crate::tracking::LocalRecordsHits::new());
    // Share the audit writer with the DNS handler so it
    // can emit `cname_block` records on chain-block events. Same file as
    // the lifecycle/CLI-mutation entries — `action=cname_block` distinguishes
    // them in `warden audit tail`.
    let handler_audit_writer = Arc::new(audit_writer.clone());
    let handler = ForwardHandler::new(
        upstream,
        filter.clone(),
        cache.clone(),
        profiles.clone(),
        stats.clone(),
        security.clone(),
        local_records,
        ip_filter,
        allow_from,
        config.server.default_blocked_ttl_secs,
        prefetch_semaphore,
        config.cache.prefetch_threshold,
        config.cache.cname_max_depth,
    )
    .with_local_records_hits(local_records_hits.clone())
    .with_audit_writer(handler_audit_writer)
    .with_dynamic_ttl_secs(config.local_dns.dynamic_ttl_secs)
    .with_nodata_for_missing_types_network_name(config.local_dns.nodata_for_missing_types)
    .with_filter_ready(filter_ready.clone());

    // Hot-reload: grab a clone of the handler's shared ACL cell BEFORE it
    // is moved into the DNS server, so `signal_loop` → `handle_reload` can
    // live-swap `server.allow_from` on reload without a daemon restart.
    let acl_handle = handler.allow_from_handle();

    let tcp_timeout = Duration::from_secs(config.server.tcp_timeout_secs);
    let server = DnsServer::new(handler, config.server.listen, tcp_timeout).await?;
    attest_runtime_capability_after_dns_ready(
        runtime_lease,
        runtime_attestation,
        config.schema_version,
    )?;

    // Shutdown channel: signal loop sends () to stop the DNS server
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let server_handle = tokio::spawn(async move { server.run(shutdown_rx).await });

    // IPC channels: allow IPC commands to trigger reload/shutdown. Each
    // payload carries the invoker uid from `SO_PEERCRED` — `Some(uid)` for
    // IPC-originated events (`warden stop`, `warden reload`) and `None`
    // for signal-driven / API-originated events. Threaded through to the
    // audit log writer.
    let (ipc_shutdown_tx, mut ipc_shutdown_rx) = mpsc::channel::<Option<u32>>(1);
    let (ipc_reload_tx, mut ipc_reload_rx) = mpsc::channel::<Option<u32>>(1);
    let (activation_tx, mut activation_rx) = mpsc::channel::<ActivationRequest>(32);

    // Clone reload sender for API before moving into DaemonState
    let api_reload_tx = ipc_reload_tx.clone();
    // Clone a reload sender for the secondary poll loop too, BEFORE
    // `ipc_reload_tx` moves into `DaemonState`. `Some` only for an enabled
    // secondary, so a primary/standalone build never holds an unused sender.
    #[cfg(feature = "cluster")]
    let cluster_reload_tx = is_cluster_secondary(config).then(|| ipc_reload_tx.clone());

    // Start IPC socket server.
    //
    // The IPC authorization gate reuses the same token hash as the
    // HTTP API (`config.api.token_hash`). One secret per operator. If
    // the API was never configured, this is an empty string — the server
    // treats that as "no token" and refuses Mutating/Admin commands with
    // a plain-English error pointing the user at `warden token generate`.
    let socket_path = config.socket.path.clone();
    let initial_hash = config.api.token_hash.clone();
    // Wrap the auth hash in `Arc<ArcSwap<_>>` so that
    // `handle_reload` can atomically swap in a new hash when the
    // operator rotates the token via `warden token regenerate`. Both
    // the IPC auth gate and the signal_loop reload path hold clones of
    // the same Arc — a store on one side is visible on the other
    // without a daemon restart.
    let api_token_hash: Arc<arc_swap::ArcSwap<Option<String>>> =
        Arc::new(arc_swap::ArcSwap::from_pointee(initial_hash));
    let api_token_hash_for_state = api_token_hash.clone();
    // Wire the IPC-reload coalescer. It owns a clone of `ipc_reload_tx`
    // and sends ONE batched reload per window. SIGHUP-driven reloads keep
    // their direct path through `state.reload_tx`.
    //
    // The worker JoinHandle is dropped: the worker exits on its own when
    // the underlying mpsc closes at shutdown, and its death is reported
    // to the operator by the coalescer refusing further requests, not by
    // anyone joining the task.
    let reload_coalescer = Arc::new(crate::ipc::ReloadCoalescer::new(ipc_reload_tx.clone()));
    let _reload_coalescer_worker = reload_coalescer.clone().spawn_worker();
    // Build the config-write lock once and share it between
    // the IPC daemon state and the REST API state below. Same Arc, so a
    // racing `POST /api/lists/add` and `warden blocklist add` over IPC
    // serialise against each other instead of trampling each other's
    // read-modify-write window.
    let config_write_lock = Arc::new(tokio::sync::Mutex::new(()));

    // The plan registry and mutation queue are process-wide so every adapter
    // shares the same capacity and idempotency view. Recovery completes before
    // an adapter can submit work; a failure leaves the control plane available
    // for reads but makes plan/apply return an honest 503.
    let operator_rule_service =
        Arc::new(crate::operator_rules::OperatorRulesService::with_runtime(
            config_path.to_path_buf(),
            Arc::clone(&candidate_runtime),
        ));
    let (operator_rule_supervisor, operator_rule_jobs) =
        crate::api::operator_rule_jobs::OperatorRuleJobSupervisor::new(
            operator_rule_service,
            crate::api::operator_rule_jobs::OperatorRuleJobConfig::default(),
            Some(activation_tx),
            Arc::new(|receipt| {
                tracing::info!(
                    target: "audit",
                    action = "operator_rules.intent",
                    operation_id = %receipt.operation_id,
                    request_id = %receipt.request_id,
                    "operator-rule intent is durable"
                );
            }),
        );
    operator_rule_jobs.attach_profile_resolver(profiles.clone());
    match operator_rule_jobs.recover().await {
        Ok(summary) => tracing::info!(
            state = %summary.state,
            operation_id = ?summary.operation_id,
            "operator-rule transaction recovery complete"
        ),
        Err(error) => tracing::error!(
            error = %error,
            "operator-rule transaction recovery failed; mutations remain unavailable"
        ),
    }
    let (operator_jobs_shutdown_tx, operator_jobs_shutdown_rx) = oneshot::channel();
    let mut operator_jobs_shutdown_tx = Some(operator_jobs_shutdown_tx);
    let mut operator_jobs_handle = Some(tokio::spawn(
        operator_rule_supervisor.run(operator_jobs_shutdown_rx),
    ));

    // MAC OUI vendor table — disk-resident, mmap'd. Searched once
    // alongside the binary's directory and at the production install
    // path. Missing or malformed file is non-fatal: the daemon logs a
    // single warning and stores `None`; lookups return `None` and the
    // TUI hides the Vendor row in the device card.
    let oui_table: Option<Arc<crate::oui::OuiTable>> = open_oui_table();

    // Finalise the bit → label snapshot built inside the lists block
    // above. Wrapped in `Arc` for cheap
    // sharing with the IPC handler; replaced wholesale on hot-reload
    // when `DaemonState` is rebuilt.
    let list_labels = Arc::new(list_labels_vec);
    // Create the resource-budget store once, share it between
    // `DaemonState` (read by `handle_status`) and the sampler task
    // (writes the latest snapshot via `ArcSwap::store`).
    let resource_budget_store = crate::resource_budget::types::new_store();

    #[cfg(feature = "cluster")]
    let (managed_restart, mut managed_restart_rx) = crate::cluster::managed_restart::channel(1);
    #[cfg(not(feature = "cluster"))]
    let mut managed_restart_rx = std::marker::PhantomData;
    #[cfg(feature = "cluster")]
    let node_runtime_enabled =
        runtime_attestation == RuntimeCapabilityAttestation::AuthoritativeSchema5Tree;
    #[cfg(feature = "cluster")]
    let node_transport = crate::api::node_transport::NodeTransport::new(
        node_runtime_enabled.then_some(&config.api),
    )?;
    #[cfg(feature = "cluster")]
    let node_controller = {
        let listener_control: Arc<dyn crate::cluster::node_control::NodeListenerControl> =
            node_transport.clone();
        crate::cluster::node_control::NodeController::new(
            config_path.to_path_buf(),
            listener_control,
            managed_restart,
            node_active_provider,
        )
    };
    #[cfg(feature = "cluster")]
    let node_runtime_plan = if node_runtime_enabled {
        node_controller.runtime_start().await?
    } else {
        crate::cluster::node_control::NodeRuntimePlan {
            listeners: Vec::new(),
            operations_to_resume: Vec::new(),
        }
    };
    let ipc_state = Arc::new(DaemonState {
        filter: filter.clone(),
        cache: cache.clone(),
        profiles: profiles.clone(),
        stats: stats.clone(),
        listen_addr: config.server.listen.to_string(),
        upstream_mode: config.upstream.mode.to_string(),
        upstream_count: config.upstream.servers.len(),
        // Precompute the per-server {address, kind} list once
        // at boot (primary then fallback). `upstream_count` above stays
        // primary-only for legacy wire compat; this list additionally
        // carries fallback servers so a mixed-kind config renders its kinds.
        upstream_servers: config
            .upstream
            .server_list()
            .into_iter()
            .map(|(address, mode)| crate::ipc::protocol::UpstreamServerInfo {
                address,
                kind: mode.to_string(),
            })
            .collect(),
        upstream_runtime: Some(upstream_runtime.clone()),
        list_count: config.lists.sources.len(),
        started_at,
        shutdown_tx: Some(ipc_shutdown_tx),
        reload_tx: Some(ipc_reload_tx),
        api_token_hash: api_token_hash_for_state,
        config_path: Some(config_path.to_path_buf()),
        config_write_lock: config_write_lock.clone(),
        operator_rule_jobs: Some(operator_rule_jobs.clone()),
        list_statuses: Some(list_status_registry.clone()),
        list_state: list_state_handle.clone(),
        local_records_hits: Some(local_records_hits),
        // The same process-wide ring the capture layer
        // installed by `init_tracing` pushes into. Not a second buffer —
        // `global()` is a `OnceLock`, so this is the one the daemon has
        // been filling since before the config was even parsed.
        log_ring: Some(std::sync::Arc::clone(crate::tracking::log_ring::global())),
        notification_tx: Some(notification_tx.clone()),
        reload_coalescer: Some(reload_coalescer),
        oui_table,
        list_labels: list_labels.clone(),
        list_cmd_tx: list_cmd_tx_swap.clone(),
        // Peer-uid gate baseline. Captured once at daemon boot;
        // constant for the daemon's lifetime.
        daemon_uid: crate::ipc::socket_server::current_euid(),
        resource_budget_store: resource_budget_store.clone(),
        #[cfg(feature = "cluster")]
        cluster_observe: cluster_observe.clone(),
        #[cfg(feature = "cluster")]
        node_controller: node_runtime_enabled.then(|| node_controller.clone()),
    });
    let ipc_handle = spawn_ipc_server(socket_path.clone(), ipc_state).await?;

    let api_state = Arc::new(crate::api::state::ApiState {
        filter: filter.clone(),
        cache: cache.clone(),
        profiles: profiles.clone(),
        stats: stats.clone(),
        config_path: config_path.to_path_buf(),
        token_hash: config.api.token_hash.clone().unwrap_or_default(),
        rate_limiter: crate::auth::middleware::AuthRateLimiter::new(),
        api_rate_limiter: crate::api::rate_limit::ApiRateLimiter::new(
            config.api.rate_limit_per_minute,
        ),
        reload_tx: api_reload_tx,
        upstream: Some(upstream_runtime.clone()),
        started_at,
        listen_addr: config.server.listen.to_string(),
        upstream_mode: config.upstream.mode.to_string(),
        upstream_count: config.upstream.servers.len(),
        list_count: config.lists.sources.len(),
        list_statuses: Some(list_status_registry.clone()),
        list_labels: list_labels.clone(),
        config_write_lock: config_write_lock.clone(),
        operator_rule_jobs: Some(operator_rule_jobs.clone()),
        #[cfg(feature = "cluster")]
        cluster: cluster_state.clone(),
        #[cfg(feature = "cluster")]
        cluster_observe: cluster_observe.clone(),
        #[cfg(feature = "cluster")]
        node_controller: node_runtime_enabled.then(|| node_controller.clone()),
    });

    #[cfg(feature = "cluster")]
    {
        node_transport.install_node_router(crate::cluster::node_control::node_router(
            node_controller.clone(),
        ))?;
        if cluster_state.is_some() {
            node_transport.install_replication_router(
                crate::cluster::routes::replication_router(api_state.clone())
                    .with_state(api_state.clone()),
            )?;
        }
    }

    // Start REST API server (if enabled)
    let mut api_handle: Option<JoinHandle<()>> = None;
    #[cfg(feature = "cluster")]
    let api_transport_active = config.api.enabled || cluster_state.is_some();
    #[cfg(not(feature = "cluster"))]
    let api_transport_active = config.api.enabled;
    let mut api_cleanup_handle = api_transport_active.then(|| {
        let rl_state = api_state.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                rl_state.rate_limiter.cleanup();
                rl_state.api_rate_limiter.cleanup();
            }
        })
    });
    if config.api.enabled {
        // A deliberate public API bind deserves the same are-you-sure
        // WARN as `server.listen`. The validator already FORCES
        // TLS for a non-loopback `api.listen`, so this fires only for an
        // intentional public-TLS bind — token-authenticated, but still
        // reachable off-LAN.
        if is_public_bind(config.api.listen.ip()) {
            let api_addr = config.api.listen;
            tracing::warn!(
                %api_addr,
                "api.listen binds a publicly-routable address; the REST API is \
                 token-authenticated and (validator-enforced) TLS-only off loopback, \
                 but it is reachable from the internet — confirm this is intended"
            );
        }
        #[cfg(not(feature = "cluster"))]
        match crate::api::server::spawn_api_server(&config.api, api_state).await {
            Ok(h) => api_handle = Some(h),
            Err(e) => {
                if let Some(handle) = api_cleanup_handle.take() {
                    handle.abort();
                }
                #[cfg(feature = "cluster")]
                if config.cluster.enabled
                    && config.cluster.membership_version == Some(1)
                    && config.cluster.role == crate::config::schema::ClusterRole::Primary
                {
                    return Err(e).context("primary node API failed to become ready");
                }
                tracing::error!(error = %e, "failed to start REST API server");
            }
        }
        #[cfg(feature = "cluster")]
        {
            node_transport.install_api_router(crate::api::routes::build_router(
                api_state,
                config.api.metrics_enabled,
            ))?;
            match node_transport.start_api().await {
                Ok(()) => {}
                Err(error) => {
                    if let Some(handle) = api_cleanup_handle.take() {
                        handle.abort();
                    }
                    if config.cluster.enabled
                        && config.cluster.membership_version == Some(1)
                        && config.cluster.role == crate::config::schema::ClusterRole::Primary
                    {
                        return Err(error).context("primary node API failed to become ready");
                    }
                    tracing::error!(%error, "failed to start REST API server");
                }
            }
        }
    }

    #[cfg(feature = "cluster")]
    let mut node_ready_endpoints = Vec::with_capacity(node_runtime_plan.listeners.len());
    #[cfg(feature = "cluster")]
    {
        for listener in node_runtime_plan.listeners {
            let endpoint = listener.endpoint;
            crate::cluster::node_control::NodeListenerControl::prepare(
                node_transport.as_ref(),
                listener,
            )
            .await
            .with_context(|| format!("failed to restore Nodes listener {endpoint}"))?;
            node_ready_endpoints.push(endpoint);
        }
    }

    // Spawn the secondary convergence poll loop — a NEW background
    // task (NOT on `signal_loop`). Fires only for an enabled secondary (the
    // `Some` from the boot-time clone above); identity (peer/token/interval) is
    // read once here. An absent/empty token still polls → 401 → logged →
    // last-good kept; the loop never panics the daemon.
    #[cfg(feature = "cluster")]
    if let (Some(cluster_reload_tx), Some(observe)) = (cluster_reload_tx, cluster_observe.clone()) {
        let token = crate::cluster::secret::load_cluster_token(config_path)
            .ok()
            .flatten()
            .unwrap_or_default();
        let peer = config.cluster.peer.clone().unwrap_or_default();
        // The validator rejects poll_interval_secs == 0, but clamp to
        // >= 1 here too so a value that somehow bypassed validation can never
        // panic `tokio::time::interval(0)` on the `panic = "abort"` profile.
        let poll_interval = Duration::from_secs(config.cluster.poll_interval_secs.max(1));
        tracing::info!(%peer, "cluster: starting secondary poll loop");
        // Hand the poll loop the observe handle (write-through sync
        // telemetry) + this node's name (advertised on every heartbeat).
        tokio::spawn(crate::cluster::poll::run(
            config_path.to_path_buf(),
            cluster_reload_tx,
            peer,
            token,
            poll_interval,
            stats.clone(),
            observe,
            config
                .node
                .name
                .clone()
                .or_else(|| config.cluster.node_name.clone()),
            profiles.clone(),
            Arc::clone(&candidate_runtime),
            node_controller.clone(),
        ));
    }

    // Spawn stats background tasks
    let mut stats_handles: Vec<tokio::task::JoinHandle<()>> = Vec::new();
    if let Some(ref engine) = stats {
        // Top-N computation task
        let top_n_handle = crate::tracking::top_n::spawn_top_n_task(
            engine.clone(),
            engine.config.top_n_limit,
            Duration::from_secs(engine.config.top_n_interval_secs),
        );
        stats_handles.push(top_n_handle);

        // Snapshot writer task
        let snap_handle = crate::tracking::snapshot::spawn_snapshot_task(
            engine.clone(),
            snapshot_path(config_path),
            Duration::from_secs(engine.config.snapshot_interval_secs),
        );
        stats_handles.push(snap_handle);
    }

    // Spawn security cleanup task (every 60s: evict stale rate limiter/RRL/tunneling entries)
    if let Some(ref sec) = security {
        let sec_clone = sec.clone();
        stats_handles.push(tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                sec_clone.cleanup();
            }
        }));
    }

    // Resource Budget sampler. Reads `/proc/self/*` once per
    // `tick_secs` and stores the latest snapshot into the shared
    // `resource_budget_store`. On non-Linux targets this spawns an
    // immediately-completing future (snapshot stays None).
    let rb_handle = crate::resource_budget::spawn_sampler(
        resource_budget_store.clone(),
        Duration::from_secs(config.resource_budget.tick_secs),
        config.resource_budget.rss_warn_mb,
    );
    stats_handles.push(rb_handle);

    // Enter signal loop (now also listens for IPC-triggered events).
    let has_schedules = !config.schedules.is_empty();
    let mut current_files = boot_files.clone();
    let mut current_hash = boot_hash.clone();
    // Thread the cluster serve-state through the reload path so a SIGHUP /
    // IPC reload re-serialises the policy bundle and re-arms the rebuilt
    // list manager's map hook. `PhantomData` when the feature is off.
    #[cfg(feature = "cluster")]
    let cluster_reload_handle: ClusterReloadHandle = cluster_state.as_ref();
    #[cfg(not(feature = "cluster"))]
    let cluster_reload_handle: ClusterReloadHandle = std::marker::PhantomData;
    #[cfg(feature = "cluster")]
    {
        let master = config_path.to_owned();
        let active = config.clone();
        tokio::task::spawn_blocking(move || {
            crate::cluster::lifecycle::acknowledge_runtime_start(&master, &active)
        })
        .await
        .context("node readiness worker failed")??;
        for endpoint in node_ready_endpoints {
            node_controller.runtime_ready(endpoint).await?;
        }
        if node_runtime_enabled {
            let controller = node_controller.clone();
            stats_handles.push(tokio::spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(2));
                interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                loop {
                    interval.tick().await;
                    match controller.runtime_tick().await {
                        Ok(advanced) if advanced > 0 => {
                            tracing::info!(advanced, "durable Nodes operation reconciled");
                        }
                        Ok(_) => {}
                        Err(error) => {
                            tracing::warn!(%error, "durable Nodes reconciliation failed");
                        }
                    }
                }
            }));
        }
    }
    let restart_only = RestartOnlyRuntimeFingerprint::from_config(config)?;
    let exit_result = signal_loop(
        config_path,
        &list_client,
        Some(RuntimeReloadContext {
            client: &upstream_client,
            upstream: &upstream_runtime,
            cache: &cache,
            restart_only: &restart_only,
            #[cfg(feature = "cluster")]
            node_ip_filter: node_ip_filter.as_ref(),
            #[cfg(feature = "cluster")]
            node_observe: cluster_observe.as_ref(),
        }),
        &filter,
        profiles.as_ref(),
        &candidate_runtime,
        &mut refresh_handle,
        &mut lists_fingerprint,
        has_schedules,
        &mut ipc_shutdown_rx,
        &mut ipc_reload_rx,
        &mut activation_rx,
        &audit_writer,
        &mut current_files,
        &mut current_hash,
        &api_token_hash,
        &acl_handle,
        stats.as_ref(),
        Some(&list_status_registry),
        &notification_tx,
        &list_cmd_tx_swap,
        cluster_reload_handle,
        security.as_ref(),
        &mut api_handle,
        &mut operator_jobs_handle,
        &mut managed_restart_rx,
    )
    .await;

    // WHY: handlers outlive signal_loop briefly; close Force/Forget admission
    // before audit or cleanup gives every already-spawned handler the same
    // retiring endpoint rather than a still-running sender.
    publish_list_manager_transitioning(&list_cmd_tx_swap);
    retire_activation_queue(
        &mut activation_rx,
        profiles
            .as_ref()
            .map(|resolver| resolver.active_policy_identity()),
    );

    // Audit the shutdown before we tear anything down so a rollover that
    // crashes mid-cleanup still leaves a trail. `shutdown_uid` is
    // Some(peer_uid) for an IPC Shutdown command and None for SIGTERM /
    // SIGINT / channel-closed exits.
    let shutdown_uid = exit_result.as_ref().ok().and_then(SignalLoopExit::peer_uid);
    let shutdown_rec = AuditRecord::new(AuditEvent::Shutdown, AuditResult::Ok)
        .with_uid(shutdown_uid)
        .with_files(current_files.iter())
        .with_pre_hash(current_hash.clone());
    if let Err(e) = audit_writer.append(&shutdown_rec) {
        tracing::warn!(error = %e, "failed to write shutdown audit record");
    }

    // Graceful shutdown
    tracing::info!("shutting down...");

    // Write final stats snapshot before stopping
    if let Some(ref engine) = stats {
        crate::tracking::snapshot::write_final_snapshot(engine, &snapshot_path(config_path));
    }

    // Abort background tasks
    for h in stats_handles {
        h.abort();
    }

    if shutdown_tx.send(()).is_err() {
        tracing::warn!("DNS server already exited before shutdown signal");
    }
    ipc_handle.abort();
    if let Some(h) = api_handle {
        h.abort();
    }
    #[cfg(feature = "cluster")]
    {
        if node_runtime_enabled {
            if let Err(error) = node_controller.runtime_shutdown().await {
                tracing::error!(%error, "Nodes controller shutdown failed");
            }
        }
        node_transport.shutdown().await;
    }
    if let Some(h) = api_cleanup_handle {
        h.abort();
    }
    if let Some(shutdown) = operator_jobs_shutdown_tx.take() {
        let _ = shutdown.send(());
    }
    if let Some(handle) = operator_jobs_handle {
        if let Err(error) = handle.await {
            tracing::error!(error = %error, "operator-rule supervisor failed during shutdown");
        }
    }

    // Drain the query-log writer's final buffer before the runtime tears
    // down. The DNS server + IPC/API tasks were just signalled to stop, so no
    // producer still holds the writer Arc — detach it from the engine and
    // await its flush-and-exit. (The reload path detaches on a non-blocking
    // task to stay responsive; the final path can await because we are
    // exiting.) `shutdown(self)` drops the sender, the writer flushes-and-
    // exits on channel close, and the JoinHandle resolves — no deadlock.
    // Without this the writer's last ≤1 s batch races runtime teardown and is
    // lost on every clean shutdown.
    if let Some(ref engine) = stats {
        if let Some(old_ql) = engine.detach_query_log() {
            match Arc::try_unwrap(old_ql) {
                Ok(inner) => inner.shutdown().await,
                Err(_arc) => {
                    // A transient hot-path clone outlived the stop signal; the
                    // writer flushes on channel close once that clone drops.
                }
            }
        }
    }

    // Clean up socket file
    if socket_path.exists() {
        if let Err(e) = std::fs::remove_file(&socket_path) {
            tracing::warn!(
                error = %e,
                path = %socket_path.display(),
                "failed to remove IPC socket file during shutdown"
            );
        }
    }

    // The endpoint was unpublished immediately after signal_loop returned;
    // retire its receiver only after the remaining shutdown bookkeeping.
    if let Some(h) = refresh_handle.take() {
        if let Err(error) = h.retire().await {
            tracing::error!(%error, "list manager controller ended abnormally during shutdown");
        }
    }

    // Wait for server to finish
    match server_handle.await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => tracing::error!("server error during shutdown: {e}"),
        Err(e) => tracing::error!("server task panicked: {e}"),
    }

    exit_result.map(|reason| match reason {
        SignalLoopExit::Stopped(_) => StartOutcome::Stopped,
        #[cfg(feature = "cluster")]
        SignalLoopExit::ManagedRestart(request) => {
            StartOutcome::ManagedRestart(crate::cluster::managed_restart::ManagedRestartRequest {
                operation_id: request.operation_id,
                step_id: request.step_id,
            })
        }
    })
}

fn attest_runtime_capability_after_dns_ready(
    runtime_lease: &crate::config::runtime_lease::RuntimeLease,
    attestation: RuntimeCapabilityAttestation,
    schema_version: u32,
) -> anyhow::Result<()> {
    match attestation {
        RuntimeCapabilityAttestation::Disabled => Ok(()),
        RuntimeCapabilityAttestation::AuthoritativeSchema5Tree => {
            runtime_lease.attest_schema5_runtime(schema_version)
        }
    }
}

/// Hand the manager the bulk download client, for the background refresh
/// loop it is about to become.
///
/// Called at both transition points, and no longer symmetrically. **Reload**
/// calls it after its tight-client refresh worker has returned. **Boot** calls it
/// FIRST — see [`load_corpus_before_bind`] — because the boot path no longer
/// refreshes over the network at all, so there is no inline refresh left to
/// starve, and the background loop it hands off to now starts seconds after
/// the bind instead of `update_interval_secs` later. See
/// [`crate::lists::manager::ListManager::set_download_client`] for why the
/// two phases want different limits.
///
/// A failure to build the client is logged and swallowed rather than
/// propagated: the manager already holds a working tight client, so the
/// worst case is that large lists keep failing exactly as they did before
/// this existed. Aborting a boot — or a reload whose refresh has already
/// succeeded — over a `ClientBuilder` error would trade a degraded refresh
/// for no DNS at all.
fn install_bulk_download_client(mgr: &mut crate::lists::manager::ListManager) {
    match crate::lists::http_client::build_bulk_list_client() {
        Ok(client) => mgr.set_download_client(client),
        Err(e) => tracing::warn!(
            error = %e,
            "could not build the bulk download client; the background refresh \
             keeps the boot client, so lists larger than roughly \
             30s x link-speed will continue to fail"
        ),
    }
}

/// First delay before branch (c) retries a boot that could not build a map.
///
/// Doubles per attempt up to [`BIND_RETRY_MAX_BACKOFF`]. Passed into
/// [`load_corpus_before_bind`] instead of being read inside it so a test can
/// make the first sleep long enough that "still refusing to bind" and
/// "returned to the caller" cannot be confused for one another under load.
///
/// Callers must pass a non-zero delay: `backoff * 2` on a zero `Duration`
/// stays zero, so `.min(BIND_RETRY_MAX_BACKOFF)` never lifts it and branch
/// (c) degenerates into an un-delayed retry hammer against a source that is
/// down.
const BIND_RETRY_INITIAL_BACKOFF: Duration = Duration::from_secs(5);

/// Ceiling on the branch-(c) retry delay. Five minutes: long enough not to
/// hammer a source that is down, short enough that a link coming back does
/// not leave the house without DNS for another hour.
const BIND_RETRY_MAX_BACKOFF: Duration = Duration::from_secs(300);

/// Build the filter map the DNS listener will serve — **before** it binds.
///
/// Builds the map via branches (a), (b) and (c) below. Returns the installed
/// domain count once a configured source set has reached a serveable state.
///
/// # Precondition
///
/// Call this **only** when [`boot_spawns_list_manager`] is true. Branch (d) —
/// no lists configured — is the one legitimate empty-map bind and it is
/// expressed by not calling this at all. There is deliberately no
/// "are lists configured" check inside: a second copy of that predicate is a
/// second chance for the three consumers to disagree.
///
/// # Order
///
/// The bulk client goes in AHEAD of every refresh. Not to make a boot
/// download succeed — branch (a) downloads nothing — but so the first
/// background cycle, which now runs seconds after the bind rather than 12 h
/// later, holds the client that can finish a 180 MB list on a slow link.
async fn load_corpus_before_bind(mgr: &mut ListManager, initial_backoff: Duration) -> usize {
    install_bulk_download_client(mgr);
    mgr.load_disk_cache();
    mgr.cleanup_stale_caches();

    // Branch (a): boot from disk. Zero HTTP, cache used at any age. This is
    // the change that takes the measured boot from ~199 s to ~35 s — 164 s of
    // it was four downloads that a 30 s TOTAL deadline made structurally
    // impossible to finish, whose fallback was this exact disk read anyway.
    let mut count = mgr.refresh_with_mode(RefreshMode::CacheOnly).await;
    let mut served_state = mgr.served_state();
    tracing::info!(count, "blocklist loaded from disk cache");

    // Branch (b): no cache generation is ready to serve. Block on the network.
    if !served_state.is_ready_for_bind() {
        tracing::warn!(
            "no usable disk cache; downloading before the listener binds \
             (first run, or the cache was refused)"
        );
        count = mgr.refresh_with_mode(RefreshMode::Force).await;
        served_state = mgr.served_state();
    }

    // Branch (c): still no serveable generation. Retry instead of binding
    // without validated list state.
    let mut backoff = initial_backoff;
    while !served_state.is_ready_for_bind() {
        tracing::error!(
            retry_in_secs = backoff.as_secs(),
            "REFUSING TO BIND: no filter map could be built from disk or \
             network, and lists are configured. DNS stays down rather than \
             answering unfiltered. Retrying."
        );
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(BIND_RETRY_MAX_BACKOFF);
        count = mgr.refresh_with_mode(RefreshMode::Force).await;
        served_state = mgr.served_state();
    }

    count
}

/// Parse `server.allow_from` CIDR strings into the pre-parsed ACL the
/// DNS handler reads on the hot path. `None` = empty list = accept all sources.
/// Shared by the boot path and `handle_reload` so both derive the ACL the same
/// way. The load-time validator already checks each entry, so an error here is
/// a bug — boot surfaces it as a startup error (`?`); reload logs it and keeps
/// the previous ACL rather than widening to accept-all.
fn parse_allow_from(
    entries: &[String],
) -> anyhow::Result<Option<Arc<Vec<crate::config::cidr::Cidr>>>> {
    if entries.is_empty() {
        return Ok(None);
    }
    let mut parsed = Vec::with_capacity(entries.len());
    for entry in entries {
        let cidr = crate::config::cidr::Cidr::parse(entry)
            .map_err(|e| anyhow::anyhow!("server.allow_from: failed to parse '{entry}': {e}"))?;
        parsed.push(cidr);
    }
    Ok(Some(Arc::new(parsed)))
}

/// Main signal handling loop. Returns when a shutdown signal is received.
///
/// Listens for: OS signals (SIGINT, SIGTERM, SIGHUP), IPC-triggered
/// shutdown/reload, and a 60-second schedule re-evaluation timer.
///
/// Cache flushing is intentionally *not* on this signal loop — a
/// signal-based flush would bypass the token-gated IPC auth. Cache
/// flushing requires a token-gated `IpcCommand::CacheFlush` call.
///
/// `list_client` must be the hardened client from
/// `http_client::build_bulk_list_client`; it is used exclusively for catalog
/// and list refreshes inside `handle_reload`.
/// `runtime_reload` carries the startup fingerprint and the independently
/// hardened resolver generation replaced after candidate validation succeeds.
#[derive(Debug)]
struct ManagedRestartSignal {
    operation_id: String,
    step_id: String,
}

#[derive(Debug)]
enum SignalLoopExit {
    Stopped(Option<u32>),
    #[cfg(feature = "cluster")]
    ManagedRestart(ManagedRestartSignal),
}

impl SignalLoopExit {
    fn peer_uid(&self) -> Option<u32> {
        match self {
            Self::Stopped(uid) => *uid,
            #[cfg(feature = "cluster")]
            Self::ManagedRestart(_) => None,
        }
    }
}

#[cfg(feature = "cluster")]
type ManagedRestartLoop<'a> = &'a mut crate::cluster::managed_restart::ManagedRestartReceiver;
#[cfg(not(feature = "cluster"))]
type ManagedRestartLoop<'a> = &'a mut std::marker::PhantomData<()>;

#[cfg(feature = "cluster")]
async fn receive_managed_restart(receiver: ManagedRestartLoop<'_>) -> Option<ManagedRestartSignal> {
    receiver.recv().await.map(|request| ManagedRestartSignal {
        operation_id: request.operation_id,
        step_id: request.step_id,
    })
}

#[cfg(not(feature = "cluster"))]
async fn receive_managed_restart(
    _receiver: ManagedRestartLoop<'_>,
) -> Option<ManagedRestartSignal> {
    std::future::pending().await
}

#[allow(clippy::too_many_arguments)]
async fn signal_loop(
    config_path: &Path,
    list_client: &reqwest::Client,
    runtime_reload: Option<RuntimeReloadContext<'_>>,
    filter: &Arc<FilterEngine>,
    profiles: Option<&Arc<ProfileResolver>>,
    candidate_runtime: &Arc<crate::operator_rules::PolicyCandidateRuntime>,
    refresh_handle: &mut Option<ListManagerTask>,
    lists_fingerprint: &mut Option<ListsFingerprint>,
    mut has_schedules: bool,
    ipc_shutdown_rx: &mut mpsc::Receiver<Option<u32>>,
    ipc_reload_rx: &mut mpsc::Receiver<Option<u32>>,
    activation_rx: &mut mpsc::Receiver<ActivationRequest>,
    audit_writer: &AuditWriter,
    current_files: &mut Vec<PathBuf>,
    current_hash: &mut Option<String>,
    api_token_hash: &Arc<arc_swap::ArcSwap<Option<String>>>,
    acl_handle: &Arc<arc_swap::ArcSwapOption<Vec<crate::config::cidr::Cidr>>>,
    stats: Option<&Arc<StatsEngine>>,
    list_status_registry: Option<&Arc<ListStatusRegistry>>,
    notification_tx: &tokio::sync::broadcast::Sender<crate::ipc::protocol::IpcNotification>,
    list_cmd_tx_swap: &Arc<arc_swap::ArcSwap<ListManagerEndpoint>>,
    cluster_state: ClusterReloadHandle<'_>,
    security: Option<&Arc<SecurityLayer>>,
    api_handle: &mut Option<JoinHandle<()>>,
    operator_jobs_handle: &mut Option<JoinHandle<()>>,
    managed_restart_rx: ManagedRestartLoop<'_>,
) -> anyhow::Result<SignalLoopExit> {
    #[cfg(not(feature = "cluster"))]
    let _ = cluster_state;
    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sighup = signal(SignalKind::hangup())?;
    // There is no SIGUSR1 handler: it would let any local user with kill
    // permission on the PID flush the DNS cache, bypassing the
    // token-gated IPC auth gate. Cache flushing is strictly a
    // token-gated IPC Mutating command. SIGHUP is still available as an
    // unauthenticated signal because it only re-reads config — and
    // changing the config already requires write access to config.toml,
    // which is a stronger capability than sending a signal.
    let mut schedule_tick = tokio::time::interval(Duration::from_secs(60));
    // The tick arm is gated `if has_schedules`, so a
    // box that booted with zero schedules never polls this interval. When a
    // runtime quiet/schedule later flips the gate true (via a reload-refreshed
    // `has_schedules`), the interval's deadline is stale; the default `Burst`
    // catch-up would then fire one tick — a full `load_config` — per missed
    // 60 s of uptime. `Skip` collapses that backlog to a single fire and
    // re-aligns to the next period.
    schedule_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // Skip the first immediate tick — profiles were just built
    schedule_tick.tick().await;

    // Track whether IPC channels are alive. When a channel closes (sender
    // dropped), we disable that select! branch to prevent an infinite busy loop
    // (recv() returns None immediately on a closed channel).
    let mut ipc_shutdown_live = true;
    let mut ipc_reload_live = true;
    let mut activation_live = true;
    let mut managed_restart_live = true;

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("SIGINT received");
                return Ok(SignalLoopExit::Stopped(None));
            }
            _ = sigterm.recv() => {
                tracing::info!("SIGTERM received");
                return Ok(SignalLoopExit::Stopped(None));
            }
            result = ipc_shutdown_rx.recv(), if ipc_shutdown_live => {
                match result {
                    Some(peer_uid) => {
                        tracing::info!("shutdown requested via IPC");
                        return Ok(SignalLoopExit::Stopped(peer_uid));
                    }
                    None => {
                        tracing::warn!("IPC shutdown channel closed (IPC server may have crashed)");
                        ipc_shutdown_live = false;
                    }
                }
            }
            request = receive_managed_restart(managed_restart_rx), if managed_restart_live => {
                match request {
                    Some(request) => {
                        tracing::info!(
                            operation_id = %request.operation_id,
                            step_id = %request.step_id,
                            "managed Nodes restart requested"
                        );
                        #[cfg(feature = "cluster")]
                        return Ok(SignalLoopExit::ManagedRestart(request));
                        #[cfg(not(feature = "cluster"))]
                        unreachable!("feature-less managed restart future never resolves");
                    }
                    None => {
                        tracing::error!("managed restart channel closed");
                        managed_restart_live = false;
                    }
                }
            }
            _ = sighup.recv() => {
                tracing::info!("SIGHUP received, reloading config and lists");
                // Refresh the schedule-tick gate from
                // the reloaded config. `None` = reload rejected → gate unchanged.
                if let Some(h) = handle_reload(
                    config_path,
                    list_client,
                    runtime_reload,
                    filter,
                    profiles,
                    candidate_runtime,
                    refresh_handle,
                    lists_fingerprint,
                    audit_writer,
                    current_files,
                    current_hash,
                    api_token_hash,
                    acl_handle,
                    stats,
                    list_status_registry,
                    notification_tx,
                    list_cmd_tx_swap,
                    None,
                    cluster_state,
                    security,
                )
                .await?
                {
                    has_schedules = h;
                }
            }
            result = ipc_reload_rx.recv(), if ipc_reload_live => {
                match result {
                    Some(peer_uid) => {
                        tracing::info!("reload requested via IPC");
                        // Refresh the schedule-tick
                        // gate from the reloaded config (None = reload rejected).
                        if let Some(h) = handle_reload(
                            config_path,
                            list_client,
                            runtime_reload,
                            filter,
                            profiles,
                            candidate_runtime,
                            refresh_handle,
                            lists_fingerprint,
                            audit_writer,
                            current_files,
                            current_hash,
                            api_token_hash,
                            acl_handle,
                            stats,
                            list_status_registry,
                            notification_tx,
                            list_cmd_tx_swap,
                            peer_uid,
                            cluster_state,
                            security,
                        )
                        .await?
                        {
                            has_schedules = h;
                        }
                    }
                    None => {
                        tracing::warn!("IPC reload channel closed (IPC server may have crashed)");
                        ipc_reload_live = false;
                    }
                }
            }
            request = activation_rx.recv(), if activation_live => {
                let Some(request) = request else {
                    activation_live = false;
                    continue;
                };
                tracing::info!(
                    target: "audit",
                    operation_id = %request.operation_id,
                    request_id = %request.request_id,
                    actor = %request.actor,
                    correlation_id = %request.correlation_id,
                    "operator-policy activation requested"
                );
                let active = profiles.map(|resolver| resolver.active_policy_identity());
                if active.as_ref().is_some_and(|identity| {
                    identity.is_known()
                        && identity.config_revision == request.expected_config_revision
                        && identity.operator_policy_hash == request.expected_policy_hash
                }) {
                    let result = classify_activation(&request, active, Ok(true));
                    let _ = request.completion.send(result);
                    continue;
                }
                let reload = handle_reload(
                    config_path,
                    list_client,
                    runtime_reload,
                    filter,
                    profiles,
                    candidate_runtime,
                    refresh_handle,
                    lists_fingerprint,
                    audit_writer,
                    current_files,
                    current_hash,
                    api_token_hash,
                    acl_handle,
                    stats,
                    list_status_registry,
                    notification_tx,
                    list_cmd_tx_swap,
                    None,
                    cluster_state,
                    security,
                ).await;
                let active = profiles.map(|resolver| resolver.active_policy_identity());
                let outcome = match &reload {
                    Ok(Some(_)) => Ok(true),
                    Ok(None) => Ok(false),
                    Err(error) => Err(error.to_string()),
                };
                let result = classify_activation(&request, active, outcome);
                let _ = request.completion.send(result);
                if let Some(schedules) = reload? {
                    has_schedules = schedules;
                }
            }
            result = api_task_exit(&mut *api_handle), if api_handle.is_some() => {
                match result {
                    Ok(()) => tracing::error!(
                        "REST API task exited on its own; the API is unreachable until \
                         the daemon restarts. DNS filtering is unaffected"
                    ),
                    Err(e) => tracing::error!(
                        error = %e,
                        panicked = e.is_panic(),
                        "REST API task ended abnormally; the API is unreachable until \
                         the daemon restarts. DNS filtering is unaffected"
                    ),
                }
            }
            result = operator_jobs_task_exit(&mut *operator_jobs_handle), if operator_jobs_handle.is_some() => {
                match result {
                    Ok(()) => tracing::error!(
                        "operator-rule supervisor exited; plan/apply is unavailable until restart"
                    ),
                    Err(error) => tracing::error!(
                        error = %error,
                        panicked = error.is_panic(),
                        "operator-rule supervisor failed; plan/apply is unavailable until restart"
                    ),
                }
            }
            _ = schedule_tick.tick(), if has_schedules => {
                handle_schedule_tick(profiles);
            }
        }
    }
}

/// Resolve when the supervised REST API task exits, and retire its handle.
///
/// Parks forever when the API is disabled: an arm that completed on `None`
/// would spin the supervisor `select!` at full speed instead of waiting on
/// signals. Retiring the handle as it reports is what makes the arm safe to
/// re-enter — a `JoinHandle` panics if polled after it resolves, and the
/// arm's guard reads the same `Option` cleared here, so guard and future
/// cannot drift apart.
///
/// Cancel-safe: losing the `select!` race drops this future before the
/// assignment, leaving a still-running task's handle intact.
async fn api_task_exit(handle: &mut Option<JoinHandle<()>>) -> Result<(), tokio::task::JoinError> {
    let result = match handle.as_mut() {
        Some(h) => h.await,
        None => std::future::pending().await,
    };
    *handle = None;
    result
}

async fn operator_jobs_task_exit(
    handle: &mut Option<JoinHandle<()>>,
) -> Result<(), tokio::task::JoinError> {
    let result = match handle.as_mut() {
        Some(handle) => handle.await,
        None => std::future::pending().await,
    };
    *handle = None;
    result
}

/// Canonical path for the audit log relative to the config master.
///
/// v1 FHS split: when the master lives under `/etc/<pkg>/` the
/// audit log (and every other mutable-state file) must land under
/// `/var/lib/<pkg>/` — `/etc/` is read-only under the daemon's
/// `ProtectSystem=strict` systemd hardening. For dev / single-file installs
/// (tests, `warden config lint`), the audit log stays next to the config so
/// the whole deployment is self-contained in one directory.
pub(crate) fn audit_log_path(config_path: &Path) -> PathBuf {
    let dir = config_path.parent().unwrap_or_else(|| Path::new("."));
    state_dir_for(dir)
        .join(audit::AUDIT_DIR_NAME)
        .join(audit::AUDIT_FILE_NAME)
}

/// Directory `--daemon` writes its logs into.
///
/// Routed through [`state_dir_for`] like every other mutable-state path
/// (audit log, lists cache, stats snapshot, query log): `/etc/` is
/// read-only under the daemon's `ProtectSystem=strict` hardening, so a
/// log directory resolved directly under the config path there would take
/// EACCES from `open_panic_fallback_log`'s `create_dir_all` and `--daemon`
/// could not launch at all.
pub(crate) fn daemon_log_dir(config_path: &Path) -> PathBuf {
    state_dir_for(config_path.parent().unwrap_or_else(|| Path::new("."))).join("logs")
}

/// Map the config-master parent to the daemon's mutable-state directory.
///
/// Rules:
/// - `/etc/<pkg>/...` → `/var/lib/<pkg>/` (FHS v1 layout).
/// - Any other location → returned as-is (dev / single-file installs keep
///   audit log, lists cache, stats snapshot, query log beside the config).
///
/// Only the first path component under `/etc` matters: the state directory
/// is always `/var/lib/<leaf>` regardless of any deeper subdirs operators
/// may have set up under `/etc/<pkg>/`.
pub(crate) fn state_dir_for(config_parent: &Path) -> PathBuf {
    crate::config::state_dir::for_config_parent(config_parent)
}

/// Acquire the first complete secondary corpus before configuration-dependent
/// startup state is assembled. An existing complete pair survives an outage.
#[cfg(feature = "cluster")]
pub async fn prepare_nodes_before_load(config_path: &Path) -> anyhow::Result<()> {
    let master = config_path.to_owned();
    tokio::task::spawn_blocking(move || crate::cluster::lifecycle::recover_before_load(&master))
        .await
        .context("node recovery worker failed")??;
    let loaded =
        crate::config::loader::load_config_v5(config_path, time::OffsetDateTime::now_utc())
            .map_err(|errors| anyhow::anyhow!("node bootstrap config rejected: {errors:?}"))?;
    if loaded.config.cluster.enabled
        && loaded.config.cluster.membership_version == Some(1)
        && loaded.config.cluster.role == crate::config::schema::ClusterRole::Secondary
    {
        let bytes = RuleCompileLimits::HARD_CEILINGS
            .max_compiled_bytes_total
            .checked_mul(2)
            .context("node bootstrap admission ceiling overflow")?;
        let runtime = Arc::new(crate::operator_rules::PolicyCandidateRuntime::new(
            crate::filter::operator_rules::CompileAdmission::new(bytes, 1)?,
        ));
        crate::cluster::poll::bootstrap(config_path, runtime).await?;
    }
    Ok(())
}

/// Recover an interrupted policy transaction before the daemon loads config.
pub fn recover_policy_transaction_before_load(config_path: &Path) -> anyhow::Result<()> {
    let recovery = {
        let guard = crate::config::write_lock::acquire_for_migration(config_path)?;
        let state_directory = crate::config::state_dir::open_for_migration(&guard)?;
        let receipts =
            crate::config::policy_transaction::ReceiptStore::open(&state_directory, &guard)?;
        let recovered = crate::config::policy_transaction::recover_active(&guard, &receipts)?;
        #[cfg(feature = "cluster")]
        {
            let mut publications = crate::cluster::publication::PublicationStore::open(&guard)?;
            crate::cluster::publisher::recover(&guard, &receipts, &mut publications)?;
        }
        recovered
    };
    match recovery {
        crate::config::policy_transaction::RecoveryOutcome::Absent => {}
        crate::config::policy_transaction::RecoveryOutcome::SetupRemoved => {
            eprintln!("recovered an interrupted policy-transaction setup");
        }
        crate::config::policy_transaction::RecoveryOutcome::Recovered(receipt) => {
            eprintln!(
                "recovered policy transaction {} with persistence {:?}",
                receipt.transaction_id, receipt.persistence
            );
        }
        crate::config::policy_transaction::RecoveryOutcome::LegacyActive => {
            anyhow::bail!(
                "an interrupted v3-to-v4 migration requires `warden migrate v3-to-v4` recovery before the daemon can start"
            );
        }
    }
    Ok(())
}

/// Enumerate every file the loader considered when parsing the current config:
/// the master + everything reached via `includes`. Duplicates are removed.
/// Missing master → returns just the master path (which is what tree_hash
/// will skip). Used for the audit log's `files` field AND its
/// `pre_hash` / `post_hash` tree hash.
///
/// `secrets.toml` is deliberately EXCLUDED. It is loaded
/// separately from the v1 tree (never merged into it), and folding a 0600
/// secrets file into the 0640 audit log's `tree_hash` would turn
/// `pre_hash` / `post_hash` into an offline brute-force oracle for token
/// values — a group member who can read the audit log + the non-secret
/// config could confirm guessed secrets against the recorded digest.
fn collect_loaded_files(config_path: &Path) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = Vec::new();
    let now = time::OffsetDateTime::now_utc();
    if let (Ok(loaded), _) =
        crate::config::loader::load_current_config_emitting_collect(config_path, now)
    {
        for (_, (path, _line)) in loaded.provenance {
            files.push(path);
        }
    }
    files.push(config_path.to_path_buf());
    files.sort();
    files.dedup();
    files
}

/// Always returns an owned resolver — the non-`Option` return type
/// pins the resolver's unconditional presence so future refactors don't
/// silently skip construction for an "empty `[[devices]]`" optimisation.
#[cfg(test)]
fn build_profile_resolver(
    config: &crate::config::schema::ConfigV1,
    custom_lists: &CustomListStore,
) -> Arc<ProfileResolver> {
    Arc::new(ProfileResolver::build_without_list_bits(
        config,
        custom_lists,
    ))
}

struct CapturedOperatorPolicy {
    files_loaded: Vec<PathBuf>,
    projected: crate::config::schema::ConfigV1,
    compiled: Arc<CompiledOperatorRules>,
    identity: ActivePolicyIdentity,
    audit_hash: Option<String>,
    #[cfg(feature = "cluster")]
    cluster_snapshot: Option<Arc<crate::cluster::artifact::PolicySnapshot>>,
}

fn admit_boot_capture(
    captured: Option<CapturedOperatorPolicy>,
    runtime_config: &crate::config::schema::ConfigV1,
    attestation: RuntimeCapabilityAttestation,
) -> anyhow::Result<Option<CapturedOperatorPolicy>> {
    match (attestation, captured) {
        (RuntimeCapabilityAttestation::Disabled, None) => Ok(None),
        (RuntimeCapabilityAttestation::Disabled, Some(_)) => {
            anyhow::bail!("safe-mode boot unexpectedly captured an authoritative policy")
        }
        (RuntimeCapabilityAttestation::AuthoritativeSchema5Tree, None) => {
            anyhow::bail!("authoritative schema-5 boot has no compiled policy capture")
        }
        (RuntimeCapabilityAttestation::AuthoritativeSchema5Tree, Some(captured)) => {
            let mut effective_projection = captured.projected.clone();
            effective_projection.server.listen = runtime_config.server.listen;
            effective_projection
                .upstream
                .servers
                .clone_from(&runtime_config.upstream.servers);
            effective_projection.lists.update_interval_secs =
                runtime_config.lists.update_interval_secs;

            if toml::to_string(&effective_projection).ok() != toml::to_string(runtime_config).ok() {
                anyhow::bail!(
                    "authoritative schema-5 tree changed between initial load and policy capture; retry startup"
                );
            }
            Ok(Some(captured))
        }
    }
}

#[derive(Clone, Copy)]
enum AuditWarningEmission {
    Quiet,
    Emit,
}

fn capture_operator_policy(
    config_path: &Path,
    daemon_instance_id: &str,
    candidate_runtime: &crate::operator_rules::PolicyCandidateRuntime,
    audit_warning_emission: AuditWarningEmission,
) -> anyhow::Result<CapturedOperatorPolicy> {
    use crate::config::policy_revision::{PolicyMemberKind, PolicyMemberState};
    use sha2::{Digest, Sha256};

    let guard = crate::config::write_lock::acquire_for_read(config_path)?;
    let now = time::OffsetDateTime::now_utc();
    let loaded = if matches!(audit_warning_emission, AuditWarningEmission::Emit) {
        crate::config::loader::load_config_v5_with_policy_overlays_emitting_under_service_read_guard(
            &guard,
            guard.canonical_master(),
            now,
            None,
            None,
        )
    } else {
        crate::config::loader::load_config_v5_with_policy_overlays_under_service_read_guard(
            &guard,
            guard.canonical_master(),
            now,
            None,
            None,
        )
    }
    .map_err(|error| anyhow::anyhow!(format_guarded_load_error(error)))?;
    let (snapshot, loaded) =
        crate::config::policy_revision::capture_coherent_loaded_v5_under_read_guard(
            &guard, &loaded, now,
        )?;
    let semantic_packs = loaded
        .pack_bodies
        .iter()
        .map(|(id, body)| crate::operator_rules::SemanticPack {
            id: id.as_str(),
            body: body.as_ref(),
        })
        .collect::<Vec<_>>();
    let config_revision = snapshot.revision().to_string();
    let operator_policy_hash =
        crate::operator_rules::hash_policy_candidate(&loaded.config, &semantic_packs)?.to_string();
    let candidate = match candidate_runtime.matching(&config_revision, &operator_policy_hash)? {
        Some(candidate) => candidate,
        None => {
            let candidate = candidate_runtime.compile(
                config_revision.clone(),
                operator_policy_hash.clone(),
                &loaded.config,
                &loaded.pack_bodies,
            )?;
            candidate_runtime.remember_candidate(Arc::clone(&candidate))?;
            candidate
        }
    };
    let projected = candidate.config().validation_projection()?;
    let identity = ActivePolicyIdentity {
        daemon_instance_id: daemon_instance_id.to_string(),
        config_revision,
        operator_policy_hash,
        resolver_generation: 1,
    };
    // Preserve the lifecycle audit encoding, but hash captured bytes so a
    // later disk edit cannot relabel the policy being published.
    let mut members = BTreeMap::new();
    for member in snapshot.inventory().members() {
        if member.kind() == PolicyMemberKind::Pack {
            continue;
        }
        if let PolicyMemberState::Present(bytes) = member.state() {
            members.insert(
                guard.tree_io().identity.root.join(member.path()),
                hex::encode(Sha256::digest(bytes)),
            );
        }
    }
    let mut digest = Sha256::new();
    for (path, hash) in &members {
        digest.update(path.display().to_string().as_bytes());
        digest.update(b":");
        digest.update(hash.as_bytes());
        digest.update(b"\n");
    }
    #[cfg(feature = "cluster")]
    let cluster_snapshot = Some(Arc::new(
        crate::cluster::artifact::PolicySnapshot::from_verified_candidate(&candidate)?,
    ));
    Ok(CapturedOperatorPolicy {
        files_loaded: loaded.files_loaded,
        projected,
        compiled: candidate.compiled(),
        identity,
        audit_hash: (!members.is_empty()).then(|| hex::encode(digest.finalize())),
        #[cfg(feature = "cluster")]
        cluster_snapshot,
    })
}

fn format_guarded_load_error(error: crate::config::loader::GuardedLoadFailure) -> String {
    use crate::config::loader::GuardedLoadFailure;
    match error {
        GuardedLoadFailure::Diagnostics(errors) => format_config_errors(&errors),
        GuardedLoadFailure::UnsafePath(error)
        | GuardedLoadFailure::BudgetExceeded(error)
        | GuardedLoadFailure::TreeChanged(error)
        | GuardedLoadFailure::RecoveryRequired(error)
        | GuardedLoadFailure::Storage(error) => format!("{error:#}"),
    }
}

fn format_config_errors(errors: &[crate::config::error::ConfigError]) -> String {
    errors
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("; ")
}

fn publish_active_policy(
    profiles: Option<&Arc<ProfileResolver>>,
    config: &crate::config::schema::ConfigV1,
    compiled: Arc<CompiledOperatorRules>,
    identity: ActivePolicyIdentity,
    cluster_state: ClusterReloadHandle<'_>,
) {
    let active_identity = profiles.map(|resolver| {
        resolver.swap_with_operator_rules_and_policy_identity(config, compiled, identity)
    });

    #[cfg(not(feature = "cluster"))]
    let _ = (active_identity, cluster_state);

    #[cfg(feature = "cluster")]
    if let (Some(state), Some(identity)) = (cluster_state, active_identity) {
        state.set_primary_active_identity(identity);
    }
}

#[allow(clippy::too_many_arguments)]
async fn install_runtime_reload(
    runtime_reload: Option<RuntimeReloadContext<'_>>,
    prepared_upstream: &mut Option<crate::upstream::PreparedUpstream>,
    prepared_acl: &Option<Arc<Vec<crate::config::cidr::Cidr>>>,
    stats: Option<&Arc<StatsEngine>>,
    security: Option<&Arc<SecurityLayer>>,
    config: &crate::config::schema::ConfigV1,
    config_path: &Path,
    api_token_hash: &Arc<arc_swap::ArcSwap<Option<String>>>,
    acl_handle: &Arc<arc_swap::ArcSwapOption<Vec<crate::config::cidr::Cidr>>>,
) {
    // Install only after the list pipeline has either completed or proved it
    // can be reused. An activation identity published after this function
    // therefore describes every live reloadable consumer, not a candidate
    // that can still fail in the long-running list preparation phase.
    if let (Some(context), Some(prepared)) = (runtime_reload, prepared_upstream.take()) {
        context.upstream.install(prepared);
        // Resident entries are removed before activation is acknowledged.
        // Pre-swap misses and prefetches carry their generation into the
        // cache and evict a completed fill if this swap superseded it. That
        // check stays on the miss path; ordinary cache hits pay nothing.
        context.cache.clear().await;
    }

    if let Some(engine) = stats {
        apply_query_log_reload(engine, &config.tracking, config_path);
    }

    // Only parameters of already-built checkers reload. Their enabled
    // topology is part of RestartOnlyRuntimeFingerprint, because rebuilding
    // a checker here would reset live rate counters.
    if let Some(sec) = security {
        if let Some(td) = sec.tunneling.as_ref() {
            td.set_params(&config.security.tunneling);
        }
        if let Some(rl) = sec.rate_limiter.as_ref() {
            rl.set_params(&config.security.rate_limit);
        }
        if let Some(rrl) = sec.rrl.as_ref() {
            rrl.set_params(&config.security.rrl);
        }
    }

    api_token_hash.store(Arc::new(config.api.token_hash.clone()));
    acl_handle.store(prepared_acl.clone());
    let acl_count = prepared_acl.as_ref().map_or(0, |cidrs| cidrs.len());
    tracing::info!(count = acl_count, "server.allow_from ACL reloaded");
}

#[cfg(feature = "cluster")]
async fn prepare_cluster_policy(
    config_path: &Path,
    cluster_state: ClusterReloadHandle<'_>,
    snapshot: Option<Arc<crate::cluster::artifact::PolicySnapshot>>,
) -> anyhow::Result<Option<crate::cluster::state::PreparedPolicyArtifact>> {
    let (Some(state), Some(snapshot)) = (cluster_state, snapshot) else {
        return Ok(None);
    };
    let state = Arc::clone(state);
    let master = config_path.to_path_buf();
    tokio::task::spawn_blocking(move || {
        let guard = crate::config::write_lock::acquire_for_migration(&master)?;
        state.prepare_policy(&guard, snapshot).map(Some)
    })
    .await?
}

#[cfg(feature = "cluster")]
fn install_cluster_policy(
    cluster_state: ClusterReloadHandle<'_>,
    prepared: Option<crate::cluster::state::PreparedPolicyArtifact>,
) {
    if let (Some(state), Some(prepared)) = (cluster_state, prepared) {
        state.install_policy(prepared);
    }
}

fn classify_activation(
    request: &ActivationRequest,
    active: Option<ActivePolicyIdentity>,
    reload: Result<bool, String>,
) -> ActivationResult {
    let active = active.filter(ActivePolicyIdentity::is_known);
    match reload {
        Err(reason) => ActivationResult::Unknown { active, reason },
        Ok(false) => ActivationResult::Rejected {
            active,
            reason:
                "policy reload rejected by validation or source admission; see reload diagnostics"
                    .into(),
        },
        Ok(true) => match active {
            Some(identity) if identity.config_revision != request.expected_config_revision => {
                ActivationResult::Superseded {
                    active: identity,
                    superseding_operation_id: None,
                }
            }
            Some(identity) if identity.operator_policy_hash == request.expected_policy_hash => {
                ActivationResult::Applied(identity)
            }
            active => ActivationResult::Unknown {
                active,
                reason: "reload completed without the expected immutable policy identity".into(),
            },
        },
    }
}

fn retire_activation_queue(
    receiver: &mut mpsc::Receiver<ActivationRequest>,
    active: Option<ActivePolicyIdentity>,
) {
    receiver.close();
    let active = active.filter(ActivePolicyIdentity::is_known);
    while let Ok(request) = receiver.try_recv() {
        let _ = request.completion.send(ActivationResult::Unknown {
            active: active.clone(),
            reason: "daemon stopped before processing the activation request".into(),
        });
    }
}

/// Re-evaluate schedules from the active policy snapshot. Called every 60 s by
/// the signal loop so an unrelated disk edit cannot become active without a
/// successful reload.
/// Expired rows remain inert until an explicit configuration mutation removes
/// them: automatic pruning could activate unrelated pending edits on disk.
fn handle_schedule_tick(profiles: Option<&Arc<ProfileResolver>>) {
    let resolver = match profiles {
        Some(r) => r,
        None => return,
    };
    let identity = resolver.refresh_schedules();
    tracing::debug!(
        generation = identity.resolver_generation,
        "schedule tick: active profile map rebuilt"
    );
}

/// Everything the list pipeline consumes, distilled into a value two
/// reloads can be compared on.
///
/// A naive reload rebuilds the entire domain map on every call, whatever
/// had actually changed — expensive with warm caches, far worse once
/// they expire. The operator's real workflow (adding an allow rule to a
/// device) would pay that cost while changing nothing this type covers.
///
/// **The predicate is "did anything the list pipeline consume change?",
/// deliberately not "did the config tree hash change".** The tree hash
/// moves on *every* edit, so a hash gate would reintroduce the exact
/// waste this type exists to avoid.
///
/// **Membership rule.** A field belongs here if it is baked into the
/// [`ListManager`] at construction, or changes what the parser yields
/// from an unchanged URL set. Fields that only affect *presentation* —
/// `display_name`, `tags`, `lists.staleness_threshold_secs` — are
/// excluded on purpose: the skip path still refreshes the status
/// registry and the profile resolver, which is where those land.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ListsFingerprint {
    /// Representative source vector, **order-sensitive**. [`SourceBitMap::from_plan`]
    /// assigns bits positionally, so reordering `lists.sources` re-maps
    /// every profile's bitmask and genuinely does need a rebuild — never
    /// sort this before comparing.
    sources: Vec<String>,
    /// Catalog-resolved identities. A slug retaining its spelling while the
    /// selected catalog moves its URL still needs a fresh manager.
    canonical_urls: Vec<String>,
    /// Ordered exact request targets. Canonical equivalence is insufficient:
    /// query spelling can select different upstream content or validators.
    fetch_urls: Vec<String>,
    /// Command and status aliases belong to the manager generation too.
    source_aliases: Vec<(String, String)>,
    id_aliases: Vec<(crate::config::schema::Id, String)>,
    /// Effective cadence in representative order. This is what the manager
    /// consumes, including schema-3 inheritance and schema-4 row floors.
    source_update_interval_secs: Vec<u64>,
    max_body_bytes: usize,
    /// This changes what the parser keeps
    /// from an unchanged URL set, so a gate that only diffs URLs would
    /// serve a stale-width map while reporting success.
    max_entries: usize,
    /// Effective caps in representative order. Row values must participate:
    /// changing only one source's cap changes the corpus for unchanged bytes.
    source_max_entries: Vec<usize>,
    /// The raw config value, *not* the resolved path: resolving means
    /// calling [`lists_cache_dir`], which `create_dir_all`s as a side
    /// effect. A fingerprint must not touch the filesystem.
    cache_dir: PathBuf,
    /// Missing here would mean a reload that changes only `[lists]
    /// max_total_domains` matches the live fingerprint, takes the
    /// reuse-gate skip path below, and never reaches
    /// `mgr.set_max_total_domains` — so `warden lists set max_total_domains`
    /// (and a raw SIGHUP after hand-editing the key) rewrites config.toml,
    /// `warden lists show` reads the new value straight off it and reports
    /// success, but the live `ListManager`'s `corpus_guard` keeps enforcing
    /// the OLD ceiling until the next full daemon restart — a reload
    /// reporting success while the live process keeps the old intent.
    max_total_domains: usize,
    shrink_guard_enabled: bool,
    shrink_guard_max_drop_pct: u8,
    /// Only first-owner fields reach the live manager. Alias-only fields
    /// cannot trigger a rebuild because the source plan ignores them.
    source_owners: Vec<SourceOwnerFingerprint>,
    /// Profile overrides alter the policy masks the manager publishes even
    /// when no row-level list field changed.
    profile_list_policies:
        BTreeMap<String, BTreeMap<crate::config::schema::Id, crate::config::schema::ListPolicy>>,
    /// SipHash of the *resolved* bearer tokens, key-sorted. A digest and
    /// not the values themselves, because this struct derives `Debug`
    /// and must never be able to print a secret (same reasoning as the
    /// hand-written `Debug` on [`SourceTokenMap`]). Hashing the resolved
    /// value rather than the `auth_token_ref` name means rotating a
    /// secret in `secrets.toml` forces the rebuild that puts the new
    /// token on the wire.
    token_digest: u64,
}

/// The source-owner fields that change fetch or parse behavior.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SourceOwnerFingerprint {
    id: crate::config::schema::Id,
    format: crate::config::schema::BlocklistFormat,
    auth_token_ref: Option<String>,
    base: crate::config::schema::BlocklistBase,
    trust: crate::config::schema::BlocklistTrust,
    max_consecutive_failures: u32,
    /// The `imported.local` bridge (`lists::manager::try_bridge_imported_local`)
    /// re-reads this row's on-disk file fresh on every `ListManager::refresh`
    /// — but nothing above this field changes when the operator edits that
    /// file's *content* rather than its config row. Without it, a SIGHUP sent
    /// right after such an edit matches the live fingerprint, takes the
    /// reuse-gate skip path, and never calls `refresh()` at all: the daemon
    /// logs "reload: list pipeline inputs unchanged, reusing live blocklist
    /// (no rebuild)" and keeps serving the pre-edit list, indefinitely — a
    /// reload reporting success on a no-op. `None` for any non-`imported.local`
    /// row and for one whose file is
    /// currently unreadable; see [`crate::lists::manager::stat_local_source`].
    local_stamp: Option<crate::lists::manager::LocalFileStamp>,
}

impl ListsFingerprint {
    /// Build from the plan `handle_reload` already derived.
    fn compute(
        config: &crate::config::schema::ConfigV1,
        plan: &ResolvedSourcePlan,
        source_tokens: &SourceTokenMap,
        config_dir: &Path,
    ) -> Self {
        use std::hash::{Hash, Hasher};

        // Sort representative/token pairs so equal plans hash equally.
        let mut token_entries: Vec<(&str, &str)> = plan
            .sources()
            .filter_map(|source| {
                source_tokens
                    .token_for_url(source.representative())
                    .map(|token| (source.representative(), token))
            })
            .collect();
        token_entries.sort_unstable();
        // `DefaultHasher::new` is fixed-key, so it is deterministic for
        // the life of the process. That is the whole requirement here —
        // the digest is only ever compared against another one computed
        // by this same daemon, and never persisted or sent anywhere.
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        token_entries.hash(&mut hasher);

        Self {
            sources: plan.representatives(),
            canonical_urls: plan
                .sources()
                .map(|source| source.canonical_url().to_string())
                .collect(),
            fetch_urls: plan
                .sources()
                .map(|source| source.fetch_url().to_string())
                .collect(),
            source_aliases: {
                let mut aliases: Vec<_> = plan
                    .source_aliases()
                    .iter()
                    .map(|(alias, representative)| (alias.clone(), representative.clone()))
                    .collect();
                aliases.sort_unstable();
                aliases
            },
            id_aliases: {
                let mut aliases: Vec<_> = plan
                    .id_aliases()
                    .iter()
                    .map(|(id, representative)| (id.clone(), representative.clone()))
                    .collect();
                aliases.sort_unstable();
                aliases
            },
            source_update_interval_secs: plan
                .sources()
                .map(|source| source.effective_update_interval_secs())
                .collect(),
            max_body_bytes: config.lists.max_body_bytes,
            max_entries: config.lists.max_entries,
            source_max_entries: plan
                .sources()
                .map(|source| source.effective_max_entries())
                .collect(),
            cache_dir: config.lists.cache_dir.clone(),
            max_total_domains: config.lists.max_total_domains,
            shrink_guard_enabled: config.lists.shrink_guard_enabled,
            shrink_guard_max_drop_pct: config.lists.shrink_guard_max_drop_pct,
            source_owners: plan
                .sources()
                .filter_map(|source| source.owner_blocklist())
                .map(|b| SourceOwnerFingerprint {
                    id: b.id.clone(),
                    format: b.format,
                    auth_token_ref: b.auth_token_ref.clone(),
                    base: b.base,
                    trust: b.trust,
                    max_consecutive_failures: b.max_consecutive_failures,
                    local_stamp: matches!(b.trust, crate::config::schema::BlocklistTrust::Local)
                        .then(|| crate::lists::manager::stat_local_source(&b.url, config_dir))
                        .flatten(),
                })
                .collect(),
            profile_list_policies: config
                .profiles
                .iter()
                .map(|(id, profile)| {
                    let policies = profile
                        .lists
                        .iter()
                        .filter(|(list_id, _)| plan.representative_for_id(list_id).is_some())
                        .map(|(list_id, policy)| (list_id.clone(), *policy))
                        .collect();
                    (id.clone(), policies)
                })
                .collect(),
            token_digest: hasher.finish(),
        }
    }

    /// Test helper deriving the fallback plan and its tokens from config.
    #[cfg(test)]
    fn from_config(
        config: &crate::config::schema::ConfigV1,
        secrets: &crate::config::secrets::Secrets,
        config_dir: &Path,
    ) -> Self {
        let plan = ResolvedSourcePlan::build_for_schema(
            &Catalog::fallback(),
            &config.lists.sources,
            &config.blocklists,
            &config.profiles,
            crate::lists::source_key::RowControlDefaults {
                max_entries: config.lists.max_entries,
                update_interval_secs: config.lists.update_interval_secs,
            },
            config.schema_version,
        )
        .expect("test fingerprint config has unambiguous list aliases");
        Self::compute(
            config,
            &plan,
            &SourceTokenMap::from_plan(&plan, secrets),
            config_dir,
        )
    }
}

/// The reuse gate's predicate, isolated from `handle_reload` so it can
/// be exercised without standing up a daemon — the rebuild branch it
/// guards puts `lists.purge.cc` on the wire, so the only way to test
/// both directions offline is at this seam.
///
/// `live_refresh` is whether a refresh loop — and therefore a live
/// [`ListManager`] — actually exists to be reused. A finished task is not
/// live even while its handle is still `Some`: treating it as reusable would
/// leave the daemon with a stale map and no future refreshes. It is ANDed
/// rather than assumed: with no live loop, a matching fingerprint would
/// otherwise "reuse" a manager that is not there, leaving the daemon
/// with a stale map and nothing refreshing it. Every uncertain case
/// resolves to `false`, i.e. rebuild.
fn should_reuse_live_lists(
    live_refresh: bool,
    live: Option<&ListsFingerprint>,
    next: &ListsFingerprint,
) -> bool {
    live_refresh && live == Some(next)
}

fn has_live_list_manager(task: Option<&ListManagerTask>) -> bool {
    task.is_some_and(|task| !task.is_finished())
}

#[cfg(test)]
tokio::task_local! {
    static PANIC_RELOAD_WORKER: bool;
}

/// Handle SIGHUP / IPC reload: re-read v1 config, validate, re-download
/// lists, rebuild profiles, swap into filter.
///
/// `list_client` is the hardened `reqwest::Client` used for catalog and list
/// downloads (see `http_client::build_bulk_list_client`).
///
/// Every call emits exactly one audit record with the
/// invoker uid (from `SO_PEERCRED` on the IPC socket; `None` for SIGHUP),
/// the on-disk file set, and the pre/post tree hash. Rejected reloads
/// (validator errors) still emit a record with `pre_hash == post_hash`
/// and the errors listed verbatim — so a reader can tell "someone asked
/// and we refused" from "someone asked and we accepted".
#[allow(clippy::too_many_arguments)]
async fn handle_reload(
    config_path: &Path,
    list_client: &reqwest::Client,
    runtime_reload: Option<RuntimeReloadContext<'_>>,
    filter: &Arc<FilterEngine>,
    profiles: Option<&Arc<ProfileResolver>>,
    candidate_runtime: &Arc<crate::operator_rules::PolicyCandidateRuntime>,
    refresh_handle: &mut Option<ListManagerTask>,
    lists_fingerprint: &mut Option<ListsFingerprint>,
    audit_writer: &AuditWriter,
    current_files: &mut Vec<PathBuf>,
    current_hash: &mut Option<String>,
    api_token_hash: &Arc<arc_swap::ArcSwap<Option<String>>>,
    acl_handle: &Arc<arc_swap::ArcSwapOption<Vec<crate::config::cidr::Cidr>>>,
    stats: Option<&Arc<StatsEngine>>,
    list_status_registry: Option<&Arc<ListStatusRegistry>>,
    notification_tx: &tokio::sync::broadcast::Sender<crate::ipc::protocol::IpcNotification>,
    list_cmd_tx_swap: &Arc<arc_swap::ArcSwap<ListManagerEndpoint>>,
    invoker_uid: Option<u32>,
    cluster_state: ClusterReloadHandle<'_>,
    security: Option<&Arc<SecurityLayer>>,
) -> anyhow::Result<Option<bool>> {
    #[cfg(not(feature = "cluster"))]
    let _ = cluster_state;
    let pre_hash = current_hash.clone();

    let daemon_instance_id = match profiles.map(|resolver| resolver.active_policy_identity()) {
        Some(identity) if !identity.daemon_instance_id.is_empty() => identity.daemon_instance_id,
        _ => new_daemon_instance_id()?,
    };
    let capture_path = config_path.to_path_buf();
    let candidate_runtime = Arc::clone(candidate_runtime);
    let captured = match tokio::task::spawn_blocking(move || {
        capture_operator_policy(
            &capture_path,
            &daemon_instance_id,
            &candidate_runtime,
            AuditWarningEmission::Emit,
        )
    })
    .await?
    {
        Ok(captured) => captured,
        Err(error) => {
            tracing::error!(%error, "config reload failed");
            let err_strings = vec![error.to_string()];
            let rec = AuditRecord::new(AuditEvent::Reload, AuditResult::Rejected)
                .with_uid(invoker_uid)
                .with_files(current_files.iter())
                .with_pre_hash(pre_hash.clone())
                .with_post_hash(pre_hash)
                .with_errors(err_strings);
            if let Err(e) = audit_writer.append(&rec) {
                tracing::warn!(error = %e, "failed to write audit record");
            }
            // A rejected config still ENDS the reload the caller asked
            // for. Without a mark the counter never moves and a waiter
            // burns its whole timeout to report that it does not know,
            // about a cycle the daemon closed deliberately.
            if let Some(reg) = list_status_registry {
                reg.record_cycle(CycleOutcome::ConfigRejected);
            }
            return Ok(None);
        }
    };
    let CapturedOperatorPolicy {
        files_loaded,
        projected,
        compiled,
        identity,
        audit_hash: new_hash,
        #[cfg(feature = "cluster")]
        cluster_snapshot,
    } = captured;
    let config = &projected;

    if let Some(context) = runtime_reload {
        let candidate = match check_cluster_build(config)
            .and_then(|()| check_dnssec_build(config))
            .and_then(|()| RestartOnlyRuntimeFingerprint::from_config(config))
        {
            Ok(candidate) => candidate,
            Err(error) => {
                tracing::error!(%error, "reload aborted: runtime fingerprint rejected");
                let record = AuditRecord::new(AuditEvent::Reload, AuditResult::Rejected)
                    .with_uid(invoker_uid)
                    .with_files(current_files.iter())
                    .with_pre_hash(pre_hash.clone())
                    .with_post_hash(pre_hash)
                    .with_errors([error.to_string()]);
                if let Err(write_error) = audit_writer.append(&record) {
                    tracing::warn!(error = %write_error, "failed to write audit record");
                }
                if let Some(registry) = list_status_registry {
                    registry.record_cycle(CycleOutcome::ConfigRejected);
                }
                return Ok(None);
            }
        };
        let changed = context.restart_only.changed_sections(&candidate);
        if !changed.is_empty() {
            let error = format!(
                "reload requires daemon restart for runtime sections: {}",
                changed.join(", ")
            );
            tracing::error!(%error, "config reload rejected");
            let record = AuditRecord::new(AuditEvent::Reload, AuditResult::Rejected)
                .with_uid(invoker_uid)
                .with_files(current_files.iter())
                .with_pre_hash(pre_hash.clone())
                .with_post_hash(pre_hash)
                .with_errors([error]);
            if let Err(write_error) = audit_writer.append(&record) {
                tracing::warn!(error = %write_error, "failed to write audit record");
            }
            if let Some(registry) = list_status_registry {
                registry.record_cycle(CycleOutcome::ConfigRejected);
            }
            return Ok(None);
        }
    }

    // Report this accepted config's schedule presence
    // back to the signal loop so it re-arms (or disarms) the 60 s schedule
    // tick. Every reject below returns `None` (gate unchanged → "a rejected
    // reload changes nothing"); every success path returns this value.
    let reload_has_schedules = !config.schedules.is_empty();

    // The auth-hash swap is deferred to AFTER the secrets +
    // source-bitmap gates and the resolver swap (see below), so a reload that
    // aborts on one of those gates leaves the in-memory admin token untouched
    // too — "a rejected reload changes nothing".
    log_empty_profile_lists_warning(config);

    // Secrets live in a separate file; reload them here so
    // that `auth_token_ref` additions or edits take effect without a full
    // daemon restart. A rejected secrets file (e.g. mode widened to 0644)
    // aborts the reload with the config already-accepted — we do NOT
    // revert to the pre-reload state, because the daemon's in-memory
    // state has not changed yet at this point.
    let secrets_path = secrets::secrets_path_for(config_path);
    let secrets_state = match secrets::load_secrets(&secrets_path) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = %e, "reload aborted: secrets file rejected");
            let rec = AuditRecord::new(AuditEvent::Reload, AuditResult::Rejected)
                .with_uid(invoker_uid)
                .with_files(current_files.iter())
                .with_pre_hash(pre_hash.clone())
                .with_post_hash(pre_hash)
                .with_errors([e.to_string()]);
            if let Err(write_err) = audit_writer.append(&rec) {
                tracing::warn!(error = %write_err, "failed to write audit record");
            }
            // Same reason as the reject above: the cycle is over.
            if let Some(reg) = list_status_registry {
                reg.record_cycle(CycleOutcome::ConfigRejected);
            }
            return Ok(None);
        }
    };

    // The old refresh loop is NOT retired here. This point sits above the
    // source-bitmap reject gate, the empty-sources branch, and the reuse
    // gate — retiring here would orphan the live manager on paths that
    // never re-arm one (a rejected bitmap build would leave the daemon
    // silently never refreshing its lists again), and it is incompatible
    // with reusing the live manager. Each path that genuinely retires the
    // manager retires it itself: the empty-sources branch and the rebuild
    // path.

    #[cfg(feature = "cluster")]
    let node_corpus = match nodes_runtime::NodeCorpusRuntime::load(config_path, config, true) {
        Ok(context) => context,
        Err(error) => {
            tracing::error!(%error, "reload rejected: node corpus unavailable");
            if let Some(registry) = list_status_registry {
                registry.record_cycle(CycleOutcome::ConfigRejected);
            }
            return Ok(None);
        }
    };
    #[cfg(feature = "cluster")]
    let (prepared_node_ip, node_auxiliary) = match &node_corpus {
        Some(context) => match nodes_runtime::prepare_ip_filter(config, list_client, context).await
        {
            Ok(prepared) => prepared,
            Err(error) => {
                tracing::error!(%error, "reload rejected: IP corpus preparation failed");
                if let Some(registry) = list_status_registry {
                    registry.record_cycle(CycleOutcome::ConfigRejected);
                }
                return Ok(None);
            }
        },
        None => (None, Vec::new()),
    };
    #[cfg(feature = "cluster")]
    let enrollment_artifact = match &node_corpus {
        Some(context) => match &context.secondary {
            Some(manifest) => Some(manifest.artifact.clone()),
            None => match cluster_snapshot.clone() {
                Some(snapshot) => match crate::cluster::node_control::capture_enrollment_policy(
                    config_path,
                    snapshot,
                ) {
                    Ok(artifact) => Some(artifact),
                    Err(error) => {
                        tracing::error!(%error, "reload rejected: enrollment policy capture failed");
                        if let Some(registry) = list_status_registry {
                            registry.record_cycle(CycleOutcome::ConfigRejected);
                        }
                        return Ok(None);
                    }
                },
                None => {
                    tracing::error!("reload rejected: enrollment policy snapshot unavailable");
                    if let Some(registry) = list_status_registry {
                        registry.record_cycle(CycleOutcome::ConfigRejected);
                    }
                    return Ok(None);
                }
            },
        },
        None => None,
    };
    let has_enabled_sources =
        config_declares_list_sources(config) || modern_primary_auxiliary(config);
    let lists_dir = has_enabled_sources.then(|| lists_cache_dir(config_path, config));
    #[cfg(feature = "cluster")]
    let received_catalog = node_corpus.as_ref().and_then(|context| {
        context
            .secondary
            .as_ref()
            .map(|manifest| manifest.catalog())
    });
    #[cfg(not(feature = "cluster"))]
    let received_catalog: Option<Catalog> = None;
    let catalog = match received_catalog {
        Some(catalog) => catalog,
        None => match &lists_dir {
            Some(dir) => {
                fetch_catalog_or_fallback(list_client, dir, CatalogPreference::Network).await
            }
            None => Catalog::fallback(),
        },
    };
    let source_plan = match ResolvedSourcePlan::build_for_schema(
        &catalog,
        &config.lists.sources,
        &config.blocklists,
        &config.profiles,
        crate::lists::source_key::RowControlDefaults {
            max_entries: config.lists.max_entries,
            update_interval_secs: config.lists.update_interval_secs,
        },
        config.schema_version,
    ) {
        Ok(plan) => plan,
        Err(e) => {
            tracing::error!(error = %e, "reload aborted: source identity plan failed");
            let rec = AuditRecord::new(AuditEvent::Reload, AuditResult::Rejected)
                .with_uid(invoker_uid)
                .with_files(current_files.iter())
                .with_pre_hash(pre_hash.clone())
                .with_post_hash(pre_hash)
                .with_errors([e.to_string()]);
            if let Err(write_err) = audit_writer.append(&rec) {
                tracing::warn!(error = %write_err, "failed to write audit record");
            }
            if let Some(reg) = list_status_registry {
                reg.record_cycle(CycleOutcome::ConfigRejected);
            }
            return Ok(None);
        }
    };
    if rejects_declared_empty_plan(config, &source_plan) {
        // Keep the historical orphan-source warning permissive when another
        // source still resolves. Only an entirely empty plan would otherwise
        // make a declared source set indistinguishable from an operator clear.
        let error = "configured list sources resolved to no usable catalog entries";
        tracing::error!("reload aborted: {error}");
        let rec = AuditRecord::new(AuditEvent::Reload, AuditResult::Rejected)
            .with_uid(invoker_uid)
            .with_files(current_files.iter())
            .with_pre_hash(pre_hash.clone())
            .with_post_hash(pre_hash)
            .with_errors([error.to_string()]);
        if let Err(write_err) = audit_writer.append(&rec) {
            tracing::warn!(error = %write_err, "failed to write audit record");
        }
        if let Some(reg) = list_status_registry {
            reg.record_cycle(CycleOutcome::ConfigRejected);
        }
        return Ok(None);
    }
    let merged_sources = source_plan.representatives();

    let source_bits = match SourceBitMap::from_plan(&source_plan) {
        Ok(bits) => bits,
        Err(e) => {
            tracing::error!(error = %e, "reload aborted: source bit map build failed");
            let rec = AuditRecord::new(AuditEvent::Reload, AuditResult::Rejected)
                .with_uid(invoker_uid)
                .with_files(current_files.iter())
                .with_pre_hash(pre_hash.clone())
                .with_post_hash(pre_hash)
                .with_errors([e.to_string()]);
            if let Err(write_err) = audit_writer.append(&rec) {
                tracing::warn!(error = %write_err, "failed to write audit record");
            }
            // Same reason as the reject above: the cycle is over.
            if let Some(reg) = list_status_registry {
                reg.record_cycle(CycleOutcome::ConfigRejected);
            }
            return Ok(None);
        }
    };

    let mut prepared_upstream = match runtime_reload {
        Some(context) => {
            let upstream = config.upstream.clone();
            let forwarding = config.forwarding.clone();
            let dnssec = config.dnssec.clone();
            let client = context.client.clone();
            let runtime = Arc::clone(context.upstream);
            let prepared = tokio::task::spawn_blocking(move || {
                runtime.prepare(&upstream, &forwarding, &client, &dnssec)
            })
            .await
            .map_err(|error| anyhow::anyhow!("upstream generation worker failed: {error}"))
            .and_then(|result| result);

            match prepared {
                Ok(prepared) => prepared,
                Err(error) => {
                    tracing::error!(%error, "reload aborted: upstream generation rejected");
                    let record = AuditRecord::new(AuditEvent::Reload, AuditResult::Rejected)
                        .with_uid(invoker_uid)
                        .with_files(current_files.iter())
                        .with_pre_hash(pre_hash.clone())
                        .with_post_hash(pre_hash)
                        .with_errors([error.to_string()]);
                    if let Err(write_error) = audit_writer.append(&record) {
                        tracing::warn!(error = %write_error, "failed to write audit record");
                    }
                    if let Some(registry) = list_status_registry {
                        registry.record_cycle(CycleOutcome::ConfigRejected);
                    }
                    return Ok(None);
                }
            }
        }
        None => None,
    };

    let prepared_acl = match parse_allow_from(&config.server.allow_from) {
        Ok(acl) => acl,
        Err(error) => {
            tracing::error!(%error, "reload aborted: server.allow_from preparation rejected");
            let record = AuditRecord::new(AuditEvent::Reload, AuditResult::Rejected)
                .with_uid(invoker_uid)
                .with_files(current_files.iter())
                .with_pre_hash(pre_hash.clone())
                .with_post_hash(pre_hash)
                .with_errors([error.to_string()]);
            if let Err(write_error) = audit_writer.append(&record) {
                tracing::warn!(error = %write_error, "failed to write audit record");
            }
            if let Some(registry) = list_status_registry {
                registry.record_cycle(CycleOutcome::ConfigRejected);
            }
            return Ok(None);
        }
    };

    #[cfg(feature = "cluster")]
    let prepared_cluster =
        match prepare_cluster_policy(config_path, cluster_state, cluster_snapshot).await {
            Ok(prepared) => prepared,
            Err(error) => {
                tracing::error!(%error, "reload aborted: cluster artifact preparation rejected");
                let record = AuditRecord::new(AuditEvent::Reload, AuditResult::Rejected)
                    .with_uid(invoker_uid)
                    .with_files(current_files.iter())
                    .with_pre_hash(pre_hash.clone())
                    .with_post_hash(pre_hash)
                    .with_errors([error.to_string()]);
                if let Err(write_error) = audit_writer.append(&record) {
                    tracing::warn!(error = %write_error, "failed to write audit record");
                }
                if let Some(registry) = list_status_registry {
                    registry.record_cycle(CycleOutcome::ConfigRejected);
                }
                return Ok(None);
            }
        };

    // Derived from the map just built — one build, not two.
    let policy_masks = source_bits.project_policy(&config.blocklists, &config.profiles);

    let new_files = files_loaded;

    if merged_sources.is_empty() && !modern_primary_auxiliary(config) {
        tracing::info!("no list sources in config, clearing blocklist");
        // The operator removed every source: retire the live manager so
        // its refresh loop cannot re-download the old sources and
        // re-populate the map we are about to clear.
        list_cmd_tx_swap.store(Arc::new(ListManagerEndpoint::Transitioning));
        if let Some(h) = refresh_handle.take() {
            if let Err(error) = h.retire().await {
                tracing::error!(%error, "list manager controller ended abnormally during reload");
            }
        }
        *lists_fingerprint = None;
        #[cfg(feature = "cluster")]
        if node_corpus.is_some() {
            nodes_runtime::clear_active(
                runtime_reload.and_then(|runtime| runtime.node_observe),
                cluster_state,
            );
        }
        filter.swap_blocklist(Default::default());
        install_runtime_reload(
            runtime_reload,
            &mut prepared_upstream,
            &prepared_acl,
            stats,
            security,
            config,
            config_path,
            api_token_hash,
            acl_handle,
        )
        .await;
        publish_active_policy(profiles, config, compiled, identity, cluster_state);
        #[cfg(feature = "cluster")]
        install_cluster_policy(cluster_state, prepared_cluster);
        #[cfg(feature = "cluster")]
        if let Some(context) = &node_corpus {
            if let (Some(live), Some(prepared)) = (
                runtime_reload.and_then(|runtime| runtime.node_ip_filter),
                prepared_node_ip.as_ref(),
            ) {
                live.install_prepared(prepared);
            }
            if let Err(error) = context.finish_activation(
                None,
                runtime_reload.and_then(|runtime| runtime.node_observe),
                cluster_state,
                enrollment_artifact.as_ref(),
                node_auxiliary.clone(),
            ) {
                nodes_runtime::clear_active(
                    runtime_reload.and_then(|runtime| runtime.node_observe),
                    cluster_state,
                );
                tracing::error!(%error, "node corpus activation proof unavailable; DNS continues with installed policy");
            }
        }
        let rec = AuditRecord::new(AuditEvent::Reload, AuditResult::Ok)
            .with_uid(invoker_uid)
            .with_files(new_files.iter())
            .with_pre_hash(pre_hash)
            .with_post_hash(new_hash.clone());
        if let Err(e) = audit_writer.append(&rec) {
            tracing::warn!(error = %e, "failed to write audit record");
        }
        *current_files = new_files;
        *current_hash = new_hash;
        // The blocklist was CLEARED, which is a completed cycle and the one
        // an operator most needs told: this host now filters nothing. It
        // never reaches the manager, so this is the only place that can say
        // so.
        if let Some(reg) = list_status_registry {
            reg.sync_plan(&source_plan);
            // An intentional no-sources clear is a new, empty corpus, not a
            // continued refusal. Clear both lifecycle payloads before the
            // completed mark makes it observable.
            reg.set_corpus_refusal(None);
            reg.clear_corpus_freeze();
            reg.record_cycle_with_source_coverage(CycleOutcome::ClearedNoSources, false, 0);
        }
        list_cmd_tx_swap.store(Arc::new(ListManagerEndpoint::EmptyStable));
        return Ok(Some(reload_has_schedules));
    }

    let source_tokens = SourceTokenMap::from_plan(&source_plan, &secrets_state);

    // Computed here, ahead of the manager construction it feeds, so the
    // fingerprint can stat `trust = local` sources through the same
    // directory the bridge itself resolves against. Pure path
    // arithmetic, no I/O of its own — safe to compute before the gate
    // decides anything.
    let bridge_config_dir_for_fingerprint = config_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf();

    // ── reuse gate ──────────────────────────
    //
    // Everything above this point has been prepared but not published. Each
    // success branch installs the runtime consumers, resolver, and policy
    // identity only after the list path succeeds or is proven reusable.
    // What follows is the 9.9 M-domain rebuild — 16-25 s warm, 164 s once
    // the disk caches expire — and it is worth doing only when the list
    // pipeline's own inputs moved.
    //
    // The reuse branch must still publish the prepared profile policy;
    // otherwise an unrelated list fingerprint would hide the operator's
    // profile or device change.
    //
    // A present, unfinished `refresh_handle` is the proof that a live
    // `ListManager` exists to reuse. A finished handle is dead generation
    // state, so rebuild regardless of what the fingerprint says.
    let fingerprint = ListsFingerprint::compute(
        config,
        &source_plan,
        &source_tokens,
        &bridge_config_dir_for_fingerprint,
    );
    #[cfg(feature = "cluster")]
    let node_requires_preparation = node_corpus.is_some();
    #[cfg(not(feature = "cluster"))]
    let node_requires_preparation = false;
    if !node_requires_preparation
        && should_reuse_live_lists(
            has_live_list_manager(refresh_handle.as_ref()),
            lists_fingerprint.as_ref(),
            &fingerprint,
        )
    {
        // The registry follows the accepted alias plan even when the
        // manager is reused.
        if let Some(reg) = list_status_registry {
            reg.sync_plan(&source_plan);
            // A fingerprint skip IS a completed cycle. The manager can also
            // report an unchanged usable corpus after a failed source attempt,
            // but it never runs here — the function returns below — so a mark
            // written only in the manager would
            // leave the sequence frozen through this completed reload, and a
            // waiter would report "still reloading" about a cycle that
            // finished instantly.
            //
            // `corpus_refusal` is deliberately NOT cleared: no corpus was
            // built, so any standing refusal is still the truth about what
            // is installed. Clearing it here would announce a recovery that
            // did not happen.
            reg.record_cycle(CycleOutcome::SkippedUnchanged);
        }

        tracing::info!(
            sources = merged_sources.len(),
            "reload: list pipeline inputs unchanged, reusing live blocklist (no rebuild)"
        );

        install_runtime_reload(
            runtime_reload,
            &mut prepared_upstream,
            &prepared_acl,
            stats,
            security,
            config,
            config_path,
            api_token_hash,
            acl_handle,
        )
        .await;
        publish_active_policy(profiles, config, compiled, identity, cluster_state);
        #[cfg(feature = "cluster")]
        install_cluster_policy(cluster_state, prepared_cluster);

        // A skip is a SUCCESS path and still owes exactly
        // one audit record plus the post-hash write-back — drop either
        // and the next reload's `pre_hash` describes a config that was
        // never live.
        let rec = AuditRecord::new(AuditEvent::Reload, AuditResult::Ok)
            .with_uid(invoker_uid)
            .with_files(new_files.iter())
            .with_pre_hash(pre_hash)
            .with_post_hash(new_hash.clone());
        if let Err(e) = audit_writer.append(&rec) {
            tracing::warn!(error = %e, "failed to write audit record");
        }
        *current_files = new_files;
        *current_hash = new_hash;
        return Ok(Some(reload_has_schedules));
    }

    // Past the gate: this reload genuinely retires the live manager, so
    // its refresh loop stops here.
    // Unpublish before retiring so no IPC sender can target the old
    // generation. Retire before constructing the replacement: an old worker
    // must never publish cache/filter state after the new generation exists.
    if !node_requires_preparation {
        list_cmd_tx_swap.store(Arc::new(ListManagerEndpoint::Transitioning));
        if let Some(h) = refresh_handle.take() {
            if let Err(error) = h.retire().await {
                tracing::error!(%error, "list manager controller ended abnormally during reload");
            }
        }
    }
    let prepared_filter = if node_requires_preparation {
        Arc::new(FilterEngine::new())
    } else {
        filter.clone()
    };

    let interval = Duration::from_secs(config.lists.update_interval_secs);
    // Same value the fingerprint above was stamped against — computed once
    // and reused rather than re-derived, so the two can never disagree.
    let bridge_config_dir = bridge_config_dir_for_fingerprint;

    let mut mgr = ListManager::with_plan_and_tokens(
        list_client.clone(),
        prepared_filter.clone(),
        source_plan.clone(),
        interval,
        source_bits.clone(),
        source_tokens,
        config.lists.max_body_bytes,
        config.lists.max_entries,
        Some(lists_dir.expect("enabled sources selected a cache directory")),
    );

    // Same wiring the boot path applies, rebuilt from the post-reload
    // config. A reload that skipped any of it would serve the PREVIOUS
    // generation's policy against the new corpus — and since list bits
    // are positional, that is not merely stale, it points at different
    // lists — while authenticated lists would fetch anonymously and the
    // retry state machine would stop being driven.
    ManagerWiring::from_config(
        config,
        config_path,
        &source_plan,
        bridge_config_dir,
        policy_masks,
        if node_requires_preparation {
            ListStateWriteback::ReadOnly
        } else {
            ListStateWriteback::Persist
        },
    )
    .apply(&mut mgr);
    #[cfg(feature = "cluster")]
    if let Some(context) = &node_corpus {
        if context.secondary.is_some() {
            context.configure_secondary(&mut mgr)?;
        } else {
            mgr.isolate_candidate_cache(&context.store)?;
        }
    }

    // Keep the registry handle DaemonState reads so stats switch with the
    // plan. `sync_plan` publishes aliases after slots exist, then retires
    // obsolete slots.
    if !node_requires_preparation {
        if let Some(reg) = list_status_registry {
            reg.sync_plan(&source_plan);
            mgr.attach_status_registry(reg.clone());
        }
    }
    // Re-attach the broadcast publisher so the post-reload
    // manager keeps emitting `ListStatsUpdated`. Same Sender clone
    // already wired to `DaemonState.notification_tx`, so future
    // subscribers see the post-reload events without re-subscribing.
    if !node_requires_preparation {
        mgr.set_notification_channel(notification_tx.clone());
        mgr.set_status_persistence_path(list_stats_path(config_path));
    }

    // Wire a fresh out-of-band command channel for the post-reload manager,
    // but keep its sender private until the controller exists. Publishing it
    // before the rebuild worker completes would let IPC accept a command into
    // a generation with no receiver yet.
    let (list_cmd_tx, list_cmd_rx) = tokio::sync::mpsc::channel(16);
    mgr.set_command_channel(list_cmd_rx);

    mgr.load_disk_cache();
    mgr.cleanup_stale_caches();
    #[cfg(test)]
    if PANIC_RELOAD_WORKER
        .try_with(|enabled| *enabled)
        .unwrap_or(false)
    {
        mgr.set_worker_hook_for_test(|at| {
            if at == "start" {
                panic!("injected replacement list worker panic");
            }
        });
    }
    // Keep the tight client for this foreground reload refresh. It runs via
    // the same owned blocking worker as controller refreshes, so parsing and
    // shard work never monopolize the signal-loop runtime thread.
    let (mut mgr, count) = match mgr.refresh_in_blocking(RefreshMode::Scheduled).await {
        Ok(result) => result,
        Err(error) => {
            if node_requires_preparation {
                tracing::error!(%error, "node corpus preparation failed; previous manager remains active");
                if let Some(registry) = list_status_registry {
                    registry.record_cycle(CycleOutcome::ConfigRejected);
                }
                return Ok(None);
            }
            // Config consumers have changed and the old manager is gone.
            // Only daemon teardown can safely resolve this half-applied reload.
            tracing::error!(%error, uid = ?invoker_uid, pre_hash = ?pre_hash,
                attempted_hash = ?new_hash, "fatal reload: replacement list worker ended abnormally");
            let rec = AuditRecord::new(AuditEvent::Reload, AuditResult::Rejected)
                .with_uid(invoker_uid)
                .with_files(new_files.iter())
                .with_pre_hash(pre_hash)
                .with_post_hash(None)
                .with_errors([format!(
                    "replacement list worker failed; config partially applied, daemon stopping; attempted config hash {new_hash:?}: {error}"
                )]);
            if let Err(write_error) = audit_writer.append(&rec) {
                tracing::error!(%write_error, "failed to append fatal reload audit");
            }
            *current_files = new_files;
            *current_hash = None;
            return Err(
                anyhow::Error::new(error).context("fatal reload replacement list worker failure")
            );
        }
    };
    #[cfg(feature = "cluster")]
    if node_requires_preparation {
        if let Err(error) = mgr.verify_node_corpus() {
            tracing::error!(%error, "node corpus rejected; previous policy remains active");
            if let Some(registry) = list_status_registry {
                registry.record_cycle(CycleOutcome::ConfigRejected);
            }
            return Ok(None);
        }
        list_cmd_tx_swap.store(Arc::new(ListManagerEndpoint::Transitioning));
        if let Some(controller) = refresh_handle.take() {
            controller.retire().await?;
        }
        nodes_runtime::clear_active(
            runtime_reload.and_then(|runtime| runtime.node_observe),
            cluster_state,
        );
        filter.install_prepared_shards(&prepared_filter);
        mgr.install_prepared_filter(filter.clone());
        if let Some(registry) = list_status_registry {
            mgr.install_prepared_status_registry(registry.clone());
        }
        mgr.set_notification_channel(notification_tx.clone());
        mgr.set_status_persistence_path(list_stats_path(config_path));
    }
    tracing::info!(count, "lists reloaded");
    // The completed rebuild used the tight client above; only the background
    // controller receives the bulk client.
    install_bulk_download_client(&mut mgr);

    // Describe the manager that is now live, so
    // the next reload can compare against it. Stored only once the
    // rebuild has actually happened — an earlier store would let a
    // reload that died mid-refresh advertise a pipeline that never ran.
    *lists_fingerprint = Some(fingerprint);

    // Each installed shard carries the profile-id policy projected against
    // its own source-bit assignment, so the shard-at-a-time list publication
    // above cannot pair new bits with masks from ProfileResolver. The resolver
    // swap below changes client-to-profile selection only after all other
    // reloadable consumers are ready.
    install_runtime_reload(
        runtime_reload,
        &mut prepared_upstream,
        &prepared_acl,
        stats,
        security,
        config,
        config_path,
        api_token_hash,
        acl_handle,
    )
    .await;
    publish_active_policy(profiles, config, compiled, identity, cluster_state);
    #[cfg(feature = "cluster")]
    install_cluster_policy(cluster_state, prepared_cluster);
    #[cfg(feature = "cluster")]
    if let Some(context) = &node_corpus {
        if let (Some(live), Some(prepared)) = (
            runtime_reload.and_then(|runtime| runtime.node_ip_filter),
            prepared_node_ip.as_ref(),
        ) {
            live.install_prepared(prepared);
        }
        nodes_runtime::wire_live_manager(
            &mut mgr,
            config,
            runtime_reload.and_then(|runtime| runtime.node_ip_filter),
            runtime_reload.and_then(|runtime| runtime.node_observe),
            cluster_state,
        );
        if let Err(error) = context.finish_activation(
            Some(&mut mgr),
            runtime_reload.and_then(|runtime| runtime.node_observe),
            cluster_state,
            enrollment_artifact.as_ref(),
            node_auxiliary.clone(),
        ) {
            nodes_runtime::clear_active(
                runtime_reload.and_then(|runtime| runtime.node_observe),
                cluster_state,
            );
            tracing::error!(%error, "node corpus activation proof unavailable; DNS continues with installed policy");
        }
    }
    let manager_task = mgr.spawn_refresh_loop_after_refresh();
    list_cmd_tx_swap.store(Arc::new(ListManagerEndpoint::running(list_cmd_tx)));
    *refresh_handle = Some(manager_task);

    let rec = AuditRecord::new(AuditEvent::Reload, AuditResult::Ok)
        .with_uid(invoker_uid)
        .with_files(new_files.iter())
        .with_pre_hash(pre_hash)
        .with_post_hash(new_hash.clone());
    if let Err(e) = audit_writer.append(&rec) {
        tracing::warn!(error = %e, "failed to write audit record");
    }
    *current_files = new_files;
    *current_hash = new_hash;
    Ok(Some(reload_has_schedules))
}

/// Start a `QueryLog` writer task and attach it to the
/// engine's ArcSwap slots. Shared by the initial startup path and the
/// `handle_reload` path so both agree on how the writer is resolved,
/// sized, and capped.
fn attach_query_log_writer(
    engine: &Arc<StatsEngine>,
    tracking: &crate::config::settings::TrackingConfig,
    config_path: &Path,
) {
    let path =
        crate::tracking::query_log::resolved_query_log_path(&tracking.query_log_path, config_path);
    let max_bytes = tracking.query_log_max_size_mb.saturating_mul(1024 * 1024);
    let ql = Arc::new(crate::tracking::query_log::QueryLog::start(
        path.clone(),
        max_bytes,
        tracking.query_log_max_files,
        tracking.retention_days,
    ));
    engine.attach_query_log(ql, path.clone());
    tracing::info!(
        path = %path.display(),
        max_mb = tracking.query_log_max_size_mb,
        max_files_per_day = tracking.query_log_max_files,
        retention_days = tracking.retention_days,
        "query log writer attached"
    );
}

/// Detach the currently-attached writer (if any) and
/// schedule its flush-and-exit on a detached task so the reload path
/// never blocks on a slow writer drain. Best-effort `shutdown().await`
/// when we hold sole ownership of the `Arc<QueryLog>`; otherwise we
/// drop, and the writer task exits on its own once the last hot-path
/// clone (held briefly inside `log_query_event`) drops.
fn detach_query_log_writer(engine: &Arc<StatsEngine>) {
    let Some(old_ql) = engine.detach_query_log() else {
        return;
    };
    tracing::info!("query log writer detached");
    tokio::spawn(async move {
        match Arc::try_unwrap(old_ql) {
            Ok(inner) => inner.shutdown().await,
            Err(_arc) => {
                // A hot-path `log_query_event` call holds a transient
                // clone — drop our reference and the writer task exits
                // on the next `recv(None)` once that call finishes.
            }
        }
    });
}

/// Align the engine's query-log writer state with the reloaded
/// `tracking.query_log_enabled` flag. No-op when the state hasn't
/// changed.
fn apply_query_log_reload(
    engine: &Arc<StatsEngine>,
    tracking: &crate::config::settings::TrackingConfig,
    config_path: &Path,
) {
    let wants_enabled = tracking.query_log_enabled;
    let currently_attached = engine.query_log_file_path().is_some();
    match (wants_enabled, currently_attached) {
        (true, false) => attach_query_log_writer(engine, tracking, config_path),
        (false, true) => detach_query_log_writer(engine),
        _ => {}
    }
}

/// Which source [`fetch_catalog_or_fallback`] tries first.
///
/// Boot prefers the disk copy because it runs in front of the DNS bind and a
/// dead link there costs up to 30 s of household downtime. Reload prefers the
/// network because it runs behind an already-bound listener, and because it is
/// the only path that ever refreshes the persisted copy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CatalogPreference {
    Disk,
    Network,
}

/// Whether a freshly fetched catalog is viable for a reproducible plan.
fn catalog_worth_persisting(c: &Catalog) -> bool {
    c.is_usable()
}

/// Admit a fetched catalog only after its persistence boundary succeeds.
///
/// List caches record the resolved catalog URL. Using bytes selected by a
/// catalog that cannot be saved would let those cache stamps outlive the
/// catalog needed to interpret them after restart. The injected save boundary
/// keeps this rule deterministic in tests.
fn admit_fetched_catalog<F>(fetched: Catalog, persisted: Option<Catalog>, save: F) -> Catalog
where
    F: FnOnce(&Catalog) -> std::io::Result<()>,
{
    if !catalog_worth_persisting(&fetched) {
        tracing::warn!("fetched catalog is empty, using a reproducible fallback");
        return persisted.unwrap_or_else(Catalog::fallback);
    }
    match save(&fetched) {
        Ok(()) => fetched,
        Err(e) => {
            tracing::warn!(error = %e, "failed to persist fetched catalog; using a reproducible fallback");
            persisted.unwrap_or_else(Catalog::fallback)
        }
    }
}

/// Resolve the list catalog.
///
/// Boot may fetch here only when no viable disk catalog exists. It cannot
/// defer catalog selection past cache loading: `load_disk_cache` verifies the
/// sidecar's resolved URL against this generation's plan. Cache stems remain
/// tied to the representative source spelling; the sidecar is what prevents
/// a moved catalog URL from reusing that spelling's old body.
///
/// `pref` decides which side of the bind the caller is on:
/// [`CatalogPreference::Disk`] for boot (never blocks),
/// [`CatalogPreference::Network`] for reload. A fetched catalog becomes live
/// only if its save succeeds; otherwise this returns the prior viable disk
/// copy or the compiled fallback.
pub(crate) async fn fetch_catalog_or_fallback(
    client: &reqwest::Client,
    lists_dir: &Path,
    pref: CatalogPreference,
) -> Catalog {
    if pref == CatalogPreference::Disk {
        if let Some(c) = Catalog::load_from_disk(lists_dir) {
            tracing::info!("catalog loaded from disk, no fetch");
            return c;
        }
    }
    match Catalog::fetch(client).await {
        Ok(c) => admit_fetched_catalog(c, Catalog::load_from_disk(lists_dir), |catalog| {
            catalog.save_to_disk(lists_dir)
        }),
        Err(e) => {
            // Under `Network` the disk copy is a better fallback than the
            // compiled-in entries: it is what purge.cc last published, and
            // FALLBACK_ENTRIES is frozen at build time.
            if let Some(c) = Catalog::load_from_disk(lists_dir) {
                tracing::warn!(error = %e, "catalog fetch failed, using the persisted copy");
                return c;
            }
            tracing::warn!(error = %e, "catalog fetch failed, using fallback");
            Catalog::fallback()
        }
    }
}

/// Log a loud warning if the server is bound to a publicly-routable
/// address. The validator already refuses 0.0.0.0/:: with empty
/// `allow_from`, but binding to e.g. a public VPS IP is still a config
/// the operator should be deliberate about — log it so they see it on
/// every startup.
/// True if `ip` is a publicly-routable bind address — i.e. NOT loopback,
/// unspecified, RFC1918 / link-local IPv4, or loopback / ULA / link-local IPv6.
/// Shared by the `server.listen` and `api.listen` bind warnings so the
/// v6-ULA/link-local predicate has exactly one definition.
fn is_public_bind(ip: std::net::IpAddr) -> bool {
    let is_loopback = ip.is_loopback();
    let is_unspecified = ip.is_unspecified();
    let is_private_v4 =
        matches!(ip, std::net::IpAddr::V4(v4) if v4.is_private() || v4.is_link_local());
    let is_local_v6 = matches!(ip, std::net::IpAddr::V6(v6)
        if v6.is_loopback()
            || (v6.segments()[0] & 0xfe00) == 0xfc00   // ULA
            || (v6.segments()[0] & 0xffc0) == 0xfe80   // link-local
    );
    !(is_loopback || is_unspecified || is_private_v4 || is_local_v6)
}

fn log_public_bind_warning(ip: std::net::IpAddr, acl_active: bool) {
    if !is_public_bind(ip) {
        return;
    }

    if acl_active {
        tracing::warn!(
            %ip,
            "server.listen binds a publicly-routable address; \
             server.allow_from is set so non-matching sources will be REFUSED, \
             but you are still exposed to the internet — confirm this is intended"
        );
    } else {
        // Should not happen — validator should have caught it. Belt-and-suspenders.
        tracing::error!(
            %ip,
            "server.listen binds a publicly-routable address with NO server.allow_from; \
             this is an open-resolver configuration. The validator should have refused this — \
             please report it as a bug."
        );
    }
}

/// Profiles whose `lists` array is empty, sorted alphabetically.
///
/// An empty-lists profile is legal (operators occasionally want a
/// permissive bucket for a specific client group) but it is the single
/// most common silent-failure path for a fresh install: the daemon comes
/// up healthy, binds `:53`, yet performs zero filtering because the
/// catch-all profile has nothing to match. `warden init`'s template
/// already avoids this gap; this helper surfaces the same gap for
/// operators with hand-written configs so the warning shows up in the
/// journal alongside the other startup noise.
///
/// `Profile.blocklists` no longer exists, so this always returns empty:
/// the function is preserved as a stub so the call site keeps its
/// callable shape until the signal is reintroduced by checking
/// `effective_tags(d) == ∅` per-device.
fn profiles_with_empty_lists(_config: &crate::config::schema::ConfigV1) -> Vec<&str> {
    Vec::new()
}

/// Report every declared custom list that enforces nothing, at every load.
///
/// This is the **log** site for both conditions. The unmounted line is
/// derived by the validator, which only collects it — the config load can
/// complete before a `tracing` subscriber exists, so logging it there would
/// drop it at boot. Logging it here, on a path that runs after the
/// subscriber is installed, is what makes "at every load" true.
///
/// The unmounted case is INFO: an unmounted list is a legitimate staging
/// drawer, and a chronic warning on a deliberate state trains the operator
/// to skim past the empty-file WARN, which does need acting on.
fn log_inert_custom_lists(config: &crate::config::schema::ConfigV1, store: &CustomListStore) {
    for (id, reason) in crate::config::schema::validator::inert_custom_lists(config) {
        tracing::info!(
            target: "audit",
            custom_list = %id.as_str(),
            "{}",
            reason.message(id.as_str())
        );
    }
    for cl in &config.custom_lists {
        match store.get(&cl.id) {
            Some(c) if c.allow.is_empty() && c.deny.is_empty() => {
                tracing::warn!(
                    custom_list = %cl.id,
                    skipped = c.skipped,
                    "{}",
                    crate::config::schema::validator::InertListReason::CustomListEmpty
                        .message(cl.id.as_str())
                );
            }
            Some(c) if c.skipped > 0 => {
                tracing::warn!(
                    custom_list = %cl.id,
                    skipped = c.skipped,
                    "custom list has unparseable rules that enforce nothing"
                );
            }
            _ => {}
        }
    }
}

fn log_empty_profile_lists_warning(config: &crate::config::schema::ConfigV1) {
    let empty = profiles_with_empty_lists(config);
    for name in empty {
        if name == "default" {
            tracing::warn!(
                profile = name,
                "profile \"{name}\" has no blocklists subscribed — every query \
                 hitting this profile will be FORWARDED unfiltered. If this \
                 is unintended, run `warden lists add <set>` or edit the \
                 config and reload."
            );
        } else {
            tracing::warn!(
                profile = name,
                "profile \"{name}\" has no blocklists subscribed — clients using \
                 this profile get no filtering. If this is unintended, run \
                 `warden lists add <set>` or edit the config and reload."
            );
        }
    }
}

/// Last-chance label for a Tier 1 source bit
/// when the catalog has no entry matching its URL (e.g.
/// operator-pinned raw URLs, `imported.local` synthetic sources).
/// Returns the URL's filename stem stripped of a trailing `.txt`,
/// e.g. `https://lists.purge.cc/ads.txt` → `"ads"`. Falls back to
/// the full URL when the stem cannot be derived.
fn url_stem_fallback(url: &str) -> String {
    url.rsplit('/')
        .next()
        .map(|tail| tail.trim_end_matches(".txt").to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| url.to_string())
}

/// Derive the stats snapshot path from the config file path.
/// For the FHS v1 layout (`/etc/<pkg>/config.toml`), redirects to
/// `/var/lib/<pkg>/data/stats.json`. Otherwise `./config.toml` →
/// `./data/stats.json`.
fn snapshot_path(config_path: &Path) -> PathBuf {
    let dir = state_dir_for(config_path.parent().unwrap_or_else(|| Path::new(".")));
    dir.join("data").join("stats.json")
}

/// Derive the per-list `prev_entries` persistence path.
/// Same FHS v1 redirect as `snapshot_path` so both files live next to
/// each other under `/var/lib/<pkg>/data/`.
pub(crate) fn list_stats_path(config_path: &Path) -> PathBuf {
    let dir = state_dir_for(config_path.parent().unwrap_or_else(|| Path::new(".")));
    dir.join("data").join("list_stats.json")
}

/// Resolve the path to the retry-state file. Lives next to
/// `list_stats.json` (telemetry)
/// in the daemon's mutable-state directory; the two files are
/// distinct because they evolve at different cadences (the state
/// machine writes on every transition, telemetry on every refresh).
fn list_state_path(config_path: &Path) -> PathBuf {
    let dir = state_dir_for(config_path.parent().unwrap_or_else(|| Path::new(".")));
    dir.join("data").join("list_state.toml")
}

pub(crate) fn list_schedule_state_path(config_path: &Path) -> PathBuf {
    let dir = state_dir_for(config_path.parent().unwrap_or_else(|| Path::new(".")));
    dir.join("data").join("list_schedule_state.toml")
}

/// Whether the manager built from this wiring owns the on-disk list
/// state. The daemon does, and records every transition into it. The
/// foreground refresh reads the same state but never writes back, so a
/// one-shot command cannot clobber counters the running daemon is
/// maintaining.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ListStateWriteback {
    Persist,
    ReadOnly,
}

/// Everything a [`ListManager`] needs that is derived from the operator's
/// config rather than handed to its constructor.
///
/// Three sites build a manager — daemon boot, the reload rebuild, and the
/// foreground refresh — and the constructor defaults every field below to
/// a neutral empty value. A setter one site forgets is therefore neither
/// a compile error nor a runtime error, only a silent degradation:
/// authenticated lists fetch anonymously, a declared parse format defers
/// to auto-detection, and the retry state machine stops being driven.
/// Routing all three through one value is what stops them drifting.
///
/// Deliberately not carried here, because each is a real asymmetry rather
/// than an omission:
/// - the readiness gate — a latch with no `close()`, so only the first
///   manager can open it;
/// - the status registry — boot *creates* it through the manager, and
///   only a rebuild has to re-attach the existing handle;
/// - the notification channel, command channel, status-persistence path
///   and bulk download client — daemon-only, absent by design from a
///   one-shot foreground refresh.
pub(crate) struct ManagerWiring {
    source_trust: crate::lists::source_key::SourceTrustMap,
    bridge_config_dir: PathBuf,
    policy_masks: crate::filter::engine::PolicyMasks,
    shrink_guard_enabled: bool,
    shrink_guard_max_drop_pct: u8,
    max_total_domains: usize,
    source_to_blocklist: std::collections::HashMap<String, (crate::config::schema::Id, u32)>,
    source_to_format: std::collections::HashMap<String, crate::lists::detector::ListFormat>,
    source_to_max_entries: std::collections::HashMap<String, usize>,
    list_state: crate::config::list_state::ListState,
    list_state_path: Option<PathBuf>,
    schedule_state: crate::config::list_schedule_state::ListScheduleState,
    schedule_state_path: Option<PathBuf>,
    schedule_state_allows_legacy_seed: bool,
}

impl ManagerWiring {
    /// Derive the wiring from config. `plan`, `bridge_config_dir`
    /// and `policy_masks` are parameters because every caller has already
    /// computed them — `policy_masks` in particular must be projected
    /// before `source_bits` moves into the manager.
    pub(crate) fn from_config(
        config: &crate::config::schema::ConfigV1,
        config_path: &Path,
        plan: &ResolvedSourcePlan,
        bridge_config_dir: PathBuf,
        policy_masks: crate::filter::engine::PolicyMasks,
        writeback: ListStateWriteback,
    ) -> Self {
        let state_path = list_state_path(config_path);
        // Fail-open: an unreadable state file yields an empty state, so
        // counters restart and every list keeps applying. Both consumers
        // of this file go through the one reader, so it cannot mean two
        // different things on the two sides of the wire.
        let list_state =
            crate::profiles::resolver::read_list_state_fail_open(&state_path).unwrap_or_default();
        let schedule_path = list_schedule_state_path(config_path);
        let (schedule_state, schedule_state_allows_legacy_seed) =
            match crate::config::list_schedule_state::ListScheduleState::read_or_default(
                &schedule_path,
            ) {
                Ok(state) => (state, true),
                Err(error) => {
                    tracing::warn!(path = %schedule_path.display(), %error, "ignoring unreadable list scheduling state; every source is due and compatibility seeding is suppressed");
                    (
                        crate::config::list_schedule_state::ListScheduleState::default(),
                        false,
                    )
                }
            };
        let (source_to_blocklist, source_to_format, source_to_max_entries) =
            plan.manager_source_maps();
        Self {
            source_trust: SourceTrustMap::from_plan(plan),
            bridge_config_dir,
            policy_masks,
            shrink_guard_enabled: config.lists.shrink_guard_enabled,
            shrink_guard_max_drop_pct: config.lists.shrink_guard_max_drop_pct,
            max_total_domains: config.lists.max_total_domains,
            source_to_blocklist,
            source_to_format,
            source_to_max_entries,
            list_state,
            list_state_path: match writeback {
                ListStateWriteback::Persist => Some(state_path),
                ListStateWriteback::ReadOnly => None,
            },
            schedule_state,
            schedule_state_path: match writeback {
                ListStateWriteback::Persist => Some(schedule_path),
                ListStateWriteback::ReadOnly => None,
            },
            schedule_state_allows_legacy_seed,
        }
    }

    /// Apply the wiring to a freshly-constructed manager.
    pub(crate) fn apply(self, mgr: &mut ListManager) {
        // Destructured exhaustively on purpose: a field added above has
        // to be wired here or this stops compiling. Prose asking the next
        // author to remember is what let the three sites drift apart.
        let Self {
            source_trust,
            bridge_config_dir,
            policy_masks,
            shrink_guard_enabled,
            shrink_guard_max_drop_pct,
            max_total_domains,
            source_to_blocklist,
            source_to_format,
            source_to_max_entries,
            list_state,
            list_state_path,
            schedule_state,
            schedule_state_path,
            schedule_state_allows_legacy_seed,
        } = self;
        mgr.set_local_bridge(source_trust, bridge_config_dir);
        mgr.set_list_policy(policy_masks);
        mgr.set_shrink_guard(shrink_guard_enabled, shrink_guard_max_drop_pct);
        mgr.set_max_total_domains(max_total_domains);
        mgr.set_source_blocklist_map(source_to_blocklist);
        mgr.set_source_format_map(source_to_format);
        mgr.set_source_max_entries(source_to_max_entries);
        mgr.set_list_state(list_state, list_state_path);
        mgr.set_schedule_state(
            schedule_state,
            schedule_state_path,
            schedule_state_allows_legacy_seed,
        );
    }
}

/// Resolve the lists cache directory from config, creating it if needed.
///
/// `config.lists.cache_dir` is resolved against the daemon's mutable-state
/// directory — `/var/lib/<pkg>/<cache_dir>` for the FHS v1 layout, else
/// `<config-parent>/<cache_dir>` for dev / single-file installs.
pub(crate) fn lists_cache_dir(
    config_path: &Path,
    config: &crate::config::schema::ConfigV1,
) -> PathBuf {
    let base = state_dir_for(config_path.parent().unwrap_or_else(|| Path::new(".")));
    let dir = base.join(&config.lists.cache_dir);
    if let Err(e) = std::fs::create_dir_all(&dir) {
        tracing::warn!(
            error = %e,
            path = %dir.display(),
            "failed to create lists cache directory"
        );
    }
    dir
}

/// Try opening the OUI vendor table at the standard production path
/// first, then alongside the running binary, then in the current
/// working directory's `assets/oui` (dev convenience). Returns `None`
/// on first miss after exhausting all candidates — the daemon logs a
/// single warning and continues; vendor lookups become no-ops.
fn open_oui_table() -> Option<Arc<crate::oui::OuiTable>> {
    let mut candidates: Vec<PathBuf> = vec![PathBuf::from("/var/lib/purge-warden/data")];
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            candidates.push(parent.join("assets/oui"));
            candidates.push(parent.join("../assets/oui"));
        }
    }
    candidates.push(PathBuf::from("assets/oui"));

    for dir in &candidates {
        let bin = dir.join("oui.bin");
        if !bin.exists() {
            continue;
        }
        match crate::oui::OuiTable::open(dir) {
            Ok(t) => {
                tracing::info!(
                    path = %dir.display(),
                    "OUI vendor table loaded"
                );
                return Some(Arc::new(t));
            }
            Err(e) => {
                tracing::warn!(
                    path = %dir.display(),
                    error = %e,
                    "OUI table present but failed to open; skipping vendor lookup"
                );
                return None;
            }
        }
    }
    tracing::warn!(
        "OUI vendor table not found in any of the standard locations; vendor lookup disabled"
    );
    None
}

/// Open `<log_dir>/daemon-stderr.log` with mode `0o600` and return the
/// open file plus its path. Creates the directory if missing. Forces
/// permissions to `0o600` on the open path even when the file already
/// existed (`OpenOptions::mode` only affects creation), so a previous
/// daemon build that left the file at a wider mode cannot leak panic
/// output to other local users on this boot.
fn open_panic_fallback_log(log_dir: &Path) -> anyhow::Result<(std::fs::File, PathBuf)> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    std::fs::create_dir_all(log_dir)
        .map_err(|e| anyhow::anyhow!("cannot create log directory {}: {}", log_dir.display(), e))?;
    let stderr_path = log_dir.join("daemon-stderr.log");
    let stderr_file = std::fs::OpenOptions::new()
        .mode(0o600)
        .create(true)
        .append(true)
        .open(&stderr_path)
        .map_err(|e| anyhow::anyhow!("cannot open {}: {}", stderr_path.display(), e))?;
    std::fs::set_permissions(&stderr_path, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| anyhow::anyhow!("cannot enforce 0o600 on {}: {}", stderr_path.display(), e))?;
    Ok((stderr_file, stderr_path))
}

/// Fork a background daemon process and exit the parent.
///
/// The child inherits `PURGE_WARDEN_DAEMON_LOGS_DIR=<log_dir>` so its
/// `init_tracing` installs a daily-rotating file appender.
/// stdout/stderr are also redirected to a
/// raw `daemon-stderr.log` file inside the same directory so panics
/// and any non-tracing `eprintln!` from the bootstrap window survive
/// — without that fallback, a panic before tracing initializes would
/// vanish into the void.
fn fork_daemon(pid_file: &Path, log_dir: &Path) -> anyhow::Result<()> {
    let exe = std::env::current_exe()
        .map_err(|e| anyhow::anyhow!("cannot determine executable path: {}", e))?;

    // Rebuild args without --daemon to prevent infinite fork loop
    let args: Vec<String> = std::env::args()
        .skip(1)
        .filter(|a| a != "--daemon")
        .collect();

    // Open the panic-fallback log file (create dir if needed). The
    // primary tracing output goes through tracing-appender to a
    // separate daily-rotating file in the same directory.
    let (stderr_file, stderr_path) = open_panic_fallback_log(log_dir)?;
    let stderr_file_clone = stderr_file
        .try_clone()
        .map_err(|e| anyhow::anyhow!("cannot clone log file handle: {}", e))?;

    let child = std::process::Command::new(exe)
        .args(&args)
        .env("PURGE_WARDEN_DAEMON_LOGS_DIR", log_dir)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::from(stderr_file))
        .stderr(std::process::Stdio::from(stderr_file_clone))
        .spawn()
        .map_err(|e| anyhow::anyhow!("failed to spawn daemon: {}", e))?;

    // The parent forks-and-forgets: it cannot confirm the child won the PID
    // lock (another instance may already hold it — the child only tries
    // `acquire_pid_lock` after this returns) without a readiness handshake.
    // So the message says "launching", not "started", and points at how to
    // confirm. `--daemon` is a dev convenience; the supported production path
    // is the systemd unit (`Type=simple`, no fork).
    let primary_log_glob = log_dir.join("purge-warden.log.<date>");
    println!(
        "purge-warden launching in background (PID {})\n\
         confirm it stayed up with `warden status` (or check the log below)\n\
         PID file: {}\n\
         Log:      {}\n\
         Fallback: {}",
        child.id(),
        pid_file.display(),
        primary_log_glob.display(),
        stderr_path.display()
    );

    Ok(())
}

pub fn spawn_daemon(pid_file: &Path, config_path: &Path) -> anyhow::Result<()> {
    fork_daemon(pid_file, &daemon_log_dir(config_path))
}

#[cfg(test)]
#[allow(clippy::field_reassign_with_default)]
mod tests;

#[cfg(test)]
mod activation_tests {
    use super::*;
    use crate::config::atomic_write::{hardened_atomic_write, AtomicWriteOpts};
    use crate::config::schema::{ConfigV5, CustomList, Id, ProfileV5};

    fn candidate_runtime() -> Arc<crate::operator_rules::PolicyCandidateRuntime> {
        Arc::new(crate::operator_rules::PolicyCandidateRuntime::new(
            crate::filter::operator_rules::CompileAdmission::new(
                RuleCompileLimits::HARD_CEILINGS.max_compiled_bytes_total * 2,
                1,
            )
            .unwrap(),
        ))
    }

    fn identity(revision: &str, hash: &str) -> ActivePolicyIdentity {
        ActivePolicyIdentity {
            daemon_instance_id: "daemon-test".into(),
            config_revision: revision.into(),
            operator_policy_hash: hash.into(),
            resolver_generation: 7,
        }
    }

    fn request() -> ActivationRequest {
        ActivationRequest {
            operation_id: "operation-test".into(),
            request_id: "request-test".into(),
            actor: "test".into(),
            correlation_id: "correlation-test".into(),
            expected_config_revision: "revision-a".into(),
            expected_policy_hash: "hash-a".into(),
            completion: tokio::sync::oneshot::channel().0,
        }
    }

    #[test]
    fn activation_requires_exact_published_revision_and_hash() {
        let request = request();
        let expected = identity("revision-a", "hash-a");
        assert_eq!(
            classify_activation(&request, Some(expected.clone()), Ok(true)),
            ActivationResult::Applied(expected.clone())
        );
        let newer = identity("revision-b", "hash-a");
        assert_eq!(
            classify_activation(&request, Some(newer.clone()), Ok(true)),
            ActivationResult::Superseded {
                active: newer,
                superseding_operation_id: None,
            }
        );
        for active in [
            None,
            Some(ActivePolicyIdentity::default()),
            Some(identity("revision-a", "different-hash")),
        ] {
            assert!(matches!(
                classify_activation(&request, active, Ok(true)),
                ActivationResult::Unknown { .. }
            ));
        }
        assert!(matches!(
            classify_activation(&request, Some(expected.clone()), Ok(false)),
            ActivationResult::Rejected { .. }
        ));
        assert!(matches!(
            classify_activation(&request, Some(expected), Err("worker failed".into())),
            ActivationResult::Unknown { .. }
        ));
    }

    #[tokio::test]
    async fn shutdown_completes_queued_activations_without_certifying_a_swap() {
        let (sender, mut receiver) = mpsc::channel(1);
        let mut request = request();
        let (completion, completed) = tokio::sync::oneshot::channel();
        request.completion = completion;
        sender.try_send(request).ok().unwrap();
        retire_activation_queue(&mut receiver, Some(identity("revision-a", "hash-a")));
        assert!(sender.is_closed());
        assert!(matches!(
            completed.await.unwrap(),
            ActivationResult::Unknown { .. }
        ));
    }

    fn disk_policy(root: &Path) -> (PathBuf, PathBuf) {
        let id = Id::new("local").unwrap();
        let mut config = ConfigV5::default();
        config.upstream.servers = vec!["192.0.2.1:53".into()];
        config.custom_lists.push(CustomList {
            id: id.clone(),
            display_name: String::new(),
            description: String::new(),
        });
        config.server.default_profile = Some(Id::new("default").unwrap());
        config.profiles.insert(
            "default".into(),
            ProfileV5 {
                custom_lists: vec![id.clone()],
                ..ProfileV5::default()
            },
        );
        let master = root.join("config.toml");
        let pack = crate::config::custom_list::pack_path(root, &id);
        hardened_atomic_write(
            &master,
            toml::to_string(&config).unwrap().as_bytes(),
            AtomicWriteOpts::default(),
        )
        .unwrap();
        hardened_atomic_write(
            &pack,
            b"||blocked.example.test^\n",
            AtomicWriteOpts::default(),
        )
        .unwrap();
        (master, pack)
    }

    #[test]
    fn audit_warnings_emit_once_per_lifecycle_owner() {
        use tracing_subscriber::layer::SubscriberExt;

        struct Messages(std::sync::Arc<std::sync::Mutex<Vec<String>>>);

        impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Messages {
            fn on_event(
                &self,
                event: &tracing::Event<'_>,
                _ctx: tracing_subscriber::layer::Context<'_, S>,
            ) {
                struct Visitor(String);
                impl tracing::field::Visit for Visitor {
                    fn record_debug(
                        &mut self,
                        field: &tracing::field::Field,
                        value: &dyn std::fmt::Debug,
                    ) {
                        if field.name() == "message" {
                            self.0 = format!("{value:?}");
                        }
                    }
                }
                let mut visitor = Visitor(String::new());
                event.record(&mut visitor);
                self.0.lock().unwrap().push(visitor.0);
            }
        }

        let root = tempfile::tempdir().unwrap();
        let (master, _) = disk_policy(root.path());
        let messages = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::registry().with(Messages(messages.clone()));
        {
            let _guard = tracing::subscriber::set_default(subscriber);
            crate::config::loader::load_current_config(&master, time::OffsetDateTime::now_utc())
                .unwrap();
            crate::config::loader::load_current_config(&master, time::OffsetDateTime::now_utc())
                .unwrap();
            collect_loaded_files(&master);
            capture_operator_policy(
                &master,
                "daemon-test",
                &candidate_runtime(),
                AuditWarningEmission::Quiet,
            )
            .unwrap();
            capture_operator_policy(
                &master,
                "daemon-test",
                &candidate_runtime(),
                AuditWarningEmission::Emit,
            )
            .unwrap();
        }
        let count = messages
            .lock()
            .unwrap()
            .iter()
            .filter(|message| message.contains("has no domains to block"))
            .count();
        assert_eq!(
            count, 2,
            "boot emits once, its quiet capture does not duplicate it, and reload emits once"
        );
    }

    #[test]
    fn captured_revision_hash_and_compiled_pack_do_not_follow_later_disk_edits() {
        let root = tempfile::tempdir().unwrap();
        let (master, pack) = disk_policy(root.path());
        let runtime = candidate_runtime();
        let captured = capture_operator_policy(
            &master,
            "daemon-test",
            &runtime,
            AuditWarningEmission::Quiet,
        )
        .unwrap();
        let captured_identity = captured.identity.clone();
        hardened_atomic_write(
            &pack,
            b"||changed.example.test^\n",
            AtomicWriteOpts::default(),
        )
        .unwrap();
        let later = capture_operator_policy(
            &master,
            "daemon-test",
            &runtime,
            AuditWarningEmission::Quiet,
        )
        .unwrap();
        assert_ne!(
            captured.identity.config_revision,
            later.identity.config_revision
        );
        assert_ne!(
            captured.identity.operator_policy_hash,
            later.identity.operator_policy_hash
        );
        let resolver = Arc::new(
            ProfileResolver::build_with_operator_rules_and_policy_identity(
                &captured.projected,
                Arc::clone(&captured.compiled),
                captured.identity,
            ),
        );
        assert_eq!(resolver.active_policy_identity(), captured_identity);
        assert!(captured
            .compiled
            .profile(&Id::new("default").unwrap())
            .is_some());
        let bytes_before_tick = std::fs::read(&pack).unwrap();
        handle_schedule_tick(Some(&resolver));
        assert_eq!(std::fs::read(&pack).unwrap(), bytes_before_tick);
        let refreshed = resolver.active_policy_identity();
        assert_eq!(refreshed.config_revision, captured_identity.config_revision);
        assert_eq!(
            refreshed.operator_policy_hash,
            captured_identity.operator_policy_hash
        );
    }

    #[test]
    fn exact_committed_candidate_is_reused_without_recompiling_on_reload() {
        let root = tempfile::tempdir().unwrap();
        let (master, _) = disk_policy(root.path());
        let runtime = candidate_runtime();
        let first = capture_operator_policy(
            &master,
            "daemon-test",
            &runtime,
            AuditWarningEmission::Quiet,
        )
        .unwrap();
        let cached = runtime
            .matching(
                &first.identity.config_revision,
                &first.identity.operator_policy_hash,
            )
            .unwrap()
            .unwrap();
        assert!(Arc::ptr_eq(&first.compiled, &cached.compiled()));

        let second = capture_operator_policy(
            &master,
            "daemon-test",
            &runtime,
            AuditWarningEmission::Quiet,
        )
        .unwrap();
        assert!(Arc::ptr_eq(&first.compiled, &second.compiled));
    }

    #[test]
    fn policy_affecting_boot_drift_is_rejected_instead_of_using_legacy_rules() {
        let root = tempfile::tempdir().unwrap();
        let (master, _) = disk_policy(root.path());
        let captured = capture_operator_policy(
            &master,
            "daemon-test",
            &candidate_runtime(),
            AuditWarningEmission::Quiet,
        )
        .unwrap();
        let mut runtime_config = captured.projected.clone();
        runtime_config
            .profiles
            .get_mut("default")
            .unwrap()
            .custom_lists
            .clear();

        let error = admit_boot_capture(
            Some(captured),
            &runtime_config,
            RuntimeCapabilityAttestation::AuthoritativeSchema5Tree,
        )
        .err()
        .expect("policy drift must abort boot");
        assert!(error.to_string().contains("retry startup"));
    }

    #[test]
    fn startup_only_overrides_keep_the_admitted_schema5_policy() {
        let root = tempfile::tempdir().unwrap();
        let (master, _) = disk_policy(root.path());
        let captured = capture_operator_policy(
            &master,
            "daemon-test",
            &candidate_runtime(),
            AuditWarningEmission::Quiet,
        )
        .unwrap();
        let compiled = Arc::clone(&captured.compiled);
        let mut runtime_config = captured.projected.clone();
        runtime_config.server.listen = "127.0.0.1:15354".parse().unwrap();
        runtime_config.upstream.servers = vec!["192.0.2.54:53".into()];
        runtime_config.lists.update_interval_secs = 900;

        let admitted = admit_boot_capture(
            Some(captured),
            &runtime_config,
            RuntimeCapabilityAttestation::AuthoritativeSchema5Tree,
        )
        .expect("startup-only overrides remain coherent")
        .expect("authoritative boot must retain its capture");
        assert!(Arc::ptr_eq(&compiled, &admitted.compiled));
    }

    #[cfg(feature = "cluster")]
    #[test]
    fn cluster_reload_carries_the_same_complete_capture_as_the_resolver() {
        let root = tempfile::tempdir().unwrap();
        let (master, pack) = disk_policy(root.path());
        let mut config: ConfigV5 =
            toml::from_str(&std::fs::read_to_string(&master).unwrap()).unwrap();
        config.cluster.enabled = true;
        config.cluster.token_hash = Some("a".repeat(64));
        std::fs::write(&master, toml::to_string(&config).unwrap()).unwrap();
        let captured = capture_operator_policy(
            &master,
            "daemon-test",
            &candidate_runtime(),
            AuditWarningEmission::Quiet,
        )
        .unwrap();
        let snapshot = captured.cluster_snapshot.as_ref().unwrap();
        assert_eq!(
            snapshot.config_revision(),
            captured.identity.config_revision
        );
        assert_eq!(
            snapshot.operator_policy_hash(),
            captured.identity.operator_policy_hash
        );
        let captured_body = Arc::clone(&snapshot.packs()[&Id::new("local").unwrap()].bytes);
        std::fs::write(&pack, b"||later.example.test^\n").unwrap();
        let state = crate::cluster::ClusterState::new(
            crate::config::schema::ClusterRole::Primary,
            1,
            "a".repeat(64),
            Vec::new(),
        );
        let guard = crate::config::write_lock::acquire_for_migration(&master).unwrap();
        state.update_policy(&guard, Arc::clone(snapshot)).unwrap();
        assert!(Arc::ptr_eq(
            snapshot,
            state.policy().snapshot.as_ref().unwrap()
        ));
        assert_eq!(captured_body.as_ref(), b"||blocked.example.test^\n");
        assert_eq!(
            state
                .policy()
                .manifest
                .as_ref()
                .unwrap()
                .operator_policy_hash,
            captured.identity.operator_policy_hash
        );
    }

    #[test]
    fn cosmetic_pack_edit_changes_revision_but_not_semantic_hash() {
        let root = tempfile::tempdir().unwrap();
        let (master, pack) = disk_policy(root.path());
        let runtime = candidate_runtime();
        let before = capture_operator_policy(
            &master,
            "daemon-test",
            &runtime,
            AuditWarningEmission::Quiet,
        )
        .unwrap();
        hardened_atomic_write(
            &pack,
            b"# operator comment\n||blocked.example.test^\n",
            AtomicWriteOpts::default(),
        )
        .unwrap();
        let after = capture_operator_policy(
            &master,
            "daemon-test",
            &runtime,
            AuditWarningEmission::Quiet,
        )
        .unwrap();
        assert_ne!(
            before.identity.config_revision,
            after.identity.config_revision
        );
        assert_eq!(
            before.identity.operator_policy_hash,
            after.identity.operator_policy_hash
        );
        assert_eq!(before.audit_hash, after.audit_hash);

        hardened_atomic_write(
            &pack,
            b"||blocked.example.test^\n# inactive note\n",
            AtomicWriteOpts::default(),
        )
        .unwrap();
        let skipped = capture_operator_policy(
            &master,
            "daemon-test",
            &runtime,
            AuditWarningEmission::Quiet,
        )
        .unwrap();
        assert_ne!(
            after.identity.config_revision,
            skipped.identity.config_revision
        );
        assert_eq!(
            after.identity.operator_policy_hash,
            skipped.identity.operator_policy_hash
        );
    }
}
