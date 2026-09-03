//! Start the DNS filtering server — foreground or daemon mode.
//!
//! When started, the server:
//! 1. Loads and validates the config file
//! 2. Builds list→bit mapping and profile resolver
//! 3. Optionally downloads blocklists from configured sources
//! 4. Starts the DNS server on the configured listen address
//! 5. Enters a signal loop: SIGTERM/SIGINT→shutdown, SIGHUP→reload
//!    (cache flush is NOT signal-based; use the authenticated IPC command)
//! 6. On shutdown: aborts background tasks, removes PID file, exits cleanly

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

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
use crate::ipc::socket_server::{spawn_ipc_server, DaemonState};
use crate::lists::catalog::Catalog;
use crate::lists::manager::{merge_sources_with_blocklists, ListManager, RefreshMode};
use crate::lists::readiness::ReadinessGate;
use crate::lists::source_key::{SourceBitMap, SourceTokenMap};
use crate::lists::status::{CycleOutcome, ListStatusRegistry};
use crate::profiles::ProfileResolver;
use crate::tracking::StatsEngine;
use crate::upstream::forwarding::ForwardingRouter;
use crate::upstream::UpstreamResolver;

use super::pid;

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
    use crate::config::schema::{ConfigV1, ResourceBudgetConfig, ServerGlobals, SCHEMA_VERSION_V1};
    use crate::config::settings::{
        AntiBypassConfig, ApiConfig, CacheConfig, DnssecConfig, IpBlocklistConfig, ListsConfig,
        LocalDnsConfig, SecurityConfig, SocketConfig, TrackingConfig, UpstreamConfig, UpstreamMode,
    };

    ConfigV1 {
        schema_version: SCHEMA_VERSION_V1,
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

/// Build the cluster serve-state when this node is an enabled primary with
/// the API server on. Returns `None` for a standalone node, a secondary (no
/// serve side), or a primary whose `[api]` is disabled (the cluster routes
/// mount on the API server — warn and stay inert). Seeds
/// `config_generation = 1`; the map artifact is seeded by the first refresh.
#[cfg(feature = "cluster")]
fn build_cluster_state(
    config: &crate::config::schema::ConfigV1,
) -> Option<Arc<crate::cluster::ClusterState>> {
    use crate::config::schema::ClusterRole;

    let c = &config.cluster;
    if !c.enabled || c.role != ClusterRole::Primary {
        return None;
    }
    if !config.api.enabled {
        tracing::warn!(
            "cluster: node is an enabled primary but [api] is disabled — \
             /api/cluster/* endpoints mount on the API server and will NOT be \
             served. Enable [api] to serve cluster peers."
        );
        return None;
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
    let state = crate::cluster::ClusterState::new(c.role, c.priority, token_hash, allow_peer);
    state.update_policy(config);
    tracing::info!(
        priority = c.priority,
        allow_peer = c.allow_peer.len(),
        "cluster: primary serve-side active (§4.11-2) — /api/cluster/* mounted"
    );
    Some(Arc::new(state))
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
/// **Not "are any blocklists configured".** Sources arrive through two
/// channels (`[lists].sources` and `[[blocklists]]`, merged by
/// [`merge_sources_with_blocklists`]), so `config.blocklists` alone is empty on
/// a fully configured node.
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

/// Start the DNS filtering server from a validated v1 [`ConfigV1`](crate::config::schema::ConfigV1).
pub async fn run_start(
    config: &crate::config::schema::ConfigV1,
    custom_lists: &CustomListStore,
    config_path: &Path,
    pid_file: &Path,
    blocklist_path: Option<&str>,
    daemon: bool,
) -> anyhow::Result<()> {
    // Refuse a DNSSEC mode the binary cannot honor — before the daemon fork, so
    // the error reaches the operator's terminal rather than the child's log.
    check_dnssec_build(config)?;
    // Refuse to start if clustering is enabled on a feature-less binary,
    // before the daemon fork so the error reaches the operator.
    check_cluster_build(config)?;

    // Daemon mode: re-exec as background process and exit parent
    if daemon {
        return fork_daemon(pid_file, &daemon_log_dir(config_path));
    }

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
    let result = run_server(config, custom_lists, config_path, blocklist_path).await;

    pid::remove_pid_file(pid_file);

    if result.is_err() {
        tracing::error!("startup failed, PID file cleaned up");
    } else {
        tracing::info!("purge-warden stopped");
    }

    result
}

/// Core server startup + signal loop. Separated so the caller can
/// guarantee PID file cleanup regardless of how this returns.
async fn run_server(
    config: &crate::config::schema::ConfigV1,
    custom_lists: &CustomListStore,
    config_path: &Path,
    blocklist_path: Option<&str>,
) -> anyhow::Result<()> {
    let started_at = Instant::now();

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

    // Load-bearing beyond the hash it feeds. `collect_loaded_files` runs a
    // full `load_config`, and this is the FIRST such load after
    // `init_tracing` (main.rs must read `server.log_level` from the
    // config, so its own boot load necessarily precedes the subscriber
    // and every WARN raised there is dropped). That makes this call the
    // only reason any validator audit WARN is visible at daemon startup
    // at all — verified by running the daemon and reading the boot log,
    // which carries both ANTI_BYPASS_ENABLED_NO_DOMAINS and
    // PROFILE_CONTRIBUTES_NO_TAGS.
    //
    // So: do not "optimise" this into a cheaper include-list walk that
    // skips validation. It would silently take every operator WARN off
    // the boot log while every test stayed green — the tests read the
    // collector's return value, not the tracing output. If this ever
    // needs to stop validating, re-emit the collected warnings
    // explicitly right here instead.
    //
    // (The `LIST_PRUNE_WARN` comment in `schema::validator` still says
    // boot warns are "dropped entirely". That was true of main.rs's load
    // and is stale for the daemon as a whole.)
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

    let upstream_resolver = Arc::new(UpstreamResolver::from_config(
        &config.upstream,
        &upstream_client,
    )?);
    let base_upstream: Arc<dyn crate::upstream::Upstream> = upstream_resolver.clone();

    // Wrap in ForwardingRouter if forwarding zones are configured
    let upstream: Arc<dyn crate::upstream::Upstream> = if !config.forwarding.is_empty() {
        let timeout = Duration::from_millis(config.upstream.timeout_ms);
        let router = ForwardingRouter::new(
            &config.forwarding,
            base_upstream,
            &upstream_client,
            timeout,
            config.upstream.dot.pool_size,
            config.upstream.ecs.enabled,
        )?;
        tracing::info!(
            zones = config.forwarding.len(),
            "conditional forwarding enabled"
        );
        Arc::new(router)
    } else {
        base_upstream
    };

    // `--blocklist` is refused rather than honoured — see
    // [`START_BLOCKLIST_FLAG_RETIRED`] for why loading the file was worse
    // than not having the flag.
    if blocklist_path.is_some() {
        anyhow::bail!("{START_BLOCKLIST_FLAG_RETIRED}");
    }
    let filter = Arc::new(FilterEngine::new());

    // Unify legacy `lists.sources` with v1 `[[blocklists]]` URLs into the
    // source vector that drives the bit map AND the manager's fetch loop.
    // `import-local` only writes the `[[blocklists]]` row, so without this
    // merge the synthetic `imported.local` URL never reaches the manager
    // and the loader-bridge has nothing to intercept. Trust map
    // (per-source `BlocklistTrust`) is consumed by `set_local_bridge`
    // below.
    let (merged_sources, source_trust) =
        merge_sources_with_blocklists(&config.lists.sources, &config.blocklists);

    // Build the typed source bit map from merged sources + the v1
    // `[[blocklists]]` catalogue. The validator caps `lists.sources`
    // at 64, so this is defence-in-depth — if the cap is ever bypassed
    // the operator gets a plain-English message instead of a panic.
    // [`SourceBitMap`] seeds `by_v1_id` from both source channels so
    // profile resolution by `&Id` always hits the right bit, regardless
    // of whether the operator put their lists in `[lists].sources`
    // (legacy slash-form) or in `[[blocklists]]` (v1).
    let source_bits = SourceBitMap::build(&merged_sources, &config.blocklists)
        .map_err(|e| anyhow::anyhow!("lists.sources: {e}"))?;

    // The operator's per-profile list policy, projected onto the bit
    // assignment `source_bits` just made. Computed here because
    // `source_bits` is moved into the manager below — and it is the ONLY
    // place ids become bits, which is what keeps a positional mask from
    // travelling on its own.
    let policy_masks = source_bits.project_policy(&config.blocklists, &config.profiles);

    // Resolve `[blocklists].auth_token_ref` values against the loaded
    // secrets. The typed [`SourceTokenMap`] keys by legacy slash-form
    // source string for the manager's fetch path AND by canonical v1
    // [`Id`] for future id-keyed consumers; absence means the list fetch
    // stays anonymous.
    let source_tokens = SourceTokenMap::build(config, &secrets);

    let profiles = Some(build_profile_resolver(config, &source_bits, custom_lists));

    // Initial list download
    let mut refresh_handle: Option<JoinHandle<()>> = None;
    // Fingerprints the list pipeline the manager below is built from, so
    // the FIRST reload can already skip a rebuild it does not need.
    // Stays `None` when no manager is spawned — the gate then falls
    // through to a rebuild, which is the safe direction.
    let mut lists_fingerprint: Option<ListsFingerprint> = None;
    // ArcSwap-wrapped sender for the list manager's out-of-band command
    // channel. Always allocated so the reload path
    // can swap in a fresh sender after rebuilding the manager. Starts
    // `None` — only flipped to `Some(tx)` when a manager is actually
    // spawned (no sources = no manager = forget is unreachable, which
    // is the correct behaviour).
    let list_cmd_tx_swap: Arc<
        arc_swap::ArcSwap<
            Option<tokio::sync::mpsc::Sender<crate::lists::manager::ListManagerCommand>>,
        >,
    > = Arc::new(arc_swap::ArcSwap::from_pointee(None));
    let mut list_status_registry: Option<Arc<ListStatusRegistry>> = None;
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

    // Cluster serve-state when this node is an enabled primary with the API
    // on; `None` otherwise. Bound before the list-manager block so the boot
    // manager can arm the map-refresh hook and the API server + reload path
    // can share it. Seeds config_generation = 1.
    #[cfg(feature = "cluster")]
    let cluster_state = build_cluster_state(config);

    // A cluster secondary downloads and builds its OWN lists, exactly like a
    // standalone node. The Tier-1 bitmask is a positional index into this
    // process's merged sources vector, so it is derived here rather than
    // received — each node computes identical bits from the identical
    // policy the bundle replicated.
    //
    // Kept as a named predicate rather than an inline `!merged_sources
    // .is_empty()` so that invariant is pinned by a test in both feature
    // configurations rather than re-derived by eye — see
    // `boot_spawns_list_manager`.
    let spawn_lists = boot_spawns_list_manager(&merged_sources, config);

    // Readiness gate. Seeded CLOSED exactly when this node will build its
    // own filter map, and OPEN
    // otherwise — the manager is the only thing that opens it, so
    // seeding it closed on a node whose manager never runs would refuse
    // every query forever.
    //
    // `spawn_lists` is that predicate. It is NOT
    // `config.blocklists.is_empty()`: sources arrive through two
    // channels (`[lists].sources` and `[[blocklists]]`, merged by
    // `merge_sources_with_blocklists`), so a node configured entirely
    // through `[lists].sources` would read as "no lists" and seed the
    // gate open with no map built yet.
    //
    // This is the only place the seed is decided — and, since the gate
    // is a `ReadinessGate`, the only place in the whole tree where a
    // `false` can enter it at all. Nothing downstream can close it.
    let filter_ready = ReadinessGate::new(!spawn_lists);

    if spawn_lists {
        // Bound BEFORE the catalog is acquired: that is where the
        // persisted copy is read from, and where a freshly fetched one is
        // written back. `lists_cache_dir` `create_dir_all`s as a side
        // effect, so this moves the directory's creation ahead of the
        // fetch. Checked what that crosses: the catalog acquisition
        // itself — the point of the move, since it is what needs this
        // directory to exist — then the bit→label snapshot loop and the
        // `interval` binding, neither of which touches the filesystem,
        // and all three stay below.
        let lists_dir = lists_cache_dir(config_path, config);
        let catalog =
            fetch_catalog_or_fallback(&list_client, &lists_dir, CatalogPreference::Disk).await;
        // Build the snapshot before `catalog` moves into the manager.
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
        // same entry point the gate's tests use — rather than reusing
        // the locals below, so there is exactly one definition of "the
        // fingerprint of this config" and no way for boot and reload to
        // drift apart. It redoes the source merge, which its own doc
        // calls a cold path; a duplicate merge once per boot is not
        // worth a second code path.
        lists_fingerprint = Some(ListsFingerprint::from_config(
            config,
            &secrets,
            &bridge_config_dir,
        ));

        let mut mgr = ListManager::with_tokens(
            list_client.clone(),
            filter.clone(),
            merged_sources,
            catalog,
            interval,
            source_bits.clone(),
            source_tokens.clone(),
            config.lists.max_body_bytes,
            config.lists.max_entries,
            Some(lists_dir),
        );

        // The daemon owns `list_state.json`, so this manager records its
        // refresh transitions into it.
        ManagerWiring::from_config(
            config,
            config_path,
            source_trust,
            bridge_config_dir,
            policy_masks,
            ListStateWriteback::Persist,
        )
        .apply(&mut mgr);

        // Daemon-only, so it stays outside the shared wiring: wire
        // `list_stats.json` for `delta_pct_vs_prev` persistence and
        // capture the registry handle BEFORE `spawn_refresh_loop`
        // consumes the manager. Same Arc goes to `DaemonState`, so the
        // IPC handler reads through the atomic state the manager writes.
        mgr.set_status_persistence_path(list_stats_path(config_path));
        list_status_registry = Some(mgr.status_registry());

        // Seed the registry's `by_v1_id_index` so future id-keyed
        // consumers (TUI Lists tab, audit attribution)
        // resolve a `&Id` straight to the slot without re-deriving the
        // URL. The manager constructed the registry with slash-form
        // translations only (it doesn't have `&[Blocklist]` in scope);
        // we own the catalogue here.
        if let Some(reg) = list_status_registry.as_ref() {
            reg.populate_v1_id_index(&config.blocklists);
        }

        // Wire the broadcast publisher so each refresh cycle emits one
        // `ListStatsUpdated` per source. The Sender lives in
        // `DaemonState` for future subscriber-endpoint resubscription.
        mgr.set_notification_channel(notification_tx.clone());

        // Clone the list_state Arc before the manager moves into
        // spawn_refresh_loop. Same Arc backs the refresh loop's
        // transition writes AND the IPC handler's diagnostics walk —
        // single source of truth.
        list_state_handle = Some(mgr.list_state_handle());

        // Hand the resolver the SAME Arc the refresh loop writes
        // through, so every later map rebuild (SIGHUP reload, 60 s
        // schedule tick) sees each list's
        // current download state instead of assuming all of them are
        // live. Attaching does not rebuild anything by itself — the
        // swap below, after the initial refresh, is what publishes the
        // first state-aware map.
        if let Some(resolver) = profiles.as_ref() {
            resolver.attach_list_state(mgr.list_state_handle());
        }

        // Wire the out-of-band command channel so the IPC `ForgetList`
        // handler can reach the refresh loop. Channel
        // depth 16 covers a burst of operator forgets without blocking
        // the IPC task (each send is fire-and-forget from the loop's
        // perspective once acked).
        let (list_cmd_tx, list_cmd_rx) = tokio::sync::mpsc::channel(16);
        mgr.set_command_channel(list_cmd_rx);
        list_cmd_tx_swap.store(Arc::new(Some(list_cmd_tx)));

        // The manager is the only thing that opens the gate. Handed over
        // before the first cycle of any mode so the CacheOnly load below
        // is what unlatches it on a healthy boot.
        mgr.set_filter_ready_gate(filter_ready.clone());

        // `load_corpus_before_bind` performs the `load_disk_cache` +
        // `cleanup_stale_caches` pair itself before its first cycle, so the
        // two calls this replaced are inside it, not dropped.
        let count = load_corpus_before_bind(&mut mgr, BIND_RETRY_INITIAL_BACKOFF).await;
        tracing::info!(count, "initial blocklist loaded");
        // The refresh above wrote every list's outcome into the state
        // the resolver now holds a handle to. Republish the map so the
        // one the DNS listener
        // starts serving is built from those outcomes — the resolver
        // built at startup predates the manager and assumed every list
        // was live. This runs before the listener binds, so no query is
        // ever answered from the pre-refresh map.
        //
        // Without this the first state-aware rebuild would wait for a
        // reload or a schedule tick, and the tick only runs on a box
        // that has schedules configured.
        if let Some(resolver) = profiles.as_ref() {
            resolver.swap(config, &source_bits, custom_lists);
        }
        refresh_handle = Some(mgr.spawn_refresh_loop());
    } else {
        tracing::info!("no lists configured, filtering disabled");
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
    let ip_filter: Option<Arc<IpFilter>> = if config.ip_blocklists.enabled {
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

    // Attach the DNSSEC response-path validator when enabled. It is
    // given its OWN DO-on upstream (same targets + failover, DO bit set); the
    // client-facing `upstream` above stays DO-off so normal resolution is
    // byte-identical. `mode = Off` and the default (feature-off) build skip this
    // block entirely, so they pay nothing.
    #[cfg(feature = "dnssec")]
    let handler = if config.dnssec.mode != crate::config::settings::DnssecMode::Off {
        let do_upstream: Arc<dyn crate::upstream::Upstream> = Arc::new(
            UpstreamResolver::from_config_validator(&config.upstream, &upstream_client)?,
        );
        let validator = Arc::new(crate::dns::dnssec_validator::DnssecValidator::new(
            do_upstream,
            &config.dnssec,
        ));
        handler.with_dnssec_validator(validator)
    } else {
        handler
    };

    // Hot-reload: grab a clone of the handler's shared ACL cell BEFORE it
    // is moved into the DNS server, so `signal_loop` → `handle_reload` can
    // live-swap `server.allow_from` on reload without a daemon restart.
    let acl_handle = handler.allow_from_handle();

    let tcp_timeout = Duration::from_secs(config.server.tcp_timeout_secs);
    let server = DnsServer::new(handler, config.server.listen, tcp_timeout).await?;

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
        let node_name = config.cluster.node_name.clone();
        match (config.cluster.enabled, config.cluster.role) {
            (false, _) => None,
            // Primary: needs the serve-state for generations/hashes; `None` when
            // the API is off (no heartbeats arrive, so no roster — already
            // warned by `build_cluster_state`). Roster cap 64 is far beyond any
            // realistic LAN cluster; eviction is logged (observe::Roster).
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
        list_count: config.lists.sources.len(),
        started_at,
        shutdown_tx: Some(ipc_shutdown_tx),
        reload_tx: Some(ipc_reload_tx),
        api_token_hash: api_token_hash_for_state,
        config_path: Some(config_path.to_path_buf()),
        config_write_lock: config_write_lock.clone(),
        list_statuses: list_status_registry.clone(),
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
    });
    let ipc_handle = spawn_ipc_server(socket_path.clone(), ipc_state).await?;

    // Start REST API server (if enabled)
    let mut api_handle: Option<JoinHandle<()>> = None;
    let mut api_cleanup_handle: Option<JoinHandle<()>> = None;
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

        let api_state = Arc::new(crate::api::state::ApiState {
            filter: filter.clone(),
            cache: cache.clone(),
            profiles: profiles.clone(),
            stats: stats.clone(),
            config_path: config_path.to_path_buf(),
            // `check_api` (API_ENABLED_REQUIRES_TOKEN_HASH) rejects the config at
            // load when `api.enabled = true` and `token_hash` is unset
            // or blank, so this branch sees `Some` in practice; the
            // unwrap_or_default is a fail-closed safety net — `verify_token`
            // against `""` always returns false because `subtle::ct_eq`
            // rejects on length mismatch (a 64-hex SHA never equals a
            // 0-byte slice).
            token_hash: config.api.token_hash.clone().unwrap_or_default(),
            rate_limiter: crate::auth::middleware::AuthRateLimiter::new(),
            api_rate_limiter: crate::api::rate_limit::ApiRateLimiter::new(
                config.api.rate_limit_per_minute,
            ),
            reload_tx: api_reload_tx,
            upstream: Some(upstream_resolver.clone()),
            started_at,
            listen_addr: config.server.listen.to_string(),
            upstream_mode: config.upstream.mode.to_string(),
            upstream_count: config.upstream.servers.len(),
            list_count: config.lists.sources.len(),
            // Same registry the IPC handler reads. The HTTP surface is
            // always token-gated by the `/api/...` middleware — IPC's
            // "ReadOnly = no token" does NOT extend to HTTP.
            list_statuses: list_status_registry.clone(),
            // Same bit→label snapshot DaemonState holds, so /api/query
            // can name the blocking list. Cheap Arc clone.
            list_labels: list_labels.clone(),
            // Share the IPC mutation lock so concurrent
            // POSTs against `/api/lists/add` (and the symmetric IPC
            // path) cannot lose updates.
            config_write_lock: config_write_lock.clone(),
            #[cfg(feature = "cluster")]
            cluster: cluster_state.clone(),
            #[cfg(feature = "cluster")]
            cluster_observe: cluster_observe.clone(),
        });

        // Spawn rate limiter cleanup task (every 60s) — sweeps both the
        // auth-failure lockout map and the per-IP request-rate windows.
        let rl_state = api_state.clone();
        let rl_handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                rl_state.rate_limiter.cleanup();
                rl_state.api_rate_limiter.cleanup();
            }
        });

        match crate::api::server::spawn_api_server(&config.api, api_state).await {
            Ok(h) => {
                api_handle = Some(h);
                // Store cleanup handle for shutdown (added below via stats_handles)
                api_cleanup_handle = Some(rl_handle);
            }
            Err(e) => {
                rl_handle.abort();
                tracing::error!(error = %e, "failed to start REST API server");
            }
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
            config.cluster.node_name.clone(),
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
    // signal_loop only needs the list_client — reloads re-fetch catalogs and lists.
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
    let exit_result = signal_loop(
        config_path,
        &list_client,
        &filter,
        profiles.as_ref(),
        &mut refresh_handle,
        &mut lists_fingerprint,
        has_schedules,
        &mut ipc_shutdown_rx,
        &mut ipc_reload_rx,
        &audit_writer,
        &mut current_files,
        &mut current_hash,
        &api_token_hash,
        &acl_handle,
        stats.as_ref(),
        list_status_registry.as_ref(),
        &notification_tx,
        &list_cmd_tx_swap,
        cluster_reload_handle,
        security.as_ref(),
        &mut api_handle,
    )
    .await;

    // Audit the shutdown before we tear anything down so a rollover that
    // crashes mid-cleanup still leaves a trail. `shutdown_uid` is
    // Some(peer_uid) for an IPC Shutdown command and None for SIGTERM /
    // SIGINT / channel-closed exits.
    let shutdown_uid = exit_result.as_ref().ok().and_then(|uid| *uid);
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
    if let Some(h) = api_cleanup_handle {
        h.abort();
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

    if let Some(h) = refresh_handle.take() {
        h.abort();
    }

    // Wait for server to finish
    match server_handle.await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => tracing::error!("server error during shutdown: {e}"),
        Err(e) => tracing::error!("server task panicked: {e}"),
    }

    exit_result.map(|_peer_uid| ())
}

/// Hand the manager the bulk download client, for the background refresh
/// loop it is about to become.
///
/// Called at both transition points, and no longer symmetrically. **Reload**
/// still calls it after its inline `refresh()` has returned. **Boot** calls it
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
/// domain count, and the contract is that it **only returns at all once a
/// map exists**: the caller binds on return, so returning `0` would be an
/// unfiltered boot.
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
    tracing::info!(count, "blocklist loaded from disk cache");

    // Branch (b): nothing on disk — a fresh install, or a cache the corpus
    // guard refused. Fall back to the old behaviour and block on the network,
    // now with the bulk client so a big list can actually complete.
    if count == 0 {
        tracing::warn!(
            "no usable disk cache; downloading before the listener binds \
             (first run, or the cache was refused)"
        );
        count = mgr.refresh_with_mode(RefreshMode::Network).await;
    }

    // Branch (c): still nothing. Do NOT bind. A daemon that answers without a
    // filter map is the failure this change exists to prevent, and it has
    // shipped here before. Retry rather than exit: exiting hands the box to a
    // systemd restart loop, which removes DNS just as thoroughly and hides the
    // cause.
    let mut backoff = initial_backoff;
    while count == 0 {
        tracing::error!(
            retry_in_secs = backoff.as_secs(),
            "REFUSING TO BIND: no filter map could be built from disk or \
             network, and lists are configured. DNS stays down rather than \
             answering unfiltered. Retrying."
        );
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(BIND_RETRY_MAX_BACKOFF);
        count = mgr.refresh_with_mode(RefreshMode::Network).await;
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
#[allow(clippy::too_many_arguments)]
async fn signal_loop(
    config_path: &Path,
    list_client: &reqwest::Client,
    filter: &Arc<FilterEngine>,
    profiles: Option<&Arc<ProfileResolver>>,
    refresh_handle: &mut Option<JoinHandle<()>>,
    lists_fingerprint: &mut Option<ListsFingerprint>,
    mut has_schedules: bool,
    ipc_shutdown_rx: &mut mpsc::Receiver<Option<u32>>,
    ipc_reload_rx: &mut mpsc::Receiver<Option<u32>>,
    audit_writer: &AuditWriter,
    current_files: &mut Vec<PathBuf>,
    current_hash: &mut Option<String>,
    api_token_hash: &Arc<arc_swap::ArcSwap<Option<String>>>,
    acl_handle: &Arc<arc_swap::ArcSwapOption<Vec<crate::config::cidr::Cidr>>>,
    stats: Option<&Arc<StatsEngine>>,
    list_status_registry: Option<&Arc<ListStatusRegistry>>,
    notification_tx: &tokio::sync::broadcast::Sender<crate::ipc::protocol::IpcNotification>,
    list_cmd_tx_swap: &Arc<
        arc_swap::ArcSwap<
            Option<tokio::sync::mpsc::Sender<crate::lists::manager::ListManagerCommand>>,
        >,
    >,
    cluster_state: ClusterReloadHandle<'_>,
    security: Option<&Arc<SecurityLayer>>,
    api_handle: &mut Option<JoinHandle<()>>,
) -> anyhow::Result<Option<u32>> {
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

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("SIGINT received");
                return Ok(None);
            }
            _ = sigterm.recv() => {
                tracing::info!("SIGTERM received");
                return Ok(None);
            }
            result = ipc_shutdown_rx.recv(), if ipc_shutdown_live => {
                match result {
                    Some(peer_uid) => {
                        tracing::info!("shutdown requested via IPC");
                        return Ok(peer_uid);
                    }
                    None => {
                        tracing::warn!("IPC shutdown channel closed (IPC server may have crashed)");
                        ipc_shutdown_live = false;
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
                    filter,
                    profiles,
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
                .await
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
                            filter,
                            profiles,
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
                        .await
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
            _ = schedule_tick.tick(), if has_schedules => {
                handle_schedule_tick(config_path, profiles);
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
    if let Ok(stripped) = config_parent.strip_prefix("/etc") {
        if let Some(first) = stripped.components().next() {
            return Path::new("/var/lib").join(first.as_os_str());
        }
    }
    config_parent.to_path_buf()
}

/// Enumerate every file the loader considered when parsing the v1 config:
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
    if let Ok(loaded) = crate::config::loader::load_config(config_path, now) {
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
fn build_profile_resolver(
    config: &crate::config::schema::ConfigV1,
    source_bits: &SourceBitMap,
    custom_lists: &CustomListStore,
) -> Arc<ProfileResolver> {
    Arc::new(ProfileResolver::build(config, source_bits, custom_lists))
}

/// Re-evaluate schedules by re-reading the v1 config and rebuilding
/// profiles. Called every 60 s by the signal loop.
///
/// Also prunes expired schedules from disk: a lapsed one-shot row —
/// typically a `warden device quiet`
/// leftover — is dropped from the file that defines it via per-file
/// surgery, NOT `write_config_v1` (which would flatten multi-file
/// layouts). Prune failure is non-fatal: expired rows are inert at
/// resolver-build time anyway.
fn handle_schedule_tick(config_path: &Path, profiles: Option<&Arc<ProfileResolver>>) {
    let resolver = match profiles {
        Some(r) => r,
        None => return,
    };
    let now = time::OffsetDateTime::now_utc();
    let loaded = match crate::config::loader::load_config(config_path, now) {
        Ok(l) => l,
        Err(errs) => {
            // Log the actual errors, not just the count — a tick that
            // fails every 60 s with "N error(s)" gives the operator
            // nothing actionable in the journal.
            let detail = errs
                .iter()
                .map(|e| e.to_string())
                .collect::<Vec<_>>()
                .join("; ");
            tracing::warn!(
                errors = errs.len(),
                "schedule tick: config load failed: {detail}"
            );
            return;
        }
    };
    if loaded.config.schedules.is_empty() {
        return;
    }
    let (merged_sources, _trust) =
        merge_sources_with_blocklists(&loaded.config.lists.sources, &loaded.config.blocklists);
    let source_bits = match SourceBitMap::build(&merged_sources, &loaded.config.blocklists) {
        Ok(bits) => bits,
        Err(e) => {
            tracing::warn!(error = %e, "schedule tick: source bit map build failed");
            return;
        }
    };
    resolver.swap(&loaded.config, &source_bits, &loaded.custom_lists);
    tracing::debug!("schedule tick: profile map rebuilt");

    // Drop lapsed one-shot rows from disk. Best-effort: a failure (e.g.
    // a read-only config tree under a hardened unit) only means the
    // inert rows stay until a CLI path prunes them.
    match crate::cli::commands::schedules::prune_expired_schedules(config_path, &loaded, now) {
        Ok(pruned) if !pruned.is_empty() => {
            tracing::info!(
                count = pruned.len(),
                ids = %pruned.join(", "),
                "schedule tick: pruned expired schedule(s) from config"
            );
        }
        Ok(_) => {}
        Err(e) => {
            tracing::warn!(error = %e, "schedule tick: expired-schedule prune failed");
        }
    }
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
    /// Merged source vector, **order-sensitive**. [`SourceBitMap::build`]
    /// assigns bits positionally, so reordering `lists.sources` re-maps
    /// every profile's bitmask and genuinely does need a rebuild — never
    /// sort this before comparing.
    sources: Vec<String>,
    /// Baked into the manager's refresh loop at construction.
    update_interval_secs: u64,
    max_body_bytes: usize,
    /// This changes what the parser keeps
    /// from an unchanged URL set, so a gate that only diffs URLs would
    /// serve a stale-width map while reporting success.
    max_entries: usize,
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
    /// Per-row fields that reach the fetch / parse / trust path. This
    /// also covers `SourceTrustMap`, which `merge_sources_with_blocklists`
    /// derives deterministically from these same rows.
    blocklists: Vec<BlocklistFingerprint>,
    /// SipHash of the *resolved* bearer tokens, key-sorted. A digest and
    /// not the values themselves, because this struct derives `Debug`
    /// and must never be able to print a secret (same reasoning as the
    /// hand-written `Debug` on [`SourceTokenMap`]). Hashing the resolved
    /// value rather than the `auth_token_ref` name means rotating a
    /// secret in `secrets.toml` forces the rebuild that puts the new
    /// token on the wire.
    token_digest: u64,
}

/// The subset of a `[[blocklists]]` row that changes what gets fetched
/// or how it parses. `display_name` and `tags` are deliberately absent —
/// see the membership rule on [`ListsFingerprint`].
#[derive(Debug, Clone, PartialEq, Eq)]
struct BlocklistFingerprint {
    id: crate::config::schema::Id,
    url: String,
    format: crate::config::schema::BlocklistFormat,
    update_interval_hours: u32,
    max_entries: u64,
    enabled: bool,
    auth_token_ref: Option<String>,
    base: crate::config::schema::BlocklistBase,
    trust: crate::config::schema::BlocklistTrust,
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
    /// Build from the values `handle_reload` has already derived, so the
    /// gate costs no extra merge.
    fn compute(
        config: &crate::config::schema::ConfigV1,
        merged_sources: &[String],
        source_tokens: &SourceTokenMap,
        config_dir: &Path,
    ) -> Self {
        use std::hash::{Hash, Hasher};

        // `url_tokens()` is a `HashMap`: iteration order varies between
        // instances, so hashing it as-iterated would yield a different
        // digest for two equal maps and force a spurious rebuild on
        // every single reload. Sort first.
        let mut token_entries: Vec<(&str, &str)> = source_tokens
            .url_tokens()
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        token_entries.sort_unstable();
        // `DefaultHasher::new` is fixed-key, so it is deterministic for
        // the life of the process. That is the whole requirement here —
        // the digest is only ever compared against another one computed
        // by this same daemon, and never persisted or sent anywhere.
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        token_entries.hash(&mut hasher);

        Self {
            sources: merged_sources.to_vec(),
            update_interval_secs: config.lists.update_interval_secs,
            max_body_bytes: config.lists.max_body_bytes,
            max_entries: config.lists.max_entries,
            cache_dir: config.lists.cache_dir.clone(),
            max_total_domains: config.lists.max_total_domains,
            shrink_guard_enabled: config.lists.shrink_guard_enabled,
            shrink_guard_max_drop_pct: config.lists.shrink_guard_max_drop_pct,
            blocklists: config
                .blocklists
                .iter()
                .map(|b| BlocklistFingerprint {
                    id: b.id.clone(),
                    url: b.url.clone(),
                    format: b.format,
                    update_interval_hours: b.update_interval_hours,
                    max_entries: b.max_entries,
                    enabled: b.enabled,
                    auth_token_ref: b.auth_token_ref.clone(),
                    base: b.base,
                    trust: b.trust,
                    local_stamp: matches!(b.trust, crate::config::schema::BlocklistTrust::Local)
                        .then(|| crate::lists::manager::stat_local_source(&b.url, config_dir))
                        .flatten(),
                })
                .collect(),
            token_digest: hasher.finish(),
        }
    }

    /// Derive from a loaded config + secrets, doing the source merge and
    /// token resolution internally. Used to seed the fingerprint at
    /// daemon boot (so the *first* reload can already skip) and by the
    /// gate's tests.
    fn from_config(
        config: &crate::config::schema::ConfigV1,
        secrets: &crate::config::secrets::Secrets,
        config_dir: &Path,
    ) -> Self {
        let (merged_sources, _trust) =
            merge_sources_with_blocklists(&config.lists.sources, &config.blocklists);
        Self::compute(
            config,
            &merged_sources,
            &SourceTokenMap::build(config, secrets),
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
/// [`ListManager`] — actually exists to be reused. It is ANDed rather
/// than assumed: with no live loop, a matching fingerprint would
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
    filter: &Arc<FilterEngine>,
    profiles: Option<&Arc<ProfileResolver>>,
    refresh_handle: &mut Option<JoinHandle<()>>,
    lists_fingerprint: &mut Option<ListsFingerprint>,
    audit_writer: &AuditWriter,
    current_files: &mut Vec<PathBuf>,
    current_hash: &mut Option<String>,
    api_token_hash: &Arc<arc_swap::ArcSwap<Option<String>>>,
    acl_handle: &Arc<arc_swap::ArcSwapOption<Vec<crate::config::cidr::Cidr>>>,
    stats: Option<&Arc<StatsEngine>>,
    list_status_registry: Option<&Arc<ListStatusRegistry>>,
    notification_tx: &tokio::sync::broadcast::Sender<crate::ipc::protocol::IpcNotification>,
    list_cmd_tx_swap: &Arc<
        arc_swap::ArcSwap<
            Option<tokio::sync::mpsc::Sender<crate::lists::manager::ListManagerCommand>>,
        >,
    >,
    invoker_uid: Option<u32>,
    cluster_state: ClusterReloadHandle<'_>,
    security: Option<&Arc<SecurityLayer>>,
) -> Option<bool> {
    #[cfg(not(feature = "cluster"))]
    let _ = cluster_state;
    let pre_hash = current_hash.clone();

    let loaded =
        match crate::config::loader::load_config(config_path, time::OffsetDateTime::now_utc()) {
            Ok(l) => l,
            Err(errs) => {
                tracing::error!("config reload failed: {} error(s)", errs.len());
                for err in &errs {
                    tracing::error!(%err, "reload error");
                }
                let err_strings: Vec<String> = errs.iter().map(|e| e.to_string()).collect();
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
                return None;
            }
        };
    let config = &loaded.config;

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
    log_inert_custom_lists(config, &loaded.custom_lists);

    // Keep the query log writer's attach state in sync
    // with the reloaded `tracking.query_log_enabled`. Attaches when the
    // operator flipped the flag from `false` to `true`, detaches (and
    // schedules the writer's flush-and-exit) on the inverse transition.
    // No-op when the state hasn't changed.
    if let Some(engine) = stats {
        apply_query_log_reload(engine, &config.tracking, config_path);
    }

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
            return None;
        }
    };

    // The old refresh loop is NOT aborted here. This point sits above the
    // source-bitmap reject gate, the empty-sources branch, and the reuse
    // gate — aborting here would orphan the live manager on paths that
    // never re-arm one (a rejected bitmap build would leave the daemon
    // silently never refreshing its lists again), and it is incompatible
    // with reusing the live manager. Each path that genuinely retires the
    // manager aborts it itself: the empty-sources branch and the rebuild
    // path.

    // Same merge as the initial path so reloads pick up
    // newly-imported `[[blocklists]]` URLs and refresh their trust map.
    let (merged_sources, source_trust) =
        merge_sources_with_blocklists(&config.lists.sources, &config.blocklists);

    let source_bits = match SourceBitMap::build(&merged_sources, &config.blocklists) {
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
            return None;
        }
    };

    // Derived from the map just built — one build, not two.
    let policy_masks = source_bits.project_policy(&config.blocklists, &config.profiles);

    if let Some(resolver) = profiles {
        resolver.swap(config, &source_bits, &loaded.custom_lists);
    }

    // Live-swap the tunneling thresholds + `exempt_domains`, the
    // per-client rate limiter's qps/burst, and the RRL
    // responses_per_second/window_secs/slip_rate — so `warden security
    // set …` and `warden security tunneling exempt …` apply without a
    // restart. The tunneling escape hatch exists because the tunneling
    // gates run before the filter engine and no allow rule can reach
    // them; costing ~30 s of downed DNS to use it would make the remedy
    // dearer than the fault. The rate/RRL knobs exist for the same
    // reason `warden security set` exists at all: tuning a live incident
    // response should not cost a restart either.
    //
    // Deliberately narrow: only the *parameters* swap. Rebuilding
    // `SecurityLayer` here would reconstruct `RateLimiter`, `Rrl` and the
    // per-(client, base) subdomain map, zeroing every counter — handing
    // an attacker a fresh budget on each config edit, and resetting the
    // very gates this change leans on as primary defences.
    //
    // Not reachable from here by construction: `tunneling.enabled`,
    // `rate_limit.enabled`, `rrl.enabled`. Each sub-checker is an
    // `Option` decided when `SecurityLayer` is built, so flipping any of
    // the three flags still needs a restart. `warden security set`
    // reports that explicitly instead of printing unqualified success —
    // see `cli::commands::security::run_set`.
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

    // Atomically swap the auth hash so a freshly-rotated token
    // from `warden token regenerate` goes live the instant this reload lands —
    // not on the next daemon restart. If the new config has an empty hash (API
    // disabled / token revoked), store `None` so the auth gate falls back to
    // "no token configured" rather than silently keeping the old hash.
    // This store sits AFTER the config-validate, secrets, and
    // source-bitmap gates (each early-returns `Rejected` on failure) and after
    // the resolver swap — every success path (cluster-secondary, empty-sources,
    // normal) flows through here, every abort path returns before it. So a
    // reload reported `Rejected` rotates neither the policy nor the token hash.
    api_token_hash.store(Arc::new(config.api.token_hash.clone()));

    // Live-swap the source-IP ACL (`server.allow_from`) so a tightened
    // ACL applies on reload without a daemon restart. Placed alongside the
    // token-hash store — past every reject gate and the resolver swap — so a
    // reload reported `Rejected` leaves the ACL untouched ("a rejected reload
    // changes nothing"). The load-time validator already checks each entry, so
    // a parse error here is should-never-happen; on error we KEEP the previous
    // ACL rather than widening to accept-all (storing `None` would be a
    // security regression). The DNS handler reads the same cell lock-free.
    match parse_allow_from(&config.server.allow_from) {
        Ok(acl) => {
            let count = acl.as_ref().map_or(0, |c| c.len());
            acl_handle.store(acl);
            tracing::info!(count, "server.allow_from ACL reloaded");
        }
        Err(e) => {
            tracing::error!(error = %e, "reload: server.allow_from re-parse failed; keeping previous ACL");
        }
    }

    // Re-serialise the policy bundle + bump config_generation on
    // every successful reload. After the resolver swap, both the empty-sources
    // and normal paths flow through here; the earlier abort points already
    // returned. No-op when not a clustering primary.
    #[cfg(feature = "cluster")]
    if let Some(cs) = cluster_state {
        cs.update_policy(config);
    }

    let new_files = collect_loaded_files(config_path);
    let new_hash = audit::tree_hash(new_files.iter());

    if merged_sources.is_empty() {
        tracing::info!("no list sources in config, clearing blocklist");
        // The operator removed every source: retire the live manager so
        // its refresh loop cannot re-download the old sources and
        // re-populate the map we are about to clear.
        if let Some(h) = refresh_handle.take() {
            h.abort();
        }
        *lists_fingerprint = None;
        filter.swap_blocklist(Default::default());
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
            reg.record_cycle(CycleOutcome::ClearedNoSources);
        }
        return Some(reload_has_schedules);
    }

    let source_tokens = SourceTokenMap::build(config, &secrets_state);

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
    // Everything above this point has already applied: the profile
    // resolver swap (which is how an operator's new device allow rule
    // goes live), the token hash, the ACL, the query-log writer. What
    // follows is the 9.9 M-domain rebuild — 16-25 s warm, 164 s once
    // the disk caches expire — and it is worth doing only when the list
    // pipeline's own inputs moved.
    //
    // The gate sits BELOW the resolver swap on purpose. Hoisting it
    // above would skip the very change the operator asked for.
    //
    // `refresh_handle.is_some()` is the proof that a live `ListManager`
    // exists to reuse; with no live loop there is nothing to keep, so
    // rebuild regardless of what the fingerprint says.
    let fingerprint = ListsFingerprint::compute(
        config,
        &merged_sources,
        &source_tokens,
        &bridge_config_dir_for_fingerprint,
    );
    if should_reuse_live_lists(
        refresh_handle.is_some(),
        lists_fingerprint.as_ref(),
        &fingerprint,
    ) {
        // The status registry still has to be re-synced. A blocklist's
        // display name, tags, or trust label can change without moving
        // anything the fingerprint covers, and the TUI reads the
        // registry — not the config — to render the Lists tab.
        // `ensure_slots` / `retain_only` are no-ops here by definition
        // (the source set is unchanged); `populate_v1_id_index` is not.
        // The live manager already holds this same `Arc`, so nothing
        // needs re-attaching.
        if let Some(reg) = list_status_registry {
            reg.ensure_slots(&merged_sources);
            reg.retain_only(&merged_sources);
            reg.populate_v1_id_index(&config.blocklists);
            // A skip IS a completed cycle, and this is the ONLY path that
            // can say so. The manager's install path never runs here — the
            // function returns below — so a mark written only there would
            // leave the sequence frozen through a perfectly successful
            // reload, and anyone waiting for it to advance would wait out
            // their whole timeout and then report "still reloading" about a
            // cycle that finished instantly and correctly.
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
        return Some(reload_has_schedules);
    }

    // Past the gate: this reload genuinely retires the live manager, so
    // its refresh loop stops here.
    if let Some(h) = refresh_handle.take() {
        h.abort();
    }

    // Bound before the catalog is acquired — same ordering constraint as
    // the boot site: the persisted copy lives in here, and this reload is
    // the only path that ever refreshes it.
    let lists_dir = lists_cache_dir(config_path, config);
    let catalog =
        fetch_catalog_or_fallback(list_client, &lists_dir, CatalogPreference::Network).await;
    let interval = Duration::from_secs(config.lists.update_interval_secs);
    // Same value the fingerprint above was stamped against — computed once
    // and reused rather than re-derived, so the two can never disagree.
    let bridge_config_dir = bridge_config_dir_for_fingerprint;

    let mut mgr = ListManager::with_tokens(
        list_client.clone(),
        filter.clone(),
        merged_sources.clone(),
        catalog,
        interval,
        source_bits.clone(),
        source_tokens,
        config.lists.max_body_bytes,
        config.lists.max_entries,
        Some(lists_dir),
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
        source_trust,
        bridge_config_dir,
        policy_masks,
        ListStateWriteback::Persist,
    )
    .apply(&mut mgr);

    // Keep the SAME registry handle DaemonState is reading through, so
    // the IPC stats stay live across reload. The registry grows on
    // demand, and `ensure_slots` pre-seeds rows for the new merged
    // source set so the TUI sees "never_fetched" placeholders for fresh
    // subscriptions within one IPC poll instead of waiting on the first
    // download to complete (~1-3s). `retain_only` handles the symmetric
    // case — deleting a [[blocklists]] entry also evicts its registry
    // slot so the TUI doesn't render a permanent orphan row keyed on
    // the dead URL.
    if let Some(reg) = list_status_registry {
        reg.ensure_slots(&merged_sources);
        reg.retain_only(&merged_sources);
        // Rebuild the registry's typed
        // `by_v1_id_index` to track the post-reload `[[blocklists]]`
        // catalogue (rows added, removed, or trust-changed since the
        // previous reload). Atomic replacement via ArcSwap.
        reg.populate_v1_id_index(&config.blocklists);
        mgr.attach_status_registry(reg.clone());
    }
    // Re-attach the broadcast publisher so the post-reload
    // manager keeps emitting `ListStatsUpdated`. Same Sender clone
    // already wired to `DaemonState.notification_tx`, so future
    // subscribers see the post-reload events without re-subscribing.
    mgr.set_notification_channel(notification_tx.clone());
    mgr.set_status_persistence_path(list_stats_path(config_path));

    // Wire a fresh out-of-band command channel for
    // the post-reload manager and swap the new sender into the shared
    // ArcSwap so the IPC `ForgetList` handler picks it up on the next
    // call. The previous channel's receiver dies with the aborted
    // refresh task; the old sender (now disconnected) is overwritten
    // here.
    let (list_cmd_tx, list_cmd_rx) = tokio::sync::mpsc::channel(16);
    mgr.set_command_channel(list_cmd_rx);
    list_cmd_tx_swap.store(Arc::new(Some(list_cmd_tx)));

    mgr.load_disk_cache();
    mgr.cleanup_stale_caches();
    let count = mgr.refresh().await;
    tracing::info!(count, "lists reloaded");
    // Same transition as the boot path: the inline refresh above ran inside
    // the signal loop's `select!`, whose sibling arm is SIGTERM — so it had
    // to stay on the tight client. The background loop it is about to
    // become blocks nothing, so it gets the bulk one.
    install_bulk_download_client(&mut mgr);
    *refresh_handle = Some(mgr.spawn_refresh_loop());
    // Describe the manager that is now live, so
    // the next reload can compare against it. Stored only once the
    // rebuild has actually happened — an earlier store would let a
    // reload that died mid-refresh advertise a pipeline that never ran.
    *lists_fingerprint = Some(fingerprint);

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
    Some(reload_has_schedules)
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
enum CatalogPreference {
    Disk,
    Network,
}

/// Whether a freshly fetched catalog is worth writing to disk.
///
/// Isolated from [`fetch_catalog_or_fallback`]'s `Ok` arm for the same
/// reason [`should_reuse_live_lists`] is isolated from `handle_reload`:
/// the caller only reaches that arm through `Catalog::fetch`, which
/// hardcodes `https://lists.purge.cc/index.json`, so this predicate is
/// the only seam a network-free test can exercise.
///
/// `false` for zero entries. `Catalog::fetch_from`
/// has no viability check of its own — an HTTP 200 carrying a valid
/// `{"lists": []}` is a well-formed `Ok` with nothing usable in it.
/// Persisting that would freeze every later boot onto an empty catalog:
/// `CatalogPreference::Disk` would keep finding it and resolving nothing,
/// permanently, until a reload happened to see a real response. Does not
/// change what the *current* process uses — the caller still returns `c`
/// either way.
fn catalog_worth_persisting(c: &Catalog) -> bool {
    !c.entries().is_empty()
}

/// Resolve the list catalog.
///
/// This is the ONLY
/// remaining pre-bind network call — 0.3 s on a live link, up to the
/// client's 30 s total on a dead one, in front of a listener that has
/// everything else it needs. It cannot be deferred past the bind:
/// `load_disk_cache` resolves each source through the catalog and the
/// cache stem derives from the resolved URL, so the on-disk list bodies
/// are unreadable without it.
///
/// `pref` decides which side of the bind the caller is on:
/// [`CatalogPreference::Disk`] for boot (never blocks),
/// [`CatalogPreference::Network`] for reload (refreshes the persisted
/// copy — the only path that ever does, because `Catalog::resolve`
/// returns `None` for an unknown id rather than triggering a fetch).
async fn fetch_catalog_or_fallback(
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
        Ok(c) => {
            if catalog_worth_persisting(&c) {
                if let Err(e) = c.save_to_disk(lists_dir) {
                    // Not fatal: a catalog we cannot persist still works
                    // for this process, it just does not help the next
                    // boot.
                    tracing::warn!(error = %e, "failed to persist catalog");
                }
            } else {
                tracing::warn!("fetched catalog has zero entries, not persisting to disk");
            }
            c
        }
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

/// Map a canonical kebab-form blocklist `Id` (e.g. `"privacy-ads"`) back to
/// its legacy slash-form catalog slug (e.g. `"privacy/ads"`). Splits
/// on the **first** hyphen so multi-segment topics survive intact:
/// `"security-malicious-extra"` → `"security/malicious-extra"`. Returns
/// `None` for ids without a hyphen — those are not catalog-shaped.
///
/// Mirrors the inverse transform used by [`SourceBitMap::build`] and
/// `build_slug_to_id_map` in `crate::profiles::resolver` (module-private),
/// so the manager's `source_to_blocklist` lookup hits regardless of
/// whether the operator pinned the list via `lists.sources` (slash
/// form) or `[[blocklists]]` (canonical id).
fn canonical_id_to_slash(id: &str) -> Option<String> {
    let idx = id.find('-')?;
    Some(format!("{}/{}", &id[..idx], &id[idx + 1..]))
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
    list_state: crate::config::list_state::ListState,
    list_state_path: Option<PathBuf>,
}

impl ManagerWiring {
    /// Derive the wiring from config. `source_trust`, `bridge_config_dir`
    /// and `policy_masks` are parameters because every caller has already
    /// computed them — `policy_masks` in particular must be projected
    /// before `source_bits` moves into the manager.
    pub(crate) fn from_config(
        config: &crate::config::schema::ConfigV1,
        config_path: &Path,
        source_trust: crate::lists::source_key::SourceTrustMap,
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
        let (source_to_blocklist, source_to_format) = build_source_maps(&config.blocklists);
        Self {
            source_trust,
            bridge_config_dir,
            policy_masks,
            shrink_guard_enabled: config.lists.shrink_guard_enabled,
            shrink_guard_max_drop_pct: config.lists.shrink_guard_max_drop_pct,
            max_total_domains: config.lists.max_total_domains,
            source_to_blocklist,
            source_to_format,
            list_state,
            list_state_path: match writeback {
                ListStateWriteback::Persist => Some(state_path),
                ListStateWriteback::ReadOnly => None,
            },
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
            list_state,
            list_state_path,
        } = self;
        mgr.set_local_bridge(source_trust, bridge_config_dir);
        mgr.set_list_policy(policy_masks);
        mgr.set_shrink_guard(shrink_guard_enabled, shrink_guard_max_drop_pct);
        mgr.set_max_total_domains(max_total_domains);
        mgr.set_source_blocklist_map(source_to_blocklist);
        mgr.set_source_format_map(source_to_format);
        mgr.set_list_state(list_state, list_state_path);
    }
}

/// Map every source string a manager may see back to its `[[blocklists]]`
/// row — the fetch URL, the slash-form catalog id a legacy
/// `lists.sources` entry uses, and the canonical id itself.
///
/// The first map carries the canonical id and per-list failure threshold
/// the retry state machine runs on. The second carries a declared parse
/// format; only `hosts` and `adguard` rows enter it, so a `domains` or
/// omitted format leaves the parse dispatch on content auto-detection.
fn build_source_maps(
    blocklists: &[crate::config::schema::Blocklist],
) -> (
    std::collections::HashMap<String, (crate::config::schema::Id, u32)>,
    std::collections::HashMap<String, crate::lists::detector::ListFormat>,
) {
    let mut source_to_blocklist = std::collections::HashMap::new();
    let mut source_to_format = std::collections::HashMap::new();
    for b in blocklists {
        if !b.enabled {
            continue;
        }
        let declared_fmt = match b.format {
            crate::config::schema::BlocklistFormat::Hosts => {
                Some(crate::lists::detector::ListFormat::Hosts)
            }
            crate::config::schema::BlocklistFormat::Adguard => {
                Some(crate::lists::detector::ListFormat::AdGuard)
            }
            crate::config::schema::BlocklistFormat::Domains => None,
        };
        let mut insert = |key: String| {
            source_to_blocklist.insert(key.clone(), (b.id.clone(), b.max_consecutive_failures));
            if let Some(fmt) = declared_fmt {
                source_to_format.insert(key, fmt);
            }
        };
        // Every blocklist exposes its fetch URL as a potential
        // `merged_sources` entry.
        insert(b.url.as_str().to_string());
        // A list pinned through `lists.sources` arrives as the slash
        // slug, not the URL.
        if let Some(slash) = canonical_id_to_slash(b.id.as_str()) {
            insert(slash);
        }
        // Defensive: a future caller passing the canonical id still hits.
        insert(b.id.as_str().to_string());
    }
    (source_to_blocklist, source_to_format)
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

#[cfg(test)]
#[allow(clippy::field_reassign_with_default)]
mod tests;
