//! `warden lists refresh` — trigger list re-download through the live
//! daemon's typed IPC, or perform a foreground download when it is stopped.
//!
//! The module keeps the `update` name (and `run_update` its symbol)
//! because the CLI rename to `lists refresh` was a label change only;
//! `tests/cli_update_pure_v1.rs` imports this path.

use std::io::ErrorKind;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use super::lists_knobs::{format_corpus_lines, LiveCorpus};
use super::pid;
use super::start::{list_stats_path, lists_cache_dir, ListStateWriteback, ManagerWiring};
use crate::cli::exit_codes::{CONFIG, FAILURE, SUCCESS};
use crate::config::loader;
use crate::filter::FilterEngine;
use crate::ipc::protocol::{IpcCommand, IpcResponse, ListRegistrySnapshotDto};
use crate::ipc::socket_client::send_command;
use crate::lists::manager::ListManager;
use crate::lists::source_key::{ResolvedSourcePlan, SourceBitMap, SourceTokenMap};
use crate::lists::status::{CycleOutcome, ServedState};

fn spill_rollback_failed_lines() -> [&'static str; 3] {
    [
        "the list refresh kept the previous generation because its temporary spill could not be rolled back.",
        "the prior generation remains active; this cycle contributes no records.",
        "Check the journal, then retry the refresh.",
    ]
}

fn source_coverage_incomplete_lines() -> [&'static str; 3] {
    [
        "source coverage is incomplete for the most recent manager list attempt.",
        "A hot attempt keeps the complete prior corpus; a cold attempt may install",
        "usable sources. Check failed list sources before treating this as a full update.",
    ]
}

/// A failed cycle and the live corpus are different facts; report both.
fn generation_degraded_lines(state: ServedState) -> [String; 2] {
    let served = match state {
        ServedState::Complete => "the previous complete generation remains serving",
        ServedState::Partial => "a partial generation is serving; retry expected",
        ServedState::Uninitialized => "no generation is installed; DNS is answering unfiltered",
        ServedState::IntentionalEmpty => {
            "an accepted complete empty generation is serving; filtering nothing"
        }
        ServedState::Cleared => "the config-cleared corpus is serving; filtering nothing",
        ServedState::Unknown => "served-generation completeness cannot be determined (legacy)",
    };
    [
        format!("the refresh did not complete; served state: {served}."),
        "The daemon will retry automatically; inspect status and the journal.".to_string(),
    ]
}

/// Classify the completed cycle, not delivery of its request.
fn completed_refresh_exit(snapshot: &ListRegistrySnapshotDto) -> i32 {
    let cycle = snapshot.cycle;
    if cycle.outcome == Some(CycleOutcome::ConfigRejected) {
        return CONFIG;
    }
    if cycle.source_coverage_incomplete || cycle.generation_degraded {
        return FAILURE;
    }
    match cycle.outcome {
        Some(
            CycleOutcome::Installed
            | CycleOutcome::SkippedUnchanged
            | CycleOutcome::ClearedNoSources,
        ) => SUCCESS,
        Some(
            CycleOutcome::Refused
            | CycleOutcome::SpillRollbackFailed
            | CycleOutcome::ConfigRejected,
        )
        | None => FAILURE,
    }
}

fn live_corpus_from_snapshot(snapshot: &ListRegistrySnapshotDto) -> LiveCorpus {
    LiveCorpus {
        unique_installed: snapshot.domain_count as u64,
        truncated: snapshot
            .rows
            .iter()
            .filter(|row| row.status.parsed_truncated > 0)
            .count() as u32,
        total_sources: snapshot.rows.len() as u32,
        refusal: snapshot.corpus_refusal.clone(),
        freeze: snapshot.corpus_freeze.clone(),
        cycle: Some(snapshot.cycle),
    }
}

fn print_snapshot_corpus(snapshot: &ListRegistrySnapshotDto, ceiling: Option<u64>) {
    let Some(ceiling) = ceiling else { return };
    let live = live_corpus_from_snapshot(snapshot);
    println!();
    for line in format_corpus_lines(ceiling, Ok(&live)) {
        println!("{line}");
    }
}

/// Render exactly the completed actor snapshot used for the exit decision.
fn render_completed_refresh(snapshot: &ListRegistrySnapshotDto, ceiling: Option<u64>) {
    let cycle = snapshot.cycle;
    match cycle.outcome {
        Some(CycleOutcome::Installed) => {
            println!("installed.");
            print_snapshot_corpus(snapshot, ceiling);
        }
        Some(CycleOutcome::SkippedUnchanged) => {
            println!("no new list generation was built; the current corpus was retained.");
        }
        Some(CycleOutcome::ClearedNoSources) => {
            println!("the config has NO list sources, so the blocklist was CLEARED.");
        }
        Some(CycleOutcome::Refused) => {
            println!("REFUSED — the merged corpus exceeds max_total_domains.");
            let live = live_corpus_from_snapshot(snapshot);
            if live.unique_installed == 0 {
                println!("NOTHING is installed; DNS is answering unfiltered.");
            } else {
                println!(
                    "The previous generation is still filtering; no new list domains are active."
                );
            }
            print_snapshot_corpus(snapshot, ceiling);
        }
        Some(CycleOutcome::SpillRollbackFailed) if !cycle.generation_degraded => {
            for line in spill_rollback_failed_lines() {
                println!("{line}");
            }
        }
        Some(CycleOutcome::SpillRollbackFailed) => {}
        Some(CycleOutcome::ConfigRejected) => {
            println!("the daemon REFUSED the new config; the previous config remains in force.");
        }
        None => println!("the refresh completed without a reported outcome."),
    }
    if cycle.source_coverage_incomplete {
        for line in source_coverage_incomplete_lines() {
            println!("{line}");
        }
    }
    if cycle.generation_degraded {
        for line in generation_degraded_lines(cycle.served_state) {
            println!("{line}");
        }
    }
}

/// Trigger a list update. A validated live daemon receives only typed IPC;
/// otherwise this process performs the foreground refresh.
///
/// Returns the intended process exit code; `main.rs` translates it via
/// [`crate::cli::exit_codes::exit_with`].
///
/// # Exit codes
///
/// - [`SUCCESS`] — the exact completed cycle installed, retained unchanged,
///   or intentionally cleared an empty configuration without degradation.
/// - [`FAILURE`] — a live IPC/auth/compatibility failure, or a completed
///   cycle that was refused, incomplete, or degraded.
/// - [`CONFIG`] — the config could not be loaded. This path previously
///   printed the errors and returned `Ok(())`, so `warden lists refresh`
///   reported success on a config the daemon would refuse to boot.
///
/// Note this command does **not** return [`FAILURE`](crate::cli::exit_codes::FAILURE) merely because no
/// daemon was running: a foreground download that completes *is* the
/// operation succeeding. "Daemon down" is only a failure for the verbs
/// whose whole job is talking to the daemon.
///
/// **Loader.** Uses the v1 [`loader::load_config`] (the same loader the
/// daemon and the rest of the CLI surface use), so a config with
/// `[lists].sources = []` and `[[blocklists]]` populated is read
/// correctly here rather than reporting "no list sources configured".
///
/// **Cache directory.** Reuses [`lists_cache_dir`] from `start.rs` so
/// the foreground tool writes into the same FHS-aware path as the
/// daemon (`/var/lib/<pkg>/lists/` on prod, `<config-parent>/<cache_dir>`
/// on dev).
pub async fn run_update(config_path: &Path, pid_file: &Path) -> anyhow::Result<i32> {
    // Resolve this command's socket here, not in `main`: an invalid config
    // must return CONFIG rather than escaping through anyhow as exit 1.
    let now = time::OffsetDateTime::now_utc();
    let loaded = match loader::load_config(config_path, now) {
        Ok(l) => l,
        Err(errs) => {
            eprintln!(
                "cannot load config {} ({} error(s)):",
                config_path.display(),
                errs.len()
            );
            for err in &errs {
                eprintln!("  - {err}");
            }
            return Ok(CONFIG);
        }
    };
    let socket_path = &loaded.config.socket.path;

    // This lease is the decision, not a prior liveness observation. Holding it
    // through foreground work excludes a concurrent daemon start and its list
    // state writes. A held lease belongs to a daemon (or another refresh), so
    // it is IPC-only and can never fall back.
    let foreground_lease = match pid::try_acquire_pid_lock(pid_file) {
        Ok(lease) => Some(lease),
        Err(pid::PidLockError::AlreadyRunning(_)) => None,
        Err(pid::PidLockError::Io(error)) => {
            eprintln!(
                "cannot acquire PID-file lease {}: {error}",
                pid_file.display()
            );
            return Ok(FAILURE);
        }
    };

    let socket_probe = if foreground_lease.is_some() {
        probe_socket(socket_path).await
    } else {
        // A contended lease is already a live/unsafe signal. Do not probe a
        // second time before routing IPC: that would only add delay.
        SocketProbe::Live
    };
    match select_refresh_route(foreground_lease.is_some(), socket_probe) {
        RefreshRoute::Foreground => {}
        RefreshRoute::FailClosed => {
            // WHY: an uncertain socket can be a wedged live daemon; treating it as
            // absent would reintroduce concurrent cache/list-state writes.
            eprintln!("cannot determine whether the configured IPC socket is live; refusing foreground refresh");
            return Ok(FAILURE);
        }
        RefreshRoute::TypedIpc => {
            // Once a held lease or a live socket is observed, IPC failure is
            // terminal: foreground work could overlap the daemon's writes.
            match send_command(socket_path, &IpcCommand::ForceListRefresh { token: None }).await {
                Ok(IpcResponse::ListRefreshCompleted {
                    disposition,
                    snapshot,
                    max_total_domains,
                }) => {
                    println!("list refresh accepted: {}", disposition.as_str());
                    render_completed_refresh(&snapshot, max_total_domains);
                    return Ok(completed_refresh_exit(&snapshot));
                }
                Ok(IpcResponse::Error { message }) => {
                    if message == crate::ipc::errors::IPC_ERROR_INVALID_COMMAND {
                        eprintln!(
                            "live daemon and CLI are incompatible: typed list refresh is unsupported. \
                             Restart or upgrade the daemon before retrying."
                        );
                    } else {
                        eprintln!("live daemon refused list refresh: {message}");
                    }
                }
                Ok(other) => {
                    eprintln!(
                        "live daemon and CLI are incompatible: typed list refresh is unsupported \
                         ({other:?}). Restart or upgrade the daemon before retrying."
                    );
                }
                Err(error) => {
                    eprintln!("could not request typed list refresh from live daemon: {error}");
                }
            }
            return Ok(FAILURE);
        }
    }

    // No daemon socket is reachable and the lease remains held for this whole
    // branch — do a foreground download.
    println!("no running daemon found, performing foreground list download...");

    if loaded.config.lists.sources.is_empty()
        && !loaded
            .config
            .blocklists
            .iter()
            .any(|blocklist| blocklist.enabled)
    {
        // Not a failure: an operator with no lists configured asked for a
        // refresh and got the correct answer — there is nothing to fetch.
        println!("no list sources or blocklists configured");
        return Ok(SUCCESS);
    }

    let (_filter, completion) = refresh_foreground_filter(config_path, &loaded.config).await?;
    let snapshot: ListRegistrySnapshotDto = completion.snapshot.into();
    render_completed_refresh(
        &snapshot,
        completion.max_total_domains.map(|value| value as u64),
    );
    Ok(completed_refresh_exit(&snapshot))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SocketProbe {
    Live,
    AbsentOrRefused,
    Ambiguous,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RefreshRoute {
    Foreground,
    TypedIpc,
    FailClosed,
}

/// Select exactly one writer path from the atomic PID lease plus socket probe.
fn select_refresh_route(lease_acquired: bool, socket_probe: SocketProbe) -> RefreshRoute {
    if !lease_acquired || matches!(socket_probe, SocketProbe::Live) {
        RefreshRoute::TypedIpc
    } else if matches!(socket_probe, SocketProbe::AbsentOrRefused) {
        RefreshRoute::Foreground
    } else {
        RefreshRoute::FailClosed
    }
}

/// Probe only after owning the foreground lease. A live unlinked daemon PID
/// file is still caught by its socket; all uncertain transport states fail
/// closed instead of being mistaken for a stopped daemon.
async fn probe_socket(socket_path: &Path) -> SocketProbe {
    match tokio::time::timeout(
        Duration::from_secs(1),
        tokio::net::UnixStream::connect(socket_path),
    )
    .await
    {
        Ok(Ok(_)) => SocketProbe::Live,
        Ok(Err(error))
            if matches!(
                error.kind(),
                ErrorKind::NotFound | ErrorKind::ConnectionRefused
            ) =>
        {
            SocketProbe::AbsentOrRefused
        }
        Ok(Err(_)) | Err(_) => SocketProbe::Ambiguous,
    }
}

/// Build a [`ListManager`] exactly the way the daemon's boot and reload
/// paths do (`cli::commands::start`) and run one refresh cycle.
///
/// Split out of [`run_update`]'s foreground branch so a test can inspect
/// the [`FilterEngine`] this produces. `run_update` itself only surfaces an
/// exit code, a domain count, and the on-disk list cache — none of which can
/// distinguish a domain that landed in `allow_mask` from one that landed in
/// `block_mask`, so none of them would catch a manager built without ever
/// telling it which sources are allow-direction — every list, `base =
/// allow` included, would be stamped `DomainMasks::block_only`. The
/// `set_allow_bits` call below is what prevents that.
///
/// Returns the engine (the caller is free to drop it immediately — nothing
/// outside this one-shot process reads it again) and the merged domain
/// count.
async fn refresh_foreground_filter(
    config_path: &Path,
    config: &crate::config::schema::ConfigV1,
) -> anyhow::Result<(
    Arc<FilterEngine>,
    crate::lists::manager::ForceRefreshCompletion,
)> {
    // Bulk client: this fetches whole list bodies, which a single total
    // deadline turns into a bandwidth-dependent size cap. Unlike the boot
    // and reload paths, an operator-invoked foreground refresh blocks only
    // the operator's own terminal — waiting is exactly what they asked for.
    //
    // `Catalog::fetch` below shares this client. Its `send()` is wrapped in
    // NOTHING (`catalog.rs`: only `read_bounded_body_bytes` sits inside the
    // 2s `tokio::time::timeout`; `fetch_unified`'s outer wrapper is a
    // different entry point this does not route through), so the connect and
    // headers phase is bounded by the client's `connect_timeout` and
    // `read_timeout` — 10s and 30s — not by the 600s total. That is fine
    // here, but it is load-bearing: shortening BULK_READ_TIMEOUT is safe,
    // removing it would leave the catalog's pending phase on the 600s
    // ceiling.
    let client = crate::lists::http_client::build_bulk_list_client()?;
    let lists_dir = lists_cache_dir(config_path, config);

    let catalog = super::start::fetch_catalog_or_fallback(
        &client,
        &lists_dir,
        super::start::CatalogPreference::Network,
    )
    .await;
    println!(
        "catalog ready ({} lists available)",
        catalog.entries().len()
    );
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
    if super::start::config_declares_list_sources(config) && source_plan.is_empty() {
        anyhow::bail!("configured list sources resolved to no reproducible catalog entries");
    }
    let filter = Arc::new(FilterEngine::new());
    let interval = Duration::from_secs(config.lists.update_interval_secs);
    let source_bits =
        SourceBitMap::from_plan(&source_plan).map_err(|e| anyhow::anyhow!("lists.sources: {e}"))?;

    // The operator's per-profile list policy, projected onto this
    // bit assignment. Computed here, before `source_bits` moves into the
    // manager below, mirroring `start.rs`'s boot and reload paths.
    let policy_masks = source_bits.project_policy(&config.blocklists, &config.profiles);

    let bridge_config_dir = config_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf();

    // Resolve `[[blocklists]].auth_token_ref` against the secrets file.
    // Without this the foreground refresh fetches every authenticated
    // list anonymously — in the one command an operator runs precisely
    // expecting a fetch. A secrets file the loader refuses (a mode wider
    // than 0600) is an error the operator must see, not a silent
    // downgrade to unauthenticated.
    let secrets_path = crate::config::secrets::secrets_path_for(config_path);
    let secrets = crate::config::secrets::load_secrets(&secrets_path)
        .map_err(|e| anyhow::anyhow!("secrets file rejected: {e}"))?;
    let source_tokens = SourceTokenMap::from_plan(&source_plan, &secrets);

    let mut mgr = ListManager::with_plan_and_tokens(
        client,
        filter.clone(),
        source_plan.clone(),
        interval,
        source_bits,
        source_tokens,
        config.lists.max_body_bytes,
        config.lists.max_entries,
        Some(lists_dir),
    );
    mgr.status_registry().sync_plan(&source_plan);

    // The same wiring the daemon applies at boot and at reload. This
    // tool used to hand-maintain its own shorter list, which is how it
    // ended up without the loader-bridge, then without the list policy —
    // so a `base = allow` list silently blocked the domains it was
    // imported to permit — and then without the source maps.
    //
    // `ReadOnly`: the refresh reads list state so the retry state machine
    // sees canonical ids and per-list thresholds, but never writes back.
    // The same reason keeps `load_status_baselines` below read-only — a
    // one-shot command must not clobber what the running daemon owns.
    // Direction is pinned red-then-green by
    // `tests::foreground_refresh_honors_list_direction`.
    ManagerWiring::from_config(
        config,
        config_path,
        &source_plan,
        bridge_config_dir,
        policy_masks,
        ListStateWriteback::ReadOnly,
    )
    .apply(&mut mgr);

    // Arm the retention guard's baselines so this refresh is guarded too
    // — otherwise `warden lists refresh` would be a bypass: a garbage 200
    // would overwrite the good on-disk cache the daemon later trusts.
    mgr.load_status_baselines(&list_stats_path(config_path));

    mgr.load_disk_cache();
    let completion = mgr.force_refresh_completion().await;
    Ok((filter, completion))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    const ALLOWED_DOMAIN: &str = "allowed-example.test";
    const BLOCKED_DOMAIN: &str = "blocked-example.test";

    fn completed_snapshot(
        outcome: Option<CycleOutcome>,
        source_coverage_incomplete: bool,
        generation_degraded: bool,
    ) -> ListRegistrySnapshotDto {
        ListRegistrySnapshotDto {
            rows: Vec::new(),
            corpus_refusal: None,
            corpus_freeze: None,
            domain_count: 0,
            cycle: crate::lists::status::CycleMark {
                seq: 1,
                outcome,
                source_coverage_incomplete,
                generation_degraded,
                served_state: ServedState::Complete,
            },
        }
    }

    #[test]
    fn refresh_exit_uses_completed_outcome_and_health() {
        for outcome in [
            CycleOutcome::Installed,
            CycleOutcome::SkippedUnchanged,
            CycleOutcome::ClearedNoSources,
        ] {
            assert_eq!(
                completed_refresh_exit(&completed_snapshot(Some(outcome), false, false)),
                SUCCESS
            );
        }
        for outcome in [CycleOutcome::Refused, CycleOutcome::SpillRollbackFailed] {
            assert_eq!(
                completed_refresh_exit(&completed_snapshot(Some(outcome), false, false)),
                FAILURE
            );
        }
        assert_eq!(
            completed_refresh_exit(&completed_snapshot(None, false, false)),
            FAILURE
        );
        assert_eq!(
            completed_refresh_exit(&completed_snapshot(
                Some(CycleOutcome::Installed),
                true,
                false,
            )),
            FAILURE
        );
        assert_eq!(
            completed_refresh_exit(&completed_snapshot(
                Some(CycleOutcome::SpillRollbackFailed),
                false,
                true,
            )),
            FAILURE
        );
        assert_eq!(
            completed_refresh_exit(&completed_snapshot(
                Some(CycleOutcome::ConfigRejected),
                false,
                false,
            )),
            CONFIG
        );
        assert_eq!(
            completed_refresh_exit(&completed_snapshot(
                Some(CycleOutcome::ConfigRejected),
                true,
                true
            )),
            CONFIG
        );
        assert_eq!(
            completed_refresh_exit(&completed_snapshot(
                Some(CycleOutcome::ClearedNoSources),
                true,
                false
            )),
            FAILURE
        );
        assert_eq!(
            completed_refresh_exit(&completed_snapshot(
                Some(CycleOutcome::Installed),
                false,
                true
            )),
            FAILURE
        );
    }

    #[test]
    fn spill_rollback_failure_rendering_keeps_the_previous_generation() {
        assert_eq!(
            spill_rollback_failed_lines(),
            [
                "the list refresh kept the previous generation because its temporary spill could not be rolled back.",
                "the prior generation remains active; this cycle contributes no records.",
                "Check the journal, then retry the refresh.",
            ]
        );
    }

    #[test]
    fn incomplete_source_coverage_rendering_names_hot_and_cold_policy() {
        assert_eq!(
            source_coverage_incomplete_lines(),
            [
                "source coverage is incomplete for the most recent manager list attempt.",
                "A hot attempt keeps the complete prior corpus; a cold attempt may install",
                "usable sources. Check failed list sources before treating this as a full update.",
            ]
        );
    }

    #[test]
    fn degraded_refresh_rendering_names_the_served_state() {
        let cases = [
            (
                ServedState::Complete,
                "previous complete generation remains serving",
            ),
            (
                ServedState::Partial,
                "partial generation is serving; retry expected",
            ),
            (
                ServedState::Uninitialized,
                "no generation is installed; DNS is answering unfiltered",
            ),
            (
                ServedState::IntentionalEmpty,
                "accepted complete empty generation is serving; filtering nothing",
            ),
            (
                ServedState::Unknown,
                "served-generation completeness cannot be determined (legacy)",
            ),
        ];
        for (served_state, expected) in cases {
            let lines = generation_degraded_lines(served_state).join("\n");
            assert!(lines.contains(expected), "{served_state:?}: {lines}");
            assert!(
                lines.contains("the refresh did not complete; served state:"),
                "{served_state:?}: {lines}"
            );
            assert!(
                lines.contains("will retry automatically"),
                "{served_state:?}: {lines}"
            );
            assert!(
                !lines.contains("no complete generation was installed"),
                "{served_state:?}: {lines}"
            );
        }
    }

    /// Two `trust = "local"` blocklists: one `base = "allow"` carrying
    /// [`ALLOWED_DOMAIN`], one `base = "deny"` (the default) carrying
    /// [`BLOCKED_DOMAIN`]. Same `imported.local` bridge fixture shape as
    /// `tests/cli_update_pure_v1.rs` — see its module doc for why that
    /// scheme is used instead of a mock HTTP server (the URL guard in
    /// `lists::http_client` refuses non-HTTPS / loopback targets before a
    /// request would land).
    fn write_direction_fixture(dir: &Path) -> PathBuf {
        let master = dir.join("config.toml");
        std::fs::write(
            &master,
            r#"schema_version = 4

[server]
listen = "0.0.0.0:53"
default_profile = "default"
allow_from = ["127.0.0.0/8"]

[lists]
sources = []
cache_dir = "lists"

[[blocklists]]
id = "test-allow-direction"
display_name = "Test allow-direction"
url = "https://imported.local/test-allow-direction.txt"
format = "domains"
trust = "local"
base = "allow"
tags = ["ads"]
update_interval_hours = 24
max_entries = 1_000_000
enabled = true

[[blocklists]]
id = "test-deny-direction"
display_name = "Test deny-direction"
url = "https://imported.local/test-deny-direction.txt"
format = "domains"
trust = "local"
update_interval_hours = 24
max_entries = 1_000_000
enabled = true

[profiles.default]
display_name = "Default"

[upstream]
servers = ["192.0.2.1:53"]
"#,
        )
        .unwrap();

        let lists_src = dir.join("lists");
        std::fs::create_dir_all(&lists_src).unwrap();
        std::fs::write(
            lists_src.join("test-allow-direction.txt"),
            format!("{ALLOWED_DOMAIN}\n"),
        )
        .unwrap();
        std::fs::write(
            lists_src.join("test-deny-direction.txt"),
            format!("{BLOCKED_DOMAIN}\n"),
        )
        .unwrap();

        master
    }

    /// Guards `run_update`'s foreground path calling `set_allow_bits`
    /// before building its `ListManager` — without it `Spill::build_shard`
    /// stamps every domain, `base = allow` lists included, as
    /// `DomainMasks::block_only`. This pins the actual per-domain verdict
    /// `FilterEngine::list_membership` returns, which is the primitive a
    /// missing wiring call would corrupt. `run_update`'s exit code and
    /// printed domain count are identical whether the wiring is present
    /// or not (both lists contribute one domain each either way), so
    /// neither would catch a regression here — this test calls the
    /// extracted `refresh_foreground_filter` directly to get at the
    /// engine itself.
    #[tokio::test(flavor = "current_thread")]
    async fn foreground_refresh_honors_list_direction() {
        let tmp = tempfile::tempdir().unwrap();
        let master = write_direction_fixture(tmp.path());

        let now = time::OffsetDateTime::now_utc();
        let loaded = loader::load_config(&master, now).expect("fixture config must load");
        let (filter, _count) = refresh_foreground_filter(&master, &loaded.config)
            .await
            .expect("foreground refresh must succeed on the direction fixture");

        let allowed = filter.list_membership(ALLOWED_DOMAIN);
        assert_ne!(
            allowed.allow_mask, 0,
            "{ALLOWED_DOMAIN} came from a kind=allow list and must carry an allow_mask bit"
        );
        assert_eq!(
            allowed.block_mask, 0,
            "{ALLOWED_DOMAIN} must not also be classified block-direction"
        );

        let blocked = filter.list_membership(BLOCKED_DOMAIN);
        assert_ne!(
            blocked.block_mask, 0,
            "{BLOCKED_DOMAIN} came from the default kind=deny list and must carry a block_mask bit"
        );
        assert_eq!(
            blocked.allow_mask, 0,
            "{BLOCKED_DOMAIN} must not also be classified allow-direction"
        );
    }

    #[test]
    fn lease_and_socket_probe_choose_one_refresh_writer() {
        assert_eq!(
            select_refresh_route(true, SocketProbe::AbsentOrRefused),
            RefreshRoute::Foreground
        );
        assert_eq!(
            select_refresh_route(true, SocketProbe::Live),
            RefreshRoute::TypedIpc
        );
        assert_eq!(
            select_refresh_route(true, SocketProbe::Ambiguous),
            RefreshRoute::FailClosed
        );
        assert_eq!(
            select_refresh_route(false, SocketProbe::AbsentOrRefused),
            RefreshRoute::TypedIpc,
            "a contended PID lease never falls back to foreground"
        );
    }

    #[test]
    fn foreground_lease_excludes_a_concurrent_daemon_start() {
        let directory = tempfile::tempdir().unwrap();
        let pid_path = directory.path().join("warden.pid");
        let _foreground_lease = pid::try_acquire_pid_lock(&pid_path)
            .expect("foreground refresh takes the exclusive PID-file lease");

        assert!(
            matches!(
                pid::try_acquire_pid_lock(&pid_path),
                Err(pid::PidLockError::AlreadyRunning(_))
            ),
            "a daemon start must not acquire the PID file while refresh owns it"
        );
    }
}
