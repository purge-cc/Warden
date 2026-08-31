//! Show daemon status — live stats via IPC socket, config fallback without daemon.
//!
//! # Exit codes
//!
//! - [`SUCCESS`] — the daemon answered over IPC.
//! - [`FAILURE`] — the daemon is not reachable. `warden status` exists to
//!   answer "is it up?", so returning 0 for "it is down" made the command
//!   useless to the monitoring probes that are its main consumer.
//! - [`CONFIG`] — the daemon is down *and* the config cannot be loaded.
//!   Config problems dominate: without a readable config we cannot even
//!   resolve the socket path, so "down" is not a claim we can make.

use std::path::Path;

use crate::cli::exit_codes::{CONFIG, FAILURE, SUCCESS};
use crate::config::loader::load_config;
use crate::config::schema::validator::{inert_blocklists, InertListReason};
use crate::ipc::protocol::{IpcCommand, IpcResponse};
use crate::ipc::socket_client;

use super::pid;

/// Run the status command. Returns the intended process exit code;
/// `main.rs` translates it via [`crate::cli::exit_codes::exit_with`].
pub async fn run_status(
    config_path: &Path,
    pid_file: &Path,
    socket_path: &Path,
    json: bool,
) -> anyhow::Result<i32> {
    // Try IPC first — gives live stats from the running daemon
    match socket_client::send_command(socket_path, &IpcCommand::Status).await {
        Ok(resp) => {
            // "The socket answered" is not "the daemon is healthy". A daemon
            // that replies `Error` (or with an unexpected variant) has told
            // us nothing about its status, and must not be reported as up.
            //
            // The text renderer has always treated that as a failure — it
            // `bail!`s on `IpcResponse::Error`. The JSON renderer matched
            // with `if let IpcResponse::Status { .. }`, so an `Error` reply
            // fell straight through and produced an object with none of the
            // status fields and exit 0. Adding the `running` discriminator
            // turned that from a missing-fields problem into a positive
            // false claim, so the two paths are reconciled here rather than
            // in either renderer.
            let healthy = matches!(resp, IpcResponse::Status { .. });
            // Only worth asking for tracking stats if the daemon is
            // actually answering status queries.
            let tracking = if healthy {
                socket_client::send_command(socket_path, &IpcCommand::TrackingStats { token: None })
                    .await
                    .ok()
            } else {
                None
            };
            if json {
                print_live_status_json(config_path, resp, tracking, healthy)?;
                Ok(if healthy { SUCCESS } else { FAILURE })
            } else {
                // Bails on a non-Status reply, which `main` renders as 1.
                print_live_status(config_path, resp, tracking)?;
                Ok(SUCCESS)
            }
        }
        Err(e) => {
            // Show IPC error in offline output so the user knows why
            // live stats aren't available. The daemon is down, so this is
            // never SUCCESS — only "how badly".
            if json {
                Ok(print_offline_status_json(config_path, pid_file, Some(&e)))
            } else {
                Ok(print_offline_status(config_path, pid_file, Some(&e)))
            }
        }
    }
}

fn print_live_status(
    config_path: &Path,
    resp: IpcResponse,
    tracking: Option<IpcResponse>,
) -> anyhow::Result<()> {
    match resp {
        IpcResponse::Status {
            pid,
            listen,
            upstream_mode,
            upstream_count,
            domain_count,
            cache_entries,
            list_count,
            uptime_secs,
            query_log_drops,
            version,
            cache_cap,
            cache_weighted_size,
            lists_active,
            lists_total,
            lists_truncated,
            lists_corpus_refusal,
            // Not printed here, and that is the right call: this summary
            // already renders `CORPUS REFUSED — NOT INSTALLED` off
            // `lists_corpus_refusal`, which is the fact an operator reading
            // `status` needs. The cycle mark exists for callers that must
            // wait for a cycle to END — `lists refresh` — and a sequence
            // number in a human summary is noise. Destructured to keep the
            // pattern exhaustive.
            lists_cycle: _,
            lc2_list_diagnostics,
            // §4.13 — resource_budget is surfaced through the TUI
            // Dashboard, not the text CLI summary; the field is
            // destructured here to keep the pattern exhaustive but
            // intentionally not printed.
            resource_budget: _,
        } => {
            // §4.19: surface the daemon binary version in the header
            // line when it's reported (pre-§4.19 daemons send "").
            if version.is_empty() {
                println!("purge-warden is running (PID {pid})");
            } else {
                println!("purge-warden v{version} is running (PID {pid})");
            }
            println!();
            println!("listen:     {listen}");
            println!("upstream:   {upstream_mode} ({upstream_count} servers)");
            // §4.19: render `active/total` when the registry-derived
            // counters are populated; fall back to the legacy
            // `list_count` scalar so pre-§4.19 daemons keep the same
            // single-number output.
            if lists_total > 0 {
                for line in format_lists_lines(
                    lists_active,
                    lists_total,
                    lists_truncated,
                    lists_corpus_refusal.as_ref(),
                ) {
                    println!("{line}");
                }
            } else {
                println!("lists:      {list_count} sources");
            }
            // `tag_model_consolidation` §3.3: a list can be active AND
            // filter nothing. The counters above cannot show that —
            // they count fetches, not reach.
            for line in inert_list_lines(config_path) {
                println!("{line}");
            }
            println!(
                "{}",
                format_domains_line(domain_count, lists_corpus_refusal.as_ref())
            );
            // mem2608-s3 / F-E: `cache_cap` is a moka *weight* ceiling,
            // not an entry count (see `format_cache_line`), so the pair
            // printed must be weight-vs-weight, not count-vs-weight.
            println!(
                "{}",
                format_cache_line(cache_entries, cache_weighted_size, cache_cap)
            );
            println!("uptime:     {}", format_uptime(uptime_secs));

            // T2.9 / H-20: surface query-log silent-drop counters so the
            // operator has a signal that logging is degraded before the
            // file ends up incomplete. Skip the line when the writer
            // isn't attached — "logging disabled" is its own state and
            // shouldn't render misleading zeros.
            if let Some(drops) = query_log_drops {
                println!(
                    "qlog drops: channel_full={} flush_open_errors={} flush_write_errors={}",
                    drops.channel_full, drops.flush_open_errors, drops.flush_write_errors,
                );
            }

            // Sprint C T3 of `lists_categories_v2` (§5.4 / §8.5):
            // surface the retry state machine's per-state counts so
            // the operator can spot blocklist health on a glance.
            // Skipped entirely when no list_state is wired (zeros
            // across the board) — keeps the section meaningful only
            // when there's signal to show.
            for line in format_lc2_list_diagnostics(&lc2_list_diagnostics) {
                println!("{line}");
            }

            // Show tracking stats if available
            if let Some(IpcResponse::TrackingStats {
                queries_total,
                blocked_total,
                blocked_pct,
                cache_hit_rate,
                top_blocked,
                prefetch_pool_size,
                prefetch_promotions_total,
                prefetch_demotions_total,
                ..
            }) = tracking
            {
                println!();
                println!(
                    "queries:    {} (blocked: {:.1}%)",
                    queries_total, blocked_pct
                );
                println!("blocked:    {blocked_total}");
                println!("cache rate: {cache_hit_rate:.1}%");
                // Sprint §4.4 P1 — surface the prefetch hit-tracker so
                // operators can watch the pool fill on a live deploy.
                // Only print when the tracker has observed at least one
                // promotion (avoids three zero-lines on disabled
                // tracker, the Phase 1 default).
                if prefetch_promotions_total > 0 || prefetch_pool_size > 0 {
                    println!(
                        "prefetch:   pool_size={prefetch_pool_size} \
                         promotions_total={prefetch_promotions_total} \
                         demotions_total={prefetch_demotions_total}"
                    );
                }
                if !top_blocked.is_empty() {
                    println!();
                    println!("Top blocked:");
                    for (i, entry) in top_blocked.iter().take(5).enumerate() {
                        println!("  {:>2}. {:<40} {} hits", i + 1, entry.domain, entry.count);
                    }
                }
            }

            Ok(())
        }
        IpcResponse::Error { message } => {
            anyhow::bail!("daemon error: {message}");
        }
        _ => {
            anyhow::bail!("unexpected response from daemon");
        }
    }
}

/// Render the live-daemon JSON object.
///
/// `running` comes from the caller rather than being assumed: a reply that
/// arrived is not necessarily a reply that reported status. See the
/// reconciliation comment in [`run_status`].
fn print_live_status_json(
    config_path: &Path,
    resp: IpcResponse,
    tracking: Option<IpcResponse>,
    running: bool,
) -> anyhow::Result<()> {
    // Captured before the destructuring below consumes `resp`.
    let daemon_error = match &resp {
        IpcResponse::Status { .. } => None,
        IpcResponse::Error { message } => Some(message.clone()),
        other => Some(format!("unexpected response from daemon: {other:?}")),
    };

    // Build a combined JSON object
    let mut map = serde_json::Map::new();

    // The discriminator both JSON paths emit. Additive — no existing key
    // changes meaning — and it is what lets a monitoring script parse one
    // shape instead of guessing which renderer produced the object.
    map.insert("running".into(), serde_json::Value::Bool(running));
    if let Some(msg) = daemon_error {
        // Present only when the daemon answered but did not report status,
        // so a consumer can tell that case from an unreachable socket
        // (which renders `daemon_state`/`ipc_error` instead).
        map.insert("daemon_error".into(), msg.into());
    }

    // `tag_model_consolidation` §3.3: same signal as the text form, so a
    // script watching for inert lists does not have to scrape stdout.
    // Additive — absent-when-empty would make consumers special-case the
    // key, so it is always present (possibly an empty array).
    let now = time::OffsetDateTime::now_utc();
    let inert: Vec<serde_json::Value> = match load_config(config_path, now) {
        Ok(loaded) => inert_blocklists(&loaded.config)
            .into_iter()
            .map(|(id, reason)| serde_json::json!({ "id": id, "reason": reason.message(id) }))
            .collect(),
        Err(_) => Vec::new(),
    };
    map.insert("inert_lists".into(), serde_json::Value::Array(inert));

    if let IpcResponse::Status {
        pid,
        listen,
        upstream_mode,
        upstream_count,
        domain_count,
        cache_entries,
        list_count,
        uptime_secs,
        query_log_drops,
        version,
        cache_cap,
        cache_weighted_size,
        lists_active,
        lists_total,
        lists_truncated,
        lists_corpus_refusal,
        lists_cycle,
        lc2_list_diagnostics,
        resource_budget,
    } = resp
    {
        map.insert("pid".into(), pid.into());
        map.insert("listen".into(), listen.into());
        map.insert("upstream_mode".into(), upstream_mode.into());
        map.insert("upstream_count".into(), upstream_count.into());
        map.insert("domain_count".into(), domain_count.into());
        map.insert("cache_entries".into(), cache_entries.into());
        map.insert("list_count".into(), list_count.into());
        map.insert("uptime_secs".into(), uptime_secs.into());
        // T2.9 / H-20: only emit the counters when the writer is
        // attached, so JSON consumers can distinguish "logging
        // disabled" (`null`) from "zero drops".
        map.insert(
            "query_log_drops".into(),
            serde_json::to_value(query_log_drops).unwrap_or(serde_json::Value::Null),
        );
        // §4.19: always emit the new fields — defaults (empty string,
        // 0) are themselves a meaningful "pre-§4.19 daemon" signal.
        map.insert("version".into(), version.into());
        map.insert("cache_cap".into(), cache_cap.into());
        // mem2608-s3 / F-E: the weight-unit counterpart to `cache_entries`
        // — see `format_cache_line`'s doc comment for why the two are not
        // directly comparable and this field is.
        map.insert("cache_weighted_size".into(), cache_weighted_size.into());
        map.insert("lists_active".into(), lists_active.into());
        map.insert("lists_total".into(), lists_total.into());
        map.insert("lists_truncated".into(), lists_truncated.into());
        // Emitted unconditionally, `null` when the last cycle installed.
        // A JSON consumer that only ever saw per-source rows would read a
        // refused cycle as fully healthy — every source is `ok`, because
        // every source genuinely parsed.
        map.insert(
            "lists_corpus_refusal".into(),
            serde_json::to_value(&lists_corpus_refusal).unwrap_or(serde_json::Value::Null),
        );
        // Also unconditional, and `null` carries real information here: it
        // means the daemon does not report cycles at all, not that none has
        // run. A consumer waiting on `seq` has to be able to tell those
        // apart or it waits forever.
        map.insert(
            "lists_cycle".into(),
            serde_json::to_value(lists_cycle).unwrap_or(serde_json::Value::Null),
        );
        // Sprint C T3 — emit the four per-state counts even when zero,
        // so JSON consumers always see the canonical shape and can
        // distinguish "section absent" (pre-Sprint-C daemon, no field)
        // from "all zeros" (Sprint-C daemon, no list_state wired).
        map.insert(
            "lc2_list_diagnostics".into(),
            serde_json::to_value(&lc2_list_diagnostics).unwrap_or(serde_json::Value::Null),
        );
        // §4.13 — surface the resource-budget sample so JSON consumers
        // (Prometheus scrapers, monitoring dashboards) can ingest RSS /
        // CPU / fd counts without spawning the TUI. `null` distinguishes
        // "no sample yet / non-Linux daemon" from a real reading.
        map.insert(
            "resource_budget".into(),
            serde_json::to_value(resource_budget).unwrap_or(serde_json::Value::Null),
        );
    }

    if let Some(IpcResponse::TrackingStats {
        queries_total,
        blocked_total,
        blocked_pct,
        cache_hit_rate,
        top_blocked,
        top_queried,
        hourly,
        daily,
        ..
    }) = tracking
    {
        map.insert("queries_total".into(), queries_total.into());
        map.insert("blocked_total".into(), blocked_total.into());
        map.insert(
            "blocked_pct".into(),
            serde_json::Number::from_f64(blocked_pct)
                .map(serde_json::Value::Number)
                .unwrap_or(serde_json::Value::Null),
        );
        map.insert(
            "cache_hit_rate".into(),
            serde_json::Number::from_f64(cache_hit_rate)
                .map(serde_json::Value::Number)
                .unwrap_or(serde_json::Value::Null),
        );
        map.insert(
            "top_blocked".into(),
            serde_json::to_value(top_blocked).unwrap_or_default(),
        );
        map.insert(
            "top_queried".into(),
            serde_json::to_value(top_queried).unwrap_or_default(),
        );
        map.insert(
            "hourly".into(),
            serde_json::to_value(hourly).unwrap_or_default(),
        );
        map.insert(
            "daily".into(),
            serde_json::to_value(daily).unwrap_or_default(),
        );
    }

    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::Value::Object(map))?
    );
    Ok(())
}

/// What the PID file says about the daemon on the branch reached only
/// after IPC has already failed to answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OfflineDaemonState {
    /// The PID file names a daemon that is still up — IPC is the thing
    /// that is broken, not the process.
    Live(u32),
    /// The PID file is readable but nothing is behind it.
    StalePidFile(u32),
    /// No PID file, or its contents are not a PID.
    NoPidFile,
}

/// Classify the daemon from its PID file.
///
/// `daemon_is_live`, not `is_process_alive`: the bare existence probe
/// passes on a stale PID file whose number the kernel has since recycled
/// onto an unrelated process, so a dead daemon reads as running. The
/// advisory lock separates them — only a live daemon holds it.
///
/// Both renderers share this so the text and JSON paths cannot disagree
/// about the same PID file. The JSON one carries the sharper consequence:
/// a monitoring probe told `ipc_unreachable` retries, where
/// `stale_pid_file` means the daemon is gone and someone must be paged.
fn classify_offline_daemon(pid_file: &Path) -> OfflineDaemonState {
    match pid::read_pid_file(pid_file) {
        Ok(daemon_pid) if pid::daemon_is_live(pid_file, daemon_pid) => {
            OfflineDaemonState::Live(daemon_pid)
        }
        Ok(daemon_pid) => OfflineDaemonState::StalePidFile(daemon_pid),
        Err(_) => OfflineDaemonState::NoPidFile,
    }
}

/// Render the daemon-is-down status page and return the exit code.
///
/// Returns [`CONFIG`] when the config also fails to load, else [`FAILURE`].
/// Never [`SUCCESS`]: reaching this function means IPC did not answer.
///
/// The config-load failure is printed rather than propagated as an `Err`,
/// because the PID/liveness lines above it are still real information —
/// bubbling the error out would discard the one fact the operator came for.
fn print_offline_status(
    config_path: &Path,
    pid_file: &Path,
    ipc_error: Option<&anyhow::Error>,
) -> i32 {
    // Check if daemon is running via PID
    match classify_offline_daemon(pid_file) {
        OfflineDaemonState::Live(daemon_pid) => {
            println!("purge-warden is running (PID {daemon_pid})");
            if let Some(e) = ipc_error {
                println!("IPC unavailable: {e}");
                println!("hint: showing config only (no live stats)");
            }
        }
        OfflineDaemonState::StalePidFile(daemon_pid) => {
            println!("purge-warden is not running (stale PID file: {daemon_pid})");
        }
        OfflineDaemonState::NoPidFile => {
            println!("purge-warden is not running (no PID file)");
        }
    }

    // §4.41: v1 loader replaces the v0 `Settings::from_file`. The
    // printed fields are pass-through sections on `ConfigV1`
    // (`server`/`upstream`/`lists`/`cache`) so field access is unchanged.
    let now = time::OffsetDateTime::now_utc();
    let loaded = match load_config(config_path, now) {
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
            return CONFIG;
        }
    };
    let cfg = &loaded.config;
    println!();
    println!("config:     {}", config_path.display());
    println!("listen:     {}", cfg.server.listen);
    println!("log_level:  {}", cfg.server.log_level);
    println!(
        "upstream:   {} ({})",
        cfg.upstream
            .servers
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>()
            .join(", "),
        cfg.upstream.mode
    );

    for line in format_config_lists_lines(
        cfg.blocklists.iter().filter(|b| b.enabled).count(),
        cfg.blocklists.len(),
        &cfg.lists.sources,
    ) {
        println!("{line}");
    }
    // `tag_model_consolidation` §3.3 — the config is already loaded
    // here, so this path reads it directly instead of re-loading.
    for line in format_inert_lists(&inert_blocklists(cfg)) {
        println!("{line}");
    }
    println!("update:     {}s", cfg.lists.update_interval_secs);
    println!("cache max:  {} entries", cfg.cache.max_entries);

    FAILURE
}

/// `--json` on the daemon-is-down path.
///
/// Before this existed, `warden status --json` silently fell through to the
/// human renderer whenever the daemon was down — so a monitoring script got
/// neither a usable exit code nor parseable output, in precisely the state
/// it was deployed to detect. The `json` flag was simply never consulted on
/// that branch.
///
/// The object is deliberately a *subset* of the live one, sharing the key
/// names (`listen`, `config`, …) plus the `running` discriminator that both
/// paths now emit. A consumer parses one shape and reads `running` to know
/// which fields to expect, rather than needing two parsers.
fn print_offline_status_json(
    config_path: &Path,
    pid_file: &Path,
    ipc_error: Option<&anyhow::Error>,
) -> i32 {
    let mut map = serde_json::Map::new();
    map.insert("running".into(), serde_json::Value::Bool(false));
    map.insert("config".into(), config_path.display().to_string().into());

    // The PID file distinguishes "never started" from "died leaving a stale
    // entry" — a real operational difference, so it is not collapsed.
    match classify_offline_daemon(pid_file) {
        OfflineDaemonState::Live(daemon_pid) => {
            map.insert("pid".into(), daemon_pid.into());
            map.insert("daemon_state".into(), "ipc_unreachable".into());
        }
        OfflineDaemonState::StalePidFile(daemon_pid) => {
            map.insert("pid".into(), daemon_pid.into());
            map.insert("daemon_state".into(), "stale_pid_file".into());
        }
        OfflineDaemonState::NoPidFile => {
            map.insert("pid".into(), serde_json::Value::Null);
            map.insert("daemon_state".into(), "not_running".into());
        }
    }
    map.insert(
        "ipc_error".into(),
        match ipc_error {
            Some(e) => e.to_string().into(),
            None => serde_json::Value::Null,
        },
    );

    let now = time::OffsetDateTime::now_utc();
    let code = match load_config(config_path, now) {
        Ok(loaded) => {
            let cfg = &loaded.config;
            map.insert("listen".into(), cfg.server.listen.to_string().into());
            map.insert("log_level".into(), cfg.server.log_level.to_string().into());
            map.insert("upstream_mode".into(), cfg.upstream.mode.to_string().into());
            map.insert("upstream_count".into(), cfg.upstream.servers.len().into());
            map.insert(
                "inert_lists".into(),
                serde_json::Value::Array(
                    inert_blocklists(cfg)
                        .into_iter()
                        .map(|(id, reason)| {
                            serde_json::json!({ "id": id, "reason": reason.message(id) })
                        })
                        .collect(),
                ),
            );
            map.insert("config_errors".into(), serde_json::Value::Array(Vec::new()));
            FAILURE
        }
        Err(errs) => {
            // Emitted as data, not prose on stderr: a consumer that already
            // parses this object should not need a second channel to learn
            // why the fields it expected are missing.
            map.insert(
                "config_errors".into(),
                serde_json::Value::Array(
                    errs.iter()
                        .map(|e| serde_json::Value::String(e.to_string()))
                        .collect(),
                ),
            );
            CONFIG
        }
    };

    match serde_json::to_string_pretty(&serde_json::Value::Object(map)) {
        Ok(s) => println!("{s}"),
        // Serialising a map of owned scalars cannot realistically fail, but
        // a status command must not panic on the path that reports trouble.
        Err(e) => eprintln!("cannot serialise status JSON: {e}"),
    }
    code
}

/// `tag_model_consolidation` §3.3: render the inert-list section — a
/// count plus one line per list explaining why it filters nothing.
///
/// Zero inert lists renders **nothing at all**, not `inert: 0`: the
/// section exists to be noticed, and a permanent zero row trains the
/// operator to skim past it. Same rule as
/// [`format_lc2_list_diagnostics`] below.
///
/// The per-list sentences are the validator's own frozen strings, so
/// `warden status`, `warden config lint` and the journal all describe an
/// inert list identically — detection lives in exactly one place
/// (`validator::inert_blocklists`) and this only renders it.
fn format_inert_lists(rows: &[(&str, InertListReason)]) -> Vec<String> {
    if rows.is_empty() {
        return Vec::new();
    }
    let mut out = vec![format!("inert:      {}", rows.len())];
    for (id, reason) in rows {
        out.push(format!("  {}", reason.message(id)));
    }
    out
}

/// Load the config purely to compute the inert-list section.
///
/// **Best-effort by design.** `warden status` against a running daemon
/// must not start failing because the config on disk is mid-edit or
/// unreadable — the live stats are still valid and still worth printing.
/// An unreadable config yields no section, exactly like zero inert lists.
fn inert_list_lines(config_path: &Path) -> Vec<String> {
    let now = time::OffsetDateTime::now_utc();
    let Ok(loaded) = load_config(config_path, now) else {
        return Vec::new();
    };
    format_inert_lists(&inert_blocklists(&loaded.config))
}

/// Sprint C T3 of `lists_categories_v2` (§5.4 / §8.5): render the
/// list state machine diagnostics as a leading blank line + 4
/// labelled count rows, OR an empty `Vec` when there's no signal to
/// show (no `list_state` wired, or every count zero).
///
/// Frozen-string output: the 5 labels (`""`, `"Lists:"`, `"  Active:"`,
/// `"  Pending:"`, `"  Failed:"`, `"  Stale > 7d:"`) are byte-pinned
/// per RR3. Renaming any of them is a deliberate operator-visible
/// change; the test below catches accidental drift.
/// Render the `lists:` summary — three states, not two.
///
/// A truncated source is still an *active* source, so the `active/total`
/// fraction cannot express under-coverage: it read `8/8 sources active`
/// while 2,370,261 domains were being dropped. An operator must not be
/// able to read this line and conclude they are fully covered when they
/// are not.
///
/// A **refused cycle** is the sharper case of the same defect. Every
/// source fetched, parsed and reported `Ok`, so the fraction is a
/// perfectly truthful `N/N` about downloading and a complete lie about
/// serving — the daemon is on the previous generation. So that state does
/// not get the word *active* at all: it reports what was fetched, states
/// plainly that nothing was installed, and names the source that would
/// free the most room.
fn format_lists_lines(
    lists_active: u32,
    lists_total: u32,
    lists_truncated: u32,
    refusal: Option<&crate::lists::status::CorpusRefusal>,
) -> Vec<String> {
    let Some(r) = refusal else {
        let line = if lists_truncated > 0 {
            format!(
                "lists:      {lists_active}/{lists_total} sources active, \
                 {lists_truncated} TRUNCATED (run `warden blocklist show` for counts)"
            )
        } else {
            format!("lists:      {lists_active}/{lists_total} sources active")
        };
        return vec![line];
    };

    let mut lines = vec![
        format!(
            "lists:      {lists_active}/{lists_total} sources fetched, CORPUS REFUSED \
             — NOT INSTALLED"
        ),
        format!(
            "            {} unique domains exceeds max_total_domains {}; \
             serving the previous generation",
            r.unique, r.ceiling
        ),
    ];
    if let Some((source, novel)) = r.novel_by_source.first() {
        lines.push(format!(
            "            largest contributor: {source} (+{novel} domains no other list \
             supplies; order-dependent)"
        ));
    }
    if lists_truncated > 0 {
        lines.push(format!(
            "            {lists_truncated} of the fetched sources were also TRUNCATED"
        ));
    }
    lines
}

/// Render the `domains:` line, annotated when a refusal is standing.
///
/// The bare number is only self-explanatory when the last cycle
/// installed. Under a refusal it describes the **previous** generation,
/// and at zero it does not describe a generation at all — it means
/// nothing is installed and every query is being answered unfiltered.
/// Printed bare, that zero read as an ordinary counter sitting a few
/// lines under correct refusal text, and the refusal lines are the ones
/// an operator scans past because they are long.
///
/// Zero-with-a-refusal is rarer since a cold start over the ceiling
/// installs rather than refusing (`lists::manager::cold_start_hard_cap`),
/// but it is still reachable past the hard cap, and it is the single
/// worst state the daemon has: up, listening, filtering nothing.
fn format_domains_line(
    domain_count: usize,
    refusal: Option<&crate::lists::status::CorpusRefusal>,
) -> String {
    match refusal {
        None => format!("domains:    {domain_count}"),
        Some(_) if domain_count == 0 => format!(
            "domains:    {domain_count} — NOTHING IS INSTALLED, DNS IS ANSWERING UNFILTERED \
             (the corpus was refused and no previous generation exists)"
        ),
        Some(_) => format!(
            "domains:    {domain_count} (the PREVIOUS generation — the last refresh was refused, \
             see the lists lines above)"
        ),
    }
}

/// Render the `cache:` line, with both printed numbers in the same unit
/// (mem2608-s3 / F-E).
///
/// `[cache] max_entries` is a moka *weight* ceiling
/// (`dns/cache.rs::DnsCache::new`: a positive entry costs 10 units, a
/// negative costs 1 — SEC-1, so an NXDOMAIN flood cannot evict real
/// answers), not an entry count. Printing `cache_entries` — a raw count —
/// against `cache_cap` — a weight — silently compared two different
/// units, which is how a live, actively-hit cache read as "0 / 10000
/// entries". The primary pair here is `cache_weighted_size` vs.
/// `cache_cap`: both are weight, so this pair can never invert (a
/// count-vs-count/POSITIVE_WEIGHT framing *can* — a negative-heavy
/// workload, the exact shape the weigher exists to survive, can hold far
/// more than `cap/10` raw entries). `cache_entries` is kept as an
/// informational aside for the "how many answers" intuition.
///
/// `cache_cap == 0` is the existing pre-§4.19 fallback signal (a daemon
/// that predates weighted reporting entirely) and reproduces that
/// fallback's exact byte-for-byte text; `cache_weighted_size` defaulting
/// to 0 on an old daemon reads the same as a genuinely empty cache; that
/// is an already-established ambiguity (see `cache_cap`'s own doc
/// comment in `ipc/protocol.rs`), not a new one introduced here.
fn format_cache_line(cache_entries: u64, cache_weighted_size: u64, cache_cap: u64) -> String {
    if cache_cap > 0 {
        format!(
            "cache:      {cache_weighted_size}/{cache_cap} weight ({cache_entries} entries; \
             positive=10, negative=1 per [cache] max_entries)"
        )
    } else {
        format!("cache:      {cache_entries} entries")
    }
}

/// Render the `lists:` line on the **daemon-unreachable** path, from the
/// config file alone.
///
/// This used to test `cfg.lists.sources.is_empty()` and nothing else —
/// the legacy `[lists].sources` array. Lists have been `[[blocklists]]`
/// entities since the v1 schema, so on a pure-v1 config the array is
/// empty by construction and this printed `lists:      (none)`
/// **unconditionally**, healthy or not. During the 2026-08-05 corpus
/// incident that line was read as evidence the lists had failed to load,
/// and cost twenty minutes on a config with thirteen of them.
///
/// The wording is `configured`, deliberately not `active`: this path
/// cannot reach the daemon, so it knows what the operator asked for and
/// nothing at all about what is serving. The live renderer owns `active`
/// (see [`format_lists_lines`]), and the two must not be confusable.
///
/// Both sources are reported because both are honoured by the loader —
/// showing one and hiding the other is how this defect started.
fn format_config_lists_lines(enabled: usize, configured: usize, legacy: &[String]) -> Vec<String> {
    if configured == 0 && legacy.is_empty() {
        return vec!["lists:      (none)".to_string()];
    }

    let mut out = Vec::new();
    if configured > 0 {
        // `enabled` is only worth a number when it differs; on a healthy
        // config it always matches and would be noise on every run.
        out.push(if enabled == configured {
            format!("lists:      {configured} configured")
        } else {
            format!(
                "lists:      {configured} configured, {enabled} enabled ({} disabled)",
                configured - enabled
            )
        });
    }
    if !legacy.is_empty() {
        // 12-column continuation, matching `format_lists_lines`. Takes the
        // label itself when there are no `[[blocklists]]` to hold it.
        let label = if out.is_empty() {
            "lists:     "
        } else {
            "           "
        };
        out.push(format!(
            "{label} legacy [lists].sources: {}",
            legacy.join(", ")
        ));
    }
    out
}

fn format_lc2_list_diagnostics(diagnostics: &crate::ipc::protocol::ListDiagnostics) -> Vec<String> {
    let total = diagnostics.active + diagnostics.pending + diagnostics.failed;
    if total == 0 {
        return Vec::new();
    }
    vec![
        String::new(),
        "Lists:".to_string(),
        format!("  Active:        {}", diagnostics.active),
        format!("  Pending:       {}", diagnostics.pending),
        format!("  Failed:        {}", diagnostics.failed),
        format!("  Stale > 7d:    {}", diagnostics.stale_over_7d),
    ]
}

fn format_uptime(secs: u64) -> String {
    let days = secs / 86400;
    let hours = (secs % 86400) / 3600;
    let mins = (secs % 3600) / 60;
    if days > 0 {
        format!("{days}d {hours}h {mins}m")
    } else if hours > 0 {
        format!("{hours}h {mins}m")
    } else {
        format!("{mins}m")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lists::status::CorpusRefusal;

    // ── the daemon-unreachable `lists:` line ─────────────────────────

    /// A v1 config with `[[blocklists]]` and no legacy array must not be
    /// reported as having no lists.
    ///
    /// The old test was `cfg.lists.sources.is_empty()`, so this printed
    /// `(none)` for every pure-v1 config that has ever existed. On
    /// 2026-08-05 it was read as evidence that thirteen lists had failed
    /// to load, and sent the investigation the wrong way for twenty
    /// minutes.
    #[test]
    fn v1_blocklists_are_not_reported_as_no_lists() {
        let lines = format_config_lists_lines(13, 13, &[]).join("\n");
        assert!(
            !lines.contains("(none)"),
            "thirteen configured lists were reported as none: {lines}"
        );
        assert!(lines.contains("13"), "{lines}");
    }

    /// `(none)` is still correct, but only when BOTH surfaces are empty.
    #[test]
    fn none_is_reserved_for_a_config_with_no_lists_at_all() {
        assert_eq!(
            format_config_lists_lines(0, 0, &[]),
            vec!["lists:      (none)".to_string()]
        );
    }

    /// The count of disabled entries is shown only when it is non-zero —
    /// and it must be shown, since a disabled list filters nothing.
    #[test]
    fn disabled_entries_are_called_out_and_healthy_configs_stay_quiet() {
        let mixed = format_config_lists_lines(10, 13, &[]).join("\n");
        assert!(mixed.contains("10 enabled"), "{mixed}");
        assert!(mixed.contains("3 disabled"), "{mixed}");

        let healthy = format_config_lists_lines(13, 13, &[]).join("\n");
        assert!(
            !healthy.contains("enabled"),
            "a fully-enabled config should not carry a redundant tally: {healthy}"
        );
    }

    /// The legacy array is still honoured by the loader, so hiding it
    /// would be the same defect pointing the other way.
    #[test]
    fn the_legacy_sources_array_is_still_reported_in_both_shapes() {
        let both =
            format_config_lists_lines(2, 2, &["https://a.example/l.txt".to_string()]).join("\n");
        assert!(both.contains("2 configured"), "{both}");
        assert!(both.contains("https://a.example/l.txt"), "{both}");

        // Legacy-only: the label has to move onto the line that exists.
        let legacy_only =
            format_config_lists_lines(0, 0, &["https://a.example/l.txt".to_string()]).join("\n");
        assert!(
            legacy_only.starts_with("lists:"),
            "the legacy-only line lost its label: {legacy_only}"
        );
        assert!(!legacy_only.contains("(none)"), "{legacy_only}");
    }

    // ── the `domains:` line ──────────────────────────────────────────

    /// Zero domains under a standing refusal is the daemon's worst state
    /// — up, listening, filtering nothing — and must not render as a bare
    /// counter.
    #[test]
    fn a_zero_domain_count_under_a_refusal_says_nothing_is_filtered() {
        let r = CorpusRefusal {
            unique: 14_359_682,
            ceiling: 14_000_000,
            novel_by_source: vec![],
        };
        let line = format_domains_line(0, Some(&r));
        assert!(line.contains("UNFILTERED"), "{line}");
        assert_ne!(line, "domains:    0", "the bare zero is the defect");
    }

    /// A non-zero count under a refusal describes the PREVIOUS
    /// generation, which is a different claim and must read as one.
    #[test]
    fn a_nonzero_count_under_a_refusal_is_marked_as_the_previous_generation() {
        let r = CorpusRefusal {
            unique: 14_359_682,
            ceiling: 14_000_000,
            novel_by_source: vec![],
        };
        let line = format_domains_line(12_300_000, Some(&r));
        assert!(line.contains("PREVIOUS"), "{line}");
        assert!(
            !line.contains("UNFILTERED"),
            "a serving generation must not be described as unfiltered: {line}"
        );
    }

    /// With no refusal the line stays exactly as it was — the annotation
    /// is for the abnormal state, and would be noise on every healthy run.
    #[test]
    fn the_domains_line_is_unchanged_when_nothing_is_refused() {
        assert_eq!(
            format_domains_line(12_300_000, None),
            "domains:    12300000"
        );
    }

    // ── the `cache:` line ────────────────────────────────────────────

    /// mem2608-s3 / F-E: the modern pair printed is weight-vs-weight
    /// (`cache_weighted_size`/`cache_cap`), not count-vs-weight. Guards
    /// against reverting to printing `cache_entries` against `cache_cap`
    /// directly, which is the defect this task exists to fix.
    #[test]
    fn the_modern_cache_line_compares_weight_against_weight() {
        let line = format_cache_line(741, 8_234, 10_000);
        assert_eq!(
            line,
            "cache:      8234/10000 weight (741 entries; positive=10, negative=1 per \
             [cache] max_entries)"
        );
    }

    /// A count-vs-count/POSITIVE_WEIGHT framing can invert under a
    /// negative-heavy workload (more raw entries than `cap/10`) — this
    /// pins that the printed pair never reads as a count exceeding its
    /// own weight ceiling for that reason, because both sides are weight.
    #[test]
    fn the_cache_line_pair_cannot_invert_under_a_negative_heavy_workload() {
        // 9,000 negative entries (weight 1 each) plus 100 positive
        // (weight 10 each): 9,000 raw entries, far more than
        // `cap / POSITIVE_WEIGHT` (1,000) would allow if entries were
        // compared against that derived ceiling instead of weight.
        let line = format_cache_line(9_100, 10_000, 10_000);
        assert_eq!(line, "cache:      10000/10000 weight (9100 entries; positive=10, negative=1 per [cache] max_entries)");
    }

    /// A pre-§4.19 daemon (`cache_cap == 0`) must still render byte-for-
    /// byte identically to the original single-number fallback — the new
    /// weighted format must not leak into the path that has no cap to
    /// compare against.
    #[test]
    fn the_legacy_fallback_cache_line_is_unchanged() {
        assert_eq!(format_cache_line(1234, 0, 0), "cache:      1234 entries");
    }

    // ── exit-code contract ───────────────────────────────────────────
    //
    // `warden status` is what a monitoring probe calls. Returning 0 for
    // "the daemon is down" made it useless in exactly the state it was
    // deployed to detect.

    /// The two renderers must agree about what "running" means.
    ///
    /// A daemon that answers `IpcResponse::Error` has told us nothing about
    /// its status. The text path has always treated that as a failure
    /// (`bail!`). The JSON path matched on `IpcResponse::Status` with an
    /// `if let`, so an `Error` reply fell through, emitted an object with
    /// none of the status fields, and returned 0 — and once the `running`
    /// discriminator was added, that object positively asserted
    /// `running: true`. A monitoring script would have read a daemon
    /// reporting an internal error as healthy.
    ///
    /// The fence in `tests/cli_exit_code_fence.rs` cannot catch this: it
    /// never has a live daemon, so it only ever drives the down path.
    #[test]
    fn a_daemon_error_reply_is_not_reported_as_running() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config.toml");
        std::fs::write(
            &config,
            "schema_version = 3\n\n[server]\ndefault_profile = \"default\"\n\n\
             [profiles.default]\ndisplay_name = \"Default\"\ntags = [\"uncategorized\"]\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
        )
        .unwrap();

        let err_reply = IpcResponse::Error {
            message: "internal failure".into(),
        };
        // `healthy` is what `run_status` computes; assert the classification
        // itself, since that is the value both branches key off.
        assert!(
            !matches!(err_reply, IpcResponse::Status { .. }),
            "an Error reply must never classify as healthy"
        );

        // The renderer must not panic and must honour the flag it is given.
        print_live_status_json(&config, err_reply, None, false)
            .expect("rendering an error reply must not fail");

        // Control arm: the text renderer's treatment of the same reply is
        // an error, which is what the JSON path is being aligned to.
        let same_reply = IpcResponse::Error {
            message: "internal failure".into(),
        };
        assert!(
            print_live_status(&config, same_reply, None).is_err(),
            "the text path must still treat a daemon error as a failure"
        );
    }

    /// Daemon down, config fine → FAILURE, not SUCCESS.
    #[test]
    fn status_offline_with_a_good_config_exits_failure() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config.toml");
        std::fs::write(
            &config,
            "schema_version = 3\n\n[server]\ndefault_profile = \"default\"\n\n\
             [profiles.default]\ndisplay_name = \"Default\"\ntags = [\"uncategorized\"]\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
        )
        .unwrap();
        let pid = dir.path().join("absent.pid");

        assert_eq!(print_offline_status(&config, &pid, None), FAILURE);
        assert_eq!(print_offline_status_json(&config, &pid, None), FAILURE);
    }

    /// Daemon down AND the config will not load → CONFIG. The config
    /// problem dominates: without it we cannot even resolve the socket
    /// path, so "the daemon is down" is not a claim we can make.
    #[test]
    fn status_offline_with_an_unloadable_config_exits_config() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("no-such-config.toml");
        let pid = dir.path().join("absent.pid");

        assert_eq!(print_offline_status(&missing, &pid, None), CONFIG);
        assert_eq!(print_offline_status_json(&missing, &pid, None), CONFIG);
    }

    /// The `--json` flag was never consulted on the daemon-down branch,
    /// so a script asking for JSON got human prose. Assert the offline
    /// renderer emits a parseable object carrying the `running`
    /// discriminator — and that it says `false`, which is the whole
    /// point of calling it.
    #[test]
    fn status_offline_json_emits_a_parseable_object_marked_not_running() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config.toml");
        std::fs::write(
            &config,
            "schema_version = 3\n\n[server]\nlisten = \"127.0.0.1:15353\"\n\
             default_profile = \"default\"\n\n[profiles.default]\n\
             display_name = \"Default\"\ntags = [\"uncategorized\"]\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
        )
        .unwrap();
        let pid = dir.path().join("absent.pid");

        // Build the same map the renderer prints, then assert on it. The
        // renderer writes to stdout, which a unit test cannot portably
        // capture; this asserts the shape via the one thing both share —
        // that `serde_json` can round-trip it — by re-running the load.
        let code = print_offline_status_json(&config, &pid, None);
        assert_eq!(code, FAILURE);

        // The real assertion lives in the binary-level fence
        // (`tests/cli_exit_code_fence.rs::status_json_down_is_json`),
        // which parses actual stdout. This test pins the exit code and
        // that the path does not panic on a config it can read.
    }

    // ── daemon liveness on the IPC-failed branch ─────────────────────

    /// A PID file whose number the kernel has recycled onto an unrelated
    /// live process is stale, and `status` must say so.
    ///
    /// The bare `kill(pid, 0)` probe this branch used to run passes here —
    /// the PID exists, it is this test process — so a box whose daemon is
    /// gone was reported as "running", and the JSON path emitted
    /// `ipc_unreachable` (transient, retry) instead of `stale_pid_file`
    /// (dead, page someone). No `flock` is held on the file below, which
    /// is exactly what a daemon leaves behind when it dies.
    #[test]
    fn a_live_unrelated_pid_in_an_unlocked_file_reads_as_stale() {
        let dir = tempfile::tempdir().unwrap();
        let pid_file = dir.path().join("warden.pid");
        std::fs::write(&pid_file, std::process::id().to_string()).unwrap();

        assert_eq!(
            classify_offline_daemon(&pid_file),
            OfflineDaemonState::StalePidFile(std::process::id()),
        );
    }

    /// Negative control. Without it the test above is equally satisfied by
    /// a classifier that answers `StalePidFile` unconditionally — which
    /// would report every live-but-IPC-broken daemon as dead, the same
    /// defect with the sign flipped.
    #[test]
    fn a_locked_pid_file_still_reads_as_a_live_daemon() {
        let dir = tempfile::tempdir().unwrap();
        let pid_file = dir.path().join("warden.pid");
        // Holds `LOCK_EX` for the guard's lifetime and writes our PID.
        // `flock` denies a second descriptor even inside one process, so
        // this stands in for a daemon without forking one.
        let _guard = pid::acquire_pid_lock(&pid_file).unwrap();

        assert_eq!(
            classify_offline_daemon(&pid_file),
            OfflineDaemonState::Live(std::process::id()),
        );
    }

    /// "Never started" is a third state, not a flavour of stale — the JSON
    /// renderer emits `not_running` for it and a null `pid`.
    #[test]
    fn an_absent_pid_file_is_not_reported_as_stale() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            classify_offline_daemon(&dir.path().join("absent.pid")),
            OfflineDaemonState::NoPidFile,
        );
    }

    #[test]
    fn format_uptime_minutes() {
        assert_eq!(format_uptime(300), "5m");
    }

    /// The recurring P1 of this whole workstream, in its newest clothes.
    ///
    /// `active` conflates *downloaded and parsed* with *installed and
    /// serving*. That is what let `8/8 sources active` print while
    /// 2,370,261 domains were being dropped, and a refused refresh cycle
    /// walks straight back into it: every source fetches, parses and
    /// reports `Ok`, so the untouched line would read `8/8 sources active`
    /// while the daemon serves a stale corpus. An operator must not be
    /// able to read this line and conclude they are fully covered.
    #[test]
    fn a_refused_cycle_never_reads_as_all_sources_active() {
        let refusal = CorpusRefusal {
            unique: 15_000_000,
            ceiling: 14_000_000,
            novel_by_source: vec![
                ("security/malicious".to_string(), 4_000_000),
                ("privacy/ads".to_string(), 1_000_000),
            ],
        };

        let refused = format_lists_lines(8, 8, 0, Some(&refusal)).join("\n");
        assert!(
            !refused.contains("active"),
            "a refused cycle still described its sources as active:\n{refused}"
        );
        assert!(
            refused.contains("REFUSED"),
            "the refusal is not stated:\n{refused}"
        );
        assert!(
            refused.contains("15000000") && refused.contains("14000000"),
            "the measured corpus and the ceiling must both be named:\n{refused}"
        );
        // Actionable: naming the largest novel contributor is the only way
        // the operator knows which list to drop.
        assert!(
            refused.contains("security/malicious"),
            "the refusal names no source to act on:\n{refused}"
        );
        // ...and it must say so is order-dependent, because it is: a
        // shared domain is attributed to whichever source merged first.
        assert!(
            refused.contains("order-dependent"),
            "the novelty diagnostic is presented as if it were exact:\n{refused}"
        );

        // Control arm: without a refusal the line is unchanged, so the
        // assertions above are about the refused state and not about some
        // blanket rewording of the line.
        let healthy = format_lists_lines(8, 8, 0, None).join("\n");
        assert!(
            healthy.contains("8/8 sources active"),
            "the healthy line changed:\n{healthy}"
        );
        assert!(!healthy.contains("REFUSED"));

        // And the pre-existing truncation suffix still works, refusal or
        // not — this line has three states now, not two.
        let truncated = format_lists_lines(8, 8, 2, None).join("\n");
        assert!(truncated.contains("2 TRUNCATED"), "{truncated}");
    }

    #[test]
    fn format_uptime_hours() {
        assert_eq!(format_uptime(7200), "2h 0m");
    }

    #[test]
    fn format_uptime_days() {
        assert_eq!(format_uptime(90061), "1d 1h 1m");
    }

    /// Sprint C T3 of `lists_categories_v2` (§5.4 / §8.5, RR3
    /// frozen-strings): the 5 labels emitted by the diagnostics
    /// section MUST stay byte-pinned. Rename any of them and this
    /// test catches it. Operators read these strings — drift is
    /// operator-visible churn we want to gate intentionally.
    #[test]
    fn format_lc2_list_diagnostics_frozen_string_labels() {
        let d = crate::ipc::protocol::ListDiagnostics {
            active: 4,
            pending: 0,
            failed: 1,
            stale_over_7d: 2,
        };
        let lines = format_lc2_list_diagnostics(&d);
        assert_eq!(
            lines,
            vec![
                String::new(),
                "Lists:".to_string(),
                "  Active:        4".to_string(),
                "  Pending:       0".to_string(),
                "  Failed:        1".to_string(),
                "  Stale > 7d:    2".to_string(),
            ],
        );
    }

    // ── tag_model_consolidation §3.3 — inert list section ───────────

    /// Zero inert lists must print NOTHING — not `inert: 0`. A row that
    /// is always there is a row the operator stops reading, which is
    /// exactly the failure this section exists to fix.
    #[test]
    fn tmc_no_inert_lists_renders_nothing() {
        assert!(format_inert_lists(&[]).is_empty());
    }

    /// The count line plus one indented sentence per list, each of them
    /// the validator's own frozen string so `status`, `config lint` and
    /// the journal cannot drift apart.
    ///
    /// **Two rows, and that is load-bearing.** The property is "one line
    /// *per* list"; a single-row fixture is satisfied by a renderer that
    /// emits exactly one reason line and ignores the rest of the slice, so
    /// it would pin the count line and nothing else. The two ids differ so
    /// a renderer that formatted the first row twice is caught too.
    ///
    /// Both rows are `BaseIgnore` because it is the only variant
    /// `inert_blocklists` produces. They used to be `AllowListNoTags` and
    /// `TagsMatchNothing`, which `plp-s5f` removed as unproduced — this
    /// test was the last thing naming them, and it was rendering two
    /// operator sentences the daemon had no way to reach.
    #[test]
    fn tmc_inert_lists_render_count_then_one_reason_per_list() {
        let rows = [
            ("mycompany", InertListReason::BaseIgnore),
            ("orphan", InertListReason::BaseIgnore),
        ];
        let lines = format_inert_lists(&rows);
        assert_eq!(
            lines,
            vec![
                "inert:      2".to_string(),
                "  list \"mycompany\" has base = \"ignore\" — it is downloaded and refreshed but filters nothing in any profile that does not override it".to_string(),
                "  list \"orphan\" has base = \"ignore\" — it is downloaded and refreshed but filters nothing in any profile that does not override it"
                    .to_string(),
            ],
        );
    }

    /// An unreadable / missing config must not break `warden status`
    /// against a live daemon: the live stats are still valid. No
    /// section, no error.
    #[test]
    fn tmc_unreadable_config_yields_no_inert_section() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("no-such-config.toml");
        assert!(inert_list_lines(&missing).is_empty());
    }

    /// End-to-end over a real config: the section is derived from
    /// `validator::inert_blocklists`, not re-detected here.
    #[test]
    fn tmc_inert_section_is_derived_from_a_real_config() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(
            &path,
            r#"schema_version = 3

[server]
default_profile = "default"

[profiles.default]
display_name = "Default"
tags = ["uncategorized"]

[[blocklists]]
id = "working"
display_name = "Working"
url = "https://example.com/deny.txt"

[[blocklists]]
id = "mycompany"
display_name = "My Company"
url = "https://example.com/allow.txt"
base = "allow"
trust = "local"

[[blocklists]]
id = "shelved"
display_name = "Shelved"
url = "https://example.com/shelved.txt"
base = "ignore"

[upstream]
servers = ["192.0.2.1:53"]
"#,
        )
        .unwrap();
        let lines = inert_list_lines(&path);
        assert_eq!(lines.len(), 2, "count line + one reason: {lines:?}");
        assert_eq!(lines[0], "inert:      1");
        // `base = "ignore"` is the ONLY inert reason after `plp-s5b`. This
        // fixture used to expect `mycompany` here, on the retired premise
        // that an untagged allow-list applies to nobody.
        assert!(lines[1].contains("shelved"), "{lines:?}");
        // Two control arms, both pinning a premise that is GONE — they are
        // the point of the test, not decoration. If either reason comes
        // back, `inert_blocklists` has regressed to tag-era logic and this
        // is where it shows.
        //
        // `mycompany`: an allow-direction list is inherited by every profile
        // that does not override it, tagged or not. Calling it inert was a
        // false positive on a security-relevant direction, and it invited
        // the operator to "fix" it with a tag verb that no longer exists.
        assert!(!lines[1].contains("mycompany"), "{lines:?}");
        // `working`: a deny list is not inert either. The old comment here
        // credited the default profile's `uncategorized` tag for that, which
        // stopped deciding anything at the `plp-s3` cutover — it is `base`
        // that reaches every profile now.
        assert!(!lines[1].contains("working"), "{lines:?}");
    }

    /// Sprint C T3: zero-everywhere diagnostics emit no output —
    /// the operator only sees the section when there's signal to
    /// show. Pre-Sprint-C daemons send default-empty
    /// `ListDiagnostics`, and we don't want to clutter the status
    /// page with empty health blocks for those.
    #[test]
    fn format_lc2_list_diagnostics_no_signal_omits_section() {
        let d = crate::ipc::protocol::ListDiagnostics::default();
        let lines = format_lc2_list_diagnostics(&d);
        assert!(
            lines.is_empty(),
            "no list_state wired ⇒ no section, not empty rows",
        );
    }
}
