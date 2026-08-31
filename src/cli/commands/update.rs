//! `warden lists refresh` — trigger list re-download. Sends SIGHUP to a
//! running daemon, or performs a foreground download if none is up.
//!
//! The module keeps the `update` name (and `run_update` its symbol)
//! because the CLI rename to `lists refresh` was a label change only;
//! `tests/cli_update_pure_v1.rs` imports this path.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use crate::cli::exit_codes::{CONFIG, SUCCESS};
use crate::config::loader;
use crate::filter::FilterEngine;
use crate::lists::catalog::Catalog;
use crate::lists::manager::{merge_sources_with_blocklists, ListManager};
use crate::lists::source_key::{SourceBitMap, SourceTokenMap};

use crate::lists::status::{CycleMark, CycleOutcome};

use super::lists_knobs::{fetch_live_corpus, format_corpus_lines, LiveCorpus};
use super::pid;
use super::start::{list_stats_path, lists_cache_dir, ListStateWriteback, ManagerWiring};

/// How long to wait for the signalled reload to finish before giving up and
/// saying so.
///
/// Sized against the work, not against a round number: a full rebuild of a
/// ~13M-domain corpus is tens of seconds on the boxes this runs on. Too
/// short and the command reports "could not confirm" on healthy hosts,
/// which trains the operator to ignore the line; too long and a wedged
/// daemon holds the terminal. The timeout is not a verdict either way — it
/// is reported as the non-answer it is.
const RELOAD_WAIT: Duration = Duration::from_secs(90);

/// Gap between polls while waiting. Each one is a full IPC round-trip
/// against a daemon that is busy merging, so this is deliberately not
/// aggressive.
const RELOAD_POLL_EVERY: Duration = Duration::from_secs(2);

/// Whether the cycle that just ended can be attributed to this command.
///
/// A monotonic counter proves a cycle ENDED. It cannot, on its own, prove
/// the cycle was the one this command asked for — SIGHUP carries no payload,
/// so there is no request id to correlate on. The DISTANCE between the two
/// readings is what remains, and it is enough to rule out the wrong claims.
///
/// Pulled out of [`report_reload_outcome`] purely so it can be tested: the
/// caller is `async`, polls a real socket, and cannot be driven through
/// these cases without a daemon. The rule is arithmetic and belongs where
/// arithmetic can be checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Attribution {
    /// Exactly one cycle closed after the signal. Ours.
    Ours,
    /// More than one closed. The daemon runs periodic refreshes and serves
    /// other clients, so the reported outcome may belong to one of those.
    /// Reported as the latest, and said to be possibly not ours — the naive
    /// "the counter moved, therefore this is my result" would present a
    /// concurrent cycle's verdict as this command's own.
    Ambiguous { cycles: u64 },
    /// The counter went BACKWARDS, which it never does inside one process:
    /// it is per-daemon and starts at zero. The daemon restarted, so what
    /// ran was the boot rebuild.
    Restarted,
}

impl Attribution {
    fn of(before: u64, after: u64) -> Self {
        if after < before {
            Self::Restarted
        } else if after > before + 1 {
            Self::Ambiguous {
                cycles: after - before,
            }
        } else {
            Self::Ours
        }
    }
}

/// Report what the reload the caller just triggered actually DID.
///
/// The defect this exists to fix: `lists refresh` sent SIGHUP, printed
/// "lists will reload" and exited 0 — including when the corpus was about
/// to be refused. On a live daemon the ceiling is a hard wall, so a refused
/// cycle does not serve zero, it FREEZES: the previous generation keeps
/// filtering and never advances, and every domain published from then on
/// goes unblocked. Filtering that is stale rather than absent is the harder
/// state to notice, and the command that caused it said nothing.
///
/// **Never gates on the absence of a refusal.** `corpus_refusal()` is an
/// `Option` over four states — installed, refused, still running, skipped —
/// and three of them read `None`, so "no refusal appeared" is not evidence
/// that anything installed. The verdict comes from the cycle counter
/// advancing and from the outcome that counter carries.
///
/// Best-effort and never fatal: this reports on a refresh that has already
/// been triggered successfully. An IPC hiccup here must not turn a
/// delivered SIGHUP into a failed command, so every arm prints and returns.
async fn report_reload_outcome(socket_path: &Path, config_path: &Path, before: Option<CycleMark>) {
    // `None` means the daemon cannot answer at all — too old to carry the
    // field, or no list subsystem wired. Waiting would burn the whole
    // timeout on every refresh for a counter that is never going to move.
    let Some(before) = before else {
        return;
    };

    // `tokio::time::Instant`, NOT `std::time::Instant`, and the two must not
    // be mixed. The sleep below is on tokio's clock; a deadline on the std
    // clock is invisible to it, so under a paused clock (any `start_paused`
    // test) the sleeps would return instantly while the deadline sat still —
    // spinning the connect loop for a real 90 seconds. Under a normal clock
    // the mix happens to work, which is what makes it a trap: it is correct
    // in production and wrong in the only place that can prove it.
    let deadline = tokio::time::Instant::now() + RELOAD_WAIT;
    let mut live = None;
    while tokio::time::Instant::now() < deadline {
        tokio::time::sleep(RELOAD_POLL_EVERY).await;
        let Ok(now) = fetch_live_corpus(socket_path).await else {
            // The daemon may be mid-reload and briefly unresponsive; that
            // is not an answer, so keep waiting rather than concluding.
            continue;
        };
        if now.cycle.is_some_and(|c| c.seq != before.seq) {
            live = Some(now);
            break;
        }
    }

    let Some(live) = live else {
        println!();
        println!("could not confirm the reload finished within {RELOAD_WAIT:?}.");
        println!("The refresh was triggered — this says nothing about whether it");
        println!("succeeded. Check with: warden status");
        return;
    };

    // ATTRIBUTION, before the outcome. A counter says a cycle ENDED; it
    // cannot by itself say the cycle was ours. SIGHUP carries no payload, so
    // there is no request id to correlate on — but the DISTANCE between the
    // two readings still rules out the wrong readings:
    //
    //   +1        exactly one cycle closed after our signal. Ours.
    //   > +1      several closed. The daemon has periodic refreshes and other
    //             clients; one of them may be the one being reported. Say so
    //             rather than claim a causal link the counter cannot support.
    //   < before  the counter went BACKWARDS, which it never does within one
    //             process. The daemon restarted, and whatever ran is the boot
    //             rebuild, not our refresh.
    //
    // Written as an explicit reading of the gap because the naive form —
    // "seq changed, therefore this is my result" — reports a concurrent
    // cycle's verdict as this command's own, which is the same lie in a new
    // place. Found by an external audit of this file, not by its own tests.
    let after_seq = live.cycle.map_or(0, |c| c.seq);
    match Attribution::of(before.seq, after_seq) {
        Attribution::Restarted => {
            println!();
            println!("the daemon restarted while the reload was in flight, so this");
            println!("refresh has no result of its own — the corpus was rebuilt at");
            println!("boot instead. Check with: warden status");
            return;
        }
        Attribution::Ambiguous { cycles } => {
            println!();
            println!("note: {cycles} reload cycles completed while waiting, so what follows");
            println!("is the LATEST one and may not be the result of this command.");
        }
        Attribution::Ours => {}
    }

    match live.cycle.and_then(|c| c.outcome) {
        Some(CycleOutcome::SkippedUnchanged) => {
            println!();
            println!("nothing to do — the list files on disk are unchanged, so the");
            println!("live blocklist was reused without rebuilding.");
        }
        Some(CycleOutcome::Refused) => {
            println!();
            println!("REFUSED — the merged corpus exceeds max_total_domains.");
            println!();
            println!("The previous generation is still filtering, and it will keep");
            println!("filtering the SAME domains until this is resolved: nothing new");
            println!("from any list will be blocked. Raise the ceiling with");
            println!("`warden lists set max_total_domains <n>` or drop a list.");
            print_corpus(config_path, &live);
        }
        Some(CycleOutcome::Installed) => {
            println!();
            println!("installed.");
            print_corpus(config_path, &live);
        }
        Some(CycleOutcome::ClearedNoSources) => {
            println!();
            println!("the config has NO list sources, so the blocklist was CLEARED.");
            println!("This host is now filtering nothing. Add a list with");
            println!("`warden lists add <id>` if that was not intended.");
        }
        Some(CycleOutcome::ConfigRejected) => {
            println!();
            println!("the daemon REFUSED the new config, so nothing was reloaded and");
            println!("the previous config is still in force. The validator errors are");
            println!("in the journal: journalctl -u purge-warden");
        }
        // `seq` moved forward but carries no outcome. The two are written
        // together and `seq: 0` is the only markless state, so this is
        // unreachable short of a protocol change.
        None => {
            println!();
            println!("the reload finished, but the daemon did not report what it did.");
            println!("Check with: warden status");
        }
    }
}

/// Render the corpus block, reusing `lists show`'s renderer rather than
/// growing a second one that can disagree with it.
///
/// The reuse pays for itself beyond consistency: the config is re-read here,
/// so the ceiling printed could differ from the one the daemon actually
/// enforced if an edit landed between the SIGHUP and this report.
/// [`format_corpus_lines`] already carries the note for exactly that skew —
/// it compares the refusal's own `ceiling` against the one passed in and
/// says which is which — so a second renderer would have to grow the same
/// warning or silently print the newer number as if it were in force.
fn print_corpus(config_path: &Path, live: &LiveCorpus) {
    let now = time::OffsetDateTime::now_utc();
    let Ok(loaded) = loader::load_config(config_path, now) else {
        return;
    };
    println!();
    for line in format_corpus_lines(loaded.config.lists.max_total_domains as u64, Ok(live)) {
        println!("{line}");
    }
}

/// Trigger a list update. If a daemon is running, sends SIGHUP.
/// Otherwise, performs a foreground download to verify the config.
///
/// Returns the intended process exit code; `main.rs` translates it via
/// [`crate::cli::exit_codes::exit_with`].
///
/// # Exit codes
///
/// - [`SUCCESS`] — SIGHUP delivered, or the foreground refresh completed
///   (including the legitimate "nothing configured to fetch" case).
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
/// daemon and the rest of the post-§4.24 CLI surface use). Pre-§4.24
/// follow-up this path was on the legacy `Settings::from_file` which
/// did not carry `[[blocklists]]` structurally — with `[lists].sources
/// = []` (post-S53 steady state) and `[[blocklists]]` populated it
/// silently exited with `"no list sources configured"`. The migration
/// closes that gap on the foreground path; the SIGHUP path on a live
/// daemon was already correct via §4.24.
///
/// **Cache directory.** Reuses [`lists_cache_dir`] from `start.rs` so
/// the foreground tool writes into the same FHS-aware path as the
/// daemon (`/var/lib/<pkg>/lists/` on prod, `<config-parent>/<cache_dir>`
/// on dev). Pre-fix this path had its own ad-hoc resolution that wrote
/// to `<config-parent>/<cache_dir>` regardless — silently inconsistent
/// with the daemon on FHS installs.
pub async fn run_update(
    config_path: &Path,
    pid_file: &Path,
    socket_path: &Path,
) -> anyhow::Result<i32> {
    // If daemon is running, just signal it.
    //
    // The gate is `daemon_is_live`, not `is_process_alive`: a stale PID file
    // whose number the kernel recycled onto an unrelated process passes the
    // liveness check, and this path does not merely *report* on that PID —
    // it signals it. SIGHUP's default disposition is terminate, so the old
    // gate could kill an unrelated process and then print "lists will
    // reload" as if a daemon had been refreshed.
    if let Ok(daemon_pid) = pid::read_pid_file(pid_file) {
        if pid::daemon_is_live(pid_file, daemon_pid) {
            // Read the cycle counter BEFORE signalling. Everything the
            // report below says depends on being able to tell THIS
            // refresh's cycle from whatever ran last.
            let before = fetch_live_corpus(socket_path)
                .await
                .ok()
                .and_then(|c| c.cycle);

            pid::send_signal(daemon_pid, "HUP")?;
            println!(
                "sent SIGHUP to purge-warden (PID {}) — lists will reload",
                daemon_pid
            );

            report_reload_outcome(socket_path, config_path, before).await;
            return Ok(SUCCESS);
        }
    }

    // No daemon running — do a foreground download
    println!("no running daemon found, performing foreground list download...");
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

    let (merged_sources, source_trust) =
        merge_sources_with_blocklists(&loaded.config.lists.sources, &loaded.config.blocklists);
    if merged_sources.is_empty() {
        // Not a failure: an operator with no lists configured asked for a
        // refresh and got the correct answer — there is nothing to fetch.
        println!("no list sources or blocklists configured");
        return Ok(SUCCESS);
    }

    let (_filter, count) =
        refresh_foreground_filter(config_path, &loaded.config, merged_sources, source_trust)
            .await?;
    println!("downloaded and merged: {} unique domains", count);

    Ok(SUCCESS)
}

/// Build a [`ListManager`] exactly the way the daemon's boot and reload
/// paths do (`cli::commands::start`) and run one refresh cycle.
///
/// Split out of [`run_update`]'s foreground branch so a test can inspect
/// the [`FilterEngine`] this produces. `run_update` itself only surfaces an
/// exit code, a domain count, and the on-disk list cache — none of which can
/// distinguish a domain that landed in `allow_mask` from one that landed in
/// `block_mask`, so none of them would have caught the bug this function's
/// `set_allow_bits` call fixes (neutrality-06 follow-up: this command built
/// its manager without ever telling it which sources were allow-direction,
/// so every list — `base = allow` included — was stamped
/// `DomainMasks::block_only`).
///
/// Returns the engine (the caller is free to drop it immediately — nothing
/// outside this one-shot process reads it again) and the merged domain
/// count.
async fn refresh_foreground_filter(
    config_path: &Path,
    config: &crate::config::schema::ConfigV1,
    merged_sources: Vec<String>,
    source_trust: crate::lists::source_key::SourceTrustMap,
) -> anyhow::Result<(Arc<FilterEngine>, usize)> {
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

    let catalog = match Catalog::fetch(&client).await {
        Ok(c) => {
            println!("catalog fetched ({} lists available)", c.entries().len());
            c
        }
        Err(e) => {
            println!("catalog fetch failed ({}), using fallback", e);
            Catalog::fallback()
        }
    };

    let filter = Arc::new(FilterEngine::new());
    let interval = Duration::from_secs(config.lists.update_interval_secs);
    let source_bits = SourceBitMap::build(&merged_sources, &config.blocklists)
        .map_err(|e| anyhow::anyhow!("lists.sources: {e}"))?;

    // `plp-s3`: the operator's per-profile list policy, projected onto this
    // bit assignment. Computed here, before `source_bits` moves into the
    // manager below, mirroring `start.rs`'s boot and reload paths.
    let policy_masks = source_bits.project_policy(&config.blocklists, &config.profiles);

    let lists_dir = lists_cache_dir(config_path, config);
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
    let source_tokens = SourceTokenMap::build(config, &secrets);

    let mut mgr = ListManager::with_tokens(
        client,
        filter.clone(),
        merged_sources,
        catalog,
        interval,
        source_bits,
        source_tokens,
        config.lists.max_body_bytes,
        config.lists.max_entries,
        Some(lists_dir),
    );

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
        source_trust,
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
    let count = mgr.refresh().await;
    Ok((filter, count))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    const ALLOWED_DOMAIN: &str = "allowed-example.test";
    const BLOCKED_DOMAIN: &str = "blocked-example.test";

    /// A counter that moved is not proof that OUR cycle moved it.
    ///
    /// The gap between the two readings is the only correlation available —
    /// SIGHUP carries no request id — and each band means something the
    /// operator must be told differently. An external audit named the naive
    /// reading (`after != before` ⇒ "this is my result") as the top defect in
    /// this feature: under a concurrent reload it reports someone else's
    /// verdict as this command's own, with exit 0 and the word "installed".
    ///
    /// The restart case is the one that would otherwise be silently wrong in
    /// the WORST direction: after a restart the boot rebuild records
    /// `seq: 1, Installed`, so a `!=` test sees movement and a plausible
    /// success — for a refresh that never ran.
    #[test]
    fn attribution_reads_the_gap_not_merely_a_change() {
        assert_eq!(Attribution::of(7, 8), Attribution::Ours);
        assert_eq!(Attribution::of(0, 1), Attribution::Ours, "first ever cycle");

        assert_eq!(
            Attribution::of(7, 10),
            Attribution::Ambiguous { cycles: 3 },
            "three cycles closed; the last one may not be ours"
        );

        // The daemon restarted and its boot rebuild installed: seq 1 with a
        // perfectly healthy outcome. Movement, and none of it ours.
        assert_eq!(Attribution::of(42, 1), Attribution::Restarted);
        assert_eq!(
            Attribution::of(42, 0),
            Attribution::Restarted,
            "restarted, no cycle finished yet"
        );

        // Equality cannot reach the reporter — the poll only breaks out on a
        // CHANGE — but the classifier must not invent a restart from it.
        assert_eq!(Attribution::of(7, 7), Attribution::Ours);
    }

    /// A daemon that cannot report cycles must not be WAITED for.
    ///
    /// `None` reaches [`report_reload_outcome`] from a daemon too old to
    /// carry `lists_cycle`, or one with no list subsystem wired. In both
    /// cases no cycle mark is ever coming, so polling for one to advance
    /// burns the entire [`RELOAD_WAIT`] on every single refresh and then
    /// reports "could not confirm" — turning a working command into a
    /// 90-second hang against every older daemon on the network.
    ///
    /// **Timed, because the ambiguity is temporal, not textual.** A version
    /// that polls produces the same final output as one that returns at
    /// once; the only thing separating them is how long it took. Asserting
    /// on the printed text would pass on the broken build. The threshold is
    /// two orders of magnitude below `RELOAD_WAIT`, so it cannot be met by
    /// a poll that merely got lucky on its first iteration —
    /// `RELOAD_POLL_EVERY` alone is 2s.
    #[tokio::test]
    async fn old_daemon_is_not_polled() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let sock = tmp.path().join("absent.sock");
        let cfg = tmp.path().join("absent.toml");

        let started = std::time::Instant::now();
        report_reload_outcome(&sock, &cfg, None).await;
        let elapsed = started.elapsed();

        assert!(
            elapsed < Duration::from_millis(500),
            "a daemon that cannot report cycles must return immediately, \
             not wait out RELOAD_WAIT ({RELOAD_WAIT:?}); took {elapsed:?}"
        );
    }

    /// The control arm for the test above: the same function, given a mark,
    /// DOES wait. Without this the timing assertion is unfalsifiable — a
    /// `report_reload_outcome` that returned instantly in every case would
    /// satisfy it forever while measuring nothing.
    ///
    /// The socket does not exist, so every poll fails and the loop runs to
    /// its deadline. That is the point: it proves the waiting is real. Uses
    /// a paused clock so proving it costs no wall-clock time.
    #[tokio::test(start_paused = true)]
    async fn a_reporting_daemon_is_waited_for() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let sock = tmp.path().join("absent.sock");
        let cfg = tmp.path().join("absent.toml");

        let started = tokio::time::Instant::now();
        report_reload_outcome(
            &sock,
            &cfg,
            Some(CycleMark {
                seq: 7,
                outcome: Some(CycleOutcome::Installed),
            }),
        )
        .await;

        assert!(
            started.elapsed() >= RELOAD_WAIT,
            "given a cycle mark, the reporter must actually wait for the \
             cycle to advance — otherwise the other test proves nothing"
        );
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
            r#"schema_version = 3

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

    /// neutrality-06 follow-up. `run_update`'s foreground path built its
    /// `ListManager` without ever calling `set_allow_bits`, so
    /// `Spill::build_shard` stamped every domain — `base = allow` lists
    /// included — as `DomainMasks::block_only`. This pins the actual
    /// per-domain verdict `FilterEngine::list_membership` returns, which is
    /// the primitive the bug corrupts. `run_update`'s exit code and printed
    /// domain count are identical whether the wiring is present or not
    /// (both lists contribute one domain each either way), so neither
    /// would have caught this — this test calls the extracted
    /// `refresh_foreground_filter` directly to get at the engine itself.
    #[tokio::test(flavor = "current_thread")]
    async fn foreground_refresh_honors_list_direction() {
        let tmp = tempfile::tempdir().unwrap();
        let master = write_direction_fixture(tmp.path());

        let now = time::OffsetDateTime::now_utc();
        let loaded = loader::load_config(&master, now).expect("fixture config must load");
        let (merged_sources, source_trust) =
            merge_sources_with_blocklists(&loaded.config.lists.sources, &loaded.config.blocklists);

        let (filter, _count) =
            refresh_foreground_filter(&master, &loaded.config, merged_sources, source_trust)
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
}
