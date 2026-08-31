//! §4.11-3 — the secondary's convergence poll loop (CS1/CS6).
//!
//! A NEW background tokio task (NOT bolted onto `signal_loop`), spawned only
//! when `cluster.enabled && role == secondary`. Every `poll_interval_secs`:
//!
//! 1. `POST /api/cluster/heartbeat` with this node's stats + the plaintext
//!    cluster token (CS2 verifies plaintext vs the primary's stored hash) and
//!    reads back the primary's `config_hash`;
//! 2. if `config_hash` differs from last-applied, `GET /bundle` and apply it
//!    ([`crate::cluster::apply::apply_bundle`], stage→validate→install→reload).
//!
//! **Policy is the only thing on this wire.** The Tier-1 domain map used to be
//! shipped alongside it; it is not, and must not be. The bitmask is a
//! *positional* index into the process's own merged sources vector, so it is
//! meaningful only inside the process that built it — publishing it produced a
//! fixed size ceiling, a bit↔policy misalignment window, and the silent loss of
//! list direction. The secondary now downloads and builds its own lists from
//! the replicated policy, and derives identical bits by construction. See
//! `_docs/features/cluster_sync_policy_only.md` §3.
//!
//! Convergence is conditioned on the **content hash**, not the generation
//! counter (the hash survives a primary restart; the counter resets). A failed
//! poll = log + keep last-good + retry next tick: NO self-promotion, NO
//! takeover (failover is Phase 2; `failover_after_secs` stays parsed-unused).
//!
//! The last-applied hash lives in-memory (D-F): the first poll after a restart
//! re-pulls the bundle. The bundle itself is on disk in `cluster.d/`, so a
//! secondary that boots with the primary down still loads its last-good policy.

use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use reqwest::header::IF_NONE_MATCH;
use reqwest::StatusCode;
use tokio::sync::mpsc;

use crate::tracking::StatsEngine;

use super::apply::apply_bundle;
use super::dto::{ClusterStats, HeartbeatRequest, HeartbeatResponse};
use super::observe::{ClusterObserve, SyncStatus};

/// Per-request timeout for the poll HTTP client — bounded so a hung primary
/// never stalls the loop past a tick or two.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Hard ceiling on the policy-bundle body the secondary will buffer (`poll-01`).
/// The bundle is policy-only TOML (KB–low-MB); 16 MB is a safe upper bound.
///
/// Lived in `domainmap.rs` until that module was deleted with the map transfer.
/// It caps the BUNDLE, not the map, so it outlived its old home.
const MAX_BUNDLE_BYTES: usize = 16 * 1024 * 1024;

/// Run the secondary poll loop forever. Captures clones of the daemon's
/// shared handles; returns only if the reload channel closes (daemon
/// shutdown). All identity (`peer`, `token`, `interval`) is boot-time (D5).
#[allow(clippy::too_many_arguments)]
pub async fn run(
    config_path: PathBuf,
    reload_tx: mpsc::Sender<Option<u32>>,
    peer: String,
    token: String,
    interval: Duration,
    stats: Option<Arc<StatsEngine>>,
    observe: Arc<ClusterObserve>,
    node_name: Option<String>,
) {
    let peer = peer.trim_end_matches('/').to_string();
    if peer.is_empty() {
        tracing::error!("cluster secondary: no peer URL configured; poll loop will not start");
        return;
    }
    if token.is_empty() {
        tracing::warn!(
            "cluster secondary: no plaintext cluster token found (run `warden cluster join \
             --token …`); polls will fail authentication until one is present"
        );
    }
    // §6: the poll client trusts the primary's pinned certificate and NO
    // public CA. Neither household box has a publicly-issued certificate, so
    // this is what makes the channel exist at all — the previous bare builder
    // (webpki roots only) could not complete a single poll against a
    // non-loopback peer.
    //
    // Failing to build is FATAL to the loop, deliberately. The alternative —
    // fall back to an unpinned client — is a sync that silently succeeds
    // against anyone holding a public certificate for the peer's name, which
    // is the one outcome worse than not syncing.
    let peer_cert = peer_cert_from_config(&config_path);
    let client = match super::pinned::build_pinned_client(
        &peer,
        peer_cert.as_deref(),
        REQUEST_TIMEOUT,
    ) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %format!("{e:#}"), "cluster secondary: cannot build the pinned poll client; poll loop aborting");
            return;
        }
    };

    tracing::info!(%peer, interval_secs = interval.as_secs(), "cluster secondary: poll loop started");

    // In-memory last-applied content hash (D-F). `None` ⇒ pull on the first
    // poll (and again after any restart). The bundle itself is on disk in
    // `cluster.d/`, so a re-pull re-confirms rather than re-enables filtering.
    let mut last_config_hash: Option<String> = None;

    // §4.11-4 observe-only telemetry locals (NOT convergence state): the time
    // of the last *successful* poll and whether we've ever synced. Mirrored
    // into `observe` at the end of every tick for the IPC reader; they never
    // feed a convergence decision.
    let mut last_sync: Option<Instant> = None;
    let mut synced_once = false;

    // `interval`'s first tick fires immediately, so the secondary converges on
    // boot without waiting a full period.
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        ticker.tick().await;
        let result = poll_once(
            &client,
            &peer,
            &token,
            &config_path,
            &reload_tx,
            &mut last_config_hash,
            stats.as_ref(),
            node_name.as_deref(),
        )
        .await;
        let (last_poll_ok, last_error) = match &result {
            Ok(()) => {
                last_sync = Some(Instant::now());
                synced_once = true;
                (true, None)
            }
            Err(e) => {
                // A closed reload channel means the daemon is shutting down —
                // stop cleanly rather than spin logging.
                if reload_tx.is_closed() {
                    tracing::info!("cluster secondary: reload channel closed; poll loop exiting");
                    return;
                }
                tracing::warn!(error = %e, "cluster secondary: poll failed; keeping last-good, retrying next tick");
                (false, Some(e.to_string()))
            }
        };

        // Write-through the lifted poll state for the IPC `ClusterStatus`
        // reader. The convergence locals above are unchanged — this only
        // mirrors them out for observation (CS9).
        observe.store_sync(SyncStatus {
            last_config_hash: last_config_hash.clone(),
            last_sync,
            last_poll_ok,
            last_error,
            synced_at_least_once: synced_once,
        });
    }
}

/// Read `cluster.peer_cert` from the node's **merged** configuration.
///
/// Read here rather than threaded in from the daemon's already-loaded config
/// because [`run`]'s caller is outside this lane's ownership; the cost is one
/// extra load at loop start, which happens once per boot.
///
/// **Through the loader, not off the master.** An earlier version parsed the
/// master's raw TOML on the reasoning that `[cluster]` is node-local and never
/// replicated (CS3), so the master must be authoritative. That conflates two
/// different things: CS3 says the section is never *replicated*, not that it
/// always *lives in the master*. `cluster` is a known singleton top-level key
/// (`config::loader`), so an operator may legitimately put `[cluster]` in an
/// `includes` drop-in — and the raw read would then return `None` on a node
/// that is correctly configured, refusing to poll. The merged view is also
/// where `peer`, `token` and `node_name` come from, so this keeps every field
/// of the node's cluster identity reading from one source.
///
/// Every failure returns `None`, which
/// [`super::pinned::build_pinned_client`] turns into the operator-facing
/// refusal. That keeps one diagnostic for "no usable pin" instead of several
/// that differ by whether the file was missing, unparseable, or simply unset.
fn peer_cert_from_config(config_path: &Path) -> Option<String> {
    let now = time::OffsetDateTime::now_utc();
    let loaded = crate::config::loader::load_config(config_path, now).ok()?;
    loaded
        .config
        .cluster
        .peer_cert
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
}

/// One poll cycle: heartbeat → policy bundle on a hash mismatch.
#[allow(clippy::too_many_arguments)]
async fn poll_once(
    client: &reqwest::Client,
    peer: &str,
    token: &str,
    config_path: &Path,
    reload_tx: &mpsc::Sender<Option<u32>>,
    last_config_hash: &mut Option<String>,
    stats: Option<&Arc<StatsEngine>>,
    node_name: Option<&str>,
) -> anyhow::Result<()> {
    // ── 1. heartbeat ────────────────────────────────────────────────
    let hb_req = HeartbeatRequest {
        // We track content hashes, not generations; the primary parses but
        // drops these (§16.2), so 0 is correct for the MVP contract.
        config_generation: 0,
        stats: current_stats(stats),
        // §4.11-4: advertise our label so the primary's roster shows a name.
        node_name: node_name.map(str::to_owned),
    };
    let resp = client
        .post(format!("{peer}/api/cluster/heartbeat"))
        .bearer_auth(token)
        .json(&hb_req)
        .send()
        .await?;
    if !resp.status().is_success() {
        anyhow::bail!("heartbeat HTTP {}", resp.status());
    }
    let hb: HeartbeatResponse = resp.json().await?;

    // ── 2. policy ───────────────────────────────────────────────────
    // The fetched bundle's content hash is verified against `hb.config_hash`
    // and its policy-only shape fenced inside `apply_bundle` (apply-01/03).
    // A 304 (None) means already current — fall through to advance the hash.
    if last_config_hash.as_deref() != Some(hb.config_hash.as_str()) {
        if let Some(bundle_toml) =
            fetch_bundle(client, peer, token, last_config_hash.as_deref()).await?
        {
            apply_bundle(config_path, &bundle_toml, &hb.config_hash, reload_tx).await?;
        }
        *last_config_hash = Some(hb.config_hash.clone());
    }

    Ok(())
}

/// Buffer an HTTP response body with a hard ceiling (`poll-01`). reqwest applies
/// no default size limit, so a malicious/compromised/MITM'd primary could stream
/// an unbounded (chunked, no `Content-Length`) body and exhaust memory before the
/// payload is even decoded. We accumulate `chunk()`s and abort the instant the
/// running total would exceed `max` — the `Content-Length` is attacker-controlled,
/// so only the streamed total is trustworthy.
async fn read_body_capped(
    mut resp: reqwest::Response,
    max: usize,
    what: &str,
) -> anyhow::Result<Vec<u8>> {
    let mut buf = Vec::new();
    while let Some(chunk) = resp.chunk().await? {
        if buf.len() + chunk.len() > max {
            anyhow::bail!("{what} response exceeds the {max}-byte cap; aborting (possible resource-exhaustion)");
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}

/// `GET /api/cluster/bundle`. `Ok(Some(toml))` on 200, `Ok(None)` on 304.
async fn fetch_bundle(
    client: &reqwest::Client,
    peer: &str,
    token: &str,
    prev_hash: Option<&str>,
) -> anyhow::Result<Option<String>> {
    let mut req = client
        .get(format!("{peer}/api/cluster/bundle"))
        .bearer_auth(token);
    if let Some(h) = prev_hash {
        req = req.header(IF_NONE_MATCH, format!("\"{h}\""));
    }
    let resp = req.send().await?;
    if resp.status() == StatusCode::NOT_MODIFIED {
        return Ok(None);
    }
    if !resp.status().is_success() {
        anyhow::bail!("bundle HTTP {}", resp.status());
    }
    let bytes = read_body_capped(resp, MAX_BUNDLE_BYTES, "bundle").await?;
    Ok(Some(String::from_utf8(bytes).map_err(|e| {
        anyhow::anyhow!("bundle body is not valid UTF-8: {e}")
    })?))
}

/// Snapshot this node's global counters for the heartbeat (mirrors the
/// primary's `routes::current_stats`).
fn current_stats(stats: Option<&Arc<StatsEngine>>) -> ClusterStats {
    match stats {
        Some(e) => ClusterStats {
            total_queries: e.global.total_queries.load(Ordering::Relaxed),
            total_blocked: e.global.total_blocked.load(Ordering::Relaxed),
            cache_hits: e.global.total_cache_hits.load(Ordering::Relaxed),
        },
        None => ClusterStats::default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal config the loader actually accepts. `peer_cert_from_config`
    /// goes through the real loader, so the fixture must be loadable — a bare
    /// `[cluster]` table is not.
    const LOADABLE: &str = r#"schema_version = 3

[server]
default_profile = "default"

[profiles.default]
display_name = "Default"

[upstream]
servers = ["192.0.2.1:53"]
"#;

    fn write_config(extra: &str) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("config.toml");
        std::fs::write(&path, format!("{LOADABLE}{extra}")).expect("write config");
        (dir, path)
    }

    #[test]
    fn peer_cert_is_read_from_the_config() {
        let (_d, path) =
            write_config("\n[cluster]\npeer_cert = \"/etc/purge-warden/primary-cert.pem\"\n");
        assert_eq!(
            peer_cert_from_config(&path).as_deref(),
            Some("/etc/purge-warden/primary-cert.pem")
        );
    }

    /// The regression that the raw-master read had.
    ///
    /// `cluster` is a known singleton top-level key, so an operator may put
    /// `[cluster]` in an `includes` drop-in. Reading the master's own TOML
    /// returns `None` there and the poll loop refuses on a node that is
    /// correctly configured. CS3 says the section is never REPLICATED — not
    /// that it always lives in the master.
    #[test]
    fn peer_cert_is_found_when_the_cluster_section_lives_in_an_include() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("config.toml");
        // `includes` must precede every section header — appended after
        // `[upstream]` it parses as `upstream.includes` and the drop-in is
        // never read. That mistake made this test fail against a correct
        // implementation the first time.
        std::fs::write(&path, format!("includes = [\"conf.d/*.toml\"]\n{LOADABLE}"))
            .expect("write master");
        let confd = dir.path().join("conf.d");
        std::fs::create_dir_all(&confd).expect("mkdir");
        std::fs::write(
            confd.join("cluster.toml"),
            "[cluster]\npeer_cert = \"/etc/purge-warden/primary-cert.pem\"\n",
        )
        .expect("write drop-in");

        assert_eq!(
            peer_cert_from_config(&path).as_deref(),
            Some("/etc/purge-warden/primary-cert.pem"),
            "a [cluster] section in an include must be seen; the master is not the only home"
        );
    }

    /// Every "no usable pin" shape collapses to `None` so the poll client
    /// emits ONE refusal. A missing file, a section without the key, and a
    /// blank value are the same operator problem — an unpinned node — and
    /// splitting them would give several diagnostics for one remedy.
    #[test]
    fn every_unusable_shape_reads_as_no_pin() {
        for extra in [
            "",                                   // no [cluster] at all
            "\n[cluster]\nrole = \"primary\"\n",  // section, no key
            "\n[cluster]\npeer_cert = \"\"\n",    // empty
            "\n[cluster]\npeer_cert = \"   \"\n", // whitespace only
        ] {
            let (_d, path) = write_config(extra);
            assert!(
                peer_cert_from_config(&path).is_none(),
                "should read as no pin: {extra:?}"
            );
        }
        assert!(
            peer_cert_from_config(Path::new("/nonexistent/config.toml")).is_none(),
            "a missing config must read as no pin, not panic"
        );
    }

    /// A surrounding-whitespace path is trimmed rather than passed to
    /// `std::fs::read`, which would fail on a path the operator can see is
    /// correct.
    #[test]
    fn a_padded_peer_cert_path_is_trimmed() {
        let (_d, path) = write_config("\n[cluster]\npeer_cert = \"  /etc/primary.pem  \"\n");
        assert_eq!(
            peer_cert_from_config(&path).as_deref(),
            Some("/etc/primary.pem")
        );
    }
}
