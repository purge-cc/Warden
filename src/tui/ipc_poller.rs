//! Async IPC data fetching — wraps socket_client::send_command for each data type.

use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Instant;

use anyhow::Result;

use std::net::IpAddr;

use crate::config::settings::ClientConfig;
#[cfg(feature = "cluster")]
use crate::ipc::protocol::ClusterStatusDto;
use crate::ipc::protocol::{
    DaemonLogDto, DevicePatch, DeviceViewDto, IpcCommand, IpcResponse, LocalRecordsHitEntry,
    ProfileUpdatePatch, QueryLogDto, QueryLogFileState, QueryLogRequest, TrackingPatch,
};
use crate::ipc::socket_client::send_command;
use crate::lists::status::BlocklistStatusDto;
use crate::tracking::query_log::QueryLogCursor;
use crate::tui::app::{DaemonStatus, TrackingData};

pub struct IpcPoller {
    socket_path: PathBuf,
    /// Previous `prefetch_promotions_total` plus the
    /// instant of the previous fetch. Used to derive a per-minute rate
    /// for the Dashboard Pulse row. `None` on first poll; the rate
    /// stays `0.0` until a second poll establishes a baseline.
    prev_prefetch: Mutex<Option<(u64, Instant)>>,
}

/// Bundled result of `fetch_query_logs`. Carries the three fields the
/// TUI needs to render its empty-state messages without
/// inferring: the DTO list, the live `query_log_enabled` flag as the
/// daemon sees it, and the file-read outcome.
#[derive(Debug, Clone)]
pub struct QueryLogPollResult {
    pub entries: Vec<QueryLogDto>,
    pub logging_enabled: bool,
    pub file_state: QueryLogFileState,
    /// Resume point for the next older page, or `None` when the walk
    /// reached the end of the retained window.
    pub next_cursor: Option<QueryLogCursor>,
    /// The cursor sent was stale (its file rotated) and this page is the
    /// live tail instead.
    pub cursor_stale: bool,
}

/// Bundled result of [`IpcPoller::fetch_daemon_logs`].
///
/// `dropped` and `capacity` travel with the entries rather than being
/// fetched separately: they describe THIS page's honesty — how much the
/// ring can hold and how much capture lost to contention — and a
/// separately-fetched pair could describe a different moment.
#[derive(Debug, Clone)]
pub struct DaemonLogPage {
    pub entries: Vec<DaemonLogDto>,
    pub dropped: u64,
    pub capacity: usize,
}

impl IpcPoller {
    pub fn new(socket_path: &Path) -> Self {
        Self {
            socket_path: socket_path.to_path_buf(),
            prev_prefetch: Mutex::new(None),
        }
    }

    /// Compute promotions-per-minute from the inter-poll delta of the
    /// daemon's cumulative `prefetch_promotions_total`. Updates the
    /// stored baseline as a side effect. Returns `0.0` on the first
    /// call (no baseline yet) and on a same-instant call (delta = 0s).
    fn prefetch_promotions_per_min(&self, current_total: u64) -> f64 {
        let now = Instant::now();
        // Recover from a poisoned lock instead of a second panic: the
        // critical section is a trivial Copy-tuple swap and cannot leave
        // the guarded value in a torn state, so the prior-panic poison is
        // safe to ignore. Keeps the client path panic-free.
        let mut guard = self.prev_prefetch.lock().unwrap_or_else(|e| e.into_inner());
        let rate = match *guard {
            Some((prev_total, prev_at)) => {
                let delta_promotions = current_total.saturating_sub(prev_total);
                let elapsed = now.saturating_duration_since(prev_at).as_secs_f64();
                if elapsed > 0.0 {
                    (delta_promotions as f64) * 60.0 / elapsed
                } else {
                    0.0
                }
            }
            None => 0.0,
        };
        *guard = Some((current_total, now));
        rate
    }

    /// Borrow the socket path so callers (e.g. the Lists
    /// assignment modal commit handler) can chain a manual
    /// `ipc_reload::attempt_reload` after a batch of inline writes,
    /// keeping the modal flow async-friendly without re-creating the
    /// poller.
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// Shared tail for every `fetch_*`/`send_*` match below: an
    /// `IpcResponse::Error` carries the daemon's own message, and
    /// anything else is a protocol mismatch worth naming — `verb` plus
    /// the `Debug` of the variant actually received, not a bare
    /// "unexpected response" that discards the one diagnostic available.
    fn bail_unexpected<T>(verb: &str, response: IpcResponse) -> Result<T> {
        match response {
            IpcResponse::Error { message } => anyhow::bail!("{message}"),
            other => anyhow::bail!("{verb}: unexpected response {other:?}"),
        }
    }

    pub async fn fetch_status(&self) -> Result<DaemonStatus> {
        Self::status_from_response(send_command(&self.socket_path, &IpcCommand::Status).await?)
    }

    /// Project an `IpcResponse` onto the TUI's [`DaemonStatus`].
    ///
    /// Split out of [`IpcPoller::fetch_status`] rather than left inline:
    /// inline, the projection sat inside an `async fn` that needs a live
    /// Unix socket to call, so nothing exercised it, and a field
    /// vanishing into the `..` cost nothing at gate time. As a pure
    /// function over a value the test can build, the mapping is
    /// checkable.
    fn status_from_response(response: IpcResponse) -> Result<DaemonStatus> {
        match response {
            // `query_log_drops` is skipped via `..` — the TUI's own status
            // panel doesn't surface drop counters yet, and a fresh field
            // would otherwise break this exhaustive destructure.
            //
            // `version` / `cache_cap` / `lists_active` / `lists_total`
            // flow through to `DaemonStatus` so the dashboard can replace
            // its `cache_capacity` extrapolation and surface real list /
            // version counters.
            //
            // `lists_corpus_refusal`, `lists_corpus_freeze` and
            // `lists_truncated` must NOT be swallowed by the `..` below:
            // each describes an outcome that the counters beside them
            // actively contradict. A refused or truncated cycle still
            // reports `lists_active == lists_total`, because every source
            // really did fetch. Anything added here that qualifies an
            // existing counter must be destructured, not defaulted away.
            //
            // `upstream_servers` flows through so the System card can
            // render the literal resolver addresses.
            IpcResponse::Status {
                pid,
                listen,
                upstream_mode,
                upstream_count,
                domain_count,
                cache_entries,
                list_count,
                uptime_secs,
                version,
                cache_cap,
                lists_active,
                lists_total,
                resource_budget,
                lists_corpus_refusal,
                lists_corpus_freeze,
                lists_truncated,
                upstream_servers,
                ..
            } => Ok(DaemonStatus {
                pid,
                listen,
                upstream_mode,
                upstream_count,
                domain_count,
                cache_entries,
                list_count,
                uptime_secs,
                version,
                cache_cap,
                lists_active,
                lists_total,
                resource_budget,
                lists_corpus_refusal,
                lists_corpus_freeze,
                lists_truncated,
                upstream_servers,
            }),
            other => Self::bail_unexpected("Status", other),
        }
    }

    /// Live cluster view for the dashboard dot + Cluster
    /// tab. Mirrors `fetch_status` — `ClusterStatus` is a ReadOnly,
    /// token-less command (no `token: None` plumbing needed). Returns the
    /// whole `ClusterStatusDto` verbatim; the dot/tab renderers project it.
    #[cfg(feature = "cluster")]
    pub async fn fetch_cluster_status(&self) -> Result<ClusterStatusDto> {
        match send_command(&self.socket_path, &IpcCommand::ClusterStatus).await? {
            IpcResponse::ClusterStatus { status } => Ok(status),
            other => Self::bail_unexpected("ClusterStatus", other),
        }
    }

    pub async fn fetch_tracking_stats(&self) -> Result<TrackingData> {
        // P0-3: send_command auto-attaches the plaintext token from
        // ~/.config/purge-warden/token for Mutating/Admin commands, so
        // passing None here is correct at this layer.
        match send_command(
            &self.socket_path,
            &IpcCommand::TrackingStats { token: None },
        )
        .await?
        {
            IpcResponse::TrackingStats {
                queries_total,
                blocked_total,
                blocked_pct,
                cache_hit_rate,
                cache_negative_hits,
                uptime_secs: _,
                top_blocked,
                top_queried,
                hourly,
                daily,
                cache_hit_rate_24h,
                blocked_pct_24h,
                cache_hit_rate_delta_1h,
                blocked_pct_delta_1h,
                qtype_distribution,
                // Second bar of the Dashboard QTYPE chart
                // card. Same shape + canonical order as
                // `qtype_distribution`; only the daemon-side counter
                // semantics differ (blocked-only).
                qtype_blocked_distribution,
                // 24h rolling window variants of the two
                // qtype distributions above. The chart card reads these
                // directly; the cumulative pair stays on TrackingData
                // for future surfacing.
                qtype_distribution_24h,
                qtype_blocked_distribution_24h,
                // Wired into the Dashboard Pulse row.
                prefetch_pool_size,
                prefetch_promotions_total,
                prefetch_demotions_total,
                // Daemon-resolved scope/topic labels for the Top Lists
                // card. Already sorted desc + capped at 5 by
                // `extract_top_n_u8`; renderer truncates defensively.
                top_blocked_lists,
                // 24h-rolling siblings of the lifetime Top-N vectors
                // above. Drive the retitled row-4 cards. Empty on older
                // daemon builds that predate this field, in which case
                // the row-4 cards render `collecting…` placeholder.
                top_blocked_24h,
                top_queried_24h,
                top_blocked_lists_24h,
            } => {
                // Compute the per-minute rate before constructing the
                // struct so the renderer is purely formatting (and the
                // baseline mutation is centralised here, not in the App
                // poll loop).
                let prefetch_promotions_per_min =
                    self.prefetch_promotions_per_min(prefetch_promotions_total);
                Ok(TrackingData {
                    queries_total,
                    blocked_total,
                    blocked_pct,
                    cache_hit_rate,
                    cache_negative_hits,
                    top_blocked,
                    top_queried,
                    hourly,
                    daily,
                    cache_hit_rate_24h,
                    blocked_pct_24h,
                    cache_hit_rate_delta_1h,
                    blocked_pct_delta_1h,
                    qtype_distribution,
                    qtype_blocked_distribution,
                    qtype_distribution_24h,
                    qtype_blocked_distribution_24h,
                    prefetch_pool_size,
                    prefetch_promotions_total,
                    prefetch_demotions_total,
                    prefetch_promotions_per_min,
                    top_blocked_lists,
                    top_blocked_24h,
                    top_queried_24h,
                    top_blocked_lists_24h,
                })
            }
            other => Self::bail_unexpected("TrackingStats", other),
        }
    }

    /// Snapshot all per-blocklist runtime telemetry for
    /// the Lists tab. ReadOnly tier — no token attached. Returns the
    /// `Vec<BlocklistStatusDto>` in the same order as `[lists].sources`
    /// (the manager preserves insertion order in the registry).
    pub async fn fetch_blocklist_stats(&self) -> Result<Vec<BlocklistStatusDto>> {
        let cmd = IpcCommand::BlocklistStats { source_id: None };
        match send_command(&self.socket_path, &cmd).await? {
            IpcResponse::BlocklistStatsList { stats } => Ok(stats),
            other => Self::bail_unexpected("BlocklistStats", other),
        }
    }

    /// Snapshot the per-record
    /// `LocalRecordsHits` counter for the `Leaf::LocalDns` hits column.
    /// ReadOnly tier — no token attached. Daemon-side iteration order is
    /// unspecified; the TUI builds its own `(scope, domain) → count`
    /// lookup at render time.
    pub async fn fetch_local_records_hits(&self) -> Result<Vec<LocalRecordsHitEntry>> {
        let cmd = IpcCommand::LocalRecordsHits;
        match send_command(&self.socket_path, &cmd).await? {
            IpcResponse::LocalRecordsHitsList { entries } => Ok(entries),
            other => Self::bail_unexpected("LocalRecordsHits", other),
        }
    }

    /// A filtered page of the daemon's own `tracing` events.
    ///
    /// Admin tier — the daemon's log text carries client IPs and query
    /// names. `send_command` attaches the auto-discovered token, the same
    /// way `fetch_query_logs` gets its.
    ///
    /// Both filters go DOWN with the request so the daemon applies them
    /// while walking its ring; filtering the response here would search
    /// only the newest `limit` rows.
    pub async fn fetch_daemon_logs(
        &self,
        limit: usize,
        level: Option<crate::tracking::log_ring::LogLevel>,
        contains: Option<String>,
    ) -> Result<DaemonLogPage> {
        let cmd = IpcCommand::DaemonLogs {
            limit,
            level,
            contains,
            token: None,
        };
        match send_command(&self.socket_path, &cmd).await? {
            IpcResponse::DaemonLogs {
                entries,
                dropped,
                capacity,
            } => Ok(DaemonLogPage {
                entries,
                dropped,
                capacity,
            }),
            other => Self::bail_unexpected("DaemonLogs", other),
        }
    }

    /// Fetch the full device view (mapped + unmapped + block flag).
    /// Uses the `GetAllDevices` endpoint, which is ReadOnly
    /// (no token needed) so the Dashboard widget works on a fresh
    /// install and on locked-out networks.
    pub async fn fetch_device_view(&self) -> Result<DeviceViewDto> {
        match send_command(&self.socket_path, &IpcCommand::GetAllDevices).await? {
            IpcResponse::DeviceView(view) => Ok(view),
            other => Self::bail_unexpected("GetAllDevices", other),
        }
    }

    /// `cursor` of `None` reads the live tail (page 0). Anything else is
    /// a resume point minted by a previous response's `next_cursor`.
    pub async fn fetch_query_logs(&self, req: QueryLogRequest) -> Result<QueryLogPollResult> {
        let QueryLogRequest {
            limit,
            client,
            blocked_only,
            domain,
            since_secs,
            cursor,
            advanced,
        } = req;
        let cmd = IpcCommand::QueryLogs {
            limit,
            client,
            blocked_only,
            domain,
            since_secs,
            cursor,
            advanced,
            token: None,
        };
        match send_command(&self.socket_path, &cmd).await? {
            IpcResponse::QueryLogs {
                entries,
                logging_enabled,
                file_state,
                next_cursor,
                cursor_stale,
            } => Ok(QueryLogPollResult {
                entries,
                logging_enabled,
                file_state,
                next_cursor,
                cursor_stale,
            }),
            other => Self::bail_unexpected("QueryLogs", other),
        }
    }

    pub async fn send_reload(&self) -> Result<String> {
        match send_command(&self.socket_path, &IpcCommand::Reload { token: None }).await? {
            IpcResponse::Ok { message } => Ok(message),
            other => Self::bail_unexpected("Reload", other),
        }
    }

    /// Submit the TUI Settings → Tracking panel patch as
    /// an `IpcCommand::TrackingConfigUpdate`. Success returns the
    /// daemon's "tracking config updated" message; any daemon-side
    /// rejection (e.g. retention out of range) is bubbled up as the
    /// error body for the TUI to render in its status line.
    pub async fn send_tracking_update(&self, patch: TrackingPatch) -> Result<String> {
        let cmd = IpcCommand::TrackingConfigUpdate { patch, token: None };
        match send_command(&self.socket_path, &cmd).await? {
            IpcResponse::Ok { message } => Ok(message),
            other => Self::bail_unexpected("TrackingConfigUpdate", other),
        }
    }

    /// Submit a `DeviceAdd` IPC mutation. Returns the daemon's success
    /// message on Ok or bubbles the daemon error verbatim. Used by the
    /// TUI device form modal on submit. The parameter is a
    /// `ClientConfig` — the v0 legacy struct kept as the `[[devices]]`
    /// pass-through type.
    pub async fn send_device_add(&self, device: ClientConfig) -> Result<String> {
        let cmd = IpcCommand::DeviceAdd {
            client: device,
            token: None, // socket_client::send_command auto-attaches
        };
        match send_command(&self.socket_path, &cmd).await? {
            IpcResponse::Ok { message } => Ok(message),
            other => Self::bail_unexpected("DeviceAdd", other),
        }
    }

    /// Submit a `DeviceUpdate` IPC mutation with a partial patch. `id` is the
    /// device's stable id — the IPC `name` field is keyed by id, not
    /// display name; the wire field name is not renamed to match.
    pub async fn send_device_update(&self, id: String, patch: DevicePatch) -> Result<String> {
        let cmd = IpcCommand::DeviceUpdate {
            name: id,
            patch,
            token: None,
        };
        match send_command(&self.socket_path, &cmd).await? {
            IpcResponse::Ok { message } => Ok(message),
            other => Self::bail_unexpected("DeviceUpdate", other),
        }
    }

    /// Submit a `DeviceRemove` IPC mutation. The TUI delete confirmation
    /// modal calls this after the user picks "yes".
    pub async fn send_device_remove(&self, name: String) -> Result<String> {
        let cmd = IpcCommand::DeviceRemove { name, token: None };
        match send_command(&self.socket_path, &cmd).await? {
            IpcResponse::Ok { message } => Ok(message),
            other => Self::bail_unexpected("DeviceRemove", other),
        }
    }

    /// Submit a `DevicePromote` IPC mutation. The daemon strictly
    /// requires an ARP MAC for the IP — the keybindings layer should
    /// already have rejected this call if ARP was stale, but if it
    /// slips through the daemon's plain-English error surfaces here.
    pub async fn send_device_promote(&self, fields: PromoteFields) -> Result<String> {
        let cmd = IpcCommand::DevicePromote {
            ip: fields.ip,
            name: fields.name,
            profile: fields.profile,
            owner: fields.owner,
            device_type: fields.device_type,
            department: fields.department,
            token: None,
        };
        match send_command(&self.socket_path, &cmd).await? {
            IpcResponse::Ok { message } => Ok(message),
            other => Self::bail_unexpected("DevicePromote", other),
        }
    }

    /// Submit a `ProfileCreate` IPC mutation. Used by the
    /// Profiles tab Add modal on submit. The daemon handler validates the
    /// id, refuses duplicates, writes + validates the TOML, and
    /// self-reloads via `notify_reload` — the TUI only needs to refresh
    /// its offline `loaded_config` cache afterwards. `token: None` — the
    /// socket client auto-attaches the plaintext token for Mutating verbs.
    pub async fn send_profile_create(&self, id: String, display_name: String) -> Result<String> {
        let cmd = IpcCommand::ProfileCreate {
            id,
            display_name,
            token: None,
        };
        match send_command(&self.socket_path, &cmd).await? {
            IpcResponse::Ok { message } => Ok(message),
            other => Self::bail_unexpected("ProfileCreate", other),
        }
    }

    /// Submit a `ProfileUpdate` IPC mutation. The `patch`
    /// carries every changed MUTATE field — the daemon applies them in a
    /// single atomic TOML rewrite. Used by the Profiles tab Edit modal.
    pub async fn send_profile_update(
        &self,
        id: String,
        patch: ProfileUpdatePatch,
    ) -> Result<String> {
        let cmd = IpcCommand::ProfileUpdate {
            id,
            patch,
            token: None,
        };
        match send_command(&self.socket_path, &cmd).await? {
            IpcResponse::Ok { message } => Ok(message),
            other => Self::bail_unexpected("ProfileUpdate", other),
        }
    }

    /// Submit a `ProfileDelete` IPC mutation. The daemon
    /// validator refuses the delete if any device / group / subnet /
    /// schedule still references the id; that rejection bubbles up here
    /// as the error body for the modal to render. Used by the Profiles
    /// tab Delete confirm.
    pub async fn send_profile_delete(&self, id: String) -> Result<String> {
        let cmd = IpcCommand::ProfileDelete { id, token: None };
        match send_command(&self.socket_path, &cmd).await? {
            IpcResponse::Ok { message } => Ok(message),
            other => Self::bail_unexpected("ProfileDelete", other),
        }
    }
}

/// Fields the TUI form collects for a Promote action — mirrors the
/// IPC `DevicePromote` payload minus the auth token. Wrapping in a
/// struct keeps `IpcPoller::send_device_promote` under the
/// `clippy::too_many_arguments` threshold without bypassing the lint.
pub struct PromoteFields {
    pub ip: IpAddr,
    pub name: String,
    pub profile: String,
    pub owner: Option<String>,
    pub device_type: Option<String>,
    pub department: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lists::status::{CorpusFreeze, CorpusRefusal};
    use time::macros::datetime;

    /// Build a `Status` response with every field named explicitly.
    ///
    /// Deliberately NOT `..Default::default()`: a field can join the wire
    /// and be defaulted away without anything going red, and a fixture
    /// that spreads a default reproduces exactly that blindness inside
    /// the test meant to catch it.
    /// Naming all of them costs one compile error when the wire grows — which
    /// is the notification this projection never had.
    fn status_response(
        lists_corpus_refusal: Option<CorpusRefusal>,
        lists_corpus_freeze: Option<CorpusFreeze>,
        lists_truncated: u32,
    ) -> IpcResponse {
        IpcResponse::Status {
            pid: 1234,
            listen: "127.0.0.1:15353".into(),
            upstream_mode: "plain".into(),
            upstream_count: 2,
            upstream_servers: Vec::new(),
            domain_count: 500_000,
            cache_entries: 1234,
            list_count: 3,
            uptime_secs: 3600,
            query_log_drops: None,
            version: "0.37.0".into(),
            cache_cap: 0,
            lists_active: 8,
            lists_total: 8,
            lists_truncated,
            lists_corpus_refusal,
            lists_cycle: None,
            lists_corpus_freeze,
            lc2_list_diagnostics: Default::default(),
            resource_budget: None,
            cache_weighted_size: 0,
        }
    }

    fn refusal() -> CorpusRefusal {
        CorpusRefusal {
            unique: 14_200_000,
            ceiling: 14_000_000,
            novel_by_source: vec![("privacy-ads".to_string(), 2_100_000)],
        }
    }

    fn freeze() -> CorpusFreeze {
        CorpusFreeze {
            since: Some(datetime!(2026-08-04 03:00:00 UTC)),
            consecutive: 9,
        }
    }

    /// The projection must CARRY the refusal, not merely compile.
    ///
    /// The mutation this is built to catch is not deletion — dropping the
    /// field from the destructure fails to build, which is not evidence.
    /// It is a projection that keeps the field and hardcodes
    /// `lists_corpus_refusal: None`, which compiles, renders a healthy
    /// dashboard, and is precisely the defect that shipped.
    #[test]
    fn corpus_refusal_survives_the_poller_projection() {
        let status =
            IpcPoller::status_from_response(status_response(Some(refusal()), Some(freeze()), 0))
                .unwrap();
        let carried = status
            .lists_corpus_refusal
            .expect("the refusal must survive the projection, not vanish into the `..`");
        assert_eq!(carried.unique, 14_200_000);
        assert_eq!(carried.ceiling, 14_000_000);
        assert_eq!(
            carried.novel_by_source.first().map(|(s, _)| s.as_str()),
            Some("privacy-ads"),
            "the largest-contributor diagnostic must survive too — it is the \
             only part of the refusal that tells the operator what to remove"
        );
    }

    /// The second blind spot of the same shape.
    #[test]
    fn truncation_count_survives_the_poller_projection() {
        let status = IpcPoller::status_from_response(status_response(None, None, 3)).unwrap();
        assert_eq!(
            status.lists_truncated, 3,
            "a truncated source is also `active`, so this counter is the only \
             thing that can contradict a healthy-looking N/N"
        );
    }

    /// The third field of the same shape, and the one whose loss is
    /// hardest to notice: without it the TUI can show a refusal and still
    /// not distinguish this morning's from a fortnight-old one.
    #[test]
    fn freeze_duration_survives_the_poller_projection() {
        let status =
            IpcPoller::status_from_response(status_response(Some(refusal()), Some(freeze()), 0))
                .unwrap();
        let carried = status
            .lists_corpus_freeze
            .expect("the freeze must survive the projection, not vanish into the `..`");
        assert_eq!(carried.consecutive, 9);
        assert_eq!(carried.since, Some(datetime!(2026-08-04 03:00:00 UTC)));
    }

    /// The control arm. Without it, a projection that hardcoded
    /// `Some(refusal)` would pass the two tests above and alarm on every
    /// healthy daemon.
    #[test]
    fn a_healthy_cycle_projects_no_refusal_and_no_truncation() {
        let status = IpcPoller::status_from_response(status_response(None, None, 0)).unwrap();
        assert!(status.lists_corpus_refusal.is_none());
        assert!(status.lists_corpus_freeze.is_none());
        assert_eq!(status.lists_truncated, 0);
    }
}
