//! REST API request handlers.
//!
//! Each handler extracts `State<Arc<ApiState>>` and returns JSON.
//! Mutation handlers (POST/DELETE) edit config.toml and trigger reload.

use std::sync::atomic::Ordering;
use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde::{Deserialize, Serialize};
use time::macros::datetime;

use crate::filter::engine::FilterResult;
use crate::tracking::query_log;

use super::deprecation::deprecation_headers;
use super::state::ApiState;

/// Sunset date for the `/api/clients` legacy endpoint. Two tagged
/// releases out from v0.4.4-terminology-normalization (the T5 close
/// tag) per §3 R1. Operators who scrape the API have roughly six
/// months to cut over to `/api/devices`; after the sunset date the
/// legacy route should be removed.
const API_CLIENTS_SUNSET: time::OffsetDateTime = datetime!(2026-10-01 00:00 UTC);

// ── Response types ──────────────────────────────────────────────

#[derive(Serialize)]
struct StatusResponse {
    pid: u32,
    listen: String,
    upstream_mode: String,
    upstream_count: usize,
    domain_count: usize,
    cache_entries: u64,
    list_count: usize,
    uptime_secs: u64,
    queries_total: u64,
    blocked_total: u64,
    blocked_pct: f64,
    cache_hit_rate: f64,
}

#[derive(Serialize)]
struct DeviceEntry {
    name: String,
    ip: String,
    queries: u64,
    blocked: u64,
    blocked_pct: f64,
    cache_hits: u64,
    profile: String,
    last_seen: u64,
}

#[derive(Serialize)]
struct QueryResult {
    domain: String,
    blocked: bool,
    /// §4.2 G1a — block attribution (`list:<name>` / `rule:<pattern>` /
    /// `admin_block` / …) from `BlockSource::describe`. Omitted from the
    /// JSON when absent (allowed domains, or a block with no profile
    /// context) so pre-G1a consumers are unaffected.
    #[serde(skip_serializing_if = "Option::is_none")]
    blocked_by: Option<String>,
}

#[derive(Serialize)]
struct ListsResponse {
    sources: Vec<String>,
}

#[derive(Serialize)]
struct WhitelistResponse {
    entries: Vec<String>,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

#[derive(Serialize)]
struct OkResponse {
    message: String,
}

#[derive(Serialize)]
struct LogEntry {
    timestamp: String,
    client_ip: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_name: Option<String>,
    domain: String,
    query_type: String,
    result: String,
    response_time_us: u64,
}

// ── Request body types ──────────────────────────────────────────

#[derive(Deserialize)]
pub struct ListBody {
    #[serde(deserialize_with = "deserialize_id_256")]
    pub id: String,
}

#[derive(Deserialize)]
pub struct WhitelistBody {
    #[serde(deserialize_with = "deserialize_domain_253")]
    pub domain: String,
}

#[derive(Deserialize)]
pub struct LogsQuery {
    #[serde(default = "default_log_limit")]
    pub limit: usize,
    #[serde(default, deserialize_with = "deserialize_opt_client_253")]
    pub client: Option<String>,
    #[serde(default)]
    pub blocked: bool,
    #[serde(default, deserialize_with = "deserialize_opt_domain_253")]
    pub domain: Option<String>,
}

fn default_log_limit() -> usize {
    20
}

/// T3.9 M-42: cap a single-field string at `max` bytes, rejecting
/// at deserialization time so an attacker can't induce a multi-MB
/// allocation by submitting `{"domain": "<huge>"}`.
///
/// `visit_str` is the primary defence — serde_json calls it on the
/// fast path with a borrowed `&str` from the input buffer, so the
/// length check fires BEFORE any per-field allocation. `visit_string`
/// is the fallback for inputs that needed escape processing (where
/// serde_json builds an owned String to hold the unescaped content);
/// the post-allocation check still rejects the request before any
/// handler logic runs. The body extractor's global cap (axum's
/// default 2 MB on JSON) catches truly enormous payloads first; this
/// per-field cap catches cleverly-shaped payloads where the body
/// is small but a single string field is implausibly long.
///
/// Operator-facing message follows `feedback_usability_first`:
/// names the field, the limit, and what to check.
fn deserialize_bounded_string<'de, D>(
    d: D,
    max: usize,
    field: &'static str,
) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct BoundedStringVisitor {
        max: usize,
        field: &'static str,
    }

    impl<'de> serde::de::Visitor<'de> for BoundedStringVisitor {
        type Value = String;

        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            write!(
                f,
                "a string of at most {} bytes for field '{}'",
                self.max, self.field
            )
        }

        fn visit_str<E: serde::de::Error>(self, s: &str) -> Result<Self::Value, E> {
            if s.len() > self.max {
                return Err(E::custom(format!(
                    "'{}' is too long: got {} bytes, max {} bytes. \
                     Shorten the value or check that you didn't paste extra data.",
                    self.field,
                    s.len(),
                    self.max,
                )));
            }
            Ok(s.to_string())
        }

        fn visit_string<E: serde::de::Error>(self, s: String) -> Result<Self::Value, E> {
            if s.len() > self.max {
                return Err(E::custom(format!(
                    "'{}' is too long: got {} bytes, max {} bytes. \
                     Shorten the value or check that you didn't paste extra data.",
                    self.field,
                    s.len(),
                    self.max,
                )));
            }
            Ok(s)
        }
    }

    d.deserialize_string(BoundedStringVisitor { max, field })
}

fn deserialize_id_256<'de, D>(d: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserialize_bounded_string(d, 256, "id")
}

fn deserialize_domain_253<'de, D>(d: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserialize_bounded_string(d, 253, "domain")
}

fn deserialize_client_253<'de, D>(d: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserialize_bounded_string(d, 253, "client")
}

fn deserialize_opt_domain_253<'de, D>(d: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    struct Wrap(#[serde(deserialize_with = "deserialize_domain_253")] String);
    Option::<Wrap>::deserialize(d).map(|o| o.map(|Wrap(s)| s))
}

fn deserialize_opt_client_253<'de, D>(d: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    struct Wrap(#[serde(deserialize_with = "deserialize_client_253")] String);
    Option::<Wrap>::deserialize(d).map(|o| o.map(|Wrap(s)| s))
}

/// §4.27-A: load the v1 [`ConfigV1`](crate::config::schema::ConfigV1) off the async runtime. Replaces
/// the pre-migration `read_settings` — the API now reads the v1 schema
/// via the loader (which merges master + includes) instead of the v0
/// single-file `Settings::from_file` parse.
///
/// T2.8 H-18 rationale carries over verbatim: `spawn_blocking` runs the
/// synchronous multi-file read on tokio's dedicated blocking pool,
/// never a runtime worker — so even when this future is awaited inside
/// the `config_write_lock` window, no async worker is starved.
async fn read_config_v1(
    path: std::path::PathBuf,
) -> anyhow::Result<crate::config::schema::ConfigV1> {
    let loaded = tokio::task::spawn_blocking(move || {
        crate::config::loader::load_config(&path, time::OffsetDateTime::now_utc())
    })
    .await
    .map_err(|e| anyhow::anyhow!("config read task panicked: {e}"))?
    .map_err(|errs| anyhow::anyhow!("config load failed with {} error(s)", errs.len()))?;
    Ok(loaded.config)
}

/// §4.27-A: outcome of an [`edit_master_lists_sources`] mutation that
/// the handler maps to an HTTP status.
enum ListEditError {
    /// Operator precondition failed (already-subscribed for add /
    /// not-subscribed for remove). Handler maps to 409 / 404 with this
    /// operator-facing message.
    Precondition(String),
    /// Read / write / validate failure — handler maps to 500.
    Io(anyhow::Error),
}

/// §4.27-A: edit the master config's `[lists].sources` array under a
/// `spawn_blocking` hop, then atomic-write + validate-or-revert.
///
/// `[lists]` is a v1 pass-through table that lives only in the master
/// file (never an include slice), so a single-file `toml::Value` edit
/// is the correct mutation — re-serialising a whole `ConfigV1` through
/// `write_config_v1` would flatten a multi-file include layout into a
/// monolith. This mirrors the per-file surgery the v1 IPC device
/// handlers do via `cli::commands::target`, scoped to the master's
/// `[lists]` table.
///
/// `edit` receives the mutable `sources` array and returns `Ok(())` to
/// commit the write or `Err(msg)` to abort with a precondition failure
/// (no bytes hit disk).
async fn edit_master_lists_sources<F>(
    config_path: std::path::PathBuf,
    edit: F,
) -> Result<(), ListEditError>
where
    F: FnOnce(&mut Vec<toml::Value>) -> Result<(), String> + Send + 'static,
{
    tokio::task::spawn_blocking(move || {
        let (mut doc, _) =
            crate::cli::commands::target::read_or_empty(&config_path).map_err(ListEditError::Io)?;
        {
            let table = doc.as_table_mut().ok_or_else(|| {
                ListEditError::Io(anyhow::anyhow!("config root is not a TOML table"))
            })?;
            let lists = table
                .entry("lists".to_string())
                .or_insert_with(|| toml::Value::Table(Default::default()));
            let lists_tbl = lists
                .as_table_mut()
                .ok_or_else(|| ListEditError::Io(anyhow::anyhow!("`lists` must be a table")))?;
            let sources = lists_tbl
                .entry("sources".to_string())
                .or_insert_with(|| toml::Value::Array(Vec::new()));
            let arr = sources.as_array_mut().ok_or_else(|| {
                ListEditError::Io(anyhow::anyhow!("`lists.sources` must be an array"))
            })?;
            edit(arr).map_err(ListEditError::Precondition)?;
        }
        crate::cli::commands::target::write_value_validated(&config_path, &config_path, &doc)
            .map_err(ListEditError::Io)?;
        Ok(())
    })
    .await
    .map_err(|e| ListEditError::Io(anyhow::anyhow!("config edit task panicked: {e}")))?
}

/// T2.8 H-18: same `spawn_blocking` rationale as `read_config_v1`,
/// applied to the rotated-log walker. `read_log_entries_with_state`
/// can walk up to `retention_days` sibling files synchronously; in
/// production with `retention_days = 30` and ~10 MB-per-day logs,
/// that's a 300 MB worst-case sync read on the runtime thread.
async fn read_log_entries_async(
    path: std::path::PathBuf,
    limit: usize,
    client_filter: Option<String>,
    blocked_only: bool,
    domain_filter: Option<String>,
    retention_days: u32,
    cutoff_epoch: Option<i64>,
) -> Result<
    (
        Vec<crate::tracking::query_log::QueryLogEntry>,
        crate::ipc::protocol::QueryLogFileState,
    ),
    String,
> {
    tokio::task::spawn_blocking(move || {
        query_log::read_log_entries_with_state(
            &path,
            limit,
            client_filter.as_deref(),
            blocked_only,
            domain_filter.as_deref(),
            retention_days,
            cutoff_epoch,
        )
    })
    .await
    .map_err(|e| format!("query log read task panicked: {e}"))
}

/// T2.8 H-16: validate a domain at the API trust boundary using the
/// shared validator from `config::schema::admin_rule`. Reuses the
/// same rules that gate IPC `warden blocklist add` and v1 admin
/// rules — RFC 1035 LDH ASCII, ≤253 octets total, ≤63 per label,
/// no leading/trailing dots, no double-dots, no leading/trailing
/// hyphens, no control characters or non-ASCII bytes.
///
/// On rejection the response is **400 Bad Request** with a body
/// that names the specific violation in plain English (per
/// `feedback_usability_first` — the operator should understand what
/// they typed wrong without consulting docs). The body never echoes
/// the raw input verbatim into a position where it could break out
/// of the JSON encoding.
///
/// `clippy::result_large_err` is allowed deliberately: the `Response`
/// is the natural error type for an API helper whose caller short-
/// circuits on rejection. Boxing the `Response` would add an
/// allocation on every rejected request without removing the cost
/// elsewhere — the caller already returns the `Response` directly
/// to axum, which moves it down the response pipeline regardless.
#[allow(clippy::result_large_err)]
fn validate_api_domain(input: &str, field_name: &str) -> Result<String, axum::response::Response> {
    crate::config::schema::admin_rule::validate_domain(input).map_err(|reason| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!(
                    "'{field_name}' is not a valid domain: {reason}. \
                     Examples: example.com, mail.google.com"
                ),
            }),
        )
            .into_response()
    })
}

/// T2.8 H-17: build the 500 response when the reload notification
/// fails after a successful disk write. The on-disk config and the
/// running daemon's in-memory state have diverged — surface this
/// loudly so the operator can recover, instead of swallowing the
/// error and returning 200 OK on a half-applied mutation.
///
/// The response body NEVER includes the raw `mpsc::error::SendError`
/// debug — that would leak internal channel state. Only the
/// operator-meaningful next-step is exposed; the underlying error is
/// logged for the agent's debugging path.
fn reload_failed_response(
    target: &str,
    action: &'static str,
    err: &tokio::sync::mpsc::error::SendError<Option<u32>>,
) -> axum::response::Response {
    tracing::error!(
        target: "api",
        action = action,
        target_id = target,
        error = %err,
        "reload notification failed after successful disk write — daemon will not pick up the change until restarted",
    );
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ErrorResponse {
            error: format!(
                "the change was saved to disk but the daemon couldn't be told \
                 to reload — its in-memory state has not picked it up yet. \
                 Reload the daemon to apply the change: \
                 systemctl reload purge-warden (target: {target})"
            ),
        }),
    )
        .into_response()
}

// ── Handlers ────────────────────────────────────────────────────

/// GET /api/status — server stats + tracking counters.
pub async fn get_status(State(state): State<Arc<ApiState>>) -> impl IntoResponse {
    let uptime_secs = state.started_at.elapsed().as_secs();

    let (queries_total, blocked_total, blocked_pct, cache_hit_rate) = match &state.stats {
        Some(engine) => {
            let total = engine.global.total_queries.load(Ordering::Relaxed);
            let blocked = engine.global.total_blocked.load(Ordering::Relaxed);
            let hits = engine.global.total_cache_hits.load(Ordering::Relaxed);
            let b_pct = if total > 0 {
                (blocked as f64 / total as f64) * 100.0
            } else {
                0.0
            };
            let c_rate = if total > 0 {
                (hits as f64 / total as f64) * 100.0
            } else {
                0.0
            };
            (total, blocked, b_pct, c_rate)
        }
        None => (0, 0, 0.0, 0.0),
    };

    // mem2608-s3 / F-E: flush moka before reading, same reasoning and
    // same primitive as the IPC `handle_status` path — see
    // `DnsCache::flushed_usage`. Off the `:53` hot path.
    let cache_entries = state.cache.flushed_usage().await.entries;

    Json(StatusResponse {
        pid: std::process::id(),
        listen: state.listen_addr.clone(),
        upstream_mode: state.upstream_mode.clone(),
        upstream_count: state.upstream_count,
        domain_count: state.filter.domain_count(),
        cache_entries,
        list_count: state.list_count,
        uptime_secs,
        queries_total,
        blocked_total,
        blocked_pct,
        cache_hit_rate,
    })
}

/// Collect per-device stats once, shared between the canonical
/// `/api/devices` handler and the legacy `/api/clients` handler so
/// both surfaces serialize the same rows.
fn collect_device_entries(engine: &crate::tracking::engine::StatsEngine) -> Vec<DeviceEntry> {
    engine
        .devices
        .iter()
        .map(|entry| {
            let q = entry.value().queries.load(Ordering::Relaxed);
            let b = entry.value().blocked.load(Ordering::Relaxed);
            let pct = if q > 0 {
                (b as f64 / q as f64) * 100.0
            } else {
                0.0
            };
            DeviceEntry {
                name: entry.value().name.to_string(),
                ip: entry.key().to_string(),
                queries: q,
                blocked: b,
                blocked_pct: pct,
                cache_hits: entry.value().cache_hits.load(Ordering::Relaxed),
                profile: entry.value().profile.to_string(),
                last_seen: entry.value().last_seen.load(Ordering::Relaxed),
            }
        })
        .collect()
}

/// GET /api/clients — per-device stats table, legacy path.
///
/// Kept alongside `/api/devices` for one deprecation cycle per §3 R1.
/// Every response carries the three deprecation headers (Deprecation,
/// Sunset, Link) built from the shared helper so clients can migrate
/// without breaking.
pub async fn get_clients(State(state): State<Arc<ApiState>>) -> impl IntoResponse {
    let engine = match &state.stats {
        Some(e) => e,
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({"error": "tracking not enabled"})),
            )
                .into_response();
        }
    };

    let devices = collect_device_entries(engine);
    let headers = deprecation_headers("/api/devices", API_CLIENTS_SUNSET)
        .expect("static inputs produce valid header values");
    (
        StatusCode::OK,
        headers,
        Json(serde_json::json!({"clients": devices})),
    )
        .into_response()
}

/// GET /api/devices — per-device stats table, canonical path (T5).
///
/// Same payload as `/api/clients` but without deprecation headers.
pub async fn get_devices(State(state): State<Arc<ApiState>>) -> impl IntoResponse {
    let engine = match &state.stats {
        Some(e) => e,
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({"error": "tracking not enabled"})),
            )
                .into_response();
        }
    };

    let devices = collect_device_entries(engine);
    Json(serde_json::json!({"devices": devices})).into_response()
}

/// GET /api/logs — query log with optional filters.
pub async fn get_logs(
    State(state): State<Arc<ApiState>>,
    Query(params): Query<LogsQuery>,
) -> impl IntoResponse {
    let engine = match &state.stats {
        Some(e) => e,
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({"error": "tracking not enabled"})),
            )
                .into_response();
        }
    };

    // Sprint 38 QLP4: use the rotated-aware helper so the API walks
    // `query.log.YYYY-MM-DD` siblings for free. Resolve the path from
    // the engine's attached-writer slot when available (S37 QL1
    // invariant); otherwise fall back to the raw config string, which
    // is usually correct for dev setups but broken under systemd's
    // `cwd=/`. A proper resolver call needs the config path which the
    // API handler doesn't carry today; that gap is tracked as a
    // follow-up.
    let path_buf = engine
        .query_log_file_path()
        .unwrap_or_else(|| engine.config.query_log_path.clone());
    // T2.8 H-18: see `read_log_entries_async` for the spawn_blocking
    // rationale — the rotated-log walker can stream up to
    // `retention_days` siblings synchronously.
    let (raw, _file_state) = match read_log_entries_async(
        path_buf,
        params.limit.min(1000),
        params.client.clone(),
        params.blocked,
        params.domain.clone(),
        engine.config.retention_days,
        None, // REST API path: `since` is not exposed here yet.
    )
    .await
    {
        Ok(pair) => pair,
        Err(msg) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: msg }),
            )
                .into_response();
        }
    };

    let entries: Vec<LogEntry> = raw
        .into_iter()
        .map(|e| LogEntry {
            timestamp: e.timestamp,
            client_ip: e.client_ip.to_string(),
            client_name: e.client_name,
            domain: e.domain,
            query_type: e.query_type,
            result: e.result,
            response_time_us: e.response_time_us,
        })
        .collect();

    Json(serde_json::json!({"entries": entries})).into_response()
}

/// GET /api/blocklists/:id/stats — Sprint 43 T2 per-list runtime stats.
///
/// `id` may be a canonical `[[blocklists]].id`, a legacy slash-form slug
/// (`"privacy/ads"`), or an exact source string. The handler resolves it
/// through the same three-pass logic the IPC layer uses (exact match →
/// resolver `slug_to_id` ↔ `slug_for_id` bridge → case-insensitive
/// substring), then renders the matched
/// [`BlocklistStatusDto`](crate::lists::status::BlocklistStatusDto).
///
/// Token-gated by the `/api/` `auth_middleware` (Cybersec lens — IPC's
/// `BlocklistStats` ReadOnly-no-token rule does NOT extend to HTTP).
///
/// Status codes:
/// - 200 with the DTO when the id resolves to a live registry slot
/// - 404 when no source matches and a `list_statuses` registry exists
/// - 503 when `list_statuses` is `None` (daemon started with no
///   `[lists].sources` configured — the registry was never built)
pub async fn get_blocklist_stats(
    State(state): State<Arc<ApiState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    // T3.9 M-41: an empty `id` would substring-match every source in
    // pass 3 (every string contains the empty string), making the
    // first-sorted entry win arbitrarily. Reject up-front so the
    // caller learns the input shape is wrong, not a random source.
    if id.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "blocklist id must not be empty. \
                          Examples: privacy/ads, security/malicious, \
                          or the canonical [[blocklists]].id from config.toml",
            })),
        )
            .into_response();
    }

    let registry = match &state.list_statuses {
        Some(r) => r,
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({
                    "error": "blocklist telemetry unavailable: daemon was started with no [lists].sources",
                })),
            )
                .into_response();
        }
    };

    // Pass 1: exact source string (slug or raw URL as it lives in
    // `[lists].sources`).
    if let Some(status) = registry.status_for_url(&id) {
        let canonical = state
            .profiles
            .as_ref()
            .and_then(|r| r.id_for_slug(&id))
            .map(|i| i.as_str().to_string());
        let dto = crate::lists::status::BlocklistStatusDto::from_status(id, canonical, &status);
        return Json(dto).into_response();
    }

    // Pass 2: canonical [[blocklists]].id → resolve to slug, look up.
    if let Some(slug) = state.profiles.as_ref().and_then(|r| r.slug_for_id(&id)) {
        if let Some(status) = registry.status_for_url(&slug) {
            let dto = crate::lists::status::BlocklistStatusDto::from_status(
                slug,
                Some(id.clone()),
                &status,
            );
            return Json(dto).into_response();
        }
    }

    // Pass 3: case-insensitive substring on the source string. Bounded
    // by the 64-source cap of `build_source_bit_map`. T3.9 M-41:
    // `registry.snapshot()` walks a HashMap so iteration order is
    // non-deterministic — same query on same data could return
    // different sources across calls. Sort by longer-match-first
    // (more specific wins) then lexicographic ascending so repeated
    // calls converge on the same answer.
    let needle = id.to_ascii_lowercase();
    let mut snapshot = registry.snapshot();
    snapshot.sort_by(|(a, _), (b, _)| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));
    if let Some((source, status)) = snapshot
        .into_iter()
        .find(|(s, _)| s.to_ascii_lowercase().contains(&needle))
    {
        let canonical = state
            .profiles
            .as_ref()
            .and_then(|r| r.id_for_slug(&source))
            .map(|i| i.as_str().to_string());
        let dto = crate::lists::status::BlocklistStatusDto::from_status(source, canonical, &status);
        return Json(dto).into_response();
    }

    (
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({
            "error": format!("blocklist not found: {id}"),
        })),
    )
        .into_response()
}

/// GET /api/lists — current list subscriptions.
pub async fn get_lists(State(state): State<Arc<ApiState>>) -> impl IntoResponse {
    // §4.27-A: see `read_config_v1` for the spawn_blocking rationale.
    match read_config_v1(state.config_path.clone()).await {
        Ok(config) => Json(ListsResponse {
            sources: config.lists.sources,
        })
        .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("failed to read config: {e}"),
            }),
        )
            .into_response(),
    }
}

/// POST /api/lists/add — add a list subscription.
pub async fn add_list(
    State(state): State<Arc<ApiState>>,
    Json(body): Json<ListBody>,
) -> impl IntoResponse {
    // Refuse before writing. `[lists].sources` accepts a slash-form
    // catalogue slug (`privacy/ads`) as well as a URL, so only strings
    // that look like a URL go through the fetch-side guard — but one that
    // the fetcher will reject is a subscription that silently filters
    // nothing, and 200 OK is the wrong answer for it. Validated before
    // the lock is taken, as `add_whitelist` does.
    if body.id.contains("://") {
        if let Err(e) = crate::lists::http_client::validate_list_url(&body.id) {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: format!(
                        "'id' is not a usable list source: {e}. \
                         Use an https:// URL or a catalogue slug such as privacy/ads."
                    ),
                }),
            )
                .into_response();
        }
    }

    // §4.27-A: edit the master's `[lists].sources` in place via
    // `toml::Value` surgery — the v1 mutation pattern. The dup check
    // runs inside the same `spawn_blocking` hop, on the array we are
    // about to mutate, so there is no read/write race. `mutate_config`
    // owns the write lock across exactly this block.
    let id = body.id.clone();
    match state
        .mutate_config(|| {
            edit_master_lists_sources(state.config_path.clone(), move |sources| {
                if sources.iter().any(|v| v.as_str() == Some(id.as_str())) {
                    return Err(format!("already subscribed: {id}"));
                }
                sources.push(toml::Value::String(id));
                Ok(())
            })
        })
        .await
    {
        Ok(()) => {}
        Err(ListEditError::Precondition(msg)) => {
            return (StatusCode::CONFLICT, Json(ErrorResponse { error: msg })).into_response();
        }
        Err(ListEditError::Io(e)) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("failed to write config: {e}"),
                }),
            )
                .into_response();
        }
    }

    tracing::info!(target: "audit", action = "lists.add", source = %body.id, "API mutation");
    if let Err(e) = state.reload_tx.send(None).await {
        return reload_failed_response(&body.id, "lists.add", &e);
    }

    (
        StatusCode::OK,
        Json(OkResponse {
            message: format!("added: {}", body.id),
        }),
    )
        .into_response()
}

/// DELETE /api/lists/remove — remove a list subscription.
pub async fn remove_list(
    State(state): State<Arc<ApiState>>,
    Json(body): Json<ListBody>,
) -> impl IntoResponse {
    // §4.27-A: edit the master's `[lists].sources` in place — see
    // `add_list`. The not-found check runs inside the same
    // `spawn_blocking` hop on the array being mutated.
    let id = body.id.clone();
    match state
        .mutate_config(|| {
            edit_master_lists_sources(state.config_path.clone(), move |sources| {
                let before = sources.len();
                sources.retain(|v| v.as_str() != Some(id.as_str()));
                if sources.len() == before {
                    return Err(format!("not subscribed: {id}"));
                }
                Ok(())
            })
        })
        .await
    {
        Ok(()) => {}
        Err(ListEditError::Precondition(msg)) => {
            return (StatusCode::NOT_FOUND, Json(ErrorResponse { error: msg })).into_response();
        }
        Err(ListEditError::Io(e)) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("failed to write config: {e}"),
                }),
            )
                .into_response();
        }
    }

    tracing::info!(target: "audit", action = "lists.remove", source = %body.id, "API mutation");
    if let Err(e) = state.reload_tx.send(None).await {
        return reload_failed_response(&body.id, "lists.remove", &e);
    }

    Json(OkResponse {
        message: format!("removed: {}", body.id),
    })
    .into_response()
}

/// POST /api/update — trigger list re-download + config reload.
pub async fn trigger_update(State(state): State<Arc<ApiState>>) -> impl IntoResponse {
    tracing::info!(target: "audit", action = "update", "API mutation");
    match state.reload_tx.send(None).await {
        Ok(()) => Json(OkResponse {
            message: "reload triggered".into(),
        })
        .into_response(),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "reload channel closed".into(),
            }),
        )
            .into_response(),
    }
}

/// GET /api/whitelist — default profile allow rules.
pub async fn get_whitelist(State(state): State<Arc<ApiState>>) -> impl IntoResponse {
    // §4.27-A: v1 expresses a profile's allow list as `[[admin_rules]]`
    // rows referenced by `profiles.<id>.admin_rules`. Reconstruct the
    // pre-migration `WhitelistResponse` shape — the `@@||domain^` rule
    // strings — by resolving the "default" profile's allow-type refs.
    // See `read_config_v1` for the spawn_blocking rationale.
    match read_config_v1(state.config_path.clone()).await {
        Ok(config) => {
            let entries = config
                .profiles
                .get("default")
                .map(|p| {
                    p.admin_rules
                        .iter()
                        .filter_map(|rid| {
                            config
                                .admin_rules
                                .iter()
                                .find(|ar| ar.id.as_str() == rid.as_str())
                        })
                        .filter(|ar| ar.rule.starts_with("@@"))
                        .map(|ar| ar.rule.clone())
                        .collect()
                })
                .unwrap_or_default();
            Json(WhitelistResponse { entries }).into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("failed to read config: {e}"),
            }),
        )
            .into_response(),
    }
}

/// POST /api/whitelist/add — add an allow rule to the default profile.
pub async fn add_whitelist(
    State(state): State<Arc<ApiState>>,
    Json(body): Json<WhitelistBody>,
) -> impl IntoResponse {
    // T2.8 H-16: validate BEFORE acquiring the lock or touching disk.
    // Strip any operator-typed `@@||...^` wrapper first so we validate
    // the bare domain shape, then re-wrap below from the canonical
    // (lowercased) form returned by the validator.
    let bare = body.domain.trim_start_matches("@@||").trim_end_matches('^');
    let canonical = match validate_api_domain(bare, "domain") {
        Ok(d) => d,
        Err(resp) => return resp,
    };

    // §4.27-A: route through the shared v1 admin-rule seat
    // (`cli::commands::rules::add_inner`). It synthesises the
    // `[[admin_rules]]` row, references it from
    // `profiles.default.admin_rules`, and runs validate-or-revert as
    // one compound write. `Scope::Profile("default")` keeps the
    // pre-migration semantic — the endpoint edits the profile literally
    // named "default". `add_inner` is sync, so it runs under
    // `spawn_blocking` (see `read_config_v1` for the rationale), inside
    // the `mutate_config` window that holds the write lock.
    let config_path = state.config_path.clone();
    let canon = canonical.clone();
    let outcome = state
        .mutate_config(|| {
            tokio::task::spawn_blocking(move || {
                crate::cli::commands::rules::add_inner(
                    &config_path,
                    crate::cli::commands::rules::Scope::Profile("default"),
                    crate::cli::commands::rules::Action::Allow,
                    &canon,
                    None,
                    None,
                )
            })
        })
        .await;
    match outcome {
        Ok(Ok(crate::cli::commands::rules::ChangeOutcome::Applied(_))) => {}
        Ok(Ok(crate::cli::commands::rules::ChangeOutcome::NoOp(_))) => {
            return (
                StatusCode::CONFLICT,
                Json(ErrorResponse {
                    error: format!("already whitelisted: {canonical}"),
                }),
            )
                .into_response();
        }
        Ok(Err(e)) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("failed to whitelist: {e}"),
                }),
            )
                .into_response();
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("whitelist task panicked: {e}"),
                }),
            )
                .into_response();
        }
    }

    // Audit the rule that reached disk, not the string that was typed:
    // `canonical` is lowercased and `@@||`/`^` affix-stripped, so the two
    // differ. The raw input stays under its own key so an operator's typo
    // is still traceable to the request that made it.
    tracing::info!(
        target: "audit",
        action = "whitelist.add",
        domain = %canonical,
        submitted = %body.domain,
        "API mutation"
    );
    if let Err(e) = state.reload_tx.send(None).await {
        return reload_failed_response(&canonical, "whitelist.add", &e);
    }

    Json(OkResponse {
        message: format!("whitelisted: {canonical}"),
    })
    .into_response()
}

/// DELETE /api/whitelist/remove — remove an allow rule from the default profile.
pub async fn remove_whitelist(
    State(state): State<Arc<ApiState>>,
    Json(body): Json<WhitelistBody>,
) -> impl IntoResponse {
    // T2.8 H-16: validate BEFORE acquiring the lock or touching disk.
    let bare = body.domain.trim_start_matches("@@||").trim_end_matches('^');
    let canonical = match validate_api_domain(bare, "domain") {
        Ok(d) => d,
        Err(resp) => return resp,
    };

    // §4.27-A: route through the shared v1 admin-rule seat
    // (`cli::commands::rules::remove_inner`). It drops the reference
    // from `profiles.default.admin_rules`, cascades the
    // `[[admin_rules]]` row when no other entity still references it,
    // and runs validate-or-revert. `Scope::Profile("default")` keeps
    // the pre-migration semantic. Sync — runs under `spawn_blocking`,
    // inside the `mutate_config` window that holds the write lock.
    let config_path = state.config_path.clone();
    let canon = canonical.clone();
    let outcome = state
        .mutate_config(|| {
            tokio::task::spawn_blocking(move || {
                crate::cli::commands::rules::remove_inner(
                    &config_path,
                    crate::cli::commands::rules::Scope::Profile("default"),
                    crate::cli::commands::rules::Action::Allow,
                    &canon,
                    None,
                )
            })
        })
        .await;
    match outcome {
        Ok(Ok(crate::cli::commands::rules::RemoveOutcome::Removed(_))) => {}
        Ok(Ok(crate::cli::commands::rules::RemoveOutcome::NotFound)) => {
            return (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: format!("not whitelisted: {canonical}"),
                }),
            )
                .into_response();
        }
        Ok(Err(e)) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("failed to remove whitelist: {e}"),
                }),
            )
                .into_response();
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("whitelist task panicked: {e}"),
                }),
            )
                .into_response();
        }
    }

    // Audit the rule that reached disk — see `add_whitelist`.
    tracing::info!(
        target: "audit",
        action = "whitelist.remove",
        domain = %canonical,
        submitted = %body.domain,
        "API mutation"
    );
    if let Err(e) = state.reload_tx.send(None).await {
        return reload_failed_response(&canonical, "whitelist.remove", &e);
    }

    Json(OkResponse {
        message: format!("removed: {canonical}"),
    })
    .into_response()
}

/// GET /api/query/:domain — test if a domain would be blocked.
pub async fn query_domain(
    State(state): State<Arc<ApiState>>,
    Path(domain): Path<String>,
) -> impl IntoResponse {
    // T2.8 H-16 (folds api-09): validate the path-segment domain
    // before letting it touch the filter engine. Stops control-char
    // log injection and 1 MB-string DoS at the trust boundary. The
    // validator returns the canonical lowercase form; we still strip
    // a trailing dot first because RFC 1035 absolute names are
    // legitimate operator input even though the validator rejects
    // trailing dots in stored rules.
    let stripped = domain.strip_suffix('.').unwrap_or(&domain);
    let canonical = match validate_api_domain(stripped, "domain") {
        Ok(d) => d,
        Err(resp) => return resp,
    };

    // §4.2 G1a — surface the already-computed block attribution via
    // `evaluate_attributed` (off hot path; this is the on-demand probe).
    // `source` is `Some` only with a Block verdict, so allowed domains
    // map to `None`. The no-profile fallbacks lack a `ResolvedProfile`
    // to attribute against, so `blocked_by` stays `None` there.
    let (blocked, blocked_by) = match &state.profiles {
        Some(resolver) => match resolver.default_profile() {
            Some(profile) => {
                let (verdict, source) = state.filter.evaluate_attributed(&canonical, &profile);
                (
                    verdict == FilterResult::Block,
                    source.map(|s| s.describe(&state.list_labels)),
                )
            }
            // SN2/SN3 invariant — when the operator has explicitly unset
            // `default_profile`, any query that would otherwise fall to
            // level 5 is REFUSED. Report as blocked for the API consumer.
            None => (true, None),
        },
        None => (state.filter.is_blocked(&canonical), None),
    };

    Json(QueryResult {
        domain: canonical,
        blocked,
        blocked_by,
    })
    .into_response()
}

/// GET /healthz — unauthenticated liveness probe.
///
/// Returns 200 when filter is loaded and primary upstream is not circuit-open.
/// Returns 503 otherwise, with a JSON body explaining what's unhealthy.
pub async fn healthz(State(state): State<Arc<ApiState>>) -> impl IntoResponse {
    let filter_loaded = state.filter.domain_count() > 0;
    let upstream_healthy = state
        .upstream
        .as_ref()
        .map(|u| u.is_primary_healthy())
        .unwrap_or(true);

    let healthy = filter_loaded && upstream_healthy;
    let status = if healthy {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    // `filter_loaded` is the whole liveness signal. The corpus SIZE is
    // reconnaissance — it fingerprints which lists an operator subscribes
    // to — and this route is unauthenticated, always registered, and
    // rate-limit exempt. It is one of the three data points the
    // `metrics_enabled` gate exists to withhold, and it stays on the
    // token-gated `/api/status`, which already reports it.
    (
        status,
        Json(serde_json::json!({
            "status": if healthy { "ok" } else { "unhealthy" },
            "filter_loaded": filter_loaded,
            "upstream_healthy": upstream_healthy,
        })),
    )
        .into_response()
}

/// Escape a string for use as a Prometheus label *value*.
///
/// The exposition format requires backslash, double-quote and newline to
/// be escaped; leaving them raw lets a label value close its own quote and
/// forge additional labels or whole samples. Blocklist sources are
/// operator-supplied URLs, so this is attacker-adjacent input in the
/// supply-chain sense project rules rule 4 describes — a hostile list URL must
/// not be able to inject series into the scrape output.
fn escape_metric_label(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            other => out.push(other),
        }
    }
    out
}

/// GET /metrics — OpenMetrics text format exporter.
///
/// Hand-rolled formatter (no external dep). Exposes:
/// - purge_warden_queries_total (counter)
/// - purge_warden_blocked_total (counter)
/// - purge_warden_cache_hits_total (counter)
/// - purge_warden_refused_acl_total (counter)
/// - purge_warden_refused_security_total (counter)
/// - purge_warden_cache_entries (gauge)
/// - purge_warden_domains_loaded (gauge)
/// - purge_warden_uptime_seconds (gauge)
/// - purge_warden_lists_truncated (gauge)
/// - purge_warden_list_truncated_entries{source} (gauge)
pub async fn metrics(State(state): State<Arc<ApiState>>) -> impl IntoResponse {
    let mut out = String::with_capacity(1024);

    // Uptime
    let uptime_secs = state.started_at.elapsed().as_secs();
    out.push_str("# TYPE purge_warden_uptime_seconds gauge\n");
    out.push_str(&format!("purge_warden_uptime_seconds {uptime_secs}\n"));

    // Domain count
    let domains = state.filter.domain_count();
    out.push_str("# TYPE purge_warden_domains_loaded gauge\n");
    out.push_str(&format!("purge_warden_domains_loaded {domains}\n"));

    // Cache entries — deliberately the UNFLUSHED count. This route is
    // unauthenticated and exempt from the API rate limit, so
    // `flushed_usage` here would let any peer that can reach the port
    // pace moka maintenance work on the DNS cache. A gauge sampled once
    // per scrape interval can afford to lag by the pending-task queue;
    // `/api/status` keeps the flushed read, where auth and the rate limit
    // bound how often it can be asked for.
    let cache_entries = state.cache.entry_count();
    out.push_str("# TYPE purge_warden_cache_entries gauge\n");
    out.push_str(&format!("purge_warden_cache_entries {cache_entries}\n"));

    // Blocklist truncation (Lists Integrity 2026-07). Two series, because
    // they answer different questions: the scalar is what an operator
    // alerts on ("am I under-covered at all"), the per-source gauge is what
    // they act on ("which list, and by how much"). Read from
    // `list_statuses` rather than the stats engine — truncation is a
    // property of the last refresh and exists even with tracking disabled.
    if let Some(ref reg) = state.list_statuses {
        let snap = reg.snapshot();
        let truncated_lists = snap.iter().filter(|(_, s)| s.parsed_truncated > 0).count();
        out.push_str("# TYPE purge_warden_lists_truncated gauge\n");
        out.push_str(&format!("purge_warden_lists_truncated {truncated_lists}\n"));
        // Emitted for every source including the healthy ones, so the
        // series exists at 0 and an alert can be written as `> 0`. If only
        // truncated lists appeared, a scrape gap and a healthy list would
        // look identical.
        out.push_str("# TYPE purge_warden_list_truncated_entries gauge\n");
        for (source, s) in snap.iter() {
            out.push_str(&format!(
                "purge_warden_list_truncated_entries{{source=\"{}\"}} {}\n",
                escape_metric_label(source),
                s.parsed_truncated
            ));
        }

        // Global corpus guard. A cycle-level series is not a nicety here:
        // when the guard refuses, every per-source metric above is green —
        // each list downloaded and parsed perfectly — so no alert built on
        // them could fire while the daemon serves a stale corpus.
        // Emitted at 0 in the healthy case so `> 0` is a writable alert
        // and a scrape gap cannot pass for health.
        let refusal = reg.corpus_refusal();
        out.push_str("# TYPE purge_warden_lists_corpus_refused gauge\n");
        out.push_str(&format!(
            "purge_warden_lists_corpus_refused {}\n",
            u8::from(refusal.is_some())
        ));
        if let Some(r) = refusal {
            out.push_str("# TYPE purge_warden_lists_corpus_unique gauge\n");
            out.push_str(&format!("purge_warden_lists_corpus_unique {}\n", r.unique));
            out.push_str("# TYPE purge_warden_lists_corpus_ceiling gauge\n");
            out.push_str(&format!(
                "purge_warden_lists_corpus_ceiling {}\n",
                r.ceiling
            ));
        }
    }

    // Stats counters (from tracking engine)
    if let Some(ref engine) = state.stats {
        let total = engine.global.total_queries.load(Ordering::Relaxed);
        let blocked = engine.global.total_blocked.load(Ordering::Relaxed);
        let hits = engine.global.total_cache_hits.load(Ordering::Relaxed);
        let refused = engine.global.total_refused_acl.load(Ordering::Relaxed);
        let refused_security = engine.global.total_refused_security.load(Ordering::Relaxed);

        out.push_str("# TYPE purge_warden_queries_total counter\n");
        out.push_str(&format!("purge_warden_queries_total {total}\n"));

        out.push_str("# TYPE purge_warden_blocked_total counter\n");
        out.push_str(&format!("purge_warden_blocked_total {blocked}\n"));

        out.push_str("# TYPE purge_warden_cache_hits_total counter\n");
        out.push_str(&format!("purge_warden_cache_hits_total {hits}\n"));

        out.push_str("# TYPE purge_warden_refused_acl_total counter\n");
        out.push_str(&format!("purge_warden_refused_acl_total {refused}\n"));

        // engine-03 (rev-2606): security refusals (REFUSED / RRL_DROP)
        // are also counted in blocked_total; this dedicated series lets a
        // scraper separate content blocks from security refusals.
        out.push_str("# TYPE purge_warden_refused_security_total counter\n");
        out.push_str(&format!(
            "purge_warden_refused_security_total {refused_security}\n"
        ));

        // Derived rates
        let blocked_pct = if total > 0 {
            (blocked as f64 / total as f64) * 100.0
        } else {
            0.0
        };
        // mem2608-s3 / F-P: same correction as socket_server.rs's
        // handle_tracking_stats / compute_24h_stats — blocked queries are
        // decided before the cache is ever consulted and are never
        // cached, so they are a structural non-hit and must not sit in
        // this denominator. blocked_pct above is deliberately unchanged.
        let cacheable = total.saturating_sub(blocked);
        let cache_hit_pct = if cacheable > 0 {
            (hits as f64 / cacheable as f64) * 100.0
        } else {
            0.0
        };
        out.push_str("# TYPE purge_warden_blocked_ratio gauge\n");
        out.push_str(&format!("purge_warden_blocked_ratio {blocked_pct:.2}\n"));
        out.push_str("# TYPE purge_warden_cache_hit_ratio gauge\n");
        out.push_str(&format!(
            "purge_warden_cache_hit_ratio {cache_hit_pct:.2}\n"
        ));

        // Device count — canonical `purge_warden_tracked_devices` plus the
        // legacy `purge_warden_tracked_clients` metric for one release cycle
        // so existing Grafana dashboards keep scraping during T5 rollout.
        let device_count = engine.devices.len();
        out.push_str("# TYPE purge_warden_tracked_devices gauge\n");
        out.push_str(&format!("purge_warden_tracked_devices {device_count}\n"));
        out.push_str("# TYPE purge_warden_tracked_clients gauge\n");
        out.push_str(&format!("purge_warden_tracked_clients {device_count}\n"));
    }

    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        out,
    )
}

/// GET /api/config — read-only config view (secrets redacted).
pub async fn get_config(State(state): State<Arc<ApiState>>) -> impl IntoResponse {
    // §4.27-A: see `read_config_v1` for the spawn_blocking rationale.
    // The response body is now the v1 `ConfigV1` shape.
    match read_config_v1(state.config_path.clone()).await {
        // rev-2606 §07 A2: structural redaction — every credential-bearing
        // field is starred in ONE place (`ConfigV1::redacted`, guarded by
        // the deny-by-default leak test beside it), not name-matched here.
        Ok(config) => Json(config.redacted()).into_response(),
        // §7 review (api-error-bodies-leak-internal-detail): unlike the §4.33
        // IPC path, API error bodies deliberately keep the underlying error
        // detail. Every `/api/*` route sits behind `auth_middleware`, so only an
        // authenticated admin — who can read the config directly anyway — ever
        // sees these; wire-redaction here would add cost without moving the
        // trust boundary. This policy is API-wide, not specific to `get_config`.
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("failed to read config: {e}"),
            }),
        )
            .into_response(),
    }
}

#[cfg(test)]
mod metric_label_tests {
    use super::escape_metric_label;

    /// A blocklist source is an operator-supplied URL, and the exposition
    /// format has no quoting beyond backslash escapes — so an unescaped
    /// value can close its own label and append forged samples. This is the
    /// injection, spelled out: without escaping, the rendered line would
    /// carry a second metric a scraper would happily ingest.
    #[test]
    fn label_escaping_defeats_series_injection() {
        let hostile = r#"evil" } 1
purge_warden_domains_loaded{x=""#;
        let escaped = escape_metric_label(hostile);

        assert!(
            !escaped.contains('\n'),
            "a raw newline ends the sample and starts an attacker-controlled one"
        );
        for (i, c) in escaped.char_indices() {
            if c == '"' {
                assert!(
                    i > 0 && escaped.as_bytes()[i - 1] == b'\\',
                    "every quote must be backslash-escaped or the label closes early"
                );
            }
        }

        // Control: ordinary sources must pass through untouched, otherwise
        // the test above would also pass on a function that mangles input.
        assert_eq!(
            escape_metric_label("https://lists.purge.cc/privacy/ads.txt"),
            "https://lists.purge.cc/privacy/ads.txt"
        );
        assert_eq!(escape_metric_label("privacy/ads"), "privacy/ads");
    }

    #[test]
    fn backslash_is_escaped_before_it_can_eat_a_quote() {
        // `foo\` + `"` would otherwise render as `foo\"` — an escaped
        // quote — letting the value swallow its own terminator.
        assert_eq!(escape_metric_label(r"foo\"), r"foo\\");
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::auth::middleware::AuthRateLimiter;
    use crate::config::settings::{CacheConfig, TrackingConfig};
    use crate::dns::cache::DnsCache;
    use crate::filter::FilterEngine;
    use crate::tracking::StatsEngine;
    use axum::body::Body;
    use axum::http::Request;
    use axum::routing::get;
    use axum::Router;
    use std::time::Instant;
    use tower::util::ServiceExt;

    /// Build the minimum ApiState needed to exercise the per-device
    /// handlers under test. Only `stats` and fields consumed by the
    /// handler need meaningful values; everything else gets a stub.
    pub(crate) fn test_state_with_stats() -> Arc<ApiState> {
        let cache = DnsCache::new(&CacheConfig::default());
        let filter = Arc::new(FilterEngine::new());
        let stats = Arc::new(StatsEngine::new(&TrackingConfig::default()));
        // Seed one row so both responses have a non-empty body.
        stats.record_query(
            std::net::Ipv4Addr::new(10, 0, 0, 42).into(),
            "test.example",
            Some("laptop"),
            Some("default"),
            hickory_proto::rr::RecordType::A,
            false,
            false,
            None,
        );
        let (reload_tx, _reload_rx) = tokio::sync::mpsc::channel(1);
        Arc::new(ApiState {
            filter,
            cache,
            profiles: None,
            stats: Some(stats),
            config_path: "/tmp/test-config.toml".into(),
            token_hash: String::new(),
            rate_limiter: AuthRateLimiter::new(),
            api_rate_limiter: crate::api::rate_limit::ApiRateLimiter::new(60),
            reload_tx,
            started_at: Instant::now(),
            upstream: None,
            listen_addr: "127.0.0.1:15353".into(),
            upstream_mode: "plain".into(),
            upstream_count: 0,
            list_count: 0,
            list_statuses: None,
            list_labels: Arc::new(vec![None; 64]),
            config_write_lock: Arc::new(tokio::sync::Mutex::new(())),
            #[cfg(feature = "cluster")]
            cluster: None,
            #[cfg(feature = "cluster")]
            cluster_observe: None,
        })
    }

    /// Like `test_state_with_stats`, but with a real (verifiable) API
    /// token and a caller-chosen `rate_limit_per_minute` — for
    /// router-level tests that exercise the auth → rate-limit layer
    /// stack. Returns the state plus the plaintext token to present.
    pub(crate) fn test_state_with_rate_limit(limit: u32) -> (Arc<ApiState>, &'static str) {
        const TOKEN: &str = "test-token-rate-limit";
        let cache = DnsCache::new(&CacheConfig::default());
        let filter = Arc::new(FilterEngine::new());
        let stats = Arc::new(StatsEngine::new(&TrackingConfig::default()));
        let (reload_tx, _reload_rx) = tokio::sync::mpsc::channel(1);
        let state = Arc::new(ApiState {
            filter,
            cache,
            profiles: None,
            stats: Some(stats),
            config_path: "/tmp/test-config.toml".into(),
            token_hash: crate::auth::token::hash_token(TOKEN),
            rate_limiter: AuthRateLimiter::new(),
            api_rate_limiter: crate::api::rate_limit::ApiRateLimiter::new(limit),
            reload_tx,
            started_at: Instant::now(),
            upstream: None,
            listen_addr: "127.0.0.1:15353".into(),
            upstream_mode: "plain".into(),
            upstream_count: 0,
            list_count: 0,
            list_statuses: None,
            list_labels: Arc::new(vec![None; 64]),
            config_write_lock: Arc::new(tokio::sync::Mutex::new(())),
            #[cfg(feature = "cluster")]
            cluster: None,
            #[cfg(feature = "cluster")]
            cluster_observe: None,
        });
        (state, TOKEN)
    }

    /// T5 live consumer: legacy `/api/clients` must carry the three
    /// deprecation headers (Deprecation: true, Sunset: <rfc-2822>, Link:
    /// </api/devices>; rel="successor-version") pointing callers at the
    /// canonical replacement. Pairs with the helper introduced in T3.
    #[tokio::test]
    async fn old_path_returns_deprecation_headers() {
        let state = test_state_with_stats();
        let app = Router::new()
            .route("/api/clients", get(get_clients))
            .with_state(state);
        let req = Request::builder()
            .uri("/api/clients")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers().get("deprecation").unwrap(), "true");
        assert!(resp.headers().contains_key("sunset"));
        let link = resp.headers().get("link").unwrap().to_str().unwrap();
        assert!(
            link.contains("</api/devices>") && link.contains("rel=\"successor-version\""),
            "unexpected link header: {link}"
        );
    }

    // ── S43 T2: GET /api/blocklists/:id/stats ──────────────────────────
    //
    // Tests pin: status codes (200 / 404 / 503), the DTO shape on hit,
    // and the slug ↔ exact-match resolution path. Token-gating itself
    // is exercised by the `/api/` `auth_middleware`'s own tests in
    // `auth::middleware::tests`; here we test the handler in isolation
    // (router built without the middleware so we can assert the handler
    // body, not the gate behaviour).
    use crate::lists::status::{BlocklistStatusDto, ListStatus, ListStatusRegistry, ParsedCounts};

    fn test_state_with_blocklists() -> Arc<ApiState> {
        let cache = DnsCache::new(&CacheConfig::default());
        let filter = Arc::new(FilterEngine::new());
        let registry = Arc::new(ListStatusRegistry::new(&[
            "privacy/ads".to_string(),
            "security/malicious".to_string(),
        ]));
        let now = time::OffsetDateTime::now_utc();
        registry.update_for_url(
            "privacy/ads",
            ListStatus::from_refresh(123, ParsedCounts::default(), None, now),
        );
        registry.update_for_url(
            "security/malicious",
            ListStatus::from_refresh(7, ParsedCounts::default(), None, now),
        );
        let (reload_tx, _reload_rx) = tokio::sync::mpsc::channel(1);
        Arc::new(ApiState {
            filter,
            cache,
            profiles: None, // No resolver wired — exact match + substring still work.
            stats: None,
            config_path: "/tmp/test-config.toml".into(),
            token_hash: String::new(),
            rate_limiter: AuthRateLimiter::new(),
            api_rate_limiter: crate::api::rate_limit::ApiRateLimiter::new(60),
            reload_tx,
            started_at: Instant::now(),
            upstream: None,
            listen_addr: "127.0.0.1:15353".into(),
            upstream_mode: "plain".into(),
            upstream_count: 0,
            list_count: 2,
            list_statuses: Some(registry),
            list_labels: Arc::new(vec![None; 64]),
            config_write_lock: Arc::new(tokio::sync::Mutex::new(())),
            #[cfg(feature = "cluster")]
            cluster: None,
            #[cfg(feature = "cluster")]
            cluster_observe: None,
        })
    }

    fn test_state_no_blocklists() -> Arc<ApiState> {
        let cache = DnsCache::new(&CacheConfig::default());
        let filter = Arc::new(FilterEngine::new());
        let (reload_tx, _reload_rx) = tokio::sync::mpsc::channel(1);
        Arc::new(ApiState {
            filter,
            cache,
            profiles: None,
            stats: None,
            config_path: "/tmp/test-config.toml".into(),
            token_hash: String::new(),
            rate_limiter: AuthRateLimiter::new(),
            api_rate_limiter: crate::api::rate_limit::ApiRateLimiter::new(60),
            reload_tx,
            started_at: Instant::now(),
            upstream: None,
            listen_addr: "127.0.0.1:15353".into(),
            upstream_mode: "plain".into(),
            upstream_count: 0,
            list_count: 0,
            list_statuses: None,
            list_labels: Arc::new(vec![None; 64]),
            config_write_lock: Arc::new(tokio::sync::Mutex::new(())),
            #[cfg(feature = "cluster")]
            cluster: None,
            #[cfg(feature = "cluster")]
            cluster_observe: None,
        })
    }

    async fn read_body_json(resp: axum::response::Response) -> serde_json::Value {
        let body_bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .unwrap();
        serde_json::from_slice(&body_bytes).unwrap()
    }

    /// §4.2 G1a — `GET /api/query/{domain}` carries block attribution.
    /// A default profile with `block_all` blocks every name via the
    /// admin layer → `blocked_by = "admin_block"` present in the JSON.
    #[tokio::test]
    async fn query_domain_reports_block_source() {
        use crate::config::schema::{ConfigV1, Id, Profile};
        use crate::profiles::ProfileResolver;

        let mut config = ConfigV1 {
            schema_version: 3,
            ..Default::default()
        };
        config.profiles.insert(
            "strict".into(),
            Profile {
                block_all: true,
                ..Default::default()
            },
        );
        config.server.default_profile = Some(Id::new("strict").unwrap());
        let bit_map = crate::lists::source_key::SourceBitMap::default();
        let profiles = Arc::new(ProfileResolver::build(
            &config,
            &bit_map,
            &crate::config::custom_list::CustomListStore::new(),
        ));

        let (reload_tx, _reload_rx) = tokio::sync::mpsc::channel(1);
        let state = Arc::new(ApiState {
            filter: Arc::new(FilterEngine::new()),
            cache: DnsCache::new(&CacheConfig::default()),
            profiles: Some(profiles),
            stats: None,
            config_path: "/tmp/test-config.toml".into(),
            token_hash: String::new(),
            rate_limiter: AuthRateLimiter::new(),
            api_rate_limiter: crate::api::rate_limit::ApiRateLimiter::new(60),
            reload_tx,
            started_at: Instant::now(),
            upstream: None,
            listen_addr: "127.0.0.1:15353".into(),
            upstream_mode: "plain".into(),
            upstream_count: 0,
            list_count: 0,
            list_statuses: None,
            list_labels: Arc::new(vec![None; 64]),
            config_write_lock: Arc::new(tokio::sync::Mutex::new(())),
            #[cfg(feature = "cluster")]
            cluster: None,
            #[cfg(feature = "cluster")]
            cluster_observe: None,
        });

        let app = Router::new()
            .route("/api/query/{domain}", get(query_domain))
            .with_state(state);
        let req = Request::builder()
            .uri("/api/query/anything.example")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = read_body_json(resp).await;
        assert_eq!(body["blocked"], serde_json::json!(true));
        assert_eq!(body["blocked_by"], serde_json::json!("admin_block"));
    }

    #[tokio::test]
    async fn blocklist_stats_returns_200_with_dto_on_exact_match() {
        let state = test_state_with_blocklists();
        let app = Router::new()
            .route("/api/blocklists/{id}/stats", get(get_blocklist_stats))
            .with_state(state);
        let req = Request::builder()
            .uri("/api/blocklists/privacy%2Fads/stats")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body: BlocklistStatusDto = serde_json::from_value(read_body_json(resp).await).unwrap();
        assert_eq!(body.source, "privacy/ads");
        assert_eq!(body.entries, 123);
    }

    #[tokio::test]
    async fn blocklist_stats_returns_404_for_unknown_id() {
        let state = test_state_with_blocklists();
        let app = Router::new()
            .route("/api/blocklists/{id}/stats", get(get_blocklist_stats))
            .with_state(state);
        let req = Request::builder()
            .uri("/api/blocklists/no-such-list/stats")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        let body = read_body_json(resp).await;
        assert!(
            body["error"].as_str().unwrap().contains("not found"),
            "unexpected error body: {body}"
        );
    }

    #[tokio::test]
    async fn blocklist_stats_returns_503_when_no_registry() {
        // Daemon started with no `[lists].sources` → registry is None.
        // Surface as 503 with an explanatory error rather than 200 of
        // an empty list (which would mislead the operator into thinking
        // their config has zero sources rather than telemetry being
        // unavailable).
        let state = test_state_no_blocklists();
        let app = Router::new()
            .route("/api/blocklists/{id}/stats", get(get_blocklist_stats))
            .with_state(state);
        let req = Request::builder()
            .uri("/api/blocklists/privacy%2Fads/stats")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn blocklist_stats_substring_fallback_resolves_partial_id() {
        // Pass 3 of the resolver: `ads` is a substring of `privacy/ads`.
        // No resolver wired in test state → pass 1/2 miss; pass 3 hits.
        let state = test_state_with_blocklists();
        let app = Router::new()
            .route("/api/blocklists/{id}/stats", get(get_blocklist_stats))
            .with_state(state);
        let req = Request::builder()
            .uri("/api/blocklists/ads/stats")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body: BlocklistStatusDto = serde_json::from_value(read_body_json(resp).await).unwrap();
        assert_eq!(body.source, "privacy/ads");
    }

    // ── T3.9 M-41: deterministic substring fallback ─────────────────
    //
    // The pass-3 substring scan walks `ListStatusRegistry::snapshot()`
    // which returns a `Vec` whose order mirrors the inner HashMap's
    // RandomState — non-deterministic across calls. Two sources whose
    // names both contain the operator's needle would otherwise be
    // resolved to whichever the HashMap happened to yield first.
    // The fix sorts longer-first then lexicographic, so repeated calls
    // converge on the same answer.

    fn registry_with_overlapping_substrings() -> Arc<ApiState> {
        let cache = DnsCache::new(&CacheConfig::default());
        let filter = Arc::new(FilterEngine::new());
        // Two sources whose names both contain `track` as a substring
        // (without exact-matching it, so pass 1 falls through and pass
        // 3 actually fires). The longer + more specific name should
        // win regardless of insertion or HashMap iteration order.
        let registry = Arc::new(ListStatusRegistry::new(&[
            "privacy/track".to_string(),
            "privacy/tracking-extended".to_string(),
            "security/malicious".to_string(),
        ]));
        let now = time::OffsetDateTime::now_utc();
        registry.update_for_url(
            "privacy/track",
            ListStatus::from_refresh(1, ParsedCounts::default(), None, now),
        );
        registry.update_for_url(
            "privacy/tracking-extended",
            ListStatus::from_refresh(2, ParsedCounts::default(), None, now),
        );
        registry.update_for_url(
            "security/malicious",
            ListStatus::from_refresh(3, ParsedCounts::default(), None, now),
        );
        let (reload_tx, _reload_rx) = tokio::sync::mpsc::channel(1);
        Arc::new(ApiState {
            filter,
            cache,
            profiles: None,
            stats: None,
            config_path: "/tmp/test-config.toml".into(),
            token_hash: String::new(),
            rate_limiter: AuthRateLimiter::new(),
            api_rate_limiter: crate::api::rate_limit::ApiRateLimiter::new(60),
            reload_tx,
            started_at: Instant::now(),
            upstream: None,
            listen_addr: "127.0.0.1:15353".into(),
            upstream_mode: "plain".into(),
            upstream_count: 0,
            list_count: 3,
            list_statuses: Some(registry),
            list_labels: Arc::new(vec![None; 64]),
            config_write_lock: Arc::new(tokio::sync::Mutex::new(())),
            #[cfg(feature = "cluster")]
            cluster: None,
            #[cfg(feature = "cluster")]
            cluster_observe: None,
        })
    }

    #[tokio::test]
    async fn blocklist_stats_substring_fallback_is_deterministic() {
        // 32 successive calls with two sources sharing a substring must
        // resolve to the same source every time. Pre-fix this would flap
        // because HashMap iteration order is randomised per process and
        // (for some implementations) per-call.
        let state = registry_with_overlapping_substrings();
        let app = Router::new()
            .route("/api/blocklists/{id}/stats", get(get_blocklist_stats))
            .with_state(state);

        let mut seen: Option<String> = None;
        for _ in 0..32 {
            let req = Request::builder()
                .uri("/api/blocklists/rack/stats")
                .body(Body::empty())
                .unwrap();
            let resp = app.clone().oneshot(req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
            let body: BlocklistStatusDto =
                serde_json::from_value(read_body_json(resp).await).unwrap();
            match &seen {
                None => seen = Some(body.source),
                Some(prev) => assert_eq!(
                    prev, &body.source,
                    "substring fallback returned a different source across calls",
                ),
            }
        }
        // Longer-match-first contract: `privacy/tracking-extended` is
        // more specific than `privacy/track`, so it wins.
        assert_eq!(seen.unwrap(), "privacy/tracking-extended");
    }

    #[tokio::test]
    async fn blocklist_stats_rejects_empty_id_with_400() {
        // An empty `id` substring-matches every source (every string
        // contains the empty string), so pass 3 would otherwise return
        // an arbitrary source. Reject up-front with a 400 + plain-English
        // hint so the operator learns the input shape is wrong.
        let state = test_state_with_blocklists();
        let app = Router::new()
            .route("/api/blocklists/{id}/stats", get(get_blocklist_stats))
            // Also accept the bare path so the empty-id test reaches
            // the handler — axum's path extractor would otherwise
            // 404 on `/api/blocklists//stats` before our handler runs.
            .route(
                "/api/blocklists/stats-empty-id",
                get(|State(state): State<Arc<ApiState>>| async move {
                    get_blocklist_stats(State(state), Path(String::new())).await
                }),
            )
            .with_state(state);
        let req = Request::builder()
            .uri("/api/blocklists/stats-empty-id")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = read_body_json(resp).await;
        assert!(
            body["error"]
                .as_str()
                .unwrap()
                .contains("must not be empty"),
            "unexpected error body: {body}"
        );
    }

    // ── T3.9 M-42: per-field length caps via custom serde deserializer ──
    //
    // Each body / query type now annotates string fields with a
    // bounded-string deserialize_with. The cap fires at deserialization
    // time so an attacker can't induce per-field allocation by
    // submitting a JSON body whose `domain` is hundreds of MB.
    // Tests pin (a) the under-cap accept path round-trips, (b) the
    // over-cap reject path errors with the field name + limit visible,
    // and (c) the cap fires at deserialization time on the JSON body
    // itself (boundary surfaced through the Json extractor).

    #[test]
    fn list_body_accepts_id_at_cap() {
        let id = "a".repeat(256);
        let body = serde_json::json!({ "id": id });
        let parsed: ListBody = serde_json::from_value(body).unwrap();
        assert_eq!(parsed.id.len(), 256);
    }

    fn expect_serde_err<T>(r: Result<T, serde_json::Error>) -> serde_json::Error {
        match r {
            Ok(_) => panic!("expected deserialization error, got Ok"),
            Err(e) => e,
        }
    }

    #[test]
    fn list_body_rejects_id_one_byte_over_cap() {
        let id = "a".repeat(257);
        let body = serde_json::json!({ "id": id });
        let err = expect_serde_err(serde_json::from_value::<ListBody>(body));
        let msg = err.to_string();
        assert!(
            msg.contains("'id'") && msg.contains("257") && msg.contains("256"),
            "expected field+sizes in error, got: {msg}"
        );
    }

    #[test]
    fn whitelist_body_rejects_domain_over_253() {
        let domain = "a".repeat(254);
        let body = serde_json::json!({ "domain": domain });
        let err = expect_serde_err(serde_json::from_value::<WhitelistBody>(body));
        let msg = err.to_string();
        assert!(
            msg.contains("'domain'") && msg.contains("254") && msg.contains("253"),
            "expected field+sizes in error, got: {msg}"
        );
    }

    #[test]
    fn logs_query_rejects_overlong_domain() {
        // The deserialize_with helper runs against any deserializer,
        // so a JSON-shaped value is sufficient to pin the cap. axum's
        // Query<LogsQuery> extractor uses serde_urlencoded which calls
        // the same Visitor::visit_str path under the hood.
        let domain = "a".repeat(254);
        let body = serde_json::json!({ "domain": domain });
        let err = expect_serde_err(serde_json::from_value::<LogsQuery>(body));
        let msg = err.to_string();
        assert!(
            msg.contains("'domain'") && msg.contains("253"),
            "expected field+limit in error, got: {msg}"
        );
    }

    #[test]
    fn logs_query_rejects_overlong_client() {
        let client = "a".repeat(254);
        let body = serde_json::json!({ "client": client });
        let err = expect_serde_err(serde_json::from_value::<LogsQuery>(body));
        let msg = err.to_string();
        assert!(
            msg.contains("'client'") && msg.contains("253"),
            "expected field+limit in error, got: {msg}"
        );
    }

    #[test]
    fn logs_query_accepts_under_cap_domain_and_client() {
        // Round-trip: an under-cap, non-empty domain + client must
        // deserialize cleanly. Pins the happy path against an
        // accidental over-tightening of the helper.
        let body = serde_json::json!({
            "domain": "ads.example.com",
            "client": "alex-laptop",
            "blocked": true,
        });
        let parsed: LogsQuery = serde_json::from_value(body).unwrap();
        assert_eq!(parsed.domain.as_deref(), Some("ads.example.com"));
        assert_eq!(parsed.client.as_deref(), Some("alex-laptop"));
        assert!(parsed.blocked);
    }

    #[tokio::test]
    async fn add_list_returns_400_on_overlong_id_via_router() {
        // End-to-end: oversized JSON `id` reaches the axum Json extractor,
        // serde rejects at deserialization, axum surfaces the error as a
        // 400 (or 422 in some axum versions). The handler body never runs,
        // so the config write lock is never touched. Mirrors the M-42
        // security guarantee at the trust boundary, not just the unit
        // level.
        let initial = "schema_version = 3\n\n[profiles.default]\ndisplay_name = \"Default\"\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n";
        let path = api_mutation_temp_config(initial, "m42-overlong-id");
        let state = test_state_with_config_path(path.clone());
        let app = Router::new()
            .route("/api/lists/add", axum::routing::post(add_list))
            .with_state(state);
        let body = serde_json::json!({ "id": "a".repeat(257) });
        let req = Request::builder()
            .uri("/api/lists/add")
            .method("POST")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        // axum maps deserialization errors to 422 by default for Json
        // extractor failures; some versions return 400. Either is fine
        // for our purposes — both are 4xx and the body never reaches
        // the handler.
        let status = resp.status().as_u16();
        assert!(
            (400..500).contains(&status),
            "expected 4xx for over-cap id, got {status}"
        );
        let _ = std::fs::remove_file(&path);
    }

    // ── T2.8 H-15: shared config_write_lock concurrency regression ─────
    //
    // Two POST `/api/lists/add` calls fired concurrently against the
    // same config file MUST both persist — without the lock the second
    // would read the same config the first did, push its own id,
    // and overwrite the first's append (last-writer-wins). Mirrors
    // `client_add_concurrent_calls_serialize_through_write_lock` in
    // `ipc/socket_server.rs` so the IPC + REST trust boundaries are
    // exercised symmetrically.
    fn api_mutation_temp_config(content: &str, suffix: &str) -> std::path::PathBuf {
        let path = std::path::PathBuf::from(format!(
            "/tmp/purge-warden-test-api-mut-{}-{suffix}.toml",
            std::process::id()
        ));
        std::fs::write(&path, content).unwrap();
        path
    }

    /// §4.27-A: load the v1 config for post-mutation assertions.
    /// Replaces the pre-migration `Settings::from_file(&path)` checks —
    /// the API mutation handlers are now v1-native.
    fn load_v1(path: &std::path::Path) -> crate::config::schema::ConfigV1 {
        crate::config::loader::load_config(path, time::OffsetDateTime::now_utc())
            .expect("v1 config must load")
            .config
    }

    /// Build an `ApiState` for mutation-handler tests that:
    ///  - persists the receiver in a background drain task so
    ///    `reload_tx.send(...).await` does NOT see a closed channel
    ///    (would surface as a H-17 500 and mask the test's real
    ///    assertion);
    ///  - shares an isolated, fresh `config_write_lock`.
    fn test_state_with_config_path(path: std::path::PathBuf) -> Arc<ApiState> {
        let cache = DnsCache::new(&CacheConfig::default());
        let filter = Arc::new(FilterEngine::new());
        let (reload_tx, mut reload_rx) = tokio::sync::mpsc::channel::<Option<u32>>(1);
        // Detach a drain task so the receiver outlives the helper return.
        tokio::spawn(async move { while reload_rx.recv().await.is_some() {} });
        Arc::new(ApiState {
            filter,
            cache,
            profiles: None,
            stats: None,
            config_path: path,
            token_hash: String::new(),
            rate_limiter: AuthRateLimiter::new(),
            api_rate_limiter: crate::api::rate_limit::ApiRateLimiter::new(60),
            reload_tx,
            started_at: Instant::now(),
            upstream: None,
            listen_addr: "127.0.0.1:15353".into(),
            upstream_mode: "plain".into(),
            upstream_count: 0,
            list_count: 0,
            list_statuses: None,
            list_labels: Arc::new(vec![None; 64]),
            config_write_lock: Arc::new(tokio::sync::Mutex::new(())),
            #[cfg(feature = "cluster")]
            cluster: None,
            #[cfg(feature = "cluster")]
            cluster_observe: None,
        })
    }

    /// rev-2606 §07 A2: `GET /api/config` must star BOTH bearer-token
    /// hashes — `cluster.token_hash` used to ship verbatim while
    /// `api.token_hash` beside it was redacted. Asserts no 64-hex secret
    /// survives anywhere in the body.
    #[tokio::test]
    async fn get_config_redacts_cluster_token_hash() {
        let api_hash = "a".repeat(64);
        let cluster_hash = "b".repeat(64);
        let initial = format!(
            "schema_version = 3\n\n[api]\ntoken_hash = \"{api_hash}\"\n\n\
             [cluster]\ntoken_hash = \"{cluster_hash}\"\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n"
        );
        let path = api_mutation_temp_config(&initial, "a2-redaction");
        let state = test_state_with_config_path(path.clone());

        let resp = get_config(State(state)).await.into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        let body = std::str::from_utf8(&bytes).unwrap();
        let json: serde_json::Value = serde_json::from_str(body).unwrap();

        assert_eq!(json["api"]["token_hash"], "***");
        assert_eq!(json["cluster"]["token_hash"], "***");
        assert!(
            !body.contains(&api_hash) && !body.contains(&cluster_hash),
            "no 64-hex secret may survive anywhere in the body"
        );
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn h_15_add_list_concurrent_calls_serialize_through_write_lock() {
        // Mirrors the IPC concurrency regression test
        // (`client_add_concurrent_calls_serialize_through_write_lock`).
        let initial = "schema_version = 3\n\n[profiles.default]\ndisplay_name = \"Default\"\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n";
        let path = api_mutation_temp_config(initial, "h15-concurrent");
        let state = test_state_with_config_path(path.clone());

        let s1 = state.clone();
        let s2 = state.clone();

        let h1 = tokio::spawn(async move {
            add_list(
                State(s1),
                Json(ListBody {
                    id: "https://example.com/list-one.txt".into(),
                }),
            )
            .await
            .into_response()
        });
        let h2 = tokio::spawn(async move {
            add_list(
                State(s2),
                Json(ListBody {
                    id: "https://example.com/list-two.txt".into(),
                }),
            )
            .await
            .into_response()
        });

        let r1 = h1.await.unwrap();
        let r2 = h2.await.unwrap();
        assert_eq!(r1.status(), StatusCode::OK);
        assert_eq!(r2.status(), StatusCode::OK);

        let config = load_v1(&path);
        assert_eq!(
            config.lists.sources.len(),
            2,
            "both concurrent adds must persist (write lock works)"
        );
        assert!(config
            .lists
            .sources
            .iter()
            .any(|src| src == "https://example.com/list-one.txt"));
        assert!(config
            .lists
            .sources
            .iter()
            .any(|src| src == "https://example.com/list-two.txt"));

        std::fs::remove_file(&path).ok();
    }

    // ── T2.8 H-16: domain validation at the API trust boundary ────────
    //
    // The shared `config::schema::admin_rule::validate_domain` is
    // already exhaustively tested for individual rule semantics
    // (~20 unit tests in admin_rule.rs). These tests pin only the
    // **API-surface contract**: 400 status, plain-English body, and
    // that the validator is actually being called from the handler
    // (not bypassed) for each of the three call-sites.
    #[tokio::test]
    async fn h_16_add_whitelist_rejects_double_dot_with_400() {
        let initial = "schema_version = 3\n\n[profiles.default]\ndisplay_name = \"Default\"\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n";
        let path = api_mutation_temp_config(initial, "h16-wl-double-dot");
        let state = test_state_with_config_path(path.clone());

        let resp = add_whitelist(
            State(state),
            Json(WhitelistBody {
                domain: "bad..example.com".into(),
            }),
        )
        .await
        .into_response();

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = read_body_json(resp).await;
        let msg = body["error"].as_str().unwrap();
        assert!(
            msg.contains("not a valid domain"),
            "operator-facing 400 must say 'not a valid domain', got: {msg}"
        );
        assert!(
            msg.contains("consecutive dots"),
            "400 must explain the specific violation, got: {msg}"
        );

        // Rejected before the lock + before disk write — file unchanged.
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(!raw.contains("bad..example.com"));
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn h_16_add_whitelist_rejects_control_char_with_400() {
        let initial = "schema_version = 3\n\n[profiles.default]\ndisplay_name = \"Default\"\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n";
        let path = api_mutation_temp_config(initial, "h16-wl-ctrl");
        let state = test_state_with_config_path(path.clone());

        // Newline in the body — log injection vector if accepted.
        let resp = add_whitelist(
            State(state),
            Json(WhitelistBody {
                domain: "evil.com\nINJECTED".into(),
            }),
        )
        .await
        .into_response();

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = read_body_json(resp).await;
        let msg = body["error"].as_str().unwrap();
        assert!(
            msg.contains("control byte"),
            "control-char 400 must name the violation, got: {msg}"
        );
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn h_16_add_whitelist_rejects_oversize_label_with_400() {
        let initial = "schema_version = 3\n\n[profiles.default]\ndisplay_name = \"Default\"\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n";
        let path = api_mutation_temp_config(initial, "h16-wl-oversize");
        let state = test_state_with_config_path(path.clone());

        // 64-octet label exceeds RFC 1035's 63-octet limit.
        let oversize_label = "a".repeat(64);
        let resp = add_whitelist(
            State(state),
            Json(WhitelistBody {
                domain: format!("{oversize_label}.example.com"),
            }),
        )
        .await
        .into_response();

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn h_16_remove_whitelist_rejects_invalid_domain_with_400() {
        let initial = "schema_version = 3\n\n[profiles.default]\ndisplay_name = \"Default\"\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n";
        let path = api_mutation_temp_config(initial, "h16-wl-rm-bad");
        let state = test_state_with_config_path(path.clone());

        let resp = remove_whitelist(
            State(state),
            Json(WhitelistBody {
                domain: ".leading-dot.com".into(),
            }),
        )
        .await
        .into_response();

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn h_16_query_domain_rejects_invalid_path_segment_with_400() {
        let cache = DnsCache::new(&CacheConfig::default());
        let filter = Arc::new(FilterEngine::new());
        let (reload_tx, _rx) = tokio::sync::mpsc::channel(1);
        let state = Arc::new(ApiState {
            filter,
            cache,
            profiles: None,
            stats: None,
            config_path: "/tmp/unused.toml".into(),
            token_hash: String::new(),
            rate_limiter: AuthRateLimiter::new(),
            api_rate_limiter: crate::api::rate_limit::ApiRateLimiter::new(60),
            reload_tx,
            started_at: Instant::now(),
            upstream: None,
            listen_addr: "127.0.0.1:15353".into(),
            upstream_mode: "plain".into(),
            upstream_count: 0,
            list_count: 0,
            list_statuses: None,
            list_labels: Arc::new(vec![None; 64]),
            config_write_lock: Arc::new(tokio::sync::Mutex::new(())),
            #[cfg(feature = "cluster")]
            cluster: None,
            #[cfg(feature = "cluster")]
            cluster_observe: None,
        });

        let resp = query_domain(State(state), Path("bad..example.com".into()))
            .await
            .into_response();

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn h_16_add_whitelist_lowercases_canonical_form() {
        // Validator returns the lowercased canonical form; the
        // resulting `@@||...^` rule on disk must use it, regardless of
        // how the operator capitalised the input. This makes the
        // disk-side rule list deterministic for downstream filter
        // engine matching.
        let initial = "schema_version = 3\n\n[profiles.default]\ndisplay_name = \"Default\"\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n";
        let path = api_mutation_temp_config(initial, "h16-wl-lower");
        let state = test_state_with_config_path(path.clone());

        let resp = add_whitelist(
            State(state),
            Json(WhitelistBody {
                domain: "Example.COM".into(),
            }),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::OK);

        // v1: the rule lands as an `[[admin_rules]]` row referenced by
        // `profiles.default.admin_rules`. Reconstruct the allow-rule
        // strings the same way `get_whitelist` does.
        let config = load_v1(&path);
        let profile = config
            .profiles
            .get("default")
            .expect("default profile must exist");
        let allow: Vec<&str> = profile
            .admin_rules
            .iter()
            .filter_map(|rid| {
                config
                    .admin_rules
                    .iter()
                    .find(|ar| ar.id.as_str() == rid.as_str())
            })
            .map(|ar| ar.rule.as_str())
            .collect();
        assert!(
            allow.contains(&"@@||example.com^"),
            "rule must use canonical lowercase, got: {allow:?}"
        );
        std::fs::remove_file(&path).ok();
    }

    // ── §4.27-A: the REST API now mutates v1 masters natively ─────────
    //
    // Pre-§4.27-A the API only spoke v0 `Settings`; a v1 master tripped
    // the writer's `guard_against_v1_master` and the handler returned
    // 409 with a "use the CLI instead" hint (the T2.8 H-19 behaviour).
    // The mutation path is v1-native now — these tests pin that the
    // endpoints succeed on a v1 master and the change lands in the v1
    // schema. (They are the inverted successors of the two
    // `h_19_*_on_v1_master_returns_409_with_cli_hint` tests.)
    #[tokio::test]
    async fn add_list_on_v1_master_succeeds() {
        let initial = "schema_version = 3\n\n[profiles.default]\ndisplay_name = \"Default\"\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n";
        let path = api_mutation_temp_config(initial, "v1-add-list");
        let state = test_state_with_config_path(path.clone());

        let resp = add_list(
            State(state),
            Json(ListBody {
                id: "https://example.com/list-v1.txt".into(),
            }),
        )
        .await
        .into_response();

        assert_eq!(resp.status(), StatusCode::OK);

        // The source landed in the v1 `[lists].sources` table.
        let config = load_v1(&path);
        assert!(
            config
                .lists
                .sources
                .iter()
                .any(|src| src == "https://example.com/list-v1.txt"),
            "add_list must persist into the v1 [lists].sources, got: {:?}",
            config.lists.sources
        );

        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn add_whitelist_on_v1_master_succeeds() {
        let initial = "schema_version = 3\n\n[profiles.default]\ndisplay_name = \"Default\"\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n";
        let path = api_mutation_temp_config(initial, "v1-add-wl");
        let state = test_state_with_config_path(path.clone());

        let resp = add_whitelist(
            State(state),
            Json(WhitelistBody {
                domain: "example.com".into(),
            }),
        )
        .await
        .into_response();

        assert_eq!(resp.status(), StatusCode::OK);

        // The allow rule landed as an `[[admin_rules]]` row referenced
        // by `profiles.default.admin_rules`.
        let config = load_v1(&path);
        let profile = config
            .profiles
            .get("default")
            .expect("default profile must exist");
        let has_rule = profile.admin_rules.iter().any(|rid| {
            config
                .admin_rules
                .iter()
                .any(|ar| ar.id.as_str() == rid.as_str() && ar.rule == "@@||example.com^")
        });
        assert!(
            has_rule,
            "add_whitelist must reference an @@||example.com^ admin rule from the default profile"
        );

        std::fs::remove_file(&path).ok();
    }

    // ── T2.8 H-17: closed reload channel surfaces as 500 ──────────────
    #[tokio::test]
    async fn h_17_add_list_reload_channel_closed_returns_500_with_restart_hint() {
        // Drop the receiver immediately — the next `send().await` on
        // the sender returns `SendError`, simulating "daemon shutting
        // down" between the disk write and the reload notification.
        let initial = "schema_version = 3\n\n[profiles.default]\ndisplay_name = \"Default\"\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n";
        let path = api_mutation_temp_config(initial, "h17-closed");

        let cache = DnsCache::new(&CacheConfig::default());
        let filter = Arc::new(FilterEngine::new());
        let (reload_tx, reload_rx) = tokio::sync::mpsc::channel::<Option<u32>>(1);
        drop(reload_rx);
        let state = Arc::new(ApiState {
            filter,
            cache,
            profiles: None,
            stats: None,
            config_path: path.clone(),
            token_hash: String::new(),
            rate_limiter: AuthRateLimiter::new(),
            api_rate_limiter: crate::api::rate_limit::ApiRateLimiter::new(60),
            reload_tx,
            started_at: Instant::now(),
            upstream: None,
            listen_addr: "127.0.0.1:15353".into(),
            upstream_mode: "plain".into(),
            upstream_count: 0,
            list_count: 0,
            list_statuses: None,
            list_labels: Arc::new(vec![None; 64]),
            config_write_lock: Arc::new(tokio::sync::Mutex::new(())),
            #[cfg(feature = "cluster")]
            cluster: None,
            #[cfg(feature = "cluster")]
            cluster_observe: None,
        });

        let resp = add_list(
            State(state),
            Json(ListBody {
                id: "https://example.com/list-h17.txt".into(),
            }),
        )
        .await
        .into_response();

        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = read_body_json(resp).await;
        let msg = body["error"].as_str().unwrap();
        assert!(
            msg.contains("systemctl reload purge-warden"),
            "operator-facing 500 must name the recovery command, got: {msg}"
        );
        // `reload`, NOT `restart`: warden binds its listener after ingesting
        // the blocklists, so a restart costs a real DNS outage (~80s on a
        // 12M-domain install) where SIGHUP costs nothing. The unit ships
        // `ExecReload=/bin/kill -HUP $MAINPID` and `signal_loop`'s SIGHUP arm
        // reaches the same `handle_reload` the IPC path failed to.
        assert!(
            !msg.contains("systemctl restart purge-warden"),
            "recommending a restart here buys an outage for nothing, got: {msg}"
        );
        assert!(
            !msg.contains("SendError"),
            "operator-facing 500 must NOT leak the internal channel error type, got: {msg}"
        );

        // Disk write still happened — the change is durable, only the
        // in-memory reload was lost. That is the worst-case fault model
        // H-17 makes visible.
        let config = load_v1(&path);
        assert_eq!(config.lists.sources.len(), 1);
        assert!(config
            .lists
            .sources
            .iter()
            .any(|src| src == "https://example.com/list-h17.txt"));

        std::fs::remove_file(&path).ok();
    }

    /// The liveness probe is unauthenticated, always registered and
    /// rate-limit exempt, so its body is the one API surface an operator
    /// cannot switch off. Pin the exact key set rather than the absence of
    /// one string: a re-added corpus gauge under any other name is the same
    /// disclosure, and `metrics_enabled` exists to withhold it.
    #[tokio::test]
    async fn healthz_body_carries_only_the_liveness_contract() {
        let state = test_state_with_stats();
        let resp = healthz(State(state)).await.into_response();
        let body = read_body_json(resp).await;
        let mut keys: Vec<&str> = body
            .as_object()
            .expect("healthz body is a JSON object")
            .keys()
            .map(|k| k.as_str())
            .collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            vec!["filter_loaded", "status", "upstream_healthy"],
            "healthz must publish liveness booleans only, got: {body}"
        );
    }

    /// A source the fetcher will refuse is a subscription that filters
    /// nothing, so answering 200 for it is the defect. Refused before the
    /// write, leaving the config byte-identical.
    #[tokio::test]
    async fn add_list_refuses_a_url_the_fetcher_would_reject() {
        let initial = "schema_version = 3\n\n[profiles.default]\ndisplay_name = \"Default\"\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n";
        let path = api_mutation_temp_config(initial, "addlist-bad-url");
        let before = std::fs::read(&path).expect("fixture readable");
        let state = test_state_with_config_path(path.clone());

        let resp = add_list(
            State(state),
            Json(ListBody {
                id: "http://example.com/plain.txt".into(),
            }),
        )
        .await
        .into_response();

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            std::fs::read(&path).expect("fixture readable"),
            before,
            "a refused source must not reach disk"
        );
        std::fs::remove_file(&path).ok();
    }

    /// `[lists].sources` also holds slash-form catalogue slugs, which are
    /// not URLs — the guard must not swallow them.
    #[tokio::test]
    async fn add_list_still_accepts_a_catalogue_slug() {
        let initial = "schema_version = 3\n\n[profiles.default]\ndisplay_name = \"Default\"\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n";
        let path = api_mutation_temp_config(initial, "addlist-slug");
        let state = test_state_with_config_path(path.clone());

        let resp = add_list(
            State(state),
            Json(ListBody {
                id: "privacy/ads".into(),
            }),
        )
        .await
        .into_response();

        assert_eq!(resp.status(), StatusCode::OK);
        let config = load_v1(&path);
        assert!(
            config.lists.sources.iter().any(|src| src == "privacy/ads"),
            "a catalogue slug must still persist, got: {:?}",
            config.lists.sources
        );
        std::fs::remove_file(&path).ok();
    }

    /// Keeps whatever the `fmt` layer wrote, so a test can read the audit
    /// line the operator's log would have received.
    #[derive(Clone, Default)]
    struct AuditSink(Arc<std::sync::Mutex<Vec<u8>>>);

    impl AuditSink {
        fn text(&self) -> String {
            String::from_utf8(self.0.lock().expect("audit sink").clone())
                .expect("fmt output is utf8")
        }
    }

    impl std::io::Write for AuditSink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().expect("audit sink").extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for AuditSink {
        type Writer = AuditSink;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    /// A thread-local audit capture that survives running beside its
    /// siblings.
    ///
    /// `tracing` caches each callsite's interest process-wide, and while
    /// only ONE dispatcher is registered that cache is computed against
    /// whichever thread happens to reach the callsite first. A parallel
    /// test that touches the same audit line first therefore caches
    /// `never`, after which this thread's subscriber is never consulted
    /// and the capture comes back empty — a failure with nothing to do
    /// with the code under test. Keeping a second dispatcher registered
    /// forces the full-list rebuild, which resolves the callsite the same
    /// way whichever thread asks.
    struct AuditCapture {
        sink: AuditSink,
        _forces_full_list_rebuild: tracing::Dispatch,
        _default: tracing::subscriber::DefaultGuard,
    }

    impl AuditCapture {
        fn arm() -> Self {
            fn subscriber(sink: AuditSink) -> impl tracing::Subscriber + Send + Sync + 'static {
                tracing_subscriber::fmt()
                    .with_writer(sink)
                    .with_ansi(false)
                    .finish()
            }
            let sink = AuditSink::default();
            let second = tracing::Dispatch::new(subscriber(AuditSink::default()));
            let default = tracing::subscriber::set_default(subscriber(sink.clone()));
            Self {
                sink,
                _forces_full_list_rebuild: second,
                _default: default,
            }
        }

        fn text(&self) -> String {
            self.sink.text()
        }
    }

    /// Default (current-thread) runtime on purpose: the audit line is
    /// emitted after an `await` on `spawn_blocking`, and the subscriber
    /// is installed on *this* thread only. A multi-threaded runtime could
    /// resume the continuation on a worker that has no capture armed.
    #[tokio::test]
    async fn whitelist_mutations_audit_the_rule_that_reached_disk() {
        let initial = "schema_version = 3\n\n[profiles.default]\ndisplay_name = \"Default\"\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n";
        let path = api_mutation_temp_config(initial, "audit-canonical");
        let state = test_state_with_config_path(path.clone());

        let capture = AuditCapture::arm();
        let resp = add_whitelist(
            State(state.clone()),
            Json(WhitelistBody {
                domain: "@@||EVIL.COM^".into(),
            }),
        )
        .await
        .into_response();
        let logged = capture.text();
        drop(capture);
        assert!(
            !logged.is_empty(),
            "nothing was captured at all — the harness lost the event, \
             which is not a claim about the handler"
        );
        assert_eq!(resp.status(), StatusCode::OK);
        let body = read_body_json(resp).await;
        assert_eq!(
            body["message"].as_str().unwrap(),
            "whitelisted: evil.com",
            "the response must name the rule that landed, not the raw input"
        );

        // What actually reached disk.
        let config = load_v1(&path);
        let profile = config
            .profiles
            .get("default")
            .expect("default profile must exist");
        assert!(
            profile
                .admin_rules
                .iter()
                .any(|rid| config
                    .admin_rules
                    .iter()
                    .any(|ar| ar.id.as_str() == rid.as_str() && ar.rule == "@@||evil.com^")),
            "expected an @@||evil.com^ rule on disk"
        );

        assert!(
            logged.contains("domain=evil.com"),
            "audit must name the canonical rule, got: {logged}"
        );
        assert!(
            logged.contains("submitted=@@||EVIL.COM^"),
            "audit must keep the raw input traceable, got: {logged}"
        );
        assert!(
            !logged.contains("domain=@@||EVIL.COM^"),
            "audit must not report the pre-canonical input as the rule, got: {logged}"
        );

        let capture = AuditCapture::arm();
        let resp = remove_whitelist(
            State(state),
            Json(WhitelistBody {
                domain: "@@||Evil.Com^".into(),
            }),
        )
        .await
        .into_response();
        let logged = capture.text();
        drop(capture);
        assert_eq!(resp.status(), StatusCode::OK);
        let body = read_body_json(resp).await;
        assert_eq!(body["message"].as_str().unwrap(), "removed: evil.com");
        assert!(
            logged.contains("domain=evil.com") && logged.contains("submitted=@@||Evil.Com^"),
            "remove must audit the canonical rule too, got: {logged}"
        );

        std::fs::remove_file(&path).ok();
    }

    // ── the config write lock has one taker, and every writer uses it ──
    //
    // Both scans enumerate their subject at run time rather than from a
    // hand-written list, because a hand-written list is the failure mode
    // they exist to catch. Needles are split with `concat!` so this file's
    // own source can never match them.

    fn api_source_files() -> Vec<std::path::PathBuf> {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/api");
        let mut files: Vec<std::path::PathBuf> = std::fs::read_dir(&dir)
            .expect("src/api must be readable")
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.extension().and_then(|x| x.to_str()) == Some("rs"))
            .collect();
        files.sort();
        assert!(files.len() > 1, "src/api enumeration found nothing");
        files
    }

    /// Holding the guard across the reload notification deadlocks the
    /// capacity-1 channel; skipping it re-opens the read-modify-write race
    /// the lock was added to close. Both are impossible for a caller that
    /// goes through `mutate_config`, which owns the guard — so the lock may
    /// be acquired in exactly that one place.
    #[test]
    fn the_config_write_lock_has_exactly_one_taker() {
        let needle = concat!("config_write_lock", ".lock()");
        let hits: Vec<(String, usize)> = api_source_files()
            .into_iter()
            .filter_map(|path| {
                let body = std::fs::read_to_string(&path).expect("api source readable");
                let n = body.matches(needle).count();
                (n > 0).then(|| (path.file_name().unwrap().to_string_lossy().into_owned(), n))
            })
            .collect();
        assert_eq!(
            hits,
            vec![("state.rs".to_string(), 1)],
            "the write lock must be taken only by ApiState::mutate_config"
        );
    }

    /// The other direction: a new endpoint that writes config without going
    /// through the helper takes no lock at all, and the scan above would
    /// still be green. Enumerate the handlers instead of naming them.
    #[test]
    fn every_config_writing_handler_goes_through_mutate_config() {
        let seats = [
            concat!("edit_master_lists", "_sources("),
            concat!("rules::add", "_inner("),
            concat!("rules::remove", "_inner("),
            concat!("write_value", "_validated("),
        ];
        let split = concat!("\npub async ", "fn ");
        let body = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/api/handlers.rs"),
        )
        .expect("handlers.rs readable");

        // Chunk 0 is everything before the first handler — the private
        // helpers that own the write seats themselves.
        let chunks: Vec<&str> = body.split(split).skip(1).collect();
        let writers: Vec<&&str> = chunks
            .iter()
            .filter(|chunk| seats.iter().any(|seat| chunk.contains(seat)))
            .collect();
        // A scan that matches nothing passes vacuously. Deliberately not a
        // count of handlers: if this file is split and the mutating
        // endpoints move out, the scan has to follow them, and going red
        // here is how that gets noticed.
        assert!(
            !writers.is_empty(),
            "no config-writing handler found — the scan no longer covers them"
        );

        let offenders: Vec<&str> = writers
            .into_iter()
            .filter(|chunk| !chunk.contains("mutate_config"))
            .map(|chunk| chunk.split('(').next().unwrap_or("?"))
            .collect();
        assert!(
            offenders.is_empty(),
            "these handlers write config without the write lock: {offenders:?}"
        );
    }

    /// T5 canonical path: `/api/devices` must respond cleanly — no
    /// Deprecation, Sunset, or Link-to-successor header on the way out.
    #[tokio::test]
    async fn new_path_has_no_deprecation_headers() {
        let state = test_state_with_stats();
        let app = Router::new()
            .route("/api/devices", get(get_devices))
            .with_state(state);
        let req = Request::builder()
            .uri("/api/devices")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(!resp.headers().contains_key("deprecation"));
        assert!(!resp.headers().contains_key("sunset"));
        assert!(!resp.headers().contains_key("link"));
    }
}
