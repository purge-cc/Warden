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

/// Sunset date for the `/api/clients` legacy endpoint. Operators who
/// scrape the API have roughly six months to cut over to
/// `/api/devices`; after the sunset date the legacy route should be
/// removed.
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
    /// The standing corpus refusal, mirroring the IPC field of the same
    /// name. Present here because an HTTP consumer that only ever saw
    /// `domain_count` reads a refused cycle as a healthy one: the count is
    /// truthful about the generation being served and says nothing about
    /// the one that was thrown away.
    lists_corpus_refusal: Option<crate::lists::status::CorpusRefusal>,
    /// The last completed reload cycle and what it did.
    lists_cycle: Option<crate::lists::status::CycleMark>,
    /// How long a standing refusal has stood, and across how many cycles.
    lists_corpus_freeze: Option<crate::lists::status::CorpusFreeze>,
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
    /// Block attribution (`list:<name>` / `rule:<pattern>` /
    /// `admin_block` / …) from `BlockSource::describe`. Omitted from the
    /// JSON when absent (allowed domains, or a block with no profile
    /// context) so existing consumers are unaffected.
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

/// Cap a single-field string at `max` bytes, rejecting at
/// deserialization time so an attacker can't induce a multi-MB
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
/// Operator-facing message names the field, the limit, and what to
/// check.
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

/// Load the v1 [`ConfigV1`](crate::config::schema::ConfigV1) off the async runtime. Reads the
/// v1 schema via the loader (which merges master + includes) rather
/// than a single-file parse.
///
/// `spawn_blocking` runs the synchronous multi-file read on tokio's
/// dedicated blocking pool, never a runtime worker — so even when this
/// future is awaited inside the `config_write_lock` window, no async
/// worker is starved.
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

/// Outcome of an [`edit_master_lists_sources`] mutation that the
/// handler maps to an HTTP status.
enum ListEditError {
    /// Operator precondition failed (already-subscribed for add /
    /// not-subscribed for remove). Handler maps to 409 / 404 with this
    /// operator-facing message.
    Precondition(String),
    /// Read / write / validate failure — handler maps to 500.
    Io(anyhow::Error),
}

/// Edit the master config's `[lists].sources` array under a
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

/// Same `spawn_blocking` rationale as `read_config_v1`, applied to
/// the rotated-log walker. `read_log_entries_with_state`
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

/// Validate a domain at the API trust boundary using the shared
/// validator from `config::schema::admin_rule`. Reuses the same
/// rules that gate IPC `warden blocklist add` and v1 admin rules —
/// RFC 1035 LDH ASCII, ≤253 octets total, ≤63 per label, no
/// leading/trailing dots, no double-dots, no leading/trailing
/// hyphens, no control characters or non-ASCII bytes.
///
/// On rejection the response is **400 Bad Request** with a body
/// that names the specific violation in plain English — the operator
/// should understand what they typed wrong without consulting docs.
/// The body never echoes
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

/// Build the 500 response when the reload notification fails after
/// a successful disk write. The on-disk config and the
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

    // Flush moka before reading, same reasoning and same primitive as
    // the IPC `handle_status` path — see `DnsCache::flushed_usage`.
    // Off the `:53` hot path.
    let cache_entries = state.cache.flushed_usage().await.entries;

    // Cycle-level facts, read straight off the registry for the same
    // reason `handle_status` does: in a refused cycle every per-source row
    // is healthy, which is precisely the problem. Same read order as the
    // IPC path — payload first, mark second — so a cycle landing between
    // the reads makes a caller re-poll rather than pair a new mark with an
    // old payload.
    let lists_corpus_refusal = state
        .list_statuses
        .as_ref()
        .and_then(|reg| reg.corpus_refusal());
    let lists_corpus_freeze = state
        .list_statuses
        .as_ref()
        .and_then(|reg| reg.corpus_freeze());
    let lists_cycle = state.list_statuses.as_ref().map(|reg| reg.cycle());

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
        lists_corpus_refusal,
        lists_cycle,
        lists_corpus_freeze,
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
/// Kept alongside `/api/devices` for one deprecation cycle.
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

/// GET /api/devices — per-device stats table, canonical path.
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

    // Use the rotated-aware helper so the API walks
    // `query.log.YYYY-MM-DD` siblings for free. Resolve the path from
    // the engine's attached-writer slot when available; otherwise
    // fall back to the raw config string, which is usually correct
    // for dev setups but broken under systemd's `cwd=/`. A proper
    // resolver call needs the config path, which the API handler
    // doesn't carry today.
    let path_buf = engine
        .query_log_file_path()
        .unwrap_or_else(|| engine.config.query_log_path.clone());
    // See `read_log_entries_async` for the spawn_blocking rationale —
    // the rotated-log walker can stream up to `retention_days`
    // siblings synchronously.
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

/// GET /api/blocklists/:id/stats — per-list runtime stats.
///
/// `id` may be a canonical `[[blocklists]].id`, a legacy slash-form slug
/// (`"privacy/ads"`), or an exact source string. The handler resolves it
/// through the same three-pass logic the IPC layer uses (exact match →
/// resolver `slug_to_id` ↔ `slug_for_id` bridge → case-insensitive
/// substring), then renders the matched
/// [`BlocklistStatusDto`](crate::lists::status::BlocklistStatusDto).
///
/// Token-gated by the `/api/` `auth_middleware` — IPC's
/// `BlocklistStats` ReadOnly-no-token rule does not extend to HTTP.
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
    // An empty `id` would substring-match every source in pass 3
    // (every string contains the empty string), making the
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
    // by the 64-source cap of `build_source_bit_map`. `registry.snapshot()`
    // walks a HashMap so iteration order is
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
    // See `read_config_v1` for the spawn_blocking rationale.
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

    // Edit the master's `[lists].sources` in place via `toml::Value`
    // surgery — the v1 mutation pattern. The dup check
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
    // Edit the master's `[lists].sources` in place — see `add_list`.
    // The not-found check runs inside the same
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
    // v1 expresses a profile's allow list as `[[admin_rules]]` rows
    // referenced by `profiles.<id>.admin_rules`. Reconstruct the
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
    // Validate BEFORE acquiring the lock or touching disk. Strip any
    // operator-typed `@@||...^` wrapper first so we validate
    // the bare domain shape, then re-wrap below from the canonical
    // (lowercased) form returned by the validator.
    let bare = body.domain.trim_start_matches("@@||").trim_end_matches('^');
    let canonical = match validate_api_domain(bare, "domain") {
        Ok(d) => d,
        Err(resp) => return resp,
    };

    // Route through the shared v1 admin-rule seat
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
    // Validate BEFORE acquiring the lock or touching disk.
    let bare = body.domain.trim_start_matches("@@||").trim_end_matches('^');
    let canonical = match validate_api_domain(bare, "domain") {
        Ok(d) => d,
        Err(resp) => return resp,
    };

    // Route through the shared v1 admin-rule seat
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
    // Validate the path-segment domain before letting it touch the
    // filter engine. Stops control-char
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

    // Surface the already-computed block attribution via
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
            // When the operator has explicitly unset `default_profile`,
            // any query that would otherwise fall to level 5 is
            // REFUSED. Report as blocked for the API consumer.
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
/// operator-supplied URLs, so this is attacker-adjacent supply-chain
/// input — a hostile list URL must not be able to inject series into
/// the scrape output.
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
/// - purge_warden_lists_corpus_refused (gauge)
/// - purge_warden_lists_corpus_unique (gauge)
/// - purge_warden_lists_corpus_ceiling (gauge)
/// - purge_warden_lists_corpus_refused_cycles (gauge)
/// - purge_warden_lists_corpus_frozen_since_seconds (gauge)
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

    // Blocklist truncation. Two series, because
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
        // Unconditional, unlike before: a series that exists only while the
        // corpus is refused graphs a recovery as a collapse to nothing, and
        // a scrape gap passes for health. Both values come from the refusal
        // record, so they read 0 whenever nothing is refused — they alert
        // on a standing refusal; they cannot predict one.
        out.push_str("# TYPE purge_warden_lists_corpus_unique gauge\n");
        out.push_str(&format!(
            "purge_warden_lists_corpus_unique {}\n",
            refusal.as_ref().map_or(0, |r| r.unique)
        ));
        out.push_str("# TYPE purge_warden_lists_corpus_ceiling gauge\n");
        out.push_str(&format!(
            "purge_warden_lists_corpus_ceiling {}\n",
            refusal.as_ref().map_or(0, |r| r.ceiling)
        ));

        // How long, and how many times. A boolean cannot distinguish a
        // refusal that started this morning from one nine cycles old, so
        // an alert on `purge_warden_lists_corpus_refused` alone fires
        // identically for a blip and for a fortnight of drift.
        //
        // Named `..._refused_cycles` rather than `..._refusals_total`
        // because it is a gauge in prometheus terms: it resets to 0 on the
        // next install, and `rate()` over a `_total` that goes backwards is
        // nonsense.
        //
        // Both can stand while `purge_warden_lists_corpus_refused` reads 0.
        // That is not an inconsistency: a cycle that fails to install
        // without refusing (flush error, degraded shard build, an empty
        // spill) clears the refusal payload and leaves the previous
        // generation serving. The corpus is still frozen; only the last
        // cycle's verdict changed.
        let freeze = reg.corpus_freeze();
        out.push_str("# TYPE purge_warden_lists_corpus_refused_cycles gauge\n");
        out.push_str(&format!(
            "purge_warden_lists_corpus_refused_cycles {}\n",
            freeze.as_ref().map_or(0, |f| f.consecutive)
        ));
        out.push_str("# TYPE purge_warden_lists_corpus_frozen_since_seconds gauge\n");
        out.push_str(&format!(
            "purge_warden_lists_corpus_frozen_since_seconds {}\n",
            freeze
                .as_ref()
                .and_then(|f| f.since)
                .map_or(0, |t| t.unix_timestamp())
        ));
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

        // Security refusals (REFUSED / RRL_DROP) are also counted in
        // blocked_total; this dedicated series lets a
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
        // Same correction as socket_server.rs's handle_tracking_stats /
        // compute_24h_stats — blocked queries are
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
        // so existing Grafana dashboards keep scraping through the rollout.
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
    // See `read_config_v1` for the spawn_blocking rationale. The
    // response body is the v1 `ConfigV1` shape.
    match read_config_v1(state.config_path.clone()).await {
        // Structural redaction — every credential-bearing field is
        // starred in ONE place (`ConfigV1::redacted`, guarded by the
        // deny-by-default leak test beside it), not name-matched here.
        Ok(config) => Json(config.redacted()).into_response(),
        // Unlike the IPC path, API error bodies deliberately keep the
        // underlying error detail. Every `/api/*` route sits behind
        // `auth_middleware`, so only an authenticated admin — who can
        // read the config directly anyway — ever sees these;
        // wire-redaction here would add cost without moving the trust
        // boundary. This policy is API-wide, not specific to `get_config`.
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
mod metric_label_tests;

#[cfg(test)]
pub(crate) mod tests;
