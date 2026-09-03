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

async fn read_body_text(resp: axum::response::Response) -> String {
    let body_bytes = axum::body::to_bytes(resp.into_body(), 256 * 1024)
        .await
        .unwrap();
    String::from_utf8(body_bytes.to_vec()).unwrap()
}

/// A corpus series that only exists while the corpus is refused cannot
/// carry the alert that matters — the one firing at 90% of the ceiling,
/// before the freeze. `absent` and `healthy` must not scrape alike.
#[tokio::test]
async fn metrics_names_the_corpus_series_on_a_healthy_daemon() {
    let state = test_state_with_blocklists();
    let body = read_body_text(metrics(State(state)).await.into_response()).await;

    for series in [
        "purge_warden_lists_corpus_refused 0",
        "purge_warden_lists_corpus_unique 0",
        "purge_warden_lists_corpus_ceiling 0",
        "purge_warden_lists_corpus_refused_cycles 0",
        "purge_warden_lists_corpus_frozen_since_seconds 0",
    ] {
        assert!(
            body.contains(series),
            "healthy scrape is missing `{series}`:\n{body}"
        );
    }
}

/// The frozen-string fence on the two names a dashboard and an alert
/// rule are written against. Renaming either is an operator-visible
/// break, not a refactor.
#[tokio::test]
async fn metrics_names_a_frozen_corpus_with_its_age_and_its_streak() {
    use crate::lists::status::CorpusRefusal;
    use time::macros::datetime;

    let state = test_state_with_blocklists();
    let reg = state.list_statuses.as_ref().expect("registry wired");
    let t0 = datetime!(2026-08-04 03:00:00 UTC);
    reg.note_refused_cycle(t0);
    reg.note_refused_cycle(t0 + time::Duration::hours(24));
    reg.set_corpus_refusal(Some(CorpusRefusal {
        unique: 15_012_024,
        ceiling: 14_000_000,
        novel_by_source: vec![],
    }));

    let body = read_body_text(metrics(State(state.clone())).await.into_response()).await;
    assert!(
        body.contains("purge_warden_lists_corpus_refused 1"),
        "{body}"
    );
    assert!(
        body.contains("purge_warden_lists_corpus_unique 15012024"),
        "{body}"
    );
    assert!(
        body.contains("purge_warden_lists_corpus_refused_cycles 2"),
        "the streak length is the one number that separates a blip from a \
         fortnight of drift:\n{body}"
    );
    assert!(
        body.contains(&format!(
            "purge_warden_lists_corpus_frozen_since_seconds {}",
            t0.unix_timestamp()
        )),
        "the freeze start must be the FIRST refusal, not the latest:\n{body}"
    );

    // An install ends it, and the series must go back to 0 rather than
    // disappear — a vanished series and a recovered one look identical to
    // a scraper that only sees gaps.
    reg.note_installed_cycle();
    reg.set_corpus_refusal(None);
    let after = read_body_text(metrics(State(state)).await.into_response()).await;
    assert!(
        after.contains("purge_warden_lists_corpus_refused_cycles 0"),
        "{after}"
    );
    assert!(
        after.contains("purge_warden_lists_corpus_frozen_since_seconds 0"),
        "{after}"
    );
}

/// `/api/status` is the authenticated surface a scraper without a socket
/// reads. Before this it published `domain_count` and nothing that could
/// contradict it — a refused cycle reads as a healthy one, because the
/// count truthfully describes the generation still being served.
#[tokio::test]
async fn api_status_names_a_refused_and_frozen_corpus() {
    use crate::lists::status::CorpusRefusal;
    use time::macros::datetime;

    let state = test_state_with_blocklists();
    let reg = state.list_statuses.as_ref().expect("registry wired");
    let t0 = datetime!(2026-08-04 03:00:00 UTC);
    // Two, so the `since` assertion below is not vacuous: with one
    // refusal, "dates from the first" and "dates from the latest" agree.
    reg.note_refused_cycle(t0);
    reg.note_refused_cycle(t0 + time::Duration::hours(24));
    reg.set_corpus_refusal(Some(CorpusRefusal {
        unique: 15_012_024,
        ceiling: 14_000_000,
        novel_by_source: vec![("security/malicious".to_string(), 4_000_000)],
    }));
    reg.record_cycle(crate::lists::status::CycleOutcome::Refused);

    let body = read_body_json(get_status(State(state)).await.into_response()).await;
    assert_eq!(body["lists_corpus_refusal"]["unique"], 15_012_024_u64);
    assert_eq!(body["lists_corpus_refusal"]["ceiling"], 14_000_000_u64);
    assert_eq!(body["lists_corpus_freeze"]["consecutive"], 2);
    assert_eq!(
        body["lists_corpus_freeze"]["since"],
        serde_json::json!("2026-08-04T03:00:00Z"),
        "the freeze start must reach HTTP as RFC3339: {body}"
    );
    assert_eq!(body["lists_cycle"]["outcome"], serde_json::json!("refused"));
}

/// The control arm for the pair above: a healthy daemon must publish the
/// keys as `null`, not omit them. An absent key and a healthy one are
/// indistinguishable to a consumer, which is how a scraper reads a
/// daemon too old to report the fact as a daemon reporting health.
#[tokio::test]
async fn api_status_publishes_the_corpus_keys_when_healthy() {
    let state = test_state_with_blocklists();
    let body = read_body_json(get_status(State(state)).await.into_response()).await;
    let obj = body.as_object().expect("status body is an object");
    for key in ["lists_corpus_refusal", "lists_cycle", "lists_corpus_freeze"] {
        assert!(obj.contains_key(key), "`{key}` missing from: {body}");
    }
    assert!(body["lists_corpus_refusal"].is_null(), "{body}");
    assert!(body["lists_corpus_freeze"].is_null(), "{body}");
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
        let body: BlocklistStatusDto = serde_json::from_value(read_body_json(resp).await).unwrap();
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
        "client": "operator-laptop",
        "blocked": true,
    });
    let parsed: LogsQuery = serde_json::from_value(body).unwrap();
    assert_eq!(parsed.domain.as_deref(), Some("ads.example.com"));
    assert_eq!(parsed.client.as_deref(), Some("operator-laptop"));
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
        String::from_utf8(self.0.lock().expect("audit sink").clone()).expect("fmt output is utf8")
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
        profile.admin_rules.iter().any(|rid| config
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
