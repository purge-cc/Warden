//! API router — all endpoints under `/api/` with auth middleware.

use std::sync::Arc;
use std::time::Duration;

use axum::http::StatusCode;
use axum::middleware;
use axum::routing::{delete, get, post};
use axum::Router;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;

use super::handlers;
use super::state::ApiState;
use crate::auth::middleware::auth_middleware;

/// Per-request handler timeout for every API endpoint. Generous enough to
/// cover bulk mutations that touch disk (e.g. `POST /api/lists/add`
/// rewrites `config.toml` under `config_write_lock`); short enough that a
/// hung handler — upstream wedge, blocking syscall, deadlocked future —
/// returns `408 Request Timeout` instead of pinning a tokio task forever.
/// Layered globally so authenticated `/api/*` routes and public `/healthz`
/// + `/metrics` are both bounded.
const API_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Build the API router with all routes and middleware layers.
///
/// `metrics_enabled` gates whether `GET /metrics` is registered. When
/// `false` the route is not mounted at all — requests return 404 from
/// axum's NotFound fallback rather than from the handler, so the
/// endpoint leaves no enumeration surface.
pub fn build_router(state: Arc<ApiState>, metrics_enabled: bool) -> Router {
    // Authenticated API routes
    let api_routes = Router::new()
        // Read endpoints
        .route("/api/status", get(handlers::get_status))
        .route("/api/clients", get(handlers::get_clients))
        .route("/api/devices", get(handlers::get_devices))
        .route("/api/logs", get(handlers::get_logs))
        .route("/api/lists", get(handlers::get_lists))
        // Per-blocklist runtime telemetry — entries, last fetch outcome,
        // parsed counters, delta-pct vs prev cycle. Token-gated by the
        // same `auth_middleware` wrapping every `/api/` route below —
        // the IPC ReadOnly-no-token rule does not extend to HTTP.
        .route(
            "/api/blocklists/{id}/stats",
            get(handlers::get_blocklist_stats),
        )
        .route("/api/query/{domain}", get(handlers::query_domain))
        .route("/api/config", get(handlers::get_config))
        .route("/api/whitelist", get(handlers::get_whitelist))
        // Mutation endpoints
        .route("/api/lists/add", post(handlers::add_list))
        .route("/api/lists/remove", delete(handlers::remove_list))
        .route("/api/update", post(handlers::trigger_update))
        .route("/api/whitelist/add", post(handlers::add_whitelist))
        .route("/api/whitelist/remove", delete(handlers::remove_whitelist))
        // Two layers on all /api/ routes. Axum runs the LAST-added layer
        // first, so the request order is: auth_middleware (outer) →
        // rate_limit_middleware (inner) → handler. Rate limiting AFTER
        // auth is deliberate: the knob caps *valid-token* clients,
        // unauthenticated callers cannot probe the window or burn a
        // legit client's budget, a locked-out IP keeps getting the
        // lockout 429 (Retry-After: 300) rather than a softer rate-limit
        // 429, and lockout accounting is fully settled before the
        // limiter ever runs. `/healthz` + `/metrics` (public,
        // below) and `/api/cluster/*` (own cluster-token + CIDR gate,
        // machine-to-machine cadence) are exempt by construction — these
        // layers attach to `api_routes` only.
        .layer(middleware::from_fn_with_state(
            state.clone(),
            crate::api::rate_limit::rate_limit_middleware,
        ))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ));

    // Unauthenticated routes. `/healthz` is the always-on liveness probe
    // (Kubernetes / SRE convention). `/metrics` is opt-in via
    // `[api] metrics_enabled = true` so default deployments do not leak
    // operational reconnaissance (query rate, block ratio, domain count).
    let mut public_routes = Router::new().route("/healthz", get(handlers::healthz));
    if metrics_enabled {
        public_routes = public_routes.route("/metrics", get(handlers::metrics));
    }

    let app = api_routes.merge(public_routes);

    // Cluster serve endpoints mount on THIS server, under their own
    // cluster-token auth layer, only when the primary built a `ClusterState`
    // (`cluster.enabled && role == primary && api.enabled`). Absent otherwise,
    // so `/api/cluster/*` 404s exactly like `/metrics` when disabled — no
    // enumeration surface. The outer `.with_state(state)` binds both sub-routers.
    #[cfg(feature = "cluster")]
    let app = if state.cluster.is_some() {
        app.merge(crate::cluster::routes::cluster_router(state.clone()))
    } else {
        app
    };

    app.layer(TimeoutLayer::with_status_code(
        StatusCode::REQUEST_TIMEOUT,
        API_REQUEST_TIMEOUT,
    ))
    .layer(TraceLayer::new_for_http())
    .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;

    use axum::body::Body;
    use axum::http::Request;
    use axum::routing::get;
    use tower::ServiceExt;

    use super::super::handlers::tests::test_state_with_stats;

    /// Pin the production timeout so a future ergonomic edit (e.g. tightening
    /// to 5s for a single endpoint) cannot silently regress the global cap.
    #[test]
    fn api_request_timeout_is_30_seconds() {
        assert_eq!(API_REQUEST_TIMEOUT, Duration::from_secs(30));
    }

    /// Verify `tower_http::timeout::TimeoutLayer` translates an over-budget
    /// handler into `408 Request Timeout`. Uses a 100 ms test cap so the test
    /// is fast; production cap is `API_REQUEST_TIMEOUT` (asserted above).
    #[tokio::test]
    async fn timeout_layer_returns_408_when_handler_exceeds_budget() {
        let app: Router = Router::new()
            .route(
                "/slow",
                get(|| async {
                    tokio::time::sleep(Duration::from_secs(60)).await;
                    "never reached"
                }),
            )
            .layer(TimeoutLayer::with_status_code(
                StatusCode::REQUEST_TIMEOUT,
                Duration::from_millis(100),
            ));

        let req = Request::builder().uri("/slow").body(Body::empty()).unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::REQUEST_TIMEOUT);
    }

    /// `[api] metrics_enabled = false` (default): the `/metrics` route is
    /// not registered on the router, so requests return 404 from axum's
    /// fallback — no leak that the endpoint conceptually exists. Pairs
    /// with `metrics_route_present_when_enabled` below.
    #[tokio::test]
    async fn metrics_route_absent_when_disabled() {
        let state = test_state_with_stats();
        let router = build_router(state, /* metrics_enabled */ false);
        let req = Request::builder()
            .uri("/metrics")
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    /// `[api] metrics_enabled = true`: the `/metrics` route is registered
    /// and serves OpenMetrics text. Asserts both the status code and one
    /// of the seven metric names in the body so a future router-rewiring
    /// that mis-binds the path fails loudly.
    #[tokio::test]
    async fn metrics_route_present_when_enabled() {
        let state = test_state_with_stats();
        let router = build_router(state, /* metrics_enabled */ true);
        let req = Request::builder()
            .uri("/metrics")
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body_bytes = axum::body::to_bytes(resp.into_body(), 8192).await.unwrap();
        let body = std::str::from_utf8(&body_bytes).unwrap();
        assert!(
            body.contains("purge_warden_uptime_seconds"),
            "expected uptime metric in body, got: {body}"
        );
        // Frozen pin on the security-refusal metric series — scrapers
        // depend on the exact metric name.
        assert!(
            body.contains("purge_warden_refused_security_total"),
            "expected security-refusal metric in body, got: {body}"
        );
    }

    // ── per-IP request rate limit ──────────

    use axum::extract::connect_info::MockConnectInfo;
    use std::net::SocketAddr;

    use super::super::handlers::tests::test_state_with_rate_limit;

    fn mock_addr() -> SocketAddr {
        "192.0.2.7:55555".parse().unwrap()
    }

    async fn body_text(resp: axum::response::Response) -> String {
        let bytes = axum::body::to_bytes(resp.into_body(), 8192).await.unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    fn authed_req(token: &str) -> Request<Body> {
        Request::builder()
            .uri("/api/status")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap()
    }

    /// Authenticated requests past the budget get the rate-limit 429 with
    /// a parseable Retry-After — and the body is the RATE-LIMIT body, not
    /// the auth-lockout one (the two throttles must stay tellable apart).
    #[tokio::test]
    async fn authed_requests_429_past_limit_with_retry_after() {
        let (state, token) = test_state_with_rate_limit(2);
        let router = build_router(state, false).layer(MockConnectInfo(mock_addr()));

        for n in 0..2 {
            let resp = router.clone().oneshot(authed_req(token)).await.unwrap();
            assert_eq!(resp.status(), StatusCode::OK, "request {n} within budget");
        }
        let resp = router.clone().oneshot(authed_req(token)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        let retry: u64 = resp
            .headers()
            .get("Retry-After")
            .expect("Retry-After present")
            .to_str()
            .unwrap()
            .parse()
            .expect("Retry-After parses");
        assert!((1..=60).contains(&retry), "{retry}");
        let body = body_text(resp).await;
        assert!(
            body.contains("API rate limit exceeded"),
            "rate-limit body, not lockout body: {body}"
        );
    }

    /// Unauthenticated requests are rejected by the OUTER auth layer and
    /// never reach the limiter — they cannot burn a legit client's
    /// budget. Pins the after-auth layering order.
    #[tokio::test]
    async fn unauthenticated_requests_do_not_consume_budget() {
        let (state, token) = test_state_with_rate_limit(1);
        let router = build_router(state, false).layer(MockConnectInfo(mock_addr()));

        for _ in 0..3 {
            let req = Request::builder()
                .uri("/api/status")
                .body(Body::empty())
                .unwrap();
            let resp = router.clone().oneshot(req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        }
        // Budget of 1 must still be intact for the valid client.
        let resp = router.clone().oneshot(authed_req(token)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// A rate-limited request must leave auth-lockout state clean: the
    /// 429 comes from the limiter, not from failure accounting.
    #[tokio::test]
    async fn rate_limited_request_leaves_auth_state_clean() {
        let (state, token) = test_state_with_rate_limit(1);
        let router = build_router(state.clone(), false).layer(MockConnectInfo(mock_addr()));

        let resp = router.clone().oneshot(authed_req(token)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let resp = router.clone().oneshot(authed_req(token)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(
            !state.rate_limiter.is_locked_out(&mock_addr().ip()),
            "rate-limit 429 must not contribute to auth lockout"
        );
    }

    /// `/healthz` sits outside both auth and the limiter — a liveness
    /// poller can never be throttled by the operator knob.
    #[tokio::test]
    async fn healthz_exempt_from_rate_limit() {
        let (state, _token) = test_state_with_rate_limit(1);
        let router = build_router(state, false).layer(MockConnectInfo(mock_addr()));
        for n in 0..5 {
            let req = Request::builder()
                .uri("/healthz")
                .body(Body::empty())
                .unwrap();
            let resp = router.clone().oneshot(req).await.unwrap();
            // The stub state has no upstream, so /healthz legitimately
            // reports degraded (503) — the property under test is only
            // that the limiter (budget 1) never throttles it.
            assert_ne!(
                resp.status(),
                StatusCode::TOO_MANY_REQUESTS,
                "healthz hit {n} must not be rate limited"
            );
        }
    }

    /// `/metrics` (when enabled) is likewise exempt — Prometheus scrape
    /// cadence must not contend with the authed-API budget.
    #[tokio::test]
    async fn metrics_exempt_from_rate_limit_when_enabled() {
        let (state, _token) = test_state_with_rate_limit(1);
        let router = build_router(state, true).layer(MockConnectInfo(mock_addr()));
        for n in 0..3 {
            let req = Request::builder()
                .uri("/metrics")
                .body(Body::empty())
                .unwrap();
            let resp = router.clone().oneshot(req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::OK, "metrics hit {n}");
        }
    }
}
