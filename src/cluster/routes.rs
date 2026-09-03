//! `/api/cluster/*` serve-side endpoints + cluster-token auth.
//!
//! Mounted on the EXISTING axum server only when `cluster.enabled && role ==
//! primary` — the mount site (`api::routes::build_router`) checks
//! `ApiState.cluster.is_some()`. The cluster routes carry their OWN auth layer,
//! distinct from `/api`'s:
//!   1. optional `allow_peer` CIDR gate (defence-in-depth — network layer);
//!   2. the SHARED per-IP [`crate::auth::middleware::AuthRateLimiter`] from `ApiState`;
//!   3. a DISTINCT cluster bearer token verified constant-time against
//!      `[cluster] token_hash` — the API token does NOT work here.

use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Instant;

use axum::body::Body;
use axum::extract::{ConnectInfo, State};
use axum::http::{header, HeaderMap, Request, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};

use crate::api::state::ApiState;
use crate::auth::token::verify_token;
use crate::config::cidr::any_contains;

use super::dto::{ClusterStats, ClusterStatusResponse, HeartbeatRequest, HeartbeatResponse};

/// Build the cluster sub-router (routes + cluster auth layer). The `State` is
/// applied by the caller's outer `.with_state(state)`, exactly as the `/api`
/// routes are wired. Caller guarantees `state.cluster.is_some()`.
pub fn cluster_router(state: Arc<ApiState>) -> Router<Arc<ApiState>> {
    Router::new()
        .route("/api/cluster/heartbeat", post(heartbeat))
        .route("/api/cluster/bundle", get(bundle))
        .route("/api/cluster/status", get(status))
        .layer(middleware::from_fn_with_state(
            state,
            cluster_auth_middleware,
        ))
}

// NOTE for a future reader: `Cidr::contains` itself is NOT normalised — it
// answers `false` on a family mismatch and is shared with `server.allow_from`,
// the DNS-path ACL. Whether that path has the same lockout is a separate
// question and deliberately NOT changed from here: it sits on the hot path and
// belongs to its own review, not to a cluster-route fix.

/// Does `allow_peer` bar this source IP from `/api/cluster/*`?
///
/// **An empty `allow_peer` is no restriction, and that is deliberate** — it is
/// the *absence* of an opt-in network ACL, not an empty allowlist that denies
/// everyone. Denying on empty would lock out every install that has not set
/// the field, including a freshly enabled primary, and the bearer token is the
/// gate that always applies. `allow_peer` narrows it further when the operator
/// asks for that.
///
/// Extracted from the middleware so the empty-list rule is **named and
/// testable** rather than an `is_empty()` inside a boolean chain. The design
/// doc listed the chain as an open item precisely because a reader cannot tell
/// an intended default from a missing branch by looking at it.
fn source_ip_is_barred(allow_peer: &[crate::config::cidr::Cidr], ip: std::net::IpAddr) -> bool {
    // Normalise `::ffff:a.b.c.d` to `a.b.c.d` before the ACL compare.
    // `Cidr::contains` is family-strict and a dual-stack listener hands us
    // the mapped form for every peer dialling over IPv4, so an `allow_peer`
    // of IPv4 CIDRs that does not see through it locks the operator out of
    // their own secondary. `any_contains` normalises on its way in, so this
    // is idempotent.
    let ip = match ip {
        std::net::IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, std::net::IpAddr::V4),
        v4 => v4,
    };
    !allow_peer.is_empty() && !any_contains(allow_peer, ip)
}

/// Cluster auth middleware. Order: allow_peer gate → lockout → token.
async fn cluster_auth_middleware(
    State(state): State<Arc<ApiState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let Some(cluster) = state.cluster.as_ref() else {
        // Unreachable in practice (routes are mounted only when Some), but
        // fail closed rather than unwrap on the request path.
        return (StatusCode::NOT_FOUND, "cluster not enabled").into_response();
    };
    let ip = addr.ip();

    // (1) Defence-in-depth: source-IP CIDR gate, before any token work.
    if source_ip_is_barred(&cluster.allow_peer, ip) {
        tracing::warn!(
            target: "audit",
            client_ip = %ip,
            "cluster: source IP not in allow_peer"
        );
        return (StatusCode::FORBIDDEN, "source not in cluster allow_peer").into_response();
    }

    // (2) Shared per-IP lockout (same AuthRateLimiter instance as /api).
    // Because the instance is shared, an IP flooding
    // `/api/cluster/*` with bad cluster tokens also locks itself out of `/api`
    // (and vice-versa). Defensible — lockout is per-IP and a peer has no reason
    // to share an IP with an API client — but the cross-surface amplification is
    // intentional, not an oversight.
    if state.rate_limiter.is_locked_out(&ip) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [("Retry-After", "300")],
            "Too many failed attempts. Try again later.",
        )
            .into_response();
    }

    // (3) Bearer token, verified against the CLUSTER hash (NOT the API token).
    let token = request
        .headers()
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    let token = match token {
        Some(t) => t,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                "Missing or invalid Authorization header. Expected: Bearer <token>",
            )
                .into_response();
        }
    };
    if !verify_token(token, &cluster.token_hash) {
        let locked = state.rate_limiter.record_failure(&ip);
        tracing::warn!(
            target: "audit",
            client_ip = %ip,
            locked_out = locked,
            "invalid cluster token"
        );
        return (StatusCode::UNAUTHORIZED, "Invalid token").into_response();
    }
    state.rate_limiter.record_success(&ip);

    next.run(request).await
}

/// `POST /api/cluster/heartbeat`. Accepts the secondary's generations +
/// stats; returns the primary's authoritative view.
async fn heartbeat(
    State(state): State<Arc<ApiState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    body: Option<Json<HeartbeatRequest>>,
) -> Response {
    let Some(cluster) = state.cluster.as_ref() else {
        return cluster_absent();
    };
    // Retain the peer's view in the roster, keyed by source IP.
    // `body` stays optional so a malformed/empty body still yields a useful
    // response — we record the peer only when it parsed. `record_self` samples
    // this primary's own counters on every beat so the contribution-share
    // denominator (Σ qps) includes the local node without a separate timer.
    if let Some(obs) = state.cluster_observe.as_ref() {
        let now = Instant::now();
        if let Some(Json(req)) = &body {
            obs.record_peer(
                addr.ip(),
                req.node_name.clone(),
                req.stats.clone(),
                req.config_generation,
                now,
            );
        }
        obs.record_self(current_stats(&state), now);
    }
    let policy = cluster.policy();
    Json(HeartbeatResponse {
        config_generation: cluster.config_generation(),
        config_hash: policy.hash.clone(),
        stats: current_stats(&state),
        role: cluster.role,
        priority: cluster.priority,
    })
    .into_response()
}

/// `GET /api/cluster/bundle` — `cluster-policy.toml` + ETag(config_hash); 304
/// when the caller's `If-None-Match` already matches the current hash.
async fn bundle(State(state): State<Arc<ApiState>>, headers: HeaderMap) -> Response {
    let Some(cluster) = state.cluster.as_ref() else {
        return cluster_absent();
    };
    let policy = cluster.policy();
    if if_none_match(&headers, &policy.hash) {
        return not_modified(&policy.hash);
    }
    (
        StatusCode::OK,
        [
            (header::ETAG, etag_value(&policy.hash)),
            (header::CONTENT_TYPE, "application/toml".to_string()),
        ],
        policy.toml.clone(),
    )
        .into_response()
}

/// `GET /api/cluster/status` — this node's role/generation/hash/stats + the
/// peers it has heard from.
///
/// A reporting gap here is not a correctness one — the IPC
/// view (`warden cluster status`, the TUI) always reads the same roster
/// correctly — but "no peers" and "peers I cannot see" must not look alike on
/// the one surface a script can reach.
async fn status(State(state): State<Arc<ApiState>>) -> Response {
    let Some(cluster) = state.cluster.as_ref() else {
        return cluster_absent();
    };
    let policy = cluster.policy();
    Json(ClusterStatusResponse {
        role: cluster.role,
        priority: cluster.priority,
        config_generation: cluster.config_generation(),
        config_hash: policy.hash.clone(),
        stats: current_stats(&state),
        peers: peer_views(&state, Instant::now()),
    })
    .into_response()
}

/// Project the observe roster onto the wire [`super::dto::PeerView`]s.
///
/// Three deliberate choices, all of them load-bearing:
///
///  * **the self-row is dropped** — the field is `peers`, and this node's own
///    numbers are already the response's `stats` / `config_generation`;
///  * **stale peers are still reported.** [`super::dto::PeerView`] carries no `online` /
///    `last_seen`, so a stale peer is indistinguishable from a live one here —
///    but *omitting* it would report a shrinking cluster as a healthy one,
///    which is failing open silently on the surface least likely to be watched
///    by a human. Reporting it is the lesser gap; adding `online` to
///    `PeerView` is the open follow-up;
///  * **`role` is `Secondary` by construction, not by measurement.** Only a
///    secondary POSTs `/api/cluster/heartbeat` (the poll loop is the sole
///    caller, and this router is mounted only on a primary), so every roster
///    peer is one. If a peer ever heartbeats in another role, this line becomes
///    a lie — retain the advertised role then, as `config_generation` already
///    is.
fn peer_views(state: &ApiState, now: Instant) -> Vec<super::dto::PeerView> {
    let Some(obs) = state.cluster_observe.as_ref() else {
        return Vec::new();
    };
    project_peers(obs.roster_snapshot(now))
}

/// The projection itself, split out so it is testable without standing up an
/// `ApiState` — and so the three rules above are pinned by tests rather than by
/// this comment.
fn project_peers(rows: Vec<super::observe::RosterRow>) -> Vec<super::dto::PeerView> {
    rows.into_iter()
        .filter(|r| !r.is_self)
        .map(|r| super::dto::PeerView {
            addr: r.addr,
            role: crate::config::schema::ClusterRole::Secondary,
            config_generation: r.config_generation,
            stats: ClusterStats {
                total_queries: r.total_queries,
                total_blocked: r.total_blocked,
                cache_hits: r.cache_hits,
            },
        })
        .collect()
}

fn cluster_absent() -> Response {
    (StatusCode::NOT_FOUND, "cluster not enabled").into_response()
}

/// ETag value for a content hash: the hash wrapped in the required quotes.
fn etag_value(hash: &str) -> String {
    format!("\"{hash}\"")
}

/// True when the request's `If-None-Match` already names the current hash —
/// i.e. the caller is up to date and should get a 304. Tolerates the
/// comma-separated multi-tag form and surrounding quotes; `*` matches anything.
fn if_none_match(headers: &HeaderMap, hash: &str) -> bool {
    headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|raw| {
            raw.split(',').any(|tag| {
                let t = tag.trim().trim_start_matches("W/").trim_matches('"');
                t == hash || t == "*"
            })
        })
}

fn not_modified(hash: &str) -> Response {
    (StatusCode::NOT_MODIFIED, [(header::ETAG, etag_value(hash))]).into_response()
}

fn current_stats(state: &ApiState) -> ClusterStats {
    match state.stats.as_ref() {
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
    use axum::http::HeaderValue;

    fn headers_with(inm: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(header::IF_NONE_MATCH, HeaderValue::from_str(inm).unwrap());
        h
    }

    fn cidrs(list: &[&str]) -> Vec<crate::config::cidr::Cidr> {
        list.iter()
            .map(|s| crate::config::cidr::Cidr::parse(s).unwrap())
            .collect()
    }

    /// Empty `allow_peer` is the ABSENCE of a network ACL, not an empty
    /// allowlist. Flipping this denies every install that has not set the
    /// field — including a freshly enabled primary, which then rejects its
    /// own secondary's very first poll.
    #[test]
    fn an_empty_allow_peer_bars_nobody() {
        let none = cidrs(&[]);
        for ip in ["10.10.1.94", "203.0.113.7", "::1"] {
            assert!(
                !source_ip_is_barred(&none, ip.parse().unwrap()),
                "{ip} must reach the token check when allow_peer is unset"
            );
        }
    }

    /// An IPv4-mapped IPv6 source (`::ffff:a.b.c.d`) must be matched against
    /// an IPv4 CIDR, because a dual-stack listener hands the middleware
    /// exactly that form for a peer dialling over IPv4.
    ///
    /// **The failure this pins is a LOCKOUT, not a bypass.** `Cidr::contains`
    /// is family-strict (`_ => false`), so a gate that compares the mapped
    /// form as-is reads it as "not in the list" and bars the **legitimate**
    /// secondary — sync stops with a FORBIDDEN the operator did not
    /// configure. An allowlist fails closed; the same missing normalisation
    /// in a *denylist* would fail open. Worth stating because the reflex on
    /// reading "IPv4-mapped ACL" is to assume bypass, and the remedy is the
    /// same either way.
    ///
    /// Asserted through `source_ip_is_barred` rather than at whichever call
    /// normalises, so the property survives the step moving between them.
    #[test]
    fn an_ipv4_mapped_source_is_matched_against_an_ipv4_cidr() {
        let allow = cidrs(&["100.64.0.0/10"]);
        assert!(
            !source_ip_is_barred(&allow, "::ffff:100.64.0.7".parse().unwrap()),
            "a mapped form of a listed address must reach the token check"
        );
        assert!(
            source_ip_is_barred(&allow, "::ffff:203.0.113.7".parse().unwrap()),
            "normalisation must not turn the gate off — a mapped UNlisted \
             address must still be barred"
        );
    }

    /// …and a NON-empty one is enforced, in both directions. The pair is the
    /// point: the first test alone is satisfied by a gate that never bars
    /// anyone, which is exactly the "parsed but not wired" state the schema
    /// comment used to claim.
    #[test]
    fn a_configured_allow_peer_is_enforced_both_ways() {
        let allow = cidrs(&["10.10.1.0/24", "100.64.0.0/10"]);
        assert!(!source_ip_is_barred(&allow, "10.10.1.94".parse().unwrap()));
        assert!(!source_ip_is_barred(&allow, "100.64.0.7".parse().unwrap()));
        assert!(source_ip_is_barred(&allow, "203.0.113.7".parse().unwrap()));
        assert!(
            source_ip_is_barred(&allow, "10.10.2.1".parse().unwrap()),
            "a neighbouring /24 must be barred, or the mask is being ignored"
        );
    }

    fn row(name: &str, is_self: bool, online: bool) -> crate::cluster::observe::RosterRow {
        crate::cluster::observe::RosterRow {
            name: name.into(),
            addr: if is_self { "local".into() } else { name.into() },
            is_self,
            online,
            total_queries: 100,
            total_blocked: 7,
            cache_hits: 42,
            qps: 1.0,
            blocked_pct: 7.0,
            share_pct: 50.0,
            config_generation: 5,
        }
    }

    /// The self-row is not a peer: this node's own numbers are already the
    /// response's `stats` / `config_generation`, and repeating them under
    /// `peers` would double-count the cluster in any consumer that sums it.
    #[test]
    fn the_self_row_is_not_reported_as_a_peer() {
        let out = project_peers(vec![
            row("this node", true, true),
            row("203.0.113.7", false, true),
        ]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].addr, "203.0.113.7");
    }

    /// A peer that stopped beating is still reported. `PeerView` cannot express
    /// `online`, so this row is indistinguishable from a live one — but
    /// *dropping* it would render a cluster losing its members as a healthy
    /// smaller cluster, which is failing open silently on the one surface a
    /// script reads. Reporting it is the lesser gap; adding `online` to
    /// `PeerView` is the fix.
    #[test]
    fn a_stale_peer_is_still_reported() {
        let out = project_peers(vec![row("203.0.113.9", false, false)]);
        assert_eq!(out.len(), 1, "an offline peer must not be filtered away");
    }

    /// Everything the roster retained travels: the generation the peer
    /// advertised, and all three counters. Inventing a `0` for `cache_hits` —
    /// which `RosterRow` used to force — is a fabricated statistic.
    #[test]
    fn the_peer_view_carries_what_the_peer_advertised() {
        let out = project_peers(vec![row("203.0.113.7", false, true)]);
        assert_eq!(out[0].config_generation, 5);
        assert_eq!(out[0].stats.total_queries, 100);
        assert_eq!(out[0].stats.total_blocked, 7);
        assert_eq!(out[0].stats.cache_hits, 42);
        assert_eq!(out[0].role, crate::config::schema::ClusterRole::Secondary);
    }

    #[test]
    fn etag_is_quoted() {
        assert_eq!(etag_value("abc"), "\"abc\"");
    }

    #[test]
    fn if_none_match_hit_on_exact() {
        assert!(if_none_match(&headers_with("\"deadbeef\""), "deadbeef"));
    }

    #[test]
    fn if_none_match_miss_on_different() {
        assert!(!if_none_match(&headers_with("\"deadbeef\""), "feedface"));
    }

    #[test]
    fn if_none_match_absent_is_miss() {
        assert!(!if_none_match(&HeaderMap::new(), "deadbeef"));
    }

    #[test]
    fn if_none_match_handles_multi_and_wildcard() {
        assert!(if_none_match(
            &headers_with("\"x\", \"deadbeef\""),
            "deadbeef"
        ));
        assert!(if_none_match(&headers_with("W/\"deadbeef\""), "deadbeef"));
        assert!(if_none_match(&headers_with("*"), "anything"));
    }
}
