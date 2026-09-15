//! `/api/cluster/*` serve-side endpoints + cluster-token auth.
//!
//! Mounted on the administrative API or an active Nodes HTTPS listener when
//! `cluster.enabled && role == primary`. The cluster routes carry their own
//! auth layer, distinct from `/api`'s:
//!   1. optional `allow_peer` CIDR gate (defence-in-depth — network layer);
//!   2. the SHARED per-IP [`crate::auth::middleware::AuthRateLimiter`] from `ApiState`;
//!   3. a DISTINCT cluster bearer token verified constant-time against
//!      `[cluster] token_hash` — the API token does NOT work here.

use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Instant;

use axum::body::Body;
use axum::extract::{ConnectInfo, Extension, Path as RoutePath, Query, State};
use axum::http::{header, HeaderMap, Request, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use tower_http::timeout::TimeoutLayer;

use crate::api::state::ApiState;
use crate::auth::token::verify_token;
use crate::config::cidr::any_contains;
use anyhow::Context;

use super::dto::{ClusterStats, ClusterStatusResponse, HeartbeatRequest};

/// Build the cluster sub-router (routes + cluster auth layer). The `State` is
/// applied by the caller's outer `.with_state(state)`, exactly as the `/api`
/// routes are wired. Caller guarantees `state.cluster.is_some()`.
pub fn cluster_router(state: Arc<ApiState>) -> Router<Arc<ApiState>> {
    authenticated_replication_routes()
        .route("/api/cluster/heartbeat", post(heartbeat))
        .route("/api/cluster/bundle", get(bundle))
        .route(
            "/api/cluster/v2/enroll",
            post(enroll).layer(axum::extract::DefaultBodyLimit::max(8192)),
        )
        .route("/api/cluster/v2/cancel", post(cancel_enrollment))
        .layer(middleware::from_fn_with_state(
            state,
            cluster_auth_middleware,
        ))
}

/// Authenticated policy and capability routes mounted on a Nodes listener
/// when the administrative API is disabled or uses another socket.
pub fn replication_router(state: Arc<ApiState>) -> Router<Arc<ApiState>> {
    authenticated_replication_routes()
        .layer(middleware::from_fn_with_state(
            state,
            cluster_auth_middleware,
        ))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            std::time::Duration::from_secs(30),
        ))
}

fn authenticated_replication_routes() -> Router<Arc<ApiState>> {
    Router::new()
        .route("/api/cluster/status", get(status))
        .route("/api/cluster/v2/heartbeat", post(heartbeat_v2))
        .route(
            "/api/cluster/v2/management-capability",
            post(management_capability).layer(axum::extract::DefaultBodyLimit::max(8192)),
        )
        .route("/api/cluster/v2/status", get(status_v2))
        .route("/api/cluster/v2/activate", post(activate))
        .route("/api/cluster/v2/corpus/manifest", get(corpus_manifest))
        .route(
            "/api/cluster/v2/corpus/objects/{digest}",
            get(corpus_object),
        )
        .route(
            "/api/cluster/v2/artifacts/{hash}/manifest",
            get(artifact_manifest),
        )
        .route(
            "/api/cluster/v2/artifacts/{hash}/objects/{digest}",
            get(artifact_object),
        )
}

async fn management_capability(
    State(state): State<Arc<ApiState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    principal: Option<Extension<super::membership::AuthenticatedNode>>,
    Json(request): Json<super::dto::ManagementCapabilityRequest>,
) -> Response {
    let (Some(controller), Some(context), Some(Extension(principal))) = (
        state.node_controller.as_ref(),
        state
            .cluster
            .as_ref()
            .and_then(|cluster| cluster.membership_context()),
        principal,
    ) else {
        return (
            StatusCode::UPGRADE_REQUIRED,
            "NodesManagementUpgradeRequired",
        )
            .into_response();
    };
    let source_ip = canonical_ip(addr.ip());
    if canonical_ip(request.offer.endpoint.ip()) != source_ip {
        return (
            StatusCode::BAD_REQUEST,
            "management endpoint must use the authenticated peer address",
        )
            .into_response();
    }

    let master = context.master.clone();
    let cluster_id = context.cluster_id.clone();
    let primary_node_id = context.primary_node_id.clone();
    let node_id = principal.node_id.clone();
    let authenticated_name = tokio::task::spawn_blocking(move || -> anyhow::Result<String> {
        let guard = crate::config::write_lock::acquire_for_migration(&master)?;
        let members = super::membership::MembershipStore::open(&guard)?;
        anyhow::ensure!(
            members.matches(&cluster_id, &primary_node_id),
            "membership configuration changed"
        );
        members
            .views(super::membership::now()?)
            .into_iter()
            .find(|member| {
                member.node_id == node_id && member.state == super::membership::MemberState::Active
            })
            .map(|member| member.name)
            .context("authenticated active member absent")
    })
    .await;
    let authenticated_name = match authenticated_name {
        Ok(Ok(name)) => name,
        _ => return (StatusCode::SERVICE_UNAVAILABLE, "membership unavailable").into_response(),
    };
    match controller
        .accept_management_offer(&principal.node_id, &authenticated_name, request.offer)
        .await
    {
        Ok(grant) => Json(super::dto::ManagementCapabilityResponse { grant }).into_response(),
        Err(error) => {
            tracing::warn!(
                node_id = %principal.node_id,
                %error,
                "authenticated Nodes management upgrade rejected"
            );
            (
                StatusCode::BAD_REQUEST,
                "Nodes management capability rejected",
            )
                .into_response()
        }
    }
}

fn canonical_ip(ip: std::net::IpAddr) -> std::net::IpAddr {
    match ip {
        std::net::IpAddr::V6(ip) => ip
            .to_ipv4_mapped()
            .map_or(std::net::IpAddr::V6(ip), std::net::IpAddr::V4),
        ip => ip,
    }
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
    mut request: Request<Body>,
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

    if request.uri().path() == "/api/cluster/v2/enroll" {
        return if cluster.membership_context().is_some() {
            next.run(request).await
        } else {
            (StatusCode::UPGRADE_REQUIRED, "modern membership required").into_response()
        };
    }
    // Authentication produces a stable principal independently of the source IP.

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
    if let Some(context) = cluster.membership_context() {
        let token = super::membership::SecretString(token.to_owned());
        let master = context.master.clone();
        let cluster_id = context.cluster_id.clone();
        let primary = context.primary_node_id.clone();
        let authenticated = tokio::task::spawn_blocking(
            move || -> anyhow::Result<Option<super::membership::AuthenticatedNode>> {
                let guard = crate::config::write_lock::acquire_for_migration(&master)?;
                let members = super::membership::MembershipStore::open(&guard)?;
                anyhow::ensure!(
                    members.matches(&cluster_id, &primary),
                    "membership configuration changed; restart required"
                );
                Ok(members.authenticate(&token.0, super::membership::now()?))
            },
        )
        .await;
        return match authenticated {
            Ok(Ok(Some(principal))) => {
                state.rate_limiter.record_success(&ip);
                request.extensions_mut().insert(principal);
                next.run(request).await
            }
            Ok(Ok(None)) => {
                state.rate_limiter.record_failure(&ip);
                (
                    StatusCode::UNAUTHORIZED,
                    "node credential invalid, expired or revoked",
                )
                    .into_response()
            }
            _ => (StatusCode::SERVICE_UNAVAILABLE, "membership unavailable").into_response(),
        };
    }
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
    ConnectInfo(_addr): ConnectInfo<SocketAddr>,
    _body: Option<Json<HeartbeatRequest>>,
) -> Response {
    let Some(_cluster) = state.cluster.as_ref() else {
        return cluster_absent();
    };
    (
        StatusCode::UPGRADE_REQUIRED,
        "ArtifactCapabilityMismatch: schema-4 peer retired; use cluster v2",
    )
        .into_response()
}

/// `GET /api/cluster/bundle` — `cluster-policy.toml` + ETag(config_hash); 304
/// when the caller's `If-None-Match` already matches the current hash.
async fn bundle(State(state): State<Arc<ApiState>>, headers: HeaderMap) -> Response {
    let Some(_cluster) = state.cluster.as_ref() else {
        return cluster_absent();
    };
    let _ = headers;
    (
        StatusCode::UPGRADE_REQUIRED,
        "ArtifactCapabilityMismatch: schema-4 bundle retired; use cluster v2",
    )
        .into_response()
}

async fn heartbeat_v2(
    State(state): State<Arc<ApiState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    principal: Option<Extension<super::membership::AuthenticatedNode>>,
    Json(request): Json<super::dto::HeartbeatV2Request>,
) -> Response {
    let Some(cluster) = state.cluster.as_ref() else {
        return cluster_absent();
    };
    let policy = cluster.policy();
    let Some(manifest) = policy.manifest.as_ref() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "ArtifactPublicationPending",
        )
            .into_response();
    };
    let incompatible = request.artifact_format != manifest.artifact_format
        || request.schema_version != manifest.schema_version
        || request.operator_rule_grammar != manifest.operator_rule_grammar
        || request.compiled_cost_version != manifest.compiled_cost_version;
    let invalid_name = request
        .node_name
        .as_ref()
        .is_some_and(|name| super::membership::validate_name(name).is_err());
    let desired = super::dto::ArtifactIdentity::from(manifest.as_ref());
    let acknowledged = active_acknowledged(&request, &desired);
    let desired_corpus = if cluster.membership_context().is_some() {
        let store = cluster.corpus_store().cloned();
        let artifact = desired.artifact_hash.clone();
        match tokio::task::spawn_blocking(move || {
            store
                .and_then(|s| s.manifest_for_artifact(&artifact).ok())
                .map(|m| m.generation)
        })
        .await
        {
            Ok(Some(generation)) => Some(generation),
            _ => {
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "complete policy corpus not published",
                )
                    .into_response()
            }
        }
    } else {
        None
    };
    let corpus_acknowledged =
        acknowledged && desired_corpus.is_some() && request.active_corpus == desired_corpus;
    let persisted_corpus = request.persisted_corpus.clone();
    let active_corpus = request.active_corpus.clone();
    let reported_name = request.node_name.clone();
    let node_controller = state.node_controller.clone();
    let serve_state = Arc::clone(cluster);
    let master = state.config_path.clone();
    let persisted = (!incompatible && !invalid_name)
        .then(|| request.persisted.clone())
        .flatten();
    let active = (!incompatible && !invalid_name)
        .then(|| request.active.clone())
        .flatten();
    let recorded = tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
        let guard = crate::config::write_lock::acquire_for_migration(&master)?;
        if let Some(context) = serve_state.membership_context() {
            let principal = principal
                .as_ref()
                .context("authenticated node identity absent")?;
            let authoritative_name = if invalid_name {
                None
            } else {
                node_controller
                    .as_ref()
                    .map(|controller| {
                        controller.authoritative_peer_name_under_guard(&guard, &principal.node_id)
                    })
                    .transpose()?
                    .flatten()
            };
            let mut members = super::membership::MembershipStore::open(&guard)?;
            anyhow::ensure!(
                members
                    .views(super::membership::now()?)
                    .iter()
                    .any(|m| m.node_id == principal.node_id
                        && m.state == super::membership::MemberState::Active),
                "active member required for acknowledgement"
            );
            if !invalid_name {
                apply_heartbeat_membership_name(
                    &mut members,
                    &principal.node_id,
                    authoritative_name.as_deref(),
                    reported_name.as_deref(),
                )?;
            }
            return context
                .acknowledgements
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .record(
                    &principal.node_id,
                    addr.ip().to_string(),
                    super::acknowledgement::NodeAcknowledgement {
                        persisted,
                        active,
                        persisted_corpus,
                        active_corpus,
                    },
                    Instant::now(),
                );
        }
        let ip = match addr.ip() {
            std::net::IpAddr::V6(ip) => ip
                .to_ipv4_mapped()
                .map_or(std::net::IpAddr::V6(ip), std::net::IpAddr::V4),
            ip => ip,
        };
        serve_state.acknowledge(&guard, ip, persisted, active, Instant::now())
    })
    .await;
    if !matches!(recorded, Ok(Ok(()))) {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "ArtifactAcknowledgementUnavailable",
        )
            .into_response();
    }
    if incompatible {
        return (StatusCode::UPGRADE_REQUIRED, "ArtifactCapabilityMismatch").into_response();
    }
    if invalid_name {
        return (StatusCode::BAD_REQUEST, "invalid peer name").into_response();
    }
    if cluster.membership_context().is_none() {
        if let Some(observe) = &state.cluster_observe {
            observe.record_peer(
                addr.ip(),
                request.node_name,
                request.stats,
                request
                    .persisted
                    .as_ref()
                    .map_or(0, |identity| identity.policy_epoch),
                Instant::now(),
            );
            observe.record_self(current_stats(&state), Instant::now());
        }
    }
    Json(super::dto::HeartbeatV2Response {
        desired,
        active_acknowledged: acknowledged,
        desired_corpus,
        corpus_acknowledged,
    })
    .into_response()
}

fn apply_heartbeat_membership_name(
    members: &mut super::membership::MembershipStore<'_>,
    node_id: &str,
    authoritative_name: Option<&str>,
    reported_name: Option<&str>,
) -> anyhow::Result<()> {
    if let Some(name) = authoritative_name.or(reported_name) {
        members.rename(node_id, name)?;
    }
    Ok(())
}

fn active_acknowledged(
    request: &super::dto::HeartbeatV2Request,
    desired: &super::dto::ArtifactIdentity,
) -> bool {
    request.persisted.as_ref() == Some(desired)
        && request.active.as_ref().is_some_and(|ack| {
            ack.artifact == *desired && super::acknowledgement::valid_active_ack(ack)
        })
}

async fn status_v2(State(state): State<Arc<ApiState>>) -> Response {
    let Some(cluster) = state.cluster.as_ref() else {
        return cluster_absent();
    };
    let policy = cluster.policy();
    let now = Instant::now();
    let stale = std::time::Duration::from_secs(
        state
            .cluster_observe
            .as_ref()
            .map_or(45, |observe| observe.stale_secs),
    );
    if let Some(context) = cluster.membership_context() {
        let cluster = Arc::clone(cluster);
        let master = context.master.clone();
        return match tokio::task::spawn_blocking(move || -> anyhow::Result<serde_json::Value> {
            let guard=crate::config::write_lock::acquire_for_migration(&master)?;
            let primary_config=crate::config::loader::load_config_v5_with_policy_overlays_under_service_migration_guard(&guard,&master,time::OffsetDateTime::now_utc(),None,None).map_err(|_|anyhow::anyhow!("primary identity unavailable"))?;
            let mut roster=super::membership::MembershipStore::open(&guard)?.views(super::membership::now()?);
            cluster.record_membership_roster(roster.clone());
            let desired=policy.manifest.as_deref().map(super::dto::ArtifactIdentity::from);
            let corpus=desired.as_ref().and_then(|d|cluster.corpus_store().and_then(|store|store.manifest_for_artifact(&d.artifact_hash).ok())).map(|m|m.generation);
            let context=cluster.membership_context().context("membership context absent")?;
            let acks=context.acknowledgements.lock().unwrap_or_else(|e|e.into_inner());
            acks.enrich(&mut roster,desired.as_ref(),corpus.as_deref(),now,stale);
            let converged=desired.as_ref().is_some_and(|d|cluster.primary_pair_matches(d, corpus.as_deref()) && acks.converged(&roster,d,corpus.as_deref(),now,stale));
            Ok(serde_json::json!({"cluster_id":context.cluster_id,"primary_node_id":context.primary_node_id,"primary_name":primary_config.config.node.display_name(),"desired":desired,"desired_corpus":corpus,"config_generation":policy.config_generation,"policy_epoch":policy.epoch,"converged":converged,"peers":roster}))
        }).await {
            Ok(Ok(value))=>Json(value).into_response(),
            _=>(StatusCode::SERVICE_UNAVAILABLE,"membership status unavailable").into_response(),
        };
    }
    Json(serde_json::json!({
        "desired": policy.manifest.as_deref().map(super::dto::ArtifactIdentity::from),
        "config_generation": policy.config_generation,
        "policy_epoch": policy.epoch,
        "converged": policy.manifest.as_deref().is_some_and(|manifest|
            cluster.converged_for(&super::dto::ArtifactIdentity::from(manifest),now,stale)),
        "peers": cluster.peer_acknowledgements(now, stale).into_iter().map(|peer| serde_json::json!({
            "addr": peer.ip, "persisted": peer.persisted, "active": peer.active,
            "last_ack_secs": peer.last_ack_secs, "fresh": peer.fresh,
        })).collect::<Vec<_>>(),
    })).into_response()
}

async fn artifact_manifest(
    State(state): State<Arc<ApiState>>,
    RoutePath(hash): RoutePath<String>,
) -> Response {
    if !super::manifest::is_hash(&hash) {
        return (StatusCode::BAD_REQUEST, "invalid artifact hash").into_response();
    }
    let master = state.config_path.clone();
    let result = tokio::task::spawn_blocking(move || -> anyhow::Result<_> {
        let guard = crate::config::write_lock::acquire_for_migration(&master)?;
        let mut store = super::publication::PublicationStore::open(&guard)?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        let delivery = store.deliver_manifest(&hash, now)?;
        Ok(super::dto::ManifestResponse {
            manifest: super::manifest::Manifest::decode(&delivery.artifact.manifest)?,
            available_until: delivery.available_until,
        })
    })
    .await;
    match result {
        Ok(Ok(delivery)) => Json(delivery).into_response(),
        Ok(Err(error)) => {
            tracing::warn!(%error, "cluster artifact manifest unavailable");
            (StatusCode::SERVICE_UNAVAILABLE, "ArtifactUnavailable").into_response()
        }
        Err(_) => (StatusCode::SERVICE_UNAVAILABLE, "ArtifactUnavailable").into_response(),
    }
}

async fn artifact_object(
    State(state): State<Arc<ApiState>>,
    RoutePath((hash, digest)): RoutePath<(String, String)>,
) -> Response {
    if !super::manifest::is_hash(&hash) || !super::manifest::is_hash(&digest) {
        return (StatusCode::BAD_REQUEST, "invalid artifact object identity").into_response();
    }
    let master = state.config_path.clone();
    let result = tokio::task::spawn_blocking(move || -> anyhow::Result<_> {
        let guard = crate::config::write_lock::acquire_for_migration(&master)?;
        let store = super::publication::PublicationStore::open(&guard)?;
        store.object(&hash, &digest)
    })
    .await;
    match result {
        Ok(Ok(bytes)) => (
            [(header::CONTENT_TYPE, "application/octet-stream")],
            axum::body::Bytes::from_owner(bytes),
        )
            .into_response(),
        Ok(Err(error)) => {
            tracing::warn!(%error, "cluster artifact object unavailable");
            (StatusCode::SERVICE_UNAVAILABLE, "ArtifactUnavailable").into_response()
        }
        Err(_) => (StatusCode::SERVICE_UNAVAILABLE, "ArtifactUnavailable").into_response(),
    }
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
        config_generation: policy.config_generation,
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
#[cfg(test)]
fn etag_value(hash: &str) -> String {
    format!("\"{hash}\"")
}

/// True when the request's `If-None-Match` already names the current hash —
/// i.e. the caller is up to date and should get a 304. Tolerates the
/// comma-separated multi-tag form and surrounding quotes; `*` matches anything.
#[cfg(test)]
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

    struct NoopListener;

    #[async_trait::async_trait]
    impl super::super::node_control::NodeListenerControl for NoopListener {
        async fn prepare(
            &self,
            _spec: super::super::node_control::NodeListenerSpec,
        ) -> anyhow::Result<()> {
            Ok(())
        }

        async fn retire(&self, _endpoint: SocketAddr) -> anyhow::Result<()> {
            Ok(())
        }
    }

    struct NoopPairProvider;

    #[async_trait::async_trait]
    impl super::super::node_control::ActivePairProvider for NoopPairProvider {
        fn active_pair(&self) -> Option<super::super::node_control::ActivePolicyCorpus> {
            None
        }

        async fn enrollment_pair(
            &self,
        ) -> anyhow::Result<super::super::node_control::ActivePolicyCorpus> {
            anyhow::bail!("unused test provider")
        }
    }

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

    #[test]
    fn heartbeat_acknowledges_an_active_artifact_with_a_node_local_revision() {
        let desired = super::super::dto::ArtifactIdentity {
            primary_lineage: "1".repeat(64),
            policy_epoch: 1,
            artifact_hash: "2".repeat(64),
            config_revision: "3".repeat(64),
            operator_policy_hash: "4".repeat(64),
        };
        let request = super::super::dto::HeartbeatV2Request {
            artifact_format: 2,
            schema_version: 5,
            operator_rule_grammar: "1".into(),
            compiled_cost_version: crate::filter::operator_rules::CompiledCostV1::VERSION,
            persisted_corpus: None,
            active_corpus: None,
            node_name: None,
            stats: ClusterStats::default(),
            persisted: Some(desired.clone()),
            active: Some(super::super::dto::ActiveArtifactAck {
                artifact: desired.clone(),
                local_config_revision: "5".repeat(64),
                daemon_instance_id: "secondary-test".into(),
                resolver_generation: 1,
            }),
        };
        assert!(active_acknowledged(&request, &desired));
    }

    #[test]
    fn managed_rename_survives_stale_heartbeat_while_legacy_name_still_propagates() {
        let directory = tempfile::tempdir().unwrap();
        let master = directory.path().join("config.toml");
        let guard = crate::config::write_lock::acquire_for_migration(&master).unwrap();
        let cluster_id = super::super::membership::random_id();
        let primary_id = super::super::membership::random_id();
        let managed_id = super::super::membership::random_id();
        let legacy_id = super::super::membership::random_id();
        let now = super::super::membership::now().unwrap();
        let managed_credential =
            super::super::membership::SecretString(crate::auth::token::generate_token().0);
        let legacy_credential =
            super::super::membership::SecretString(crate::auth::token::generate_token().0);
        let mut members = super::super::membership::MembershipStore::initialize(
            &guard,
            &cluster_id,
            &primary_id,
            &"a".repeat(64),
        )
        .unwrap();
        for (node_id, name, credential) in [
            (&managed_id, "Secondary", &managed_credential),
            (&legacy_id, "Legacy secondary", &legacy_credential),
        ] {
            members
                .admit_prepared(
                    &super::super::membership::random_id(),
                    node_id,
                    name,
                    "192.0.2.20:8053".parse().unwrap(),
                    credential,
                    now,
                )
                .unwrap();
            let principal = members.authenticate(&credential.0, now).unwrap();
            members.activate(&principal, now).unwrap();
        }
        members.rename(&managed_id, "Office resolver").unwrap();
        drop(members);

        let mut peers = serde_json::Map::new();
        peers.insert(
            managed_id.clone(),
            serde_json::json!({
                "view": {
                    "node_id": managed_id,
                    "name": "Office resolver",
                    "endpoint": "192.0.2.20:8053",
                    "role": "secondary",
                    "state": "active",
                    "capabilities": {
                        "protocol_version": 2,
                        "persistent_management": true,
                        "endpoint_transition": true,
                        "durable_detach": true
                    },
                    "last_seen_at": null,
                    "last_error": null
                },
                "outgoing_credential": "",
                "incoming_credential_hash": "a".repeat(64),
                "issued_incoming_credential": null,
                "source_fingerprint": "b".repeat(64)
            }),
        );
        let control_state = serde_json::json!({
            "format": 1,
            "control_endpoint": null,
            "certificate_pem": null,
            "private_key_pem": null,
            "certificate_fingerprint": null,
            "previous_listener": null,
            "pending_primary_transition": null,
            "bootstrap": null,
            "peers": peers,
            "legacy_upgrade_required": [],
            "detach_receipts": {},
            "released_corpus_pins": [],
            "operations": {},
            "runtime_online": true,
            "last_shutdown_at": null
        });
        super::super::store::PrivateStore::open(&guard, ".warden-node-control")
            .unwrap()
            .write("state.json", &serde_json::to_vec(&control_state).unwrap())
            .unwrap();
        let (restart, _requests) = super::super::managed_restart::channel(1);
        let controller = super::super::node_control::NodeController::new(
            master,
            Arc::new(NoopListener),
            restart,
            Arc::new(NoopPairProvider),
        );

        let managed_name = controller
            .authoritative_peer_name_under_guard(&guard, &managed_id)
            .unwrap();
        let legacy_name = controller
            .authoritative_peer_name_under_guard(&guard, &legacy_id)
            .unwrap();
        let mut members = super::super::membership::MembershipStore::open(&guard).unwrap();
        apply_heartbeat_membership_name(
            &mut members,
            &managed_id,
            managed_name.as_deref(),
            Some("Secondary"),
        )
        .unwrap();
        apply_heartbeat_membership_name(
            &mut members,
            &legacy_id,
            legacy_name.as_deref(),
            Some("Legacy updated"),
        )
        .unwrap();
        let views = members.views(now);
        assert_eq!(
            views
                .iter()
                .find(|peer| peer.node_id == managed_id)
                .unwrap()
                .name,
            "Office resolver"
        );
        assert_eq!(
            views
                .iter()
                .find(|peer| peer.node_id == legacy_id)
                .unwrap()
                .name,
            "Legacy updated"
        );
    }
}

async fn enroll(
    State(state): State<Arc<ApiState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(request): Json<super::pairing::EnrollmentRequest>,
) -> Response {
    let Some(context) = state.cluster.as_ref().and_then(|c| c.membership_context()) else {
        return cluster_absent();
    };
    let cluster = Arc::clone(state.cluster.as_ref().expect("membership context checked"));
    let master = context.master.clone();
    let cluster_id = context.cluster_id.clone();
    let primary = context.primary_node_id.clone();
    let result = tokio::task::spawn_blocking(move || {
        let guard = crate::config::write_lock::acquire_for_migration(&master)?;
        let mut members = super::membership::MembershipStore::open(&guard)?;
        anyhow::ensure!(
            members.matches(&cluster_id, &primary)
                && request.cluster_id == cluster_id
                && request.primary_node_id == primary,
            "invitation identity mismatch"
        );
        let view = members.enroll(
            &request.invitation,
            &request.node_id,
            &request.name,
            &request.credential,
            super::membership::now()?,
        )?;
        cluster.record_membership_roster(members.views(super::membership::now()?));
        Ok::<_, anyhow::Error>(view)
    })
    .await;
    match result {
        Ok(Ok(view)) => {
            state.rate_limiter.record_success(&addr.ip());
            Json(view).into_response()
        }
        _ => {
            state.rate_limiter.record_failure(&addr.ip());
            (StatusCode::FORBIDDEN, "enrollment refused").into_response()
        }
    }
}

async fn activate(
    State(state): State<Arc<ApiState>>,
    principal: Option<Extension<super::membership::AuthenticatedNode>>,
) -> Response {
    membership_transition(state, principal, false).await
}
async fn cancel_enrollment(
    State(state): State<Arc<ApiState>>,
    principal: Option<Extension<super::membership::AuthenticatedNode>>,
) -> Response {
    membership_transition(state, principal, true).await
}
async fn membership_transition(
    state: Arc<ApiState>,
    principal: Option<Extension<super::membership::AuthenticatedNode>>,
    cancel: bool,
) -> Response {
    let Some(context) = state.cluster.as_ref().and_then(|c| c.membership_context()) else {
        return cluster_absent();
    };
    let Some(Extension(principal)) = principal else {
        return (StatusCode::UNAUTHORIZED, "node authentication required").into_response();
    };
    let master = context.master.clone();
    let cluster = state.cluster.as_ref().unwrap().clone();
    let result = tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
        let guard = crate::config::write_lock::acquire_for_migration(&master)?;
        let mut members = super::membership::MembershipStore::open(&guard)?;
        let was_pending = members.views(super::membership::now()?).iter().any(|m| {
            m.node_id == principal.node_id && m.state == super::membership::MemberState::Pending
        });
        if cancel || was_pending {
            if let Some(context) = cluster.membership_context() {
                context
                    .acknowledgements
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .forget(&principal.node_id);
            }
        }
        if cancel {
            anyhow::ensure!(
                members
                    .views(super::membership::now()?)
                    .iter()
                    .any(|m| m.node_id == principal.node_id
                        && m.state == super::membership::MemberState::Pending),
                "only pending admission can be cancelled remotely"
            );
            members.revoke(&principal.node_id)?;
        } else {
            members.activate(&principal, super::membership::now()?)?;
        }
        cluster.record_membership_roster(members.views(super::membership::now()?));
        Ok::<_, anyhow::Error>(())
    })
    .await;
    if matches!(result, Ok(Ok(()))) {
        StatusCode::NO_CONTENT.into_response()
    } else {
        (StatusCode::CONFLICT, "membership transition refused").into_response()
    }
}

#[derive(serde::Deserialize)]
struct CorpusQuery {
    artifact: String,
}
async fn corpus_manifest(
    State(state): State<Arc<ApiState>>,
    Query(query): Query<CorpusQuery>,
) -> Response {
    let Some(store) = state
        .cluster
        .as_ref()
        .and_then(|c| c.corpus_store())
        .cloned()
    else {
        return cluster_absent();
    };
    match tokio::task::spawn_blocking(move || store.manifest_for_artifact(&query.artifact)).await {
        Ok(Ok(manifest)) => Json(manifest).into_response(),
        _ => (StatusCode::NOT_FOUND, "corpus manifest unavailable").into_response(),
    }
}
async fn corpus_object(
    State(state): State<Arc<ApiState>>,
    RoutePath(digest): RoutePath<String>,
) -> Response {
    let Some(store) = state
        .cluster
        .as_ref()
        .and_then(|c| c.corpus_store())
        .cloned()
    else {
        return cluster_absent();
    };
    match tokio::task::spawn_blocking(move || store.authorized_object(&digest)).await {
        Ok(Ok(file)) => {
            let length = match file.metadata() {
                Ok(meta) => meta.len(),
                Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
            };
            let body = Body::from_stream(tokio_util::io::ReaderStream::new(
                tokio::fs::File::from_std(file),
            ));
            (
                [
                    (header::CONTENT_TYPE, "application/octet-stream".to_owned()),
                    (header::CONTENT_LENGTH, length.to_string()),
                ],
                body,
            )
                .into_response()
        }
        _ => (StatusCode::NOT_FOUND, "corpus object unavailable").into_response(),
    }
}
