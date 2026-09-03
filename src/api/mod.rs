//! Optional REST API — read-only observability plus a small set of config
//! mutations.
//!
//! Off unless the operator sets `[api] enabled`: the daemon builds no
//! listener otherwise, so a default install exposes no HTTP surface at all.
//!
//! The server serves TLS when a cert and key are configured and plain HTTP
//! when they are not. Loopback is the only place that second branch is
//! reachable — the validator refuses an enabled API on a non-loopback
//! `listen` without both, so a bearer token cannot cross the network in
//! clear by omission.
//!
//! **Nothing here is on the DNS query path.** Handlers read the same
//! `ArcSwap` and atomic state the resolver publishes, and a mutation writes
//! `config.toml` and then notifies the daemon to reload rather than editing
//! live state. Nothing watches those files, so that notification is the only
//! thing that applies the change: when it fails the handler answers 500
//! naming the edit that reached disk and not memory, rather than a 200 that
//! would read as applied.
//!
//! Three auth regimes coexist, and which one a route gets is decided once
//! in [`routes::build_router`] rather than per handler:
//!
//! - `/api/*` — bearer token first, [`rate_limit`] second. That order is
//!   what stops an unauthenticated caller probing the window or spending a
//!   valid client's budget.
//! - `/healthz` always, `/metrics` only when `[api] metrics_enabled` — both
//!   public. A disabled `/metrics` is not registered at all rather than
//!   registered and refusing, so it is not an enumeration surface.
//! - `/api/cluster/*` — its own cluster token plus a peer-CIDR gate,
//!   mounted only on a primary with clustering on.

pub mod deprecation;
pub mod handlers;
pub mod rate_limit;
pub mod routes;
pub mod server;
pub mod state;
