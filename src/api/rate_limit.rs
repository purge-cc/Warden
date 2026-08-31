//! Per-IP fixed-window request limiter for authenticated `/api/*` routes.
//!
//! Wires `[api] rate_limit_per_minute` (a dead knob until rev-2606
//! `api-auth-07-03`). Separate concern from
//! `auth::middleware::AuthRateLimiter` (§4.48 failure lockout): that one
//! counts FAILED auth attempts; this one counts SUCCESSFUL authenticated
//! requests. Separate map, zero shared state — the pacing-attack
//! invariants cannot be touched from here by construction.
//!
//! Layering (see `api::routes::build_router`): mounted INNER to
//! `auth_middleware`, so it runs only after a request presented a valid
//! token. Unauthenticated callers can neither probe the window nor burn a
//! legitimate client's budget; `/healthz`, `/metrics`, and the
//! cluster-token-gated `/api/cluster/*` routes are exempt.

use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::{ConnectInfo, Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use dashmap::DashMap;

use crate::api::state::ApiState;

/// Fixed accounting window. Monotonic `Instant` ⇒ NTP-step immune (same
/// rationale as `AuthFailureEntry.last_failure`).
const RATE_LIMIT_WINDOW: Duration = Duration::from_secs(60);

struct RateWindow {
    window_start: Instant,
    count: u32,
    /// Audit-log "limit exceeded" once per window per IP (anti log-flood).
    limited_logged: bool,
}

/// Per-IP fixed-window counter over authenticated API requests.
pub struct ApiRateLimiter {
    /// `None` when `rate_limit_per_minute = 0` ⇒ limiter disabled:
    /// `check()` is a no-op and allocates nothing.
    limit: Option<NonZeroU32>,
    windows: DashMap<IpAddr, RateWindow>,
}

/// Outcome of an admission check.
pub enum RateDecision {
    Allowed,
    /// Remaining window in whole seconds, clamped to `1..=60`.
    Limited {
        retry_after_secs: u64,
    },
}

impl ApiRateLimiter {
    /// `limit_per_minute = 0` disables the limiter (deny-all-on-0 would
    /// silently brick the API; 0-as-unlimited is the least-surprise
    /// reading and is documented on the config field).
    pub fn new(limit_per_minute: u32) -> Self {
        Self {
            limit: NonZeroU32::new(limit_per_minute),
            windows: DashMap::new(),
        }
    }

    /// Admit or reject one request from `ip`. The `DashMap::entry` guard
    /// is held across check-then-increment, so concurrent requests from
    /// one IP cannot over-admit at the window boundary.
    pub fn check(&self, ip: IpAddr) -> RateDecision {
        let Some(limit) = self.limit else {
            return RateDecision::Allowed;
        };
        let now = Instant::now();
        let mut entry = self.windows.entry(ip).or_insert(RateWindow {
            window_start: now,
            count: 0,
            limited_logged: false,
        });

        let elapsed = now.saturating_duration_since(entry.window_start);
        if elapsed >= RATE_LIMIT_WINDOW {
            entry.window_start = now;
            entry.count = 0;
            entry.limited_logged = false;
        }

        if entry.count >= limit.get() {
            let remaining =
                RATE_LIMIT_WINDOW.saturating_sub(now.saturating_duration_since(entry.window_start));
            let retry_after_secs = (remaining.as_secs() + 1).clamp(1, 60);
            if !entry.limited_logged {
                entry.limited_logged = true;
                tracing::warn!(
                    target: "audit",
                    client_ip = %ip,
                    limit_per_minute = limit.get(),
                    "API rate limit exceeded"
                );
            }
            return RateDecision::Limited { retry_after_secs };
        }

        entry.count = entry.count.saturating_add(1);
        RateDecision::Allowed
    }

    /// Drop windows older than `RATE_LIMIT_WINDOW`. Called from the same
    /// 60 s housekeeping task that sweeps `AuthRateLimiter` — bounds the
    /// map at "IPs that authenticated in the last ~2 minutes".
    pub fn cleanup(&self) {
        let now = Instant::now();
        self.windows
            .retain(|_, w| now.saturating_duration_since(w.window_start) < RATE_LIMIT_WINDOW);
    }
}

/// Axum middleware: enforce the per-IP request budget. Mounted inner to
/// `auth_middleware`, so every request seen here already carries a valid
/// token.
pub async fn rate_limit_middleware(
    State(state): State<Arc<ApiState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    request: Request,
    next: Next,
) -> Response {
    match state.api_rate_limiter.check(addr.ip()) {
        RateDecision::Allowed => next.run(request).await,
        RateDecision::Limited { retry_after_secs } => (
            StatusCode::TOO_MANY_REQUESTS,
            [("Retry-After", retry_after_secs.to_string())],
            // Body deliberately distinct from the auth-lockout 429
            // ("Too many failed attempts. Try again later.") so the two
            // throttles are tellable apart from the client side.
            "API rate limit exceeded. Try again later.",
        )
            .into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    /// Backdate an IP's window by `secs` — the same test-only map poke
    /// `auth::middleware` uses to simulate elapsed time.
    fn backdate(limiter: &ApiRateLimiter, ip: IpAddr, secs: u64) {
        let mut entry = limiter.windows.get_mut(&ip).unwrap();
        entry.window_start = Instant::now() - Duration::from_secs(secs);
    }

    #[test]
    fn allows_up_to_limit_then_limits() {
        let limiter = ApiRateLimiter::new(3);
        let a = ip("10.0.0.1");
        for _ in 0..3 {
            assert!(matches!(limiter.check(a), RateDecision::Allowed));
        }
        assert!(matches!(limiter.check(a), RateDecision::Limited { .. }));
    }

    #[test]
    fn per_ip_budgets_independent() {
        let limiter = ApiRateLimiter::new(1);
        let a = ip("10.0.0.1");
        let b = ip("10.0.0.2");
        assert!(matches!(limiter.check(a), RateDecision::Allowed));
        assert!(matches!(limiter.check(a), RateDecision::Limited { .. }));
        assert!(matches!(limiter.check(b), RateDecision::Allowed));
    }

    #[test]
    fn zero_limit_disables_and_allocates_nothing() {
        let limiter = ApiRateLimiter::new(0);
        let a = ip("10.0.0.1");
        for _ in 0..1000 {
            assert!(matches!(limiter.check(a), RateDecision::Allowed));
        }
        assert_eq!(
            limiter.windows.len(),
            0,
            "disabled limiter must not allocate"
        );
    }

    #[test]
    fn window_resets_after_expiry() {
        let limiter = ApiRateLimiter::new(2);
        let a = ip("10.0.0.1");
        limiter.check(a);
        limiter.check(a);
        assert!(matches!(limiter.check(a), RateDecision::Limited { .. }));
        backdate(&limiter, a, 61);
        assert!(matches!(limiter.check(a), RateDecision::Allowed));
    }

    #[test]
    fn retry_after_clamped_1_to_60() {
        let limiter = ApiRateLimiter::new(1);
        let a = ip("10.0.0.1");
        limiter.check(a);
        match limiter.check(a) {
            RateDecision::Limited { retry_after_secs } => {
                assert!((1..=60).contains(&retry_after_secs), "{retry_after_secs}");
            }
            RateDecision::Allowed => panic!("expected Limited"),
        }
        // Near window end the hint counts down but never reaches 0.
        backdate(&limiter, a, 59);
        match limiter.check(a) {
            RateDecision::Limited { retry_after_secs } => {
                assert!((1..=2).contains(&retry_after_secs), "{retry_after_secs}");
            }
            RateDecision::Allowed => panic!("expected Limited near window end"),
        }
    }

    #[test]
    fn count_saturates_at_u32_max_no_wrap() {
        let limiter = ApiRateLimiter::new(u32::MAX);
        let a = ip("10.0.0.1");
        assert!(matches!(limiter.check(a), RateDecision::Allowed));
        limiter.windows.get_mut(&a).unwrap().count = u32::MAX - 1;
        // u32::MAX - 1 < MAX ⇒ admit + saturate; then count == MAX ⇒ limit.
        assert!(matches!(limiter.check(a), RateDecision::Allowed));
        assert!(matches!(limiter.check(a), RateDecision::Limited { .. }));
        assert_eq!(limiter.windows.get(&a).unwrap().count, u32::MAX);
    }

    #[test]
    fn concurrent_burst_admits_exactly_limit() {
        const LIMIT: u32 = 50;
        let limiter = Arc::new(ApiRateLimiter::new(LIMIT));
        let a = ip("10.0.0.1");
        let mut handles = Vec::new();
        for _ in 0..8 {
            let l = Arc::clone(&limiter);
            handles.push(std::thread::spawn(move || {
                let mut admitted = 0u32;
                for _ in 0..25 {
                    if matches!(l.check(a), RateDecision::Allowed) {
                        admitted += 1;
                    }
                }
                admitted
            }));
        }
        let total: u32 = handles.into_iter().map(|h| h.join().unwrap()).sum();
        assert_eq!(
            total, LIMIT,
            "entry-guard atomicity must admit exactly the limit"
        );
    }

    #[test]
    fn cleanup_evicts_expired_keeps_live() {
        let limiter = ApiRateLimiter::new(10);
        let stale = ip("10.0.0.1");
        let live = ip("10.0.0.2");
        limiter.check(stale);
        limiter.check(live);
        backdate(&limiter, stale, 61);
        limiter.cleanup();
        assert!(
            limiter.windows.get(&stale).is_none(),
            "stale window evicted"
        );
        assert!(limiter.windows.get(&live).is_some(), "live window kept");
    }
}
