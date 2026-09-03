//! Bearer token authentication middleware for the REST API.
//!
//! Extracts `Authorization: Bearer <token>` from requests, verifies against
//! the stored hash, and enforces lockout after repeated failures.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::{ConnectInfo, State};
use axum::http::{Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use dashmap::DashMap;

use super::token::verify_token;
use crate::api::state::ApiState;

const MAX_FAILURES: u32 = 10;
const LOCKOUT_DURATION: Duration = Duration::from_secs(300); // 5 minutes

/// Failure counters stay in the map for this long after the last failed
/// attempt. Sized as 4× `LOCKOUT_DURATION` so a paced attacker must fire
/// faster than 1 fail per 20 min to keep accumulating toward
/// `MAX_FAILURES` — the pacing-attack threat model this window
/// defends against.
const STALENESS_WINDOW: Duration = Duration::from_secs(LOCKOUT_DURATION.as_secs() * 4);

/// Hard cap on the number of tracked source addresses.
///
/// Mirrors the cap `security::rate_limiter` applies, for the same reason:
/// any peer that can reach the port mints a fresh map slot per source
/// address, and the IPv6 address space makes that supply effectively
/// unlimited. `cleanup` bounds entry *age*, never the entry count, so the
/// ceiling has to be enforced where entries are created.
const MAX_TRACKED_IPS: usize = 100_000;

/// Unlocked entries to weigh per over-cap insert before picking a victim.
/// Sampling rather than exact LRU: an exact ordering needs a shared list
/// touched on every access, and the approximation holds the ceiling just
/// as well.
const EVICTION_SAMPLE: usize = 8;

/// Ceiling on entries visited while looking for an unlocked victim, so a
/// map saturated with locked-out entries cannot turn one insert into a
/// full scan.
const EVICTION_SCAN_LIMIT: usize = EVICTION_SAMPLE * 4;

/// Per-IP auth failure state.
///
/// `last_failure` is updated on every `record_failure` call and is used
/// by `cleanup` to drop entries whose failure counters have gone stale
/// (no new failures within `STALENESS_WINDOW`). Monotonic `Instant`
/// avoids clock-skew artifacts (NTP corrections, leap seconds). See
/// the pacing-attack threat model that motivated the staleness
/// check.
struct AuthFailureEntry {
    count: u32,
    last_failure: Instant,
    lockout_until: Option<Instant>,
}

/// Tracks auth failures per IP for lockout enforcement.
///
/// Holds at most `MAX_TRACKED_IPS` entries; an insert beyond that evicts an
/// approximately-oldest entry that is not serving a lockout.
pub struct AuthRateLimiter {
    failures: DashMap<IpAddr, AuthFailureEntry>,
    cap: usize,
}

impl Default for AuthRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl AuthRateLimiter {
    pub fn new() -> Self {
        Self::with_cap(MAX_TRACKED_IPS)
    }

    fn with_cap(cap: usize) -> Self {
        Self {
            failures: DashMap::new(),
            cap,
        }
    }

    /// Drop one entry to make room, preferring the oldest that is not
    /// serving an active lockout.
    ///
    /// The lockout preference is why this cannot order on age alone. A
    /// locked-out IP is turned away before `record_failure` runs, so its
    /// `last_failure` stops advancing and it becomes the oldest entry in
    /// the map precisely because the lockout is holding. Evicting it clears
    /// the lockout, which would sell an attacker a reset for a flood they
    /// are already sending.
    ///
    /// When every entry the scan reaches is locked out, the oldest of those
    /// is evicted anyway: the size ceiling is the harder guarantee, and the
    /// attacker still cannot choose whose lockout is lifted.
    fn evict_one(&self, now: Instant) {
        // DashMap's iterator holds shard read locks, so the victim is
        // chosen inside a scope that ends before the removal.
        let victim = {
            let mut oldest_unlocked: Option<(IpAddr, Instant)> = None;
            let mut oldest_any: Option<(IpAddr, Instant)> = None;
            let mut unlocked_seen = 0usize;
            let mut visited = 0usize;
            for entry in self.failures.iter() {
                let key = *entry.key();
                let age = entry.last_failure;
                if entry.lockout_until.is_none_or(|until| now >= until) {
                    unlocked_seen += 1;
                    if oldest_unlocked.is_none_or(|(_, cur)| age < cur) {
                        oldest_unlocked = Some((key, age));
                    }
                }
                if oldest_any.is_none_or(|(_, cur)| age < cur) {
                    oldest_any = Some((key, age));
                }
                visited += 1;
                if unlocked_seen >= EVICTION_SAMPLE || visited >= EVICTION_SCAN_LIMIT {
                    break;
                }
            }
            oldest_unlocked.or(oldest_any)
        };
        if let Some((ip, _)) = victim {
            self.failures.remove(&ip);
        }
    }

    /// Check if an IP is currently locked out.
    /// If the lockout has expired, clears the entry (decay) and returns false.
    pub fn is_locked_out(&self, ip: &IpAddr) -> bool {
        if let Some(entry) = self.failures.get(ip) {
            if let Some(until) = entry.lockout_until {
                if Instant::now() < until {
                    return true;
                }
                // Lockout expired — drop the read guard before removing
                drop(entry);
                self.failures.remove(ip);
                tracing::info!(
                    target: "audit",
                    client_ip = %ip,
                    "lockout expired and cleared"
                );
                return false;
            }
        }
        false
    }

    /// Record a failed auth attempt. Returns `true` if the IP is now locked out.
    pub fn record_failure(&self, ip: &IpAddr) -> bool {
        let now = Instant::now();
        // Probe for an existing entry before `len()`, which read-locks every
        // shard: a repeat offender must not pay that scan, and only a source
        // address the map has never seen can push it past the cap. The check
        // is deliberately not atomic with the insert below, so concurrent
        // inserts may overshoot by a few entries; the next eviction reclaims
        // them.
        if !self.failures.contains_key(ip) && self.failures.len() >= self.cap {
            self.evict_one(now);
        }
        let mut entry = self.failures.entry(*ip).or_insert(AuthFailureEntry {
            count: 0,
            last_failure: now,
            lockout_until: None,
        });
        entry.count += 1;
        entry.last_failure = now;
        if entry.count >= MAX_FAILURES {
            let newly_locked = entry.lockout_until.is_none();
            entry.lockout_until = Some(now + LOCKOUT_DURATION);
            if newly_locked {
                tracing::warn!(
                    target: "audit",
                    client_ip = %ip,
                    "lockout triggered: {MAX_FAILURES} failed auth attempts"
                );
            }
            return true;
        }
        false
    }

    /// Record a successful auth. Clears the failure counter for this IP.
    pub fn record_success(&self, ip: &IpAddr) {
        if self.failures.remove(ip).is_some() {
            tracing::info!(
                target: "audit",
                client_ip = %ip,
                "auth failure counter cleared on success"
            );
        }
    }

    /// Remove stale entries.
    ///
    /// Keeps entries with EITHER:
    /// 1. An active lockout (`lockout_until = Some(t)`, `t > now`) — pinned
    ///    until the lockout naturally expires; or
    /// 2. A non-zero failure counter whose `last_failure` is fresher than
    ///    `STALENESS_WINDOW` — pinned so an attacker pacing failures across
    ///    cleanup ticks (cadence ~60s, see `src/cli/commands/start.rs`)
    ///    still accumulates toward `MAX_FAILURES`. Without this, a
    ///    9-fail-per-60s pacing attack would never trip the lockout
    ///    (see the pacing-attack regression test below).
    ///
    /// Entries with neither active lockout nor a fresh failure are dropped.
    /// That is an age bound, not a size bound: between ticks the map still
    /// grows with the failure rate, so what limits its size is
    /// `MAX_TRACKED_IPS`, enforced when an entry is created.
    pub fn cleanup(&self) {
        let now = Instant::now();
        self.failures.retain(|_, entry| {
            let lockout_active = entry.lockout_until.is_some_and(|until| now < until);
            let staleness_alive = entry.count > 0
                && now.saturating_duration_since(entry.last_failure) < STALENESS_WINDOW;
            lockout_active || staleness_alive
        });
    }
}

/// Axum middleware: verify Bearer token on every request.
pub async fn auth_middleware(
    State(state): State<Arc<ApiState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    request: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let ip = addr.ip();

    // Check lockout first
    if state.rate_limiter.is_locked_out(&ip) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [("Retry-After", "300")],
            "Too many failed attempts. Try again later.",
        )
            .into_response();
    }

    // Extract Bearer token
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

    // Verify token
    if !verify_token(token, &state.token_hash) {
        let locked = state.rate_limiter.record_failure(&ip);
        tracing::warn!(
            target: "audit",
            client_ip = %ip,
            locked_out = locked,
            "invalid API token"
        );
        return (StatusCode::UNAUTHORIZED, "Invalid token").into_response();
    }

    // Success — clear any accumulated failure count
    state.rate_limiter.record_success(&ip);

    next.run(request).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lockout_after_max_failures() {
        let limiter = AuthRateLimiter::new();
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        for _ in 0..9 {
            assert!(!limiter.record_failure(&ip));
            assert!(!limiter.is_locked_out(&ip));
        }
        assert!(limiter.record_failure(&ip)); // 10th failure
        assert!(limiter.is_locked_out(&ip));
    }

    #[test]
    fn different_ips_independent() {
        let limiter = AuthRateLimiter::new();
        let ip1: IpAddr = "192.168.1.1".parse().unwrap();
        let ip2: IpAddr = "192.168.1.2".parse().unwrap();

        for _ in 0..10 {
            limiter.record_failure(&ip1);
        }
        assert!(limiter.is_locked_out(&ip1));
        assert!(!limiter.is_locked_out(&ip2));
    }

    #[test]
    fn cleanup_removes_stale() {
        let limiter = AuthRateLimiter::new();
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        // Add a non-lockout entry.
        limiter.record_failure(&ip);
        assert_eq!(limiter.failures.len(), 1);

        // Fresh entry — staleness check keeps it.
        limiter.cleanup();
        assert_eq!(limiter.failures.len(), 1);

        // Age `last_failure` past STALENESS_WINDOW; cleanup now evicts.
        if let Some(mut e) = limiter.failures.get_mut(&ip) {
            e.last_failure = Instant::now() - STALENESS_WINDOW - Duration::from_secs(1);
        }
        limiter.cleanup();
        assert_eq!(limiter.failures.len(), 0);
    }

    #[test]
    fn no_lockout_below_threshold() {
        let limiter = AuthRateLimiter::new();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        for _ in 0..5 {
            limiter.record_failure(&ip);
        }
        assert!(!limiter.is_locked_out(&ip));
    }

    #[test]
    fn success_clears_failure_counter() {
        let limiter = AuthRateLimiter::new();
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        // Accumulate 9 failures (one away from lockout)
        for _ in 0..9 {
            limiter.record_failure(&ip);
        }
        assert!(!limiter.is_locked_out(&ip));

        // Successful auth clears the counter
        limiter.record_success(&ip);
        assert_eq!(limiter.failures.len(), 0);

        // Now 9 more failures won't trigger lockout (counter was reset)
        for _ in 0..9 {
            limiter.record_failure(&ip);
        }
        assert!(!limiter.is_locked_out(&ip));
    }

    #[test]
    fn lockout_decays_after_expiry() {
        let limiter = AuthRateLimiter::new();
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        // Trigger lockout
        for _ in 0..10 {
            limiter.record_failure(&ip);
        }
        assert!(limiter.is_locked_out(&ip));

        // Manually expire the lockout by setting it to the past
        if let Some(mut entry) = limiter.failures.get_mut(&ip) {
            entry.lockout_until = Some(Instant::now() - Duration::from_secs(1));
        }

        // Should no longer be locked out (decayed)
        assert!(!limiter.is_locked_out(&ip));
        // Entry should have been removed
        assert_eq!(limiter.failures.len(), 0);
    }

    /// Regression: a 9-fails-per-cleanup-window pacing attack used to
    /// reset the counter every 60s and never trip `MAX_FAILURES`. The
    /// staleness window keeps the entry across cleanup ticks so the
    /// 10th fail (a window later) trips the lockout as policy dictates.
    #[test]
    fn pacing_attack_trips_lockout_across_cleanup_ticks() {
        let limiter = AuthRateLimiter::new();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        // Window 1: 9 fails (one shy of lockout).
        for _ in 0..9 {
            assert!(!limiter.record_failure(&ip));
        }
        assert!(!limiter.is_locked_out(&ip));

        // Cleanup tick lands between attacker's pacing windows.
        // Without the staleness window: drops the entry, counter resets to 0.
        // With it: `last_failure` is fresh, entry kept with count=9.
        limiter.cleanup();

        // Window 2: 1 more fail.
        // Without the staleness window: count=1 (fresh entry), no lockout — attacker paces forever.
        // With it: count=10 (accumulated across cleanup), lockout fires.
        let locked = limiter.record_failure(&ip);
        assert!(locked, "10th fail across cleanup tick should trip lockout");
        assert!(limiter.is_locked_out(&ip));
    }

    /// DoS-safety floor: when the attacker stops pacing, entries DO
    /// evict at the next cleanup tick that lands past `STALENESS_WINDOW`,
    /// so the failures map cannot grow unboundedly under a
    /// pacing-spread-across-many-IPs scenario.
    #[test]
    fn stale_entry_evicted_after_staleness_window() {
        let limiter = AuthRateLimiter::new();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        limiter.record_failure(&ip);
        assert_eq!(limiter.failures.len(), 1);

        // Manually age `last_failure` past the staleness window.
        if let Some(mut e) = limiter.failures.get_mut(&ip) {
            e.last_failure = Instant::now() - STALENESS_WINDOW - Duration::from_secs(1);
        }

        limiter.cleanup();
        assert_eq!(
            limiter.failures.len(),
            0,
            "Entry stale beyond STALENESS_WINDOW must evict"
        );
    }

    /// One address per index out of a single /64 — the supply an attacker
    /// has for free, and the reason an age sweep cannot bound this map.
    fn nth_ip(i: u128) -> IpAddr {
        IpAddr::from(std::net::Ipv6Addr::from((0x2001_0db8u128 << 96) | i))
    }

    #[test]
    fn unique_ip_flood_stays_within_cap() {
        let limiter = AuthRateLimiter::new();
        for i in 0..(MAX_TRACKED_IPS as u128 * 2) {
            limiter.record_failure(&nth_ip(i));
        }
        let len = limiter.failures.len();
        assert!(
            len <= MAX_TRACKED_IPS,
            "failures map holds {len} entries against a cap of {MAX_TRACKED_IPS}"
        );
    }

    /// A capped map must not become a lockout reset. A locked-out IP is
    /// turned away before `record_failure`, so its `last_failure` freezes
    /// and it is the oldest entry in the map exactly while the lockout is
    /// doing its job. Age-ordered eviction would therefore evict it first,
    /// and the flood that fills the map is one the attacker is already
    /// sending.
    #[test]
    fn active_lockout_survives_unique_ip_flood() {
        let limiter = AuthRateLimiter::with_cap(16);
        let attacker: IpAddr = "10.0.0.1".parse().unwrap();

        for _ in 0..MAX_FAILURES {
            limiter.record_failure(&attacker);
        }
        assert!(limiter.is_locked_out(&attacker));

        for i in 0..1_000u128 {
            limiter.record_failure(&nth_ip(i));
        }

        assert!(
            limiter.is_locked_out(&attacker),
            "eviction cleared an active lockout: a unique-IP flood bought a reset"
        );
        assert!(limiter.failures.len() <= 16);
    }

    /// The size ceiling outranks the lockout preference. When no unlocked
    /// victim is reachable the oldest locked entry goes, or a map that an
    /// attacker saturates with lockouts would grow without limit again.
    #[test]
    fn flood_of_locked_out_entries_still_respects_the_cap() {
        let limiter = AuthRateLimiter::with_cap(16);
        for i in 0..200u128 {
            let ip = nth_ip(i);
            for _ in 0..MAX_FAILURES {
                limiter.record_failure(&ip);
            }
        }
        let len = limiter.failures.len();
        assert!(
            len <= 16,
            "all-locked map grew to {len} against a cap of 16"
        );
    }

    /// Eviction takes the least-recently-failed entry, so an attacker who
    /// keeps failing refreshes their own timestamp and is the last to be
    /// evicted, not the first. The pacing counter survives the cap.
    #[test]
    fn eviction_prefers_the_least_recently_failed_entry() {
        let limiter = AuthRateLimiter::with_cap(4);
        let idle: IpAddr = "10.0.0.1".parse().unwrap();

        limiter.record_failure(&idle);
        for i in 1..4u128 {
            limiter.record_failure(&nth_ip(i));
        }
        assert_eq!(limiter.failures.len(), 4);

        let fresh = nth_ip(99);
        limiter.record_failure(&fresh);

        assert!(
            limiter.failures.get(&idle).is_none(),
            "the least-recently-failed entry should be the victim"
        );
        assert!(limiter.failures.get(&fresh).is_some());
        assert_eq!(limiter.failures.len(), 4);
    }
}
