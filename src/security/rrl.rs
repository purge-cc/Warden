//! Response Rate Limiting (RRL) — mitigates DNS amplification attacks.
//!
//! Tracks outgoing response rate per destination /24 subnet (IPv4) or /48
//! prefix (IPv6). When rate exceeds threshold, responses are either dropped
//! or "slipped" (TC bit set, forcing TCP retry which proves non-spoofed).
//!
//! Key insight: attackers spoof source IPs within nearby ranges, so tracking
//! per /24 subnet catches amplification patterns that per-IP tracking misses.
//!
//! That grouping is correct for sources the operator has not vouched for and
//! wrong for the ones it has: on a household LAN it put every device into a
//! single shared budget, so one noisy client could throttle the rest. Callers
//! that have confirmed a source sits inside a configured `server.allow_from`
//! CIDR pass `per_client = true` to [`Rrl::check`] to key on the exact
//! address instead. See [`client_key`] for the full rationale and the
//! key-space disjointness argument.

use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Instant;

use arc_swap::ArcSwap;

use super::atomic_window::AtomicWindowCounter;
use super::bounded_map::BoundedMap;
use crate::config::settings::RrlConfig;

/// Hard cap on the number of tracked destination prefixes (P0-4).
///
/// RRL buckets keyed per /24 (IPv4) or /48 (IPv6) give 2^24 and 2^48
/// possible keys respectively. A spoofed-source amplification flood can
/// pin all of those as live entries without this cap. When at capacity,
/// new inserts evict the prefix with the oldest window_start via sample-8
/// approximate LRU — good enough because RRL state is already a rate
/// *approximation* per window.
const MAX_TRACKED_PREFIXES: usize = 100_000;

/// Extract window_start for [`BoundedMap`] eviction ordering.
fn prefix_age(state: &PrefixState) -> u64 {
    state.counter.window_start_secs()
}

/// What to do with a response that exceeds the rate limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RrlAction {
    /// Send the response normally.
    Allow,
    /// Drop the response entirely.
    Drop,
    /// Send a truncated response (TC bit set) to force TCP retry.
    Slip,
}

/// Per-/24 (or /48 for IPv6) counter state.
struct PrefixState {
    /// Packed `[count:u32 | window_start_secs:u32]` — atomic window reset
    /// closes the Hermes T2.3 TOCTOU between the prior two-store reset
    /// pattern. Preserves the L-11 invariant: first responder sees prior
    /// count = 0, so a single `check_and_bump` covers first-responder and
    /// subsequent-responder paths uniformly.
    counter: AtomicWindowCounter,
    /// Per-prefix slip selection counter (rrl-02, rev-2606). BIND-style:
    /// each throttled prefix gets its own deterministic 1-in-N TC-slip
    /// cadence. Pre-fix this was one global counter, so under concurrent
    /// over-budget prefixes one victim /24 could draw consecutive Drops
    /// (clients waiting out full timeouts) while another absorbed the
    /// Slips — the alternation was only statistical globally.
    slip: AtomicU32,
}

impl PrefixState {
    fn new(now_secs: u64) -> Self {
        Self {
            counter: AtomicWindowCounter::new(now_secs),
            slip: AtomicU32::new(0),
        }
    }
}

/// Response rate limiter. Tracks response rates per destination prefix.
///
/// Backed by a [`BoundedMap`] capped at [`MAX_TRACKED_PREFIXES`] — prevents
/// memory DoS from spoofed-source floods that would otherwise create one
/// tracker per attacker-chosen /24 or /48 (P0-4).
pub struct Rrl {
    prefixes: BoundedMap<u64, PrefixState>,
    /// Live-swappable throughput settings. See [`RrlParams`].
    params: ArcSwap<RrlParams>,
    /// Monotonic epoch every `window_start` is measured against.
    /// Deliberately **outside** [`Self::params`]: swapping it on reload
    /// would silently corrupt every live window rather than retune
    /// anything.
    created_at: Instant,
}

/// The reload-swappable half of [`Rrl`].
///
/// Split out of [`Rrl`] so `warden security set rrl.responses_per_second
/// …` takes effect without a daemon restart. `prefixes` is *not* in here
/// on purpose: rebuilding the whole limiter on reload would zero every
/// per-prefix counter, handing every destination a fresh budget on each
/// config edit — resetting the very gate this is meant to make tunable.
#[derive(Debug, Clone)]
struct RrlParams {
    responses_per_second: u32,
    window_secs: u64,
    slip_rate: u32,
}

impl RrlParams {
    fn from_config(config: &RrlConfig) -> Self {
        Self {
            responses_per_second: config.responses_per_second,
            // settings-12 (rev-2606): a zero window resets the counter on
            // every probe and zeroes max_count — RRL silently off. The
            // validator rejects 0 when rrl is enabled; this floor is the
            // backstop for construction AND reload paths that bypass it.
            window_secs: config.window_secs.max(1),
            slip_rate: config.slip_rate,
        }
    }
}

impl Rrl {
    pub fn new(config: &RrlConfig) -> Self {
        Self {
            prefixes: BoundedMap::new(MAX_TRACKED_PREFIXES, prefix_age),
            params: ArcSwap::from_pointee(RrlParams::from_config(config)),
            created_at: Instant::now(),
        }
    }

    /// Swap throughput settings in place, preserving every live prefix
    /// counter. Called from the daemon's config-reload path.
    pub fn set_params(&self, config: &RrlConfig) {
        self.params.store(Arc::new(RrlParams::from_config(config)));
    }

    /// Current number of tracked destination prefixes.
    #[allow(dead_code)] // wired to stats/metrics in P1-13
    pub fn entry_count(&self) -> usize {
        self.prefixes.len()
    }

    /// Check if a response to this destination IP should be allowed, dropped, or slipped.
    ///
    /// L-11 (rev-2026-05-rrl-tunneling-toctou): atomic get-or-insert via
    /// [`super::bounded_map::BoundedMap::entry_or_insert_with`] closes the
    /// prior get-then-insert race. Pre-fix two concurrent first responses
    /// to a fresh prefix both saw `get(...) = None` and both ran
    /// `prefixes.insert(...)`, with the second `insert` overwriting the
    /// first — the per-prefix counter restarted at 1 instead of climbing.
    /// On a spoofed-source amplification flood (the scenario RRL exists to
    /// mitigate) this leaked the budget by `concurrency` on every fresh
    /// /24 the attacker chose. Mirrors the L-1 fix in `rate_limiter.rs`.
    ///
    /// Hermes T2.3 (rev-2026-05-18): window reset uses the packed
    /// [`AtomicWindowCounter`] so the prior two-store reset (ws then
    /// count) is now a single CAS — no torn intermediate state.
    ///
    /// `per_client` narrows the budget from a shared prefix to this exact
    /// address. See [`client_key`] for why the caller — not this function
    /// — decides, and what it must have established first.
    ///
    /// **Exactly one `params.load()` per call.** A second load could pair
    /// a pre-reload `responses_per_second` with a post-reload
    /// `window_secs` (or `slip_rate`), producing a budget or slip cadence
    /// that matches neither configuration.
    pub fn check(&self, dest_ip: &IpAddr, per_client: bool) -> RrlAction {
        let prefix_key = if per_client {
            client_key(dest_ip)
        } else {
            prefix_key(dest_ip)
        };
        let now_secs = self.created_at.elapsed().as_secs();
        let p = self.params.load();
        // settings-12 (rev-2606): saturate the u64→u32 narrowing instead of
        // `as`-truncating it — a window of exactly 2^32 truncated to 0,
        // turning the budget into "throttle everything". Saturation errs
        // toward a huge budget (≈ RRL off for absurd windows), never a
        // zero one; the validator bounds the window to 1..=86400 anyway.
        let window_u32 = u32::try_from(p.window_secs).unwrap_or(u32::MAX);
        let max_count = p.responses_per_second.saturating_mul(window_u32);

        let state = self
            .prefixes
            .entry_or_insert_with(prefix_key, || PrefixState::new(now_secs));

        let count = state.counter.check_and_bump(now_secs, p.window_secs);
        // rrl-02 (rev-2606): slip selection reads the prefix's OWN counter,
        // so the decision happens while the shard guard is still held —
        // one Relaxed fetch_add, nanoseconds. (The pre-fix guard-drop here
        // protected same-shard inserts from waiting on the then-*global*
        // slip counter; per-prefix state removed that coupling.)
        let action = if count < max_count {
            RrlAction::Allow
        } else {
            self.slip_or_drop(&state.slip, p.slip_rate)
        };
        drop(state);
        action
    }

    /// Decide between Drop and Slip from the prefix's slip counter
    /// (rrl-02: per-prefix, BIND-style — each victim /24 gets its own
    /// deterministic 1-in-N TC-slip cadence instead of competing with
    /// every other throttled prefix for a global alternation).
    ///
    /// `slip_rate` is passed in rather than reread from `self.params` so
    /// that [`Self::check`]'s single load stays the only one on this path.
    fn slip_or_drop(&self, slip: &AtomicU32, slip_rate: u32) -> RrlAction {
        if slip_rate == 0 {
            return RrlAction::Drop;
        }
        if slip_rate == 1 {
            return RrlAction::Slip;
        }
        let n = slip.fetch_add(1, Ordering::Relaxed);
        if n.is_multiple_of(slip_rate) {
            RrlAction::Slip
        } else {
            RrlAction::Drop
        }
    }

    /// Remove stale entries older than 2x the window. Call periodically.
    pub fn cleanup(&self) {
        let now_secs = self.created_at.elapsed().as_secs();
        let stale = self.params.load().window_secs * 2;

        self.prefixes.retain(|_, state| {
            let ws = state.counter.window_start_secs();
            now_secs.saturating_sub(ws) < stale
        });
    }
}

/// Per-exact-address key, for clients the caller has already established
/// are inside a configured `server.allow_from` CIDR.
///
/// # Why this is not the default
///
/// [`prefix_key`]'s /24 grouping is anti-spoofing: an attacker who
/// randomises the low octet within a prefix gets 254 fresh budgets under
/// per-address keying and one under prefix keying. That defence is real
/// and stays in place for every source the operator has not vouched for.
///
/// # Why it is nonetheless right inside `allow_from`
///
/// Grouping the whole household into a single budget made one device able
/// to deny service to another. Measured 2026-07-28 on the live CT: a
/// 500-query burst from the dev box (192.0.2.14) caused RRL_DROP and
/// RRL_SLIP on a real Philips Hue bridge (192.0.2.243) and a second
/// device, purely because they shared 192.0.2.0/24 — with the CT running
/// `responses_per_second = 5`, i.e. 75 responses per 15s window for the
/// entire house. Baseline throttling outside that test window was zero.
///
/// Within `allow_from` the spoofing calculus also changes: the ACL has
/// already refused anything outside those CIDRs (the refusal exits above
/// the RRL check in `dns::handler`), and a spoofed source claiming a LAN
/// address only redirects the response to that same LAN.
///
/// # Key-space disjointness
///
/// Both key functions feed one map, so their outputs must never collide.
/// Bit 63 marks IPv6, bit 62 marks per-client:
///
/// | key                | 63 | 62 |
/// |--------------------|----|----|
/// | `prefix_key` v4    | 0  | 0  |
/// | `client_key` v4    | 0  | 1  |
/// | `prefix_key` v6    | 1  | 0  |
/// | `client_key` v6    | 1  | 1  |
///
/// A collision would let one client's traffic decrement another's budget.
pub(crate) fn client_key(ip: &IpAddr) -> u64 {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            // All four octets fit in 32 bits, so this is exact — no
            // hashing and therefore no collisions between IPv4 clients.
            (1u64 << 62)
                | ((o[0] as u64) << 24)
                | ((o[1] as u64) << 16)
                | ((o[2] as u64) << 8)
                | (o[3] as u64)
        }
        IpAddr::V6(v6) => {
            // 128 bits do not fit, so fold with FNV-1a and keep 62 bits.
            // A collision here costs two v6 clients a shared budget — the
            // status quo for everyone today — never a bypass.
            let mut h: u64 = 0xcbf2_9ce4_8422_2325;
            for b in v6.octets() {
                h ^= b as u64;
                h = h.wrapping_mul(0x100_0000_01b3);
            }
            (h >> 2) | (1u64 << 63) | (1u64 << 62)
        }
    }
}

/// Extract /24 (IPv4) or /48 (IPv6) prefix as a u64 key.
fn prefix_key(ip: &IpAddr) -> u64 {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            // /24 = first 3 octets
            ((octets[0] as u64) << 16) | ((octets[1] as u64) << 8) | (octets[2] as u64)
        }
        IpAddr::V6(v6) => {
            let octets = v6.octets();
            // /48 = first 6 octets (48 bits fits in u64 with room to spare)
            // Set bit 63 to distinguish from IPv4 keys
            (1u64 << 63)
                | ((octets[0] as u64) << 40)
                | ((octets[1] as u64) << 32)
                | ((octets[2] as u64) << 24)
                | ((octets[3] as u64) << 16)
                | ((octets[4] as u64) << 8)
                | (octets[5] as u64)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn test_config(rps: u32, window: u64, slip: u32) -> RrlConfig {
        RrlConfig {
            enabled: true,
            responses_per_second: rps,
            window_secs: window,
            slip_rate: slip,
        }
    }

    /// The DoD for `security-rrl-cli-and-prefix-scope`: one device must
    /// not be able to exhaust another device's response budget.
    ///
    /// Reproduces the measured incident — a burst from the dev box
    /// (192.0.2.14) throttled a Philips Hue bridge (192.0.2.243) sharing
    /// 192.0.2.0/24. The control arm runs the identical burst with
    /// `per_client = false` and asserts the victim IS throttled, so a pass
    /// cannot come from the budget simply being generous.
    #[test]
    fn a_noisy_device_cannot_exhaust_its_neighbours_budget() {
        let noisy = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 14));
        let victim = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 243));

        let cfg = RrlConfig {
            enabled: true,
            responses_per_second: 5,
            window_secs: 15,
            slip_rate: 2,
        };

        // Per-client keying: burn the noisy device's whole budget.
        let rrl = Rrl::new(&cfg);
        for _ in 0..500 {
            rrl.check(&noisy, true);
        }
        assert_eq!(
            rrl.check(&victim, true),
            RrlAction::Allow,
            "the Hue bridge must still be answered after its neighbour flooded"
        );

        // Control arm: same burst, prefix keying — the victim shares the
        // /24 budget and MUST be throttled. If this ever returns Allow the
        // test above proves nothing.
        let shared = Rrl::new(&cfg);
        for _ in 0..500 {
            shared.check(&noisy, false);
        }
        assert_ne!(
            shared.check(&victim, false),
            RrlAction::Allow,
            "control arm: under /24 keying the neighbour is collateral damage"
        );
    }

    /// Prefix and per-client keys share one map, so a collision would let
    /// one client spend another's budget. Bit 63 = IPv6, bit 62 = per-client.
    #[test]
    fn client_and_prefix_key_spaces_never_collide() {
        let v4 = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 14));
        let v6: IpAddr = "2001:db8::1".parse().unwrap();

        let keys = [
            prefix_key(&v4),
            client_key(&v4),
            prefix_key(&v6),
            client_key(&v6),
        ];
        for (i, a) in keys.iter().enumerate() {
            for (j, b) in keys.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b, "key spaces overlap at {i}/{j}");
                }
            }
        }

        // Per-client keying must separate addresses that prefix keying
        // deliberately merges — the whole point of the mode.
        let neighbour = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 243));
        assert_eq!(prefix_key(&v4), prefix_key(&neighbour));
        assert_ne!(client_key(&v4), client_key(&neighbour));
    }

    #[test]
    fn prefix_key_groups_same_slash24() {
        let ip1 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let ip2 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 254));
        assert_eq!(prefix_key(&ip1), prefix_key(&ip2));
    }

    #[test]
    fn prefix_key_separates_different_slash24() {
        let ip1 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let ip2 = IpAddr::V4(Ipv4Addr::new(192, 168, 2, 1));
        assert_ne!(prefix_key(&ip1), prefix_key(&ip2));
    }

    #[test]
    fn prefix_key_ipv6_groups_slash48() {
        let ip1 = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0xabcd, 0x1, 0, 0, 0, 1));
        let ip2 = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0xabcd, 0x2, 0, 0, 0, 1));
        assert_eq!(prefix_key(&ip1), prefix_key(&ip2));
    }

    #[test]
    fn prefix_key_ipv4_ipv6_distinct() {
        let v4 = IpAddr::V4(Ipv4Addr::new(0, 0, 0, 1));
        let v6 = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1));
        assert_ne!(prefix_key(&v4), prefix_key(&v6));
    }

    /// settings-12 (rev-2606): a window of exactly 2^32 used to truncate to
    /// 0 via `as u32`, zeroing max_count — every response throttled, RRL
    /// effectively inverted. The saturating conversion must keep the budget
    /// huge instead.
    #[test]
    fn oversized_window_saturates_instead_of_throttling_all() {
        let rrl = Rrl::new(&test_config(10, (u32::MAX as u64) + 16, 0));
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(
            rrl.check(&ip, false),
            RrlAction::Allow,
            "first response must not be throttled under a saturated window"
        );
    }

    /// settings-12 (rev-2606): window_secs = 0 reset the counter on every
    /// probe and zeroed max_count (throttle-all). The constructor floor
    /// keeps a validator-bypassing zero from disabling RRL.
    #[test]
    fn zero_window_floored_at_construction() {
        let rrl = Rrl::new(&test_config(10, 0, 0));
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(
            rrl.check(&ip, false),
            RrlAction::Allow,
            "zero window must floor to 1s, not throttle everything"
        );
    }

    #[test]
    fn allows_under_threshold() {
        let rrl = Rrl::new(&test_config(10, 1, 0));
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

        for _ in 0..10 {
            assert_eq!(rrl.check(&ip, false), RrlAction::Allow);
        }
    }

    #[test]
    fn drops_over_threshold_slip_zero() {
        let rrl = Rrl::new(&test_config(5, 1, 0)); // 5 per window, no slip
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

        for _ in 0..5 {
            assert_eq!(rrl.check(&ip, false), RrlAction::Allow);
        }
        assert_eq!(rrl.check(&ip, false), RrlAction::Drop);
    }

    #[test]
    fn slips_over_threshold_slip_one() {
        let rrl = Rrl::new(&test_config(5, 1, 1)); // always slip
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

        for _ in 0..5 {
            assert_eq!(rrl.check(&ip, false), RrlAction::Allow);
        }
        assert_eq!(rrl.check(&ip, false), RrlAction::Slip);
    }

    #[test]
    fn slip_rate_two_alternates() {
        let rrl = Rrl::new(&test_config(1, 1, 2)); // 50% slip
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

        // First response allowed
        assert_eq!(rrl.check(&ip, false), RrlAction::Allow);

        // Over threshold: alternate slip/drop
        let a1 = rrl.check(&ip, false);
        let a2 = rrl.check(&ip, false);
        assert!(
            (a1 == RrlAction::Slip && a2 == RrlAction::Drop)
                || (a1 == RrlAction::Drop && a2 == RrlAction::Slip)
        );
    }

    /// rrl-02 (rev-2606) regression: slip selection is per-prefix. With
    /// the old single global counter, two concurrently-throttled prefixes
    /// shared one alternation — one victim /24 could draw consecutive
    /// Drops while the other absorbed the Slips. Per-prefix state makes
    /// the cadence deterministic: with slip_rate = 2 every prefix's FIRST
    /// throttled response is a Slip (its own counter starts at 0), then
    /// alternates, regardless of what other prefixes are doing.
    #[test]
    fn slip_selection_is_per_prefix_deterministic() {
        let rrl = Rrl::new(&test_config(1, 1, 2));
        let ip_a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let ip_b = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1));

        // Burn each prefix's 1-response budget.
        assert_eq!(rrl.check(&ip_a, false), RrlAction::Allow);
        assert_eq!(rrl.check(&ip_b, false), RrlAction::Allow);

        // First throttled response per prefix: both must Slip — under the
        // global counter, B's first throttle would have been a Drop
        // (global n=1 after A consumed n=0).
        assert_eq!(
            rrl.check(&ip_a, false),
            RrlAction::Slip,
            "prefix A first throttle"
        );
        assert_eq!(
            rrl.check(&ip_b, false),
            RrlAction::Slip,
            "prefix B first throttle"
        );

        // And each alternates independently afterwards.
        assert_eq!(rrl.check(&ip_a, false), RrlAction::Drop, "prefix A second");
        assert_eq!(rrl.check(&ip_b, false), RrlAction::Drop, "prefix B second");
        assert_eq!(rrl.check(&ip_a, false), RrlAction::Slip, "prefix A third");
        assert_eq!(rrl.check(&ip_b, false), RrlAction::Slip, "prefix B third");
    }

    /// rrl-01 (rev-2606) regression: the DEFAULT config must absorb a busy
    /// home LAN. RRL keys by /24 and a home LAN is exactly one /24, so the
    /// budget is shared by every device — pre-fix it was 5 resp/s × 15 s
    /// = 75 per window, which two browsing sessions exceeded (50 % TC-slip +
    /// 50 % silent drop on the overflow). With the raised default, 16
    /// devices × 50 responses inside one window (800 total — well above a
    /// realistic LAN peak) must all be allowed.
    #[test]
    fn default_config_absorbs_home_lan_burst() {
        let rrl = Rrl::new(&RrlConfig::default());

        for device in 0..16u8 {
            let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, device + 1));
            for n in 0..50 {
                assert_eq!(
                    rrl.check(&ip, false),
                    RrlAction::Allow,
                    "device {device} response {n} throttled under default config"
                );
            }
        }
    }

    #[test]
    fn same_slash24_share_counter() {
        let rrl = Rrl::new(&test_config(3, 1, 0));
        let ip1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let ip2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 200));

        // Both in same /24 — share the 3-response budget
        assert_eq!(rrl.check(&ip1, false), RrlAction::Allow);
        assert_eq!(rrl.check(&ip2, false), RrlAction::Allow);
        assert_eq!(rrl.check(&ip1, false), RrlAction::Allow);
        assert_eq!(rrl.check(&ip2, false), RrlAction::Drop);
    }

    #[test]
    fn different_slash24_independent() {
        let rrl = Rrl::new(&test_config(2, 1, 0));
        let ip1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let ip2 = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1));

        assert_eq!(rrl.check(&ip1, false), RrlAction::Allow);
        assert_eq!(rrl.check(&ip1, false), RrlAction::Allow);
        assert_eq!(rrl.check(&ip1, false), RrlAction::Drop);

        // Different /24 — fresh budget
        assert_eq!(rrl.check(&ip2, false), RrlAction::Allow);
        assert_eq!(rrl.check(&ip2, false), RrlAction::Allow);
    }

    /// `warden security set rrl.*` must apply without a daemon restart,
    /// and the swap must not hand every destination prefix a fresh
    /// counter on each config edit.
    ///
    /// Swaps `slip_rate` only — `responses_per_second`/`window_secs`
    /// stay fixed, so a verdict change below can only come from the NEW
    /// slip_rate being read, not from a widened budget. If the swap had
    /// instead rebuilt `prefixes` (zeroing the counter), the prefix
    /// would read as freshly under budget and this would observe
    /// `Allow`, not `Slip`.
    #[test]
    fn set_params_applies_without_restart_and_preserves_prefix_state() {
        let rrl = Rrl::new(&test_config(5, 1, 0)); // max_count = 5, always Drop over budget
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

        for _ in 0..5 {
            assert_eq!(rrl.check(&ip, false), RrlAction::Allow);
        }
        assert_eq!(
            rrl.check(&ip, false),
            RrlAction::Drop,
            "budget must be exhausted before the swap"
        );
        let entries_before = rrl.entry_count();

        let mut updated = test_config(5, 1, 0);
        updated.slip_rate = 1; // always Slip once over budget
        rrl.set_params(&updated);

        assert_eq!(
            rrl.entry_count(),
            entries_before,
            "a params swap must not drop tracked prefixes"
        );
        assert_eq!(
            rrl.check(&ip, false),
            RrlAction::Slip,
            "the new slip_rate must be live immediately, and the prefix must \
             still be over budget — a reset would have reported Allow instead"
        );
    }

    #[test]
    fn concurrent_first_responses_capped_at_max_count() {
        // L-11 (rev-2026-05-rrl-tunneling-toctou) regression pin: two or
        // more concurrent first responses to the same fresh /24 previously
        // each passed the `get(...) = None` check and each inserted a
        // fresh PrefixState — the last writer won, but the per-prefix
        // counter restarted from 1 instead of climbing, leaking the
        // budget by `concurrency` on every fresh prefix an attacker
        // chose. The fix replaces get-then-insert with
        // `BoundedMap::entry_or_insert_with`, atomic at the shard level.
        // Pin: with `max_count = 2` and 8 threads racing on the same
        // fresh /24, exactly 2 Allows surface (the other 6 see Drop).
        // Mirrors L-1's `concurrent_first_queries_share_one_burst_budget`
        // in `rate_limiter.rs`.
        use std::sync::{Arc, Barrier};
        use std::thread;

        // rps=1, window_secs=2 → max_count = 2.
        let rrl = Arc::new(Rrl::new(&test_config(1, 2, 0)));
        let ip = IpAddr::V4(Ipv4Addr::new(10, 9, 9, 9));
        let threads = 8usize;
        let barrier = Arc::new(Barrier::new(threads));

        let handles: Vec<_> = (0..threads)
            .map(|_| {
                let rrl = Arc::clone(&rrl);
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    rrl.check(&ip, false)
                })
            })
            .collect();

        let allowed = handles
            .into_iter()
            .map(|h| h.join().unwrap())
            .filter(|action| *action == RrlAction::Allow)
            .count();

        assert_eq!(
            allowed, 2,
            "TOCTOU regression: exactly max_count=2 concurrent responses should be allowed, got {allowed}"
        );
        assert_eq!(rrl.entry_count(), 1);
    }
}
