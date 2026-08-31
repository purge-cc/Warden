//! Response IP blocking — check resolved A/AAAA records against IP blocklists.
//!
//! Catches fast-flux domains that aren't on any domain blocklist but resolve
//! to known-bad IPs. Uses `ArcSwap<HashSet<IpAddr>>` for lock-free hot-path reads.

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;

use ahash::RandomState;
use arc_swap::ArcSwap;
use hickory_proto::rr::{RData, Record, RecordType};

use super::cname::NamePolicy;

/// IP blocklist keyed with `ahash::RandomState` — the hasher the rest of
/// `filter/` uses. The response-IP check runs on the resolution hot path, so
/// the std SipHash the default `HashSet` uses was a needless per-record cost.
type IpSet = HashSet<IpAddr, RandomState>;

/// Lock-free IP blocklist for response IP blocking.
pub struct IpFilter {
    blocklist: ArcSwap<IpSet>,
}

impl Default for IpFilter {
    fn default() -> Self {
        Self::new()
    }
}

impl IpFilter {
    pub fn new() -> Self {
        Self {
            blocklist: ArcSwap::from_pointee(IpSet::default()),
        }
    }

    /// Create with an initial set of blocked IPs.
    pub fn with_ips(ips: IpSet) -> Self {
        Self {
            blocklist: ArcSwap::from_pointee(ips),
        }
    }

    /// Atomically replace the entire blocklist.
    pub fn swap(&self, ips: IpSet) {
        self.blocklist.store(Arc::new(ips));
    }

    /// Check if any A/AAAA record in the response resolves to a blocked IP.
    /// Returns `Some(ip)` for the first match, `None` if all clean.
    ///
    /// # `policy`
    ///
    /// F4 / F5 (incident 2026-07-27): this was the last decision point on
    /// the query path with **no** access to the operator's policy — not a
    /// missing comparison but a missing parameter, so a name the operator
    /// had explicitly allowed was still blocked when its answer landed in
    /// a blocked IP range. The verdict now arrives pre-resolved from
    /// [`NamePolicy::resolve`], and any explicit allow on the queried name
    /// suppresses the check ([`NamePolicy::outranks_external`] — the
    /// blocklist is a flat `HashSet<IpAddr>` with no per-entry
    /// attribution, so it ranks with an external domain list).
    ///
    /// It is a required positional argument rather than a policy-aware
    /// second method so a new call site cannot silently inherit the old
    /// blind behaviour; callers with no client context (the prefetch
    /// paths, which populate the *shared* cache slot) pass
    /// [`NamePolicy::Neutral`] and stay fail-closed.
    pub fn check_response(&self, records: &[Record], policy: NamePolicy) -> Option<IpAddr> {
        if policy.outranks_external() {
            return None;
        }
        let set = self.blocklist.load();
        if set.is_empty() {
            return None;
        }
        for record in records {
            match (record.record_type(), &record.data) {
                (RecordType::A, RData::A(a)) => {
                    let ip = IpAddr::V4(a.0);
                    if set.contains(&ip) {
                        return Some(ip);
                    }
                }
                (RecordType::AAAA, RData::AAAA(aaaa)) => {
                    let ip = IpAddr::V6(aaaa.0);
                    if set.contains(&ip) {
                        return Some(ip);
                    }
                }
                _ => {}
            }
        }
        None
    }

    /// Number of IPs in the blocklist.
    pub fn len(&self) -> usize {
        self.blocklist.load().len()
    }

    pub fn is_empty(&self) -> bool {
        self.blocklist.load().is_empty()
    }
}

/// Parse an IP blocklist (one IP per line, # comments, blank lines skipped).
pub fn parse_ip_blocklist(content: &str) -> IpSet {
    let mut set = IpSet::default();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // Strip inline comments
        let ip_str = match line.find('#') {
            Some(pos) => line[..pos].trim(),
            None => line,
        };
        if let Ok(ip) = ip_str.parse::<IpAddr>() {
            set.insert(ip);
        }
    }
    set
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::rr::rdata::{A, AAAA};
    use hickory_proto::rr::{Name, RData, Record};
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::str::FromStr;

    fn a_record(ip: &str) -> Record {
        let addr: Ipv4Addr = ip.parse().unwrap();
        Record::from_rdata(
            Name::from_str("example.com.").unwrap(),
            300,
            RData::A(A(addr)),
        )
    }

    fn aaaa_record(ip: &str) -> Record {
        let addr: Ipv6Addr = ip.parse().unwrap();
        Record::from_rdata(
            Name::from_str("example.com.").unwrap(),
            300,
            RData::AAAA(AAAA(addr)),
        )
    }

    /// Build an `IpSet` (ahash-keyed) from IP literals — the plain
    /// `HashSet::from([..])` used before forces std SipHash and no longer
    /// coerces to the filter's `HashSet<IpAddr, ahash::RandomState>`.
    fn ipset<const N: usize>(ips: [&str; N]) -> IpSet {
        ips.iter().map(|s| s.parse().unwrap()).collect()
    }

    #[test]
    fn check_blocked_ipv4() {
        let filter = IpFilter::with_ips(ipset(["1.2.3.4"]));
        let records = vec![a_record("1.2.3.4")];
        let result = filter.check_response(&records, NamePolicy::Neutral);
        assert_eq!(result, Some("1.2.3.4".parse().unwrap()));
    }

    #[test]
    fn check_allowed_ipv4() {
        let filter = IpFilter::with_ips(ipset(["1.2.3.4"]));
        let records = vec![a_record("5.6.7.8")];
        assert!(filter
            .check_response(&records, NamePolicy::Neutral)
            .is_none());
    }

    #[test]
    fn check_blocked_ipv6() {
        let filter = IpFilter::with_ips(ipset(["fd00::bad"]));
        let records = vec![aaaa_record("fd00::bad")];
        assert!(filter
            .check_response(&records, NamePolicy::Neutral)
            .is_some());
    }

    #[test]
    fn check_allowed_ipv6() {
        let filter = IpFilter::with_ips(ipset(["fd00::bad"]));
        let records = vec![aaaa_record("fd00::1")];
        assert!(filter
            .check_response(&records, NamePolicy::Neutral)
            .is_none());
    }

    #[test]
    fn empty_blocklist_allows_all() {
        let filter = IpFilter::new();
        let records = vec![a_record("1.2.3.4")];
        assert!(filter
            .check_response(&records, NamePolicy::Neutral)
            .is_none());
    }

    #[test]
    fn mixed_records_finds_blocked() {
        let filter = IpFilter::with_ips(ipset(["10.0.0.1"]));
        let records = vec![a_record("8.8.8.8"), a_record("10.0.0.1")];
        assert_eq!(
            filter.check_response(&records, NamePolicy::Neutral),
            Some("10.0.0.1".parse().unwrap())
        );
    }

    #[test]
    fn swap_updates_blocklist() {
        let filter = IpFilter::new();
        assert_eq!(filter.len(), 0);
        filter.swap(ipset(["1.2.3.4"]));
        assert_eq!(filter.len(), 1);
        assert!(filter
            .check_response(&[a_record("1.2.3.4")], NamePolicy::Neutral)
            .is_some());
    }

    // ── F4 / F5 (incident 2026-07-27): the policy parameter ─────────────

    /// The discriminator for the two allow tests below: identical filter,
    /// identical records, `Neutral` policy → still blocked. Without it
    /// they would pass against a `check_response` that returns `None`
    /// unconditionally.
    #[test]
    fn neutral_policy_leaves_the_ip_blocklist_in_force() {
        let filter = IpFilter::with_ips(ipset(["198.51.100.66"]));
        let records = vec![a_record("198.51.100.66")];
        assert_eq!(
            filter.check_response(&records, NamePolicy::Neutral),
            Some("198.51.100.66".parse().unwrap())
        );
    }

    /// F4: a name the operator allowed at *profile* level must not be
    /// blocked because its answer landed in a blocked IP range.
    #[test]
    fn profile_allow_suppresses_the_ip_blocklist() {
        let filter = IpFilter::with_ips(ipset(["198.51.100.66"]));
        let records = vec![a_record("198.51.100.66")];
        assert!(filter
            .check_response(&records, NamePolicy::ProfileAllow)
            .is_none());
    }

    /// F4, device arm — the incident's own scope. The IP blocklist has no
    /// per-entry attribution, so `override_profile_deny` does not gate it:
    /// there is no profile deny in play for that flag to guard.
    #[test]
    fn device_allow_suppresses_the_ip_blocklist_regardless_of_override() {
        let filter = IpFilter::with_ips(ipset(["198.51.100.66"]));
        let records = vec![a_record("198.51.100.66")];
        for flag in [false, true] {
            assert!(
                filter
                    .check_response(
                        &records,
                        NamePolicy::DeviceAllow {
                            override_profile_deny: flag
                        }
                    )
                    .is_none(),
                "device allow (override_profile_deny={flag}) must beat the IP blocklist"
            );
        }
    }

    #[test]
    fn parse_ip_blocklist_basic() {
        let content = "# Bad IPs\n1.2.3.4\n5.6.7.8\n\n# more\nfd00::bad\n";
        let set = parse_ip_blocklist(content);
        assert_eq!(set.len(), 3);
        assert!(set.contains(&"1.2.3.4".parse().unwrap()));
        assert!(set.contains(&"5.6.7.8".parse().unwrap()));
        assert!(set.contains(&"fd00::bad".parse().unwrap()));
    }

    #[test]
    fn parse_ip_blocklist_inline_comments() {
        let content = "1.2.3.4 # malware C2\n5.6.7.8  # spam\n";
        let set = parse_ip_blocklist(content);
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn parse_ip_blocklist_skips_invalid() {
        let content = "1.2.3.4\nnot-an-ip\n5.6.7.8\n";
        let set = parse_ip_blocklist(content);
        assert_eq!(set.len(), 2);
    }
}
