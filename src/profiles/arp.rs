//! ARP table reader — maps IP addresses to MAC addresses via /proc/net/arp.
//!
//! Used during profile map building to resolve MAC-identified clients
//! to their current IP, handling DHCP reassignment transparently.

use std::collections::HashMap;
use std::net::IpAddr;

use compact_str::CompactString;

/// Path to the Linux ARP table.
const ARP_PATH: &str = "/proc/net/arp";

/// Read the system ARP table and return an IP → MAC mapping.
///
/// MAC addresses are normalized to uppercase (the resolver compares them
/// against upper-cased `mac_pin` / `mac_aliases`). Keyed by IP
/// because `/proc/net/arp` has one row per IP, so an IP key is lossless —
/// a MAC-keyed map silently drops all-but-one IP for a MAC that
/// holds several (DHCP-renew overlap, IP alias, dual-NIC bridge), and
/// `HashMap` iteration makes *which* row survives nondeterministic per
/// refresh. Returns an empty map on read failure
/// (non-Linux, permission denied, etc.) — the caller falls back to
/// configured IPs.
pub fn read_arp_by_ip() -> HashMap<IpAddr, CompactString> {
    read_arp_from(ARP_PATH)
}

/// Testable inner function that reads from an arbitrary path.
fn read_arp_from(path: &str) -> HashMap<IpAddr, CompactString> {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            // Surfaced at warn because an unreadable /proc/net/arp
            // silently empties the MAC snapshot — the TUI then shows
            // `(no arp)` on every unmapped row and the operator has
            // no obvious hint that systemd sandboxing (ProcSubset=pid,
            // missing procfs, etc.) is the cause. Loud once per poll
            // is noisy but diagnostic; if this ever spams production
            // logs the right fix is migrating to netlink, not silencing.
            tracing::warn!(
                target: "audit",
                path,
                error = %e,
                "arp table read failed — IP→MAC snapshot will be empty"
            );
            return HashMap::new();
        }
    };
    parse_arp_table(&content)
}

/// Parse /proc/net/arp content into an IP → MAC map.
///
/// Format:
/// ```text
/// IP address       HW type     Flags       HW address            Mask     Device
/// 192.168.1.42     0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0
/// ```
///
/// Flags 0x2 means the entry is complete (resolved). We skip incomplete
/// entries (0x0). Keyed by IP (unique per row) so every resolved entry
/// survives — see [`read_arp_by_ip`] for why MAC-keying is lossy.
fn parse_arp_table(content: &str) -> HashMap<IpAddr, CompactString> {
    let mut map = HashMap::new();
    for line in content.lines().skip(1) {
        // skip header
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 4 {
            continue;
        }
        let ip_str = fields[0];
        let flags = fields[2];
        let mac = fields[3];

        // Skip incomplete entries (flags != 0x2)
        if flags != "0x2" {
            continue;
        }
        // Skip placeholder MACs
        if mac == "00:00:00:00:00:00" {
            continue;
        }

        if let Ok(ip) = ip_str.parse::<IpAddr>() {
            map.insert(ip, CompactString::new(mac.to_ascii_uppercase()));
        }
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_ARP: &str = "\
IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:01     *        eth0
192.168.1.42     0x1         0x2         aa:bb:cc:dd:ee:02     *        eth0
192.168.1.50     0x1         0x2         aa:bb:cc:dd:ee:03     *        eth0
10.0.0.1         0x1         0x0         00:00:00:00:00:00     *        eth0
";

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn parse_valid_entries() {
        let map = parse_arp_table(SAMPLE_ARP);
        assert_eq!(map.len(), 3);
        assert_eq!(map[&ip("192.168.1.42")], "AA:BB:CC:DD:EE:02");
    }

    #[test]
    fn skip_incomplete_entries() {
        let map = parse_arp_table(SAMPLE_ARP);
        // 10.0.0.1 has flags 0x0 (incomplete) → skipped
        assert!(!map.contains_key(&ip("10.0.0.1")));
    }

    #[test]
    fn mac_uppercase_normalized() {
        let map = parse_arp_table(SAMPLE_ARP);
        // Input has lowercase MACs; stored values are uppercase.
        assert!(map.values().any(|m| m == "AA:BB:CC:DD:EE:01"));
        assert!(!map.values().any(|m| m == "aa:bb:cc:dd:ee:01"));
    }

    #[test]
    fn empty_table() {
        let content =
            "IP address       HW type     Flags       HW address            Mask     Device\n";
        let map = parse_arp_table(content);
        assert!(map.is_empty());
    }

    #[test]
    fn malformed_lines_skipped() {
        let content = "\
IP address       HW type     Flags       HW address            Mask     Device
short line
192.168.1.42     0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0
";
        let map = parse_arp_table(content);
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn multi_ip_per_mac_all_preserved() {
        // One MAC holding two complete IPv4 rows (DHCP-renew overlap /
        // IP alias / dual-NIC bridge). A MAC-keyed map would keep only
        // the last-iterated row, nondeterministically. The IP-keyed map
        // keeps BOTH, each pointing at the shared MAC, so neither IP
        // loses its snapshot entry.
        let content = "\
IP address       HW type     Flags       HW address            Mask     Device
192.168.1.10     0x1         0x2         aa:bb:cc:dd:ee:99     *        eth0
192.168.1.11     0x1         0x2         aa:bb:cc:dd:ee:99     *        eth0
";
        let map = parse_arp_table(content);
        assert_eq!(map.len(), 2, "both IP rows for the shared MAC survive");
        assert_eq!(map[&ip("192.168.1.10")], "AA:BB:CC:DD:EE:99");
        assert_eq!(map[&ip("192.168.1.11")], "AA:BB:CC:DD:EE:99");
    }

    #[test]
    fn read_nonexistent_returns_empty() {
        let map = read_arp_from("/tmp/nonexistent-arp-file-test");
        assert!(map.is_empty());
    }
}
