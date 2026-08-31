//! IPv4/IPv6 CIDR block parsing and membership testing (P0-5).
//!
//! Hand-rolled instead of pulling in the `ipnet` or `cidr` crate — scope is
//! narrow (parse a list of CIDRs at startup and test membership on the DNS
//! hot path) and the arithmetic is straightforward. Keeps the dependency
//! footprint small per project convention.
//!
//! Parses standard `addr/prefix` notation:
//!   - `10.0.0.0/8`, `192.168.1.0/24`, `172.16.0.0/12`
//!   - `::1/128`, `fe80::/10`, `2001:db8::/32`
//!   - A bare address (no `/`) is treated as `/32` for IPv4 and `/128` for IPv6.
//!
//! Sprint 50 adds a friendly IPv4 surface, [`Cidr::parse_friendly`], for
//! operators who think in `10.14.0.*` and `10.14.0.0-10.14.0.255` rather
//! than in CIDR arithmetic. Wildcard / range forms reduce to the same
//! [`Cidr`] value the strict parser produces, so storage stays canonical
//! `network/prefix` while the input UI is tolerant.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

/// A CIDR block — either IPv4 or IPv6 — with a prefix length.
///
/// Uses the network address *masked to the prefix* internally so `contains`
/// is a simple bitwise compare. Parsing `192.168.1.100/24` stores
/// `192.168.1.0/24` (the host bits are dropped); callers who need the
/// original can keep the input string separately.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cidr {
    V4 { network: u32, prefix: u8 },
    V6 { network: u128, prefix: u8 },
}

impl Cidr {
    /// Parse a `host[/prefix]` CIDR string. Accepts bare addresses as
    /// `/32` (v4) or `/128` (v6).
    pub fn parse(s: &str) -> Result<Self, String> {
        let (addr_part, prefix_part) = match s.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (s, None),
        };

        let ip: IpAddr = IpAddr::from_str(addr_part.trim())
            .map_err(|_| format!("invalid IP address in CIDR '{s}'"))?;

        match ip {
            IpAddr::V4(v4) => {
                let prefix: u8 = match prefix_part {
                    Some(p) => p
                        .trim()
                        .parse::<u8>()
                        .map_err(|_| format!("invalid prefix in CIDR '{s}'"))?,
                    None => 32,
                };
                if prefix > 32 {
                    return Err(format!("IPv4 prefix {prefix} exceeds 32 in '{s}'"));
                }
                let raw = u32::from(v4);
                let mask = Self::v4_mask(prefix);
                Ok(Cidr::V4 {
                    network: raw & mask,
                    prefix,
                })
            }
            IpAddr::V6(v6) => {
                let prefix: u8 = match prefix_part {
                    Some(p) => p
                        .trim()
                        .parse::<u8>()
                        .map_err(|_| format!("invalid prefix in CIDR '{s}'"))?,
                    None => 128,
                };
                if prefix > 128 {
                    return Err(format!("IPv6 prefix {prefix} exceeds 128 in '{s}'"));
                }
                let raw = u128::from(v6);
                let mask = Self::v6_mask(prefix);
                Ok(Cidr::V6 {
                    network: raw & mask,
                    prefix,
                })
            }
        }
    }

    /// True if `s` carries host bits below its prefix — e.g. `192.0.2.10/8`,
    /// where [`Cidr::parse`] silently masks the `.1.94` host part away.
    /// ACL validation WARNs on this (cidr-02): a `/8` where the operator
    /// meant `/32` widens an allow-list by 24 bits with no diagnostic.
    /// Returns false for a bare address (no `/`), an unparseable string (the
    /// validator reports that separately), or an exactly-aligned network.
    pub(crate) fn input_has_host_bits(s: &str) -> bool {
        let Some((addr, prefix)) = s.split_once('/') else {
            return false;
        };
        let Ok(ip) = IpAddr::from_str(addr.trim()) else {
            return false;
        };
        match ip {
            IpAddr::V4(v4) => match prefix.trim().parse::<u8>() {
                Ok(p) if p <= 32 => {
                    let raw = u32::from(v4);
                    raw & Self::v4_mask(p) != raw
                }
                _ => false,
            },
            IpAddr::V6(v6) => match prefix.trim().parse::<u8>() {
                Ok(p) if p <= 128 => {
                    let raw = u128::from(v6);
                    raw & Self::v6_mask(p) != raw
                }
                _ => false,
            },
        }
    }

    /// Parse a friendly IPv4 spec — wildcards (`10.14.0.*`),
    /// CIDR-aligned ranges (`10.14.0.0-10.14.0.255`), bare addresses,
    /// and plain CIDR — to a canonical [`Cidr`]. IPv6 still requires
    /// plain CIDR (`2001:db8::/32`); the wildcard / range syntax is
    /// IPv4-only because the surface area on v6 (128 bits, hex blocks,
    /// `::` collapse) makes the operator-friendly aliases ambiguous and
    /// the operator audience here always types v6 the standard way.
    ///
    /// Accepted forms:
    /// - **Plain CIDR**: `10.14.0.0/24`, `2001:db8::/32`
    /// - **Bare address**: `10.14.0.5` → `/32`, `::1` → `/128`
    /// - **Wildcard suffix** (IPv4): `10.14.0.*` → `10.14.0.0/24`,
    ///   `10.14.*.*` → `10.14.0.0/16`, `10.*.*.*` → `10.0.0.0/8`
    /// - **CIDR-aligned range** (IPv4): `10.14.0.0-10.14.0.255` →
    ///   `10.14.0.0/24`. Range size must be a power of two AND the
    ///   start address must sit on the boundary of the resulting
    ///   prefix; misaligned ranges (`10.14.0.5-10.14.0.30`) are
    ///   rejected with a friendly error pointing at the boundary
    ///   constraint.
    ///
    /// Rejected:
    /// - Non-contiguous wildcards (`10.*.0.*`) — wildcards must be a
    ///   trailing suffix.
    /// - Wrong octet count (`10.14.0.*.*`).
    /// - All-wildcards (`*.*.*.*`) — would resolve to `0.0.0.0/0`;
    ///   ask the operator to use plain CIDR if match-all is intended.
    /// - Mixed range + wildcard (`10.14.5-10.20.*`).
    /// - IPv6 with wildcards (`2001:db8::*`).
    pub fn parse_friendly(input: &str) -> Result<Self, String> {
        let s = input.trim();
        if s.is_empty() {
            return Err("empty subnet input".to_string());
        }

        // Plain CIDR — already canonical, hand off to the strict parser.
        if s.contains('/') {
            return Self::parse(s);
        }

        // Range form takes precedence over wildcard so a stray '-'
        // inside something like "10.14.5-10.20.*" routes to the
        // range-rejection path (which catches the wildcard inside
        // the halves) rather than the wildcard parser (which would
        // see "10.14.5-10.20.*" as a non-numeric octet).
        if s.contains('-') {
            let (lo, hi) = s
                .split_once('-')
                .expect("contains('-') guarantees split_once succeeds");
            return parse_range_friendly(lo.trim(), hi.trim(), s);
        }

        if s.contains('*') {
            return parse_wildcard_friendly(s);
        }

        // Bare address — IPv4 → /32, IPv6 → /128 via the strict parser.
        Self::parse(s)
    }

    /// True if `ip` falls inside this CIDR block. Mixed-family queries
    /// (asking an IPv4 CIDR about an IPv6 address, or vice versa) return
    /// `false`.
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self, ip) {
            (Cidr::V4 { network, prefix }, IpAddr::V4(v4)) => {
                let raw = u32::from(v4);
                let mask = Self::v4_mask(*prefix);
                raw & mask == *network
            }
            (Cidr::V6 { network, prefix }, IpAddr::V6(v6)) => {
                let raw = u128::from(v6);
                let mask = Self::v6_mask(*prefix);
                raw & mask == *network
            }
            _ => false,
        }
    }

    fn v4_mask(prefix: u8) -> u32 {
        if prefix == 0 {
            0
        } else {
            u32::MAX << (32 - prefix)
        }
    }

    fn v6_mask(prefix: u8) -> u128 {
        if prefix == 0 {
            0
        } else {
            u128::MAX << (128 - prefix)
        }
    }
}

impl std::fmt::Display for Cidr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Cidr::V4 { network, prefix } => {
                let v4 = Ipv4Addr::from(*network);
                write!(f, "{v4}/{prefix}")
            }
            Cidr::V6 { network, prefix } => {
                let v6 = Ipv6Addr::from(*network);
                write!(f, "{v6}/{prefix}")
            }
        }
    }
}

/// Wildcard-suffix IPv4 parser: `A.B.C.*` → `A.B.C.0/24`, etc.
/// The full input string is threaded through for error messages so the
/// operator sees the exact characters they typed.
fn parse_wildcard_friendly(s: &str) -> Result<Cidr, String> {
    if s.contains(':') {
        return Err(format!(
            "wildcard form is IPv4-only; use plain CIDR (e.g. 2001:db8::/32) for IPv6 (got '{s}')"
        ));
    }

    let octets: Vec<&str> = s.split('.').collect();
    if octets.len() != 4 {
        return Err(format!(
            "wildcard form needs exactly 4 octets (e.g. 10.14.0.*); got {} in '{s}'",
            octets.len()
        ));
    }

    // Walk left-to-right; specific octets first, wildcards as a
    // trailing run. Once we see '*', any later non-'*' is a
    // non-contiguous wildcard ('10.*.0.*') and we reject.
    let mut numeric_prefix_count = 0usize;
    let mut seen_wildcard = false;
    for oct in &octets {
        if *oct == "*" {
            seen_wildcard = true;
        } else if seen_wildcard {
            return Err(format!(
                "wildcards must be the trailing octets only (no '10.*.0.*' style); got '{s}'"
            ));
        } else {
            numeric_prefix_count += 1;
        }
    }

    if !seen_wildcard {
        // The dispatcher only routes here when the input contains
        // '*', so this branch is structurally unreachable. Map it to a
        // typed error rather than panicking — defensive belt-and-braces
        // in case a future caller forgets the dispatch invariant.
        return Err(format!("internal: no wildcard found in '{s}'"));
    }
    if numeric_prefix_count == 0 {
        return Err(format!(
            "at least one specific octet is required (use plain CIDR like 0.0.0.0/0 if match-all is intended); got '{s}'"
        ));
    }

    let mut bytes = [0u8; 4];
    for (i, oct) in octets.iter().take(numeric_prefix_count).enumerate() {
        bytes[i] = oct
            .parse::<u8>()
            .map_err(|_| format!("octet '{oct}' is not a valid 0..=255 value in '{s}'"))?;
    }

    let prefix = (numeric_prefix_count * 8) as u8;
    let v4 = Ipv4Addr::from(bytes);
    Cidr::parse(&format!("{v4}/{prefix}"))
}

/// IPv4 range parser: `A-B` collapses to a single CIDR iff
/// `B - A + 1` is a power of two AND `A` sits on the resulting prefix
/// boundary. The combined check rejects both fuzzy operator picks
/// (`10.14.0.5-10.14.0.30`, size 26 — not a power of two) and the
/// subtler "right size, wrong start" case (`10.14.0.5-10.14.0.20`,
/// size 16 but `0x05` is not aligned to a /28 boundary).
fn parse_range_friendly(lo: &str, hi: &str, full: &str) -> Result<Cidr, String> {
    if lo.contains('*') || hi.contains('*') {
        return Err(format!(
            "range '{full}' must not mix wildcards with '-' (use one form or the other)"
        ));
    }
    if lo.contains(':') || hi.contains(':') {
        return Err(format!(
            "range form is IPv4-only; use plain CIDR for IPv6 (got '{full}')"
        ));
    }

    let lo_addr = Ipv4Addr::from_str(lo)
        .map_err(|_| format!("range start '{lo}' is not a valid IPv4 address in '{full}'"))?;
    let hi_addr = Ipv4Addr::from_str(hi)
        .map_err(|_| format!("range end '{hi}' is not a valid IPv4 address in '{full}'"))?;

    let lo_raw = u32::from(lo_addr);
    let hi_raw = u32::from(hi_addr);
    if hi_raw < lo_raw {
        return Err(format!("range '{full}' has end before start"));
    }

    // Use u64 so the full /0 range (size 2^32) computes without
    // overflow at the addition.
    let size = u64::from(hi_raw) - u64::from(lo_raw) + 1;
    if !size.is_power_of_two() {
        return Err(format!(
            "range '{full}' covers {size} addresses, which is not a power of two; \
             pick CIDR-aligned bounds (e.g. 10.14.0.0-10.14.0.255 = /24)"
        ));
    }

    let host_bits = size.trailing_zeros() as u8;
    let prefix = 32u8.checked_sub(host_bits).ok_or_else(|| {
        format!("range '{full}' is larger than the IPv4 space (host_bits={host_bits})")
    })?;

    let mask = if prefix == 0 {
        0u32
    } else {
        u32::MAX << (32 - prefix)
    };
    if lo_raw & mask != lo_raw {
        return Err(format!(
            "range '{full}' is not aligned to a /{prefix} boundary; \
             round the start address down to the boundary or use plain CIDR"
        ));
    }

    Cidr::parse(&format!("{lo_addr}/{prefix}"))
}

/// True if any CIDR in `allow_from` contains `ip`.
///
/// The empty-list case is caller-specific — the handler treats empty as
/// "allow all" (no ACL configured), so this helper requires non-empty.
///
/// An IPv4-mapped IPv6 source (`::ffff:a.b.c.d`) is matched as the IPv4
/// address it carries. A dual-stack listener hands every IPv4 peer that
/// form and [`Cidr::contains`] is family-strict, so without this an
/// `allow_from` of IPv4 CIDRs bars the whole LAN. The step lives here
/// rather than at each call site because an ACL fails CLOSED: the symptom
/// is a silent lockout, not a breach, and every caller having to remember
/// the step is how a caller forgets it.
///
/// [`Cidr::contains`] itself is left family-strict — it is the low-level
/// primitive, and a caller may legitimately want the exact compare.
pub fn any_contains(allow_from: &[Cidr], ip: IpAddr) -> bool {
    let ip = match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        v4 => v4,
    };
    allow_from.iter().any(|c| c.contains(ip))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A dual-stack listener (`listen = "[::]:53"`, the Linux default with
    /// `bindv6only=0`) hands an IPv4 peer as `::ffff:a.b.c.d`. An IPv4
    /// `allow_from` must still admit it, or the ACL locks out the LAN it was
    /// written to admit.
    #[test]
    fn any_contains_matches_an_ipv4_mapped_source() {
        let acl = vec![Cidr::parse("192.0.2.0/24").unwrap()];
        assert!(any_contains(&acl, "::ffff:192.0.2.5".parse().unwrap()));
        assert!(any_contains(&acl, "192.0.2.5".parse().unwrap()));

        // Controls: normalising must widen the ACL to the mapped spelling of
        // the SAME addresses, and to nothing else.
        assert!(
            !any_contains(&acl, "::ffff:10.10.2.5".parse().unwrap()),
            "a mapped address outside the range stays refused"
        );
        assert!(
            !any_contains(&acl, "fd00::1".parse().unwrap()),
            "a genuine IPv6 source is still not matched by an IPv4 CIDR"
        );
    }

    #[test]
    fn input_has_host_bits_detects_unaligned_acl() {
        // cidr-02
        assert!(Cidr::input_has_host_bits("192.0.2.10/8")); // operator meant /32?
        assert!(Cidr::input_has_host_bits("192.168.1.5/24"));
        assert!(Cidr::input_has_host_bits("2001:db8::1/32"));
        assert!(!Cidr::input_has_host_bits("10.0.0.0/8")); // aligned network
        assert!(!Cidr::input_has_host_bits("192.0.2.10")); // bare = /32, no host bits
        assert!(!Cidr::input_has_host_bits("192.0.2.10/32"));
        assert!(!Cidr::input_has_host_bits("2001:db8::/32"));
        assert!(!Cidr::input_has_host_bits("garbage")); // unparseable → false
    }

    // --- parse: IPv4 ---

    #[test]
    fn parses_slash_8() {
        let c = Cidr::parse("10.0.0.0/8").unwrap();
        assert_eq!(
            c,
            Cidr::V4 {
                network: 0x0a000000,
                prefix: 8
            }
        );
    }

    #[test]
    fn parses_slash_24() {
        let c = Cidr::parse("192.168.1.0/24").unwrap();
        assert_eq!(
            c,
            Cidr::V4 {
                network: 0xc0a80100,
                prefix: 24
            }
        );
    }

    #[test]
    fn parses_slash_32_bare_address() {
        let c = Cidr::parse("8.8.8.8").unwrap();
        assert_eq!(c, Cidr::parse("8.8.8.8/32").unwrap());
    }

    #[test]
    fn host_bits_dropped_on_parse() {
        // 10.1.2.3/24 → network is 10.1.2.0/24 (host bits masked off)
        let c = Cidr::parse("10.1.2.3/24").unwrap();
        assert_eq!(
            c,
            Cidr::V4 {
                network: 0x0a010200,
                prefix: 24
            }
        );
    }

    #[test]
    fn parses_slash_0_match_everything_v4() {
        let c = Cidr::parse("0.0.0.0/0").unwrap();
        assert!(c.contains(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))));
        assert!(c.contains(IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255))));
    }

    // --- parse: IPv6 ---

    #[test]
    fn parses_v6_loopback() {
        let c = Cidr::parse("::1/128").unwrap();
        assert!(c.contains(IpAddr::V6(Ipv6Addr::LOCALHOST)));
    }

    #[test]
    fn parses_v6_slash_48() {
        let c = Cidr::parse("2001:db8::/32").unwrap();
        assert!(c.contains(IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1))));
        assert!(!c.contains(IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db9, 0, 0, 0, 0, 0, 1))));
    }

    #[test]
    fn parses_v6_bare_address_as_slash_128() {
        let c = Cidr::parse("::1").unwrap();
        assert_eq!(c, Cidr::parse("::1/128").unwrap());
    }

    #[test]
    fn parses_v6_link_local() {
        let c = Cidr::parse("fe80::/10").unwrap();
        assert!(c.contains(IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1))));
        assert!(c.contains(IpAddr::V6(Ipv6Addr::new(0xfebf, 0, 0, 0, 0, 0, 0, 1))));
        assert!(!c.contains(IpAddr::V6(Ipv6Addr::new(0xfec0, 0, 0, 0, 0, 0, 0, 1))));
    }

    // --- parse: errors ---

    #[test]
    fn rejects_garbage() {
        assert!(Cidr::parse("not a cidr").is_err());
    }

    #[test]
    fn rejects_v4_prefix_over_32() {
        assert!(Cidr::parse("10.0.0.0/33").is_err());
    }

    #[test]
    fn rejects_v6_prefix_over_128() {
        assert!(Cidr::parse("::/129").is_err());
    }

    #[test]
    fn rejects_non_numeric_prefix() {
        assert!(Cidr::parse("10.0.0.0/xx").is_err());
    }

    // --- contains: IPv4 ---

    #[test]
    fn contains_matches_same_subnet() {
        let c = Cidr::parse("192.168.1.0/24").unwrap();
        assert!(c.contains(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        assert!(c.contains(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 254))));
    }

    #[test]
    fn contains_rejects_different_subnet() {
        let c = Cidr::parse("192.168.1.0/24").unwrap();
        assert!(!c.contains(IpAddr::V4(Ipv4Addr::new(192, 168, 2, 1))));
        assert!(!c.contains(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
    }

    #[test]
    fn contains_slash_32_only_matches_exact() {
        let c = Cidr::parse("8.8.8.8/32").unwrap();
        assert!(c.contains(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
        assert!(!c.contains(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 9))));
    }

    #[test]
    fn contains_rfc1918_all_three_blocks() {
        let c10 = Cidr::parse("10.0.0.0/8").unwrap();
        let c172 = Cidr::parse("172.16.0.0/12").unwrap();
        let c192 = Cidr::parse("192.168.0.0/16").unwrap();

        assert!(c10.contains(IpAddr::V4(Ipv4Addr::new(10, 255, 255, 254))));
        assert!(c172.contains(IpAddr::V4(Ipv4Addr::new(172, 31, 255, 254))));
        assert!(!c172.contains(IpAddr::V4(Ipv4Addr::new(172, 32, 0, 1))));
        assert!(c192.contains(IpAddr::V4(Ipv4Addr::new(192, 168, 100, 1))));
    }

    // --- contains: family mismatch ---

    #[test]
    fn v4_cidr_rejects_v6_ip() {
        let c = Cidr::parse("10.0.0.0/8").unwrap();
        assert!(!c.contains(IpAddr::V6(Ipv6Addr::LOCALHOST)));
    }

    #[test]
    fn v6_cidr_rejects_v4_ip() {
        let c = Cidr::parse("::1/128").unwrap();
        assert!(!c.contains(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
    }

    // --- any_contains ---

    #[test]
    fn any_contains_matches_first() {
        let allow = vec![
            Cidr::parse("10.0.0.0/8").unwrap(),
            Cidr::parse("192.168.0.0/16").unwrap(),
        ];
        assert!(any_contains(&allow, IpAddr::V4(Ipv4Addr::new(10, 1, 1, 1))));
    }

    #[test]
    fn any_contains_matches_later() {
        let allow = vec![
            Cidr::parse("10.0.0.0/8").unwrap(),
            Cidr::parse("192.168.0.0/16").unwrap(),
        ];
        assert!(any_contains(
            &allow,
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))
        ));
    }

    #[test]
    fn any_contains_no_match() {
        let allow = vec![Cidr::parse("10.0.0.0/8").unwrap()];
        assert!(!any_contains(&allow, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
    }

    // --- display ---

    #[test]
    fn display_roundtrip_v4() {
        let c = Cidr::parse("192.168.1.0/24").unwrap();
        assert_eq!(c.to_string(), "192.168.1.0/24");
    }

    #[test]
    fn display_roundtrip_v6() {
        let c = Cidr::parse("2001:db8::/32").unwrap();
        // Ipv6Addr uses compressed form; just check the prefix is preserved.
        assert!(c.to_string().ends_with("/32"));
    }

    // ── parse_friendly: accepted forms ─────────────────────────────────

    #[test]
    fn parse_friendly_plain_cidr_passthrough_v4() {
        let got = Cidr::parse_friendly("10.0.0.0/8").unwrap();
        assert_eq!(got, Cidr::parse("10.0.0.0/8").unwrap());
    }

    #[test]
    fn parse_friendly_plain_cidr_passthrough_v6() {
        let got = Cidr::parse_friendly("2001:db8::/32").unwrap();
        assert_eq!(got, Cidr::parse("2001:db8::/32").unwrap());
    }

    #[test]
    fn parse_friendly_bare_address_v4_to_slash_32() {
        let got = Cidr::parse_friendly("10.14.0.5").unwrap();
        assert_eq!(got, Cidr::parse("10.14.0.5/32").unwrap());
    }

    #[test]
    fn parse_friendly_bare_address_v6_to_slash_128() {
        let got = Cidr::parse_friendly("::1").unwrap();
        assert_eq!(got, Cidr::parse("::1/128").unwrap());
    }

    #[test]
    fn parse_friendly_wildcard_one_octet_to_slash_24() {
        let got = Cidr::parse_friendly("10.14.0.*").unwrap();
        assert_eq!(got, Cidr::parse("10.14.0.0/24").unwrap());
    }

    #[test]
    fn parse_friendly_wildcard_two_octets_to_slash_16() {
        let got = Cidr::parse_friendly("10.14.*.*").unwrap();
        assert_eq!(got, Cidr::parse("10.14.0.0/16").unwrap());
    }

    #[test]
    fn parse_friendly_wildcard_three_octets_to_slash_8() {
        let got = Cidr::parse_friendly("10.*.*.*").unwrap();
        assert_eq!(got, Cidr::parse("10.0.0.0/8").unwrap());
    }

    #[test]
    fn parse_friendly_range_aligned_24() {
        let got = Cidr::parse_friendly("10.14.0.0-10.14.0.255").unwrap();
        assert_eq!(got, Cidr::parse("10.14.0.0/24").unwrap());
    }

    #[test]
    fn parse_friendly_range_aligned_27() {
        let got = Cidr::parse_friendly("10.14.0.0-10.14.0.31").unwrap();
        assert_eq!(got, Cidr::parse("10.14.0.0/27").unwrap());
    }

    #[test]
    fn parse_friendly_range_single_address_to_slash_32() {
        let got = Cidr::parse_friendly("10.14.0.5-10.14.0.5").unwrap();
        assert_eq!(got, Cidr::parse("10.14.0.5/32").unwrap());
    }

    #[test]
    fn parse_friendly_range_full_ipv4_space_to_slash_0() {
        let got = Cidr::parse_friendly("0.0.0.0-255.255.255.255").unwrap();
        assert_eq!(got, Cidr::parse("0.0.0.0/0").unwrap());
    }

    #[test]
    fn parse_friendly_trims_surrounding_whitespace() {
        let got = Cidr::parse_friendly("  10.14.0.*  ").unwrap();
        assert_eq!(got, Cidr::parse("10.14.0.0/24").unwrap());
    }

    // ── parse_friendly: rejected forms ─────────────────────────────────

    #[test]
    fn parse_friendly_rejects_noncontiguous_wildcards() {
        let err = Cidr::parse_friendly("10.*.0.*").unwrap_err();
        assert!(
            err.contains("trailing octets") || err.contains("non-contiguous"),
            "expected trailing-only message, got: {err}"
        );
    }

    #[test]
    fn parse_friendly_rejects_too_many_octets() {
        let err = Cidr::parse_friendly("10.14.0.*.*").unwrap_err();
        assert!(err.contains("4 octets"), "got: {err}");
    }

    #[test]
    fn parse_friendly_rejects_mixed_range_and_wildcard() {
        let err = Cidr::parse_friendly("10.14.5-10.20.*").unwrap_err();
        assert!(
            err.contains("mix wildcards") || err.contains("must not"),
            "got: {err}"
        );
    }

    #[test]
    fn parse_friendly_rejects_misaligned_range() {
        let err = Cidr::parse_friendly("10.14.0.5-10.14.0.30").unwrap_err();
        assert!(err.contains("power of two"), "got: {err}");
    }

    #[test]
    fn parse_friendly_rejects_aligned_size_but_unaligned_start() {
        // size = 16 (a power of two → /28) but start 0x05 is not on a
        // /28 boundary; the alignment branch fires.
        let err = Cidr::parse_friendly("10.14.0.5-10.14.0.20").unwrap_err();
        assert!(
            err.contains("aligned"),
            "expected boundary-alignment error, got: {err}"
        );
    }

    #[test]
    fn parse_friendly_rejects_inverted_range() {
        let err = Cidr::parse_friendly("10.14.0.255-10.14.0.0").unwrap_err();
        assert!(err.contains("end before start"), "got: {err}");
    }

    #[test]
    fn parse_friendly_rejects_v6_wildcards() {
        let err = Cidr::parse_friendly("2001:db8::*").unwrap_err();
        assert!(err.contains("IPv4-only"), "got: {err}");
    }

    #[test]
    fn parse_friendly_rejects_all_wildcards_match_all() {
        let err = Cidr::parse_friendly("*.*.*.*").unwrap_err();
        assert!(err.contains("at least one specific octet"), "got: {err}");
    }

    #[test]
    fn parse_friendly_rejects_empty() {
        let err = Cidr::parse_friendly("").unwrap_err();
        assert!(err.contains("empty"), "got: {err}");
    }

    #[test]
    fn parse_friendly_rejects_invalid_octet_in_wildcard() {
        let err = Cidr::parse_friendly("10.300.0.*").unwrap_err();
        assert!(
            err.contains("300"),
            "expected octet to be named, got: {err}"
        );
    }
}
