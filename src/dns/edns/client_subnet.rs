//! EDNS Client Subnet (RFC 7871) wrapper around `hickory_proto::rr::rdata::opt::ClientSubnet`.
//!
//! Provides a thin internal API that:
//!   * validates `source_prefix` against the address family at construction time
//!     (hickory only fails at encode-time on out-of-range prefixes);
//!   * masks address bits beyond `source_prefix` to zero before passing to hickory,
//!     satisfying RFC 7871 §6 ("padding with 0 bits to pad to the end of the last
//!     octet needed") which hickory does not enforce on its own;
//!   * forces `scope_prefix = 0` on query-side construction (RFC 7871 §6: scope is
//!     populated by the upstream resolver in responses, never by stub/recursive on
//!     the way out);
//!   * exposes an `anonymous` constructor that emits the zero-information form
//!     (`source_prefix = 0`, address all-zero), per RFC 7871 §7.1.2 privacy
//!     recommendation when the operator wants ECS infrastructure to be present
//!     on the wire without leaking client geolocation.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use hickory_proto::rr::rdata::opt::ClientSubnet;

/// Errors that prevent constructing a valid `EdnsClientSubnet`.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum EcsError {
    /// `source_prefix` exceeds the maximum allowed for the address family.
    #[error("source_prefix {prefix} out of range for {family:?} (max {max})")]
    PrefixOutOfRange {
        family: AddressFamily,
        prefix: u8,
        max: u8,
    },
}

/// IANA address family registry values used by the ECS option `FAMILY` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressFamily {
    /// IPv4 — IANA family code `1`.
    V4,
    /// IPv6 — IANA family code `2`.
    V6,
}

impl AddressFamily {
    /// Returns the maximum `source_prefix` value allowed for this family.
    pub fn max_prefix(self) -> u8 {
        match self {
            Self::V4 => 32,
            Self::V6 => 128,
        }
    }

    fn unspecified_addr(self) -> IpAddr {
        match self {
            Self::V4 => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            Self::V6 => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        }
    }
}

impl From<&IpAddr> for AddressFamily {
    fn from(addr: &IpAddr) -> Self {
        match addr {
            IpAddr::V4(_) => Self::V4,
            IpAddr::V6(_) => Self::V6,
        }
    }
}

/// Wrapper around hickory's [`ClientSubnet`] that enforces RFC 7871 invariants
/// at construction time (prefix range + zero-bit address padding) and pins the
/// query-side `scope_prefix` to `0`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EdnsClientSubnet(ClientSubnet);

impl EdnsClientSubnet {
    /// Construct an ECS option from an arbitrary client address truncated to
    /// `source_prefix` bits. The `scope_prefix` field is set to `0` (RFC 7871
    /// §6: query-side senders never populate scope).
    ///
    /// Returns [`EcsError::PrefixOutOfRange`] if `source_prefix` exceeds the
    /// family-specific maximum (32 for IPv4, 128 for IPv6).
    pub fn new(address: IpAddr, source_prefix: u8) -> Result<Self, EcsError> {
        let family = AddressFamily::from(&address);
        let max = family.max_prefix();
        if source_prefix > max {
            return Err(EcsError::PrefixOutOfRange {
                family,
                prefix: source_prefix,
                max,
            });
        }
        let masked = mask_address(address, source_prefix);
        Ok(Self(ClientSubnet::new(masked, source_prefix, 0)))
    }

    /// Construct the privacy-preserving zero-information form of ECS:
    /// `source_prefix = 0`, address all-zero. RFC 7871 §7.1.2 mandates that
    /// recursive resolvers receiving this form MUST NOT add client address
    /// information to their queries.
    pub fn anonymous(family: AddressFamily) -> Self {
        Self(ClientSubnet::new(family.unspecified_addr(), 0, 0))
    }

    /// Returns the inferred address family of the underlying address.
    pub fn family(&self) -> AddressFamily {
        AddressFamily::from(&self.0.addr())
    }

    /// Returns the source prefix length.
    pub fn source_prefix(&self) -> u8 {
        self.0.source_prefix()
    }

    /// Returns the masked address.
    pub fn address(&self) -> IpAddr {
        self.0.addr()
    }

    /// Consumes the wrapper and returns the underlying hickory `ClientSubnet`
    /// suitable for installation into an EDNS OPT record via
    /// `EdnsOption::Subnet(_)`.
    pub fn into_proto(self) -> ClientSubnet {
        self.0
    }

    /// Projects to a [`EcsPrefix`] suitable for cache keying. Returns
    /// `None` for the anonymous form (`source_prefix =
    /// 0`) so anonymous queries share the same cache slot regardless
    /// of client address family — they emit byte-identical wire data,
    /// so they yield byte-identical upstream answers.
    ///
    /// For non-anonymous forms the masked address + prefix together
    /// define the cache-bucket dimension. Two clients on the same
    /// `/24` (`10.10.1.50` and `10.10.1.99` under Coarse mode) collapse
    /// to the same `EcsPrefix` and share the upstream's answer; clients
    /// on different `/24`s get distinct slots so a CDN's
    /// geo-specialised response for `/24=10.10.1` does not poison the
    /// `/24=10.10.2` clients.
    pub fn as_cache_prefix(&self) -> Option<EcsPrefix> {
        if self.source_prefix() == 0 {
            None
        } else {
            Some(EcsPrefix {
                addr: self.address(),
                prefix: self.source_prefix(),
            })
        }
    }
}

/// Cache-key dimension for ECS-routed queries.
///
/// Embedded into [`crate::dns::cache::DnsCache`]'s key tuple as
/// `Option<EcsPrefix>`. `None` marks queries that emit no ECS option
/// (or the anonymous zero-bytes form) — they share the same bucket and
/// the cache stays byte-identical to the baseline when no profile
/// activates ECS. `Some(p)` partitions the cache by `(masked address,
/// prefix length)` so two clients on different `/24`s receive their
/// own CDN-tailored answers.
///
/// **Memory accounting:** `IpAddr` is a 17-byte tagged union
/// (`{v4: [u8; 4]} | {v6: [u8; 16]}` + 1 discriminant) and `u8` adds
/// one more byte → ~24 bytes including padding and the outer `Option`
/// tag. At 100k cache entries this is ~2.4 MB of extra footprint
/// — well within the Pi-Zero-2 budget (the existing cache already
/// dominates this in `Arc<[Record]>` payloads).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct EcsPrefix {
    /// Masked address (RFC 7871 §6 zero-bit-padding already applied by
    /// the wrapper that produced this value).
    pub addr: IpAddr,
    /// Source prefix length (1..=32 for IPv4, 1..=128 for IPv6).
    /// Zero-prefix entries are never stored — they project to `None`
    /// in [`EdnsClientSubnet::as_cache_prefix`].
    pub prefix: u8,
}

/// Zero out the bits of `address` beyond `prefix` (RFC 7871 §6 "padding with
/// 0 bits to pad to the end of the last octet needed").
fn mask_address(address: IpAddr, prefix: u8) -> IpAddr {
    match address {
        IpAddr::V4(v4) => {
            let mut octets = v4.octets();
            mask_octets(&mut octets, prefix);
            IpAddr::V4(Ipv4Addr::from(octets))
        }
        IpAddr::V6(v6) => {
            let mut octets = v6.octets();
            mask_octets(&mut octets, prefix);
            IpAddr::V6(Ipv6Addr::from(octets))
        }
    }
}

fn mask_octets(octets: &mut [u8], prefix: u8) {
    let prefix = prefix as usize;
    let total_bits = octets.len() * 8;
    if prefix >= total_bits {
        return;
    }
    let full_bytes = prefix / 8;
    let leftover_bits = prefix % 8;
    if leftover_bits != 0 {
        let mask = 0xFFu8 << (8 - leftover_bits);
        octets[full_bytes] &= mask;
        for octet in octets.iter_mut().skip(full_bytes + 1) {
            *octet = 0;
        }
    } else {
        for octet in octets.iter_mut().skip(full_bytes) {
            *octet = 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::rr::rdata::opt::{EdnsCode, EdnsOption};
    use hickory_proto::serialize::binary::{BinDecodable, BinEncodable, BinEncoder};

    fn encode(opt: &ClientSubnet) -> Vec<u8> {
        let mut buf = Vec::new();
        let mut enc = BinEncoder::new(&mut buf);
        opt.emit(&mut enc).expect("encode");
        buf
    }

    #[test]
    fn roundtrip_v4_24() {
        let ecs = EdnsClientSubnet::new("192.168.1.50".parse().unwrap(), 24).unwrap();
        let bytes = encode(&ecs.clone().into_proto());
        let decoded = ClientSubnet::from_bytes(&bytes).expect("decode");
        assert_eq!(decoded.source_prefix(), 24);
        assert_eq!(decoded.scope_prefix(), 0);
        assert_eq!(decoded.addr(), "192.168.1.0".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn roundtrip_v6_56() {
        let ecs = EdnsClientSubnet::new("2001:db8:abcd:ef01::1".parse().unwrap(), 56).unwrap();
        let bytes = encode(&ecs.clone().into_proto());
        let decoded = ClientSubnet::from_bytes(&bytes).expect("decode");
        assert_eq!(decoded.source_prefix(), 56);
        assert_eq!(decoded.scope_prefix(), 0);
        assert_eq!(
            decoded.addr(),
            "2001:db8:abcd:ef00::".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn anonymous_v4_emits_zero_address_bytes() {
        let ecs = EdnsClientSubnet::anonymous(AddressFamily::V4);
        let bytes = encode(&ecs.into_proto());
        // FAMILY(2) + SOURCE_PREFIX(1) + SCOPE_PREFIX(1) + 0 address bytes = 4
        assert_eq!(bytes, vec![0x00, 0x01, 0x00, 0x00]);
    }

    #[test]
    fn anonymous_v6_emits_zero_address_bytes() {
        let ecs = EdnsClientSubnet::anonymous(AddressFamily::V6);
        let bytes = encode(&ecs.into_proto());
        assert_eq!(bytes, vec![0x00, 0x02, 0x00, 0x00]);
    }

    #[test]
    fn family_invalid_decode_error() {
        // FAMILY=3 (unassigned), SOURCE=0, SCOPE=0 → must fail decode
        let bytes = vec![0x00, 0x03, 0x00, 0x00];
        assert!(ClientSubnet::from_bytes(&bytes).is_err());
    }

    #[test]
    fn payload_truncated_decode_error() {
        // Only FAMILY field, missing SOURCE/SCOPE → must fail decode
        let bytes = vec![0x00, 0x01];
        assert!(ClientSubnet::from_bytes(&bytes).is_err());
    }

    #[test]
    fn scope_prefix_zero_on_query_construction() {
        let ecs = EdnsClientSubnet::new("10.0.0.1".parse().unwrap(), 16).unwrap();
        assert_eq!(ecs.into_proto().scope_prefix(), 0);
    }

    #[test]
    fn address_truncation_non_multiple_of_8() {
        // prefix=20 → 2 full bytes + 4 high bits of 3rd byte; 4th byte zeroed
        let ecs = EdnsClientSubnet::new("192.168.31.250".parse().unwrap(), 20).unwrap();
        let bytes = encode(&ecs.clone().into_proto());
        // FAMILY(1), SRC(20), SCOPE(0), addr_len = 20/8+1 = 3 bytes
        // 192=0xC0, 168=0xA8, 31=0x1F masked to high-4-bits → 0x10
        assert_eq!(bytes, vec![0x00, 0x01, 0x14, 0x00, 0xC0, 0xA8, 0x10]);
        assert_eq!(ecs.address(), "192.168.16.0".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn oversize_prefix_v4_rejected() {
        let err = EdnsClientSubnet::new("192.168.1.1".parse().unwrap(), 33).unwrap_err();
        assert_eq!(
            err,
            EcsError::PrefixOutOfRange {
                family: AddressFamily::V4,
                prefix: 33,
                max: 32,
            }
        );
    }

    #[test]
    fn oversize_prefix_v6_rejected() {
        let err = EdnsClientSubnet::new("2001:db8::1".parse().unwrap(), 129).unwrap_err();
        assert_eq!(
            err,
            EcsError::PrefixOutOfRange {
                family: AddressFamily::V6,
                prefix: 129,
                max: 128,
            }
        );
    }

    #[test]
    fn byte_exact_wire_layout_v4_slash24() {
        // 192.168.1.0/24 → bytes: 00 01 18 00 C0 A8 01
        let ecs = EdnsClientSubnet::new("192.168.1.99".parse().unwrap(), 24).unwrap();
        let bytes = encode(&ecs.into_proto());
        assert_eq!(bytes, vec![0x00, 0x01, 0x18, 0x00, 0xC0, 0xA8, 0x01]);
    }

    #[test]
    fn byte_exact_wire_layout_v6_slash32() {
        // 2001:db8::/32 → FAMILY=2, SRC=32, SCOPE=0, addr_len=4: 00 02 20 00 20 01 0D B8
        let ecs = EdnsClientSubnet::new("2001:db8::1".parse().unwrap(), 32).unwrap();
        let bytes = encode(&ecs.into_proto());
        assert_eq!(bytes, vec![0x00, 0x02, 0x20, 0x00, 0x20, 0x01, 0x0D, 0xB8]);
    }

    #[test]
    fn ecs_option_code_is_8() {
        // Sanity guard for caller code (DoH/DoT/plain) that builds OPT records:
        // EdnsOption::Subnet(...) maps to EdnsCode::Subnet which is wire-encoded as 8.
        let ecs = EdnsClientSubnet::anonymous(AddressFamily::V4);
        let opt = EdnsOption::Subnet(ecs.into_proto());
        let code: EdnsCode = (&opt).into();
        assert_eq!(u16::from(code), 8);
    }

    #[test]
    fn zero_prefix_emits_zero_address_bytes_for_specific_addr() {
        // With prefix=0, even a real client IP must emit zero address bytes
        // (anonymous form, RFC 7871 §7.1.2).
        let ecs = EdnsClientSubnet::new("203.0.113.42".parse().unwrap(), 0).unwrap();
        let bytes = encode(&ecs.into_proto());
        assert_eq!(bytes, vec![0x00, 0x01, 0x00, 0x00]);
    }

    // ── cache-key projection ─────────────────────

    #[test]
    fn as_cache_prefix_zero_prefix_is_none() {
        let anon = EdnsClientSubnet::anonymous(AddressFamily::V4);
        assert!(anon.as_cache_prefix().is_none());
        let anon6 = EdnsClientSubnet::anonymous(AddressFamily::V6);
        assert!(anon6.as_cache_prefix().is_none());
    }

    #[test]
    fn as_cache_prefix_v4_carries_masked_address_and_prefix() {
        let ecs = EdnsClientSubnet::new("10.10.1.50".parse().unwrap(), 24).unwrap();
        let pre = ecs.as_cache_prefix().expect("non-zero prefix → Some");
        assert_eq!(pre.prefix, 24);
        assert_eq!(pre.addr, "10.10.1.0".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn as_cache_prefix_v6_carries_masked_address_and_prefix() {
        let ecs = EdnsClientSubnet::new("2001:db8:abcd:ef01::1".parse().unwrap(), 56).unwrap();
        let pre = ecs.as_cache_prefix().expect("non-zero prefix → Some");
        assert_eq!(pre.prefix, 56);
        assert_eq!(pre.addr, "2001:db8:abcd:ef00::".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn ecs_prefix_two_different_subnets_are_not_equal() {
        let a = EdnsClientSubnet::new("10.10.1.50".parse().unwrap(), 24)
            .unwrap()
            .as_cache_prefix()
            .unwrap();
        let b = EdnsClientSubnet::new("10.10.2.50".parse().unwrap(), 24)
            .unwrap()
            .as_cache_prefix()
            .unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn ecs_prefix_same_subnet_different_clients_collapse_to_equal() {
        // Two clients on the same /24 must project to the same EcsPrefix
        // — they share the same upstream-tailored cache slot.
        let a = EdnsClientSubnet::new("10.10.1.50".parse().unwrap(), 24)
            .unwrap()
            .as_cache_prefix()
            .unwrap();
        let b = EdnsClientSubnet::new("10.10.1.99".parse().unwrap(), 24)
            .unwrap()
            .as_cache_prefix()
            .unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn ecs_prefix_implements_hash_and_eq() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let a = EdnsClientSubnet::new("10.10.1.50".parse().unwrap(), 24)
            .unwrap()
            .as_cache_prefix()
            .unwrap();
        let b = a;
        let mut ha = DefaultHasher::new();
        let mut hb = DefaultHasher::new();
        a.hash(&mut ha);
        b.hash(&mut hb);
        assert_eq!(ha.finish(), hb.finish());
        assert_eq!(a, b);
    }
}
