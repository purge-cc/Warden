//! DNS query name validation.
//!
//! Enforces RFC 1035 limits and project-specific depth constraints.
//! All checks are zero-allocation — lengths are computed from the label
//! iterator, not by converting to a String.

use hickory_proto::rr::LowerName;

use super::error::DnsError;

const MAX_LABEL_LEN: usize = 63;
/// RFC 1035 limit: 253 bytes in presentation format (without trailing dot).
const MAX_NAME_LEN: usize = 253;
/// Project-specific depth limit. 15 real labels (excludes the root label).
pub(crate) const MAX_LABEL_COUNT: usize = 15;
/// Depth limit for names under `.arpa`.
///
/// A full IPv6 reverse name (`ip6.arpa`) is 32 nibble labels + 2 suffix
/// labels = 34 — RFC-mandated shape and the deepest legitimate name family
/// that exists. The general 15-label cap SERVFAILed every IPv6 PTR before
/// security/local-records/upstream ever saw it. Forward names keep the
/// tight cap: nothing legitimate outside `.arpa` approaches 15 labels, and
/// the 253-byte total bound still applies to both.
pub(crate) const MAX_LABEL_COUNT_ARPA: usize = 34;

/// Validate a DNS query name against RFC limits and project constraints.
///
/// Checks: label ≤63 bytes, total ≤253 bytes, non-empty, depth ≤15 labels
/// (≤34 when the final label is `arpa`, the IPv6 reverse-name shape).
/// Zero-allocation: computes length from the label iterator.
pub fn validate_query(name: &LowerName) -> Result<(), DnsError> {
    if name.is_empty() || name.is_root() {
        return Err(DnsError::EmptyName);
    }

    // Compute presentation-format length from labels without allocating.
    // Presentation format: "label1.label2.label3" (dots between, no trailing dot).
    // LowerName::iter() yields all labels INCLUDING the empty root label.
    let mut name_len: usize = 0;
    let mut label_count: usize = 0;
    // Last non-empty label (the TLD) — LowerName is already lowercase, so
    // a plain byte compare against b"arpa" suffices.
    let mut last_label: &[u8] = b"";

    for label in name.iter() {
        // Skip the empty root label (last element of iter())
        if label.is_empty() {
            continue;
        }
        if label.len() > MAX_LABEL_LEN {
            return Err(DnsError::LabelTooLong);
        }
        if label_count > 0 {
            name_len += 1; // dot separator
        }
        name_len += label.len();
        label_count += 1;
        last_label = label;
    }

    if name_len > MAX_NAME_LEN {
        return Err(DnsError::NameTooLong);
    }

    let max_labels = if last_label == b"arpa" {
        MAX_LABEL_COUNT_ARPA
    } else {
        MAX_LABEL_COUNT
    };
    if label_count > max_labels {
        return Err(DnsError::TooManyLabels);
    }

    Ok(())
}

/// Normalize a domain string to lowercase for lookups outside the hot path.
#[cfg(test)]
pub fn normalize_name(domain: &str) -> String {
    domain.to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    #[test]
    fn valid_domain_passes() {
        let name = LowerName::from_str("google.com.").unwrap();
        assert!(validate_query(&name).is_ok());
    }

    #[test]
    fn multi_level_domain_passes() {
        let name = LowerName::from_str("sub.domain.example.com.").unwrap();
        assert!(validate_query(&name).is_ok());
    }

    #[test]
    fn empty_root_rejected() {
        let name = LowerName::from_str(".").unwrap();
        assert!(matches!(validate_query(&name), Err(DnsError::EmptyName)));
    }

    #[test]
    fn label_too_long() {
        let long_label = "a".repeat(64);
        let domain = format!("{long_label}.com.");
        let name = LowerName::from_str(&domain);
        // hickory may reject this at parse time, which is also acceptable
        if let Ok(name) = name {
            assert!(matches!(validate_query(&name), Err(DnsError::LabelTooLong)));
        }
    }

    #[test]
    fn name_too_long() {
        // Build a name > 253 chars: 26 labels of 10 chars each = 285 chars
        let labels: Vec<String> = (0..26).map(|i| format!("abcdefgh{i:02}")).collect();
        let domain = format!("{}.", labels.join("."));
        let name = LowerName::from_str(&domain);
        if let Ok(name) = name {
            assert!(matches!(validate_query(&name), Err(DnsError::NameTooLong)));
        }
    }

    #[test]
    fn too_many_labels() {
        // 16 real labels exceeds our limit of 15
        let labels: Vec<&str> = (0..16).map(|_| "a").collect();
        let domain = format!("{}.", labels.join("."));
        let name = LowerName::from_str(&domain).unwrap();
        assert!(matches!(
            validate_query(&name),
            Err(DnsError::TooManyLabels)
        ));
    }

    #[test]
    fn exactly_15_labels_passes() {
        let labels: Vec<&str> = (0..15).map(|_| "a").collect();
        let domain = format!("{}.", labels.join("."));
        let name = LowerName::from_str(&domain).unwrap();
        assert!(validate_query(&name).is_ok());
    }

    /// Regression: a full IPv6 reverse name is 34 labels (32 nibbles +
    /// ip6 + arpa) — the 15-label cap SERVFAILed every IPv6 PTR query
    /// before anything else saw it.
    #[test]
    fn full_ip6_arpa_reverse_name_passes() {
        // 2001:4860:4860::8888 reversed, nibble-expanded: 32 one-char labels.
        let addr: std::net::Ipv6Addr = "2001:4860:4860::8888".parse().unwrap();
        let nibbles: Vec<String> = addr
            .octets()
            .iter()
            .rev()
            .flat_map(|o| [o & 0x0f, o >> 4])
            .map(|n| format!("{n:x}"))
            .collect();
        assert_eq!(nibbles.len(), 32);
        let domain = format!("{}.ip6.arpa.", nibbles.join("."));
        let name = LowerName::from_str(&domain).unwrap();
        assert!(
            validate_query(&name).is_ok(),
            "34-label ip6.arpa PTR name must validate"
        );
    }

    /// The relaxed cap is arpa-gated: 16 labels NOT under .arpa still fail.
    #[test]
    fn sixteen_labels_non_arpa_still_rejected() {
        let labels: Vec<&str> = (0..16).map(|_| "a").collect();
        let domain = format!("{}.", labels.join("."));
        let name = LowerName::from_str(&domain).unwrap();
        assert!(matches!(
            validate_query(&name),
            Err(DnsError::TooManyLabels)
        ));
    }

    /// Even .arpa has a ceiling: 35 labels exceeds the IPv6 reverse shape.
    #[test]
    fn over_34_labels_arpa_rejected() {
        let labels: Vec<&str> = (0..34).map(|_| "a").collect();
        let domain = format!("{}.arpa.", labels.join("."));
        let name = LowerName::from_str(&domain).unwrap();
        assert!(matches!(
            validate_query(&name),
            Err(DnsError::TooManyLabels)
        ));
    }

    /// Exactly 34 labels ending in arpa passes (the ip6.arpa bound).
    #[test]
    fn exactly_34_labels_arpa_passes() {
        let labels: Vec<&str> = (0..33).map(|_| "a").collect();
        let domain = format!("{}.arpa.", labels.join("."));
        let name = LowerName::from_str(&domain).unwrap();
        assert!(validate_query(&name).is_ok());
    }

    #[test]
    fn normalize_name_lowercases() {
        assert_eq!(normalize_name("Google.COM"), "google.com");
        assert_eq!(normalize_name("EXAMPLE.ORG"), "example.org");
        assert_eq!(normalize_name("already.lower"), "already.lower");
    }
}
