//! Extended query validation — security-focused checks beyond RFC limits.
//!
//! `dns/validation.rs` enforces RFC 1035 structural limits (label length,
//! name length, depth). This module adds character validation and
//! malicious pattern detection.

use super::MAX_LABELS;

/// Validate domain characters. Returns an error string if invalid.
///
/// Valid DNS label characters (RFC 1035 §2.3.1):
/// - Letters: a-z (case-insensitive, but we receive lowercase)
/// - Digits: 0-9
/// - Hyphen: - (not at start or end of label)
/// - Underscore: _ (non-standard but common: DKIM, SRV records)
///
/// We reject: spaces, NUL bytes, control chars, non-ASCII.
pub fn validate_domain_chars(domain: &str) -> Result<(), &'static str> {
    if domain.is_empty() {
        return Err("empty domain");
    }

    for label in domain.split('.') {
        if label.is_empty() {
            continue; // trailing dot or root — handled elsewhere
        }

        // Label must not start or end with hyphen
        if label.starts_with('-') || label.ends_with('-') {
            return Err("label starts or ends with hyphen");
        }

        for ch in label.chars() {
            match ch {
                'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' => {}
                _ => return Err("invalid character in domain label"),
            }
        }
    }

    Ok(())
}

/// Check if a query has patterns commonly used in DNS rebinding attacks.
/// These queries encode IP addresses in labels to bypass same-origin policy.
///
/// Pattern: labels that look like IP addresses (e.g. "192.168.1.1.evil.com").
///
/// Labels live in a stack array sized at `MAX_LABELS` rather than a `Vec`,
/// because this runs on every pre-cache query. That bound is *derived* from
/// the deepest name `dns::validation` admits, so a name that reached here
/// after validation always fits — a literal would drift the moment either
/// validation ceiling moved, and a heuristic reading a truncated prefix of
/// the name fails open. Mirrors the pattern at `security::tunneling::check`.
pub fn has_rebinding_pattern(domain: &str) -> bool {
    let mut labels: [&str; MAX_LABELS] = [""; MAX_LABELS];
    let mut n = 0usize;
    for label in domain.split('.').filter(|l| !l.is_empty()) {
        if n >= MAX_LABELS {
            // Unreachable for a name that passed validation, which admits
            // fewer labels than this buffer holds. Bail rather than scan a
            // truncated prefix: a prefix is not the name that was asked for.
            return false;
        }
        labels[n] = label;
        n += 1;
    }
    if n < 4 {
        return false;
    }

    // Check if any 4 consecutive labels look like an IPv4 address
    // (e.g. "192.168.1.1.attacker.com"). The `len <= 3` check is a cheap
    // length pre-filter that skips the `parse::<u8>` call entirely for
    // labels that can't be a u8 (a u8 is at most 3 digits). `<u8 as
    // FromStr>` does not allocate; the guard just avoids the parse work.
    for w in 0..=(n - 4) {
        let win = &labels[w..w + 4];
        if win.iter().all(|l| l.len() <= 3 && l.parse::<u8>().is_ok()) {
            return true;
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- validate_domain_chars ---

    #[test]
    fn valid_simple_domain() {
        assert!(validate_domain_chars("example.com").is_ok());
    }

    #[test]
    fn valid_with_hyphens() {
        assert!(validate_domain_chars("my-domain.example.com").is_ok());
    }

    #[test]
    fn valid_with_underscores() {
        // DKIM records: _dmarc.example.com
        assert!(validate_domain_chars("_dmarc.example.com").is_ok());
    }

    #[test]
    fn valid_with_digits() {
        assert!(validate_domain_chars("host123.example.com").is_ok());
    }

    #[test]
    fn invalid_space() {
        assert!(validate_domain_chars("exam ple.com").is_err());
    }

    #[test]
    fn invalid_control_char() {
        assert!(validate_domain_chars("exam\x01ple.com").is_err());
    }

    #[test]
    fn invalid_leading_hyphen() {
        assert!(validate_domain_chars("-invalid.com").is_err());
    }

    #[test]
    fn invalid_trailing_hyphen() {
        assert!(validate_domain_chars("invalid-.com").is_err());
    }

    #[test]
    fn invalid_non_ascii() {
        assert!(validate_domain_chars("examplé.com").is_err());
    }

    #[test]
    fn empty_domain_rejected() {
        assert!(validate_domain_chars("").is_err());
    }

    #[test]
    fn valid_all_digits_label() {
        // "123.example.com" is valid DNS
        assert!(validate_domain_chars("123.example.com").is_ok());
    }

    // --- has_rebinding_pattern ---

    #[test]
    fn no_rebinding_normal_domain() {
        assert!(!has_rebinding_pattern("www.example.com"));
    }

    #[test]
    fn rebinding_ipv4_prefix() {
        assert!(has_rebinding_pattern("192.168.1.1.evil.com"));
    }

    #[test]
    fn no_rebinding_partial_ip() {
        // Only 3 octets — not a full IP
        assert!(!has_rebinding_pattern("192.168.1.evil.com"));
    }

    #[test]
    fn no_rebinding_too_short() {
        assert!(!has_rebinding_pattern("a.b"));
    }

    #[test]
    fn rebinding_internal_ip() {
        assert!(has_rebinding_pattern("10.0.0.1.rebind.attacker.com"));
    }

    #[test]
    fn has_rebinding_pattern_pathological_label_count_does_not_panic() {
        // A domain with more labels than the buffer holds must fail open
        // rather than panic on the stack-array index. Sized off MAX_LABELS
        // so raising the buffer cannot quietly move this name back under
        // the cap and leave the bail arm untested.
        let huge = (0..MAX_LABELS + 5)
            .map(|i| format!("l{i}"))
            .collect::<Vec<_>>()
            .join(".");
        assert!(!has_rebinding_pattern(&huge));
    }

    /// The other half of the bound: a name as deep as validation admits
    /// must still be *analysed*, not skipped. The quad sits at the front,
    /// so a buffer that fits the name answers `true` where one that
    /// overflows answers `false` — the two are distinguishable, which the
    /// over-cap test on its own is not.
    ///
    /// At a fixed buffer of 16 this name was never looked at, so padding a
    /// rebinding name past 15 labels walked straight through the check.
    #[test]
    fn rebinding_quad_at_the_deepest_admitted_name_is_still_detected() {
        use crate::dns::validation::MAX_LABEL_COUNT_ARPA;
        let quad = ["192", "168", "1", "1"].map(str::to_string);
        let filler = (0..MAX_LABEL_COUNT_ARPA - 4).map(|i| format!("l{i}"));
        let name = quad.into_iter().chain(filler).collect::<Vec<_>>().join(".");
        assert_eq!(name.split('.').count(), MAX_LABEL_COUNT_ARPA);
        assert!(has_rebinding_pattern(&name));
    }
}
