//! Extended query validation — security-focused checks beyond RFC limits.
//!
//! Sprint 1's `dns/validation.rs` enforces RFC 1035 structural limits
//! (label length, name length, depth). This module adds character validation
//! and malicious pattern detection.

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
/// L-12 (rev-2026-05-rebinding-stack-array): zero-allocation. Pre-fix the
/// labels were collected into a `Vec<&str>` on every query — small, but
/// runs on every pre-cache request. The stack array sized at MAX_LABELS=16
/// matches the `dns::validation::MAX_LABEL_COUNT = 15` ceiling (validation
/// runs upstream of this check) plus one slack slot, so a pathological
/// over-cap input (validation was bypassed) returns false without panicking.
/// Mirrors the pattern at `security::tunneling::check`.
pub fn has_rebinding_pattern(domain: &str) -> bool {
    const MAX_LABELS: usize = 16;
    let mut labels: [&str; MAX_LABELS] = [""; MAX_LABELS];
    let mut n = 0usize;
    for label in domain.split('.').filter(|l| !l.is_empty()) {
        if n >= MAX_LABELS {
            // Over-cap input: bail out fail-open. Defensive only — real
            // production traffic is filtered by validate_query (≤15 labels).
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
        // L-12 (rev-2026-05-rebinding-stack-array) regression pin: a
        // domain crafted with > MAX_LABELS labels must fail open
        // (return false) rather than panic on the stack-array index.
        // Real production traffic is filtered by validate_query (≤15
        // labels) so this is purely a defensive guard mirroring
        // L-9 in tunneling.rs.
        let huge = (0..30)
            .map(|i| format!("l{i}"))
            .collect::<Vec<_>>()
            .join(".");
        assert!(!has_rebinding_pattern(&huge));
    }
}
