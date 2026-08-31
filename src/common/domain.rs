//! Domain-name validation helpers shared between `lists::parser` and
//! `filter::rules`.
//!
//! Both the external-list parser and the admin-rule parser need the same
//! "is this string a syntactically valid DNS name?" check. Living here
//! avoids a layering violation between `lists/` and `filter/`.

/// Validate a domain label structure.
///
/// Accepts: ASCII alphanumeric, hyphens, dots, underscores (for SRV/DMARC).
/// Rejects: empty labels (`example..com`), labels over 63 octets, labels
/// starting/ending with hyphen, domains exceeding 253 bytes (RFC 1035).
#[must_use]
pub fn is_valid_domain(domain: &str) -> bool {
    if domain.is_empty() || domain.len() > 253 {
        return false;
    }
    // Character-level check
    if !domain
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.' || b == b'_')
    {
        return false;
    }
    // Label-level check: no empty labels, RFC 1035 §2.3.4 caps a single
    // label at 63 octets, no leading/trailing hyphens.
    for label in domain.split('.') {
        if label.is_empty() || label.len() > 63 || label.starts_with('-') || label.ends_with('-') {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_basic_domain() {
        assert!(is_valid_domain("example.com"));
        assert!(is_valid_domain("a.b.c.d.example.com"));
    }

    #[test]
    fn accepts_underscores_for_srv_dmarc() {
        assert!(is_valid_domain("_dmarc.example.com"));
        assert!(is_valid_domain("_sip._tcp.example.com"));
    }

    #[test]
    fn rejects_empty() {
        assert!(!is_valid_domain(""));
    }

    #[test]
    fn rejects_over_253_bytes() {
        let too_long = "a".repeat(254);
        assert!(!is_valid_domain(&too_long));
    }

    #[test]
    fn rejects_empty_label() {
        assert!(!is_valid_domain("example..com"));
        assert!(!is_valid_domain(".example.com"));
        assert!(!is_valid_domain("example.com."));
    }

    #[test]
    fn rejects_label_over_63_octets() {
        // RFC 1035 §2.3.4 — a single label may not exceed 63 octets.
        let label_64 = "a".repeat(64);
        assert!(!is_valid_domain(&format!("{label_64}.com")));
        // Exactly 63 octets is the boundary and must still pass.
        let label_63 = "a".repeat(63);
        assert!(is_valid_domain(&format!("{label_63}.com")));
    }

    #[test]
    fn rejects_leading_or_trailing_hyphen() {
        assert!(!is_valid_domain("-example.com"));
        assert!(!is_valid_domain("example-.com"));
        assert!(!is_valid_domain("example.-com"));
    }

    #[test]
    fn rejects_html_or_script_characters() {
        assert!(!is_valid_domain("<script>foo</script>"));
        assert!(!is_valid_domain("foo<bar"));
        assert!(!is_valid_domain("foo bar"));
    }
}
