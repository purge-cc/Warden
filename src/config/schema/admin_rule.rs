//! [`AdminRule`] — a single AdGuard-syntax rule authored by the operator
//! (never sourced from an external blocklist).
//!
//! Per design doc §8.7 and project rules rule 4: `@@` allow-overrides and the
//! `$important` modifier are admin-only. External lists get the sandbox
//! parser; admin rules get the full AdGuard grammar.
//!
//! # Sprint 43 T5 — domain validator
//!
//! [`validate_domain`] is the single seat that vets operator-supplied
//! domain strings before they land in a synthesised `||domain^` or
//! `@@||domain^` rule. It enforces the §9 acceptance pipeline (LDH ASCII +
//! length caps + control-char rejection + IDN-as-Punycode requirement)
//! without taking any new crate dependency. NFKC + Punycode round-trip
//! collapse to identity on ASCII LDH input; non-ASCII input is rejected
//! with a friendly hint pointing at the Punycode form (`xn--...`).

use serde::{Deserialize, Serialize};

use super::id::Id;

/// ```toml
/// [[admin_rules]]
/// id = "default-allow-github"
/// rule = "@@||github.com^$important"
///
/// [[admin_rules]]
/// id = "default-deny-tiktok"
/// rule = "||tiktok.com^"
/// ```
///
/// The `rule` string is parse-validated at load time (rev-2606
/// schema-validator-05): the validator's `check_admin_rules` dry-runs
/// `filter::rules::parse_rule_checked` — the same parser the filter
/// engine consumes — so a config only loads if every rule will actually
/// enforce. Emptiness is checked separately first.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdminRule {
    pub id: Id,
    pub rule: String,
}

// ── Sprint 43 T5 — domain validation pipeline ─────────────────────────

/// Frozen template for [`format_rule_invalid_domain`]. Pinned by
/// `tests/frozen_strings_s43.rs` (T6) and the const-pin test below.
pub const RULE_INVALID_DOMAIN: &str =
    "'{input}' is not a valid domain (got: {reason}). Examples: example.com, mail.google.com";

/// Substitute `{input}` and `{reason}` into [`RULE_INVALID_DOMAIN`].
pub fn format_rule_invalid_domain(input: &str, reason: &str) -> String {
    RULE_INVALID_DOMAIN
        .replace("{input}", input)
        .replace("{reason}", reason)
}

/// Maximum total length of a domain in octets, per RFC 1035 §3.1.
const MAX_DOMAIN_OCTETS: usize = 253;

/// Maximum length of a single DNS label in octets, per RFC 1035 §2.3.4.
const MAX_LABEL_OCTETS: usize = 63;

/// Validate an operator-supplied domain string and return its canonical
/// (lowercased) form. The pipeline enforces, in order:
///
/// 1. Non-empty input.
/// 2. No NUL / newline / tab / other control bytes (`< 0x20` or `0x7F`).
/// 3. ASCII only (`b <= 0x7F`). Non-ASCII input is rejected with a hint
///    pointing at Punycode (`xn--...`) — IDN homoglyph attacks like
///    Cyrillic `gооgle.com` are caught here.
/// 4. LDH ASCII only (letters / digits / hyphen / dot, lowercase).
/// 5. No leading / trailing / consecutive dots.
/// 6. Each label `<= 63` octets, no leading or trailing hyphen.
/// 7. Total length `<= 253` octets.
///
/// # Why this matches the design doc's "NFKC + Punycode round-trip + LDH"
///
/// On ASCII LDH input, NFKC is the identity, and `to_ascii(s) == s` is
/// also the identity (Punycode encodes only non-ASCII labels). So the
/// composition collapses to "must end up as LDH ASCII", which this
/// function enforces directly without pulling in `idna` / `unicode-
/// normalization`. Operators who need IDN type the Punycode form.
pub fn validate_domain(input: &str) -> Result<String, String> {
    if input.is_empty() {
        return Err("empty input".into());
    }

    // (2) control chars + (3) ASCII-only
    for (i, b) in input.bytes().enumerate() {
        if b < 0x20 || b == 0x7F {
            return Err(format!(
                "control byte 0x{b:02x} at position {i} (NUL, newline, and tab are not allowed)"
            ));
        }
        if b > 0x7F {
            return Err(format!(
                "non-ASCII byte 0x{b:02x} at position {i} — for IDN use the Punycode form (xn--...)"
            ));
        }
    }

    let lowered: String = input.chars().map(|c| c.to_ascii_lowercase()).collect();

    // (5) leading / trailing dots
    if lowered.starts_with('.') {
        return Err("leading dot".into());
    }
    if lowered.ends_with('.') {
        return Err("trailing dot".into());
    }

    // (7) total length
    if lowered.len() > MAX_DOMAIN_OCTETS {
        return Err(format!(
            "{} octets exceeds RFC 1035 maximum of {MAX_DOMAIN_OCTETS}",
            lowered.len()
        ));
    }

    // Walk labels: at least one label, no empty label (no consecutive
    // dots), per-label length cap, hyphen position rule, LDH-only chars.
    let mut label_count = 0usize;
    for label in lowered.split('.') {
        label_count += 1;

        if label.is_empty() {
            return Err("empty label (consecutive dots are not allowed)".into());
        }
        if label.len() > MAX_LABEL_OCTETS {
            return Err(format!(
                "label '{label}' is {} octets — RFC 1035 limit is {MAX_LABEL_OCTETS}",
                label.len()
            ));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(format!(
                "label '{label}' must not start or end with a hyphen"
            ));
        }
        for ch in label.chars() {
            let ldh = ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-';
            if !ldh {
                return Err(format!(
                    "label '{label}' contains '{ch}' (only letters, digits, and hyphens are allowed)"
                ));
            }
        }
    }

    // A single-label "domain" (e.g. "localhost") is technically valid for
    // DNS but NEVER what an operator wants in a blocklist rule — every
    // realistic target has a TLD. Require at least two labels so the
    // operator gets a clear error if they typed "google" instead of
    // "google.com".
    if label_count < 2 {
        return Err("must contain at least one dot (e.g. example.com)".into());
    }

    Ok(lowered)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minimal_admin_rule_deserialises() {
        let a: AdminRule = toml::from_str(
            r#"
id = "allow-github"
rule = "@@||github.com^"
"#,
        )
        .unwrap();
        assert_eq!(a.id.as_str(), "allow-github");
        assert_eq!(a.rule, "@@||github.com^");
    }

    #[test]
    fn unknown_field_rejected() {
        let err = toml::from_str::<AdminRule>(
            r#"
id = "x"
rule = "||x^"
description = "unexpected"
"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("unknown field"));
    }

    // ── Sprint 43 T5 — domain validator ───────────────────────────────

    #[test]
    fn rule_invalid_domain_const_pinned() {
        // SN3 freeze — byte-for-byte. T6's `tests/frozen_strings_s43.rs`
        // re-pins this from outside the module; the in-module pin keeps
        // the const honest while T6 lands.
        assert_eq!(
            RULE_INVALID_DOMAIN,
            "'{input}' is not a valid domain (got: {reason}). Examples: example.com, mail.google.com"
        );
    }

    #[test]
    fn format_rule_invalid_domain_substitutes_input_and_reason() {
        let s = format_rule_invalid_domain("foo.bar", "leading dot");
        assert_eq!(
            s,
            "'foo.bar' is not a valid domain (got: leading dot). Examples: example.com, mail.google.com"
        );
    }

    #[test]
    fn validate_domain_accepts_simple_apex() {
        assert_eq!(validate_domain("example.com").unwrap(), "example.com");
    }

    #[test]
    fn validate_domain_lowercases_uppercase_input() {
        // Operators sometimes paste from URL bars that uppercase certain
        // labels; we silently fold to canonical lowercase.
        assert_eq!(validate_domain("Example.COM").unwrap(), "example.com");
    }

    #[test]
    fn validate_domain_accepts_subdomain() {
        assert_eq!(
            validate_domain("mail.google.com").unwrap(),
            "mail.google.com"
        );
    }

    #[test]
    fn validate_domain_accepts_punycode_idn() {
        // Punycode IDN form is LDH ASCII so the validator passes it
        // straight through. Operator who wants пример.рф types the
        // already-encoded form.
        assert_eq!(
            validate_domain("xn--e1afmkfd.xn--p1ai").unwrap(),
            "xn--e1afmkfd.xn--p1ai"
        );
    }

    #[test]
    fn validate_domain_rejects_empty() {
        let err = validate_domain("").unwrap_err();
        assert!(err.contains("empty"), "got: {err}");
    }

    #[test]
    fn validate_domain_rejects_cyrillic_homoglyph() {
        // The Cyrillic 'о' (U+043E) renders identical to Latin 'o' but
        // is a different DNS label. The validator must reject it on the
        // non-ASCII byte before any further processing.
        let err = validate_domain("gооgle.com").unwrap_err();
        assert!(
            err.contains("non-ASCII") && err.contains("Punycode"),
            "got: {err}"
        );
    }

    #[test]
    fn validate_domain_rejects_embedded_nul() {
        let err = validate_domain("ex\0ample.com").unwrap_err();
        assert!(err.contains("control byte"), "got: {err}");
    }

    #[test]
    fn validate_domain_rejects_embedded_newline() {
        let err = validate_domain("example.com\n").unwrap_err();
        assert!(err.contains("control byte"), "got: {err}");
    }

    #[test]
    fn validate_domain_rejects_leading_dot() {
        let err = validate_domain(".example.com").unwrap_err();
        assert!(err.contains("leading dot"), "got: {err}");
    }

    #[test]
    fn validate_domain_rejects_trailing_dot() {
        let err = validate_domain("example.com.").unwrap_err();
        assert!(err.contains("trailing dot"), "got: {err}");
    }

    #[test]
    fn validate_domain_rejects_double_dot() {
        let err = validate_domain("example..com").unwrap_err();
        assert!(err.contains("empty label"), "got: {err}");
    }

    #[test]
    fn validate_domain_rejects_label_over_63_octets() {
        let long = "a".repeat(64);
        let input = format!("{long}.com");
        let err = validate_domain(&input).unwrap_err();
        assert!(
            err.contains("64 octets") && err.contains("63"),
            "got: {err}"
        );
    }

    #[test]
    fn validate_domain_accepts_label_at_63_octets() {
        let max = "a".repeat(63);
        let input = format!("{max}.com");
        assert!(validate_domain(&input).is_ok());
    }

    #[test]
    fn validate_domain_rejects_total_over_253_octets() {
        // 4 × 63-char labels = 252 + 3 dots = 255, well over.
        let long_label = "a".repeat(63);
        let input = format!("{long_label}.{long_label}.{long_label}.{long_label}.com");
        let err = validate_domain(&input).unwrap_err();
        assert!(
            err.contains("octets exceeds") && err.contains("253"),
            "got: {err}"
        );
    }

    #[test]
    fn validate_domain_rejects_leading_hyphen_in_label() {
        let err = validate_domain("-bad.com").unwrap_err();
        assert!(err.contains("hyphen"), "got: {err}");
    }

    #[test]
    fn validate_domain_rejects_trailing_hyphen_in_label() {
        let err = validate_domain("bad-.com").unwrap_err();
        assert!(err.contains("hyphen"), "got: {err}");
    }

    #[test]
    fn validate_domain_rejects_underscore_in_label() {
        let err = validate_domain("foo_bar.com").unwrap_err();
        assert!(err.contains("only letters"), "got: {err}");
    }

    #[test]
    fn validate_domain_rejects_single_label() {
        let err = validate_domain("localhost").unwrap_err();
        assert!(err.contains("at least one dot"), "got: {err}");
    }

    #[test]
    fn validate_domain_accepts_digits_in_label() {
        // RFC 1123 §2.1 — labels may start with a digit.
        assert_eq!(validate_domain("3com.com").unwrap(), "3com.com");
    }
}
