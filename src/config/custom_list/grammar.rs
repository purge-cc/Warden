//! The custom-list line grammar: exactly two rule forms, nothing else.
//!
//! Anything richer — wildcard, regex, modifier — is refused here rather
//! than downstream, because the alternative destination is the advanced-rule
//! vector, which is scanned linearly on every query. A file an operator can
//! grow to tens of thousands of lines must not be able to reach it.

use compact_str::CompactString;

const MAX_DOMAIN_LEN: usize = 253;
const MAX_LABEL_LEN: usize = 63;

const ALLOW_PREFIX: &str = "@@||";
const DENY_PREFIX: &str = "||";
const TERMINATOR: char = '^';

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PackLine {
    /// Blank or comment. Carries no rule.
    Blank,
    Allow(CompactString),
    Deny(CompactString),
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GrammarError {
    #[error(
        "unrecognised rule: expected `||<domain>^` or `@@||<domain>^`; \
         wildcards, regular expressions and modifiers belong in [[admin_rules]]"
    )]
    NotARule,
    #[error("empty domain")]
    EmptyDomain,
    #[error("domain is {0} bytes, over the {MAX_DOMAIN_LEN}-byte limit")]
    DomainTooLong(usize),
    #[error("label {0:?} is over the {MAX_LABEL_LEN}-byte limit")]
    LabelTooLong(String),
    #[error("empty label — `..` or a leading/trailing dot")]
    EmptyLabel,
    #[error("label {0:?} starts or ends with a hyphen")]
    HyphenAtLabelEdge(String),
    #[error("byte {0:?} is not allowed in a domain (letters, digits, hyphen and dot only)")]
    NotLdh(char),
    #[error("value contains a line separator and would become more than one rule")]
    LineSeparator,
}

/// Parse one line of a pack file.
///
/// Leading and trailing whitespace is tolerated; the operator hand-edits
/// these files and an accidental indent must not silently drop a rule.
pub fn parse_pack_line(line: &str) -> Result<PackLine, GrammarError> {
    let t = line.trim();
    if t.is_empty() || t.starts_with('#') {
        return Ok(PackLine::Blank);
    }
    // Longest prefix first: the allow form contains the deny prefix.
    if let Some(rest) = t.strip_prefix(ALLOW_PREFIX) {
        return Ok(PackLine::Allow(strip_terminator(rest)?));
    }
    if let Some(rest) = t.strip_prefix(DENY_PREFIX) {
        return Ok(PackLine::Deny(strip_terminator(rest)?));
    }
    Err(GrammarError::NotARule)
}

fn strip_terminator(rest: &str) -> Result<CompactString, GrammarError> {
    let body = rest
        .strip_suffix(TERMINATOR)
        .ok_or(GrammarError::NotARule)?;
    normalise_domain(body)
}

/// Lowercase and validate `raw` as a bare LDH domain.
///
/// Case normalisation happens here because it must happen at ingestion as
/// well as at lookup: a rule stored with a capital can never match.
pub fn normalise_domain(raw: &str) -> Result<CompactString, GrammarError> {
    if raw.is_empty() {
        return Err(GrammarError::EmptyDomain);
    }
    if raw.len() > MAX_DOMAIN_LEN {
        return Err(GrammarError::DomainTooLong(raw.len()));
    }
    for c in raw.chars() {
        let ok = c.is_ascii_alphanumeric() || c == '-' || c == '.';
        if !ok {
            return Err(GrammarError::NotLdh(c));
        }
    }
    for label in raw.split('.') {
        if label.is_empty() {
            return Err(GrammarError::EmptyLabel);
        }
        if label.len() > MAX_LABEL_LEN {
            return Err(GrammarError::LabelTooLong(label.to_string()));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(GrammarError::HyphenAtLabelEdge(label.to_string()));
        }
    }
    Ok(CompactString::new(raw.to_ascii_lowercase()))
}

/// Build one rule line from a domain the operator picked.
///
/// Two defences, both needed. The domain is constrained to LDH, which
/// excludes every separator and every metacharacter by construction; then
/// the composed line is checked for a separator as a whole. Checking after
/// splitting would validate two legitimate lines that together are an
/// injection.
pub fn compose_line(domain: &str, allow: bool) -> Result<String, GrammarError> {
    if domain.contains('\n') || domain.contains('\r') {
        return Err(GrammarError::LineSeparator);
    }
    let d = normalise_domain(domain)?;
    let line = if allow {
        format!("{ALLOW_PREFIX}{d}{TERMINATOR}")
    } else {
        format!("{DENY_PREFIX}{d}{TERMINATOR}")
    };
    if line.contains('\n') || line.contains('\r') {
        return Err(GrammarError::LineSeparator);
    }
    Ok(line)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_two_accepted_forms_parse() {
        assert_eq!(
            parse_pack_line("@@||cdn.example.com^").unwrap(),
            PackLine::Allow("cdn.example.com".into())
        );
        assert_eq!(
            parse_pack_line("||ads.example.com^").unwrap(),
            PackLine::Deny("ads.example.com".into())
        );
    }

    #[test]
    fn blanks_and_comments_are_blank() {
        for s in ["", "   ", "\t", "# a comment", "   # indented"] {
            assert_eq!(parse_pack_line(s).unwrap(), PackLine::Blank, "input: {s:?}");
        }
    }

    #[test]
    fn surrounding_whitespace_is_tolerated() {
        assert_eq!(
            parse_pack_line("  ||ads.example.com^  ").unwrap(),
            PackLine::Deny("ads.example.com".into())
        );
    }

    #[test]
    fn every_advanced_form_is_refused() {
        // This is the hot-path guard, not a style preference. Each of these
        // would otherwise land in the linearly-scanned advanced-rule vector.
        // Mutation: re-admit any one of them and this goes red.
        let advanced = [
            "||*.example.com^",
            "||ads.example.*^",
            "/^ads[0-9]+\\.example\\.com$/",
            "||ads.example.com^$important",
            "@@||cdn.example.com^$noapex",
            "ads.example.com",         // bare domain: no anchors
            "||ads.example.com",       // missing terminator
            "ads.example.com^",        // missing prefix
            "@@ads.example.com^",      // missing pipes
            "0.0.0.0 ads.example.com", // hosts syntax
        ];
        for s in advanced {
            assert!(
                parse_pack_line(s).is_err(),
                "advanced or malformed form was accepted: {s:?}"
            );
        }
    }

    #[test]
    fn a_domain_is_lowercased_on_ingestion() {
        // Case normalisation happens at ingestion AND at lookup; a rule
        // stored with a capital never matches a normalised qname.
        assert_eq!(
            parse_pack_line("||ADS.Example.COM^").unwrap(),
            PackLine::Deny("ads.example.com".into())
        );
    }

    #[test]
    fn a_non_ldh_domain_is_refused() {
        for raw in [
            "ads_example.com",  // underscore
            "ads example.com",  // space
            "ads.example.com/", // slash
            "ads.example.com:53",
            "-ads.example.com", // leading hyphen in a label
            "ads-.example.com", // trailing hyphen in a label
            "ads..example.com", // empty label
            ".example.com",
            "example.com.",
            "",
        ] {
            assert!(
                normalise_domain(raw).is_err(),
                "non-LDH domain was accepted: {raw:?}"
            );
        }
    }

    #[test]
    fn the_length_ceilings_are_enforced() {
        let long_label = "a".repeat(64);
        assert!(normalise_domain(&format!("{long_label}.example.com")).is_err());
        let ok_label = "a".repeat(63);
        assert!(normalise_domain(&format!("{ok_label}.example.com")).is_ok());

        let long = std::iter::repeat_n("aaaaaaaa", 40)
            .collect::<Vec<_>>()
            .join(".");
        assert!(long.len() > 253);
        assert!(normalise_domain(&long).is_err());
    }

    #[test]
    fn a_hostile_qname_cannot_become_two_lines() {
        // The Query Log does not restrict the bytes inside a label: query
        // validation checks lengths and depth only. A rule written into a
        // line-oriented file has none of the escaping a TOML string gives,
        // so an embedded separator would append a second rule the operator
        // never saw. Two variants: one fails LDH, one passes a naive
        // "printable?" check but carries a separator.
        assert!(compose_line("evil.example.com\n@@||anything.example.com", false).is_err());
        assert!(compose_line("evil.example.com\r\n||x.example.com", false).is_err());
        assert!(compose_line("evil.example.com^", false).is_err());
        assert!(compose_line("evil.example.com$important", false).is_err());
    }

    #[test]
    fn compose_and_parse_are_inverses() {
        let deny = compose_line("ads.example.com", false).unwrap();
        assert_eq!(deny, "||ads.example.com^");
        assert_eq!(
            parse_pack_line(&deny).unwrap(),
            PackLine::Deny("ads.example.com".into())
        );

        let allow = compose_line("CDN.Example.com", true).unwrap();
        assert_eq!(allow, "@@||cdn.example.com^");
        assert_eq!(
            parse_pack_line(&allow).unwrap(),
            PackLine::Allow("cdn.example.com".into())
        );
    }

    #[test]
    fn compose_emits_only_forms_the_reader_accepts() {
        // The writer and the reader are two functions, and each half is
        // green on its own while the pair is broken: a composer that emits
        // a form its own parser refuses loses the rule silently. Both
        // directions, over a table, against the normalised domain rather
        // than a hand-written string.
        for d in [
            "example.com",
            "cdn.example.com",
            "CDN.Example.COM",
            "a.b.my-host.example.org",
        ] {
            let want = normalise_domain(d).unwrap();

            let allow = compose_line(d, true).unwrap();
            assert_eq!(
                parse_pack_line(&allow).unwrap(),
                PackLine::Allow(want.clone()),
                "allow line {allow:?} did not parse back to {want:?}"
            );

            let deny = compose_line(d, false).unwrap();
            assert_eq!(
                parse_pack_line(&deny).unwrap(),
                PackLine::Deny(want),
                "deny line {deny:?} did not parse back"
            );
        }

        // A trailing dot is refused at composition, in both directions, so
        // it never becomes a line the reader would have to skip.
        assert!(compose_line("example.org.", true).is_err());
        assert!(compose_line("example.org.", false).is_err());
    }
}
