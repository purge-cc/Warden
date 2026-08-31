//! DNS rule types and admin rule parser.
//!
//! `DnsRule` represents a single filtering rule with pattern matching,
//! action (block/allow), and optional `$important` priority flag.
//! These rules are used in admin profile configs — NOT for external lists
//! (external lists use the sandboxed parser in `lists::parser`).
//!
//! Supports AdGuard DNS syntax:
//! - `||domain^` — block domain + subdomains
//! - `@@||domain^` — allow (override block)
//! - `||*.suffix^` — wildcard subdomain match
//! - `/regex/` — regex pattern match (compiled case-insensitive — lookup
//!   input is lowercased by invariant, so an as-authored uppercase literal
//!   could never match; rev-2606 rules-02)
//! - `$important` / `$noapex` — the only recognized modifiers; anything
//!   else is a parse error, not a silent no-op (rev-2606 rules-03)
//! - Plain `domain` — block exact domain
//!
//! Parsing has two entry points: [`parse_rule_checked`] returns a typed
//! [`RuleParseError`] (consumed by the config validator so `config lint`
//! rejects exactly what this parser rejects — rev-2606
//! schema-validator-05), and [`parse_rule`] is its `Option` adapter for
//! engine-side callers.

use compact_str::CompactString;
use regex::{Regex, RegexBuilder};

use crate::common::domain::is_valid_domain;

/// How a rule matches domains.
#[derive(Clone)]
pub enum RulePattern {
    /// Exact domain match with subdomain walk.
    /// `||example.com^` matches `example.com`, `sub.example.com`, etc.
    Exact(CompactString),
    /// Wildcard suffix match.
    /// `||*.ads.example.com^` matches any subdomain of `ads.example.com`.
    Wildcard(CompactString),
    /// Compiled regex pattern.
    /// `/ad[0-9]+\.example\.com/` matches via regex.
    Regex {
        source: CompactString,
        compiled: Regex,
    },
}

impl std::fmt::Debug for RulePattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Exact(d) => write!(f, "Exact({d})"),
            Self::Wildcard(s) => write!(f, "Wildcard(*.{s})"),
            Self::Regex { source, .. } => write!(f, "Regex(/{source}/)"),
        }
    }
}

/// What the rule does when it matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleAction {
    /// Block the query (return canned response).
    Block,
    /// Allow the query (override blocks).
    Allow,
}

/// A single DNS filtering rule.
///
/// Rules are parsed from admin profile config strings. They carry a pattern,
/// an action, and an optional `$important` flag for priority elevation.
#[derive(Clone)]
pub struct DnsRule {
    pub pattern: RulePattern,
    pub action: RuleAction,
    pub important: bool,
    /// For wildcard rules: if `true`, do NOT auto-expand `||*.X^` to include `||X^`.
    /// Parsed from `$noapex` modifier. Only meaningful for `Wildcard` patterns.
    pub noapex: bool,
}

impl std::fmt::Debug for DnsRule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DnsRule")
            .field("pattern", &self.pattern)
            .field("action", &self.action)
            .field("important", &self.important)
            .finish()
    }
}

impl DnsRule {
    /// Test whether this rule's pattern matches a domain.
    ///
    /// - **Exact**: matches the domain itself or any subdomain (subdomain walk)
    /// - **Wildcard**: matches subdomains of the suffix (not the suffix itself)
    /// - **Regex**: matches if the regex finds a match anywhere in the domain
    pub fn matches(&self, domain: &str) -> bool {
        match &self.pattern {
            RulePattern::Exact(target) => {
                domain == target.as_str() || is_subdomain_of(domain, target.as_str())
            }
            RulePattern::Wildcard(suffix) => is_subdomain_of(domain, suffix.as_str()),
            RulePattern::Regex { compiled, .. } => compiled.is_match(domain),
        }
    }

    /// Whether this rule is a simple exact domain (no wildcard, regex, or $important).
    /// Used to decide whether a rule goes into the HashSet fast path or the rules Vec.
    pub fn is_simple_exact(&self) -> bool {
        matches!(self.pattern, RulePattern::Exact(_)) && !self.important
    }

    /// Extract the domain from an Exact pattern. Returns None for other patterns.
    pub fn exact_domain(&self) -> Option<&CompactString> {
        match &self.pattern {
            RulePattern::Exact(d) => Some(d),
            _ => None,
        }
    }
}

/// Check if `domain` is a subdomain of `parent`.
/// "sub.example.com" is a subdomain of "example.com".
/// "example.com" is NOT a subdomain of "example.com" (it's an exact match).
///
/// L-13 (rev-2026-05-suffix-empty-guard): empty-parent early return.
/// `parse_rule` rejects empty patterns upstream, so today's call sites
/// cannot reach this branch — but the helper is reachable from rule
/// patterns derived elsewhere, and an empty `parent` would otherwise
/// match every dot-terminated domain via `ends_with("")` returning true.
/// Pure contract pin.
fn is_subdomain_of(domain: &str, parent: &str) -> bool {
    if parent.is_empty() {
        return false;
    }
    domain.len() > parent.len()
        && domain.ends_with(parent)
        && domain.as_bytes()[domain.len() - parent.len() - 1] == b'.'
}

/// Why an admin rule string failed to parse. One variant per failure mode
/// of [`parse_rule_checked`].
///
/// `Display` strings are operator-facing: the config validator embeds them
/// in `ValidationFailed` errors (rev-2606 schema-validator-05), so they are
/// pinned byte-for-byte in `tests/frozen_strings_entity_contracts.rs`.
/// Payloads are `String` (not `regex::Error`) so the enum stays
/// `Clone + PartialEq + Eq` like `ConfigError`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RuleParseError {
    #[error("rule text is empty")]
    Empty,
    #[error("regex rule is missing its closing '/' — regex rules have the shape /pattern/")]
    UnterminatedRegex,
    #[error("regex rule has an empty pattern — '//' matches nothing")]
    EmptyRegex,
    #[error("regex '/{pattern}/' failed to compile: {detail}")]
    InvalidRegex { pattern: String, detail: String },
    #[error("unexpected text '{trailing}' after the regex's closing '/' — regex rules take no modifiers and must end at the final '/'")]
    TrailingAfterRegex { trailing: String },
    #[error("unknown modifier '${modifier}' — supported modifiers are $important and $noapex")]
    UnknownModifier { modifier: String },
    #[error("rule has no domain pattern between the '||' prefix and the '^' anchor")]
    EmptyPattern,
    #[error("'*' is only supported as a leading '*.' wildcard (e.g. ||*.ads.example.com^)")]
    StrayWildcard,
    #[error("'{input}' is not a valid domain (letters, digits, hyphens, underscores; dot-separated labels)")]
    InvalidDomain { input: String },
}

impl RuleParseError {
    /// Operator next step, consumed by the validator's `with_suggestion`.
    pub fn suggestion(&self) -> &'static str {
        match self {
            Self::Empty => "delete the entry or provide a pattern like ||ads.example.com^",
            Self::UnterminatedRegex => "close the pattern with '/' — e.g. /ad[0-9]+/",
            Self::EmptyRegex => "put a pattern between the slashes — e.g. /ad[0-9]+/",
            Self::InvalidRegex { .. } => {
                "fix the regex syntax (Rust regex crate dialect); escape literal specials with '\\'"
            }
            Self::TrailingAfterRegex { .. } => {
                "end the rule at the closing '/' — move modifiers onto a non-regex rule"
            }
            Self::UnknownModifier { .. } => "use $important and/or $noapex, or drop the modifier",
            Self::EmptyPattern => "add a domain between '||' and '^' — e.g. ||ads.example.com^",
            Self::StrayWildcard => "move the wildcard to a leading '*.': ||*.ads.example.com^",
            Self::InvalidDomain { .. } => "use a plain DNS name — e.g. ||tracker.example.com^",
        }
    }
}

/// Parse an admin config rule string into a `DnsRule`.
///
/// Supports full AdGuard DNS syntax:
/// - `@@||domain^$important` → Allow, Exact, important
/// - `||domain^$important` → Block, Exact, important
/// - `@@||domain^` → Allow, Exact
/// - `||domain^` → Block, Exact
/// - `@@||*.suffix^` → Allow, Wildcard
/// - `||*.suffix^` → Block, Wildcard
/// - `@@/regex/` → Allow, Regex
/// - `/regex/` → Block, Regex
/// - `domain` → Block, Exact (plain domain shorthand)
/// - `@@domain` → Allow, Exact (plain domain shorthand)
///
/// Regexes compile case-insensitive (rev-2606 rules-02): engine lookups are
/// lowercase by invariant, so an as-authored `/DoubleClick/` could never
/// match; authors can opt back out with an inline `(?-i)`. The pattern is
/// terminated by the FIRST unescaped-or-not `/` after the opening one —
/// text after it is an error, not ignored (rev-2606 rules-03), which also
/// means `$important` on a regex is rejected rather than silently dropped
/// (May res-10 / rules-01, closed in the reject direction).
///
/// This is the single source of truth for rule-text validity: the schema
/// validator's `check_admin_rules` calls it too, so `config lint` accepts
/// exactly the set the filter engine will enforce.
pub fn parse_rule_checked(line: &str) -> Result<DnsRule, RuleParseError> {
    let mut s = line.trim();
    if s.is_empty() {
        return Err(RuleParseError::Empty);
    }

    // Determine action from @@ prefix
    let action = if s.starts_with("@@") {
        s = &s[2..];
        RuleAction::Allow
    } else {
        RuleAction::Block
    };

    // Regex: /pattern/ or @@/pattern/. Any leading '/' commits to the
    // regex grammar — `/`, `//`, `/x` get regex-shaped errors here instead
    // of falling through to a misleading "not a valid domain" (the domain
    // path can never accept a '/', so the accept set is unchanged).
    if let Some(rest) = s.strip_prefix('/') {
        let Some(end) = rest.find('/') else {
            return Err(RuleParseError::UnterminatedRegex);
        };
        let pattern_str = &rest[..end];
        if pattern_str.is_empty() {
            return Err(RuleParseError::EmptyRegex);
        }
        let trailing = &rest[end + 1..];
        if !trailing.is_empty() {
            return Err(RuleParseError::TrailingAfterRegex {
                trailing: trailing.to_string(),
            });
        }
        // L-10 (rev-2026-04-admin-regex-size): cap the compiled regex
        // size at 1 MiB. Rust's `regex` crate is linear-time so there
        // is no ReDoS risk, but a huge admin pattern (e.g. a giant
        // alternation pasted by accident) can still pin a lot of
        // memory. The cap rejects patterns that would compile larger
        // than 1 MiB at parse time with a clear error, instead of
        // silently growing process RSS.
        let compiled = RegexBuilder::new(pattern_str)
            .size_limit(1 << 20)
            .case_insensitive(true)
            .build()
            .map_err(|e| RuleParseError::InvalidRegex {
                pattern: pattern_str.to_string(),
                detail: e.to_string(),
            })?;
        return Ok(DnsRule {
            pattern: RulePattern::Regex {
                source: CompactString::new(pattern_str),
                compiled,
            },
            action,
            // Modifiers on a regex are a TrailingAfterRegex error above, so
            // these are structurally always false here.
            important: false,
            noapex: false,
        });
    }

    // Strip || prefix
    let has_pipe_prefix = s.starts_with("||");
    if has_pipe_prefix {
        s = &s[2..];
    }

    // Check for $modifiers
    let mut important = false;
    let mut noapex = false;
    if let Some(dollar_pos) = s.find('$') {
        let modifiers = &s[dollar_pos + 1..];
        s = &s[..dollar_pos];
        for m in modifiers.split(',') {
            match m.trim() {
                "important" => important = true,
                "noapex" => noapex = true,
                unknown => {
                    return Err(RuleParseError::UnknownModifier {
                        modifier: unknown.to_string(),
                    });
                }
            }
        }
    }

    // Strip trailing ^ anchor
    s = s.strip_suffix('^').unwrap_or(s);

    if s.is_empty() {
        return Err(RuleParseError::EmptyPattern);
    }

    // Wildcard: *.suffix
    if let Some(suffix) = s.strip_prefix("*.") {
        if suffix.is_empty() || !is_valid_domain(suffix) {
            return Err(RuleParseError::InvalidDomain {
                input: suffix.to_string(),
            });
        }
        let mut cs = CompactString::new(suffix);
        cs.make_ascii_lowercase();
        return Ok(DnsRule {
            pattern: RulePattern::Wildcard(cs),
            action,
            important,
            noapex,
        });
    }

    // Reject remaining wildcards in unexpected positions
    if s.contains('*') {
        return Err(RuleParseError::StrayWildcard);
    }

    // Exact domain — reject malformed inputs (HTML, empty labels, etc.) at
    // parse time. Before this check the parser silently accepted patterns
    // like `||<script>foo</script>^` that could never match anything,
    // hiding admin-config typos until the operator noticed traffic flowing.
    if !is_valid_domain(s) {
        return Err(RuleParseError::InvalidDomain {
            input: s.to_string(),
        });
    }
    let mut cs = CompactString::new(s);
    cs.make_ascii_lowercase();
    Ok(DnsRule {
        pattern: RulePattern::Exact(cs),
        action,
        important,
        noapex: false,
    })
}

/// `Option` adapter over [`parse_rule_checked`] for engine-side callers
/// that only care whether a rule exists. Returns `None` for
/// empty/unparseable input.
pub fn parse_rule(line: &str) -> Option<DnsRule> {
    parse_rule_checked(line).ok()
}

/// Parse a rule string and auto-expand `||*.X^` to include `||X^` (apex match).
///
/// Returns a `Vec` with one rule for most inputs. For wildcard rules without
/// `$noapex`, returns two rules: the original wildcard plus an exact apex rule.
/// This matches user expectation: blocking `*.example.com` should also block
/// `example.com` itself.
pub fn parse_rules(line: &str) -> Vec<DnsRule> {
    let Some(rule) = parse_rule(line) else {
        return Vec::new();
    };

    // Auto-expand wildcard to include apex unless opted out
    if let RulePattern::Wildcard(ref suffix) = rule.pattern {
        if !rule.noapex {
            let apex = DnsRule {
                pattern: RulePattern::Exact(suffix.clone()),
                action: rule.action,
                important: rule.important,
                noapex: false,
            };
            return vec![rule, apex];
        }
    }

    vec![rule]
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- parse_rule ---

    #[test]
    fn parse_adguard_block() {
        let rule = parse_rule("||tiktok.com^").unwrap();
        assert_eq!(rule.action, RuleAction::Block);
        assert!(!rule.important);
        assert!(matches!(rule.pattern, RulePattern::Exact(ref d) if d == "tiktok.com"));
    }

    #[test]
    fn parse_adguard_allow() {
        let rule = parse_rule("@@||wikipedia.org^").unwrap();
        assert_eq!(rule.action, RuleAction::Allow);
        assert!(!rule.important);
        assert!(matches!(rule.pattern, RulePattern::Exact(ref d) if d == "wikipedia.org"));
    }

    #[test]
    fn parse_important_block() {
        let rule = parse_rule("||malware.com^$important").unwrap();
        assert_eq!(rule.action, RuleAction::Block);
        assert!(rule.important);
        assert!(matches!(rule.pattern, RulePattern::Exact(ref d) if d == "malware.com"));
    }

    #[test]
    fn parse_important_allow() {
        let rule = parse_rule("@@||captive.apple.com^$important").unwrap();
        assert_eq!(rule.action, RuleAction::Allow);
        assert!(rule.important);
        assert!(matches!(rule.pattern, RulePattern::Exact(ref d) if d == "captive.apple.com"));
    }

    #[test]
    fn parse_unknown_modifier_rejected() {
        // rev-2606 rules-03: sanctioned behavior overturn. Until this fix
        // unsupported modifiers were silently ignored — `$third-party` was
        // dropped and the rule enforced anyway (this test pinned that
        // tolerance). Now an unrecognized modifier is a parse error so the
        // rule can't enforce something broader than authored.
        assert_eq!(
            parse_rule_checked("||ads.com^$third-party,important").unwrap_err(),
            RuleParseError::UnknownModifier {
                modifier: "third-party".to_string()
            }
        );
        assert!(parse_rule("||ads.com^$third-party,important").is_none());
    }

    #[test]
    fn parse_wildcard_block() {
        let rule = parse_rule("||*.ads.example.com^").unwrap();
        assert_eq!(rule.action, RuleAction::Block);
        assert!(matches!(rule.pattern, RulePattern::Wildcard(ref s) if s == "ads.example.com"));
    }

    #[test]
    fn parse_wildcard_allow() {
        let rule = parse_rule("@@||*.cdn.example.com^").unwrap();
        assert_eq!(rule.action, RuleAction::Allow);
        assert!(matches!(rule.pattern, RulePattern::Wildcard(ref s) if s == "cdn.example.com"));
    }

    #[test]
    fn parse_wildcard_important() {
        let rule = parse_rule("||*.evil.com^$important").unwrap();
        assert!(rule.important);
        assert!(matches!(rule.pattern, RulePattern::Wildcard(ref s) if s == "evil.com"));
    }

    #[test]
    fn parse_regex_block() {
        let rule = parse_rule("/ad[0-9]+\\.example\\.com/").unwrap();
        assert_eq!(rule.action, RuleAction::Block);
        assert!(matches!(rule.pattern, RulePattern::Regex { .. }));
    }

    #[test]
    fn parse_regex_allow() {
        let rule = parse_rule("@@/safe-cdn[0-9]+\\.example\\.com/").unwrap();
        assert_eq!(rule.action, RuleAction::Allow);
        assert!(matches!(rule.pattern, RulePattern::Regex { .. }));
    }

    #[test]
    fn parse_plain_domain() {
        let rule = parse_rule("example.com").unwrap();
        assert_eq!(rule.action, RuleAction::Block);
        assert!(matches!(rule.pattern, RulePattern::Exact(ref d) if d == "example.com"));
    }

    #[test]
    fn parse_plain_domain_allow() {
        let rule = parse_rule("@@example.com").unwrap();
        assert_eq!(rule.action, RuleAction::Allow);
        assert!(matches!(rule.pattern, RulePattern::Exact(ref d) if d == "example.com"));
    }

    #[test]
    fn parse_case_lowered() {
        let rule = parse_rule("||TikTok.COM^").unwrap();
        assert!(matches!(rule.pattern, RulePattern::Exact(ref d) if d == "tiktok.com"));
    }

    #[test]
    fn parse_empty() {
        assert!(parse_rule("").is_none());
        assert!(parse_rule("  ").is_none());
    }

    #[test]
    fn parse_invalid_regex() {
        // Unclosed group → regex compilation fails → None
        assert!(parse_rule("/unclosed(group/").is_none());
    }

    #[test]
    fn parse_oversized_regex_rejected() {
        // L-10 (rev-2026-04-admin-regex-size) regression pin: a regex
        // whose compiled NFA exceeds 1 MiB must be rejected at parse time
        // rather than silently consuming process memory. A long alternation
        // with bounded repetition expands to a large compiled size — the
        // crate's `size_limit` check fires and we return None.
        let big = format!("a{{{}}}", 200_000);
        assert!(
            parse_rule(&format!("/{big}/")).is_none(),
            "huge `a{{200000}}` regex should be rejected by the 1 MiB size limit"
        );
    }

    #[test]
    fn parse_normal_regex_within_size_limit_accepted() {
        // L-10 sibling: realistic admin patterns must still parse cleanly —
        // the cap is a defense against absurd patterns, not normal use.
        assert!(parse_rule("/^ad[0-9]+\\.example\\.com$/").is_some());
        assert!(parse_rule("/tracker.*\\.evil/").is_some());
    }

    #[test]
    fn parse_regex_case_insensitive() {
        // rev-2606 rules-02: engine lookups are lowercase by invariant, so
        // an as-authored uppercase literal could never match. Regexes now
        // compile case-insensitive (AdGuard parity).
        let rule = parse_rule("/DoubleClick/").unwrap();
        assert!(rule.matches("doubleclick.net"));
        let classy = parse_rule("/AD[0-9]+/").unwrap();
        assert!(classy.matches("ad123.example.com"));
        // Inline opt-out still honored.
        let strict = parse_rule("/(?-i)DoubleClick/").unwrap();
        assert!(!strict.matches("doubleclick.net"));
        // Shorthand-class semantics are untouched (the source is never
        // lowercased): \D still means non-digit.
        let nondigit = parse_rule("/\\D+/").unwrap();
        assert!(nondigit.matches("ads.example.com"));
    }

    #[test]
    fn parse_regex_trailing_text_rejected() {
        // rev-2606 rules-03: text after the closing '/' was silently
        // discarded (`/foo/bar` enforced `/foo/`). Now an error — which
        // also rejects `$important` on a regex loudly (May res-10 /
        // rules-01 closed in the reject direction).
        assert_eq!(
            parse_rule_checked("/foo/bar").unwrap_err(),
            RuleParseError::TrailingAfterRegex {
                trailing: "bar".to_string()
            }
        );
        assert!(matches!(
            parse_rule_checked("/foo/$important"),
            Err(RuleParseError::TrailingAfterRegex { .. })
        ));
        assert!(matches!(
            parse_rule_checked("@@/foo/$dnstype=AAAA"),
            Err(RuleParseError::TrailingAfterRegex { .. })
        ));
    }

    #[test]
    fn parse_degenerate_regex_shapes_get_regex_errors() {
        // Guard simplification: any leading '/' commits to the regex
        // grammar, so `/`, `//`, `/x` report regex-shaped errors instead
        // of "not a valid domain".
        assert_eq!(
            parse_rule_checked("/").unwrap_err(),
            RuleParseError::UnterminatedRegex
        );
        assert_eq!(
            parse_rule_checked("//").unwrap_err(),
            RuleParseError::EmptyRegex
        );
        assert_eq!(
            parse_rule_checked("/x").unwrap_err(),
            RuleParseError::UnterminatedRegex
        );
        assert_eq!(
            parse_rule_checked("/unterminated").unwrap_err(),
            RuleParseError::UnterminatedRegex
        );
    }

    #[test]
    fn parse_checked_error_variants_cover_domain_paths() {
        assert_eq!(parse_rule_checked("").unwrap_err(), RuleParseError::Empty);
        assert_eq!(
            parse_rule_checked("||^").unwrap_err(),
            RuleParseError::EmptyPattern
        );
        assert_eq!(
            parse_rule_checked("||ads.*.com^").unwrap_err(),
            RuleParseError::StrayWildcard
        );
        assert!(matches!(
            parse_rule_checked("||foo..bar^"),
            Err(RuleParseError::InvalidDomain { .. })
        ));
        assert!(matches!(
            parse_rule_checked("||x.com^$dnstype=AAAA"),
            Err(RuleParseError::UnknownModifier { .. })
        ));
        assert!(matches!(
            parse_rule_checked("||x.com^$improtant"),
            Err(RuleParseError::UnknownModifier { .. })
        ));
        // Degenerate bare '$' — empty modifier segment.
        assert_eq!(
            parse_rule_checked("||x.com^$").unwrap_err(),
            RuleParseError::UnknownModifier {
                modifier: String::new()
            }
        );
        assert!(matches!(
            parse_rule_checked("/broken(/"),
            Err(RuleParseError::InvalidRegex { .. })
        ));
    }

    #[test]
    fn parse_checked_ok_matches_parse_rule_some() {
        // The Option adapter must stay a pure projection of the checked
        // parser — lint validates via parse_rule_checked, the engine
        // consumes via parse_rule/parse_rules (schema-validator-05).
        for input in [
            "||tiktok.com^",
            "@@||wikipedia.org^",
            "||malware.com^$important",
            "||*.ads.example.com^",
            "||*.cdn.example.com^$noapex",
            "/ad[0-9]+/",
            "plain.example.com",
            "",
            "/broken(/",
            "/foo/bar",
            "||x.com^$dnstype=AAAA",
            "||ads.*.com^",
        ] {
            assert_eq!(
                parse_rule_checked(input).is_ok(),
                parse_rule(input).is_some(),
                "adapter diverged for {input:?}"
            );
            assert_eq!(
                parse_rule_checked(input).is_ok(),
                !parse_rules(input).is_empty(),
                "parse_rules diverged for {input:?}"
            );
        }
    }

    #[test]
    fn parse_bad_wildcard_position() {
        // Wildcard not at start → rejected
        assert!(parse_rule("||ads.*.com^").is_none());
    }

    // --- S54: parse_rule rejects malformed admin patterns ---
    //
    // Before S54 these inputs were silently accepted as Exact rules
    // that could never match anything, hiding admin-config typos.
    // S54 routes Exact + Wildcard patterns through is_valid_domain.

    #[test]
    fn parse_rule_rejects_script_tags() {
        assert!(parse_rule("||<script>foo</script>^").is_none());
        assert!(parse_rule("@@||<script>foo</script>^").is_none());
        assert!(parse_rule("||*.<script>foo</script>^").is_none());
    }

    #[test]
    fn parse_rule_rejects_html_brackets() {
        assert!(parse_rule("||<b>foo^").is_none());
        assert!(parse_rule("||foo<bar^").is_none());
        assert!(parse_rule("||foo>bar^").is_none());
    }

    #[test]
    fn parse_rule_rejects_empty_labels() {
        assert!(parse_rule("||foo..bar^").is_none());
        assert!(parse_rule("||.foo.bar^").is_none());
        assert!(parse_rule("||*.foo..bar^").is_none());
    }

    #[test]
    fn parse_rule_rejects_leading_hyphen_label() {
        assert!(parse_rule("||-foo.bar^").is_none());
        assert!(parse_rule("||foo.-bar^").is_none());
        assert!(parse_rule("||*.- foo.bar^").is_none());
    }

    #[test]
    fn parse_rule_rejects_max_length_exceeded() {
        // is_valid_domain caps at 253 bytes (RFC 1035).
        let too_long = "a".repeat(254);
        assert!(parse_rule(&format!("||{too_long}^")).is_none());
        assert!(parse_rule(&format!("||*.{too_long}^")).is_none());
    }

    #[test]
    fn parse_no_caret() {
        // Missing ^ is fine — treated as domain
        let rule = parse_rule("||ads.com").unwrap();
        assert!(matches!(rule.pattern, RulePattern::Exact(ref d) if d == "ads.com"));
    }

    // --- DnsRule::matches ---

    #[test]
    fn exact_matches_self() {
        let rule = parse_rule("||example.com^").unwrap();
        assert!(rule.matches("example.com"));
    }

    #[test]
    fn exact_matches_subdomain() {
        let rule = parse_rule("||example.com^").unwrap();
        assert!(rule.matches("sub.example.com"));
        assert!(rule.matches("a.b.example.com"));
    }

    #[test]
    fn exact_no_partial_match() {
        let rule = parse_rule("||ample.com^").unwrap();
        assert!(!rule.matches("example.com"));
    }

    #[test]
    fn exact_parent_not_matched() {
        let rule = parse_rule("||sub.example.com^").unwrap();
        assert!(!rule.matches("example.com"));
    }

    #[test]
    fn wildcard_matches_subdomain() {
        let rule = parse_rule("||*.ads.example.com^").unwrap();
        assert!(rule.matches("banner.ads.example.com"));
        assert!(rule.matches("a.b.ads.example.com"));
    }

    #[test]
    fn wildcard_does_not_match_exact() {
        // *.ads.example.com should NOT match ads.example.com itself
        let rule = parse_rule("||*.ads.example.com^").unwrap();
        assert!(!rule.matches("ads.example.com"));
    }

    #[test]
    fn wildcard_no_partial() {
        let rule = parse_rule("||*.example.com^").unwrap();
        assert!(!rule.matches("notexample.com"));
    }

    #[test]
    fn regex_matches() {
        let rule = parse_rule("/ad[0-9]+\\.example\\.com/").unwrap();
        assert!(rule.matches("ad123.example.com"));
        assert!(!rule.matches("safe.example.com"));
    }

    // --- is_simple_exact ---

    #[test]
    fn simple_exact_true() {
        let rule = parse_rule("||example.com^").unwrap();
        assert!(rule.is_simple_exact());
    }

    #[test]
    fn simple_exact_false_for_important() {
        let rule = parse_rule("||example.com^$important").unwrap();
        assert!(!rule.is_simple_exact());
    }

    #[test]
    fn simple_exact_false_for_wildcard() {
        let rule = parse_rule("||*.example.com^").unwrap();
        assert!(!rule.is_simple_exact());
    }

    #[test]
    fn simple_exact_false_for_regex() {
        let rule = parse_rule("/example\\.com/").unwrap();
        assert!(!rule.is_simple_exact());
    }

    // --- parse_rules (wildcard apex auto-expansion) ---

    #[test]
    fn parse_rules_wildcard_auto_expands_apex() {
        let rules = parse_rules("||*.ads.example.com^");
        assert_eq!(rules.len(), 2);
        // First: the wildcard
        assert!(matches!(rules[0].pattern, RulePattern::Wildcard(ref s) if s == "ads.example.com"));
        // Second: the auto-expanded exact apex
        assert!(matches!(rules[1].pattern, RulePattern::Exact(ref d) if d == "ads.example.com"));
        assert_eq!(rules[1].action, RuleAction::Block);
    }

    #[test]
    fn parse_rules_wildcard_allow_expands_apex() {
        let rules = parse_rules("@@||*.cdn.example.com^");
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].action, RuleAction::Allow);
        assert_eq!(rules[1].action, RuleAction::Allow);
        assert!(matches!(rules[1].pattern, RulePattern::Exact(ref d) if d == "cdn.example.com"));
    }

    #[test]
    fn parse_rules_wildcard_noapex_suppresses_expansion() {
        let rules = parse_rules("||*.cdn.example.com^$noapex");
        assert_eq!(rules.len(), 1);
        assert!(matches!(rules[0].pattern, RulePattern::Wildcard(ref s) if s == "cdn.example.com"));
    }

    #[test]
    fn parse_rules_wildcard_important_noapex() {
        let rules = parse_rules("||*.evil.com^$important,noapex");
        assert_eq!(rules.len(), 1);
        assert!(rules[0].important);
        assert!(matches!(rules[0].pattern, RulePattern::Wildcard(ref s) if s == "evil.com"));
    }

    #[test]
    fn parse_rules_wildcard_important_expands_with_important() {
        let rules = parse_rules("||*.evil.com^$important");
        assert_eq!(rules.len(), 2);
        assert!(rules[0].important);
        assert!(rules[1].important);
        assert!(matches!(rules[1].pattern, RulePattern::Exact(ref d) if d == "evil.com"));
    }

    #[test]
    fn parse_rules_exact_returns_one() {
        let rules = parse_rules("||example.com^");
        assert_eq!(rules.len(), 1);
        assert!(matches!(rules[0].pattern, RulePattern::Exact(_)));
    }

    #[test]
    fn parse_rules_empty_returns_empty() {
        assert!(parse_rules("").is_empty());
        assert!(parse_rules("  ").is_empty());
    }

    #[test]
    fn is_subdomain_of_empty_parent_returns_false() {
        // L-13 (rev-2026-05-suffix-empty-guard) regression pin: an empty
        // parent must not match every dot-terminated domain. parse_rule
        // rejects empty patterns upstream, so this is contract pinning.
        assert!(!is_subdomain_of("sub.example.com", ""));
        assert!(!is_subdomain_of("a.", ""));
        assert!(!is_subdomain_of("", ""));
    }
}
