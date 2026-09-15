use compact_str::CompactString;
use sha2::{Digest, Sha256};

use super::{BudgetExceeded, RuleCompileLimits, RuleTier};
use crate::common::domain::is_valid_domain;
use crate::filter::rules::RuleParseError;

/// Semantic digest, independent of list membership and source spelling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RuleKey(pub [u8; 32]);

/// Uncompiled pattern. Regex source case and inline flags remain intact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OperatorPattern {
    Exact(CompactString),
    Wildcard(CompactString),
    Regex {
        source: CompactString,
        case_insensitive: bool,
    },
}

/// Normalized, single-record rule. Only the parser constructs this type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperatorRuleAst {
    pattern: OperatorPattern,
    tier: RuleTier,
    noapex: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AstError {
    #[error("rule text must contain exactly one record without record separators or NUL")]
    MultipleRecords,
    #[error(transparent)]
    Grammar(#[from] RuleParseError),
    #[error(transparent)]
    Budget(#[from] BudgetExceeded),
}

impl OperatorRuleAst {
    pub fn pattern(&self) -> &OperatorPattern {
        &self.pattern
    }
    pub fn tier(&self) -> RuleTier {
        self.tier
    }
    pub fn noapex(&self) -> bool {
        self.noapex
    }

    /// SHA-256 of the separator plus NUL and six u64-big-endian-length-prefixed
    /// fields: action (deny=0/allow=1), class (exact=0/wildcard=1/regex=2),
    /// UTF-8 pattern, case-insensitive flag, important flag, effective noapex.
    pub fn rule_key(&self) -> RuleKey {
        let mut hash = Sha256::new();
        hash.update(b"warden/uor/rule-ast/v1\0");
        let (class, flags) = match self.pattern {
            OperatorPattern::Exact(_) => (0, 0),
            OperatorPattern::Wildcard(_) => (1, 0),
            OperatorPattern::Regex {
                case_insensitive, ..
            } => (2, u8::from(case_insensitive)),
        };
        for field in [
            &[u8::from(self.tier.is_allow())][..],
            &[class][..],
            self.text().as_bytes(),
            &[flags][..],
            &[u8::from(self.tier.is_important())][..],
            &[u8::from(self.noapex)][..],
        ] {
            hash.update((field.len() as u64).to_be_bytes());
            hash.update(field);
        }
        RuleKey(hash.finalize().into())
    }

    pub(crate) fn text(&self) -> &str {
        match &self.pattern {
            OperatorPattern::Exact(s) | OperatorPattern::Wildcard(s) => s,
            OperatorPattern::Regex { source, .. } => source,
        }
    }

    pub(crate) fn indexed_domain(&self) -> Option<&CompactString> {
        match &self.pattern {
            OperatorPattern::Exact(s) => Some(s),
            OperatorPattern::Wildcard(s) if !self.noapex => Some(s),
            _ => None,
        }
    }
}

pub(crate) fn check_record(line: &str) -> Result<(), AstError> {
    if line.chars().any(|c| {
        matches!(
            c,
            '\0' | '\r' | '\n' | '\u{b}' | '\u{c}' | '\u{85}' | '\u{2028}' | '\u{2029}' | '\u{1c}'
                ..='\u{1e}'
        )
    }) {
        return Err(AstError::MultipleRecords);
    }
    Ok(())
}

/// Parse the admin grammar without compiling regex programs. Invalid regex
/// syntax is reported during strict candidate compilation, after preflight.
/// The binary's row ceiling applies even outside a candidate compilation.
pub fn parse_rule_ast(line: &str) -> Result<OperatorRuleAst, AstError> {
    check_record(line)?;
    super::limits::ensure(
        "max_rule_bytes",
        line.len(),
        RuleCompileLimits::HARD_CEILINGS.max_rule_bytes,
    )?;
    let mut s = line.trim();
    if s.is_empty() {
        return Err(RuleParseError::Empty.into());
    }
    let allow = s.starts_with("@@");
    if allow {
        s = &s[2..];
    }
    if let Some(rest) = s.strip_prefix('/') {
        let end = rest.find('/').ok_or(RuleParseError::UnterminatedRegex)?;
        let source = &rest[..end];
        if source.is_empty() {
            return Err(RuleParseError::EmptyRegex.into());
        }
        let trailing = &rest[end + 1..];
        if !trailing.is_empty() {
            return Err(RuleParseError::TrailingAfterRegex {
                trailing: trailing.into(),
            }
            .into());
        }
        return Ok(OperatorRuleAst {
            pattern: OperatorPattern::Regex {
                source: source.into(),
                case_insensitive: true,
            },
            tier: RuleTier::from_flags(allow, false),
            noapex: false,
        });
    }
    s = s.strip_prefix("||").unwrap_or(s);
    let mut important = false;
    let mut noapex = false;
    if let Some(dollar) = s.find('$') {
        for modifier in s[dollar + 1..].split(',') {
            match modifier.trim() {
                "important" => important = true,
                "noapex" => noapex = true,
                other => {
                    return Err(RuleParseError::UnknownModifier {
                        modifier: other.into(),
                    }
                    .into())
                }
            }
        }
        s = &s[..dollar];
    }
    s = s.strip_suffix('^').unwrap_or(s);
    if s.is_empty() {
        return Err(RuleParseError::EmptyPattern.into());
    }
    let wildcard = s.starts_with("*.");
    if wildcard {
        s = &s[2..];
    }
    if !wildcard && s.contains('*') {
        return Err(RuleParseError::StrayWildcard.into());
    }
    if !is_valid_domain(s) {
        return Err(RuleParseError::InvalidDomain { input: s.into() }.into());
    }
    let mut domain = CompactString::new(s);
    domain.make_ascii_lowercase();
    Ok(OperatorRuleAst {
        pattern: if wildcard {
            OperatorPattern::Wildcard(domain)
        } else {
            OperatorPattern::Exact(domain)
        },
        tier: RuleTier::from_flags(allow, important),
        noapex: wildcard && noapex,
    })
}
