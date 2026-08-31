//! Rule evaluation with AdGuard-compatible priority ordering.
//!
//! Evaluates a `Vec<DnsRule>` against a domain in four priority tiers:
//!   1. `$important` allow → Forward (highest priority)
//!   2. `$important` deny → Block
//!   3. Normal allow → Forward
//!   4. Normal deny → Block
//!
//! Returns `None` if no rule matches (caller should fall through to
//! list bitmask or default action).

use super::engine::FilterResult;
use super::rules::{DnsRule, RuleAction};

/// Map a rule's `(important, action)` pair to its AdGuard priority tier.
///
/// 3 = `$important` allow, 2 = `$important` deny, 1 = normal allow, 0 = normal deny.
/// Consumed by [`priority_scan`], which is the single shared rule-priority
/// scanner used by [`evaluate_rules`], `engine::FilterEngine::evaluate`, and
/// `engine::FilterEngine::evaluate_attributed`.
#[must_use]
pub(crate) fn priority_of(important: bool, action: RuleAction) -> i8 {
    match (important, action) {
        (true, RuleAction::Allow) => 3,
        (true, RuleAction::Block) => 2,
        (false, RuleAction::Allow) => 1,
        (false, RuleAction::Block) => 0,
    }
}

/// Scan `rules` for the highest-priority match against `domain`.
///
/// Returns `Some((priority, &rule))` for the single rule that wins under
/// AdGuard priority ordering, or `None` if no rule matches. Short-circuits
/// at priority 3 (`$important` allow) since nothing can beat it.
///
/// This is the canonical rule-priority scanner. Three callers consume it:
///   - [`evaluate_rules`] — maps the rule's action back to a [`FilterResult`].
///   - `engine::FilterEngine::evaluate` — interleaves the result with HashSet
///     allow/deny + Tier 1 bitmask probes during the M-18 single-pass walk.
///   - `engine::FilterEngine::evaluate_attributed` — captures the matched
///     rule reference so the block path can build a `BlockSource::Rule(label)`
///     in the same pass that decides the verdict.
///
/// Returning `&DnsRule` (not `FilterResult`) is what enables the third caller
/// to attribute the source authoritatively without a second scan. Forward
/// path zero-allocation is preserved: the engine drops the rule reference
/// when it doesn't need attribution.
///
/// `#[inline(always)]` is intentional: this is the hot-path scanner
/// consumed three times per query (forward path uses it once; the
/// attributed path uses it once too, plus `evaluate_rules` for the
/// standalone path). Without forced inlining the compiler kept
/// `evaluate/allowed` ~3 % slower than the S54 inline match — even
/// `#[inline]` (a hint, not a directive) wasn't enough on the
/// `aarch64-musl` and `x86_64-debian-LXC` profiles. With
/// `#[inline(always)]` the call disappears at LTO-release and the
/// forward path lands within the ±2 % budget.
#[inline(always)]
#[must_use]
pub(crate) fn priority_scan<'a>(rules: &'a [DnsRule], domain: &str) -> Option<(i8, &'a DnsRule)> {
    if rules.is_empty() {
        return None;
    }
    let mut best: Option<(i8, &DnsRule)> = None;
    for rule in rules {
        let priority = priority_of(rule.important, rule.action);
        if let Some((p, _)) = best {
            if priority <= p {
                continue;
            }
        }
        if rule.matches(domain) {
            best = Some((priority, rule));
            // `$important` allow (priority 3) is the highest possible tier —
            // nothing later in the rules slice can beat it.
            if priority == 3 {
                return best;
            }
        }
    }
    best
}

/// Evaluate advanced rules against a domain.
///
/// Thin shim over [`priority_scan`]: maps the matched rule's action back to a
/// [`FilterResult`]. Returns `None` if no rule matches (caller falls through
/// to the list bitmask or default action).
///
/// Handles only rules in the `rules` Vec — simple exact domain rules in the
/// profile's HashSets are checked separately by
/// [`super::engine::FilterEngine::evaluate`] for O(1) performance.
pub fn evaluate_rules(domain: &str, rules: &[DnsRule]) -> Option<FilterResult> {
    priority_scan(rules, domain).map(|(_, rule)| match rule.action {
        RuleAction::Allow => FilterResult::Forward,
        RuleAction::Block => FilterResult::Block,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filter::rules::parse_rule;

    fn rules(specs: &[&str]) -> Vec<DnsRule> {
        specs.iter().filter_map(|s| parse_rule(s)).collect()
    }

    #[test]
    fn empty_rules_returns_none() {
        assert!(evaluate_rules("example.com", &[]).is_none());
    }

    #[test]
    fn normal_block_matches() {
        let r = rules(&["||ads.com^"]);
        assert_eq!(evaluate_rules("ads.com", &r), Some(FilterResult::Block));
    }

    #[test]
    fn normal_allow_matches() {
        let r = rules(&["@@||safe.com^"]);
        assert_eq!(evaluate_rules("safe.com", &r), Some(FilterResult::Forward));
    }

    #[test]
    fn no_match_returns_none() {
        let r = rules(&["||ads.com^"]);
        assert!(evaluate_rules("google.com", &r).is_none());
    }

    #[test]
    fn normal_allow_beats_normal_deny() {
        let r = rules(&["||example.com^", "@@||example.com^"]);
        assert_eq!(
            evaluate_rules("example.com", &r),
            Some(FilterResult::Forward)
        );
    }

    #[test]
    fn important_deny_beats_normal_allow() {
        let r = rules(&["@@||evil.com^", "||evil.com^$important"]);
        assert_eq!(evaluate_rules("evil.com", &r), Some(FilterResult::Block));
    }

    #[test]
    fn important_allow_beats_important_deny() {
        let r = rules(&[
            "||captive.apple.com^$important",
            "@@||captive.apple.com^$important",
        ]);
        assert_eq!(
            evaluate_rules("captive.apple.com", &r),
            Some(FilterResult::Forward)
        );
    }

    #[test]
    fn important_allow_beats_everything() {
        // important allow should override normal deny, important deny, etc.
        let r = rules(&[
            "||example.com^",
            "||example.com^$important",
            "@@||example.com^$important",
        ]);
        assert_eq!(
            evaluate_rules("example.com", &r),
            Some(FilterResult::Forward)
        );
    }

    #[test]
    fn wildcard_rule_evaluated() {
        let r = rules(&["||*.ads.example.com^"]);
        assert_eq!(
            evaluate_rules("banner.ads.example.com", &r),
            Some(FilterResult::Block)
        );
        assert!(evaluate_rules("ads.example.com", &r).is_none());
    }

    #[test]
    fn regex_rule_evaluated() {
        let r = rules(&["/ad[0-9]+\\.example\\.com/"]);
        assert_eq!(
            evaluate_rules("ad123.example.com", &r),
            Some(FilterResult::Block)
        );
        assert!(evaluate_rules("safe.example.com", &r).is_none());
    }

    #[test]
    fn subdomain_match() {
        let r = rules(&["||tracker.com^"]);
        assert_eq!(
            evaluate_rules("sub.tracker.com", &r),
            Some(FilterResult::Block)
        );
    }

    #[test]
    fn mixed_rules_priority() {
        // Normal allow on parent, important deny on specific subdomain
        let r = rules(&["@@||example.com^", "||malicious.example.com^$important"]);
        // malicious.example.com → important deny wins over normal allow
        assert_eq!(
            evaluate_rules("malicious.example.com", &r),
            Some(FilterResult::Block)
        );
        // safe.example.com → normal allow
        assert_eq!(
            evaluate_rules("safe.example.com", &r),
            Some(FilterResult::Forward)
        );
    }
}
