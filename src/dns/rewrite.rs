//! Per-profile domain rewrite engine.
//!
//! Rewrites a queried qname before resolution. Useful for domain migrations
//! (`api.old.com → api.new.com`) and "fake CNAME" without committing a
//! `[[local_dns.records]]` row.
//!
//! Built once at resolver-map construction time from the profile's
//! `rewrite_rules` slice (already validated by
//! [`crate::config::validator::validate_rewrite_rules`]). Lives behind the
//! existing `ArcSwap<ResolverMap>` (zero-alloc, zero-lock hot path).
//!
//! ## Hot-path semantics
//!
//! [`ProfileRewriteRules::apply`] is **single-pass**: the rewritten output is
//! never re-fed into the table. This is the runtime depth=1 guard —
//! belt-and-braces for the validator's config-time cycle detection. Even if
//! the validator misses a cycle (unlikely; it runs three-colour DFS), the
//! runtime cannot loop.
//!
//! ## Match precedence
//!
//! 1. Exact-match probe on `forward` (O(1) HashMap).
//! 2. If `has_subdomain_rules == false`, return `None` (fast-path skip).
//! 3. Otherwise walk `q` label-by-label, scanning `suffix_rules` (sorted
//!    depth-desc) for the longest matching suffix. On hit, strip the matched
//!    suffix and append the replacement.
//!
//! Wildcard semantics: `*.old.com → *.new.com` with `match_subdomains: true`
//! and `from = "old.com"`, `to = "new.com"` rewrites `api.old.com → api.new.com`
//! and `x.y.old.com → x.y.new.com`. The leading label prefix is preserved.

use std::collections::HashMap;

use compact_str::CompactString;

use crate::config::settings::RewriteRule;

/// Per-profile rewrite table.
///
/// `forward` carries exact-match rules keyed on the lowercased `from`.
/// `suffix_rules` carries `match_subdomains: true` rules, **sorted by label
/// depth descending** so a linear scan returns the longest matching suffix
/// first. The cap mirrors [`crate::dns::local_profile::ProfileLocalRecords`]'s
/// posture — small-N home-lab scale; replaceable with a label-indexed map
/// without touching [`Self::apply`]'s surface.
///
/// `has_subdomain_rules` is the fast-path bool. When `false`, [`Self::apply`]
/// short-circuits the suffix walk completely — profiles without rewrites pay
/// one `HashMap::get` per query and are otherwise unaffected.
#[derive(Debug, Default, Clone)]
pub struct ProfileRewriteRules {
    forward: HashMap<CompactString, CompactString, ahash::RandomState>,
    suffix_rules: Vec<(CompactString, CompactString)>,
    has_subdomain_rules: bool,
}

impl ProfileRewriteRules {
    /// Build from a validated slice of [`RewriteRule`]s.
    ///
    /// **Caller contract:** the slice MUST have been through
    /// [`crate::config::validator::validate_rewrite_rules`]. Malformed FQDNs,
    /// reserved-TLD references, identity rules, and duplicates are caught
    /// earlier; this builder silently drops any rule with empty `from` or
    /// empty `to` (defensive against drift).
    pub fn build(rules: &[RewriteRule]) -> Self {
        let mut forward: HashMap<CompactString, CompactString, ahash::RandomState> =
            HashMap::with_hasher(ahash::RandomState::new());
        let mut suffix_rules: Vec<(CompactString, CompactString)> = Vec::new();

        // Shared canonical spelling: the validator's duplicate/identity/
        // shadow checks and this table must key on the same string, and
        // the key must match the handler's lowercase dot-less query
        // domain ("Ads.Example.Com." in TOML must fire on a query for
        // ads.example.com).
        let canonical: Vec<(CompactString, CompactString, bool)> = rules
            .iter()
            .filter_map(|rule| {
                let from = crate::config::validator::canonicalize_domain(&rule.from);
                let to = crate::config::validator::canonicalize_domain(&rule.to);
                if from.is_empty() || to.is_empty() {
                    return None;
                }
                Some((
                    CompactString::new(&from),
                    CompactString::new(&to),
                    rule.match_subdomains,
                ))
            })
            .collect();

        // Two-pass insert: exact rules claim apexes first; a subdomain
        // rule's apex shortcut only fills vacant slots. An exact +
        // wildcard pair for the same apex is therefore deterministic —
        // exact wins the apex, descendants route through the wildcard —
        // regardless of TOML order (previously first-write-wins on
        // insertion order). Mirrors `ProfileLocalRecords`'s "exact-match
        // wins, apex includes self" semantics.
        for (from, to, match_subdomains) in &canonical {
            if !match_subdomains {
                forward.entry(from.clone()).or_insert_with(|| to.clone());
            }
        }
        for (from, to, match_subdomains) in &canonical {
            if *match_subdomains {
                // Subdomain rule also matches the apex itself — register
                // both in forward (for the O(1) apex shortcut) AND in
                // suffix_rules (for descendants).
                forward.entry(from.clone()).or_insert_with(|| to.clone());
                suffix_rules.push((from.clone(), to.clone()));
            }
        }

        suffix_rules.sort_by_key(|b| std::cmp::Reverse(label_count(b.0.as_str())));
        let has_subdomain_rules = !suffix_rules.is_empty();

        Self {
            forward,
            suffix_rules,
            has_subdomain_rules,
        }
    }

    /// Returns `Some(rewritten_domain)` on hit, `None` otherwise.
    ///
    /// Single-pass: the returned domain is NOT re-fed into the table.
    /// The caller continues resolution against the rewritten name.
    ///
    /// Case-insensitive: `domain` is expected lowercased by the handler
    /// (LowerName upstream), but builder canonicalises so a caller that
    /// forgets still gets the correct hit on `forward`. Suffix matching
    /// assumes lowercased input.
    pub fn apply(&self, domain: &str) -> Option<CompactString> {
        // 1. Exact-match probe.
        if let Some(target) = self.forward.get(domain) {
            return Some(target.clone());
        }

        // 2. Fast-path bypass when the profile has no subdomain rules.
        if !self.has_subdomain_rules {
            return None;
        }

        // 3. Suffix walk: strip one leftmost label at a time, probe each
        //    intermediate suffix against suffix_rules (sorted depth-desc).
        //    On match: the descendant's label prefix is preserved on `to`.
        //    Example: `api.x.old.com`, rule `old.com → new.com`,
        //    match_subdomains: prefix = "api.x", new domain = "api.x.new.com".
        let mut current = domain;
        while let Some((_label, rest)) = current.split_once('.') {
            current = rest;
            if current.is_empty() {
                break;
            }
            if let Some(target) = self.suffix_lookup(current) {
                let prefix_len = domain.len() - current.len();
                // prefix_len always includes the trailing '.' separator
                // (rest = current; original was prefix + '.' + current).
                let prefix = &domain[..prefix_len];
                let mut out = CompactString::default();
                out.push_str(prefix);
                out.push_str(target.as_str());
                return Some(out);
            }
            // Stop at the TLD label — the validator prevents subdomain
            // rules on public suffixes anyway, but the lookup is
            // defensive.
            if !current.contains('.') {
                break;
            }
        }

        None
    }

    /// True iff the profile owns at least one rewrite rule.
    pub fn is_empty(&self) -> bool {
        self.forward.is_empty()
    }

    /// Total exact-match rule count. Test hook.
    #[cfg(test)]
    pub fn forward_count(&self) -> usize {
        self.forward.len()
    }

    /// Subdomain-rule count. Test hook.
    #[cfg(test)]
    pub fn suffix_count(&self) -> usize {
        self.suffix_rules.len()
    }

    /// Test hook: fast-path bit.
    #[cfg(test)]
    pub fn has_subdomain_rules(&self) -> bool {
        self.has_subdomain_rules
    }

    fn suffix_lookup(&self, suffix: &str) -> Option<&CompactString> {
        for (key, target) in &self.suffix_rules {
            if key.as_str() == suffix {
                return Some(target);
            }
        }
        None
    }
}

/// Label count helper. Mirrors the one in `local_profile.rs` — duplicated
/// rather than imported to keep this module self-contained.
fn label_count(domain: &str) -> usize {
    if domain.is_empty() {
        return 0;
    }
    domain.bytes().filter(|&b| b == b'.').count() + 1
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(from: &str, to: &str) -> RewriteRule {
        RewriteRule {
            from: from.into(),
            to: to.into(),
            match_subdomains: false,
        }
    }

    fn rule_sub(from: &str, to: &str) -> RewriteRule {
        let mut r = rule(from, to);
        r.match_subdomains = true;
        r
    }

    #[test]
    fn s412_empty_rules_yields_empty_table() {
        let t = ProfileRewriteRules::build(&[]);
        assert!(t.is_empty());
        assert_eq!(t.forward_count(), 0);
        assert_eq!(t.suffix_count(), 0);
        assert!(!t.has_subdomain_rules());
        assert!(t.apply("anything.example").is_none());
    }

    #[test]
    fn s412_exact_match_rewrites_to_target() {
        let rules = vec![rule("api.old-corp.example-int", "api.new-corp.example-int")];
        let t = ProfileRewriteRules::build(&rules);
        let r = t.apply("api.old-corp.example-int").unwrap();
        assert_eq!(r.as_str(), "api.new-corp.example-int");
    }

    #[test]
    fn s412_exact_no_match_returns_none() {
        let rules = vec![rule("api.old-corp.example-int", "api.new-corp.example-int")];
        let t = ProfileRewriteRules::build(&rules);
        assert!(t.apply("unrelated.example-int").is_none());
    }

    #[test]
    fn s412_subdomain_rule_rewrites_descendant_preserving_prefix() {
        // Rule: `old-corp.example-int → new-corp.example-int` with
        // match_subdomains. Query `api.v2.old-corp.example-int` → must
        // become `api.v2.new-corp.example-int` (prefix `api.v2.` preserved).
        let rules = vec![rule_sub("old-corp.example-int", "new-corp.example-int")];
        let t = ProfileRewriteRules::build(&rules);
        let r = t.apply("api.v2.old-corp.example-int").unwrap();
        assert_eq!(r.as_str(), "api.v2.new-corp.example-int");
    }

    #[test]
    fn s412_subdomain_rule_apex_match_via_forward() {
        // Subdomain rules also land in `forward` for the apex shortcut.
        // Querying `old-corp.example-int` exactly hits the O(1) path.
        let rules = vec![rule_sub("old-corp.example-int", "new-corp.example-int")];
        let t = ProfileRewriteRules::build(&rules);
        let r = t.apply("old-corp.example-int").unwrap();
        assert_eq!(r.as_str(), "new-corp.example-int");
    }

    #[test]
    fn s412_single_pass_no_chaining() {
        // A → B, B → C in the table. Query A must return B, NOT C.
        // The runtime depth=1 guard is built into apply()'s single probe.
        let rules = vec![
            rule("a.example-int", "b.example-int"),
            rule("b.example-int", "c.example-int"),
        ];
        let t = ProfileRewriteRules::build(&rules);
        let r = t.apply("a.example-int").unwrap();
        assert_eq!(
            r.as_str(),
            "b.example-int",
            "single-pass: A must NOT chain through to C"
        );
        // Direct query for B still hits B's rule independently:
        let r2 = t.apply("b.example-int").unwrap();
        assert_eq!(r2.as_str(), "c.example-int");
    }

    #[test]
    fn s412_longest_suffix_wins() {
        // Two subdomain rules: one shallow, one deep. Query a domain
        // descending from the deep one — must match the deep one (longer
        // suffix wins).
        let rules = vec![
            rule_sub("example-int", "fallback.example-int"),
            rule_sub("svc.example-int", "primary.example-int"),
        ];
        let t = ProfileRewriteRules::build(&rules);
        let r = t.apply("api.svc.example-int").unwrap();
        assert_eq!(r.as_str(), "api.primary.example-int");
    }

    #[test]
    fn s412_fast_path_bypass_no_subdomain_rules() {
        let rules = vec![rule("a.example-int", "b.example-int")];
        let t = ProfileRewriteRules::build(&rules);
        assert!(!t.has_subdomain_rules());
        // Lookup of a domain that DOESN'T match exact rule but WOULD
        // match a hypothetical subdomain rule → must miss without walking.
        assert!(t.apply("descendant.a.example-int").is_none());
    }

    #[test]
    fn s412_exact_only_does_not_match_descendant() {
        let rules = vec![rule("a.example-int", "b.example-int")];
        let t = ProfileRewriteRules::build(&rules);
        // descendant of "a.example-int" does NOT inherit the rule when
        // match_subdomains=false.
        assert!(t.apply("foo.a.example-int").is_none());
    }

    #[test]
    fn s412_case_insensitive_lookup_via_builder() {
        // Builder lowercases stored keys. Caller-side normalisation is
        // expected (LowerName), but the builder is defensive.
        let rules = vec![rule("API.Old.Example-Int", "api.new.example-int")];
        let t = ProfileRewriteRules::build(&rules);
        let r = t.apply("api.old.example-int").unwrap();
        assert_eq!(r.as_str(), "api.new.example-int");
    }

    #[test]
    fn s412_subdomain_rule_does_not_match_unrelated_domain() {
        let rules = vec![rule_sub("old-corp.example-int", "new-corp.example-int")];
        let t = ProfileRewriteRules::build(&rules);
        assert!(t.apply("google.com").is_none());
        // Trailing-substring trap: a domain whose tail is a substring
        // of `from` but does NOT cleanly suffix-match must miss.
        assert!(t.apply("evilold-corp.example-int").is_none());
    }

    #[test]
    fn s412_apex_exact_wins_over_apex_subdomain_when_both_present() {
        // Same `from`, one exact, one subdomain. The exact-rule entry
        // wins for the apex (two-pass build — order-independent).
        let rules = vec![
            rule("foo.example-int", "exact-target.example-int"),
            rule_sub("foo.example-int", "wild-target.example-int"),
        ];
        let t = ProfileRewriteRules::build(&rules);
        let r = t.apply("foo.example-int").unwrap();
        assert_eq!(r.as_str(), "exact-target.example-int");
        // Descendant still routes through the subdomain rule.
        let r2 = t.apply("api.foo.example-int").unwrap();
        assert_eq!(r2.as_str(), "api.wild-target.example-int");
    }

    #[test]
    fn rev2606_apex_exact_wins_even_when_wildcard_listed_first() {
        // Before the two-pass build, the apex winner was TOML insertion
        // order (or_insert first-write-wins) — wildcard-first configs
        // served the wildcard target on the apex. Two-pass build makes
        // the exact rule win regardless of order.
        let rules = vec![
            rule_sub("foo.example-int", "wild-target.example-int"),
            rule("foo.example-int", "exact-target.example-int"),
        ];
        let t = ProfileRewriteRules::build(&rules);
        assert_eq!(
            t.apply("foo.example-int").unwrap().as_str(),
            "exact-target.example-int",
            "exact must beat wildcard for the apex regardless of TOML order"
        );
        // Descendants unaffected — still the wildcard's.
        assert_eq!(
            t.apply("api.foo.example-int").unwrap().as_str(),
            "api.wild-target.example-int"
        );
    }

    #[test]
    fn s412_empty_from_or_to_silently_dropped() {
        // Validator catches these; build() defensive on drift.
        let rules = vec![
            RewriteRule {
                from: String::new(),
                to: "ok.example-int".into(),
                match_subdomains: false,
            },
            RewriteRule {
                from: "ok.example-int".into(),
                to: String::new(),
                match_subdomains: false,
            },
        ];
        let t = ProfileRewriteRules::build(&rules);
        assert!(t.is_empty());
    }
}
