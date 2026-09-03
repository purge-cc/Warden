//! Anti-bypass: block resolution of the DoH/DoT resolver domains **the
//! operator listed**.
//!
//! A device that can resolve a public encrypted-DNS endpoint can point its
//! browser or OS at it and skip the filter entirely. Blocking those names
//! forces traffic back through purge-warden.
//!
//! **Warden ships no such names.** This module used to
//! compile in 41 hostnames belonging to 13 named providers — on by
//! default, add-only, checked ahead of the filter engine, and absent from
//! the config `warden init` writes, so a fresh install blocked 41 names
//! the operator could neither see nor override. That is warden holding an
//! opinion about named companies, which CLAUDE.md §Neutrality forbids in
//! both directions. The domains now come from exactly two operator-owned
//! places: `anti_bypass.extra_domains` in their config, and a published
//! list they choose to import (which, going through the filter engine,
//! their own allow rules can override).
//!
//! Note: DNS-level blocking alone isn't sufficient — clients can hardcode
//! IPs. `warden firewall-rules` generates the matching packet-filter rules.

use ahash::AHashSet;
use compact_str::CompactString;

use crate::config::settings::AntiBypassConfig;

/// Anti-bypass checker. Maintains a HashSet of blocked resolver domains.
pub struct AntiBypass {
    domains: AHashSet<CompactString>,
}

impl AntiBypass {
    pub fn new(config: &AntiBypassConfig) -> Self {
        // The set starts EMPTY. Every entry is operator-authored — there
        // is no compiled-in seed to add to.
        let mut domains = AHashSet::with_capacity(config.extra_domains.len());

        // Mirror the lookup-side normalization at ingestion.
        // `is_bypass_domain` strips the query's trailing dot
        // before matching, so an FQDN-habit entry like
        // "mydns.example.com." could never match anything — silently, as
        // no validator covers the field. Trim whitespace, strip one
        // trailing dot, lowercase; warn-and-skip entries that normalize
        // to empty instead of inserting a useless "" key.
        for d in &config.extra_domains {
            let trimmed = d.trim();
            let stripped = trimmed.strip_suffix('.').unwrap_or(trimmed);
            if stripped.is_empty() {
                tracing::warn!(
                    entry = %d,
                    "anti_bypass.extra_domains: entry is empty after normalization, skipping"
                );
                continue;
            }
            domains.insert(CompactString::new(stripped.to_ascii_lowercase()));
        }

        Self { domains }
    }

    /// Check if a domain is a known public DNS resolver.
    /// Performs exact match and subdomain walk (e.g. "foo.doh.example.net"
    /// matches a listed "doh.example.net").
    ///
    /// Defensive normalization: the set is keyed on lowercase, dot-stripped
    /// names. The sole production caller already passes hickory's
    /// lowercased, dot-stripped `LowerName`, but this is a filter-bypass
    /// primitive — a future caller that forgets to normalize must not be
    /// able to slip `DOH.Example.Net` or `doh.example.net.` past the block. The
    /// common case (already normal) is allocation-free: trailing-dot strip
    /// is a slice and lowercasing only runs when an uppercase byte exists.
    pub fn is_bypass_domain(&self, domain: &str) -> bool {
        let stripped = domain.strip_suffix('.').unwrap_or(domain);
        if stripped.bytes().any(|b| b.is_ascii_uppercase()) {
            return self.matches(&stripped.to_ascii_lowercase());
        }
        self.matches(stripped)
    }

    /// Exact-match + subdomain-walk against the (lowercase, dot-stripped)
    /// resolver set. Caller guarantees `domain` is already normalized.
    fn matches(&self, domain: &str) -> bool {
        // Exact match
        if self.domains.contains(domain) {
            return true;
        }

        // Subdomain walk: "foo.doh.example.net" matches "doh.example.net"
        let bytes = domain.as_bytes();
        for (i, &b) in bytes.iter().enumerate() {
            if b == b'.' {
                let parent = &domain[i + 1..];
                if self.domains.contains(parent) {
                    return true;
                }
            }
        }

        false
    }

    /// True when no domain is configured, i.e. this checker can never
    /// match.
    ///
    /// With no compiled-in list, the default install reaches here with
    /// an empty set. The caller uses this to skip
    /// building the checker at all, so the hot path does not pay for a
    /// subdomain walk that cannot succeed.
    pub fn is_empty(&self) -> bool {
        self.domains.is_empty()
    }

    /// Number of domains in the blocklist.
    #[cfg(test)]
    pub fn domain_count(&self) -> usize {
        self.domains.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_config() -> AntiBypassConfig {
        AntiBypassConfig {
            enabled: true,
            extra_domains: Vec::new(),
        }
    }

    /// The mechanism tests below (subdomain walk, case folding,
    /// trailing-dot stripping, no-partial-match) used to lean on a
    /// compiled-in provider list as their fixture. The behaviour they
    /// cover is still worth pinning — only the fixture had to move to
    /// operator-authored config, which is now the only source of domains.
    fn operator_config(domains: &[&str]) -> AntiBypassConfig {
        AntiBypassConfig {
            enabled: true,
            extra_domains: domains.iter().map(|s| (*s).to_string()).collect(),
        }
    }

    /// Warden ships **no** provider domain knowledge.
    ///
    /// The built-in list used to carry 41 DoH/DoT hostnames belonging to
    /// 13 named providers. It was on by default, could only be added to
    /// (`AntiBypassConfig` has no removal field), ran ahead of the filter
    /// engine so operator allow rules never got a say, and `warden init`
    /// never wrote the `[anti_bypass]` section — so a fresh install
    /// blocked 41 names the operator could not see. See CLAUDE.md
    /// §Neutrality. The replacement is a published list the operator
    /// imports and can drop.
    #[test]
    fn neutrality01_no_built_in_provider_domains() {
        let ab = AntiBypass::new(&default_config());
        assert_eq!(
            ab.domain_count(),
            0,
            "a default install must carry zero provider domains in the binary"
        );
        for probe in [
            "dns.google",
            "cloudflare-dns.com",
            "dns.quad9.net",
            "dns.adguard.com",
            "one.one.one.one",
        ] {
            assert!(
                !ab.is_bypass_domain(probe),
                "{probe} must not be blocked by anything compiled in"
            );
        }
    }

    /// Mechanism: a listed name also covers everything beneath it.
    #[test]
    fn blocks_subdomain_of_listed_domain() {
        let ab = AntiBypass::new(&operator_config(&["doh.example.net"]));
        assert!(ab.is_bypass_domain("doh.example.net"));
        assert!(ab.is_bypass_domain("foo.doh.example.net"));
        assert!(ab.is_bypass_domain("bar.baz.doh.example.net"));
    }

    #[test]
    fn allows_normal_domains() {
        let ab = AntiBypass::new(&default_config());
        assert!(!ab.is_bypass_domain("google.com"));
        assert!(!ab.is_bypass_domain("cloudflare.com"));
        assert!(!ab.is_bypass_domain("example.com"));
    }

    #[test]
    fn extra_domains_added() {
        let config = AntiBypassConfig {
            enabled: true,
            extra_domains: vec!["custom-dns.example.com".into()],
        };
        let ab = AntiBypass::new(&config);
        assert!(ab.is_bypass_domain("custom-dns.example.com"));
    }

    #[test]
    fn extra_domains_case_normalized() {
        let config = AntiBypassConfig {
            enabled: true,
            extra_domains: vec!["CUSTOM-DNS.Example.COM".into()],
        };
        let ab = AntiBypass::new(&config);
        assert!(ab.is_bypass_domain("custom-dns.example.com"));
    }

    /// Regression: FQDN-style entries (trailing root dot) and padded
    /// entries were inserted verbatim while the lookup side strips the
    /// dot from the query — such entries could never match. Ingestion
    /// now mirrors the lookup normalization.
    #[test]
    fn extra_domains_trailing_dot_and_whitespace_normalized() {
        let config = AntiBypassConfig {
            enabled: true,
            extra_domains: vec![
                "mydns.example.com.".into(),
                "  spaced.example.com  ".into(),
                "MiXeD.Example.ORG.".into(),
            ],
        };
        let ab = AntiBypass::new(&config);
        assert!(ab.is_bypass_domain("mydns.example.com"));
        assert!(ab.is_bypass_domain("spaced.example.com"));
        assert!(ab.is_bypass_domain("mixed.example.org"));
        // And via the FQDN query form too.
        assert!(ab.is_bypass_domain("mydns.example.com."));
    }

    /// Entries that normalize to nothing are skipped, not inserted as "".
    #[test]
    fn extra_domains_empty_after_normalization_skipped() {
        let config = AntiBypassConfig {
            enabled: true,
            extra_domains: vec![".".into(), "   ".into()],
        };
        let ab = AntiBypass::new(&config);
        // Nothing is compiled in, so an all-invalid `extra_domains`
        // leaves the set empty.
        assert_eq!(ab.domain_count(), 0);
    }

    #[test]
    fn bypass_domain_mixed_case_normalized() {
        // A mixed-case input must not slip the filter even though the
        // set is lowercase-keyed.
        let ab = AntiBypass::new(&operator_config(&["doh.example.net"]));
        assert!(ab.is_bypass_domain("DOH.Example.Net"));
        assert!(ab.is_bypass_domain("FOO.DOH.EXAMPLE.NET"));
    }

    #[test]
    fn bypass_domain_trailing_dot_stripped() {
        // A FQDN trailing root dot must be stripped before matching.
        let ab = AntiBypass::new(&operator_config(&["doh.example.net"]));
        assert!(ab.is_bypass_domain("doh.example.net."));
        assert!(ab.is_bypass_domain("foo.doh.example.net."));
        assert!(ab.is_bypass_domain("DOH.Example.Net."));
    }

    #[test]
    fn allows_similar_but_not_matching() {
        let ab = AntiBypass::new(&operator_config(&["doh.example.net"]));
        // the parent label alone is not the listed name
        assert!(!ab.is_bypass_domain("example.net"));
        // a label that merely ENDS with the listed label must not match:
        // "notdoh.example.net" is not a subdomain of "doh.example.net"
        assert!(!ab.is_bypass_domain("notdoh.example.net"));
    }
}
