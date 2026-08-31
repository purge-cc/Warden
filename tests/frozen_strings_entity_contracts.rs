//! rev-2606 `rev2606-validator-entity-contracts`: cross-file byte-pins for
//! the operator-facing strings this fix sprint introduces. Same pattern as
//! `tests/frozen_strings_lc2_engine.rs` — a silent rename that the inline
//! tests miss surfaces here at code review (RR3 frozen-strings).
//!
//! Pinned surfaces:
//! 1. `RuleParseError` Display strings (schema-validator-05 / rules-02 /
//!    rules-03) — embedded verbatim in `ValidationFailed` lint errors.
//! 2. `RuleParseError::suggestion()` next-step strings.
//! # What left in `plp-s5f`
//!
//! The zero-intersection tag WARN templates (schema-validator-07) were
//! pinned here: `DEVICE_TAGS_MATCH_NO_LIST`, `PROFILE_TAGS_MATCH_NO_LIST`,
//! `BLOCKLIST_TAGS_MATCH_NOTHING` and `TAG_MATCHES_NO_ENABLED_DENY_LIST`.
//! All four asked whether an entity's tags intersected an enabled deny list.
//! `plp-s3` cut tags out of the filtering decision and `plp-s5a` removed the
//! field, so the question stopped being answerable and the four consts had
//! no emit path left. They are gone, and so are their pins.
//!
//! `ALLOW_LIST_REQUIRES_TAG`'s pin left too, but **the const did not**, and
//! the asymmetry is deliberate. `allow_direction_gates` has returned
//! `needs_tag: false` since the plp cutover, so the refusal is unreachable —
//! but it is kept in `blocklists.rs` as record, because what a security gate
//! *bought* is the argument a future reader needs before restoring it. What
//! could not stay is the byte-pin: a cross-file frozen contract on a string
//! the product cannot produce is green by construction and reads as proof
//! the refusal still fires.

use purge_warden::config::schema::validator::{
    format_blocklist_duplicate_url, ANTI_BYPASS_ENABLED_NO_DOMAINS, BLOCKLIST_DUPLICATE_URL,
    SAFE_SEARCH_FLAG_SELECTS_NOTHING, SECURITY_DISABLED_DROPS_ANTI_BYPASS,
};
use purge_warden::filter::rules::RuleParseError;

fn sample_variants() -> Vec<RuleParseError> {
    vec![
        RuleParseError::Empty,
        RuleParseError::UnterminatedRegex,
        RuleParseError::EmptyRegex,
        RuleParseError::InvalidRegex {
            pattern: "broken(".to_string(),
            detail: "unclosed group".to_string(),
        },
        RuleParseError::TrailingAfterRegex {
            trailing: "bar".to_string(),
        },
        RuleParseError::UnknownModifier {
            modifier: "dnstype=AAAA".to_string(),
        },
        RuleParseError::EmptyPattern,
        RuleParseError::StrayWildcard,
        RuleParseError::InvalidDomain {
            input: "foo..bar".to_string(),
        },
    ]
}

#[test]
fn rule_parse_error_display_byte_pinned() {
    let expected = [
        "rule text is empty",
        "regex rule is missing its closing '/' — regex rules have the shape /pattern/",
        "regex rule has an empty pattern — '//' matches nothing",
        "regex '/broken(/' failed to compile: unclosed group",
        "unexpected text 'bar' after the regex's closing '/' — regex rules take no modifiers and must end at the final '/'",
        "unknown modifier '$dnstype=AAAA' — supported modifiers are $important and $noapex",
        "rule has no domain pattern between the '||' prefix and the '^' anchor",
        "'*' is only supported as a leading '*.' wildcard (e.g. ||*.ads.example.com^)",
        "'foo..bar' is not a valid domain (letters, digits, hyphens, underscores; dot-separated labels)",
    ];
    for (variant, want) in sample_variants().iter().zip(expected) {
        assert_eq!(variant.to_string(), want, "{variant:?}");
    }
}

#[test]
fn rule_parse_error_suggestions_byte_pinned() {
    let expected = [
        "delete the entry or provide a pattern like ||ads.example.com^",
        "close the pattern with '/' — e.g. /ad[0-9]+/",
        "put a pattern between the slashes — e.g. /ad[0-9]+/",
        "fix the regex syntax (Rust regex crate dialect); escape literal specials with '\\'",
        "end the rule at the closing '/' — move modifiers onto a non-regex rule",
        "use $important and/or $noapex, or drop the modifier",
        "add a domain between '||' and '^' — e.g. ||ads.example.com^",
        "move the wildcard to a leading '*.': ||*.ads.example.com^",
        "use a plain DNS name — e.g. ||tracker.example.com^",
    ];
    for (variant, want) in sample_variants().iter().zip(expected) {
        assert_eq!(variant.suggestion(), want, "{variant:?}");
    }
}

#[test]
fn every_variant_has_a_nonempty_suggestion() {
    for variant in sample_variants() {
        assert!(
            !variant.suggestion().trim().is_empty(),
            "suggestion missing for {variant:?}"
        );
    }
}

/// `tag_model_consolidation` §3.2 — the duplicate-URL WARN. Operators
/// read this string to decide which of two lists to delete, so it is
/// pinned byte-for-byte like the rows above.
#[test]
fn blocklist_duplicate_url_warn_template_byte_pinned() {
    assert_eq!(
        BLOCKLIST_DUPLICATE_URL,
        "blocklists {ids} resolve to the same source URL \"{url}\" — they share one cache file and its ETag; remove all but one"
    );
}

/// The message must name EVERY colliding id (the operator cannot act on
/// "some lists collide") and the canonical key they share.
#[test]
fn blocklist_duplicate_url_format_names_all_ids_and_the_url() {
    let msg =
        format_blocklist_duplicate_url(&["privacy-ads", "ads"], "https://lists.purge.cc/ads.txt");
    assert!(msg.contains("privacy-ads"), "{msg}");
    assert!(msg.contains("ads"), "{msg}");
    assert!(msg.contains("\"https://lists.purge.cc/ads.txt\""), "{msg}");
    // Ids are comma-separated, not concatenated.
    assert!(msg.contains("privacy-ads, ads"), "{msg}");
}

// ── N1 — the anti-bypass drop is loud ────────────────────────────────

/// Byte-pin on [`ANTI_BYPASS_ENABLED_NO_DOMAINS`], the one string an
/// operator gets when their config claims a protection that was never
/// built. Three properties are load-bearing and each is asserted
/// separately below, because a rewrite that keeps the gist while losing
/// one of them costs the operator the whole message:
///
/// 1. It names `anti_bypass.extra_domains` — the only field
///    `AntiBypass::new` reads. Any other remedy sends them nowhere.
/// 2. It says a `[[blocklists]]` subscription is NOT this path. Nothing
///    joins a list to `AntiBypassConfig`; a list is enforced by the
///    filter engine, where allow rules override it, while
///    `extra_domains` is enforced ahead of the engine where nothing can.
///    An operator told "subscribe a list" would get a different
///    guarantee than the one they asked for.
/// 3. It names no provider. project rules §Neutrality binds frozen strings
///    too — `neutrality-08` was a vendor name that hid inside one.
#[test]
fn n1_anti_bypass_enabled_no_domains_byte_pinned() {
    assert_eq!(
        ANTI_BYPASS_ENABLED_NO_DOMAINS,
        "[anti_bypass] enabled = true but has no domains to block — \
         `anti_bypass.extra_domains` is empty, so no resolver name is refused \
         and the setting protects nothing. warden ships no built-in resolver \
         list; add the names you want refused to `anti_bypass.extra_domains`. \
         A [[blocklists]] subscription does not feed this check — list domains \
         are enforced by the filter engine, where allow rules can override them."
    );
}

#[test]
fn n1_anti_bypass_warning_names_the_only_field_that_feeds_the_checker() {
    assert!(
        ANTI_BYPASS_ENABLED_NO_DOMAINS.contains("anti_bypass.extra_domains"),
        "the remedy must name the field `AntiBypass::new` actually reads"
    );
}

#[test]
fn n1_anti_bypass_warning_denies_the_blocklist_path() {
    assert!(
        ANTI_BYPASS_ENABLED_NO_DOMAINS.contains("does not feed this check"),
        "no code joins a [[blocklists]] subscription to AntiBypassConfig — \
         the text must not let an operator believe otherwise"
    );
}

/// §Neutrality: the string must not name a provider, in either
/// direction. Not even as a worked example — an example is exactly how a
/// vendor name earns a place in `src/` outside `#[cfg(test)]`.
#[test]
fn n1_anti_bypass_warning_names_no_provider() {
    let lower = ANTI_BYPASS_ENABLED_NO_DOMAINS.to_ascii_lowercase();
    for needle in [
        "cloudflare",
        "quad9",
        "adguard",
        "nextdns",
        "opendns",
        "mullvad",
        "cleanbrowsing",
        "dns.google",
        "1.1.1.1",
        "8.8.8.8",
        "9.9.9.9",
    ] {
        assert!(
            !lower.contains(needle),
            "frozen string names a provider ({needle}) — see project rules §Neutrality"
        );
    }
}

// ── the master-switch drop is loud ───────────────────────────────────

/// Byte-pin on [`SECURITY_DISABLED_DROPS_ANTI_BYPASS`]
/// (`security-master-switch-silently-kills-anti-bypass`).
///
/// The load-bearing property is asserted separately below: the text must
/// offer **both** exits. This warning fires at the exact moment an
/// operator has deliberately switched the security layer off, so a
/// message that said only "turn `security.enabled` back on" would be
/// telling them to re-arm RRL, rate limiting and tunneling detection —
/// the three things they were switching off when they reached for the
/// flag. A refusal that can soften into half an instruction will.
#[test]
fn master_switch_drops_anti_bypass_byte_pinned() {
    assert_eq!(
        SECURITY_DISABLED_DROPS_ANTI_BYPASS,
        "[security] enabled = false switches off every security sub-checker, \
         and `[anti_bypass]` is one of them — its `enabled = true` and its \
         `extra_domains` are read at load and then never reach the query path, \
         so no resolver name is refused. Pick the exit you meant: set \
         `security.enabled = true` and switch off only the sub-features you \
         do not want (`security.rrl`, `security.rate_limit` and \
         `security.tunneling` each have their own `enabled`), or set \
         `anti_bypass.enabled = false` so the config stops claiming a \
         protection that is not running."
    );
}

#[test]
fn master_switch_warning_offers_both_exits() {
    assert!(
        SECURITY_DISABLED_DROPS_ANTI_BYPASS.contains("security.enabled = true"),
        "must name the re-enable exit"
    );
    assert!(
        SECURITY_DISABLED_DROPS_ANTI_BYPASS.contains("anti_bypass.enabled = false"),
        "must name the stand-down exit — an operator who meant to disable the \
         security layer needs a way to make the config honest without re-arming it"
    );
    for sub in ["security.rrl", "security.rate_limit", "security.tunneling"] {
        assert!(
            SECURITY_DISABLED_DROPS_ANTI_BYPASS.contains(sub),
            "the re-enable exit is only actionable if it names the per-feature \
             switches to turn off instead: {sub} missing"
        );
    }
}

// ── neutrality-04: the inert SafeSearch flag says so ─────────────────

/// Byte-pin on [`SAFE_SEARCH_FLAG_SELECTS_NOTHING`].
///
/// Emitted for every profile with `safe_search = true` now that the
/// compiled-in engine table is gone. Two properties are load-bearing and
/// asserted separately: it must name `[[rewrites]]` as the remedy (the
/// only source of rewrites that exists), and it must name **no vendor** —
/// which is the harder constraint, because the natural way to explain
/// this warning is with an example, and an example here would smuggle
/// back the exact opinion `neutrality-04` removed.
#[test]
fn neutrality04_safe_search_flag_warning_byte_pinned() {
    assert_eq!(
        SAFE_SEARCH_FLAG_SELECTS_NOTHING,
        "`safe_search = true` no longer selects any rewrite. warden used to \
         compile in a table of search-engine redirects and inject it here; \
         that table named specific vendors, was invisible in your config and \
         could not be corrected without a new build, so it was removed. The \
         effective rewrite set is now exactly this profile's `[[rewrites]]`, \
         with the flag on or off. Add the redirects your search engines \
         document as `[[rewrites]]` entries on this profile; the flag itself \
         enforces nothing."
    );
}

#[test]
fn neutrality04_safe_search_warning_names_the_only_remaining_source() {
    assert!(
        SAFE_SEARCH_FLAG_SELECTS_NOTHING.contains("[[rewrites]]"),
        "the remedy must name the only field the resolver reads"
    );
}

/// The retired table, named here and only here. A vendor name in a test
/// asserting **absence** is the sanctioned use per project rules §Neutrality;
/// any of these appearing in the operator-facing string would mean the
/// opinion came back through the diagnostic.
#[test]
fn neutrality04_safe_search_warning_names_no_engine() {
    let lower = SAFE_SEARCH_FLAG_SELECTS_NOTHING.to_ascii_lowercase();
    for needle in [
        "google",
        "youtube",
        "bing",
        "duckduckgo",
        "yandex",
        "forcesafesearch",
        "restrict.youtube",
        "strict.bing",
        "safe.duckduckgo",
    ] {
        assert!(
            !lower.contains(needle),
            "frozen string names a search vendor ({needle}) — that is the \
             opinion neutrality-04 removed, arriving via the diagnostic"
        );
    }
}
