//! rev-2606 schema-validator-05: lint↔engine agreement for admin rule text.
//!
//! The sprint's central property — `warden config lint` (via
//! `check_admin_rules` → `filter::rules::parse_rule_checked`) accepts a
//! rule string if and only if the filter engine's resolver build (via
//! `parse_rules`) produces an enforcing rule from it. Both sides consume
//! the SAME parser today; this file pins the bi-implication so a future
//! fork of the two code paths fails loudly instead of re-creating the
//! lint-clean-but-inert-rule bug.
//!
//! Per string: (1) the engine verdict (`parse_rules` non-empty/empty),
//! (2) the lint verdict (a minimal config carrying it as
//! `[[admin_rules]].rule` loads / errors with the rule's entity), and
//! (3) accept ⟺ enforce.

use std::path::Path;

use purge_warden::config::error::ConfigError;
use purge_warden::config::schema::load::load_from_str;
use purge_warden::filter::rules::parse_rules;

/// Rule shapes the engine enforces — every one must lint clean.
const ACCEPT: &[&str] = &[
    "||tiktok.com^",
    "@@||wikipedia.org^",
    "||malware.com^$important",
    "||*.ads.example.com^",
    "||*.cdn.example.com^$noapex",
    "||*.evil.com^$important,noapex",
    "/ad[0-9]+\\.example\\.com/",
    "@@/safe-cdn[0-9]+\\.example\\.com/",
    "/DoubleClick/",
    "plain.example.com",
    "@@example.com",
    "||ads.com",
    "||TikTok.COM^",
];

/// Rule shapes the engine drops — every one must be a lint error.
const REJECT: &[&str] = &[
    "/broken(/",
    "/unterminated",
    "//",
    "/foo/bar",
    "/foo/$important",
    "||ads.com^$third-party,important",
    "||example.com^$dnstype=AAAA",
    "||x.com^$improtant",
    "||x.com^$",
    "||ads.*.com^",
    "||*.^",
    "||^",
    "||foo..bar^",
    "||<script>x</script>^",
];

/// Minimal valid config with the probe rule injected. TOML literal
/// (single-quoted) strings take the rule text verbatim — none of the
/// fixtures contain a single quote.
fn config_with_rule(rule: &str) -> String {
    assert!(
        !rule.contains('\''),
        "fixture rules must be TOML-literal-safe"
    );
    format!(
        r#"
schema_version = 3

[server]
default_profile = "default"

[profiles.default]
display_name = "Default"
tags = ["uncategorized"]

[[admin_rules]]
id = "probe"
rule = '{rule}'

[upstream]
servers = ["192.0.2.1:53"]
"#
    )
}

fn lint_accepts(rule: &str) -> Result<(), Vec<ConfigError>> {
    let now = time::OffsetDateTime::now_utc();
    load_from_str(&config_with_rule(rule), Some(Path::new("probe.toml")), now).map(|_| ())
}

#[test]
fn accepted_rules_lint_clean_and_enforce() {
    for rule in ACCEPT {
        assert!(
            !parse_rules(rule).is_empty(),
            "engine must enforce {rule:?}"
        );
        assert!(
            lint_accepts(rule).is_ok(),
            "lint must accept {rule:?}: {:?}",
            lint_accepts(rule).unwrap_err()
        );
    }
}

#[test]
fn rejected_rules_lint_error_and_are_engine_inert() {
    for rule in REJECT {
        assert!(
            parse_rules(rule).is_empty(),
            "engine must be inert for {rule:?}"
        );
        let errs = lint_accepts(rule).expect_err(&format!("lint must reject {rule:?}"));
        assert!(
            errs.iter().any(|e| {
                let (ConfigError::ValidationFailed(ctx) | ConfigError::MissingRequired(ctx)) = e
                else {
                    return false;
                };
                ctx.entity.as_deref() == Some("admin_rules.probe")
            }),
            "lint error for {rule:?} must name the rule entity: {errs:?}"
        );
    }
}

#[test]
fn oversized_regex_rejected_on_both_sides() {
    // L-10 1 MiB compile cap: lint and engine refuse together.
    let rule = format!("/a{{{}}}/", 200_000);
    assert!(parse_rules(&rule).is_empty());
    assert!(lint_accepts(&rule).is_err());
}

#[test]
fn bi_implication_holds_across_the_full_matrix() {
    for rule in ACCEPT.iter().chain(REJECT.iter()) {
        let enforced = !parse_rules(rule).is_empty();
        let lints = lint_accepts(rule).is_ok();
        assert_eq!(
            enforced, lints,
            "lint↔engine divergence for {rule:?}: enforced={enforced} lint-clean={lints}"
        );
    }
}
