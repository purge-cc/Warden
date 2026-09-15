use std::sync::Arc;

use super::compiler::{indexed_winner, ExactSlots};
use super::decision::RuleToken;
use super::*;
use crate::config::schema::id::Id;
use crate::filter::engine::{FilterEngine, FilterResult};
use crate::filter::rules::{parse_rule_checked, parse_rules, RuleAction, RulePattern};
use crate::profiles::profile::ResolvedProfile;

fn compile(content: &str) -> CompiledOperatorRules {
    candidate(content, false, RuleCompileLimits::default()).unwrap()
}

fn candidate(
    content: &str,
    block_all: bool,
    limits: RuleCompileLimits,
) -> Result<CompiledOperatorRules, CompileError> {
    compile_isolated(
        &[PackSource {
            list_id: "rules",
            content,
        }],
        &[ProfileMounts {
            profile_id: "profile",
            custom_lists: &["rules"],
            block_all,
        }],
        limits,
    )
}

fn profile(candidate: &CompiledOperatorRules) -> &CompiledProfile {
    candidate.profile(&Id::new("profile").unwrap()).unwrap()
}

fn key(raw: &str) -> RuleKey {
    parse_rule_ast(raw).unwrap().rule_key()
}

#[test]
fn indexed_slots_are_compact_and_preserve_tier_and_token_winners() {
    assert_eq!(std::mem::size_of::<ExactSlots>(), 16);
    assert_eq!(indexed_winner(&[u32::MAX; 4]), None);

    for mask in 0..16 {
        let mut slots = [u32::MAX; 4];
        for (tier, slot) in slots.iter_mut().enumerate() {
            if mask & (1 << tier) != 0 {
                *slot = tier as u32;
            }
        }
        let expected = (0..4)
            .rev()
            .find(|tier| mask & (1 << tier) != 0)
            .map(|tier| RankedHit {
                tier: [
                    RuleTier::OrdinaryDeny,
                    RuleTier::OrdinaryAllow,
                    RuleTier::ImportantDeny,
                    RuleTier::ImportantAllow,
                ][tier],
                token: RuleToken(tier as u32),
            });
        assert_eq!(indexed_winner(&slots), expected);
    }

    let mut slots = [u32::MAX; 4];
    slots[RuleTier::OrdinaryAllow as usize] = 9;
    slots[RuleTier::OrdinaryAllow as usize] = slots[RuleTier::OrdinaryAllow as usize].min(3);
    assert_eq!(
        indexed_winner(&slots),
        Some(RankedHit {
            tier: RuleTier::OrdinaryAllow,
            token: RuleToken(3),
        })
    );
}

#[test]
fn accepted_grammar_matches_admin_parser_and_expansion() {
    let fixtures = [
        "example.test",
        "||example.test",
        "example.test^",
        "||example.test^",
        "@@example.test",
        "@@example.test^",
        "@@||example.test",
        "@@||example.test^",
        "  ||EXAMPLE.test^  ",
        "_srv._tcp.example.test",
        "localhost",
        "xn--bcher-kva.test",
        "example.test$noapex",
        "@@||example.test^$important,noapex",
        "example.test$important, important",
        "||example.test^$noapex, important, noapex",
        "*.example.test",
        "||*.example.test^",
        "@@*.example.test^$noapex",
        "@@||*.example.test^$important",
        "*.example.test$important,noapex",
        "/EXAMPLE/",
        "@@/EXAMPLE/",
        "/(?-i)EXAMPLE/",
        "/\\D+/",
        "/\\d+/",
        "/^ad[0-9]+\\.example\\.test$/",
        "/a b/",
        "/#comment/",
        "/a\\t/",
    ];
    for raw in fixtures {
        let old = parse_rule_checked(raw).unwrap();
        let ast = parse_rule_ast(raw).unwrap();
        assert_eq!(
            ast.tier().is_allow(),
            old.action == RuleAction::Allow,
            "{raw}"
        );
        assert_eq!(ast.tier().is_important(), old.important, "{raw}");
        assert_eq!(ast.noapex(), old.noapex, "{raw}");
        match (ast.pattern(), &old.pattern) {
            (OperatorPattern::Exact(a), RulePattern::Exact(b))
            | (OperatorPattern::Wildcard(a), RulePattern::Wildcard(b)) => assert_eq!(a, b),
            (
                OperatorPattern::Regex {
                    source: a,
                    case_insensitive,
                },
                RulePattern::Regex { source: b, .. },
            ) => {
                assert_eq!(a, b);
                assert!(*case_insensitive);
            }
            pair => panic!("class drift for {raw}: {pair:?}"),
        }
        let new = compile(raw);
        let p = profile(&new);
        assert_eq!(
            p.counts().indexed + p.counts().advanced,
            parse_rules(raw).len(),
            "{raw}"
        );
        for domain in [
            "example.test",
            "sub.example.test",
            "badexample.test",
            "ad123.example.test",
            "x.other.test",
            "123",
        ] {
            let old_match = parse_rules(raw).iter().any(|rule| rule.matches(domain));
            assert_eq!(p.lookup(domain).is_some(), old_match, "{raw:?} / {domain}");
        }
    }
}

#[test]
fn rejected_grammar_preserves_admin_rejection_set() {
    for raw in [
        "",
        " ",
        "@@",
        "||^",
        "|example.test^",
        "|||example.test^",
        "example.test^^",
        "example..test",
        ".example.test",
        "example.test.",
        "-example.test",
        "example-.test",
        "exämple.test",
        "https://example.test",
        "0.0.0.0 example.test",
        "<script>example.test",
        "||*.^",
        "||*.^$noapex",
        "||*.-example.test^",
        "ads.*.test",
        "*example.test",
        "example.test$",
        "example.test$Important",
        "example.test$important,",
        "example.test$noapex$important",
        "example.test$third-party",
        "example.test$dnstype=AAAA",
        "example.test$important^",
        "/",
        "//",
        "/x",
        "/foo/bar",
        "/foo/$important",
        "@@/foo/$noapex",
        "/foo\\/bar/",
    ] {
        let old = parse_rule_checked(raw).unwrap_err();
        assert_eq!(
            parse_rule_ast(raw).unwrap_err(),
            AstError::Grammar(old),
            "{raw:?}"
        );
    }
    for raw in ["/unclosed(/", "/[z-a]/"] {
        assert!(parse_rule_checked(raw).is_err());
        assert!(
            parse_rule_ast(raw).is_ok(),
            "regex compilation leaks into AST parsing"
        );
        assert!(matches!(
            candidate(raw, false, RuleCompileLimits::default()),
            Err(CompileError::InvalidRegex { .. })
        ));
    }
    for label in ["a".repeat(64), "a".repeat(254)] {
        assert!(parse_rule_checked(&label).is_err());
        assert!(parse_rule_ast(&label).is_err());
    }
}

#[test]
fn record_separators_are_rejected_before_trim() {
    for separator in [
        '\r', '\n', '\0', '\u{b}', '\u{c}', '\u{85}', '\u{2028}', '\u{2029}', '\u{1c}', '\u{1d}',
        '\u{1e}',
    ] {
        for raw in [
            format!("{separator}example.test"),
            format!("example.test{separator}"),
            format!("/a{separator}b/"),
            format!("example.test{separator}@@other.test"),
        ] {
            assert_eq!(parse_rule_ast(&raw).unwrap_err(), AstError::MultipleRecords);
        }
    }
    assert!(parse_rule_ast("\t example.test \t").is_ok());
    assert!(matches!(
        candidate(
            "# comment\0\nexample.test",
            false,
            RuleCompileLimits::default()
        ),
        Err(CompileError::InvalidRule { .. })
    ));
}

#[test]
fn semantic_identity_normalizes_only_effective_domain_syntax() {
    let reference = key("example.test");
    for raw in [
        "EXAMPLE.TEST",
        "||example.test",
        "example.test^",
        "||EXAMPLE.test^",
        "example.test$noapex",
        "  example.test  ",
    ] {
        assert_eq!(reference, key(raw));
    }
    assert_eq!(
        key("*.example.test$important,noapex"),
        key("||*.EXAMPLE.test^$noapex,important,important")
    );
    for raw in [
        "@@example.test",
        "example.test$important",
        "*.example.test",
        "*.example.test$noapex",
        "/example.test/",
    ] {
        assert_ne!(reference, key(raw));
    }
    assert_ne!(key("*.example.test"), key("*.example.test$noapex"));
    assert_ne!(key("/EXAMPLE/"), key("/example/"));
    assert_ne!(key("/\\D/"), key("/\\d/"));
    assert_ne!(key("/example/"), key("/(?i)example/"));
    // Independent fixed preimage pins field lengths, tags and byte order.
    let expected_preimage = b"warden/uor/rule-ast/v1\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\x0cexample.test\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\x01\0";
    use sha2::{Digest, Sha256};
    assert_eq!(
        reference.0,
        <[u8; 32]>::from(Sha256::digest(expected_preimage))
    );
}

#[test]
fn duplicate_rows_coalesce_without_losing_byte_provenance() {
    use sha2::{Digest, Sha256};
    let content = "# header\r\nexample.test\r\n\n||EXAMPLE.test^$noapex\n@@example.test";
    let c = compile(content);
    let p = profile(&c);
    assert_eq!(c.store().len(), 2);
    let pack = c.store().pack(&Id::new("rules").unwrap()).unwrap();
    assert_eq!(pack.source_rule_rows(), 3);
    assert_eq!(pack.counts().indexed, 2);
    assert_eq!(
        pack.revision(),
        <[u8; 32]>::from(Sha256::digest(content.as_bytes()))
    );
    let token = pack
        .tokens()
        .iter()
        .find(|token| c.store().ast(**token).unwrap().tier() == RuleTier::OrdinaryDeny)
        .unwrap();
    let origin = c.store().origin(*token).unwrap();
    assert_eq!(
        origin
            .source_rows()
            .iter()
            .map(|row| row.line)
            .collect::<Vec<_>>(),
        vec![2, 4]
    );
    assert_eq!(origin.pack_revision(), pack.revision());
    for row in origin.source_rows() {
        let raw = &content[row.byte_offset as usize..(row.byte_offset + row.byte_len) as usize];
        assert_eq!(row.digest, <[u8; 32]>::from(Sha256::digest(raw.as_bytes())));
        assert_eq!(
            parse_rule_ast(raw.trim_end_matches(['\r', '\n']))
                .unwrap()
                .rule_key(),
            origin.rule_key()
        );
    }
    assert_eq!(
        p.lookup("example.test").unwrap().tier,
        RuleTier::OrdinaryAllow
    );
    let edited = compile(&format!("{content}\n# cosmetic"));
    assert_ne!(
        pack.revision(),
        edited
            .store()
            .pack(&Id::new("rules").unwrap())
            .unwrap()
            .revision()
    );
    assert_eq!(origin.rule_key(), key("example.test"));
}

#[test]
fn every_tier_subset_obeys_one_lattice_with_both_defaults() {
    let rules = [
        "example.test",
        "@@example.test",
        "example.test$important",
        "@@example.test$important",
    ];
    let tiers = [
        RuleTier::OrdinaryDeny,
        RuleTier::OrdinaryAllow,
        RuleTier::ImportantDeny,
        RuleTier::ImportantAllow,
    ];
    for mask in 0..16 {
        let content = (0..4)
            .filter(|i| mask & (1 << i) != 0)
            .map(|i| rules[i])
            .collect::<Vec<_>>()
            .join("\n");
        for block_all in [false, true] {
            let c = candidate(&content, block_all, RuleCompileLimits::default()).unwrap();
            let p = profile(&c);
            let expected = (0..4)
                .rev()
                .find(|i| mask & (1 << i) != 0)
                .map(|i| tiers[i]);
            for external in [
                ExternalMatches::None,
                ExternalMatches::Disabled,
                ExternalMatches::Allow,
                ExternalMatches::Deny,
                ExternalMatches::AllowAndDeny,
            ] {
                let d = p.evaluate_attributed("sub.example.test", external);
                assert_eq!(p.lookup("sub.example.test").map(|hit| hit.tier), expected);
                let allow = expected.map_or(
                    !block_all && external != ExternalMatches::Deny,
                    RuleTier::is_allow,
                );
                assert_eq!(
                    d.verdict(),
                    if allow {
                        Verdict::Forward
                    } else {
                        Verdict::Block
                    }
                );
                assert_eq!(
                    d.grant_tier().is_some(),
                    expected.is_some_and(RuleTier::is_allow)
                );
                assert_eq!(p.evaluate("sub.example.test", external), d.verdict());
            }
        }
    }
}

#[test]
fn important_exact_uses_only_index_and_suffixes_do_not_override_tier() {
    let c = compile("@@leaf.example.test\nexample.test$important\n@@other.test$important");
    let p = profile(&c);
    assert_eq!(p.advanced_len(), 0);
    assert_eq!(
        p.counts(),
        ProjectionCounts {
            indexed: 3,
            advanced: 0,
            regex: 0
        }
    );
    assert_eq!(
        p.lookup("leaf.example.test").unwrap().tier,
        RuleTier::ImportantDeny
    );
    assert_eq!(
        p.lookup("sub.other.test").unwrap().tier,
        RuleTier::ImportantAllow
    );
    assert!(p.lookup("badexample.test").is_none());
    assert!(p.lookup("test").is_none());
}

#[test]
fn indexed_suffix_closure_preserves_ancestor_tier_winners() {
    let cases = [
        (
            "child.branch.example.test\n@@branch.example.test",
            RuleTier::OrdinaryAllow,
        ),
        (
            "@@child.branch.example.test\nbranch.example.test$important",
            RuleTier::ImportantDeny,
        ),
        (
            "child.branch.example.test$important\n@@branch.example.test$important",
            RuleTier::ImportantAllow,
        ),
    ];
    for (content, expected) in cases {
        let c = compile(content);
        let p = profile(&c);
        assert_eq!(
            p.lookup("leaf.child.branch.example.test").unwrap().tier,
            expected
        );
    }
}

#[test]
fn indexed_suffix_closure_uses_minimum_token_across_reversed_sources_and_mounts() {
    for reverse in [false, true] {
        let mut packs = [
            PackSource {
                list_id: "z-list",
                content: "@@child.branch.example.test",
            },
            PackSource {
                list_id: "a-list",
                content: "@@branch.example.test",
            },
        ];
        if reverse {
            packs.reverse();
        }
        let mounts = if reverse {
            ["a-list", "z-list"]
        } else {
            ["z-list", "a-list"]
        };
        let c = compile_isolated(
            &packs,
            &[ProfileMounts {
                profile_id: "profile",
                custom_lists: &mounts,
                block_all: false,
            }],
            RuleCompileLimits::default(),
        )
        .unwrap();
        let hit = profile(&c)
            .lookup("leaf.child.branch.example.test")
            .unwrap();
        assert_eq!(hit.origin().list_id().as_str(), "a-list");
    }

    for content in [
        "@@child.branch.example.test\n@@branch.example.test",
        "@@branch.example.test\n@@child.branch.example.test",
    ] {
        let c = compile(content);
        let hit = profile(&c)
            .lookup("leaf.child.branch.example.test")
            .unwrap();
        assert_eq!(
            hit.origin().rule_key(),
            key("@@child.branch.example.test").min(key("@@branch.example.test"))
        );
    }
}

#[test]
fn indexed_suffix_closure_keeps_advanced_competitors() {
    let c = compile("child.branch.example.test\n@@*.child.branch.example.test$important,noapex");
    let p = profile(&c);
    assert_eq!(
        p.lookup("leaf.child.branch.example.test").unwrap().tier,
        RuleTier::ImportantAllow
    );
}

#[test]
fn indexed_suffix_length_bound_preserves_short_keys_and_advanced_matches() {
    let c = compile("long.indexed.example.test\n@@a.test$important\n*.b.test\n/c[.]test/");
    let p = profile(&c);
    for (domain, expected_key) in [
        ("x.a.test", "@@a.test$important"),
        ("x.y.a.test", "@@a.test$important"),
        ("b.test", "*.b.test"),
        ("x.b.test", "*.b.test"),
        ("c.test", "/c[.]test/"),
        ("x.c.test", "/c[.]test/"),
        ("x.long.indexed.example.test", "long.indexed.example.test"),
    ] {
        let hit = p.lookup(domain).unwrap();
        assert_eq!(hit.origin().rule_key(), key(expected_key), "{domain}");
        assert_eq!(
            p.evaluate(domain, ExternalMatches::Disabled),
            p.evaluate_attributed(domain, ExternalMatches::Disabled)
                .verdict(),
            "{domain}"
        );
    }
    assert!(p.lookup("x.d.test").is_none());
    assert!(p.lookup("test").is_none());

    let c = compile("long.indexed.example.test\n*.b.test$noapex\n/c[.]test/");
    let p = profile(&c);
    assert!(p.lookup("b.test").is_none());
    assert_eq!(
        p.lookup("x.b.test").unwrap().origin().rule_key(),
        key("*.b.test$noapex")
    );
    assert_eq!(
        p.lookup("x.c.test").unwrap().origin().rule_key(),
        key("/c[.]test/")
    );
}

#[test]
fn wildcard_apex_projection_has_identical_token_and_origin() {
    for prefix in ["", "@@"] {
        for modifier in ["", "$important"] {
            let c = compile(&format!("{prefix}*.example.test{modifier}"));
            let p = profile(&c);
            assert_eq!(p.advanced_len(), 1);
            assert_eq!(p.counts().indexed, 1);
            let apex = p.lookup("example.test").unwrap();
            let child = p.lookup("sub.example.test").unwrap();
            assert_eq!(apex, child);
            assert!(std::ptr::eq(
                p.store().origin(apex.token).unwrap(),
                p.store().origin(child.token).unwrap()
            ));
            let c = compile(&format!(
                "{prefix}*.example.test$noapex{}",
                if modifier.is_empty() {
                    ""
                } else {
                    ",important"
                }
            ));
            let p = profile(&c);
            assert_eq!(p.counts().indexed, 0);
            assert!(p.lookup("example.test").is_none());
            assert!(p.lookup("sub.example.test").is_some());
        }
    }
}

#[test]
fn exact_and_advanced_ties_follow_origin_rank_not_input_order() {
    for reverse in [false, true] {
        let mut packs = vec![
            PackSource {
                list_id: "z-list",
                content: "@@leaf.example.test",
            },
            PackSource {
                list_id: "a-list",
                content: "@@*.example.test\n@@/example/",
            },
        ];
        if reverse {
            packs.reverse();
        }
        let mounts = if reverse {
            ["a-list", "z-list"]
        } else {
            ["z-list", "a-list"]
        };
        let c = compile_isolated(
            &packs,
            &[ProfileMounts {
                profile_id: "profile",
                custom_lists: &mounts,
                block_all: false,
            }],
            RuleCompileLimits::default(),
        )
        .unwrap();
        let p = profile(&c);
        let hit = p.lookup("leaf.example.test").unwrap();
        let origin = p.store().origin(hit.token).unwrap();
        assert_eq!(origin.list_id().as_str(), "a-list");
        assert_eq!(
            origin.rule_key(),
            key("@@*.example.test").min(key("@@/example/"))
        );
        assert_eq!(hit.token.index(), 0);
    }
    let a = compile("@@example.test\n@@leaf.example.test");
    let b = compile("@@leaf.example.test\n@@example.test");
    assert_eq!(
        profile(&a)
            .lookup("leaf.example.test")
            .unwrap()
            .origin()
            .rule_key(),
        profile(&b)
            .lookup("leaf.example.test")
            .unwrap()
            .origin()
            .rule_key()
    );
}

#[test]
fn indexed_and_advanced_compete_across_tiers() {
    for (content, expected) in [
        (
            "@@example.test\n*.example.test$important",
            RuleTier::ImportantDeny,
        ),
        (
            "@@/example/\nexample.test$important",
            RuleTier::ImportantDeny,
        ),
        (
            "example.test$important\n@@*.example.test$important",
            RuleTier::ImportantAllow,
        ),
        (
            "@@example.test$important\n*.example.test$important",
            RuleTier::ImportantAllow,
        ),
        ("example.test\n@@/example/", RuleTier::OrdinaryAllow),
    ] {
        let c = compile(content);
        assert_eq!(
            profile(&c).lookup("sub.example.test").unwrap().tier,
            expected
        );
    }
}

#[test]
fn same_list_indexed_and_advanced_ties_choose_minimum_semantic_key() {
    let rules = ["@@example.test", "@@*.example.test$noapex", "@@/example/"];
    let expected = rules.iter().map(|rule| key(rule)).min().unwrap();
    for content in [
        rules.join("\n"),
        rules.into_iter().rev().collect::<Vec<_>>().join("\n"),
    ] {
        let c = compile(&content);
        let p = profile(&c);
        let hit = p.lookup("child.example.test").unwrap();
        assert_eq!(p.store().origin(hit.token).unwrap().rule_key(), expected);
        assert_eq!(hit.token.index(), 0);
        assert_eq!(
            p.evaluate_attributed("child.example.test", ExternalMatches::None)
                .winning_rule()
                .map(|hit| hit.token),
            Some(hit.token)
        );
    }
}

#[test]
fn target_authority_table_and_response_ip_bypass_are_uniform() {
    for grant_rule in [
        "",
        "@@query.test",
        "@@*.query.test",
        "@@/query/",
        "@@query.test$important",
        "@@*.query.test$important",
    ] {
        let important = grant_rule.contains("important");
        let has_grant = !grant_rule.is_empty();
        for (target_rule, target_tier) in [
            ("", None),
            ("target.test", Some(RuleTier::OrdinaryDeny)),
            ("target.test$important", Some(RuleTier::ImportantDeny)),
            ("@@target.test$important", Some(RuleTier::ImportantAllow)),
        ] {
            for block_all in [false, true] {
                let c = candidate(
                    &format!("{grant_rule}\n{target_rule}"),
                    block_all,
                    RuleCompileLimits::default(),
                )
                .unwrap();
                let p = profile(&c);
                let request = p.evaluate_attributed("sub.query.test", ExternalMatches::Allow);
                assert_eq!(request.grant_tier().is_some(), has_grant);
                for external in [
                    ExternalMatches::None,
                    ExternalMatches::Allow,
                    ExternalMatches::Deny,
                ] {
                    let target = request.evaluate_target("target.test", external, true);
                    let expected_allow = request.verdict() == Verdict::Forward
                        && match target_tier {
                            Some(RuleTier::ImportantAllow) => true,
                            Some(RuleTier::ImportantDeny) => important,
                            Some(RuleTier::OrdinaryDeny) => has_grant,
                            None => has_grant || (!block_all && external != ExternalMatches::Deny),
                            _ => unreachable!(),
                        };
                    assert_eq!(
                        target.verdict(),
                        if expected_allow {
                            Verdict::Forward
                        } else {
                            Verdict::Block
                        },
                        "{grant_rule} / {target_rule} / {block_all} / {external:?}"
                    );
                    assert_eq!(
                        request
                            .evaluate_target("target.test", external, false)
                            .verdict(),
                        Verdict::Block
                    );
                }
                assert_eq!(
                    request.response_ip_verdict(true, true),
                    if has_grant {
                        Verdict::Forward
                    } else {
                        Verdict::Block
                    }
                );
                assert_eq!(request.response_ip_verdict(false, false), Verdict::Block);
            }
        }
    }
}

#[test]
fn target_local_allow_does_not_replace_original_qname_grant() {
    let c = compile("@@target.test$important\nblocked.test$important");
    let p = profile(&c);
    let request = p.evaluate_attributed("query.test", ExternalMatches::Allow);
    assert!(request.grant_tier().is_none());
    let target = request.evaluate_target("target.test", ExternalMatches::Deny, true);
    assert!(target.winning_rule().unwrap().tier().is_allow());
    assert_eq!(
        request
            .evaluate_target("blocked.test", ExternalMatches::None, true)
            .verdict(),
        Verdict::Block
    );
    assert_eq!(request.response_ip_verdict(true, true), Verdict::Block);
    let blocked = p.evaluate_attributed("blocked.test", ExternalMatches::None);
    assert_eq!(
        blocked
            .evaluate_target("target.test", ExternalMatches::Allow, true)
            .verdict(),
        blocked.verdict()
    );
}

#[test]
fn v4_runtime_oracle_remains_distinct_from_target_behavior() {
    let mut old = ResolvedProfile::permissive_default();
    old.block_all = true;
    old.allow_domains = Arc::new(["example.test".into()].into_iter().collect());
    old.rules = Arc::new(parse_rules("example.test$important"));
    let engine = FilterEngine::new();
    assert_eq!(engine.evaluate("example.test", &old), FilterResult::Forward);
    let c = candidate(
        "@@example.test\nexample.test$important",
        true,
        RuleCompileLimits::default(),
    )
    .unwrap();
    assert_eq!(
        profile(&c).evaluate("example.test", ExternalMatches::None),
        Verdict::Block
    );
    assert!(!parse_rule_checked("example.test$important")
        .unwrap()
        .is_simple_exact());
    assert_eq!(profile(&c).advanced_len(), 0);
}

#[test]
fn one_bad_row_rejects_the_whole_candidate_even_when_unmounted() {
    for content in [
        "example.test\nbad..test\n@@other.test",
        "example.test\n/(broken/",
        "example.test\n/ok/$important",
    ] {
        let result = compile_isolated(
            &[PackSource {
                list_id: "unmounted",
                content,
            }],
            &[],
            RuleCompileLimits::default(),
        );
        assert!(matches!(
            result,
            Err(CompileError::InvalidRule { row: 2, .. }
                | CompileError::InvalidRegex { row: 2, .. })
        ));
    }
}

#[test]
fn declarations_and_mounts_are_strict() {
    let limits = RuleCompileLimits::default();
    for name in ["bad_id", "-bad", "bad-", "Bad", "", "../bad"] {
        assert!(matches!(
            compile_isolated(
                &[PackSource {
                    list_id: name,
                    content: ""
                }],
                &[],
                limits
            ),
            Err(CompileError::InvalidId(_))
        ));
    }
    let packs = [PackSource {
        list_id: "rules",
        content: "",
    }];
    assert!(matches!(
        compile_isolated(&[packs[0], packs[0]], &[], limits),
        Err(CompileError::DuplicateList(_))
    ));
    for (mounts, duplicate) in [(&["rules", "rules"][..], true), (&["missing"][..], false)] {
        let error = compile_isolated(
            &packs,
            &[ProfileMounts {
                profile_id: "profile",
                custom_lists: mounts,
                block_all: false,
            }],
            limits,
        )
        .unwrap_err();
        assert!(if duplicate {
            matches!(error, CompileError::DuplicateMount { .. })
        } else {
            matches!(error, CompileError::UnknownMount { .. })
        });
    }
    let p = ProfileMounts {
        profile_id: "profile",
        custom_lists: &[],
        block_all: false,
    };
    assert!(matches!(
        compile_isolated(&packs, &[p, p], limits),
        Err(CompileError::DuplicateProfile(_))
    ));
}

#[test]
fn every_limit_rejects_zero_and_values_above_hard_ceiling() {
    RuleCompileLimits::default().validate().unwrap();
    RuleCompileLimits::HARD_CEILINGS.validate().unwrap();
    for (name, field) in RuleCompileLimits::fields() {
        let mut limits = RuleCompileLimits::HARD_CEILINGS;
        *field(&mut limits) += 1;
        assert_eq!(limits.validate().unwrap_err().limit, name);
        *field(&mut limits) = 0;
        assert_eq!(limits.validate().unwrap_err().limit, name);
        *field(&mut limits) = usize::MAX;
        assert_eq!(limits.validate().unwrap_err().limit, name);
    }
}

#[test]
fn default_and_hard_limits_are_pinned() {
    let defaults = [
        256, 1048576, 33554432, 25000, 100000, 500000, 256, 2048, 32, 128, 500000, 2048, 128, 4096,
        1048576, 33554432, 8388608, 33554432,
    ];
    let ceilings = [
        1024, 4194304, 67108864, 100000, 250000, 1000000, 512, 4096, 64, 256, 1000000, 4096, 256,
        16384, 2097152, 67108864, 16777216, 67108864,
    ];
    for ((name, field), (default, ceiling)) in RuleCompileLimits::fields()
        .into_iter()
        .zip(defaults.into_iter().zip(ceilings))
    {
        let mut actual_defaults = RuleCompileLimits::default();
        let mut actual_ceilings = RuleCompileLimits::HARD_CEILINGS;
        assert_eq!(*field(&mut actual_defaults), default, "{name}");
        assert_eq!(*field(&mut actual_ceilings), ceiling, "{name}");
    }
}

#[test]
fn repeated_mounts_charge_advanced_and_regex_counts_per_profile() {
    for (text, total_field) in [
        ("*.example.test$noapex", "max_advanced_rules_total"),
        ("/example/", "max_regex_rules_total"),
    ] {
        let packs = [PackSource {
            list_id: "rules",
            content: text,
        }];
        let profiles = [
            ProfileMounts {
                profile_id: "one",
                custom_lists: &["rules"],
                block_all: false,
            },
            ProfileMounts {
                profile_id: "two",
                custom_lists: &["rules"],
                block_all: false,
            },
        ];
        let (_, field) = RuleCompileLimits::fields()
            .into_iter()
            .find(|(name, _)| *name == total_field)
            .unwrap();
        let mut limits = RuleCompileLimits::default();
        *field(&mut limits) = 2;
        let c = compile_isolated(&packs, &profiles, limits).unwrap();
        assert_eq!(c.cost().profile_counts_total.advanced, 2);
        *field(&mut limits) = 1;
        budget_error(compile_isolated(&packs, &profiles, limits), total_field);
    }
}

#[test]
fn unmounted_regex_programs_and_empty_profiles_consume_snapshot_budget() {
    let packs = [PackSource {
        list_id: "rules",
        content: "/example/",
    }];
    let c = compile_isolated(&packs, &[], RuleCompileLimits::default()).unwrap();
    assert_eq!(c.cost().regex_programs, 1);
    assert_eq!(c.cost().snapshot_bytes, c.cost().store_bytes);
    let limits = RuleCompileLimits {
        max_store_compiled_bytes: c.cost().store_bytes - 1,
        ..Default::default()
    };
    budget_error(
        compile_isolated(&packs, &[], limits),
        "max_store_compiled_bytes",
    );
    let p = [ProfileMounts {
        profile_id: "empty",
        custom_lists: &[],
        block_all: false,
    }];
    let with_profile = compile_isolated(&packs, &p, RuleCompileLimits::default()).unwrap();
    assert_eq!(
        with_profile.cost().profile_counts_total,
        ProjectionCounts::default()
    );
    assert!(with_profile.cost().snapshot_bytes > c.cost().snapshot_bytes);
    let limits = RuleCompileLimits {
        max_compiled_bytes_total: with_profile.cost().snapshot_bytes - 1,
        ..Default::default()
    };
    budget_error(
        compile_isolated(&packs, &p, limits),
        "max_compiled_bytes_total",
    );
}

fn budget_error(result: Result<CompiledOperatorRules, CompileError>, field: &str) {
    match result.unwrap_err() {
        CompileError::BudgetExceeded(error) => assert_eq!(error.limit, field),
        error => panic!("expected budget {field}, got {error:?}"),
    }
}

#[test]
fn source_limits_count_bytes_and_duplicate_rows_before_dedup() {
    let text = "example.test\nEXAMPLE.test";
    let mut limits = RuleCompileLimits {
        max_file_bytes: text.len(),
        max_total_bytes: text.len(),
        max_rules_per_list: 2,
        max_rule_bytes: 12,
        ..Default::default()
    };
    let c = candidate(text, false, limits).unwrap();
    assert_eq!(c.store().len(), 1);
    limits.max_file_bytes -= 1;
    budget_error(candidate(text, false, limits), "max_file_bytes");
    limits.max_file_bytes += 1;
    limits.max_total_bytes -= 1;
    budget_error(candidate(text, false, limits), "max_total_bytes");
    limits.max_total_bytes += 1;
    limits.max_rules_per_list = 1;
    budget_error(candidate(text, false, limits), "max_rules_per_list");
    limits.max_rules_per_list = 2;
    limits.max_rule_bytes -= 1;
    budget_error(candidate(text, false, limits), "max_rule_bytes");
    let packs = [
        PackSource {
            list_id: "a",
            content: "#é\n",
        },
        PackSource {
            list_id: "b",
            content: "#é\n",
        },
    ];
    let mut limits = RuleCompileLimits {
        max_lists: 2,
        max_total_bytes: 8,
        ..Default::default()
    };
    compile_isolated(&packs, &[], limits).unwrap();
    limits.max_lists = 1;
    budget_error(compile_isolated(&packs, &[], limits), "max_lists");
    limits.max_lists = 2;
    limits.max_total_bytes = 7;
    budget_error(compile_isolated(&packs, &[], limits), "max_total_bytes");
}

#[test]
fn projection_store_profile_and_total_boundaries_precede_regex_compile() {
    for (text, fields) in [
        (
            "a.test$important\nb.test$important",
            [
                "max_store_indexed_rules",
                "max_indexed_rules_per_profile",
                "max_indexed_rules_total",
            ],
        ),
        (
            "*.a.test$noapex\n*.b.test$noapex",
            [
                "max_store_advanced_rules",
                "max_advanced_rules_per_profile",
                "max_advanced_rules_total",
            ],
        ),
        (
            "/a/\n/b/",
            [
                "max_store_regex_rules",
                "max_regex_rules_per_profile",
                "max_regex_rules_total",
            ],
        ),
    ] {
        for field_name in fields {
            let (_, field) = RuleCompileLimits::fields()
                .into_iter()
                .find(|(name, _)| *name == field_name)
                .unwrap();
            let mut limits = RuleCompileLimits::default();
            *field(&mut limits) = 2;
            candidate(text, false, limits).unwrap();
            *field(&mut limits) = 1;
            budget_error(candidate(text, false, limits), field_name);
        }
    }
    let limits = RuleCompileLimits {
        max_store_advanced_rules: 1,
        ..Default::default()
    };
    budget_error(
        candidate("/(broken/\n/other/", false, limits),
        "max_store_advanced_rules",
    );
    let limits = RuleCompileLimits {
        max_regex_rules_per_profile: 1,
        ..Default::default()
    };
    budget_error(
        candidate("/(broken/\n/other/", false, limits),
        "max_regex_rules_per_profile",
    );
    let limits = RuleCompileLimits {
        max_store_indexed_rules: 1,
        ..Default::default()
    };
    budget_error(
        candidate("*.a.test\nb.test", false, limits),
        "max_store_indexed_rules",
    );
    candidate("*.a.test$noapex\nb.test", false, limits).unwrap();
}

#[test]
fn declared_unmounted_packs_and_repeated_profile_mounts_consume_quota() {
    let packs = [
        PackSource {
            list_id: "a",
            content: "example.test",
        },
        PackSource {
            list_id: "b",
            content: "EXAMPLE.test",
        },
    ];
    let limits = RuleCompileLimits {
        max_store_indexed_rules: 1,
        ..Default::default()
    };
    budget_error(
        compile_isolated(&packs, &[], limits),
        "max_store_indexed_rules",
    );
    let c = compile_isolated(&packs, &[], RuleCompileLimits::default()).unwrap();
    assert_eq!(c.cost().store_counts.indexed, 2);
    assert_eq!(c.cost().profile_counts_total.indexed, 0);
    let profiles = [
        ProfileMounts {
            profile_id: "one",
            custom_lists: &["a", "b"],
            block_all: false,
        },
        ProfileMounts {
            profile_id: "two",
            custom_lists: &["a", "b"],
            block_all: false,
        },
    ];
    let limits = RuleCompileLimits {
        max_indexed_rules_per_profile: 2,
        max_indexed_rules_total: 4,
        ..Default::default()
    };
    let c = compile_isolated(&packs, &profiles, limits).unwrap();
    assert_eq!(c.cost().profile_counts_total.indexed, 4);
    assert_eq!(c.profiles()[0].1.indexed_domains(), 1);
    let limits = RuleCompileLimits {
        max_indexed_rules_total: 3,
        ..limits
    };
    budget_error(
        compile_isolated(&packs, &profiles, limits),
        "max_indexed_rules_total",
    );
}

#[test]
fn regex_sharing_counts_programs_separately_from_evaluable_rules() {
    let packs = [
        PackSource {
            list_id: "a",
            content: "/example/\n@@/example/",
        },
        PackSource {
            list_id: "b",
            content: "/example/",
        },
    ];
    let profiles = [
        ProfileMounts {
            profile_id: "one",
            custom_lists: &["a", "b"],
            block_all: false,
        },
        ProfileMounts {
            profile_id: "two",
            custom_lists: &["a"],
            block_all: false,
        },
    ];
    let c = compile_isolated(&packs, &profiles, RuleCompileLimits::default()).unwrap();
    let cost = c.cost();
    let charge = 2 * (1 << 20) + 65536;
    assert_eq!(cost.regex_programs, 1);
    assert_eq!(cost.store_counts.regex, 3);
    assert_eq!(cost.profile_counts_total.regex, 5);
    assert_eq!(
        cost.profile_bytes_total - cost.profile_owned_bytes_total,
        2 * charge
    );
    assert_eq!(
        cost.snapshot_bytes,
        cost.store_bytes + cost.profile_owned_bytes_total
    );
    for (_, p) in c.profiles() {
        assert_eq!(p.compiled_bytes() - p.owned_bytes(), charge);
    }
    let c = compile("/example/\n/EXAMPLE/\n/(?i)example/");
    assert_eq!(c.cost().regex_programs, 3);
}

#[test]
fn deterministic_cost_golden_and_all_compiled_byte_boundaries() {
    let c = compile("example.test");
    // T(rules)=40, T(example.test)=48; origin=184, AST=80,
    // projection=176, pack=136, root=256, profile=168+176+40 sidecar.
    assert_eq!(
        c.cost(),
        CompiledCostV1 {
            store_bytes: 832,
            profile_bytes_total: 384,
            profile_owned_bytes_total: 384,
            snapshot_bytes: 1216,
            store_counts: ProjectionCounts {
                indexed: 1,
                advanced: 0,
                regex: 0
            },
            profile_counts_total: ProjectionCounts {
                indexed: 1,
                advanced: 0,
                regex: 0
            },
            regex_programs: 0,
        }
    );
    for (field_name, value) in [
        ("max_store_compiled_bytes", 832),
        ("max_compiled_bytes_per_profile", 384),
        ("max_compiled_bytes_total", 1216),
    ] {
        let (_, field) = RuleCompileLimits::fields()
            .into_iter()
            .find(|(name, _)| *name == field_name)
            .unwrap();
        let mut limits = RuleCompileLimits::default();
        *field(&mut limits) = value;
        candidate("example.test", false, limits).unwrap();
        *field(&mut limits) = value - 1;
        budget_error(candidate("example.test", false, limits), field_name);
    }
    let unmounted = compile_isolated(
        &[PackSource {
            list_id: "rules",
            content: "example.test",
        }],
        &[],
        RuleCompileLimits::default(),
    )
    .unwrap();
    assert_eq!(unmounted.cost().store_bytes, c.cost().store_bytes);
    let duplicate = compile("example.test\nexample.test");
    assert_eq!(duplicate.cost().store_bytes, c.cost().store_bytes + 48);
    let limits = RuleCompileLimits {
        max_store_compiled_bytes: 128,
        ..Default::default()
    };
    budget_error(
        compile_isolated(
            &[PackSource {
                list_id: "empty",
                content: "# comment",
            }],
            &[],
            limits,
        ),
        "max_store_compiled_bytes",
    );
}

#[test]
fn arithmetic_overflow_is_an_error_not_a_wrapped_budget() {
    use super::limits::{add, mul};
    for result in [
        add(usize::MAX, 1),
        mul(usize::MAX, 2),
        CompiledCostV1::aligned_bytes(usize::MAX),
        CompiledCostV1::text_bytes(usize::MAX),
        CompiledCostV1::origin_bytes(1, usize::MAX),
        CompiledCostV1::ast_bytes(usize::MAX),
        CompiledCostV1::indexed_bytes(usize::MAX),
        CompiledCostV1::advanced_bytes(usize::MAX),
        CompiledCostV1::regex_bytes(usize::MAX),
    ] {
        assert_eq!(result.unwrap_err().actual, None);
    }
    for i in 0..3 {
        let mut counts = ProjectionCounts::default();
        match i {
            0 => counts.indexed = usize::MAX,
            1 => counts.advanced = usize::MAX,
            _ => counts.regex = usize::MAX,
        }
        assert!(counts
            .checked_add(ProjectionCounts {
                indexed: 1,
                advanced: 1,
                regex: 1
            })
            .is_err());
    }
    assert_eq!(CompiledCostV1::aligned_bytes(8).unwrap(), 8);
    assert_eq!(CompiledCostV1::aligned_bytes(9).unwrap(), 16);
}

#[test]
fn regex_limits_are_enforced_without_changing_the_historical_wrapper() {
    let limits = RuleCompileLimits {
        max_regex_program_bytes: 1,
        ..Default::default()
    };
    assert!(matches!(
        candidate("/a{100}/", false, limits),
        Err(CompileError::RegexBudgetExceeded { .. })
    ));
    assert!(parse_rule_checked("/a{100}/").is_ok());
    let limits = RuleCompileLimits {
        max_regex_program_bytes: 2 << 20,
        ..Default::default()
    };
    let c = candidate("/example/", false, limits).unwrap();
    assert_eq!(
        profile(&c).compiled_bytes() - profile(&c).owned_bytes(),
        2 * (2 << 20) + 65536
    );
    assert!(parse_rule_checked("/a{200000}/").is_err());
}

#[test]
fn query_types_are_copy_and_compact() {
    fn is_copy<T: Copy>() {}
    is_copy::<RuleToken>();
    is_copy::<RuleTier>();
    is_copy::<RuleHit<'_>>();
    is_copy::<AllowGrant>();
    is_copy::<RequestGrant<'_>>();
    assert_eq!(std::mem::size_of::<RuleToken>(), 4);
    assert_eq!(std::mem::size_of::<RuleTier>(), 1);
    assert!(std::mem::size_of::<RankedHit>() <= 8);
    assert!(std::mem::size_of::<RuleHit<'_>>() <= 24);
    assert!(std::mem::size_of::<AllowGrant>() <= 8);
    assert!(std::mem::size_of::<RuleDecision<'_>>() <= 32);
    assert!(std::mem::size_of::<TargetDecision<'_>>() <= 32);
}

#[test]
fn owned_original_grant_drives_target_lattice() {
    let compiled = compile("@@query.test\ntarget.test$important");
    let profile = profile(&compiled);
    let request = profile.evaluate_attributed("query.test", ExternalMatches::None);
    assert_eq!(request.verdict(), Verdict::Forward);
    let grant = request.grant();
    assert_eq!(
        profile
            .evaluate_target_with_grant("target.test", grant.as_ref(), ExternalMatches::None, true)
            .verdict(),
        Verdict::Block,
        "important target deny outranks an ordinary original-QNAME grant"
    );
    assert_eq!(
        profile
            .evaluate_target_with_grant("clean.test", grant.as_ref(), ExternalMatches::Deny, true)
            .verdict(),
        Verdict::Forward,
        "the same original grant uniformly outranks external target blocks"
    );
}

#[test]
fn no_request_grant_cannot_bypass_external_target_deny() {
    let compiled = compile("");
    let profile = profile(&compiled);

    assert_eq!(
        profile
            .evaluate_target_with_grant("clean.test", None, ExternalMatches::Deny, true)
            .verdict(),
        Verdict::Block,
        "a GrantTier is not public evaluation authority"
    );
}

#[test]
fn inherited_grant_and_target_rule_keep_attribution_distinct() {
    let compiled = compile("@@query.test\ntarget.test$important");
    let profile = profile(&compiled);
    let grant = profile
        .evaluate_attributed("query.test", ExternalMatches::None)
        .grant();

    let inherited = profile.evaluate_target_with_grant(
        "clean.test",
        grant.as_ref(),
        ExternalMatches::Deny,
        true,
    );
    assert_eq!(inherited.verdict(), Verdict::Forward);
    assert!(inherited.winning_rule().is_none());
    assert_eq!(
        inherited.inherited_granting_rule().map(|hit| hit.tier()),
        Some(RuleTier::OrdinaryAllow),
        "response authority retains the original-QNAME attribution"
    );

    let local_winner = profile.evaluate_target_with_grant(
        "target.test",
        grant.as_ref(),
        ExternalMatches::None,
        true,
    );
    assert_eq!(local_winner.verdict(), Verdict::Block);
    assert_eq!(
        local_winner.winning_rule().map(|hit| hit.tier()),
        Some(RuleTier::ImportantDeny),
        "a target-local winner remains attributable"
    );
}

#[test]
fn request_grant_cannot_cross_profile_or_snapshot() {
    let packs = [PackSource {
        list_id: "rules",
        content: "@@query.test",
    }];
    let mounts = [
        ProfileMounts {
            profile_id: "one",
            custom_lists: &["rules"],
            block_all: false,
        },
        ProfileMounts {
            profile_id: "two",
            custom_lists: &[],
            block_all: false,
        },
    ];
    let compiled = compile_isolated(&packs, &mounts, RuleCompileLimits::default()).unwrap();
    let one = compiled.profile(&Id::new("one").unwrap()).unwrap();
    let two = compiled.profile(&Id::new("two").unwrap()).unwrap();
    let grant = one
        .evaluate_attributed("query.test", ExternalMatches::None)
        .grant()
        .expect("allow rule issues a request grant");

    assert!(grant.is_issued_by(one));
    assert!(!grant.is_issued_by(two));
    assert_eq!(
        two.evaluate_target_with_grant("clean.test", Some(&grant), ExternalMatches::Deny, true,)
            .verdict(),
        Verdict::Block,
        "a grant from another profile cannot bypass its external target deny"
    );

    let replacement = compile("@@query.test");
    let reloaded = profile(&replacement);
    assert!(!grant.is_issued_by(reloaded));
    assert_eq!(
        reloaded
            .evaluate_target_with_grant("clean.test", Some(&grant), ExternalMatches::Deny, true,)
            .verdict(),
        Verdict::Block,
        "a matching profile in a replacement snapshot cannot replay a grant"
    );
}
