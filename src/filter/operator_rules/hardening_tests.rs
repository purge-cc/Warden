use std::sync::{Arc, Barrier};

use super::*;

fn packs(content: &str) -> [PackSource<'_>; 1] {
    [PackSource {
        list_id: "rules",
        content,
    }]
}

fn mounts() -> [ProfileMounts<'static>; 1] {
    [ProfileMounts {
        profile_id: "profile",
        custom_lists: &["rules"],
        block_all: false,
    }]
}

#[test]
fn target_allow_cannot_authorize_second_target_or_response_ip() {
    for grant in [
        "@@first.test",
        "@@first.test$important",
        "@@*.first.test",
        "@@/first/",
    ] {
        let c = compile_isolated(
            &packs(&format!("{grant}\nsecond.test")),
            &mounts(),
            RuleCompileLimits::default(),
        )
        .unwrap();
        let request = c.profiles()[0]
            .1
            .evaluate_attributed("original.test", ExternalMatches::None);
        let first = request.evaluate_target("first.test", ExternalMatches::Deny, true);
        assert_eq!(first.verdict(), Verdict::Forward);
        assert!(first.winning_rule().unwrap().tier().is_allow());
        assert_eq!(
            request
                .evaluate_target("second.test", ExternalMatches::None, true)
                .verdict(),
            Verdict::Block
        );
        assert_eq!(
            request
                .evaluate_target("external.test", ExternalMatches::Deny, true)
                .verdict(),
            Verdict::Block
        );
        assert_eq!(request.response_ip_verdict(true, true), Verdict::Block);
        assert_eq!(request.grant_tier(), None);
    }
}

#[test]
fn explain_keeps_mounted_losers_duplicates_and_wildcard_apex() {
    let c = compile_isolated(
        &[
            PackSource {
                list_id: "a",
                content: "example.test\nEXAMPLE.test\n@@example.test",
            },
            PackSource {
                list_id: "b",
                content: "example.test\n*.example.test$important\n*.example.test$noapex",
            },
            PackSource {
                list_id: "unmounted",
                content: "@@example.test$important\n@@/example/",
            },
        ],
        &[ProfileMounts {
            profile_id: "profile",
            custom_lists: &["b", "a"],
            block_all: false,
        }],
        RuleCompileLimits::default(),
    )
    .unwrap();
    let p = &c.profiles()[0].1;
    assert_eq!(p.indexed_domains(), 1);
    assert_eq!(p.mounted_rules().len(), 5);
    let apex: Vec<_> = p.explain("example.test").collect();
    assert_eq!(apex.len(), 4);
    assert_eq!(
        apex.iter()
            .filter(|entry| entry.rule.tier() == RuleTier::OrdinaryDeny)
            .count(),
        2
    );
    assert_eq!(
        apex.iter()
            .filter(|entry| entry.rule.origin().list_id().as_str() == "unmounted")
            .count(),
        0
    );
    assert_eq!(
        apex.iter()
            .map(|entry| entry.rule.origin().source_rows().len())
            .sum::<usize>(),
        5
    );
    let winner = p.lookup("example.test").unwrap();
    assert_eq!(winner.tier(), RuleTier::ImportantDeny);
    let wildcard = apex
        .iter()
        .find(|entry| entry.projection == MatchProjection::WildcardApex)
        .unwrap();
    assert_eq!(wildcard.rule, winner);
    let children: Vec<_> = p.explain("deep.sub.example.test").collect();
    assert_eq!(children.len(), 5);
    assert_eq!(
        children
            .iter()
            .filter(|entry| entry.projection == MatchProjection::WildcardDescendant)
            .count(),
        2
    );
    let child = children
        .iter()
        .find(|entry| entry.rule.tier() == RuleTier::ImportantDeny)
        .unwrap();
    assert!(std::ptr::eq(child.rule.origin(), wildcard.rule.origin()));
    assert_eq!(p.explain("unmatched.test").count(), 0);
    let reversed = compile_isolated(
        &packs("@@example.test\nexample.test"),
        &mounts(),
        RuleCompileLimits::default(),
    )
    .unwrap();
    assert_ne!(
        p.lookup("example.test"),
        reversed.profiles()[0].1.lookup("example.test")
    );
}

#[test]
fn sidecar_is_charged_before_merged_slots_and_before_regex_build() {
    let limits = RuleCompileLimits::default();
    let one = compile_isolated(&packs("example.test"), &mounts(), limits).unwrap();
    let two = compile_isolated(&packs("example.test\n@@example.test"), &mounts(), limits).unwrap();
    assert_eq!(
        one.profiles()[0].1.indexed_domains(),
        two.profiles()[0].1.indexed_domains()
    );
    assert!(two.cost().snapshot_bytes > one.cost().snapshot_bytes);
    assert_eq!(CompiledCostV1::sidecar_bytes(0).unwrap(), 32);
    assert_eq!(CompiledCostV1::sidecar_bytes(3).unwrap(), 48);
    assert!(CompiledCostV1::sidecar_bytes(usize::MAX).is_err());
    let p = &one.profiles()[0].1;
    let limits = RuleCompileLimits {
        max_compiled_bytes_per_profile: p.compiled_bytes() - 1,
        ..limits
    };
    assert!(matches!(
        compile_isolated(&packs("example.test"), &mounts(), limits),
        Err(CompileError::BudgetExceeded(BudgetExceeded {
            limit: "max_compiled_bytes_per_profile",
            ..
        }))
    ));
    let reference = compile_isolated(
        &packs("example.test\n/allowed/"),
        &mounts(),
        RuleCompileLimits::default(),
    )
    .unwrap();
    let limits = RuleCompileLimits {
        max_compiled_bytes_per_profile: reference.profiles()[0].1.compiled_bytes() - 1,
        ..Default::default()
    };
    assert!(matches!(
        compile_isolated(&packs("example.test\n/(broken/"), &mounts(), limits),
        Err(CompileError::BudgetExceeded(BudgetExceeded {
            limit: "max_compiled_bytes_per_profile",
            ..
        }))
    ));
}

#[test]
fn admission_refuses_before_invalid_regex_and_releases_failed_builds() {
    let limits = RuleCompileLimits::default();
    let admission = CompileAdmission::new(limits.max_compiled_bytes_total - 1, 1).unwrap();
    assert!(matches!(
        CompiledOperatorRules::compile(&packs("/(invalid/"), &mounts(), limits, &admission),
        Err(CompileError::BudgetExceeded(BudgetExceeded {
            limit: "admission_bytes",
            ..
        }))
    ));
    assert_eq!(admission.active_builds(), 0);
    assert_eq!(admission.reserved_bytes(), 0);
    let admission = CompileAdmission::new(limits.max_compiled_bytes_total, 1).unwrap();
    for content in ["/(invalid/", "bad..test", "/a{200000}/"] {
        assert!(
            CompiledOperatorRules::compile(&packs(content), &mounts(), limits, &admission).is_err()
        );
        assert_eq!(admission.active_builds(), 0);
        assert_eq!(admission.reserved_bytes(), 0);
    }
    assert!(CompileAdmission::new(0, 1).is_err());
    assert!(CompileAdmission::new(1, 0).is_err());
}

#[test]
fn admission_counts_active_staging_and_arc_retained_generations() {
    let limits = RuleCompileLimits {
        max_compiled_bytes_total: 4096,
        ..Default::default()
    };
    let admission = CompileAdmission::new(8192, 1).unwrap();
    let first = Arc::new(
        CompiledOperatorRules::compile(&packs("@@query.test"), &mounts(), limits, &admission)
            .unwrap(),
    );
    let cost = first.cost().snapshot_bytes;
    let active = arc_swap::ArcSwap::from(Arc::clone(&first));
    let retained = active.load_full();
    drop(first);
    let request = retained.profiles()[0]
        .1
        .evaluate_attributed("query.test", ExternalMatches::None);
    let staging = admission.begin(4096).unwrap();
    assert_eq!(admission.reserved_bytes(), cost + 4096);
    assert!(matches!(
        CompiledOperatorRules::compile(&packs("/(invalid/"), &mounts(), limits, &admission),
        Err(CompileError::BudgetExceeded(BudgetExceeded {
            limit: "concurrent_builds",
            ..
        }))
    ));
    drop(staging);
    let second = Arc::new(
        CompiledOperatorRules::compile(&packs("query.test"), &mounts(), limits, &admission)
            .unwrap(),
    );
    let second_cost = second.cost().snapshot_bytes;
    active.store(second);
    assert_eq!(admission.reserved_bytes(), cost + second_cost);
    assert_eq!(request.response_ip_verdict(true, true), Verdict::Forward);
    assert_eq!(
        active.load().profiles()[0]
            .1
            .evaluate("query.test", ExternalMatches::None),
        Verdict::Block
    );
    assert_eq!(
        request.winning_rule().unwrap().origin().rule_key(),
        parse_rule_ast("@@query.test").unwrap().rule_key()
    );
    drop(retained);
    assert_eq!(admission.reserved_bytes(), second_cost);
    drop(active);
    assert_eq!(admission.reserved_bytes(), 0);
    assert_eq!(admission.active_builds(), 0);
}

#[test]
fn retained_arc_blocks_admission_until_its_last_owner_drops() {
    let limits = RuleCompileLimits {
        max_compiled_bytes_total: 1 << 18,
        max_regex_program_bytes: 4096,
        ..Default::default()
    };
    let admission = CompileAdmission::new(limits.max_compiled_bytes_total, 1).unwrap();
    let snapshot = Arc::new(
        CompiledOperatorRules::compile(&packs("query.test"), &mounts(), limits, &admission)
            .unwrap(),
    );
    let retained = Arc::clone(&snapshot);
    drop(snapshot);
    assert!(matches!(
        CompiledOperatorRules::compile(&packs("/(invalid/"), &mounts(), limits, &admission),
        Err(CompileError::BudgetExceeded(BudgetExceeded {
            limit: "admission_bytes",
            ..
        }))
    ));
    drop(retained);
    assert!(matches!(
        CompiledOperatorRules::compile(&packs("/(invalid/"), &mounts(), limits, &admission),
        Err(CompileError::InvalidRegex { .. })
    ));
    let next = CompiledOperatorRules::compile(&packs("other.test"), &mounts(), limits, &admission)
        .unwrap();
    assert_eq!(admission.reserved_bytes(), next.cost().snapshot_bytes);
    drop(next);
    assert_eq!(admission.reserved_bytes(), 0);
}

#[test]
fn admission_unwinding_releases_both_reservations() {
    let admission = CompileAdmission::new(4096, 1).unwrap();
    assert!(std::panic::catch_unwind(|| {
        let _lease = admission.begin(4096).unwrap();
        panic!("abandon builder");
    })
    .is_err());
    assert_eq!(admission.reserved_bytes(), 0);
    assert_eq!(admission.active_builds(), 0);
}

#[test]
fn simultaneous_compiles_retain_their_charges_until_readers_release() {
    let limits = RuleCompileLimits::default();
    let admission = CompileAdmission::new(8 * limits.max_compiled_bytes_total, 8).unwrap();
    let start = Barrier::new(9);
    let ready = Barrier::new(9);
    let release = Barrier::new(9);
    let charges = std::sync::atomic::AtomicUsize::new(0);
    std::thread::scope(|scope| {
        let handles: Vec<_> = (0..8)
            .map(|_| {
                scope.spawn(|| {
                    start.wait();
                    let snapshot = CompiledOperatorRules::compile(
                        &packs(r"/\bélan\b/"),
                        &mounts(),
                        limits,
                        &admission,
                    )
                    .map(Arc::new);
                    if let Ok(snapshot) = &snapshot {
                        charges.fetch_add(
                            snapshot.cost().snapshot_bytes,
                            std::sync::atomic::Ordering::Relaxed,
                        );
                    }
                    ready.wait();
                    release.wait();
                    let snapshot = snapshot.unwrap();
                    let request = snapshot.profiles()[0]
                        .1
                        .evaluate_attributed("élan.test", ExternalMatches::None);
                    assert_eq!(request.verdict(), Verdict::Block);
                    drop(snapshot);
                })
            })
            .collect();
        start.wait();
        ready.wait();
        let builds = admission.active_builds();
        let reserved = admission.reserved_bytes();
        release.wait();
        for handle in handles {
            handle.join().unwrap();
        }
        assert_eq!(builds, 0);
        assert_eq!(reserved, charges.load(std::sync::atomic::Ordering::Relaxed));
    });
    assert_eq!(admission.reserved_bytes(), 0);
}

#[test]
fn admission_races_never_overbook_bytes_or_build_slots() {
    for (max_bytes, max_builds, accepted) in [(30, 4, 3), (100, 2, 2)] {
        let admission = CompileAdmission::new(max_bytes, max_builds).unwrap();
        let start = Barrier::new(17);
        let ready = Barrier::new(17);
        let release = Barrier::new(17);
        std::thread::scope(|scope| {
            let workers: Vec<_> = (0..16)
                .map(|_| {
                    scope.spawn(|| {
                        start.wait();
                        let lease = admission.begin(10);
                        ready.wait();
                        release.wait();
                        lease.is_ok()
                    })
                })
                .collect();
            start.wait();
            ready.wait();
            let reserved = admission.reserved_bytes();
            let builds = admission.active_builds();
            release.wait();
            assert_eq!(
                workers
                    .into_iter()
                    .map(|worker| worker.join().unwrap())
                    .filter(|accepted| *accepted)
                    .count(),
                accepted
            );
            assert_eq!(reserved, accepted * 10);
            assert_eq!(builds, accepted);
        });
        assert_eq!(admission.reserved_bytes(), 0);
        assert_eq!(admission.active_builds(), 0);
    }
}

#[test]
fn regex_syntax_and_budget_failures_have_distinct_context() {
    for (source, limit, syntax) in [
        ("/(invalid/", 1 << 20, true),
        ("/[z-a]/", 1 << 20, true),
        ("/a{200000}/", 1 << 20, false),
        ("/a/", 64, false),
    ] {
        let limits = RuleCompileLimits {
            max_regex_program_bytes: limit,
            ..Default::default()
        };
        let error = compile_isolated(&packs(&format!("# header\n{source}")), &mounts(), limits)
            .unwrap_err();
        match error {
            CompileError::InvalidRegex { list, row, .. } if syntax => {
                assert_eq!(list.as_str(), "rules");
                assert_eq!(row, 2);
            }
            CompileError::RegexBudgetExceeded {
                list, row, source, ..
            } if !syntax => {
                assert_eq!(list.as_str(), "rules");
                assert_eq!(row, 2);
                assert_eq!(source.limit, "max_regex_program_bytes");
                assert_eq!(source.maximum, limit);
            }
            error => panic!("wrong regex error class: {error:?}"),
        }
    }
    assert_eq!(CompiledCostV1::VERSION, 2);
}

#[test]
fn regex_unicode_inline_flags_and_boundary_parity() {
    let patterns = [
        r"EXAMPLE",
        r"(?-i)EXAMPLE",
        r"(?i:EXAMPLE)(?-i:Ab)",
        r"\p{Greek}+",
        r"\p{L}+",
        r"\d+",
        r"\D+",
        r"k",
        r"s",
        r"é",
        r"(?s:a.*b)",
        r"(?m:^a$)",
        r"(?mR:^a$)",
        r"\A(?:a|é)*\z",
        r"\bword\b",
        r"\bélan\b",
        r"\Bé\B",
        r"(?-u:\b)a\b",
        r"\b(?-u:\B)é",
        r"\b{start}é",
        r"é\b{end}",
        r"\b{start-half}é",
        r"é\b{end-half}",
        r"(?:\b|\B)*é",
        r"(?:\b)*",
        r"\b(?m:^a$)",
        r"(?:\bword\b|☃)",
        r"(?-u:\B)|\bword",
        r"\b(?:a|é)?\B",
        r"(?x) a \# b",
    ];
    let texts = [
        "",
        "example",
        "EXAMPLE",
        "exampleAb",
        "EXAMPLEab",
        "αβ",
        "ΑΒ",
        "é",
        "É",
        "K",
        "ſ",
        "١٢٣",
        "a\nb",
        "a\r\na",
        "word",
        " word ",
        "éwordé",
        "élan",
        "!élan!",
        "xéy",
        "☃",
        "😀",
        "a\u{301}",
        "a#b",
        "中",
        "a",
        "aé",
        "éa",
    ];
    for pattern in patterns {
        let old = ::regex::RegexBuilder::new(pattern)
            .case_insensitive(true)
            .build()
            .unwrap();
        let new =
            super::regex::RegexProgram::compile(pattern, true, 1 << 20).unwrap_or_else(|error| {
                panic!(
                    "{}",
                    error.context(
                        crate::config::schema::id::Id::new("rules").unwrap(),
                        1,
                        1 << 20
                    )
                )
            });
        for text in texts {
            assert_eq!(
                new.is_match(text),
                old.is_match(text),
                "{pattern:?} / {text:?}"
            );
        }
    }
}

#[test]
fn unicode_boundary_dense_matches_generated_utf8_corpus() {
    let alphabet = ["a", "é", "!", "\n", "\r", "中", "\u{301}", "😀"];
    for pattern in [
        r"\b(?:a|é)+\b",
        r"\B(?:é|中)",
        r"(?-u:\b)é|\b{end-half}",
        r"(?mR:^é$)|\b{start-half}a",
    ] {
        let old = ::regex::RegexBuilder::new(pattern)
            .case_insensitive(true)
            .build()
            .unwrap();
        let new = super::regex::RegexProgram::compile(pattern, true, 1 << 20)
            .unwrap_or_else(|_| panic!("failed {pattern}"));
        for a in alphabet {
            for b in alphabet {
                for c in alphabet {
                    let text = format!("{a}{b}{c}");
                    assert_eq!(
                        new.is_match(&text),
                        old.is_match(&text),
                        "{pattern:?} / {text:?}"
                    );
                }
            }
        }
    }
}
