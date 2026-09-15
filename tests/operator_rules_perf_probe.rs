//! Opt-in, bounded, in-process lookup probe. It opens no sockets and changes no
//! files or services. Percentiles include clock/scheduling overhead and are not
//! end-to-end DNS latency or evidence of the performance acceptance gate.

use std::collections::HashSet;
use std::hint::black_box;
use std::sync::{Arc, Barrier};
use std::time::Instant;

use ahash::RandomState;
use purge_warden::filter::engine::{FilterEngine, FilterResult};
use purge_warden::filter::operator_rules::{
    CompileAdmission, CompiledOperatorRules, ExternalMatches, PackSource, ProfileMounts,
    RuleCompileLimits, Verdict,
};
use purge_warden::filter::rules::{parse_rules, RuleAction};
use purge_warden::profiles::profile::ResolvedProfile;

#[global_allocator]
static ALLOCATOR: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

const SAMPLES: usize = 10_000;
const WARMUP: usize = 1_000;
const EXACT_RULES: usize = 1_000;

fn memory(label: &str, admission: &CompileAdmission) {
    let status = std::fs::read_to_string("/proc/self/status").ok();
    let kib = |field: &str| {
        status.as_deref().and_then(|status| {
            status.lines().find_map(|line| {
                line.strip_prefix(field)?
                    .split_whitespace()
                    .next()?
                    .parse::<u64>()
                    .ok()
            })
        })
    };
    eprintln!(
        "{label}: rss_kib={:?} process_peak_kib={:?} reserved_quota_bytes={} active_builds={}",
        kib("VmRSS:"),
        kib("VmHWM:"),
        admission.reserved_bytes(),
        admission.active_builds()
    );
}

fn report(label: &str, mut ns: Vec<u64>) {
    ns.sort_unstable();
    let percentile = |p: usize| ns[(ns.len() * p).div_ceil(100).saturating_sub(1)];
    eprintln!(
        "{label}: samples={} p50_ns={} p99_ns={}",
        ns.len(),
        percentile(50),
        percentile(99)
    );
}

fn sample(mut lookup: impl FnMut()) -> Vec<u64> {
    let mut ns = Vec::with_capacity(SAMPLES);
    for _ in 0..WARMUP {
        lookup();
    }
    for _ in 0..SAMPLES {
        let start = Instant::now();
        lookup();
        ns.push(start.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64);
    }
    ns
}

fn compile(
    content: &str,
    limits: RuleCompileLimits,
    admission: &CompileAdmission,
) -> Arc<CompiledOperatorRules> {
    Arc::new(
        CompiledOperatorRules::compile(
            &[PackSource {
                list_id: "probe",
                content,
            }],
            &[ProfileMounts {
                profile_id: "probe",
                custom_lists: &["probe"],
                block_all: false,
            }],
            limits,
            admission,
        )
        .unwrap(),
    )
}

fn baseline(content: &str) -> ResolvedProfile {
    let mut profile = ResolvedProfile::permissive_default();
    profile.unfiltered = true;
    let mut allow = HashSet::with_hasher(RandomState::new());
    let mut deny = HashSet::with_hasher(RandomState::new());
    let mut advanced = Vec::new();
    for line in content.lines() {
        for rule in parse_rules(line) {
            if rule.is_simple_exact() {
                let set = if rule.action == RuleAction::Allow {
                    &mut allow
                } else {
                    &mut deny
                };
                set.insert(rule.exact_domain().unwrap().clone());
            } else {
                advanced.push(rule);
            }
        }
    }
    profile.allow_domains = Arc::new(allow);
    profile.deny_domains = Arc::new(deny);
    profile.rules = Arc::new(advanced);
    profile
}

#[test]
#[ignore = "manual jemalloc/RSS/latency probe; run in release mode with --ignored --nocapture"]
fn operator_rules_perf_probe() {
    let limits = RuleCompileLimits::default();
    let admission = CompileAdmission::new(3 * limits.max_compiled_bytes_total, 1).unwrap();
    eprintln!("lookup-only probe: os={} arch={} parallelism={:?} debug_assertions={} samples={SAMPLES} warmup={WARMUP} exact_rules={EXACT_RULES}; allocator=production jemalloc; allocation counts are covered separately by unit tests; no measured acceptance claimed",
        std::env::consts::OS, std::env::consts::ARCH, std::thread::available_parallelism(), cfg!(debug_assertions));
    memory("initial", &admission);
    report(
        "clock-control",
        sample(|| {
            black_box(());
        }),
    );
    for allow in [false, true] {
        for important in [false, true] {
            let content = (0..EXACT_RULES)
                .map(|i| {
                    format!(
                        "{}tracker{i}.example.test{}\n",
                        if allow { "@@" } else { "" },
                        if important { "$important" } else { "" }
                    )
                })
                .collect::<String>();
            let old = baseline(&content);
            let engine = FilterEngine::new();
            let compiled = compile(&content, limits, &admission);
            let profile = &compiled.profiles()[0].1;
            for (case, name) in [
                ("hit", "tracker42.example.test"),
                ("suffix", "long.sub.tracker42.example.test"),
                ("miss", "unmatched.other.test"),
            ] {
                let forward = allow || case == "miss";
                assert_eq!(
                    engine.evaluate(name, &old) == FilterResult::Forward,
                    forward
                );
                assert_eq!(
                    profile.evaluate(name, ExternalMatches::Disabled) == Verdict::Forward,
                    forward
                );
                for attributed in [false, true] {
                    let label = format!(
                        "allow={allow}/important={important}/{case}/attributed={attributed}"
                    );
                    // Alternate order to avoid always giving one engine the
                    // same thermal/scheduling position. Repeat independent runs
                    // on the same host/build before drawing any conclusion.
                    for target_first in [false, true] {
                        let old_probe = || {
                            sample(|| {
                                if attributed {
                                    black_box(
                                        engine
                                            .evaluate_attributed(black_box(name), black_box(&old)),
                                    );
                                } else {
                                    black_box(engine.evaluate(black_box(name), black_box(&old)));
                                }
                            })
                        };
                        let new_probe = || {
                            sample(|| {
                                if attributed {
                                    let _ = black_box(profile.evaluate_attributed(
                                        black_box(name),
                                        ExternalMatches::Disabled,
                                    ));
                                } else {
                                    black_box(
                                        profile
                                            .evaluate(black_box(name), ExternalMatches::Disabled),
                                    );
                                }
                            })
                        };
                        let (before, after) = if target_first {
                            let after = new_probe();
                            (old_probe(), after)
                        } else {
                            let before = old_probe();
                            (before, new_probe())
                        };
                        report(&format!("v4/{label}/target_first={target_first}"), before);
                        report(&format!("v5/{label}/target_first={target_first}"), after);
                    }
                }
            }
            memory("exact fixture retained", &admission);
        }
    }

    let workers = std::thread::available_parallelism()
        .map_or(1, usize::from)
        .min(4);
    let long_miss = format!(
        "{}.{}.{}.{}.test",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(56)
    );
    assert_eq!(long_miss.len(), 253);
    // Keep regex reservation and input bounded while exercising the actual
    // default and hard advanced-scan counts. This is not a claim that all
    // independent rule-count and byte ceilings can be saturated together.
    for count in [
        0,
        limits.max_advanced_rules_per_profile,
        RuleCompileLimits::HARD_CEILINGS.max_advanced_rules_per_profile,
    ] {
        let content = if count == 0 {
            String::new()
        } else {
            let mut content = (0..count - 3)
                .map(|i| format!("*.wild{i}.test$noapex\n"))
                .collect::<String>();
            content.push_str("/^regex[0-9]+\\.test$/\n/^(?:a|aa|aaa|aaaa)+z$/\n/\\bélan\\b/\n");
            content
        };
        let advanced_limits = RuleCompileLimits {
            max_advanced_rules_per_profile: count.max(1),
            ..limits
        };
        let retained = compile(&content, advanced_limits, &admission);
        memory("active generation", &admission);
        let staging_started = Instant::now();
        let staging = compile(&content, advanced_limits, &admission);
        eprintln!(
            "advanced={count} compile_ns={} cost={:?}",
            staging_started.elapsed().as_nanos(),
            staging.cost()
        );
        memory("active plus compiled staging", &admission);
        let active = arc_swap::ArcSwap::from(staging);
        memory("active plus retained previous generation", &admission);
        let profile = &retained.profiles()[0].1;
        let names = [
            &long_miss[..],
            "sub.wild0.test",
            "regex42.test",
            "élan.test",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.test",
        ];
        let barrier = Barrier::new(workers);
        let mut all = Vec::with_capacity(workers * SAMPLES);
        std::thread::scope(|scope| {
            let handles: Vec<_> = (0..workers)
                .map(|worker| {
                    let barrier = &barrier;
                    scope.spawn(move || {
                        let mut timings = Vec::with_capacity(SAMPLES);
                        for i in 0..WARMUP {
                            black_box(
                                profile.evaluate(names[i % names.len()], ExternalMatches::Disabled),
                            );
                        }
                        barrier.wait();
                        for i in 0..SAMPLES {
                            let name = names[(i + worker) % names.len()];
                            let start = Instant::now();
                            let _ =
                                black_box(profile.evaluate_attributed(
                                    black_box(name),
                                    ExternalMatches::Disabled,
                                ));
                            timings
                                .push(start.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64);
                        }
                        timings
                    })
                })
                .collect();
            for handle in handles {
                all.extend(handle.join().unwrap());
            }
        });
        report(&format!("concurrent advanced={count} workers={workers} distribution=equal-five-names max_qname=253"), all);
        drop(retained);
        memory("previous generation released", &admission);
        drop(active);
    }
    memory(
        "all generations released; allocator may retain pages",
        &admission,
    );
    assert_eq!(admission.reserved_bytes(), 0);
    assert_eq!(admission.active_builds(), 0);
}
