use std::collections::HashMap;

use ahash::RandomState;
use compact_str::CompactString;
use criterion::{
    black_box, criterion_group, criterion_main, measurement::WallTime, BenchmarkGroup, Criterion,
    Throughput,
};

use purge_warden::filter::engine::{FilterEngine, FilterResult};
use purge_warden::filter::operator_rules::{
    CompileAdmission, CompiledOperatorRules, CompiledProfile, ExternalMatches, PackSource,
    ProfileMounts, RuleCompileLimits, Verdict,
};
use purge_warden::filter::rules::{parse_rules, RuleAction};
use purge_warden::profiles::profile::ResolvedProfile;

/// Build a domain map with `n` entries like "tracker{i}.example{i/1000}.com".
fn build_domain_map(n: usize) -> HashMap<CompactString, u64, RandomState> {
    let mut map = HashMap::with_capacity_and_hasher(n, RandomState::new());
    for i in 0..n {
        let domain = format!("tracker{}.example{}.com", i, i / 1000);
        map.insert(CompactString::new(&domain), 1u64 << (i % 64));
    }
    map
}

/// `plp-s3`: the subscription lives beside the corpus now, so the caller
/// installs it with `FilterEngine::fixture_subscribe` on the engine it is
/// about to benchmark.
fn build_profile() -> ResolvedProfile {
    ResolvedProfile {
        name: CompactString::new("bench"),
        unfiltered: false,
        allow_domains: Default::default(),
        deny_domains: Default::default(),
        block_all: false,
        rules: std::sync::Arc::new(Vec::new()),
        operator_rules: None,
        block_response: purge_warden::config::schema::BlockResponseV1::Zero,
        blocked_ttl_secs: 60,
        local_records: std::sync::Arc::new(
            purge_warden::dns::local_profile::ProfileLocalRecords::default(),
        ),
        rewrite_rules: std::sync::Arc::new(
            purge_warden::dns::rewrite::ProfileRewriteRules::default(),
        ),
        ecs_policy: purge_warden::profiles::profile::EcsPolicy::OFF,
    }
}

fn bench_list_membership(c: &mut Criterion) {
    let map = build_domain_map(500_000);
    let engine = FilterEngine::with_domain_map(map);

    let mut group = c.benchmark_group("list_membership");

    // Exact hit
    group.bench_function("exact_hit", |b| {
        b.iter(|| engine.list_membership(black_box("tracker42.example0.com")))
    });

    // Subdomain walk (3 labels deep, parent in map)
    group.bench_function("subdomain_walk", |b| {
        b.iter(|| engine.list_membership(black_box("deep.sub.tracker0.example0.com")))
    });

    // Miss (domain not in map at any level)
    group.bench_function("miss", |b| {
        b.iter(|| engine.list_membership(black_box("safe.legit-site.org")))
    });

    group.finish();
}

fn bench_evaluate(c: &mut Criterion) {
    let map = build_domain_map(500_000);
    let engine = FilterEngine::with_domain_map(map);
    let profile = build_profile();
    engine.fixture_subscribe(&profile.name, 0x1); // subscribes to bit 0

    let mut group = c.benchmark_group("evaluate");

    // Blocked domain (bitmask match)
    group.bench_function("blocked", |b| {
        b.iter(|| engine.evaluate(black_box("tracker0.example0.com"), black_box(&profile)))
    });

    // Allowed domain (no match)
    group.bench_function("allowed", |b| {
        b.iter(|| engine.evaluate(black_box("safe.legit-site.org"), black_box(&profile)))
    });

    group.finish();
}

fn bench_arcswap_load(c: &mut Criterion) {
    let engine = FilterEngine::new();
    c.bench_function("arcswap_load_baseline", |b| {
        b.iter(|| engine.list_membership(black_box("example.com")))
    });
}

const EXACT_ENSEMBLE_SIZE: usize = 16;
const EXACT_QUERY_COUNT: usize = 16;
const EXACT_FIXTURE_MASK: usize = EXACT_ENSEMBLE_SIZE - 1;
const EXACT_QUERY_MASK: usize = EXACT_QUERY_COUNT - 1;

const EXACT_HIT_QUERIES: [&str; EXACT_QUERY_COUNT] = [
    "tracker0.example.test",
    "tracker1.example.test",
    "tracker2.example.test",
    "tracker3.example.test",
    "tracker7.example.test",
    "tracker15.example.test",
    "tracker31.example.test",
    "tracker42.example.test",
    "tracker63.example.test",
    "tracker127.example.test",
    "tracker255.example.test",
    "tracker383.example.test",
    "tracker511.example.test",
    "tracker639.example.test",
    "tracker767.example.test",
    "tracker999.example.test",
];

const EXACT_SUFFIX_QUERIES: [&str; EXACT_QUERY_COUNT] = [
    "a.tracker0.example.test",
    "short.tracker1.example.test",
    "a.b.tracker2.example.test",
    "one.two.three.tracker3.example.test",
    "subdomain.tracker7.example.test",
    "alpha.beta.tracker15.example.test",
    "deep.sub.tracker31.example.test",
    "long-query-label.sub.tracker42.example.test",
    "x.y.z.tracker63.example.test",
    "child.tracker127.example.test",
    "nested.child.tracker255.example.test",
    "edge.tracker383.example.test",
    "one.more.label.tracker511.example.test",
    "suffix.tracker639.example.test",
    "many.labels.before.tracker767.example.test",
    "last.tracker999.example.test",
];

const EXACT_MISS_QUERIES: [&str; EXACT_QUERY_COUNT] = [
    "unmatched0.other.test",
    "unmatched1.other.test",
    "safe2.example.invalid",
    "a.b.safe3.example.invalid",
    "legitimate4.other.test",
    "unlisted5.example.invalid",
    "clean6.other.test",
    "deep.clean7.example.invalid",
    "unknown8.other.test",
    "absent9.example.invalid",
    "miss10.other.test",
    "nested.miss11.example.invalid",
    "ordinary12.other.test",
    "no-rule13.example.invalid",
    "long-query-label.safe14.other.test",
    "final15.example.invalid",
];

struct V4ExactFixture {
    engine: FilterEngine,
    profile: ResolvedProfile,
}

struct V5ExactFixture {
    candidate: CompiledOperatorRules,
    // Keep the controller beside the snapshot to make independent admission
    // ownership explicit for the full benchmark lifetime.
    _admission: CompileAdmission,
}

fn build_v4_exact_fixture(content: &str) -> V4ExactFixture {
    let mut profile = build_profile();
    // Disable the external layer so misses measure operator policy in both
    // engines, without a corpus/subscription snapshot on one side.
    profile.unfiltered = true;
    let mut deny = std::collections::HashSet::with_hasher(RandomState::new());
    let mut permits = std::collections::HashSet::with_hasher(RandomState::new());
    let mut advanced = Vec::new();
    for line in content.lines() {
        for rule in parse_rules(line) {
            if rule.is_simple_exact() {
                let set = if rule.action == RuleAction::Allow {
                    &mut permits
                } else {
                    &mut deny
                };
                set.insert(rule.exact_domain().unwrap().clone());
            } else {
                advanced.push(rule);
            }
        }
    }
    profile.allow_domains = std::sync::Arc::new(permits);
    profile.deny_domains = std::sync::Arc::new(deny);
    profile.rules = std::sync::Arc::new(advanced);
    V4ExactFixture {
        engine: FilterEngine::new(),
        profile,
    }
}

fn build_v5_exact_fixture(content: &str) -> V5ExactFixture {
    let limits = RuleCompileLimits::default();
    let admission = CompileAdmission::new(limits.max_compiled_bytes_total, 1).unwrap();
    let candidate = CompiledOperatorRules::compile(
        &[PackSource {
            list_id: "bench-rules",
            content,
        }],
        &[ProfileMounts {
            profile_id: "bench",
            custom_lists: &["bench-rules"],
            block_all: false,
        }],
        limits,
        &admission,
    )
    .unwrap();
    V5ExactFixture {
        candidate,
        _admission: admission,
    }
}

#[inline(always)]
fn next_exact_probe(cursor: &mut usize) -> (usize, usize) {
    let position = *cursor;
    *cursor = position.wrapping_add(1);
    (
        position & EXACT_FIXTURE_MASK,
        (position / EXACT_ENSEMBLE_SIZE) & EXACT_QUERY_MASK,
    )
}

fn bench_v4_non_attributed(
    group: &mut BenchmarkGroup<'_, WallTime>,
    fixtures: &[V4ExactFixture],
    queries: &[&str; EXACT_QUERY_COUNT],
) {
    group.bench_function("v4_baseline/non_attributed", |b| {
        let mut cursor = 0;
        b.iter(|| {
            let (fixture_index, query_index) = next_exact_probe(&mut cursor);
            let fixture = black_box(&fixtures[fixture_index]);
            fixture
                .engine
                .evaluate(black_box(queries[query_index]), black_box(&fixture.profile))
        })
    });
}

fn bench_v4_attributed(
    group: &mut BenchmarkGroup<'_, WallTime>,
    fixtures: &[V4ExactFixture],
    queries: &[&str; EXACT_QUERY_COUNT],
) {
    group.bench_function("v4_baseline/attributed", |b| {
        let mut cursor = 0;
        b.iter(|| {
            let (fixture_index, query_index) = next_exact_probe(&mut cursor);
            let fixture = black_box(&fixtures[fixture_index]);
            fixture
                .engine
                .evaluate_attributed(black_box(queries[query_index]), black_box(&fixture.profile))
        })
    });
}

fn bench_v5_non_attributed(
    group: &mut BenchmarkGroup<'_, WallTime>,
    targets: &[&CompiledProfile],
    queries: &[&str; EXACT_QUERY_COUNT],
) {
    group.bench_function("v5/non_attributed", |b| {
        let mut cursor = 0;
        b.iter(|| {
            let (fixture_index, query_index) = next_exact_probe(&mut cursor);
            black_box(targets[fixture_index]).evaluate(
                black_box(queries[query_index]),
                black_box(ExternalMatches::Disabled),
            )
        })
    });
}

fn bench_v5_attributed(
    group: &mut BenchmarkGroup<'_, WallTime>,
    targets: &[&CompiledProfile],
    queries: &[&str; EXACT_QUERY_COUNT],
) {
    group.bench_function("v5/attributed", |b| {
        let mut cursor = 0;
        b.iter(|| {
            let (fixture_index, query_index) = next_exact_probe(&mut cursor);
            black_box(targets[fixture_index]).evaluate_attributed(
                black_box(queries[query_index]),
                black_box(ExternalMatches::Disabled),
            )
        })
    });
}

fn bench_exact_group(
    group: &mut BenchmarkGroup<'_, WallTime>,
    v4_fixtures: &[V4ExactFixture],
    v5_targets: &[&CompiledProfile],
    queries: &[&str; EXACT_QUERY_COUNT],
    reverse: bool,
) {
    if reverse {
        bench_v4_attributed(group, v4_fixtures, queries);
        bench_v5_attributed(group, v5_targets, queries);
        bench_v5_non_attributed(group, v5_targets, queries);
        bench_v4_non_attributed(group, v4_fixtures, queries);
    } else {
        bench_v4_non_attributed(group, v4_fixtures, queries);
        bench_v5_non_attributed(group, v5_targets, queries);
        bench_v5_attributed(group, v5_targets, queries);
        bench_v4_attributed(group, v4_fixtures, queries);
    }
}

fn bench_operator_exact(c: &mut Criterion) {
    assert!(EXACT_ENSEMBLE_SIZE.is_power_of_two());
    assert!(EXACT_QUERY_COUNT.is_power_of_two());
    let mut group_index = 0;
    for allow in [false, true] {
        for important in [false, true] {
            let tier = if important { "important" } else { "ordinary" };
            let action = if allow { "allow" } else { "deny" };
            let content = (0..1000)
                .map(|i| {
                    format!(
                        "{}tracker{i}.example.test{}\n",
                        if allow { "@@" } else { "" },
                        if important { "$important" } else { "" }
                    )
                })
                .collect::<String>();
            let v4_fixtures = (0..EXACT_ENSEMBLE_SIZE)
                .map(|_| build_v4_exact_fixture(&content))
                .collect::<Vec<_>>();
            let v5_fixtures = (0..EXACT_ENSEMBLE_SIZE)
                .map(|_| build_v5_exact_fixture(&content))
                .collect::<Vec<_>>();
            let v5_targets = v5_fixtures
                .iter()
                .map(|fixture| &fixture.candidate.profiles()[0].1)
                .collect::<Vec<_>>();

            for (case, queries) in [
                ("hit", &EXACT_HIT_QUERIES),
                ("suffix", &EXACT_SUFFIX_QUERIES),
                ("miss", &EXACT_MISS_QUERIES),
            ] {
                let expected = if allow || case == "miss" {
                    Verdict::Forward
                } else {
                    Verdict::Block
                };
                let old_expected = if expected == Verdict::Forward {
                    FilterResult::Forward
                } else {
                    FilterResult::Block
                };
                for (v4, v5) in v4_fixtures.iter().zip(&v5_targets) {
                    for name in queries {
                        assert_eq!(v4.engine.evaluate(name, &v4.profile), old_expected);
                        assert_eq!(
                            v4.engine.evaluate_attributed(name, &v4.profile).0,
                            old_expected
                        );
                        assert_eq!(v5.evaluate(name, ExternalMatches::Disabled), expected);
                        assert_eq!(
                            v5.evaluate_attributed(name, ExternalMatches::Disabled)
                                .verdict(),
                            expected
                        );
                    }
                }
                let mut group = c.benchmark_group(format!(
                    "operator_exact/ensemble16_queries16/{action}/{tier}/{case}"
                ));
                group.throughput(Throughput::Elements(1));
                bench_exact_group(
                    &mut group,
                    &v4_fixtures,
                    &v5_targets,
                    queries,
                    group_index % 2 == 1,
                );
                group.finish();
                group_index += 1;
            }
        }
    }
}

criterion_group!(
    benches,
    bench_list_membership,
    bench_evaluate,
    bench_arcswap_load,
    bench_operator_exact
);
criterion_main!(benches);
