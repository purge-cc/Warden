use std::collections::HashMap;

use ahash::RandomState;
use compact_str::CompactString;
use criterion::{black_box, criterion_group, criterion_main, Criterion};

use purge_warden::filter::engine::FilterEngine;
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

criterion_group!(
    benches,
    bench_list_membership,
    bench_evaluate,
    bench_arcswap_load
);
criterion_main!(benches);
