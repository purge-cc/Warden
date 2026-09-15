use std::net::IpAddr;

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use purge_warden::config::custom_list::CustomListStore;
use purge_warden::config::schema::{ConfigV1, TARGET_SCHEMA_VERSION_V5};
use purge_warden::filter::engine::FilterEngine;
use purge_warden::filter::operator_rules::{
    CompileAdmission, CompiledOperatorRules, ExternalMatches, ProfileMounts, RuleCompileLimits,
};
use purge_warden::profiles::resolver::ProfileResolver;

#[global_allocator]
static ALLOCATOR: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

const CONFIG: &str = r#"
schema_version = 5

[upstream]
servers = ["192.0.2.1:53"]

[server]
default_profile = "default"
enforce_device_mac = false

[profiles.default]
display_name = "Default"
lists = {}

[profiles.mapped]
display_name = "Mapped"
lists = {}

[[devices]]
id = "resolver-bench-client"
display_name = "Bench client"
ip = "192.0.2.10"
profile = "mapped"
"#;

const QUERY_NAME: &str = "resolver-benchmark.example.test";

struct ResolverFixture {
    compatibility_resolver: ProfileResolver,
    runtime_v5_resolver: ProfileResolver,
    compatibility_engine: FilterEngine,
    _runtime_v5_admission: CompileAdmission,
    address: IpAddr,
}

fn fixture(address: &str, allow_default: bool) -> ResolverFixture {
    let mut config: ConfigV1 = toml::from_str(CONFIG).expect("benchmark configuration must parse");
    if !allow_default {
        config.server.default_profile = None;
    }

    assert_eq!(config.schema_version, TARGET_SCHEMA_VERSION_V5);
    let custom_lists = CustomListStore::default();
    let compatibility_resolver = ProfileResolver::build_without_list_bits(&config, &custom_lists);
    let limits = RuleCompileLimits::default();
    let runtime_v5_admission = CompileAdmission::new(limits.max_compiled_bytes_total, 1).unwrap();
    let runtime_v5_rules = CompiledOperatorRules::compile(
        &[],
        &[
            ProfileMounts {
                profile_id: "default",
                custom_lists: &[],
                block_all: false,
            },
            ProfileMounts {
                profile_id: "mapped",
                custom_lists: &[],
                block_all: false,
            },
        ],
        limits,
        &runtime_v5_admission,
    )
    .unwrap();
    let runtime_v5_resolver =
        ProfileResolver::build_with_operator_rules(&config, runtime_v5_rules.into());
    let address = address.parse().expect("benchmark address must parse");

    ResolverFixture {
        compatibility_resolver,
        runtime_v5_resolver,
        compatibility_engine: FilterEngine::new(),
        _runtime_v5_admission: runtime_v5_admission,
        address,
    }
}

fn resolver_fixtures() -> (ResolverFixture, ResolverFixture, ResolverFixture) {
    let mapped = fixture("192.0.2.10", true);
    let default = fixture("198.51.100.10", true);
    let refused = fixture("198.51.100.10", false);

    for fixture in [&mapped, &default] {
        assert!(fixture
            .compatibility_resolver
            .resolve(&fixture.address)
            .profile
            .is_some());
        assert!(fixture
            .runtime_v5_resolver
            .resolve(&fixture.address)
            .profile
            .is_some());
    }
    assert!(refused
        .compatibility_resolver
        .resolve(&refused.address)
        .profile
        .is_none());
    assert!(refused
        .runtime_v5_resolver
        .resolve(&refused.address)
        .profile
        .is_none());

    (mapped, default, refused)
}

fn bench_resolve(c: &mut Criterion) {
    let (mapped, default, refused) = resolver_fixtures();
    let mut group = c.benchmark_group("resolver/resolve");
    group.throughput(Throughput::Elements(1));

    for (name, fixture) in [
        ("mapped", &mapped),
        ("default", &default),
        ("refused", &refused),
    ] {
        group.bench_function(format!("{name}/v4_compatibility"), |b| {
            b.iter(|| {
                black_box(
                    fixture
                        .compatibility_resolver
                        .resolve(black_box(&fixture.address)),
                )
            })
        });
        group.bench_function(format!("{name}/v5_runtime"), |b| {
            b.iter(|| {
                black_box(
                    fixture
                        .runtime_v5_resolver
                        .resolve(black_box(&fixture.address)),
                )
            })
        });
    }

    group.finish();
}

fn bench_resolve_then_filter(c: &mut Criterion) {
    let (mapped, default, _) = resolver_fixtures();
    let mut group = c.benchmark_group("resolver/resolve_then_filter");
    group.throughput(Throughput::Elements(1));

    for (name, fixture) in [("mapped", &mapped), ("default", &default)] {
        group.bench_function(format!("{name}/v4_compatibility/non_attributed"), |b| {
            b.iter(|| {
                let resolution = fixture
                    .compatibility_resolver
                    .resolve(black_box(&fixture.address));
                let profile = resolution
                    .profile
                    .as_deref()
                    .expect("mapped and default benchmark cases must resolve");
                black_box(
                    fixture
                        .compatibility_engine
                        .evaluate(black_box(QUERY_NAME), black_box(profile)),
                )
            })
        });
        group.bench_function(format!("{name}/v5_runtime/non_attributed"), |b| {
            b.iter(|| {
                let resolution = fixture
                    .runtime_v5_resolver
                    .resolve(black_box(&fixture.address));
                let profile = resolution
                    .profile
                    .as_deref()
                    .expect("mapped and default benchmark cases must resolve");
                black_box(
                    profile
                        .operator_rules
                        .as_ref()
                        .expect("runtime-v5 resolver must bind compiled rules")
                        .profile()
                        .evaluate(black_box(QUERY_NAME), ExternalMatches::Disabled),
                )
            })
        });
        group.bench_function(format!("{name}/v4_compatibility/attributed"), |b| {
            b.iter(|| {
                let resolution = fixture
                    .compatibility_resolver
                    .resolve(black_box(&fixture.address));
                let profile = resolution
                    .profile
                    .as_deref()
                    .expect("mapped and default benchmark cases must resolve");
                black_box(
                    fixture
                        .compatibility_engine
                        .evaluate_attributed(black_box(QUERY_NAME), black_box(profile)),
                )
            })
        });
        group.bench_function(format!("{name}/v5_runtime/attributed"), |b| {
            b.iter(|| {
                let resolution = fixture
                    .runtime_v5_resolver
                    .resolve(black_box(&fixture.address));
                let profile = resolution
                    .profile
                    .as_deref()
                    .expect("mapped and default benchmark cases must resolve");
                let decision = profile
                    .operator_rules
                    .as_ref()
                    .expect("runtime-v5 resolver must bind compiled rules")
                    .profile()
                    .evaluate_attributed(black_box(QUERY_NAME), ExternalMatches::Disabled);
                black_box(decision.verdict())
            })
        });
    }

    group.finish();
}

criterion_group!(benches, bench_resolve, bench_resolve_then_filter);
criterion_main!(benches);
