use std::collections::HashMap;

use ahash::RandomState;
use compact_str::CompactString;
use criterion::{black_box, criterion_group, criterion_main, Criterion};

use purge_warden::lists::parser;

/// Generate a domain-only blocklist with `n` lines.
fn gen_domain_list(n: usize) -> String {
    let mut buf = String::with_capacity(n * 30);
    buf.push_str("# purge.cc blocklist\n");
    buf.push_str("# Generated for benchmarking\n");
    for i in 0..n {
        buf.push_str(&format!("tracker{}.example{}.com\n", i, i / 100));
    }
    buf
}

/// Generate a hosts-format blocklist with `n` entries.
fn gen_hosts_list(n: usize) -> String {
    let mut buf = String::with_capacity(n * 35);
    buf.push_str("# hosts file\n");
    for i in 0..n {
        buf.push_str(&format!("0.0.0.0 tracker{}.example{}.com\n", i, i / 100));
    }
    buf
}

/// Generate an AdGuard-format blocklist with `n` entries.
fn gen_adguard_list(n: usize) -> String {
    let mut buf = String::with_capacity(n * 35);
    buf.push_str("! AdGuard DNS filter\n");
    for i in 0..n {
        buf.push_str(&format!("||tracker{}.example{}.com^\n", i, i / 100));
    }
    buf
}

fn bench_parse_domain_list(c: &mut Criterion) {
    let content = gen_domain_list(10_000);
    c.bench_function("parse_domain_list_10k", |b| {
        b.iter(|| {
            let mut set = std::collections::HashSet::with_hasher(RandomState::new());
            parser::parse_domain_list_into(black_box(&content), &mut set);
            set
        })
    });
}

fn bench_parse_hosts_list(c: &mut Criterion) {
    let content = gen_hosts_list(10_000);
    c.bench_function("parse_hosts_list_10k", |b| {
        b.iter(|| {
            let mut map: HashMap<CompactString, u64, RandomState> =
                HashMap::with_hasher(RandomState::new());
            parser::parse_hosts_list_into_map(
                black_box(&content),
                1,
                &mut map,
                parser::DEFAULT_MAX_LIST_ENTRIES,
                "bench",
            );
            map
        })
    });
}

fn bench_parse_adguard_list(c: &mut Criterion) {
    let content = gen_adguard_list(10_000);
    c.bench_function("parse_adguard_list_10k", |b| {
        b.iter(|| {
            let mut map: HashMap<CompactString, u64, RandomState> =
                HashMap::with_hasher(RandomState::new());
            parser::parse_adguard_list_into_map(
                black_box(&content),
                1,
                &mut map,
                parser::DEFAULT_MAX_LIST_ENTRIES,
                "bench",
            );
            map
        })
    });
}

criterion_group!(
    benches,
    bench_parse_domain_list,
    bench_parse_hosts_list,
    bench_parse_adguard_list
);
criterion_main!(benches);
