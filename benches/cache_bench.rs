use std::net::Ipv4Addr;

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};

use purge_warden::config::settings::CacheConfig;
use purge_warden::dns::cache::DnsCache;

fn make_record(domain: &str, ip: Ipv4Addr) -> Record {
    let name = Name::from_ascii(domain).unwrap();
    Record::from_rdata(name, 300, RData::A(A(ip)))
}

fn bench_cache_lookup(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    let config = CacheConfig::default();
    let cache = DnsCache::new(&config);

    // Pre-populate with 1000 entries
    rt.block_on(async {
        for i in 0u32..1000 {
            let domain = format!("cached{}.example.com", i);
            let records = vec![make_record(
                &domain,
                Ipv4Addr::new(1, 2, 3, (i % 256) as u8),
            )];
            cache
                .insert(
                    &domain,
                    RecordType::A,
                    DNSClass::IN,
                    records,
                    ResponseCode::NoError,
                    None,
                    None,
                )
                .await;
        }
    });

    let mut group = c.benchmark_group("cache_lookup");

    group.bench_function("hit", |b| {
        b.to_async(
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap(),
        )
        .iter(|| async {
            cache
                .lookup(
                    black_box("cached42.example.com"),
                    RecordType::A,
                    DNSClass::IN,
                    None,
                )
                .await
        })
    });

    group.bench_function("miss", |b| {
        b.to_async(
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap(),
        )
        .iter(|| async {
            cache
                .lookup(
                    black_box("unknown.example.com"),
                    RecordType::A,
                    DNSClass::IN,
                    None,
                )
                .await
        })
    });

    group.finish();
}

criterion_group!(benches, bench_cache_lookup);
criterion_main!(benches);
