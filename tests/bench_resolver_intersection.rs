//! Hot-path latency bench: per-query DNS evaluation must stay flat as
//! the list-association model changes underneath it.
//!
//! **Design context.** Association is resolved at RELOAD time and
//! collapsed into a `list_bitmask: u64` on `ResolvedProfile`. The DNS hot
//! path reads that precomputed mask and ANDs it against the per-domain
//! `DomainMasks { allow_mask, block_mask }`. This test is a regression
//! pin: if a refactor moves the association work to a per-query
//! computation by mistake, the p99 jumps and this surfaces it.
//!
//! **It was written for the tag-intersection model** (`lists_categories_v2`
//! T6) and it outlived it, which is the point — the pin is on the hot
//! path's shape, not on which model computes the mask. `plp-s3` replaced
//! intersection with `base` + `profiles.<id>.lists` and `plp-s5a` removed
//! the tag field; the fixtures lost their tag arrays and nothing about
//! what is measured changed.
//!
//! **Method.** Build a synthetic profile with 5 lists + 10k domains in the
//! filter engine, run 100k probes, sort, pin p99 < 10 μs (generously over
//! the actual envelope).
//!
//! **Skip on debug builds.** Cargo's debug profile pessimises the
//! hash table walk by ~10×; the bench only runs under
//! `cargo test --release` to keep CI deterministic.

#![cfg(not(debug_assertions))]

use std::collections::{BTreeMap, HashMap};
use std::time::Instant;

use ahash::RandomState;
use compact_str::CompactString;

use purge_warden::config::schema::id::Id;
use purge_warden::config::schema::{
    Blocklist, BlocklistBase, BlocklistFormat, BlocklistTrust, Profile, ServerGlobals,
};
use purge_warden::filter::engine::{FilterEngine, FilterResult};
use purge_warden::lists::source_key::SourceBitMap;
use purge_warden::profiles::profile::ResolvedProfile;

const ITERATIONS: usize = 100_000;
const DOMAINS_IN_MAP: usize = 10_000;

fn make_blocklist(id: &str) -> Blocklist {
    Blocklist {
        id: Id::new(id).unwrap(),
        display_name: id.into(),
        url: format!("https://lists.purge.cc/{id}.txt"),
        format: BlocklistFormat::Domains,
        update_interval_hours: 12,
        max_entries: 5_000_000,
        enabled: true,
        auth_token_ref: None,
        base: BlocklistBase::Deny,
        trust: BlocklistTrust::RemoteUnsigned,
        accept_unsigned_allow: false,
        max_consecutive_failures: 5,
    }
}

#[test]
fn t6_resolver_intersection_p99_within_target() {
    let blocklists = vec![
        make_blocklist("ads"),
        make_blocklist("malicious"),
        make_blocklist("kids-block"),
        make_blocklist("trackers"),
        make_blocklist("phishing"),
    ];
    let bit_map = SourceBitMap::build(
        &blocklists
            .iter()
            .map(|b| b.id.to_string())
            .collect::<Vec<_>>(),
        &blocklists,
    )
    .expect("bit map at-cap accept");

    let profile = Profile {
        display_name: "default".into(),
        ..Default::default()
    };
    let resolved = ResolvedProfile::build_v1(
        &Id::new("default").unwrap(),
        &profile,
        &BTreeMap::new(),
        &purge_warden::config::custom_list::CustomListStore::new(),
        &ServerGlobals::default(),
        60,
    );

    // Build a realistic domain map: every domain tagged with the
    // first list's bit (ads) so probes hit the block path.
    let ads_bit = bit_map
        .bit_for_v1_id(&Id::new("ads").unwrap())
        .expect("ads bit");
    let mut domain_map: HashMap<CompactString, u64, RandomState> =
        HashMap::with_capacity_and_hasher(DOMAINS_IN_MAP, RandomState::new());
    for i in 0..DOMAINS_IN_MAP {
        domain_map.insert(
            CompactString::new(format!("d{i:05}.tracker.example.com")),
            1u64 << ads_bit,
        );
    }
    let engine = FilterEngine::new();
    engine.swap_domain_map(domain_map);

    // Warm up the JIT-equivalent paths: 1k iterations untimed.
    for i in 0..1_000 {
        let domain = format!("d{:05}.tracker.example.com", i % DOMAINS_IN_MAP);
        let _ = engine.evaluate(&domain, &resolved);
    }

    // Timed run: 100k probes alternating block/forward to keep the
    // branch predictor honest.
    let mut samples: Vec<u128> = Vec::with_capacity(ITERATIONS);
    for i in 0..ITERATIONS {
        let domain = if i % 2 == 0 {
            format!("d{:05}.tracker.example.com", i % DOMAINS_IN_MAP)
        } else {
            format!("safe-{}.example.org", i)
        };
        let start = Instant::now();
        let _ = std::hint::black_box(engine.evaluate(&domain, &resolved));
        samples.push(start.elapsed().as_nanos());
    }
    samples.sort_unstable();
    let p50 = samples[ITERATIONS / 2];
    let p99 = samples[(ITERATIONS as f64 * 0.99) as usize];
    let p999 = samples[(ITERATIONS as f64 * 0.999) as usize];

    eprintln!(
        "[t6-bench] p50 = {} ns, p99 = {} ns, p99.9 = {} ns over {} iterations",
        p50, p99, p999, ITERATIONS
    );

    // Generous envelope — the actual numbers on a release build land
    // well under 1 μs (~200-400 ns p99 in CT testing). The 10 μs
    // ceiling pins regressions that would balloon the hot path by an
    // order of magnitude — e.g. moving list association per-query.
    assert!(
        p99 < 10_000,
        "p99 must stay under 10 μs, observed {} ns ({}× over budget)",
        p99,
        p99 / 10_000
    );
}

/// Companion sanity check: verify the bench domain map actually
/// produces blocks. Without this a regression that returned Forward
/// for every probe could pass the latency bench while the filter
/// engine is silently broken.
#[test]
fn t6_resolver_intersection_block_path_exercised() {
    let blocklists = vec![make_blocklist("ads")];
    let bit_map =
        SourceBitMap::build(&["ads".to_string()], &blocklists).expect("bit map at-cap accept");
    let profile = Profile {
        display_name: "default".into(),
        ..Default::default()
    };
    let resolved = ResolvedProfile::build_v1(
        &Id::new("default").unwrap(),
        &profile,
        &BTreeMap::new(),
        &purge_warden::config::custom_list::CustomListStore::new(),
        &ServerGlobals::default(),
        60,
    );
    let ads_bit = bit_map
        .bit_for_v1_id(&Id::new("ads").unwrap())
        .expect("ads bit");
    let mut domain_map: HashMap<CompactString, u64, RandomState> =
        HashMap::with_hasher(RandomState::new());
    domain_map.insert(CompactString::new("doubleclick.net"), 1u64 << ads_bit);
    let engine = FilterEngine::new();
    engine.swap_domain_map(domain_map);
    assert!(matches!(
        engine.evaluate("doubleclick.net", &resolved),
        FilterResult::Block
    ));
    assert!(matches!(
        engine.evaluate("safe.example.org", &resolved),
        FilterResult::Forward
    ));
}
