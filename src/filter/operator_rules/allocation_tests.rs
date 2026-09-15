use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::hint::black_box;
use std::str::FromStr;
use std::sync::Arc;

use super::*;
use crate::filter::cname::{walk_response_with_grant, Verdict as CnameVerdict};
use crate::filter::engine::FilterEngine;
use crate::profiles::profile::ResolvedProfile;
use hickory_proto::rr::rdata::CNAME;
use hickory_proto::rr::{Name, RData, Record};

#[derive(Debug, Default, Clone, Copy)]
struct Counts {
    calls: usize,
    allocated: usize,
    freed: usize,
}

thread_local! {
    // Const-initialized TLS has no allocator-dependent initialization or Drop.
    static COUNTS: Cell<Option<Counts>> = const { Cell::new(None) };
}

struct CountingAllocator;

fn record(allocated: usize, freed: usize, call: bool) {
    let _ = COUNTS.try_with(|counts| {
        if let Some(mut value) = counts.get() {
            value.calls += usize::from(call);
            value.allocated += allocated;
            value.freed += freed;
            counts.set(Some(value));
        }
    });
}

// SAFETY: Every allocation operation delegates to System with the same pointer
// and layout. Observation uses allocation-free, thread-local scalar counters.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            record(layout.size(), 0, true);
        }
        pointer
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc_zeroed(layout) };
        if !pointer.is_null() {
            record(layout.size(), 0, true);
        }
        pointer
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        record(0, layout.size(), false);
        unsafe { System.dealloc(pointer, layout) };
    }
    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        let new = unsafe { System.realloc(pointer, layout, size) };
        if !new.is_null() {
            record(size, layout.size(), true);
        }
        new
    }
}

// This module exists only in the library unit-test crate. The daemon and each
// integration-test binary retain their own allocator; library tests use TLS so
// concurrently running tests cannot contaminate a measured interval.
#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

fn measured<T>(f: impl FnOnce() -> T) -> (T, Counts) {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            COUNTS.with(|counts| counts.set(None));
        }
    }
    COUNTS.with(|counts| {
        assert!(counts.get().is_none());
        counts.set(Some(Counts::default()));
    });
    let reset = Reset;
    let result = f();
    let counts = COUNTS.with(|counts| counts.get().unwrap());
    drop(reset);
    (result, counts)
}

fn compile(content: &str) -> CompiledOperatorRules {
    compile_isolated(
        &[PackSource {
            list_id: "rules",
            content,
        }],
        &[ProfileMounts {
            profile_id: "profile",
            custom_lists: &["rules"],
            block_all: false,
        }],
        RuleCompileLimits::default(),
    )
    .unwrap()
}

#[test]
fn warmed_exact_attributed_and_plain_lookups_allocate_nothing() {
    let long = format!(
        "{}.{}.{}.example.test",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63)
    );
    let miss = format!("{}.other.test", "m".repeat(63));
    for content in [
        "example.test",
        "@@example.test",
        "example.test$important",
        "@@example.test$important",
    ] {
        let candidate = compile(content);
        let p = &candidate.profiles()[0].1;
        for domain in ["example.test", "sub.example.test", &long, &miss] {
            black_box(p.evaluate(domain, ExternalMatches::None));
            let _ = black_box(p.evaluate_attributed(domain, ExternalMatches::None));
            for attributed in [false, true] {
                let (_, count) = measured(|| {
                    for _ in 0..1000 {
                        if attributed {
                            let _ = black_box(p.evaluate_attributed(
                                black_box(domain),
                                black_box(ExternalMatches::None),
                            ));
                        } else {
                            black_box(
                                p.evaluate(black_box(domain), black_box(ExternalMatches::None)),
                            );
                        }
                    }
                });
                assert_eq!(
                    count.calls, 0,
                    "{content} / {domain} / attributed={attributed}: {count:?}"
                );
            }
        }
    }
}

#[test]
fn compiled_quota_covers_measured_retained_allocations() {
    let large = (0..500)
        .map(|i| format!("long-owned-domain-{i}.example.test$important\n"))
        .collect::<String>();
    for content in [
        "",
        "example.test",
        "*.example.test\n@@/example/",
        r"/\bélan\b/",
        &large,
    ] {
        let (candidate, counts) = measured(|| compile(content));
        let retained = counts.allocated.checked_sub(counts.freed).unwrap();
        assert!(
            retained <= candidate.cost().snapshot_bytes,
            "retained {retained}, quota {}, gross allocations {}",
            candidate.cost().snapshot_bytes,
            counts.allocated
        );
        assert_eq!(
            candidate.profiles()[0].1.counts().advanced,
            candidate.profiles()[0].1.advanced_len()
        );
    }
}

#[test]
fn concurrent_regex_hit_and_miss_are_allocation_free_on_first_and_repeated_search() {
    use std::sync::Barrier;
    let long_miss = format!(
        "{}.{}.{}.{}.test",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(56)
    );
    for (content, hit, miss) in [
        (r"/^regex[0-9]+\.test$/", "regex42.test", long_miss.as_str()),
        (r"/\bélan\b/", "élan.test", "préélan.test"),
        (r"/\bword\b/", "word.test", "sword.test"),
        (r"/\p{Greek}+/", "αβ.test", "plain.test"),
    ] {
        for miss_first in [false, true] {
            let candidate = compile(content);
            let p = &candidate.profiles()[0].1;
            let barrier = Barrier::new(8);
            std::thread::scope(|scope| {
                let handles: Vec<_> = (0..8)
                    .map(|_| {
                        scope.spawn(|| {
                            barrier.wait();
                            let names = if miss_first { [miss, hit] } else { [hit, miss] };
                            let ((first, second), cold) = measured(|| {
                                (
                                    p.evaluate(black_box(names[0]), ExternalMatches::None),
                                    p.evaluate_attributed(
                                        black_box(names[1]),
                                        ExternalMatches::None,
                                    )
                                    .verdict(),
                                )
                            });
                            assert_eq!(
                                first,
                                if miss_first {
                                    Verdict::Forward
                                } else {
                                    Verdict::Block
                                }
                            );
                            assert_eq!(
                                second,
                                if miss_first {
                                    Verdict::Block
                                } else {
                                    Verdict::Forward
                                }
                            );
                            assert_eq!(cold.calls, 0, "cold {content}: {cold:?}");
                            let (_, warm) = measured(|| {
                                for _ in 0..1000 {
                                    for name in names {
                                        let request = p.evaluate_attributed(
                                            black_box(name),
                                            ExternalMatches::None,
                                        );
                                        let _ = black_box(request.winning_rule());
                                        let _ = black_box(request.evaluate_target(
                                            "target.test",
                                            ExternalMatches::None,
                                            true,
                                        ));
                                        black_box(request.response_ip_verdict(true, true));
                                    }
                                }
                            });
                            assert_eq!(warm.calls, 0, "warm {content}: {warm:?}");
                        })
                    })
                    .collect();
                for handle in handles {
                    handle.join().unwrap();
                }
            });
        }
    }
}

#[test]
fn sidecar_enumeration_and_attribution_borrow_without_allocating() {
    let candidate = compile("example.test\nEXAMPLE.test\n@@example.test\n*.example.test\n/other/");
    let p = &candidate.profiles()[0].1;
    let (matched, counts) = measured(|| {
        p.explain("sub.example.test")
            .map(|entry| {
                black_box(entry.rule.origin().source_rows());
                black_box(entry.rule.ast());
                1
            })
            .sum::<usize>()
    });
    assert_eq!(matched, 3);
    assert_eq!(counts.calls, 0);
}

#[test]
fn long_cname_allow_walk_with_grant_allocates_nothing() {
    let target = format!(
        "{}.{}.{}.{}",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(61),
    );
    assert_eq!(target.len(), 253);
    let records = [Record::from_rdata(
        Name::from_str("query.test").unwrap(),
        300,
        RData::CNAME(CNAME(Name::from_str(&target).unwrap())),
    )];
    let mut profile = ResolvedProfile::permissive_default();
    profile.name = compact_str::CompactString::new("profile");
    profile.unfiltered = false;
    profile.bind_operator_rules(Arc::new(compile("")));
    let engine = FilterEngine::new();

    assert_eq!(
        walk_response_with_grant(&records, "query.test", &engine, &profile, None, 16),
        CnameVerdict::Allow
    );
    let (_, counts) = measured(|| {
        for _ in 0..1_000 {
            assert_eq!(
                black_box(walk_response_with_grant(
                    black_box(&records),
                    black_box("query.test"),
                    black_box(&engine),
                    black_box(&profile),
                    None,
                    16,
                )),
                CnameVerdict::Allow
            );
        }
    });
    assert_eq!(counts.calls, 0, "long CNAME allow walk: {counts:?}");
}
