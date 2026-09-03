use super::*;
use crate::ipc::protocol::TimeBucketDto;

fn bucket(q: u64, b: u64, h: u64) -> TimeBucketDto {
    TimeBucketDto {
        timestamp: 0,
        queries: q,
        blocked: b,
        cache_hits: h,
    }
}

#[test]
fn empty_hourly_returns_zeros() {
    assert_eq!(compute_24h_stats(&[]), (0.0, 0.0, 0.0, 0.0));
}

#[test]
fn twenty_four_hours_weighted_average() {
    // 24 identical buckets — avg equals per-bucket ratio.
    // mem2608-s3 / F-P: cache_24h's denominator is (queries - blocked),
    // not queries. This fixture's 80 hits are ALL of its 80 cacheable
    // queries (100 - 20), so the correct reading is 100%, not the
    // pre-fix 80% (80 hits / 100 all-queries).
    let buckets = vec![bucket(100, 20, 80); 24];
    let (c24, b24, _, _) = compute_24h_stats(&buckets);
    assert!((c24 - 100.0).abs() < 1e-9, "got {c24}");
    assert!((b24 - 20.0).abs() < 1e-9);
}

#[test]
fn one_hour_delta_detects_change() {
    // Two buckets, same 63 cache hits in both: prev has 90 cacheable
    // (100 - 10) → 70%; last has 70 cacheable (100 - 30) → 90%. Delta
    // = +20, unchanged from before F-P — chosen so hit counts stay
    // valid under the new invariant (hits <= cacheable) while
    // reproducing the same intended 70%/90% shape.
    let buckets = vec![bucket(100, 10, 63), bucket(100, 30, 63)];
    let (_, _, cache_delta, blocked_delta) = compute_24h_stats(&buckets);
    assert!((cache_delta - 20.0).abs() < 1e-9, "got {cache_delta}");
    assert!((blocked_delta - 20.0).abs() < 1e-9, "got {blocked_delta}");
}

#[test]
fn zero_query_bucket_does_not_divide_by_zero() {
    // mem2608-s3 / F-P: 60 hits / 75 cacheable (100 - 25) = 80%.
    let buckets = vec![bucket(0, 0, 0), bucket(100, 25, 60)];
    let (c24, b24, _, _) = compute_24h_stats(&buckets);
    assert!((c24 - 80.0).abs() < 1e-9, "got {c24}");
    assert!((b24 - 25.0).abs() < 1e-9);
}

#[test]
fn window_caps_at_24_most_recent_buckets() {
    // 30 buckets — oldest 6 must be ignored. Last 24 sum to 2400 q,
    // so adding a 300-query bucket at position 0 should not shift
    // the average.
    let mut buckets = vec![bucket(300, 300, 0)]; // all blocked, no hits
    buckets.extend(vec![bucket(100, 20, 80); 24]);
    let (c24, b24, _, _) = compute_24h_stats(&buckets);
    // Window is the last 24 → same fixture as
    // twenty_four_hours_weighted_average: 80 hits / 80 cacheable = 100%.
    assert!((c24 - 100.0).abs() < 1e-9, "got {c24}");
    assert!((b24 - 20.0).abs() < 1e-9);
}
