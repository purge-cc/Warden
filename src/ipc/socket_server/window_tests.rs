use super::*;
use crate::ipc::protocol::TimeBucketDto;

const NOW: u64 = 100 * 3600 + 1800;

fn bucket(hour: u64, q: u64, b: u64, h: u64) -> TimeBucketDto {
    TimeBucketDto {
        timestamp: hour * 3600,
        queries: q,
        blocked: b,
        cache_hits: h,
    }
}

#[test]
fn empty_hourly_returns_zeros() {
    assert_eq!(compute_24h_stats(&[], NOW), (0.0, 0.0, 0.0, 0.0));
}

#[test]
fn twenty_four_hours_weighted_average_uses_nonblocked_denominator() {
    let buckets: Vec<_> = (77..=100).map(|hour| bucket(hour, 100, 20, 80)).collect();
    let (c24, b24, _, _) = compute_24h_stats(&buckets, NOW);
    assert!((c24 - 100.0).abs() < 1e-9, "got {c24}");
    assert!((b24 - 20.0).abs() < 1e-9);
}

#[test]
fn one_hour_delta_detects_change() {
    let buckets = vec![bucket(99, 100, 10, 63), bucket(100, 100, 30, 63)];
    let (_, _, cache_delta, blocked_delta) = compute_24h_stats(&buckets, NOW);
    assert!((cache_delta - 20.0).abs() < 1e-9, "got {cache_delta}");
    assert!((blocked_delta - 20.0).abs() < 1e-9, "got {blocked_delta}");
}

#[test]
fn zero_query_and_all_blocked_buckets_do_not_divide_by_zero() {
    assert_eq!(
        compute_24h_stats(&[bucket(100, 0, 0, 0)], NOW),
        (0.0, 0.0, 0.0, 0.0)
    );
    assert_eq!(
        compute_24h_stats(&[bucket(100, 100, 100, 0)], NOW),
        (0.0, 100.0, 0.0, 0.0)
    );
    let (c24, b24, _, _) = compute_24h_stats(&[bucket(99, 0, 0, 0), bucket(100, 100, 25, 60)], NOW);
    assert!((c24 - 80.0).abs() < 1e-9);
    assert!((b24 - 25.0).abs() < 1e-9);
}

#[test]
fn timestamp_window_excludes_old_and_future_buckets_even_with_sparse_history() {
    let buckets = vec![
        bucket(76, 900, 900, 0),
        bucket(77, 100, 20, 80),
        bucket(101, 900, 900, 0),
    ];
    assert_eq!(compute_24h_stats(&buckets, NOW), (100.0, 20.0, 0.0, 0.0));
    assert_eq!(
        compute_24h_stats(&buckets, NOW + 48 * 3600),
        (0.0, 0.0, 0.0, 0.0)
    );
}

#[test]
fn duplicate_fragments_are_summed_before_ratios_and_delta() {
    // Unsorted fragments of current hour: 80 hits / (100 - 20) = 100%.
    let buckets = vec![
        bucket(100, 40, 20, 20),
        bucket(99, 100, 0, 50),
        bucket(100, 60, 0, 60),
    ];
    let (cache, blocked, dc, db) = compute_24h_stats(&buckets, NOW);
    assert!((cache - 100.0 * 130.0 / 180.0).abs() < 1e-9);
    assert_eq!(blocked, 10.0);
    assert_eq!((dc, db), (50.0, 20.0));
}

#[test]
fn gaps_and_stale_tail_do_not_create_one_hour_delta() {
    let gap = vec![bucket(98, 100, 0, 0), bucket(100, 100, 20, 80)];
    let (_, _, dc, db) = compute_24h_stats(&gap, NOW);
    assert_eq!((dc, db), (0.0, 0.0));
    let stale = vec![bucket(97, 100, 0, 0), bucket(98, 100, 20, 80)];
    let (_, _, dc, db) = compute_24h_stats(&stale, NOW);
    assert_eq!((dc, db), (0.0, 0.0));
}

#[test]
fn aggregate_ratios_do_not_saturate_u64_before_dividing() {
    let q = u64::MAX;
    let b = q / 2;
    let h = q - b;
    let buckets = vec![bucket(99, q, b, h), bucket(100, q, b, h)];
    let (cache, blocked, dc, db) = compute_24h_stats(&buckets, NOW);
    assert!((cache - 100.0).abs() < 1e-9);
    assert!((blocked - 50.0).abs() < 1e-9);
    assert_eq!((dc, db), (0.0, 0.0));
}

#[test]
fn epoch_boundary_and_oversized_query_period_do_not_wrap() {
    assert!(crate::tracking::time_series::hour_in_24h_window(0, 0));
    assert!(!crate::tracking::time_series::hour_in_24h_window(3600, 0));
    assert_eq!(
        compute_24h_stats(&[bucket(0, 1, 0, 1)], 0),
        (100.0, 0.0, 0.0, 0.0)
    );
    assert_eq!(query_log_cutoff_epoch(100, 200), -100);
    assert_eq!(query_log_cutoff_epoch(i64::MIN, 1), i64::MIN);
    assert_eq!(query_log_cutoff_epoch(100, u64::MAX), i64::MIN);
    assert_eq!(query_log_cutoff_epoch(i64::MAX, u64::MAX), i64::MIN);
}

#[test]
fn intrahour_fragments_share_the_same_rate_and_delta_bucket() {
    let mut first = bucket(100, 40, 20, 20);
    first.timestamp += 10;
    let mut second = bucket(100, 60, 0, 60);
    second.timestamp += 20;
    let mut previous = bucket(99, 100, 0, 50);
    previous.timestamp += 15;
    let fragmented = [first, second, previous];
    let canonical = [bucket(100, 100, 20, 80), bucket(99, 100, 0, 50)];
    assert_eq!(
        compute_24h_stats(&fragmented, 100 * 3600 + 30),
        compute_24h_stats(&canonical, 100 * 3600 + 30)
    );
}
