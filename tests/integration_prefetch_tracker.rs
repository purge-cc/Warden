//! Sprint §4.4 P1 — Cache Prefetching hit-frequency tracker
//! integration test.
//!
//! End-to-end exercise of the data plane wired through `StatsEngine`:
//! `record_cache_hit` (the handler-side entry point) → `HitTracker`
//! state → public counter accessors. Snapshot persistence is also
//! exercised here (capture → merge_into) since the wire format is what
//! the on-disk and IPC consumers care about.
//!
//! What this file does NOT exercise: the actual DNS handler, the IPC
//! socket transport, the TUI render path. Those are unit-tested in
//! their respective modules. This file is the cross-cut sanity check
//! that the tracker behaves the same when accessed via the engine
//! façade as via the bare module.

use purge_warden::config::settings::TrackingConfig;
use purge_warden::tracking::snapshot::StatsSnapshot;
use purge_warden::tracking::{PrefetchTrackerConfig, StatsEngine};

fn engine_with_tracker(prefetch: PrefetchTrackerConfig) -> StatsEngine {
    let tracking = TrackingConfig {
        enabled: true,
        ..TrackingConfig::default()
    };
    StatsEngine::with_prefetch_config(&tracking, &prefetch)
}

#[test]
fn engine_record_cache_hit_promotes_after_threshold() {
    let cfg = PrefetchTrackerConfig {
        enabled: true,
        window_secs: 60,
        min_hits: 3,
        max_pool_size: 64,
    };
    let engine = engine_with_tracker(cfg);

    // Three positive cache hits on the same domain should land us in
    // the prefetch pool. The engine fetches `now_secs` itself; for the
    // duration of this fast test the three calls land in the same
    // window unconditionally.
    for _ in 0..3 {
        engine.record_cache_hit("hot.example");
    }

    assert_eq!(engine.prefetch_tracker.pool_size(), 1);
    assert_eq!(engine.prefetch_tracker.promotions_total(), 1);
    assert!(engine.prefetch_tracker.is_promoted("hot.example"));

    // A second domain that only got one hit must NOT be promoted.
    engine.record_cache_hit("cool.example");
    assert!(!engine.prefetch_tracker.is_promoted("cool.example"));
    assert_eq!(engine.prefetch_tracker.pool_size(), 1);
}

#[test]
fn engine_record_cache_hit_with_disabled_tracker_is_inert() {
    let cfg = PrefetchTrackerConfig {
        enabled: false,
        window_secs: 60,
        min_hits: 1,
        max_pool_size: 64,
    };
    let engine = engine_with_tracker(cfg);
    for _ in 0..50 {
        engine.record_cache_hit("hot.example");
    }
    assert_eq!(engine.prefetch_tracker.pool_size(), 0);
    assert_eq!(engine.prefetch_tracker.promotions_total(), 0);
    assert!(!engine.prefetch_tracker.is_promoted("hot.example"));
}

#[test]
fn snapshot_roundtrip_preserves_prefetch_counters_via_engine_facade() {
    let cfg = PrefetchTrackerConfig {
        enabled: true,
        window_secs: 60,
        min_hits: 2,
        max_pool_size: 16,
    };
    let engine1 = engine_with_tracker(cfg.clone());

    // Two hits → promotion (record_hit takes synthetic now via the
    // tracker direct API so we can exercise the demote path here too).
    engine1.prefetch_tracker.record_hit("hot.example", 0);
    engine1.prefetch_tracker.record_hit("hot.example", 30);
    assert_eq!(engine1.prefetch_tracker.promotions_total(), 1);
    // Window 2 with one hit → demotion.
    engine1.prefetch_tracker.record_hit("hot.example", 60);
    assert_eq!(engine1.prefetch_tracker.demotions_total(), 1);

    let snap = StatsSnapshot::capture(&engine1);
    assert_eq!(snap.prefetch_promotions_total, 1);
    assert_eq!(snap.prefetch_demotions_total, 1);

    // Round-trip through JSON and merge into a fresh engine.
    let json = serde_json::to_string(&snap).unwrap();
    let parsed: StatsSnapshot = serde_json::from_str(&json).unwrap();

    let engine2 = engine_with_tracker(cfg);
    parsed.merge_into(&engine2);
    assert_eq!(engine2.prefetch_tracker.promotions_total(), 1);
    assert_eq!(engine2.prefetch_tracker.demotions_total(), 1);
    // Pool itself is *not* persisted across restarts — it rebuilds
    // from live traffic.
    assert_eq!(engine2.prefetch_tracker.pool_size(), 0);
}

#[test]
fn pre_phase1_snapshot_without_prefetch_fields_loads_clean() {
    let legacy = serde_json::json!({
        "total_queries": 100,
        "total_blocked": 10,
        "total_cache_hits": 50,
        "total_cache_negative_hits": 2,
        "devices": [],
        "top_n": { "top_queried": [], "top_blocked": [] },
        "hourly": [],
        "daily": []
    });
    let parsed: StatsSnapshot = serde_json::from_value(legacy).unwrap();
    let cfg = PrefetchTrackerConfig {
        enabled: true,
        window_secs: 60,
        min_hits: 3,
        max_pool_size: 16,
    };
    let engine = engine_with_tracker(cfg);
    parsed.merge_into(&engine);
    // Counters must end up at zero — pre-§4.4 snapshots have no
    // prefetch fields and serde defaults them.
    assert_eq!(engine.prefetch_tracker.promotions_total(), 0);
    assert_eq!(engine.prefetch_tracker.demotions_total(), 0);
}
