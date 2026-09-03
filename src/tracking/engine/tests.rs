use super::*;
use std::net::Ipv4Addr;

fn test_config() -> TrackingConfig {
    TrackingConfig {
        max_devices: 3,
        ..TrackingConfig::default()
    }
}

/// `maybe_roll_day` rolls exactly once at a day boundary and is a
/// no-op within the same day, so the baseline is stable across the
/// many reads/sweeps that happen during a day.
#[test]
fn maybe_roll_day_is_idempotent_within_a_day() {
    let d = DeviceStats::new(CompactString::from("x"), CompactString::from("default"));
    d.queries.store(500, Ordering::Relaxed);
    let today: u64 = 20_641;

    // First call on a never-seeded device rolls: seeds baseline =
    // cumulative, stamps the day.
    assert!(d.maybe_roll_day(today));
    assert_eq!(d.queries_today_baseline.load(Ordering::Relaxed), 500);
    assert_eq!(d.today_day_index.load(Ordering::Relaxed), today);

    // Same day, more traffic: no roll, baseline preserved, today is
    // the real delta.
    d.queries.store(560, Ordering::Relaxed);
    assert!(!d.maybe_roll_day(today));
    assert_eq!(d.queries_today_baseline.load(Ordering::Relaxed), 500);
    assert_eq!(d.queries_today(today * 86_400 + 60), 60);

    // Next day: rolls again, baseline re-seeds, today resets to 0.
    assert!(d.maybe_roll_day(today + 1));
    assert_eq!(d.queries_today_baseline.load(Ordering::Relaxed), 560);
    assert_eq!(d.queries_today((today + 1) * 86_400 + 60), 0);
}

/// Regression for the Devices-tab "Q.TODAY all zero" bug: the
/// background sweep must seed the baseline so the operator's *first*
/// poll of the day returns the real same-day delta, not 0. Before
/// the fix the baseline was seeded lazily on that first read, which
/// collapsed today to 0 on a headless box no dashboard polled early.
#[test]
fn roll_today_baselines_seeds_before_first_read() {
    let engine = StatsEngine::new(&test_config());
    let ip: IpAddr = Ipv4Addr::new(10, 0, 0, 1).into();

    // Device restored from a prior-day snapshot: cumulative carried
    // over, baseline/day-index still at their never-seeded defaults.
    let stats = DeviceStats::new(CompactString::from("tv"), CompactString::from("default"));
    stats.queries.store(1_000, Ordering::Relaxed);
    engine.devices.insert(ip, stats);

    let today: u64 = 20_641;
    let now = today * 86_400 + 12 * 3_600; // noon UTC

    // Sweep runs (once per snapshot tick) and anchors the baseline.
    engine.roll_today_baselines(now);

    // Traffic arrives after the anchor.
    let dev = engine.devices.get(&ip).unwrap();
    dev.queries.fetch_add(7, Ordering::Relaxed);

    // First read of the day reports the real delta, not 0. Read with
    // the same controlled `now` (not `list_observed_ips`, which
    // samples the real clock and would make this a time-bomb test).
    assert_eq!(dev.queries_today(now), 7);
}

#[test]
fn record_query_increments_global_counters() {
    let engine = StatsEngine::new(&test_config());
    let ip: IpAddr = Ipv4Addr::new(192, 168, 1, 1).into();

    engine.record_query(
        ip,
        "google.com",
        None,
        None,
        RecordType::A,
        false,
        false,
        None,
    );
    engine.record_query(
        ip,
        "ads.example.com",
        None,
        None,
        RecordType::A,
        true,
        false,
        None,
    );
    engine.record_query(
        ip,
        "google.com",
        None,
        None,
        RecordType::A,
        false,
        true,
        None,
    );

    assert_eq!(engine.global.total_queries.load(Ordering::Relaxed), 3);
    assert_eq!(engine.global.total_blocked.load(Ordering::Relaxed), 1);
    assert_eq!(engine.global.total_cache_hits.load(Ordering::Relaxed), 1);
    // §4.6 invariant: the per-type bucket distribution sums to
    // `total_queries`. Three A queries → bucket A == 3, others == 0.
    let per_type = engine.global.per_type_snapshot();
    assert_eq!(per_type.iter().sum::<u64>(), 3);
    assert_eq!(per_type[TypeBucket::A as usize], 3);
    for bucket in TypeBucket::ALL.iter().filter(|b| **b != TypeBucket::A) {
        assert_eq!(per_type[*bucket as usize], 0);
    }
    // Negative-hit counter is independent — record_query alone doesn't touch it.
    assert_eq!(
        engine
            .global
            .total_cache_negative_hits
            .load(Ordering::Relaxed),
        0
    );
}

/// §4.6 — per-type bucket counters fan out across both global and
/// per-device stats, including blocked + cache-hit queries (the
/// design doc's "count all queries into per-type" rule).
#[test]
fn record_query_fans_out_per_type_to_global_and_device() {
    let engine = StatsEngine::new(&test_config());
    let ip: IpAddr = Ipv4Addr::new(10, 0, 0, 1).into();

    engine.record_query(ip, "a.com", None, None, RecordType::A, false, false, None);
    engine.record_query(
        ip,
        "a6.com",
        None,
        None,
        RecordType::AAAA,
        false,
        false,
        None,
    );
    engine.record_query(
        ip,
        "spf.com",
        None,
        None,
        RecordType::TXT,
        true,
        false,
        None,
    );
    engine.record_query(
        ip,
        "rev.arpa",
        None,
        None,
        RecordType::PTR,
        false,
        true,
        None,
    );
    // CNAME folds into Other per design doc, alongside MX/ANY/CAA/etc.
    engine.record_query(
        ip,
        "alias.com",
        None,
        None,
        RecordType::CNAME,
        false,
        false,
        None,
    );

    let g = engine.global.per_type_snapshot();
    assert_eq!(g[TypeBucket::A as usize], 1);
    assert_eq!(g[TypeBucket::Aaaa as usize], 1);
    assert_eq!(g[TypeBucket::Txt as usize], 1);
    assert_eq!(g[TypeBucket::Ptr as usize], 1);
    assert_eq!(g[TypeBucket::Other as usize], 1, "CNAME → Other");
    assert_eq!(g.iter().sum::<u64>(), 5);

    // Per-device array tracks the same buckets independently.
    let device = engine.devices.get(&ip).unwrap();
    let d = device.per_type_snapshot();
    assert_eq!(d, g, "per-device matches global with a single client");
}

/// §4.6 — the slow-path device insert (first query from a new
/// client) must seed the per-type bucket with `1`, not leave the
/// fresh array at zero. Pin: regression of the slow-path branch
/// would silently drop the bucket increment for the first query.
#[test]
fn record_query_first_query_seeds_device_per_type() {
    let engine = StatsEngine::new(&test_config());
    let ip: IpAddr = Ipv4Addr::new(10, 0, 0, 7).into();

    engine.record_query(
        ip,
        "a.com",
        None,
        None,
        RecordType::AAAA,
        false,
        false,
        None,
    );

    let device = engine.devices.get(&ip).unwrap();
    let d = device.per_type_snapshot();
    assert_eq!(d[TypeBucket::Aaaa as usize], 1);
    assert_eq!(d.iter().sum::<u64>(), 1);
}

#[test]
fn stale_fallback_path_records_negative_cache_hit_and_query() {
    // L-2 (rev-2026-04-stats-stale-hit) regression pin: when the DNS
    // handler serves a stale entry because upstream failed, it must
    // (1) bump total_cache_hits via record_query(.., cache_hit=true)
    // and (2) bump total_cache_negative_hits via record_cache_negative_hit
    // when the stale entry is itself negative. This test pins the
    // exact StatsEngine surface the handler.rs upstream-failure branch
    // now drives — if the per-counter contract changes, the L-2 fix
    // becomes silently meaningless and operators see undercounted
    // cache hits during upstream flakiness.
    let engine = StatsEngine::new(&test_config());
    let ip: IpAddr = Ipv4Addr::new(10, 0, 0, 1).into();

    // Simulate a stale-fallback for a negative entry (NXDOMAIN/NODATA).
    engine.record_query(
        ip,
        "tracker.example.com",
        None,
        None,
        RecordType::A,
        false,
        true,
        None,
    );
    engine.record_cache_negative_hit();

    assert_eq!(engine.global.total_queries.load(Ordering::Relaxed), 1);
    assert_eq!(engine.global.total_cache_hits.load(Ordering::Relaxed), 1);
    assert_eq!(
        engine
            .global
            .total_cache_negative_hits
            .load(Ordering::Relaxed),
        1
    );
    // Stale-served queries are not blocked — they are queries that
    // upstream couldn't refresh. blocked counter must stay at 0.
    assert_eq!(engine.global.total_blocked.load(Ordering::Relaxed), 0);
}

#[test]
fn record_cache_negative_hit_is_independent_of_record_query() {
    let engine = StatsEngine::new(&test_config());

    engine.record_cache_negative_hit();
    engine.record_cache_negative_hit();

    assert_eq!(
        engine
            .global
            .total_cache_negative_hits
            .load(Ordering::Relaxed),
        2
    );
    // Calling record_cache_negative_hit does NOT bump total_queries or
    // total_cache_hits — those are record_query's responsibility. Keeping
    // the paths decoupled means the handler can compose them freely.
    assert_eq!(engine.global.total_queries.load(Ordering::Relaxed), 0);
    assert_eq!(engine.global.total_cache_hits.load(Ordering::Relaxed), 0);
}

#[test]
fn record_query_tracks_per_device() {
    let engine = StatsEngine::new(&test_config());
    let ip1: IpAddr = Ipv4Addr::new(192, 168, 1, 1).into();
    let ip2: IpAddr = Ipv4Addr::new(192, 168, 1, 2).into();

    engine.record_query(
        ip1,
        "a.com",
        Some("laptop"),
        Some("default"),
        RecordType::A,
        false,
        false,
        None,
    );
    engine.record_query(ip1, "b.com", None, None, RecordType::A, true, false, None);
    engine.record_query(
        ip2,
        "c.com",
        Some("tablet"),
        Some("kids"),
        RecordType::A,
        false,
        true,
        None,
    );

    assert_eq!(engine.devices.len(), 2);

    let c1 = engine.devices.get(&ip1).unwrap();
    assert_eq!(c1.queries.load(Ordering::Relaxed), 2);
    assert_eq!(c1.blocked.load(Ordering::Relaxed), 1);
    assert_eq!(c1.name.as_str(), "laptop");

    let c2 = engine.devices.get(&ip2).unwrap();
    assert_eq!(c2.queries.load(Ordering::Relaxed), 1);
    assert_eq!(c2.cache_hits.load(Ordering::Relaxed), 1);
    assert_eq!(c2.name.as_str(), "tablet");
    assert_eq!(c2.profile.as_str(), "kids");
}

#[test]
fn max_devices_cap_enforced() {
    let engine = StatsEngine::new(&test_config()); // max_devices = 3
    for i in 0..5u8 {
        let ip: IpAddr = Ipv4Addr::new(10, 0, 0, i).into();
        engine.record_query(
            ip,
            "test.com",
            None,
            None,
            RecordType::A,
            false,
            false,
            None,
        );
    }
    assert_eq!(engine.devices.len(), 3);
}

/// TRK-02: a saturated `devices` table must self-heal — admit a new device
/// by evicting the approximately-stalest (smallest `last_seen`) instead of
/// freezing and leaving every new device invisible until restart (the
/// IPv6-rotation-fills-the-cap failure mode).
///
/// Deterministic because n_devices (3) <= `DEVICE_EVICT_SAMPLE` (8): the
/// sample scans ALL entries, so it always picks the global-min `last_seen`.
/// A future edit that fills a larger cap with >8 devices would make
/// sample-of-N approximate — size any such fixture to the cap.
#[test]
fn devices_evicts_stalest_when_full() {
    let engine = StatsEngine::new(&test_config()); // max_devices = 3
    let ips: [IpAddr; 3] = [
        Ipv4Addr::new(10, 0, 0, 1).into(),
        Ipv4Addr::new(10, 0, 0, 2).into(),
        Ipv4Addr::new(10, 0, 0, 3).into(),
    ];
    for ip in ips {
        engine.record_query(
            ip,
            "seed.com",
            None,
            None,
            RecordType::A,
            false,
            false,
            None,
        );
    }
    assert_eq!(engine.devices.len(), 3, "table full at cap");

    // Backdate last_seen so ips[0] is the stalest, ips[2] the freshest.
    engine
        .devices
        .get(&ips[0])
        .unwrap()
        .last_seen
        .store(100, Ordering::Relaxed);
    engine
        .devices
        .get(&ips[1])
        .unwrap()
        .last_seen
        .store(300, Ordering::Relaxed);
    engine
        .devices
        .get(&ips[2])
        .unwrap()
        .last_seen
        .store(500, Ordering::Relaxed);

    // A query from a brand-new IP must be admitted, evicting the stalest.
    let new_ip: IpAddr = Ipv4Addr::new(10, 0, 0, 99).into();
    engine.record_query(
        new_ip,
        "new.com",
        None,
        None,
        RecordType::A,
        false,
        false,
        None,
    );

    assert_eq!(engine.devices.len(), 3, "still capped at max_devices");
    assert!(
        engine.devices.get(&new_ip).is_some(),
        "new device admitted (TRK-02 self-heal)"
    );
    assert!(
        engine.devices.get(&ips[0]).is_none(),
        "stalest (last_seen=100) evicted"
    );
    assert!(
        engine.devices.get(&ips[1]).is_some(),
        "fresher device retained"
    );
    assert!(
        engine.devices.get(&ips[2]).is_some(),
        "freshest device retained"
    );
    // The size counter stays consistent through the evict+insert (net 0).
    assert_eq!(
        engine.devices_len.load(Ordering::Relaxed),
        3,
        "counter tracks eviction"
    );
}

/// TRK-03: the O(1) size counters must exactly track their maps' `.len()`
/// under serial use — every insert bumps by 1, and the hot-path gate
/// reads the counter instead of `DashMap::len()`. `max_devices` is set
/// high so device eviction never fires here (that path is covered by
/// `devices_evicts_stalest_when_full`).
#[test]
fn size_counters_track_map_len_serial() {
    let config = TrackingConfig {
        max_devices: 1000,
        ..TrackingConfig::default()
    };
    let engine = StatsEngine::new(&config);
    for i in 0..60u8 {
        let ip: IpAddr = Ipv4Addr::new(10, 0, 0, i).into();
        engine.record_query(
            ip,
            &format!("domain{i}.example"),
            None,
            None,
            RecordType::A,
            i % 3 == 0, // ~1/3 blocked → exercises the blocked-only maps
            false,
            None,
        );
    }
    // Each counter equals its map's true length, exactly (serial use).
    assert_eq!(
        engine.devices_len.load(Ordering::Relaxed),
        engine.devices.len(),
        "devices_len"
    );
    assert_eq!(
        engine.domain_queries_len.load(Ordering::Relaxed),
        engine.domain_queries.len(),
        "domain_queries_len"
    );
    assert_eq!(
        engine.domain_blocked_len.load(Ordering::Relaxed),
        engine.domain_blocked.len(),
        "domain_blocked_len"
    );
    assert_eq!(
        engine.domain_queries_hourly_len.load(Ordering::Relaxed),
        engine.domain_queries_hourly.len(),
        "domain_queries_hourly_len"
    );
    assert_eq!(
        engine.domain_blocked_hourly_len.load(Ordering::Relaxed),
        engine.domain_blocked_hourly.len(),
        "domain_blocked_hourly_len"
    );
    // Sanity: the blocked maps are a strict, nonempty subset of queries.
    assert!(!engine.domain_blocked.is_empty());
    assert!(engine.domain_blocked.len() < engine.domain_queries.len());
}

/// TRK-03: `prune_domain_freq` must re-sync the size counter from ground
/// truth. A counter left pinned at cap after a prune would make the gate
/// drop every new domain forever (the freeze bug). Here the counter is
/// deliberately desynced high; the prune tick corrects it to the real
/// map length.
#[test]
fn prune_domain_freq_resyncs_size_counter() {
    let engine = StatsEngine::new(&test_config());
    engine
        .domain_queries
        .insert(CompactString::from("a.com"), AtomicU64::new(5));
    engine
        .domain_queries
        .insert(CompactString::from("b.com"), AtomicU64::new(5));
    // Simulate drift: counter claims the map is saturated.
    engine.domain_queries_len.store(9_999, Ordering::Relaxed);

    engine.prune_domain_freq();

    // Map is under MAX_DOMAIN_FREQ_ENTRIES so nothing decays; the counter
    // is simply re-synced to the true length (2).
    assert_eq!(engine.domain_queries_len.load(Ordering::Relaxed), 2);
}

#[test]
fn domain_frequency_tracked() {
    let engine = StatsEngine::new(&test_config());
    let ip: IpAddr = Ipv4Addr::new(10, 0, 0, 1).into();

    engine.record_query(
        ip,
        "google.com",
        None,
        None,
        RecordType::A,
        false,
        false,
        None,
    );
    engine.record_query(
        ip,
        "google.com",
        None,
        None,
        RecordType::A,
        false,
        false,
        None,
    );
    engine.record_query(ip, "ads.com", None, None, RecordType::A, true, false, None);

    assert_eq!(
        engine
            .domain_queries
            .get("google.com")
            .unwrap()
            .load(Ordering::Relaxed),
        2
    );
    assert_eq!(
        engine
            .domain_queries
            .get("ads.com")
            .unwrap()
            .load(Ordering::Relaxed),
        1
    );
    assert_eq!(
        engine
            .domain_blocked
            .get("ads.com")
            .unwrap()
            .load(Ordering::Relaxed),
        1
    );
    assert!(engine.domain_blocked.get("google.com").is_none());
}

#[test]
fn prune_removes_low_frequency() {
    let engine = StatsEngine::new(&test_config());
    let ip: IpAddr = Ipv4Addr::new(10, 0, 0, 1).into();

    // Add entries — "popular.com" gets 5 hits, "rare.com" gets 1
    for _ in 0..5 {
        engine.record_query(
            ip,
            "popular.com",
            None,
            None,
            RecordType::A,
            false,
            false,
            None,
        );
    }
    engine.record_query(
        ip,
        "rare.com",
        None,
        None,
        RecordType::A,
        false,
        false,
        None,
    );

    // Force prune (normally only runs when over capacity)
    engine
        .domain_queries
        .retain(|_, count| count.load(Ordering::Relaxed) > 1);

    assert!(engine.domain_queries.get("popular.com").is_some());
    assert!(engine.domain_queries.get("rare.com").is_none());
}

#[test]
fn update_device_info() {
    let engine = StatsEngine::new(&test_config());
    let ip: IpAddr = Ipv4Addr::new(192, 168, 1, 1).into();

    engine.record_query(
        ip,
        "test.com",
        Some("old-name"),
        Some("old-profile"),
        RecordType::A,
        false,
        false,
        None,
    );
    engine.update_device_info(ip, "new-name", "new-profile");

    let entry = engine.devices.get(&ip).unwrap();
    assert_eq!(entry.name.as_str(), "new-name");
    assert_eq!(entry.profile.as_str(), "new-profile");
}

#[test]
fn last_seen_timestamp_set() {
    let engine = StatsEngine::new(&test_config());
    let ip: IpAddr = Ipv4Addr::new(10, 0, 0, 1).into();

    engine.record_query(
        ip,
        "test.com",
        None,
        None,
        RecordType::A,
        false,
        false,
        None,
    );

    let entry = engine.devices.get(&ip).unwrap();
    let ts = entry.last_seen.load(Ordering::Relaxed);
    // Should be a recent unix timestamp (> 2024-01-01)
    assert!(ts > 1_704_067_200);
}

// --- list_observed_ips (Sprint 22) ---

#[test]
fn list_observed_ips_empty_before_any_query() {
    let engine = StatsEngine::new(&test_config());
    assert!(engine.list_observed_ips().is_empty());
}

#[test]
fn list_observed_ips_snapshots_counters() {
    let engine = StatsEngine::new(&test_config());
    let mapped: IpAddr = Ipv4Addr::new(192, 168, 1, 42).into();
    let unmapped: IpAddr = Ipv4Addr::new(10, 0, 0, 99).into();

    // Mapped client with a configured name+profile, 3 queries (1 blocked, 1 cache hit)
    engine.record_query(
        mapped,
        "good.com",
        Some("casey-ipad"),
        Some("kids"),
        RecordType::A,
        false,
        false,
        None,
    );
    engine.record_query(
        mapped,
        "ads.example",
        Some("casey-ipad"),
        Some("kids"),
        RecordType::A,
        true,
        false,
        None,
    );
    engine.record_query(
        mapped,
        "good.com",
        Some("casey-ipad"),
        Some("kids"),
        RecordType::A,
        false,
        true,
        None,
    );

    // Unmapped client: no name/profile → defaults to "unknown"/"default"
    engine.record_query(
        unmapped,
        "random.example",
        None,
        None,
        RecordType::A,
        false,
        false,
        None,
    );

    let mut observed = engine.list_observed_ips();
    observed.sort_by_key(|c| c.ip);

    assert_eq!(observed.len(), 2);

    let unmapped_entry = observed.iter().find(|c| c.ip == unmapped).unwrap();
    assert_eq!(unmapped_entry.name.as_str(), "unknown");
    assert_eq!(unmapped_entry.profile.as_str(), "default");
    assert_eq!(unmapped_entry.queries, 1);
    assert_eq!(unmapped_entry.blocked, 0);
    assert!(unmapped_entry.last_seen > 1_704_067_200);

    let mapped_entry = observed.iter().find(|c| c.ip == mapped).unwrap();
    assert_eq!(mapped_entry.name.as_str(), "casey-ipad");
    assert_eq!(mapped_entry.profile.as_str(), "kids");
    assert_eq!(mapped_entry.queries, 3);
    assert_eq!(mapped_entry.blocked, 1);
    assert_eq!(mapped_entry.cache_hits, 1);
}

#[test]
fn observed_device_is_online_within_window() {
    let now = 1_000_000u64;
    let device = ObservedDevice {
        ip: Ipv4Addr::new(10, 0, 0, 1).into(),
        name: CompactString::from("test"),
        profile: CompactString::from("default"),
        queries: 1,
        queries_today: 1,
        blocked: 0,
        blocked_24h: 0,
        cache_hits: 0,
        last_seen: now - 30, // 30s ago: within 60s window
        hourly_queries: Vec::new(),
    };
    assert!(device.is_online(now));

    let stale = ObservedDevice {
        last_seen: now - 120, // 120s ago: outside window
        ..device.clone()
    };
    assert!(!stale.is_online(now));

    // Boundary: exactly 60s ago is still online
    let boundary = ObservedDevice {
        last_seen: now - ONLINE_WINDOW_SECS,
        ..device.clone()
    };
    assert!(boundary.is_online(now));
}

/// When no QueryLog is attached, `log_query_event` is a no-op — no panic,
/// no side-effects, and calling it does not touch the global counters
/// (those are still the job of `record_query`).
#[test]
fn log_query_event_without_log_is_noop() {
    let engine = StatsEngine::new(&test_config());
    let ip: IpAddr = Ipv4Addr::new(10, 0, 0, 1).into();

    engine.log_query_event(
        ip,
        Some("pc"),
        "google.com",
        "A",
        "ALLOWED",
        false,
        1234,
        None,
        None,
    );

    assert_eq!(engine.global.total_queries.load(Ordering::Relaxed), 0);
    assert_eq!(engine.devices.len(), 0);
}

/// With a QueryLog attached, events are forwarded to the writer and end
/// up on disk. The writer is async, so this test spins up a tokio runtime
/// and awaits the writer's `shutdown()` (which flushes pending entries).
#[tokio::test]
async fn log_query_event_with_log_writes_to_disk() {
    use std::sync::Arc;

    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("query.log");
    let ql = Arc::new(crate::tracking::query_log::QueryLog::start(
        log_path.clone(),
        1024 * 1024,
        3,
        7,
    ));

    let engine = StatsEngine::new(&test_config());
    engine.attach_query_log(ql.clone(), log_path.clone());

    let ip: IpAddr = Ipv4Addr::new(10, 0, 0, 2).into();
    engine.log_query_event(
        ip,
        Some("laptop"),
        "ads.example",
        "A",
        "BLOCKED",
        true,
        500,
        None,
        None,
    );
    engine.log_query_event(
        ip,
        None,
        "google.com",
        "AAAA",
        "ALLOWED",
        false,
        1200,
        None,
        None,
    );

    // Drop the engine so the ArcSwap holding its clone of `ql` is
    // released; the test's `ql` is then the only Arc and `shutdown()`
    // closes the channel cleanly.
    drop(engine);
    Arc::try_unwrap(ql)
        .ok()
        .expect("only one Arc should remain")
        .shutdown()
        .await;

    let content = std::fs::read_to_string(&log_path).unwrap();
    assert!(content.contains("ads.example"));
    assert!(content.contains("BLOCKED"));
    assert!(content.contains("google.com"));
    assert!(content.contains("ALLOWED"));
    assert!(content.contains("laptop"));
}

/// §4.5 Sprint 2/2: when the DNS handler hits the cache-hit re-check
/// branch and `walk_response` returns `Verdict::Block`, it threads
/// the offending hop into `log_query_event(...)` as the new
/// `cname_chain_via` arg. The Query Log JSONL row carries the same
/// value so the TUI can render the badge.
#[tokio::test]
async fn log_query_event_with_cname_chain_via_writes_field_to_disk() {
    use std::sync::Arc;

    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("query.log");
    let ql = Arc::new(crate::tracking::query_log::QueryLog::start(
        log_path.clone(),
        1024 * 1024,
        3,
        7,
    ));
    let engine = StatsEngine::new(&test_config());
    engine.attach_query_log(ql.clone(), log_path.clone());
    let ip: IpAddr = Ipv4Addr::new(10, 0, 0, 7).into();

    engine.log_query_event(
        ip,
        Some("phone"),
        "apex.example.com",
        "A",
        "BLOCKED",
        true,
        999,
        Some("offending.tracker.example"),
        None,
    );

    drop(engine);
    Arc::try_unwrap(ql)
        .ok()
        .expect("only one Arc should remain")
        .shutdown()
        .await;

    let content = std::fs::read_to_string(&log_path).unwrap();
    assert!(content.contains("\"cname_chain_via\":\"offending.tracker.example\""));
    assert!(content.contains("apex.example.com"));
    assert!(content.contains("BLOCKED"));
}

/// §4.12 — when the rewrite hook fires, `log_query_event` receives
/// `rewrote_from = Some(original_qname)`. The Query Log JSONL row
/// must carry both `domain` (rewritten) and `rewrote_from` (original)
/// so audit grep on either side surfaces the migration trail.
#[tokio::test]
async fn log_query_event_with_rewrote_from_writes_field_to_disk() {
    use std::sync::Arc;

    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("query.log");
    let ql = Arc::new(crate::tracking::query_log::QueryLog::start(
        log_path.clone(),
        1024 * 1024,
        3,
        7,
    ));
    let engine = StatsEngine::new(&test_config());
    engine.attach_query_log(ql.clone(), log_path.clone());
    let ip: IpAddr = Ipv4Addr::new(10, 0, 0, 9).into();

    engine.log_query_event(
        ip,
        Some("laptop"),
        "api.new-corp.example-int",
        "A",
        "ALLOWED",
        false,
        420,
        None,
        Some("api.old-corp.example-int"),
    );

    drop(engine);
    Arc::try_unwrap(ql)
        .ok()
        .expect("only one Arc should remain")
        .shutdown()
        .await;

    let content = std::fs::read_to_string(&log_path).unwrap();
    assert!(
        content.contains("\"rewrote_from\":\"api.old-corp.example-int\""),
        "expected rewrote_from on disk, got: {content}"
    );
    assert!(content.contains("\"domain\":\"api.new-corp.example-int\""));
    // cname_chain_via stays absent (we passed None and serde-skips):
    assert!(!content.contains("cname_chain_via"));
}

/// §4.5 Sprint 2/2: a non-CNAME outcome calls `log_query_event`
/// with `cname_chain_via = None`. The serialised row must NOT
/// surface a spurious `cname_chain_via: null` line — same byte
/// shape as pre-S4.5-P2 entries.
#[tokio::test]
async fn log_query_event_without_cname_chain_via_omits_field() {
    use std::sync::Arc;

    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("query.log");
    let ql = Arc::new(crate::tracking::query_log::QueryLog::start(
        log_path.clone(),
        1024 * 1024,
        3,
        7,
    ));
    let engine = StatsEngine::new(&test_config());
    engine.attach_query_log(ql.clone(), log_path.clone());
    let ip: IpAddr = Ipv4Addr::new(10, 0, 0, 8).into();

    engine.log_query_event(
        ip,
        None,
        "google.com",
        "A",
        "ALLOWED",
        false,
        100,
        None,
        None,
    );

    drop(engine);
    Arc::try_unwrap(ql)
        .ok()
        .expect("only one Arc should remain")
        .shutdown()
        .await;

    let content = std::fs::read_to_string(&log_path).unwrap();
    assert!(content.contains("google.com"));
    assert!(
        !content.contains("cname_chain_via"),
        "field must be skipped when None — got: {content}"
    );
}

/// Sprint 38 QLP1: `attach_query_log` fills both slots, `detach_query_log`
/// clears them and hands back the writer handle so the caller can
/// `.shutdown().await` it. Path slot tracks the writer slot exactly.
#[tokio::test]
async fn engine_attach_then_detach_leaves_slot_none() {
    use std::sync::Arc;

    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("query.log");
    let ql = Arc::new(crate::tracking::query_log::QueryLog::start(
        log_path.clone(),
        1024 * 1024,
        3,
        7,
    ));

    let engine = StatsEngine::new(&test_config());
    assert!(engine.query_log_file_path().is_none());

    engine.attach_query_log(ql.clone(), log_path.clone());
    assert_eq!(engine.query_log_file_path(), Some(log_path.clone()));

    let detached = engine.detach_query_log();
    assert!(detached.is_some(), "detach returned the writer handle");
    assert!(
        engine.query_log_file_path().is_none(),
        "path slot cleared after detach"
    );

    // Both the outer `ql` in the test and the `detached` Arc need to be
    // dropped before shutdown() can take sole ownership of the writer.
    drop(detached);
    Arc::try_unwrap(ql)
        .ok()
        .expect("only one Arc should remain after detach")
        .shutdown()
        .await;
}

/// Sprint 38 QLP1: a detached engine (post-`detach_query_log` or never
/// attached) silently drops events — no panic, no send attempt, no
/// file I/O.
#[test]
fn log_query_event_is_noop_when_detached() {
    let engine = StatsEngine::new(&test_config());
    // Never attached — should no-op.
    let ip: IpAddr = Ipv4Addr::new(10, 0, 0, 1).into();
    engine.log_query_event(
        ip,
        Some("pc"),
        "google.com",
        "A",
        "ALLOWED",
        false,
        1234,
        None,
        None,
    );

    // Explicitly detach (even though nothing was attached) — still no-op.
    assert!(engine.detach_query_log().is_none());
    engine.log_query_event(
        ip,
        Some("pc"),
        "google.com",
        "A",
        "ALLOWED",
        false,
        1234,
        None,
        None,
    );

    assert!(engine.query_log_file_path().is_none());
    assert_eq!(engine.global.total_queries.load(Ordering::Relaxed), 0);
}

/// Sprint 38 QLP1: detaching then re-attaching a fresh writer against
/// the same path preserves the on-disk file — entries from both
/// attachments land in the same log in order. Simulates the
/// `query_log_enabled=true → false → true` toggle sequence that a
/// live `warden reload` drives.
#[tokio::test]
async fn engine_hot_reattach_preserves_file() {
    use std::sync::Arc;

    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("query.log");
    let ip: IpAddr = Ipv4Addr::new(10, 0, 0, 3).into();

    let engine = StatsEngine::new(&test_config());

    // First attachment: write 2 entries.
    let ql1 = Arc::new(crate::tracking::query_log::QueryLog::start(
        log_path.clone(),
        1024 * 1024,
        3,
        7,
    ));
    engine.attach_query_log(ql1.clone(), log_path.clone());
    engine.log_query_event(
        ip,
        None,
        "first-a.example",
        "A",
        "ALLOWED",
        false,
        100,
        None,
        None,
    );
    engine.log_query_event(
        ip,
        None,
        "first-b.example",
        "A",
        "BLOCKED",
        true,
        200,
        None,
        None,
    );

    // Detach: drop the engine's clone, then await the writer's flush.
    let detached = engine
        .detach_query_log()
        .expect("detach returned the writer handle");
    drop(detached);
    Arc::try_unwrap(ql1)
        .ok()
        .expect("only one Arc should remain after detach")
        .shutdown()
        .await;

    // Second attachment on the SAME path: file should be preserved
    // (OpenOptions::append in the writer), not truncated.
    let ql2 = Arc::new(crate::tracking::query_log::QueryLog::start(
        log_path.clone(),
        1024 * 1024,
        3,
        7,
    ));
    engine.attach_query_log(ql2.clone(), log_path.clone());
    engine.log_query_event(
        ip,
        None,
        "second-a.example",
        "A",
        "ALLOWED",
        false,
        300,
        None,
        None,
    );
    engine.log_query_event(
        ip,
        None,
        "second-b.example",
        "A",
        "BLOCKED",
        true,
        400,
        None,
        None,
    );

    // Drop the engine so the second writer is released cleanly.
    drop(engine);
    Arc::try_unwrap(ql2)
        .ok()
        .expect("only one Arc should remain")
        .shutdown()
        .await;

    let content = std::fs::read_to_string(&log_path).unwrap();
    assert!(
        content.contains("first-a.example"),
        "first attachment entries preserved"
    );
    assert!(content.contains("first-b.example"));
    assert!(
        content.contains("second-a.example"),
        "second attachment appended"
    );
    assert!(content.contains("second-b.example"));
    let first_a = content.find("first-a.example").unwrap();
    let second_a = content.find("second-a.example").unwrap();
    assert!(first_a < second_a, "first attachment writes precede second");
}

// ── Sprint 38 QLP3: log_mode filtering ──────────────────────

/// Build an engine configured with a given `log_mode`, then collect
/// the entries that made it into the attached writer's file. Shared
/// by the four `log_mode` filter-behaviour tests below so each one
/// stays short.
async fn run_log_mode_filter(
    mode: LogMode,
    events: &[(&str, &str)],
) -> Vec<crate::tracking::query_log::QueryLogEntry> {
    use std::sync::Arc;
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("query.log");
    let ql = Arc::new(crate::tracking::query_log::QueryLog::start(
        log_path.clone(),
        1024 * 1024,
        3,
        7,
    ));

    let mut cfg = test_config();
    cfg.log_mode = mode;
    let engine = StatsEngine::new(&cfg);
    engine.attach_query_log(ql.clone(), log_path.clone());

    let ip: IpAddr = Ipv4Addr::new(10, 0, 0, 9).into();
    for (domain, result) in events {
        // &'static str is required by log_query_event; these tests
        // pass a finite set of string literals via a match. The
        // `blocked` bool mirrors the handler's real assignment
        // (content blocks + security refusals are blocked:true;
        // RRL_SLIP and allowed are blocked:false).
        let (result_static, blocked): (&'static str, bool) = match *result {
            "BLOCKED" => ("BLOCKED", true),
            "REFUSED" => ("REFUSED", true),
            "RRL_DROP" => ("RRL_DROP", true),
            "RRL_SLIP" => ("RRL_SLIP", false),
            "ALLOWED" => ("ALLOWED", false),
            _ => panic!("unexpected result tag: {result}"),
        };
        engine.log_query_event(
            ip,
            None,
            domain,
            "A",
            result_static,
            blocked,
            100,
            None,
            None,
        );
    }

    drop(engine);
    Arc::try_unwrap(ql)
        .ok()
        .expect("only one Arc should remain")
        .shutdown()
        .await;

    std::fs::read_to_string(&log_path)
        .unwrap_or_default()
        .lines()
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect()
}

#[tokio::test]
async fn log_query_event_skips_allowed_when_blocked_only() {
    let entries = run_log_mode_filter(
        LogMode::BlockedOnly,
        &[
            ("a.example", "ALLOWED"),
            ("b.example", "ALLOWED"),
            ("c.example", "BLOCKED"),
        ],
    )
    .await;
    assert_eq!(
        entries.len(),
        1,
        "only blocked entries should make it through"
    );
    assert_eq!(entries[0].domain, "c.example");
}

#[tokio::test]
async fn log_query_event_always_logs_blocked_when_blocked_only() {
    let entries = run_log_mode_filter(
        LogMode::BlockedOnly,
        &[
            ("b1.example", "BLOCKED"),
            ("b2.example", "BLOCKED"),
            ("b3.example", "BLOCKED"),
        ],
    )
    .await;
    assert_eq!(entries.len(), 3, "blocked entries always pass BlockedOnly");
}

/// engine-01 (rev-2606): the security refusals introduced by 9f60205
/// (`REFUSED`, `RRL_DROP`) carry blocked:true and MUST reach the
/// blocked-only log — the operator who picks blocked-only does so
/// precisely to surface attack volume. `RRL_SLIP` (blocked:false) is
/// a TC-retry hint, not a refusal, so it stays omitted like ALLOWED.
/// Pre-fix the gate compared `result == "BLOCKED"`, so every refusal
/// was silently dropped under the Pi/privacy-recommended default.
#[tokio::test]
async fn log_query_event_logs_security_refusals_when_blocked_only() {
    let entries = run_log_mode_filter(
        LogMode::BlockedOnly,
        &[
            ("refused.example", "REFUSED"),
            ("rrldrop.example", "RRL_DROP"),
            ("slip.example", "RRL_SLIP"),
            ("allowed.example", "ALLOWED"),
            ("blocked.example", "BLOCKED"),
        ],
    )
    .await;
    let domains: Vec<&str> = entries.iter().map(|e| e.domain.as_str()).collect();
    assert!(
        domains.contains(&"refused.example"),
        "REFUSED must reach the blocked-only log"
    );
    assert!(
        domains.contains(&"rrldrop.example"),
        "RRL_DROP must reach the blocked-only log"
    );
    assert!(domains.contains(&"blocked.example"));
    assert!(
        !domains.contains(&"slip.example"),
        "RRL_SLIP (blocked:false) stays omitted under blocked-only"
    );
    assert!(
        !domains.contains(&"allowed.example"),
        "ALLOWED stays omitted under blocked-only"
    );
    assert_eq!(entries.len(), 3);
}

#[tokio::test]
async fn log_query_event_samples_allowed_at_configured_rate() {
    // rate = 0.0: blocked stays, allowed drops entirely.
    let deterministic_off = run_log_mode_filter(
        LogMode::Sampled { allowed_rate: 0.0 },
        &[
            ("a1.example", "ALLOWED"),
            ("a2.example", "ALLOWED"),
            ("b1.example", "BLOCKED"),
        ],
    )
    .await;
    assert_eq!(deterministic_off.len(), 1);
    assert_eq!(deterministic_off[0].domain, "b1.example");

    // rate = 1.0: allowed always passes through.
    let deterministic_on = run_log_mode_filter(
        LogMode::Sampled { allowed_rate: 1.0 },
        &[("a1.example", "ALLOWED"), ("a2.example", "ALLOWED")],
    )
    .await;
    assert_eq!(deterministic_on.len(), 2);

    // rate = 0.5: statistical sanity over 2000 allowed events.
    // Tolerate ±20% slack (wide enough that the test is not flaky
    // even with a fast xorshift PRNG that only has u64 state).
    use std::sync::Arc;
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("query.log");
    let ql = Arc::new(crate::tracking::query_log::QueryLog::start(
        log_path.clone(),
        4 * 1024 * 1024,
        3,
        7,
    ));
    let mut cfg = test_config();
    cfg.log_mode = LogMode::Sampled { allowed_rate: 0.5 };
    let engine = StatsEngine::new(&cfg);
    engine.attach_query_log(ql.clone(), log_path.clone());
    let ip: IpAddr = Ipv4Addr::new(10, 0, 0, 10).into();
    for i in 0..2000u32 {
        engine.log_query_event(
            ip,
            None,
            &format!("a{i}.example"),
            "A",
            "ALLOWED",
            false,
            100,
            None,
            None,
        );
    }
    drop(engine);
    Arc::try_unwrap(ql)
        .ok()
        .expect("only one Arc should remain")
        .shutdown()
        .await;
    let kept = std::fs::read_to_string(&log_path)
        .unwrap_or_default()
        .lines()
        .count();
    assert!(
        (800..=1200).contains(&kept),
        "at rate=0.5 we should keep ~1000 of 2000 allowed events, got {kept}"
    );
}

// ── Sprint 38 QLP3: TrackingConfig defaults ─────────────────

#[test]
fn tracking_config_default_retention_days_is_seven() {
    assert_eq!(TrackingConfig::default().retention_days, 7);
}

#[test]
fn tracking_config_default_log_mode_is_all() {
    assert!(matches!(TrackingConfig::default().log_mode, LogMode::All));
}

/// Closes the Sprint 37 QL3 known gap: a partial `[tracking]`
/// section that omits `query_log_enabled` must pick up the new
/// `true` default via the named default fn (QLP3).
#[test]
fn partial_tracking_section_picks_up_new_query_log_enabled_default() {
    let src = r#"
enabled = true
"#;
    let cfg: TrackingConfig = toml::from_str(src).unwrap();
    assert!(
        cfg.query_log_enabled,
        "named default kicks in on partial section"
    );
    assert_eq!(cfg.retention_days, 7);
    assert!(matches!(cfg.log_mode, LogMode::All));
}

/// Sprint B Dashboard v2 — a `record_query` with
/// `block_list_bit = Some(bit)` increments only the slot for
/// that bit. Pre-seeding mirrors the start.rs pattern; bits
/// not in the seed are silently ignored (no shard-lock).
#[test]
fn record_query_with_list_bit_increments_correct_slot() {
    let engine = StatsEngine::new(&test_config());
    // Pre-seed bits 0, 3, 7 — start.rs equivalent.
    for bit in [0u8, 3, 7] {
        engine
            .list_blocked
            .entry(bit)
            .or_insert_with(|| AtomicU64::new(0));
    }
    let ip: IpAddr = Ipv4Addr::new(192, 168, 1, 1).into();

    engine.record_query(
        ip,
        "tracker.example",
        None,
        None,
        RecordType::A,
        true,
        false,
        Some(3),
    );

    assert_eq!(
        engine.list_blocked.get(&3).unwrap().load(Ordering::Relaxed),
        1,
        "bit 3 incremented"
    );
    assert_eq!(
        engine.list_blocked.get(&0).unwrap().load(Ordering::Relaxed),
        0,
        "bit 0 untouched"
    );
    assert_eq!(
        engine.list_blocked.get(&7).unwrap().load(Ordering::Relaxed),
        0,
        "bit 7 untouched"
    );
    assert_eq!(
        engine.list_blocked.len(),
        3,
        "no new bit added — pre-seed only"
    );
}

/// Sprint B Dashboard v2 — admin-grade blocks (no `BlockSource::List`)
/// pass `block_list_bit = None`. The `list_blocked` map must stay
/// untouched even though the rest of the BLOCKED path runs (proven
/// via the `domain_blocked` increment).
#[test]
fn record_query_admin_block_does_not_touch_list_map() {
    let engine = StatsEngine::new(&test_config());
    for bit in [0u8, 3] {
        engine
            .list_blocked
            .entry(bit)
            .or_insert_with(|| AtomicU64::new(0));
    }
    let ip: IpAddr = Ipv4Addr::new(192, 168, 1, 1).into();

    engine.record_query(
        ip,
        "evil.example",
        None,
        None,
        RecordType::A,
        true,
        false,
        None, // admin block — not list-attributed
    );

    assert_eq!(
        engine.list_blocked.get(&0).unwrap().load(Ordering::Relaxed),
        0,
        "bit 0 untouched on admin block"
    );
    assert_eq!(
        engine.list_blocked.get(&3).unwrap().load(Ordering::Relaxed),
        0,
        "bit 3 untouched on admin block"
    );
    // Sanity — the BLOCKED path actually ran (domain_blocked bumped).
    assert_eq!(
        engine
            .domain_blocked
            .get("evil.example")
            .unwrap()
            .load(Ordering::Relaxed),
        1,
        "domain_blocked incremented — block path executed"
    );
}

/// `HourlyRing::record` bumps the slot for the current hour and
/// `sum_last_24h` returns the count. Cold ring sums to 0.
#[test]
fn hourly_ring_records_and_sums() {
    let ring = HourlyRing::new();
    let now: u64 = 12 * 3600 + 42;

    assert_eq!(ring.sum_last_24h(now), 0, "fresh ring sums to 0");

    for _ in 0..7 {
        ring.record(now);
    }
    assert_eq!(ring.sum_last_24h(now), 7);

    // Different second within the same hour lands in the same slot.
    for _ in 0..3 {
        ring.record(now + 600);
    }
    assert_eq!(ring.sum_last_24h(now + 600), 10);
}

/// Records older than 24h roll off the ring. Recording at hour H,
/// then advancing to H + 25 must zero the stale slot.
#[test]
fn hourly_ring_rolls_over_after_24h() {
    let ring = HourlyRing::new();
    let h0: u64 = 100 * 3600;

    for _ in 0..10 {
        ring.record(h0);
    }
    assert_eq!(ring.sum_last_24h(h0), 10);

    // 25 hours later — h0's slot now holds a stale (out-of-window)
    // hour tag, so the reader excludes it and the h25 write lands
    // in a fresh slot. No zeroing — the slot self-describes.
    let h25 = h0 + 25 * 3600;
    for _ in 0..3 {
        ring.record(h25);
    }
    assert_eq!(
        ring.sum_last_24h(h25),
        3,
        "h0 slot out of the 24h window; only h25 writes summed"
    );
}

/// §4.39 (s-orphans-disc-1) — generation-tagged slots make the
/// pre-§4.39 hour-boundary advance race structurally impossible.
/// Stress it: pre-seed a slot with a STALE hour (prior ring
/// rotation), then have many threads concurrently record into the
/// NEW hour that maps to the same slot. Every thread either wins
/// the stale→fresh CAS (exactly one, count = 1) or the +1 CAS; the
/// final count must equal the total record count with zero losses.
#[test]
fn hourly_ring_no_lost_counts_at_boundary() {
    use std::sync::{Arc, Barrier};

    const THREADS: usize = 16;
    const PER_THREAD: u64 = 500;
    let total = THREADS as u64 * PER_THREAD;

    // h_old and h_new map to the same physical slot (24h apart),
    // so every record into h_new races a stale slot.
    let h_old: u64 = 1_000;
    let h_new: u64 = h_old + DEVICE_HOURLY_SLOTS as u64;
    let now_old = h_old * 3600;
    let now_new = h_new * 3600;

    let ring = Arc::new(HourlyRing::new());
    ring.record(now_old); // seed the slot with the stale hour

    let barrier = Arc::new(Barrier::new(THREADS));
    let mut handles = Vec::with_capacity(THREADS);
    for _ in 0..THREADS {
        let ring = Arc::clone(&ring);
        let barrier = Arc::clone(&barrier);
        handles.push(std::thread::spawn(move || {
            barrier.wait();
            for _ in 0..PER_THREAD {
                ring.record(now_new);
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    // Every record into h_new must be accounted for — the stale
    // h_old seed is overwritten, never summed, nothing lost to a
    // concurrent advance.
    assert_eq!(
        ring.sum_last_24h(now_new),
        total,
        "no counts lost when many threads cross an hour boundary into a stale slot",
    );

    // Cross-check the parallel DeviceStats rings: the queries and
    // blocked rings advance independently with the same guarantee.
    let stats = Arc::new(DeviceStats::new("stress".into(), "default".into()));
    stats.record_hourly_query(now_old); // stale seed on the queries ring
    let barrier = Arc::new(Barrier::new(THREADS));
    let mut handles = Vec::with_capacity(THREADS);
    for _ in 0..THREADS {
        let stats = Arc::clone(&stats);
        let barrier = Arc::clone(&barrier);
        handles.push(std::thread::spawn(move || {
            barrier.wait();
            for _ in 0..PER_THREAD {
                stats.record_hourly_query(now_new);
                stats.record_hourly_blocked(now_new);
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    assert_eq!(
        stats.hourly_queries_last_24h(now_new).iter().sum::<u64>(),
        total,
        "queries ring lost no counts at the hour boundary",
    );
    assert_eq!(
        stats.hourly_blocked_last_24h_sum(now_new),
        total,
        "blocked ring lost no counts at the hour boundary",
    );
}

/// `hourly_queries` and `hourly_blocked` are independent
/// generation-tagged rings — a query that wasn't blocked must NOT
/// bump the blocked ring, and vice versa.
#[test]
fn device_hourly_blocked_independent_of_queries() {
    let stats = DeviceStats::new("test".into(), "default".into());
    let now: u64 = 8 * 3600 + 7;

    // 5 queries, of which 2 blocked.
    for _ in 0..5 {
        stats.record_hourly_query(now);
    }
    for _ in 0..2 {
        stats.record_hourly_blocked(now);
    }

    // Sum via the public reader — raw slot loads now return the
    // packed `(hour << 32) | count`, not a bare count.
    let queries_sum: u64 = stats.hourly_queries_last_24h(now).iter().sum();
    assert_eq!(queries_sum, 5);
    assert_eq!(stats.hourly_blocked_last_24h_sum(now), 2);
}

/// `record_query` end-to-end on the hot path bumps both the
/// lifetime DashMaps and the parallel `*_hourly` rings.
#[test]
fn record_query_increments_24h_rings() {
    let engine = StatsEngine::new(&test_config());
    // Pre-seed list_blocked + list_blocked_hourly the way start.rs
    // does (bit 3 here).
    engine.list_blocked.insert(3, AtomicU64::new(0));
    engine.list_blocked_hourly.insert(3, HourlyRing::new());

    let ip: IpAddr = Ipv4Addr::new(192, 168, 1, 1).into();
    engine.record_query(
        ip,
        "tracker.example",
        None,
        None,
        RecordType::A,
        true, // blocked
        false,
        Some(3),
    );

    // Lifetime maps bumped.
    assert_eq!(
        engine
            .domain_queries
            .get("tracker.example")
            .unwrap()
            .load(Ordering::Relaxed),
        1
    );
    assert_eq!(
        engine
            .domain_blocked
            .get("tracker.example")
            .unwrap()
            .load(Ordering::Relaxed),
        1
    );
    assert_eq!(
        engine.list_blocked.get(&3).unwrap().load(Ordering::Relaxed),
        1
    );

    // 24h rings populated under the current hour. Use a wall-clock
    // `now` so the assertion mirrors `record_query`'s own clock.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    assert_eq!(
        engine
            .domain_queries_hourly
            .get("tracker.example")
            .unwrap()
            .sum_last_24h(now),
        1
    );
    assert_eq!(
        engine
            .domain_blocked_hourly
            .get("tracker.example")
            .unwrap()
            .sum_last_24h(now),
        1
    );
    assert_eq!(
        engine
            .list_blocked_hourly
            .get(&3)
            .unwrap()
            .sum_last_24h(now),
        1
    );
}

/// `prune_hourly_map` retains entries with non-zero 24h sums when
/// the map exceeds capacity, and drops entries whose ring has aged
/// to zero. Capacity check avoids the cost on small maps.
#[test]
fn prune_hourly_map_keeps_active_drops_idle() {
    let map: DashMap<CompactString, HourlyRing> = DashMap::new();
    let now: u64 = 50 * 3600;

    // Active: recorded recently → sum_last_24h > 0.
    let r_active = HourlyRing::new();
    r_active.record(now);
    map.insert(CompactString::from("active.com"), r_active);

    // Stale: recorded >24h ago.
    let r_stale = HourlyRing::new();
    r_stale.record(now.saturating_sub(48 * 3600));
    map.insert(CompactString::from("stale.com"), r_stale);

    // Below the capacity threshold — prune is a no-op.
    prune_hourly_map(&map, now);
    assert_eq!(map.len(), 2, "below MAX_DOMAIN_FREQ_ENTRIES — no prune");

    // Force pruning by adding > MAX_DOMAIN_FREQ_ENTRIES singleton
    // stale rings. They all have zero 24h sums, so they're all
    // dropped, but active.com is retained.
    for i in 0..(MAX_DOMAIN_FREQ_ENTRIES + 1) {
        let r = HourlyRing::new();
        r.record(now.saturating_sub(48 * 3600));
        map.insert(CompactString::from(format!("stale-{i}.com")), r);
    }
    prune_hourly_map(&map, now);
    assert!(map.contains_key("active.com"), "active entry retained");
    assert!(
        !map.contains_key("stale.com"),
        "stale entry dropped after capacity prune"
    );
}

/// engine-04 (rev-2606): a lifetime frequency map saturated with
/// count>=2 entries must not stay pinned at cap — the `count > 1`
/// retain alone frees nothing (counts are monotonic). The decay pass
/// halves and reaps idle entries so newcomers can be tracked again,
/// while a popular domain keeps its (halved) dominance.
#[test]
fn prune_map_decays_saturated_map_keeping_popular() {
    let map: DashMap<CompactString, AtomicU64> = DashMap::new();
    map.insert(
        CompactString::from("popular.example"),
        AtomicU64::new(1_000_000),
    );
    for i in 0..(MAX_DOMAIN_FREQ_ENTRIES + 100) {
        map.insert(
            CompactString::from(format!("rare{i}.example")),
            AtomicU64::new(2),
        );
    }
    assert!(map.len() > MAX_DOMAIN_FREQ_ENTRIES);

    prune_map(&map);

    assert!(
        map.len() <= MAX_DOMAIN_FREQ_ENTRIES,
        "saturated map must shed entries so newcomers fit, got len {}",
        map.len()
    );
    assert!(
        map.contains_key("popular.example"),
        "the popular domain must survive decay"
    );
    assert_eq!(
        map.get("popular.example").unwrap().load(Ordering::Relaxed),
        500_000,
        "popular count is halved by one decay pass, still dominant"
    );
}
