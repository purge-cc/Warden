//! Stats snapshot persistence — write/load JSON to survive daemon restarts.
//!
//! Write path: serialize stats → write temp file → atomic rename.
//! Load path: read JSON → validate → merge into engine.
//! Background task writes every `snapshot_interval_secs` (default 120s).

use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use compact_str::CompactString;
use serde::{Deserialize, Serialize};

use super::engine::StatsEngine;
use super::query_type::TYPE_BUCKET_COUNT;
use super::time_series::TimeBucket;
use super::top_n::TopNSnapshot;

/// Serializable stats snapshot (written to disk as JSON).
#[derive(Debug, Serialize, Deserialize)]
pub struct StatsSnapshot {
    pub total_queries: u64,
    pub total_blocked: u64,
    pub total_cache_hits: u64,
    /// Subset of `total_cache_hits` served from negative entries (NXDOMAIN/NODATA).
    /// Defaults to 0 for snapshots written before this field existed.
    #[serde(default)]
    pub total_cache_negative_hits: u64,
    /// Per-`TypeBucket` query counters in canonical bucket order
    /// (`TypeBucket::ALL`). Defaults to all-zero for older snapshots —
    /// operators upgrading mid-day see the per-type widget light up
    /// from zero rather than disappearing.
    #[serde(default = "zero_per_type")]
    pub per_type: [u64; TYPE_BUCKET_COUNT],
    /// Per-`TypeBucket` BLOCKED query counters. Parallel to `per_type`,
    /// only incremented when the query was blocked. Defaults to all-zero
    /// for older snapshots so the QTYPE chart card lights up from zero
    /// on upgrade rather than failing the load.
    #[serde(default = "zero_per_type")]
    pub per_type_blocked: [u64; TYPE_BUCKET_COUNT],
    /// Cumulative count of prefetch-set promotions since the tracker
    /// was last reset. Defaults to 0 for snapshots written before this
    /// field existed.
    #[serde(default)]
    pub prefetch_promotions_total: u64,
    /// Cumulative count of prefetch-set demotions since the tracker
    /// was last reset. Defaults to 0 for snapshots written before this
    /// field existed.
    #[serde(default)]
    pub prefetch_demotions_total: u64,
    /// Per-device entries. Serialized as `devices` (the canonical name);
    /// old snapshots with the legacy `clients` key still deserialize via
    /// the alias.
    #[serde(alias = "clients")]
    pub devices: Vec<DeviceSnapshot>,
    pub top_n: TopNSnapshot,
    pub hourly: Vec<TimeBucket>,
    pub daily: Vec<TimeBucket>,
}

/// Per-device stats in the snapshot.
#[derive(Debug, Serialize, Deserialize)]
pub struct DeviceSnapshot {
    pub ip: String,
    pub name: String,
    pub profile: String,
    pub queries: u64,
    pub blocked: u64,
    pub cache_hits: u64,
    pub last_seen: u64,
    /// Per-bucket query counters. Defaults to all-zero for older
    /// snapshots so the device row still loads — the per-device pie
    /// will be empty until the device makes its next query.
    #[serde(default = "zero_per_type")]
    pub per_type: [u64; TYPE_BUCKET_COUNT],
    /// Per-bucket BLOCKED query counters for this device. Parallel to
    /// `per_type`, defaults to all-zero for older snapshots.
    #[serde(default = "zero_per_type")]
    pub per_type_blocked: [u64; TYPE_BUCKET_COUNT],
    /// Snapshot of `DeviceStats::queries_today_baseline` — the cumulative
    /// query count at the start of `today_day_index`'s day. Persisted so
    /// "queries today" survives a daemon restart instead of re-seeding to
    /// the current total (a mid-day restart otherwise collapsed every
    /// device's today count to ~0). Defaults to 0 for snapshots written
    /// before this field existed.
    #[serde(default)]
    pub queries_today_baseline: u64,
    /// Snapshot of `DeviceStats::today_day_index` (UTC `unix_secs /
    /// 86400`) the baseline above belongs to. On restore a stale index
    /// (snapshot from a previous day) is rolled forward on the first
    /// snapshot-task tick; a matching index preserves an intra-day count
    /// across the restart. Defaults to 0 for snapshots written before
    /// this field existed.
    #[serde(default)]
    pub today_day_index: u64,
}

/// Default helper for `#[serde(default)]` on `[u64; TYPE_BUCKET_COUNT]`
/// fields. Serde can't auto-derive a `Default` for arbitrary array
/// lengths, so we name the function explicitly.
fn zero_per_type() -> [u64; TYPE_BUCKET_COUNT] {
    [0; TYPE_BUCKET_COUNT]
}

impl StatsSnapshot {
    /// Capture current engine state into a snapshot.
    pub fn capture(engine: &StatsEngine) -> Self {
        let devices: Vec<DeviceSnapshot> = engine
            .devices
            .iter()
            .map(|entry| DeviceSnapshot {
                ip: entry.key().to_string(),
                name: entry.value().name.to_string(),
                profile: entry.value().profile.to_string(),
                queries: entry.value().queries.load(Ordering::Relaxed),
                blocked: entry.value().blocked.load(Ordering::Relaxed),
                cache_hits: entry.value().cache_hits.load(Ordering::Relaxed),
                last_seen: entry.value().last_seen.load(Ordering::Relaxed),
                per_type: entry.value().per_type_snapshot(),
                per_type_blocked: entry.value().blocked_per_type_snapshot(),
                queries_today_baseline: entry
                    .value()
                    .queries_today_baseline
                    .load(Ordering::Relaxed),
                today_day_index: entry.value().today_day_index.load(Ordering::Relaxed),
            })
            .collect();

        let top_n = (**engine.top_n.load()).clone();

        Self {
            total_queries: engine.global.total_queries.load(Ordering::Relaxed),
            total_blocked: engine.global.total_blocked.load(Ordering::Relaxed),
            total_cache_hits: engine.global.total_cache_hits.load(Ordering::Relaxed),
            total_cache_negative_hits: engine
                .global
                .total_cache_negative_hits
                .load(Ordering::Relaxed),
            per_type: engine.global.per_type_snapshot(),
            per_type_blocked: engine.global.blocked_per_type_snapshot(),
            prefetch_promotions_total: engine.prefetch_tracker.promotions_total(),
            prefetch_demotions_total: engine.prefetch_tracker.demotions_total(),
            devices,
            top_n,
            hourly: engine.time_series.hourly_snapshot(),
            daily: engine.time_series.daily_snapshot(),
        }
    }

    /// Write snapshot to a file atomically via the hardened helper
    /// (fsync on temp + parent dir, preserve target mode/owner if any),
    /// rather than a raw `fs::write` + `rename` pair — the same
    /// primitive `lists/{manager,status}.rs` route through, so the
    /// atomicity guarantee is consistent across modules.
    pub fn write_to_file(&self, path: &Path) -> anyhow::Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        crate::config::atomic_write::hardened_atomic_write(
            path,
            json.as_bytes(),
            crate::config::atomic_write::AtomicWriteOpts::default(),
        )
        .map_err(|e| anyhow::anyhow!("{e}"))
    }

    /// Load snapshot from a JSON file. Returns None if file doesn't exist.
    pub fn load_from_file(path: &Path) -> anyhow::Result<Option<Self>> {
        if !path.exists() {
            return Ok(None);
        }
        let content = std::fs::read_to_string(path)?;
        let snapshot: Self = serde_json::from_str(&content)
            .map_err(|e| anyhow::anyhow!("corrupted stats snapshot: {e}"))?;
        Ok(Some(snapshot))
    }

    /// Merge loaded snapshot data into a running engine.
    pub fn merge_into(self, engine: &StatsEngine) {
        // Restore global counters
        engine
            .global
            .total_queries
            .store(self.total_queries, Ordering::Relaxed);
        engine
            .global
            .total_blocked
            .store(self.total_blocked, Ordering::Relaxed);
        engine
            .global
            .total_cache_hits
            .store(self.total_cache_hits, Ordering::Relaxed);
        engine
            .global
            .total_cache_negative_hits
            .store(self.total_cache_negative_hits, Ordering::Relaxed);
        for (i, count) in self.per_type.iter().enumerate() {
            engine.global.per_type[i].store(*count, Ordering::Relaxed);
        }
        for (i, count) in self.per_type_blocked.iter().enumerate() {
            engine.global.blocked_per_type[i].store(*count, Ordering::Relaxed);
        }
        engine.prefetch_tracker.restore_counters(
            self.prefetch_promotions_total,
            self.prefetch_demotions_total,
        );

        // Restore per-device stats, newest first, up to the same
        // `max_devices` cap the hot path enforces (`record_query` in
        // engine.rs). A snapshot carrying more rows than the cap
        // (corruption, manual edit, or a cap lowered between runs) must
        // not repopulate the map above its bound; keep the freshest by
        // `last_seen` and stop at the cap.
        let mut devices = self.devices;
        devices.sort_unstable_by_key(|b| std::cmp::Reverse(b.last_seen));
        for ds in devices {
            // Gate on the engine's O(1) size counter, the same source of
            // truth the hot path uses. Fresh engine → starts at 0.
            if engine.devices_len.load(Ordering::Relaxed) >= engine.max_devices {
                break;
            }
            if let Ok(ip) = ds.ip.parse() {
                let stats = super::engine::DeviceStats::new(
                    CompactString::from(ds.name),
                    CompactString::from(ds.profile),
                );
                stats.queries.store(ds.queries, Ordering::Relaxed);
                stats.blocked.store(ds.blocked, Ordering::Relaxed);
                stats.cache_hits.store(ds.cache_hits, Ordering::Relaxed);
                stats.last_seen.store(ds.last_seen, Ordering::Relaxed);
                for (i, count) in ds.per_type.iter().enumerate() {
                    stats.per_type[i].store(*count, Ordering::Relaxed);
                }
                for (i, count) in ds.per_type_blocked.iter().enumerate() {
                    stats.blocked_per_type[i].store(*count, Ordering::Relaxed);
                }
                stats
                    .queries_today_baseline
                    .store(ds.queries_today_baseline, Ordering::Relaxed);
                stats
                    .today_day_index
                    .store(ds.today_day_index, Ordering::Relaxed);
                // Maintain the O(1) size counter on restore. Only a fresh
                // key (`insert` returns `None`) bumps it, so a snapshot with
                // duplicate IP rows can't over-count.
                if engine.devices.insert(ip, stats).is_none() {
                    engine.devices_len.fetch_add(1, Ordering::Relaxed);
                }
            }
        }

        // Restore time-series
        engine.time_series.load(self.hourly, self.daily);

        // Restore top-N
        engine.top_n.store(Arc::new(self.top_n));
    }
}

/// Spawn background snapshot writer task.
pub fn spawn_snapshot_task(
    engine: Arc<StatsEngine>,
    path: PathBuf,
    interval: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        // `tokio::time::interval` panics on a zero period — under the release
        // profile's `panic = "abort"` that kills the daemon. The validator
        // rejects `tracking.snapshot_interval_secs = 0`; this floor is the
        // backstop for construction paths that bypass it (mirrors
        // prefetch_worker).
        let mut ticker = tokio::time::interval(interval.max(Duration::from_secs(1)));
        ticker.tick().await; // skip first immediate tick
        loop {
            ticker.tick().await;
            // `capture` walks the device shards and `write_to_file` fsyncs
            // the temp file + parent dir; on SD-class storage that fsync can
            // block tens-to-hundreds of ms. Run it on the blocking pool so
            // it never stalls a tokio worker that may be polling a DNS
            // future (a thread parked in fsync can't be work-stolen).
            let engine_c = Arc::clone(&engine);
            let path_c = path.clone();
            let result = tokio::task::spawn_blocking(move || {
                // Seed each device's "today" baseline to the current UTC
                // day *before* capturing, so the anchor exists near real
                // midnight even on a headless box no dashboard polls
                // (otherwise the operator's first read seeds it mid-day
                // and "today" collapses to ~0). Persisting the rolled
                // baseline in the same capture makes "today" survive the
                // next restart too.
                let now_secs = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                engine_c.roll_today_baselines(now_secs);
                StatsSnapshot::capture(&engine_c).write_to_file(&path_c)
            })
            .await;
            match result {
                Ok(Ok(())) => {
                    tracing::debug!(path = %path.display(), "stats snapshot written");
                }
                Ok(Err(e)) => {
                    tracing::warn!(error = %e, "failed to write stats snapshot");
                }
                Err(e) => {
                    tracing::warn!(error = %e, "stats snapshot task panicked");
                }
            }
        }
    })
}

/// Write a final snapshot (called on shutdown).
pub fn write_final_snapshot(engine: &StatsEngine, path: &Path) {
    let snapshot = StatsSnapshot::capture(engine);
    if let Err(e) = snapshot.write_to_file(path) {
        tracing::warn!(error = %e, "failed to write final stats snapshot");
    } else {
        tracing::info!(path = %path.display(), "final stats snapshot written");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::settings::TrackingConfig;
    use hickory_proto::rr::RecordType;
    use std::net::{IpAddr, Ipv4Addr};

    /// A zero interval reaching the spawn site must not panic the task —
    /// `tokio::time::interval(0)` panics and the release profile aborts on
    /// panic. The `.max(1 s)` floor is the backstop for construction paths
    /// that bypass the validator gate. The bogus path is never written:
    /// the first (immediate) tick is skipped and the test ends before the
    /// floored 1 s period elapses.
    #[tokio::test]
    async fn zero_interval_does_not_panic_task() {
        let config = TrackingConfig::default();
        let engine = std::sync::Arc::new(StatsEngine::new(&config));
        let handle = spawn_snapshot_task(
            engine,
            PathBuf::from("/nonexistent/purge-warden-test/snapshot.bin"),
            Duration::ZERO,
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!handle.is_finished(), "task died on zero interval");
        handle.abort();
    }

    #[test]
    fn snapshot_roundtrip() {
        let config = TrackingConfig::default();
        let engine = StatsEngine::new(&config);
        let ip: IpAddr = Ipv4Addr::new(192, 168, 1, 1).into();

        engine.record_query(
            ip,
            "google.com",
            Some("laptop"),
            Some("default"),
            RecordType::A,
            false,
            false,
            None,
        );
        engine.record_query(
            ip,
            "ads.com",
            None,
            None,
            RecordType::AAAA,
            true,
            false,
            None,
        );
        engine.record_query(
            ip,
            "cached.com",
            None,
            None,
            RecordType::TXT,
            false,
            true,
            None,
        );
        engine.record_cache_negative_hit();
        engine.record_cache_negative_hit();

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("stats.json");

        // Write
        let snapshot = StatsSnapshot::capture(&engine);
        snapshot.write_to_file(&path).unwrap();

        // Read
        let loaded = StatsSnapshot::load_from_file(&path).unwrap().unwrap();
        assert_eq!(loaded.total_queries, 3);
        assert_eq!(loaded.total_blocked, 1);
        assert_eq!(loaded.total_cache_hits, 1);
        assert_eq!(loaded.total_cache_negative_hits, 2);
        // Per-type counters round-trip in both global and per-device fields.
        assert_eq!(loaded.per_type[0], 1, "global A bucket");
        assert_eq!(loaded.per_type[1], 1, "global AAAA bucket");
        assert_eq!(loaded.per_type[2], 1, "global TXT bucket");
        assert_eq!(loaded.per_type.iter().sum::<u64>(), 3);
        // Only the AAAA query (`ads.com`) was blocked, so exactly one
        // bucket of `per_type_blocked` should be set.
        assert_eq!(loaded.per_type_blocked[0], 0, "global A blocked");
        assert_eq!(loaded.per_type_blocked[1], 1, "global AAAA blocked");
        assert_eq!(loaded.per_type_blocked[2], 0, "global TXT blocked");
        assert_eq!(loaded.per_type_blocked.iter().sum::<u64>(), 1);
        assert_eq!(loaded.devices.len(), 1);
        assert_eq!(loaded.devices[0].name, "laptop");
        // The single device made all three queries — its per-type
        // matches the global per-type byte-for-byte.
        assert_eq!(loaded.devices[0].per_type, loaded.per_type);
        assert_eq!(loaded.devices[0].per_type_blocked, loaded.per_type_blocked);
    }

    /// Regression: per-device "today" baseline + day index must survive a
    /// snapshot round-trip so "queries today" isn't wiped by a restart —
    /// the mid-day-restart → Q.TODAY=0 bug. Capture → file → load →
    /// `merge_into` a fresh engine, then confirm the same-day delta is
    /// preserved across the simulated restart.
    #[test]
    fn snapshot_roundtrips_today_baseline() {
        use crate::tracking::engine::DeviceStats;

        let config = TrackingConfig::default();
        let engine = StatsEngine::new(&config);
        let ip: IpAddr = Ipv4Addr::new(10, 0, 0, 7).into();

        let stats = DeviceStats::new(CompactString::from("tv"), CompactString::from("default"));
        stats.queries.store(1_000, Ordering::Relaxed);
        stats.queries_today_baseline.store(880, Ordering::Relaxed);
        stats.today_day_index.store(20_641, Ordering::Relaxed);
        engine.devices.insert(ip, stats);

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("stats.json");
        StatsSnapshot::capture(&engine)
            .write_to_file(&path)
            .unwrap();

        let loaded = StatsSnapshot::load_from_file(&path).unwrap().unwrap();
        assert_eq!(loaded.devices.len(), 1);
        assert_eq!(loaded.devices[0].queries_today_baseline, 880);
        assert_eq!(loaded.devices[0].today_day_index, 20_641);

        // Merge into a fresh engine (simulates a restart) and confirm the
        // anchor survived: today = 1000 - 880 = 120 on the same UTC day.
        // Read via the device directly with a controlled `now` (noon of
        // day 20_641) — `list_observed_ips` samples the real clock, which
        // would roll a different day and make this a time-bomb test.
        let restored = StatsEngine::new(&config);
        loaded.merge_into(&restored);
        let now = 20_641 * 86_400 + 12 * 3_600;
        let dev = restored.devices.get(&ip).unwrap();
        assert_eq!(dev.queries_today(now), 120);
    }

    /// A snapshot written before `per_type` existed (no `per_type` keys
    /// at all) must still deserialize, defaulting both global and
    /// per-device per-type arrays to all-zero.
    #[test]
    fn snapshot_legacy_without_per_type_deserializes_to_zero() {
        let legacy_json = serde_json::json!({
            "total_queries": 12,
            "total_blocked": 3,
            "total_cache_hits": 5,
            "total_cache_negative_hits": 2,
            "devices": [{
                "ip": "10.0.0.42",
                "name": "legacy-laptop",
                "profile": "default",
                "queries": 12,
                "blocked": 3,
                "cache_hits": 5,
                "last_seen": 1700000000
            }],
            "top_n": { "top_queried": [], "top_blocked": [] },
            "hourly": [],
            "daily": []
        });
        let parsed: StatsSnapshot = serde_json::from_value(legacy_json).unwrap();
        assert_eq!(parsed.total_queries, 12);
        assert_eq!(parsed.per_type, [0u64; 10]);
        assert_eq!(parsed.per_type_blocked, [0u64; 10]);
        assert_eq!(parsed.devices[0].per_type, [0u64; 10]);
        assert_eq!(parsed.devices[0].per_type_blocked, [0u64; 10]);
        // Older snapshots carry no "today" anchor — both fields must
        // default to 0 so the row still loads (the first snapshot sweep
        // re-seeds them on the next tick).
        assert_eq!(parsed.devices[0].queries_today_baseline, 0);
        assert_eq!(parsed.devices[0].today_day_index, 0);
    }

    /// A snapshot written after `per_type` existed but before
    /// `per_type_blocked` (has `per_type` but no `per_type_blocked`)
    /// must still deserialize, defaulting both global and per-device
    /// blocked arrays to zero.
    #[test]
    fn snapshot_legacy_without_per_type_blocked_deserializes_to_zero() {
        let legacy_json = serde_json::json!({
            "total_queries": 20,
            "total_blocked": 5,
            "total_cache_hits": 8,
            "total_cache_negative_hits": 1,
            "per_type": [10, 5, 0, 0, 0, 0, 0, 0, 3, 2],
            "devices": [{
                "ip": "10.0.0.42",
                "name": "midcycle-laptop",
                "profile": "default",
                "queries": 20,
                "blocked": 5,
                "cache_hits": 8,
                "last_seen": 1700000000,
                "per_type": [10, 5, 0, 0, 0, 0, 0, 0, 3, 2]
            }],
            "top_n": { "top_queried": [], "top_blocked": [] },
            "hourly": [],
            "daily": []
        });
        let parsed: StatsSnapshot = serde_json::from_value(legacy_json).unwrap();
        assert_eq!(parsed.per_type[0], 10, "per_type retained");
        assert_eq!(parsed.per_type_blocked, [0u64; 10]);
        assert_eq!(parsed.devices[0].per_type[0], 10);
        assert_eq!(parsed.devices[0].per_type_blocked, [0u64; 10]);
    }

    /// Legacy migration: a snapshot written before `total_cache_negative_hits`
    /// existed must still deserialize, defaulting the missing field to zero.
    /// The legacy `clients` key doubles as the alias path for `devices`.
    #[test]
    fn snapshot_legacy_without_negative_hits_deserializes() {
        let legacy_json = serde_json::json!({
            "total_queries": 100,
            "total_blocked": 10,
            "total_cache_hits": 50,
            "clients": [],
            "top_n": {
                "top_queried": [],
                "top_blocked": []
            },
            "hourly": [],
            "daily": []
        });
        let parsed: StatsSnapshot = serde_json::from_value(legacy_json).unwrap();
        assert_eq!(parsed.total_queries, 100);
        assert_eq!(parsed.total_cache_negative_hits, 0);
    }

    /// Decode-compat: a snapshot with the legacy `clients` JSON key must
    /// still deserialize into the renamed `devices` field via the serde
    /// alias.
    #[test]
    fn snapshot_legacy_clients_key_deserializes_into_devices() {
        let legacy_json = serde_json::json!({
            "total_queries": 7,
            "total_blocked": 2,
            "total_cache_hits": 1,
            "total_cache_negative_hits": 0,
            "clients": [{
                "ip": "10.0.0.42",
                "name": "legacy-laptop",
                "profile": "default",
                "queries": 7,
                "blocked": 2,
                "cache_hits": 1,
                "last_seen": 1700000000
            }],
            "top_n": { "top_queried": [], "top_blocked": [] },
            "hourly": [],
            "daily": []
        });
        let parsed: StatsSnapshot = serde_json::from_value(legacy_json).unwrap();
        assert_eq!(parsed.devices.len(), 1);
        assert_eq!(parsed.devices[0].name, "legacy-laptop");
    }

    /// Canonical path: a snapshot with the `devices` JSON key deserializes
    /// into the `devices` field directly (no alias involvement).
    #[test]
    fn snapshot_canonical_devices_key_deserializes() {
        let canonical_json = serde_json::json!({
            "total_queries": 3,
            "total_blocked": 0,
            "total_cache_hits": 0,
            "total_cache_negative_hits": 0,
            "devices": [{
                "ip": "10.0.0.42",
                "name": "canonical-laptop",
                "profile": "kids",
                "queries": 3,
                "blocked": 0,
                "cache_hits": 0,
                "last_seen": 1700000001
            }],
            "top_n": { "top_queried": [], "top_blocked": [] },
            "hourly": [],
            "daily": []
        });
        let parsed: StatsSnapshot = serde_json::from_value(canonical_json).unwrap();
        assert_eq!(parsed.devices.len(), 1);
        assert_eq!(parsed.devices[0].name, "canonical-laptop");
        assert_eq!(parsed.devices[0].profile, "kids");
    }

    #[test]
    fn snapshot_merge_into_engine() {
        let config = TrackingConfig::default();
        let engine1 = StatsEngine::new(&config);
        let ip: IpAddr = Ipv4Addr::new(10, 0, 0, 1).into();

        engine1.record_query(
            ip,
            "test.com",
            Some("pc"),
            Some("default"),
            RecordType::A,
            false,
            false,
            None,
        );
        engine1.record_query(ip, "test.com", None, None, RecordType::A, true, false, None);

        let snapshot = StatsSnapshot::capture(&engine1);

        // Merge into fresh engine
        let engine2 = StatsEngine::new(&config);
        snapshot.merge_into(&engine2);

        assert_eq!(engine2.global.total_queries.load(Ordering::Relaxed), 2);
        assert_eq!(engine2.global.total_blocked.load(Ordering::Relaxed), 1);
        assert_eq!(engine2.devices.len(), 1);
        let entry = engine2.devices.get(&ip).unwrap();
        assert_eq!(entry.name.as_str(), "pc");
    }

    /// A snapshot carrying more device rows than `max_devices` (e.g. a
    /// cap lowered between runs) must not repopulate the map above the
    /// bound the hot path upholds; the freshest devices by `last_seen`
    /// survive.
    #[test]
    fn merge_into_enforces_max_devices_cap() {
        let json = serde_json::json!({
            "total_queries": 0,
            "total_blocked": 0,
            "total_cache_hits": 0,
            "total_cache_negative_hits": 0,
            "devices": [
                {"ip":"10.0.0.1","name":"a","profile":"default","queries":1,"blocked":0,"cache_hits":0,"last_seen":100},
                {"ip":"10.0.0.2","name":"b","profile":"default","queries":1,"blocked":0,"cache_hits":0,"last_seen":400},
                {"ip":"10.0.0.3","name":"c","profile":"default","queries":1,"blocked":0,"cache_hits":0,"last_seen":300},
                {"ip":"10.0.0.4","name":"d","profile":"default","queries":1,"blocked":0,"cache_hits":0,"last_seen":200}
            ],
            "top_n": { "top_queried": [], "top_blocked": [] },
            "hourly": [],
            "daily": []
        });
        let snapshot: StatsSnapshot = serde_json::from_value(json).unwrap();

        let config = TrackingConfig {
            max_devices: 2,
            ..TrackingConfig::default()
        };
        let engine = StatsEngine::new(&config);
        snapshot.merge_into(&engine);

        assert_eq!(
            engine.devices.len(),
            2,
            "restored devices must be capped at max_devices"
        );
        // Freshest two by last_seen: 10.0.0.2 (400) and 10.0.0.3 (300).
        let ip2: IpAddr = "10.0.0.2".parse().unwrap();
        let ip3: IpAddr = "10.0.0.3".parse().unwrap();
        assert!(engine.devices.get(&ip2).is_some(), "freshest kept");
        assert!(engine.devices.get(&ip3).is_some(), "2nd freshest kept");
    }

    #[test]
    fn load_nonexistent_returns_none() {
        let result = StatsSnapshot::load_from_file(Path::new("/nonexistent/stats.json")).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn load_corrupted_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.json");
        std::fs::write(&path, "not valid json {{{").unwrap();

        let result = StatsSnapshot::load_from_file(&path);
        assert!(result.is_err());
    }

    /// Capture must read the prefetch tracker counters and round-trip
    /// them via merge_into. The tracker itself is built disabled by
    /// default in `StatsEngine::new`, so we install a live one via
    /// `with_prefetch_config` to exercise the wiring.
    #[test]
    fn snapshot_captures_prefetch_promotions_demotions() {
        use crate::tracking::PrefetchTrackerConfig;
        let tracking = TrackingConfig::default();
        let prefetch = PrefetchTrackerConfig {
            enabled: true,
            window_secs: 60,
            min_hits: 2,
            max_pool_size: 16,
        };
        let engine1 = StatsEngine::with_prefetch_config(&tracking, &prefetch);
        // 2 hits → promotion (min_hits = 2).
        engine1.prefetch_tracker.record_hit("hot.example", 0);
        engine1.prefetch_tracker.record_hit("hot.example", 1);
        // window 2 with 1 hit → demotion.
        engine1.prefetch_tracker.record_hit("hot.example", 60);
        assert_eq!(engine1.prefetch_tracker.promotions_total(), 1);
        assert_eq!(engine1.prefetch_tracker.demotions_total(), 1);

        let snapshot = StatsSnapshot::capture(&engine1);
        assert_eq!(snapshot.prefetch_promotions_total, 1);
        assert_eq!(snapshot.prefetch_demotions_total, 1);

        let engine2 = StatsEngine::with_prefetch_config(&tracking, &prefetch);
        snapshot.merge_into(&engine2);
        assert_eq!(engine2.prefetch_tracker.promotions_total(), 1);
        assert_eq!(engine2.prefetch_tracker.demotions_total(), 1);
    }

    /// Older snapshots embed `TimeBucket` entries without `per_type` /
    /// `blocked_per_type` keys. Both must default to all-zero so a
    /// daemon upgrading mid-day picks up the existing hourly ring
    /// without an error; live traffic backfills the per-type counters
    /// as buckets roll over.
    #[test]
    fn snapshot_legacy_time_bucket_without_per_type_deserializes_to_zero() {
        let legacy_json = serde_json::json!({
            "total_queries": 10,
            "total_blocked": 2,
            "total_cache_hits": 5,
            "total_cache_negative_hits": 0,
            "devices": [],
            "top_n": { "top_queried": [], "top_blocked": [] },
            "hourly": [{
                "timestamp": 1700000000,
                "queries": 10,
                "blocked": 2,
                "cache_hits": 5
            }],
            "daily": [{
                "timestamp": 1700000000,
                "queries": 10,
                "blocked": 2,
                "cache_hits": 5
            }]
        });
        let parsed: StatsSnapshot = serde_json::from_value(legacy_json).unwrap();
        assert_eq!(parsed.hourly.len(), 1);
        assert_eq!(parsed.hourly[0].queries, 10);
        assert_eq!(parsed.hourly[0].per_type, [0u64; TYPE_BUCKET_COUNT]);
        assert_eq!(parsed.hourly[0].blocked_per_type, [0u64; TYPE_BUCKET_COUNT]);
        assert_eq!(parsed.daily.len(), 1);
        assert_eq!(parsed.daily[0].per_type, [0u64; TYPE_BUCKET_COUNT]);
        assert_eq!(parsed.daily[0].blocked_per_type, [0u64; TYPE_BUCKET_COUNT]);
    }

    /// Older snapshots have neither `prefetch_promotions_total` nor
    /// `prefetch_demotions_total`. Both must default to zero so a
    /// daemon upgrading mid-day picks up the existing on-disk state
    /// without an error.
    #[test]
    fn snapshot_legacy_without_prefetch_fields_deserializes_to_zero() {
        let legacy_json = serde_json::json!({
            "total_queries": 100,
            "total_blocked": 10,
            "total_cache_hits": 50,
            "total_cache_negative_hits": 2,
            "devices": [],
            "top_n": { "top_queried": [], "top_blocked": [] },
            "hourly": [],
            "daily": []
        });
        let parsed: StatsSnapshot = serde_json::from_value(legacy_json).unwrap();
        assert_eq!(parsed.prefetch_promotions_total, 0);
        assert_eq!(parsed.prefetch_demotions_total, 0);
    }
}
