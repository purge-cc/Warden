use super::*;
use crate::filter::engine::ProfileMasks;
use crate::lists::catalog::Catalog;
use crate::lists::parser::DEFAULT_MAX_LIST_ENTRIES;
use std::collections::BTreeMap;

mod s7_memory;

#[cfg(unix)]
fn replace_path_with_mode_0640(path: &std::path::Path, bytes: &[u8]) {
    use std::os::unix::fs::PermissionsExt as _;

    let name = path.file_name().unwrap().to_string_lossy();
    let displaced = path.with_file_name(format!(".{name}.displaced"));
    let replacement = path.with_file_name(format!(".{name}.replacement"));
    std::fs::rename(path, displaced).unwrap();
    std::fs::write(&replacement, bytes).unwrap();
    std::fs::set_permissions(&replacement, std::fs::Permissions::from_mode(0o640)).unwrap();
    std::fs::rename(replacement, path).unwrap();
}

#[cfg(unix)]
fn streamed_temp_path_in(cache_dir: &std::path::Path) -> std::path::PathBuf {
    std::fs::read_dir(cache_dir)
        .unwrap()
        .flatten()
        .find_map(|entry| {
            entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.contains(".download-"))
                .then_some(entry.path())
        })
        .expect("streamed cache body must retain its temporary pathname")
}

/// A refresh controller returns its manager from `spawn_blocking`, so a
/// scheduler tick and the completed registry publication are deliberately
/// separate observations. Wait in wall-clock time without advancing Tokio's
/// paused clock; the small blocking sleep gives the blocking worker a chance
/// to hand the manager back to the current-thread controller.
async fn wait_for_cycle_seq(registry: &Arc<ListStatusRegistry>, expected: u64) {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while registry.cycle().seq < expected {
        assert!(
            std::time::Instant::now() < deadline,
            "timed out waiting for completed list cycle {expected}; last was {}",
            registry.cycle().seq
        );
        tokio::task::yield_now().await;
        std::thread::sleep(Duration::from_millis(1));
    }
}

impl ListManager {
    /// The client downloads currently go out on.
    ///
    /// Test-only, and it exists for exactly one obligation
    /// (`boot_list_persistence.md` §4.8): the **bulk** client must be in the
    /// manager's hand before the first refresh of any mode, which is an
    /// ordering property with no other observable. Behavioural discrimination
    /// would cost a 30 s test — the two clients differ only in deadlines —
    /// so the caller compares `{:?}` against a freshly built bulk client and
    /// asserts first that the two spellings differ at all.
    pub(crate) fn download_client(&self) -> &reqwest::Client {
        &self.client
    }
}

/// Production body cap, named through the authoritative default rather than
/// a duplicated byte count.
/// Real-network tests need at least this much because the official
/// purge.cc lists have grown past 100 MB.
const TEST_CAP: usize = crate::config::settings::DEFAULT_MAX_LIST_BODY_BYTES;

/// Small cap (50 MB) for the OOM regression test — it streams 60 MB
/// and must abort before reading the full body.
const TEST_SMALL_CAP: usize = 50 * 1024 * 1024;

fn install_test_schedule(
    mgr: &mut ListManager,
    source: &str,
) -> crate::lists::source_key::CanonicalSourceScheduleKey {
    use sha2::Digest;
    use std::str::FromStr;

    let key = crate::lists::source_key::CanonicalSourceScheduleKey::from_str(&format!(
        "canonical-url-v1-sha256-{}",
        hex::encode(sha2::Sha256::digest(source.as_bytes()))
    ))
    .unwrap();
    mgr.source_schedules.insert(
        source.to_string(),
        SourceSchedule {
            key: key.clone(),
            interval: Duration::from_secs(60 * 60),
        },
    );
    key
}

#[test]
fn list_cache_default_has_no_headers() {
    let cache = ListCache::default();
    assert!(cache.etag.is_none());
    assert!(cache.last_modified.is_none());
    assert!(cache.body.is_none());
}

#[test]
fn min_refresh_interval_clamped() {
    let client = reqwest::Client::new();
    let filter = Arc::new(FilterEngine::new());
    let catalog = Catalog::fallback();
    let mgr = ListManager::new(
        client,
        filter,
        vec![],
        catalog,
        Duration::from_secs(0),
        SourceBitMap::default(),
        TEST_CAP,
        DEFAULT_MAX_LIST_ENTRIES,
        None,
    );
    assert!(mgr.refresh_interval >= MIN_REFRESH_INTERVAL);
}

#[test]
fn refresh_cadence_degraded_interval_stays_within_the_recovery_band() {
    for (configured, expected) in [
        (Duration::from_secs(30), Duration::from_secs(60)),
        (Duration::from_secs(2 * 60), Duration::from_secs(2 * 60)),
        (Duration::from_secs(10 * 60), Duration::from_secs(5 * 60)),
    ] {
        assert_eq!(
            degraded_refresh_interval(configured),
            expected,
            "configured interval {configured:?} chose the wrong degraded retry cadence"
        );
    }
}

#[test]
fn canonical_schedule_uses_per_source_success_failure_and_future_deadlines() {
    use std::str::FromStr;

    let mut mgr = ListManager::new(
        reqwest::Client::new(),
        Arc::new(FilterEngine::new()),
        vec![],
        Catalog::fallback(),
        Duration::from_secs(12 * 60 * 60),
        SourceBitMap::default(),
        TEST_CAP,
        DEFAULT_MAX_LIST_ENTRIES,
        None,
    );
    let key = crate::lists::source_key::CanonicalSourceScheduleKey::from_str(
        "canonical-url-v1-sha256-5f96be98e676eb9d356654baaff1e8f8e02de9e32dc8cbaf27fda1599ffbb5e1",
    )
    .unwrap();
    mgr.source_schedules.insert(
        "fast".to_string(),
        SourceSchedule {
            key: key.clone(),
            interval: Duration::from_secs(2 * 60 * 60),
        },
    );
    let anchor = time::macros::datetime!(2026-09-05 10:00:00 UTC);
    mgr.schedule_state.record_success(key.clone(), anchor);
    assert!(!mgr.source_is_due("fast", anchor + time::Duration::minutes(119)));
    assert!(mgr.source_is_due("fast", anchor + time::Duration::hours(2)));

    mgr.schedule_state.record_failure(key.clone(), anchor);
    assert!(!mgr.source_is_due("fast", anchor + time::Duration::seconds(59)));
    assert!(mgr.source_is_due("fast", anchor + time::Duration::minutes(5)));

    mgr.schedule_state
        .record_success(key, anchor + time::Duration::days(1));
    assert!(mgr.source_is_due("fast", anchor));
}

#[test]
fn schedule_wait_uses_earliest_deadline_and_degraded_missing_row_floor() {
    use std::str::FromStr;

    let mut mgr = ListManager::new(
        reqwest::Client::new(),
        Arc::new(FilterEngine::new()),
        vec![],
        Catalog::fallback(),
        Duration::from_secs(12 * 60 * 60),
        SourceBitMap::default(),
        TEST_CAP,
        DEFAULT_MAX_LIST_ENTRIES,
        None,
    );
    let a = crate::lists::source_key::CanonicalSourceScheduleKey::from_str(
        "canonical-url-v1-sha256-5f96be98e676eb9d356654baaff1e8f8e02de9e32dc8cbaf27fda1599ffbb5e1",
    )
    .unwrap();
    let b = crate::lists::source_key::CanonicalSourceScheduleKey::from_str(
        "canonical-url-v1-sha256-4e597e623d4112f2872d16b23fdc91d5f7f38102bf6fcf204c8b41911e5da6f8",
    )
    .unwrap();
    for (source, key) in [("a", a.clone()), ("b", b.clone())] {
        mgr.source_schedules.insert(
            source.to_string(),
            SourceSchedule {
                key,
                interval: Duration::from_secs(60 * 60),
            },
        );
    }
    let now = time::macros::datetime!(2026-09-05 10:00:00 UTC);
    mgr.schedule_state
        .record_success(a, now - time::Duration::minutes(30));
    mgr.schedule_state
        .record_success(b, now - time::Duration::minutes(45));
    assert_eq!(mgr.next_schedule_wait(now), Duration::from_secs(15 * 60));

    mgr.schedule_state = ListScheduleState::default();
    mgr.status_registry.record_cycle_with_qualifiers(
        CycleOutcome::SpillRollbackFailed,
        true,
        true,
        0,
    );
    assert_eq!(
        mgr.next_loop_wait(now),
        Duration::from_secs(60),
        "a degraded planned loop cannot spin on a missing ledger row"
    );
}

#[test]
fn one_shot_legacy_seed_fills_absent_keys_in_a_partial_ledger() {
    let first = "https://lists.test/first.txt".to_string();
    let second = "https://lists.test/second.txt".to_string();
    let plan = ResolvedSourcePlan::build(
        &Catalog::fallback(),
        &[first.clone(), second.clone()],
        &[],
        &BTreeMap::new(),
    )
    .unwrap();
    let planned: Vec<_> = plan
        .sources()
        .map(|source| {
            (
                source.representative().to_string(),
                source.fetch_url().to_string(),
                source.schedule_key().clone(),
            )
        })
        .collect();
    let bits = SourceBitMap::from_plan(&plan).unwrap();
    let first_key = planned[0].2.clone();
    let second_url = planned[1].1.clone();
    let second_key = planned[1].2.clone();
    let mut mgr = ListManager::with_plan_and_tokens(
        reqwest::Client::new(),
        Arc::new(FilterEngine::new()),
        plan,
        Duration::from_secs(60 * 60),
        bits,
        SourceTokenMap::default(),
        TEST_CAP,
        DEFAULT_MAX_LIST_ENTRIES,
        None,
    );
    let anchor = time::macros::datetime!(2026-09-05 10:00:00 UTC);
    let mut state = ListScheduleState::default();
    state.record_success(first_key.clone(), anchor - time::Duration::minutes(1));
    mgr.set_schedule_state(state, None, true);
    mgr.cache.insert(
        second_url,
        ListCache {
            etag: None,
            last_modified: None,
            body: Some("second.example\n".to_string()),
            fetched_at: anchor - time::Duration::minutes(2),
        },
    );
    mgr.seed_schedule_state(anchor);

    assert_eq!(
        mgr.schedule_state.lookup(&second_key).unwrap().last_attempt,
        anchor - time::Duration::minutes(2)
    );
    assert_eq!(
        mgr.schedule_state.lookup(&first_key).unwrap().last_attempt,
        anchor - time::Duration::minutes(1),
        "an existing canonical row is never replaced by a compatibility seed"
    );
}

#[test]
fn plan_backed_manager_uses_schema4_cadence_override_and_floor() {
    let row = crate::config::schema::Blocklist {
        id: crate::config::schema::Id::new("fast").unwrap(),
        display_name: "fast".to_string(),
        url: "https://lists.test/fast.txt".to_string(),
        format: Default::default(),
        update_interval_hours: Some(0),
        max_entries: None,
        enabled: true,
        auth_token_ref: None,
        base: crate::config::schema::BlocklistBase::Deny,
        trust: crate::config::schema::BlocklistTrust::RemoteUnsigned,
        accept_unsigned_allow: false,
        max_consecutive_failures: 5,
    };
    let plan = ResolvedSourcePlan::build_for_schema(
        &Catalog::fallback(),
        &[],
        &[row],
        &BTreeMap::new(),
        crate::lists::source_key::RowControlDefaults {
            max_entries: DEFAULT_MAX_LIST_ENTRIES,
            update_interval_secs: 7_200,
        },
        4,
    )
    .unwrap();
    let bits = SourceBitMap::from_plan(&plan).unwrap();
    let mgr = ListManager::with_plan_and_tokens(
        reqwest::Client::new(),
        Arc::new(FilterEngine::new()),
        plan,
        Duration::from_secs(7_200),
        bits,
        SourceTokenMap::default(),
        TEST_CAP,
        DEFAULT_MAX_LIST_ENTRIES,
        None,
    );

    assert_eq!(
        mgr.source_schedules["https://lists.test/fast.txt"].interval,
        Duration::from_secs(60)
    );
}

#[tokio::test]
async fn effective_cadence_does_not_enter_the_installed_corpus_digest() {
    fn manager(hours: u32) -> (ListManager, String) {
        let row = crate::config::schema::Blocklist {
            id: crate::config::schema::Id::new("digest").unwrap(),
            display_name: "digest".to_string(),
            url: "https://lists.test/digest.txt".to_string(),
            format: Default::default(),
            update_interval_hours: Some(hours),
            max_entries: None,
            enabled: true,
            auth_token_ref: None,
            base: crate::config::schema::BlocklistBase::Deny,
            trust: crate::config::schema::BlocklistTrust::RemoteUnsigned,
            accept_unsigned_allow: false,
            max_consecutive_failures: 5,
        };
        let plan = ResolvedSourcePlan::build_for_schema(
            &Catalog::fallback(),
            &[],
            &[row],
            &BTreeMap::new(),
            crate::lists::source_key::RowControlDefaults {
                max_entries: DEFAULT_MAX_LIST_ENTRIES,
                update_interval_secs: 7_200,
            },
            4,
        )
        .unwrap();
        let url = plan.sources().next().unwrap().fetch_url().to_string();
        let bits = SourceBitMap::from_plan(&plan).unwrap();
        (
            ListManager::with_plan_and_tokens(
                reqwest::Client::new(),
                Arc::new(FilterEngine::new()),
                plan,
                Duration::from_secs(7_200),
                bits,
                SourceTokenMap::default(),
                TEST_CAP,
                DEFAULT_MAX_LIST_ENTRIES,
                None,
            ),
            url,
        )
    }

    let (mut hourly, hourly_url) = manager(1);
    let (mut two_hourly, two_hourly_url) = manager(2);
    for (mgr, url) in [(&mut hourly, hourly_url), (&mut two_hourly, two_hourly_url)] {
        mgr.cache.insert(
            url,
            ListCache {
                etag: None,
                last_modified: None,
                body: Some("same-corpus.example\n".to_string()),
                fetched_at: OffsetDateTime::now_utc(),
            },
        );
        assert_eq!(mgr.refresh_with_mode(RefreshMode::CacheOnly).await, 1);
    }
    assert_ne!(
        hourly.source_schedules.values().next().unwrap().interval,
        two_hourly
            .source_schedules
            .values()
            .next()
            .unwrap()
            .interval
    );
    assert_eq!(
        hourly.installed_corpus_digest,
        two_hourly.installed_corpus_digest
    );
}

#[test]
fn legacy_cache_timestamp_and_corrupt_sidecar_cannot_seed_a_schedule() {
    use std::str::FromStr;

    let url = "https://lists.test/legacy.txt".to_string();
    let key = crate::lists::source_key::CanonicalSourceScheduleKey::from_str(
        "canonical-url-v1-sha256-5f96be98e676eb9d356654baaff1e8f8e02de9e32dc8cbaf27fda1599ffbb5e1",
    )
    .unwrap();
    let anchor = time::macros::datetime!(2026-09-05 10:00:00 UTC);
    for allow_seed in [true, false] {
        let mut mgr = ListManager::new(
            reqwest::Client::new(),
            Arc::new(FilterEngine::new()),
            vec![url.clone()],
            Catalog::fallback(),
            Duration::from_secs(60 * 60),
            build_source_bit_map(std::slice::from_ref(&url)).unwrap(),
            TEST_CAP,
            DEFAULT_MAX_LIST_ENTRIES,
            None,
        );
        mgr.source_schedules.insert(
            url.clone(),
            SourceSchedule {
                key: key.clone(),
                interval: Duration::from_secs(60 * 60),
            },
        );
        mgr.set_schedule_state(ListScheduleState::default(), None, allow_seed);
        mgr.cache.insert(
            url.clone(),
            ListCache {
                etag: None,
                last_modified: None,
                body: Some("legacy.example\n".to_string()),
                fetched_at: anchor,
            },
        );
        if allow_seed {
            mgr.legacy_cache_timestamp_urls.insert(url.clone());
        }
        mgr.seed_schedule_state(anchor + time::Duration::minutes(1));
        assert!(mgr.schedule_state.lookup(&key).is_none());
    }

    let mut mgr = ListManager::new(
        reqwest::Client::new(),
        Arc::new(FilterEngine::new()),
        vec![url.clone()],
        Catalog::fallback(),
        Duration::from_secs(60 * 60),
        build_source_bit_map(std::slice::from_ref(&url)).unwrap(),
        TEST_CAP,
        DEFAULT_MAX_LIST_ENTRIES,
        None,
    );
    mgr.source_schedules.insert(
        url.clone(),
        SourceSchedule {
            key: key.clone(),
            interval: Duration::from_secs(60 * 60),
        },
    );
    mgr.set_schedule_state(ListScheduleState::default(), None, true);
    mgr.cache.insert(
        url,
        ListCache {
            etag: None,
            last_modified: None,
            body: Some("future.example\n".to_string()),
            fetched_at: anchor + time::Duration::days(1),
        },
    );
    mgr.seed_schedule_state(anchor);
    assert!(
        mgr.schedule_state.lookup(&key).is_none(),
        "a future compatibility candidate stays absent and therefore due"
    );
}

#[test]
fn legacy_seed_ignores_future_alias_and_cache_evidence() {
    let rows = ["owner", "alias"].map(|id| crate::config::schema::Blocklist {
        id: crate::config::schema::Id::new(id).unwrap(),
        display_name: id.to_string(),
        url: "https://lists.test/shared.txt".to_string(),
        format: Default::default(),
        update_interval_hours: None,
        max_entries: None,
        enabled: true,
        auth_token_ref: None,
        base: crate::config::schema::BlocklistBase::Deny,
        trust: crate::config::schema::BlocklistTrust::RemoteUnsigned,
        accept_unsigned_allow: false,
        max_consecutive_failures: 5,
    });
    let plan =
        ResolvedSourcePlan::build(&Catalog::fallback(), &[], &rows, &BTreeMap::new()).unwrap();
    let bits = SourceBitMap::from_plan(&plan).unwrap();
    let key = plan.sources().next().unwrap().schedule_key().clone();
    let url = plan.sources().next().unwrap().fetch_url().to_string();
    let mut mgr = ListManager::with_plan_and_tokens(
        reqwest::Client::new(),
        Arc::new(FilterEngine::new()),
        plan,
        Duration::from_secs(60 * 60),
        bits,
        SourceTokenMap::default(),
        TEST_CAP,
        DEFAULT_MAX_LIST_ENTRIES,
        None,
    );
    let anchor = time::macros::datetime!(2026-09-05 10:00:00 UTC);
    let mut state = crate::config::list_state::ListState::default();
    state.lists.insert(
        crate::config::schema::Id::new("owner").unwrap(),
        crate::config::list_state::ListStatusEntry {
            last_attempt: Some(anchor - time::Duration::minutes(2)),
            ..Default::default()
        },
    );
    state.lists.insert(
        crate::config::schema::Id::new("alias").unwrap(),
        crate::config::list_state::ListStatusEntry {
            last_attempt: Some(anchor + time::Duration::minutes(1)),
            consecutive_failures: 1,
            ..Default::default()
        },
    );
    mgr.set_list_state(state, None);
    mgr.cache.insert(
        url,
        ListCache {
            etag: None,
            last_modified: None,
            body: Some("shared.example\n".to_string()),
            fetched_at: anchor + time::Duration::minutes(2),
        },
    );

    mgr.seed_schedule_state(anchor);

    let entry = mgr.schedule_state.lookup(&key).unwrap();
    assert_eq!(entry.last_attempt, anchor - time::Duration::minutes(2));
    assert_eq!(entry.outcome, CanonicalScheduleOutcome::Success);
}

#[tokio::test]
async fn missing_retained_body_turns_a_non_due_source_into_a_recorded_attempt() {
    use std::str::FromStr;

    let url = "https://127.0.0.1/no-retained-body.txt".to_string();
    let bits = build_source_bit_map(std::slice::from_ref(&url)).unwrap();
    let mut mgr = ListManager::new(
        reqwest::Client::new(),
        Arc::new(FilterEngine::new()),
        vec![url.clone()],
        Catalog::fallback(),
        Duration::from_secs(60 * 60),
        bits,
        TEST_CAP,
        DEFAULT_MAX_LIST_ENTRIES,
        None,
    );
    let key = crate::lists::source_key::CanonicalSourceScheduleKey::from_str(
        "canonical-url-v1-sha256-5f96be98e676eb9d356654baaff1e8f8e02de9e32dc8cbaf27fda1599ffbb5e1",
    )
    .unwrap();
    let anchor = time::macros::datetime!(2026-09-05 10:00:00 UTC);
    mgr.source_schedules.insert(
        url.clone(),
        SourceSchedule {
            key: key.clone(),
            interval: Duration::from_secs(60 * 60),
        },
    );
    mgr.schedule_state.record_success(key.clone(), anchor);

    mgr.refresh_at(anchor + time::Duration::minutes(1)).await;

    let entry = mgr.schedule_state.lookup(&key).unwrap();
    assert_eq!(entry.last_attempt, anchor + time::Duration::minutes(1));
    assert_eq!(entry.outcome, CanonicalScheduleOutcome::Failure);
}

#[tokio::test]
async fn corrupted_retained_body_makes_a_non_due_planned_source_due_and_failed() {
    let (origin, pem, requests) = spawn_tls_origin_responses(vec![
        tls_ok_response("retained.example\n", "\"retained\""),
        "HTTP/1.1 500 Internal Server Error\r\nConnection: close\r\n\r\n".to_string(),
    ])
    .await;
    let url = "https://lists.test/corrupt-retained.txt".to_string();
    let plan = ResolvedSourcePlan::build(
        &Catalog::fallback(),
        std::slice::from_ref(&url),
        &[],
        &BTreeMap::new(),
    )
    .unwrap();
    let bits = SourceBitMap::from_plan(&plan).unwrap();
    let cache_dir = tempfile::tempdir().unwrap();
    let mut mgr = ListManager::with_plan_and_tokens(
        reqwest::Client::builder()
            .resolve("lists.test", origin)
            .add_root_certificate(reqwest::Certificate::from_pem(pem.as_bytes()).unwrap())
            .build()
            .unwrap(),
        Arc::new(FilterEngine::new()),
        plan,
        Duration::from_secs(60 * 60),
        bits,
        SourceTokenMap::default(),
        TEST_CAP,
        DEFAULT_MAX_LIST_ENTRIES,
        Some(cache_dir.path().to_path_buf()),
    );
    let anchor = time::macros::datetime!(2026-09-05 10:00:00 UTC);
    assert_eq!(
        mgr.refresh_at_with_mode(anchor, RefreshMode::Force).await,
        1
    );
    let key = mgr.source_schedules[&url].key.clone();
    let now = anchor + time::Duration::minutes(1);
    mgr.schedule_state.record_success(key.clone(), anchor);
    assert!(!mgr.source_is_due(&url, now), "fixture must start non-due");
    std::fs::write(
        selected_cache_body_path(cache_dir.path(), &url).unwrap(),
        "corrupt.example\n",
    )
    .unwrap();

    assert_eq!(mgr.refresh_at(now).await, 1);
    let entry = mgr.schedule_state.lookup(&key).unwrap();
    assert_eq!(entry.last_attempt, now);
    assert_eq!(entry.outcome, CanonicalScheduleOutcome::Failure);
    assert!(matches!(
        mgr.status_registry
            .status_for_url(&url)
            .unwrap()
            .last_outcome,
        LastOutcome::Failed { .. }
    ));
    assert_eq!(requests.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn planned_scheduled_cycle_fetches_only_due_remote_source_and_keeps_non_due_health() {
    let (origin, pem, requests) = spawn_tls_origin_responses(vec![
        tls_ok_response("due-old.example\n", "\"due-old\""),
        tls_ok_response("kept.example\n", "\"kept\""),
        tls_ok_response("due-new.example\n", "\"due-new\""),
    ])
    .await;
    let due = "https://lists.test/due.txt".to_string();
    let kept = "https://lists.test/kept.txt".to_string();
    let plan = ResolvedSourcePlan::build_with_row_control_defaults(
        &Catalog::fallback(),
        &[due.clone(), kept.clone()],
        &[],
        &BTreeMap::new(),
        crate::lists::source_key::RowControlDefaults {
            max_entries: DEFAULT_MAX_LIST_ENTRIES,
            update_interval_secs: 60 * 60,
        },
        crate::lists::source_key::RowControlMode::InheritAll,
    )
    .unwrap();
    let bits = SourceBitMap::from_plan(&plan).unwrap();
    let mut mgr = ListManager::with_plan_and_tokens(
        reqwest::Client::builder()
            .resolve("lists.test", origin)
            .add_root_certificate(reqwest::Certificate::from_pem(pem.as_bytes()).unwrap())
            .build()
            .unwrap(),
        Arc::new(FilterEngine::new()),
        plan,
        Duration::from_secs(60 * 60),
        bits,
        SourceTokenMap::default(),
        TEST_CAP,
        DEFAULT_MAX_LIST_ENTRIES,
        None,
    );
    let anchor = OffsetDateTime::now_utc();
    assert_eq!(
        mgr.refresh_at_with_mode(anchor, RefreshMode::Force).await,
        2
    );
    let kept_before = (*mgr.status_registry.status_for_url(&kept).unwrap()).clone();
    let due_key = mgr.source_schedules[&due].key.clone();
    let kept_key = mgr.source_schedules[&kept].key.clone();
    mgr.schedule_state
        .record_success(due_key, anchor - time::Duration::hours(2));
    mgr.schedule_state.record_success(kept_key, anchor);

    assert_eq!(mgr.refresh_at(anchor).await, 2);
    assert!(mgr.filter.is_blocked("due-new.example"));
    assert!(mgr.filter.is_blocked("kept.example"));
    assert!(!mgr.filter.is_blocked("due-old.example"));
    assert_eq!(
        *mgr.status_registry.status_for_url(&kept).unwrap(),
        kept_before,
        "parsing a planned non-due body must not refresh its health"
    );
    assert_eq!(
        requests.lock().unwrap().len(),
        3,
        "only the due source was acquired"
    );
    assert!(mgr.installed_corpus_digest.is_some());
}

#[tokio::test]
async fn force_refresh_attempts_all_sources_and_accepts_a_conditional_304() {
    use std::str::FromStr;

    let (origin, pem, requests) = spawn_tls_origin_responses(vec![
        "HTTP/1.1 304 Not Modified\r\nConnection: close\r\n\r\n".to_string(),
    ])
    .await;
    let url = "https://lists.test/forced.txt".to_string();
    let anchor = OffsetDateTime::now_utc();
    let mut mgr = ListManager::new(
        reqwest::Client::builder()
            .resolve("lists.test", origin)
            .add_root_certificate(reqwest::Certificate::from_pem(pem.as_bytes()).unwrap())
            .build()
            .unwrap(),
        Arc::new(FilterEngine::new()),
        vec![url.clone()],
        Catalog::fallback(),
        Duration::from_secs(12 * 60 * 60),
        build_source_bit_map(std::slice::from_ref(&url)).unwrap(),
        TEST_CAP,
        DEFAULT_MAX_LIST_ENTRIES,
        None,
    );
    mgr.cache.insert(
        url.clone(),
        ListCache {
            etag: Some("\"retained\"".to_string()),
            last_modified: None,
            body: Some("forced.example\n".to_string()),
            fetched_at: anchor - time::Duration::hours(1),
        },
    );
    let key = crate::lists::source_key::CanonicalSourceScheduleKey::from_str(
        "canonical-url-v1-sha256-5f96be98e676eb9d356654baaff1e8f8e02de9e32dc8cbaf27fda1599ffbb5e1",
    )
    .unwrap();
    mgr.source_schedules.insert(
        url.clone(),
        SourceSchedule {
            key: key.clone(),
            interval: Duration::from_secs(60 * 60),
        },
    );
    mgr.schedule_state
        .record_failure(key.clone(), anchor - time::Duration::minutes(1));

    assert_eq!(
        mgr.refresh_at_with_mode(anchor, RefreshMode::Force).await,
        1
    );
    assert!(mgr.filter.is_blocked("forced.example"));
    assert_eq!(mgr.cache[&url].fetched_at, anchor);
    assert_eq!(
        mgr.schedule_state.lookup(&key).unwrap().outcome,
        CanonicalScheduleOutcome::Success
    );
    assert_eq!(
        mgr.schedule_state.lookup(&key).unwrap().last_attempt,
        anchor
    );
    let requests = requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert!(requests[0].contains("if-none-match: \"retained\""));
}

#[tokio::test]
async fn scheduled_non_due_imported_local_uses_retained_disk_body_without_list_cache() {
    use std::str::FromStr;

    let (mut mgr, url, dir) = bridge_manager("retained-local.example\n");
    let anchor = OffsetDateTime::now_utc();
    assert_eq!(
        mgr.refresh_at_with_mode(anchor, RefreshMode::Force).await,
        1
    );
    assert!(
        !mgr.cache.contains_key(&url),
        "local candidates keep no memory cache"
    );
    let key = crate::lists::source_key::CanonicalSourceScheduleKey::from_str(
        "canonical-url-v1-sha256-5f96be98e676eb9d356654baaff1e8f8e02de9e32dc8cbaf27fda1599ffbb5e1",
    )
    .unwrap();
    mgr.source_schedules.insert(
        url.clone(),
        SourceSchedule {
            key: key.clone(),
            interval: Duration::from_secs(60 * 60),
        },
    );
    mgr.schedule_state.record_success(key, anchor);
    write_bridge_body(&dir, "edited-local.example\n");

    assert_eq!(mgr.refresh_at(anchor + time::Duration::minutes(1)).await, 1);
    assert!(mgr.filter.is_blocked("retained-local.example"));
    assert!(
        !mgr.filter.is_blocked("edited-local.example"),
        "a non-due source must use its retained body, not reacquire the edited file"
    );
}

#[tokio::test]
async fn cache_only_leaves_the_schedule_ledger_byte_for_byte_unchanged() {
    use std::str::FromStr;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("data/list_schedule_state.toml");
    let key = crate::lists::source_key::CanonicalSourceScheduleKey::from_str(
        "canonical-url-v1-sha256-5f96be98e676eb9d356654baaff1e8f8e02de9e32dc8cbaf27fda1599ffbb5e1",
    )
    .unwrap();
    let anchor = time::macros::datetime!(2026-09-05 10:00:00 UTC);
    let mut state = ListScheduleState::default();
    state.record_success(key, anchor);
    state.write_atomic(&path).unwrap();
    let before = std::fs::read(&path).unwrap();

    let mut mgr = ListManager::new(
        reqwest::Client::new(),
        Arc::new(FilterEngine::new()),
        vec![],
        Catalog::fallback(),
        Duration::from_secs(60),
        SourceBitMap::default(),
        TEST_CAP,
        DEFAULT_MAX_LIST_ENTRIES,
        Some(dir.path().to_path_buf()),
    );
    mgr.set_schedule_state(state.clone(), Some(path.clone()), true);
    mgr.refresh_at_with_mode(anchor + time::Duration::hours(1), RefreshMode::CacheOnly)
        .await;

    assert_eq!(mgr.schedule_state, state);
    assert_eq!(std::fs::read(path).unwrap(), before);
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn force_refresh_command_is_accepted_after_initial_cycle_publication() {
    let mut mgr = ListManager::new(
        reqwest::Client::new(),
        Arc::new(FilterEngine::new()),
        vec![],
        Catalog::fallback(),
        Duration::from_secs(12 * 60 * 60),
        SourceBitMap::default(),
        TEST_CAP,
        DEFAULT_MAX_LIST_ENTRIES,
        None,
    );
    let (tx, rx) = mpsc::channel(1);
    mgr.set_command_channel(rx);
    let registry = mgr.status_registry();
    let handle = mgr.spawn_refresh_loop();
    wait_for_cycle_seq(&registry, 1).await;

    let (accepted_tx, accepted_rx) = oneshot::channel();
    let (completion_tx, completion_rx) = oneshot::channel();
    tx.send(ListManagerCommand::ForceRefresh {
        accepted: accepted_tx,
        completion: completion_tx,
    })
    .await
    .unwrap();
    // The cycle mark is published by the blocking worker before the
    // controller receives the returned manager. A Force arriving in that
    // handoff window must queue behind the active scheduled cycle; after the
    // handoff it starts immediately. Both are prompt, correct acceptance
    // outcomes, and treating the former as Started would violate the
    // single-owner / Force-Forget ordering barrier.
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(1), accepted_rx)
            .await
            .unwrap()
            .unwrap(),
        ListManagerCommandDisposition::Started | ListManagerCommandDisposition::Queued
    ));
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), completion_rx)
            .await
            .unwrap()
            .unwrap()
            .snapshot
            .domain_count,
        0
    );
    handle.retire().await.unwrap();
}

/// The blocking worker must return the snapshot published by its own cycle.
///
/// Deliberately publish later reload marks *after the worker joins but before
/// this result is used*. The old controller design reloaded the shared
/// registry at precisely that boundary, so it would have returned the later
/// `SkippedUnchanged` snapshot instead of the Force cycle.
#[tokio::test]
async fn refresh_worker_carries_its_published_snapshot_across_later_reload_marks() {
    let mgr = ListManager::new(
        reqwest::Client::new(),
        Arc::new(FilterEngine::new()),
        vec![],
        Catalog::fallback(),
        Duration::from_secs(12 * 60 * 60),
        SourceBitMap::default(),
        TEST_CAP,
        DEFAULT_MAX_LIST_ENTRIES,
        None,
    );
    let registry = mgr.status_registry();
    let RefreshWorkerOutcome::Completed { completion, .. } =
        spawn_list_refresh_worker(mgr, RefreshMode::Force, RefreshCancellation::default())
            .await
            .expect("refresh worker completed")
    else {
        panic!("unexpected cancellation");
    };
    assert_eq!(completion.snapshot.cycle.seq, 1);
    assert_eq!(
        completion.snapshot.cycle.outcome,
        Some(CycleOutcome::Installed)
    );

    registry.record_cycle(CycleOutcome::ConfigRejected);
    registry.record_cycle(CycleOutcome::SkippedUnchanged);
    assert_eq!(registry.cycle().seq, 3);
    assert_eq!(
        registry.cycle().outcome,
        Some(CycleOutcome::SkippedUnchanged)
    );
    assert_eq!(
        completion.snapshot.cycle.seq, 1,
        "worker result must retain its own publication, not reload shared state"
    );
    assert_eq!(
        completion.snapshot.cycle.outcome,
        Some(CycleOutcome::Installed)
    );
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn post_refresh_controller_uses_the_next_deadline_not_an_immediate_tick() {
    let interval = Duration::from_secs(12 * 60 * 60);
    let mut mgr = ListManager::new(
        reqwest::Client::new(),
        Arc::new(FilterEngine::new()),
        vec![],
        Catalog::fallback(),
        interval,
        SourceBitMap::default(),
        TEST_CAP,
        DEFAULT_MAX_LIST_ENTRIES,
        None,
    );
    let registry = mgr.status_registry();
    mgr.refresh().await;
    assert_eq!(registry.cycle().seq, 1, "foreground rebuild completed");

    let task = mgr.spawn_refresh_loop_after_refresh();
    tokio::task::yield_now().await;
    assert_eq!(
        registry.cycle().seq,
        1,
        "post-refresh controller must not duplicate the completed rebuild immediately"
    );
    tokio::time::advance(interval).await;
    wait_for_cycle_seq(&registry, 2).await;
    task.retire().await.unwrap();
}

#[tokio::test]
async fn manager_retirement_reports_a_terminal_controller_failure() {
    let (retire_tx, _retire_rx) = oneshot::channel();
    let join = tokio::spawn(async { panic!("test controller failure") });
    let task = ListManagerTask { retire_tx, join };

    assert!(
        task.retire().await.is_err(),
        "a failed controller must not be normalized into successful retirement"
    );
}

fn pending_refresh_join() -> tokio::task::JoinHandle<RefreshWorkerOutcome> {
    tokio::spawn(std::future::pending())
}

fn force_command() -> (
    ListManagerCommand,
    oneshot::Receiver<ListManagerCommandDisposition>,
) {
    let (accepted_tx, accepted_rx) = oneshot::channel();
    let (completion_tx, _completion_rx) = oneshot::channel();
    (
        ListManagerCommand::ForceRefresh {
            accepted: accepted_tx,
            completion: completion_tx,
        },
        accepted_rx,
    )
}

fn forget_command(
    source: &str,
) -> (
    ListManagerCommand,
    oneshot::Receiver<ListManagerCommandDisposition>,
) {
    let (accepted_tx, accepted_rx) = oneshot::channel();
    let (completion_tx, _completion_rx) = oneshot::channel();
    (
        ListManagerCommand::Forget {
            source: source.to_string(),
            accepted: accepted_tx,
            completion: completion_tx,
        },
        accepted_rx,
    )
}

#[tokio::test]
async fn force_joins_an_active_force_only_when_the_queue_is_empty() {
    let mut active = ActiveRefresh {
        work: ActiveManagerWork::Force {
            completions: Vec::new(),
        },
        join: pending_refresh_join(),
        cancellation: RefreshCancellation::default(),
        registry: Arc::new(ListStatusRegistry::new(&[])),
        seq_at_start: 0,
    };
    let mut queued = std::collections::VecDeque::new();
    let (command, accepted) = force_command();

    accept_while_active(command, &mut active, &mut queued);

    assert_eq!(
        accepted.await.unwrap(),
        ListManagerCommandDisposition::JoinedInFlight
    );
    assert!(queued.is_empty(), "joining must not create follow-up work");
    assert!(matches!(
        &active.work,
        ActiveManagerWork::Force { completions } if completions.len() == 1
    ));
    active.join.abort();
}

#[tokio::test]
async fn forces_queue_then_coalesce_behind_an_active_scheduled_cycle() {
    let mut active = ActiveRefresh {
        work: ActiveManagerWork::Scheduled,
        join: pending_refresh_join(),
        cancellation: RefreshCancellation::default(),
        registry: Arc::new(ListStatusRegistry::new(&[])),
        seq_at_start: 0,
    };
    let mut queued = std::collections::VecDeque::new();
    let (first, first_accepted) = force_command();
    let (second, second_accepted) = force_command();

    accept_while_active(first, &mut active, &mut queued);
    accept_while_active(second, &mut active, &mut queued);

    assert_eq!(
        first_accepted.await.unwrap(),
        ListManagerCommandDisposition::Queued
    );
    assert_eq!(
        second_accepted.await.unwrap(),
        ListManagerCommandDisposition::CoalescedQueued
    );
    assert!(matches!(
        queued.front(),
        Some(QueuedManagerWork::Force { completions }) if completions.len() == 2
    ));
    active.join.abort();
}

#[tokio::test]
async fn forget_is_a_barrier_between_active_and_queued_forces() {
    let mut active = ActiveRefresh {
        work: ActiveManagerWork::Force {
            completions: Vec::new(),
        },
        join: pending_refresh_join(),
        cancellation: RefreshCancellation::default(),
        registry: Arc::new(ListStatusRegistry::new(&[])),
        seq_at_start: 0,
    };
    let mut queued = std::collections::VecDeque::new();
    let (forget, forget_accepted) = forget_command("privacy/ads");
    let (force, force_accepted) = force_command();

    accept_while_active(forget, &mut active, &mut queued);
    accept_while_active(force, &mut active, &mut queued);

    assert_eq!(
        forget_accepted.await.unwrap(),
        ListManagerCommandDisposition::Queued
    );
    assert_eq!(
        force_accepted.await.unwrap(),
        ListManagerCommandDisposition::Queued,
        "the barrier prevents joining the active force"
    );
    assert!(matches!(
        queued.pop_front(),
        Some(QueuedManagerWork::Forget { .. })
    ));
    assert!(matches!(
        queued.pop_front(),
        Some(QueuedManagerWork::Force { .. })
    ));
    assert!(queued.is_empty());
    active.join.abort();
}

/// A reserved permit must not hold retirement open or create a later cycle.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn retirement_drops_a_reserved_command_without_starting_a_scheduled_cycle() {
    let mut mgr = ListManager::new(
        reqwest::Client::new(),
        Arc::new(FilterEngine::new()),
        vec![],
        Catalog::fallback(),
        Duration::from_secs(12 * 60 * 60),
        SourceBitMap::default(),
        TEST_CAP,
        DEFAULT_MAX_LIST_ENTRIES,
        None,
    );
    let registry = mgr.status_registry();
    let (tx, rx) = mpsc::channel(1);
    mgr.set_command_channel(rx);
    mgr.refresh().await;
    let task = mgr.spawn_refresh_loop_after_refresh();

    let permit = tx
        .clone()
        .reserve_owned()
        .await
        .expect("reserve command slot");
    tokio::time::timeout(Duration::from_secs(1), task.retire())
        .await
        .expect("a reserved permit must not delay retirement")
        .unwrap();

    tokio::time::advance(Duration::from_secs(24 * 60 * 60)).await;
    tokio::task::yield_now().await;
    assert_eq!(
        registry.cycle().seq,
        1,
        "retirement must never fall through and launch a scheduled cycle"
    );
    assert!(tx.is_closed());

    let (accepted_tx, accepted_rx) = oneshot::channel();
    let (completion_tx, completion_rx) = oneshot::channel();
    permit.send(ListManagerCommand::ForceRefresh {
        accepted: accepted_tx,
        completion: completion_tx,
    });
    assert!(tokio::time::timeout(Duration::from_secs(1), accepted_rx)
        .await
        .unwrap()
        .is_err());
    assert!(tokio::time::timeout(Duration::from_secs(1), completion_rx)
        .await
        .unwrap()
        .is_err());
    assert_eq!(registry.cycle().seq, 1);
}

mod concurrency {
    use super::*;

    async fn bounded<F: std::future::Future>(future: F) -> F::Output {
        tokio::time::timeout(Duration::from_secs(10), future)
            .await
            .expect("concurrency boundary timed out")
    }

    fn pause_worker(
        manager: &mut ListManager,
        target: &'static str,
        nth: usize,
    ) -> (oneshot::Receiver<()>, std::sync::mpsc::Sender<()>) {
        let (reached_tx, reached_rx) = oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let mut reached_tx = Some(reached_tx);
        let mut seen = 0;
        manager.set_worker_hook_for_test(move |at| {
            if at == target {
                seen += 1;
                if seen == nth {
                    reached_tx.take().unwrap().send(()).unwrap();
                    release_rx
                        .recv_timeout(Duration::from_secs(10))
                        .expect("release worker barrier");
                }
            }
        });
        (reached_rx, release_tx)
    }

    fn force() -> (
        ListManagerCommand,
        oneshot::Receiver<ListManagerCommandDisposition>,
        oneshot::Receiver<ForceRefreshCompletion>,
    ) {
        let (accepted, acceptance) = oneshot::channel();
        let (completion, result) = oneshot::channel();
        (
            ListManagerCommand::ForceRefresh {
                accepted,
                completion,
            },
            acceptance,
            result,
        )
    }

    #[tokio::test]
    async fn retirement_drops_queued_buffered_and_reserved_work_before_worker_returns() {
        let (mut manager, source, dir) = bridge_manager("old.example\n");
        manager.refresh().await;
        let filter = manager.filter.clone();
        let registry = manager.status_registry();
        let generations = filter.filter_gen_ids();
        let seq = registry.cycle().seq;
        let cache_path = selected_cache_body_path(&dir.path().join("cache"), &source).unwrap();
        std::fs::write(
            dir.path().join("lists/poison.txt"),
            "new.example\nother.example\n",
        )
        .unwrap();
        let (reached, release) = pause_worker(&mut manager, "parse_line", 2);
        let (tx, rx) = mpsc::channel(8);
        manager.set_command_channel(rx);
        let task = manager.spawn_refresh_loop_after_refresh();
        let (command, accepted, active_result) = force();
        tx.send(command).await.unwrap();
        assert_eq!(
            bounded(accepted).await.unwrap(),
            ListManagerCommandDisposition::Started
        );
        bounded(reached).await.unwrap();

        let (accepted, acceptance) = oneshot::channel();
        let (completion, forget_result) = oneshot::channel();
        tx.send(ListManagerCommand::Forget {
            source: source.clone(),
            accepted,
            completion,
        })
        .await
        .unwrap();
        assert_eq!(
            bounded(acceptance).await.unwrap(),
            ListManagerCommandDisposition::Queued
        );
        let (command, accepted, force_result) = force();
        tx.send(command).await.unwrap();
        assert_eq!(
            bounded(accepted).await.unwrap(),
            ListManagerCommandDisposition::Queued
        );
        let permit = tx.clone().reserve_owned().await.unwrap();
        let (buffered, _, buffered_result) = force();
        tx.try_send(buffered).unwrap();

        let retirement = task.retire();
        tokio::pin!(retirement);
        bounded(async {
            tokio::select! {
                biased;
                _ = &mut retirement => panic!("retirement must wait for the active worker"),
                _ = tx.closed() => {}
            }
        })
        .await;
        assert!(bounded(forget_result).await.is_err());
        assert!(bounded(force_result).await.is_err());
        assert!(bounded(buffered_result).await.is_err());
        let (reserved, acceptance, reserved_result) = force();
        permit.send(reserved);
        assert!(bounded(acceptance).await.is_err());
        assert!(bounded(reserved_result).await.is_err());
        release.send(()).unwrap();
        bounded(retirement).await.unwrap();
        assert!(bounded(active_result).await.is_err());
        assert_eq!(registry.cycle().seq, seq);
        assert_eq!(filter.filter_gen_ids(), generations);
        assert_eq!(
            std::fs::read_to_string(cache_path).unwrap(),
            "old.example\n"
        );
        assert!(!dir.path().join("cache").join(SHARD_SPILL_DIR).exists());
    }

    #[tokio::test]
    async fn late_force_after_snapshot_publication_queues_a_new_cycle() {
        let (mut manager, _, _dir) = bridge_manager("old.example\n");
        manager.refresh().await;
        let registry = manager.status_registry();
        let (published, release) = pause_worker(&mut manager, "worker_return", 1);
        let (tx, rx) = mpsc::channel(8);
        manager.set_command_channel(rx);
        let task = manager.spawn_refresh_loop_after_refresh();
        let (command, accepted, first_result) = force();
        tx.send(command).await.unwrap();
        assert_eq!(
            bounded(accepted).await.unwrap(),
            ListManagerCommandDisposition::Started
        );
        bounded(published).await.unwrap();
        let published_seq = registry.cycle().seq;
        let (command, accepted, late_result) = force();
        tx.send(command).await.unwrap();
        assert_eq!(
            bounded(accepted).await.unwrap(),
            ListManagerCommandDisposition::Queued
        );
        release.send(()).unwrap();
        assert_eq!(
            bounded(first_result).await.unwrap().snapshot.cycle.seq,
            published_seq
        );
        assert_eq!(
            bounded(late_result).await.unwrap().snapshot.cycle.seq,
            published_seq + 1
        );
        bounded(task.retire()).await.unwrap();
    }

    async fn cancel_prepublication_at(
        target: &'static str,
        nth: usize,
        mode: RefreshMode,
        disk: bool,
    ) {
        let (mut manager, source, dir) = if target == "cache_hash" {
            let (manager, sources, dir) = cached_manager(&["old.example\n"]);
            (manager, sources[0].clone(), dir)
        } else {
            bridge_manager("old.example\n")
        };
        if !disk {
            manager.cache_dir = None;
        }
        manager.refresh().await;
        manager.set_max_total_domains(100_000);
        let filter = manager.filter.clone();
        let registry = manager.status_registry();
        let generations = filter.filter_gen_ids();
        let digest = manager.installed_corpus_digest;
        let seq = registry.cycle().seq;
        let cache_dir = dir.path().join("cache");
        let before_files: BTreeSet<_> = std::fs::read_dir(&cache_dir)
            .unwrap()
            .map(|p| p.unwrap().file_name())
            .collect();
        let before_meta = disk.then(|| {
            std::fs::read(cache_dir.join(format!("{}.meta", source_to_cache_stem(&source))))
                .unwrap()
        });
        // More than one read, and only comments before valid rows: cancellation
        // must not depend on the parser emitting a domain into the sink.
        let mut body = format!("{}new.example\nother.example\n", "# comment\n".repeat(2000));
        for idx in 0..DOMAIN_SHARDS {
            let domain = (0..)
                .map(|n| format!("shard-{idx}-{n}.example"))
                .find(|domain| FilterEngine::shard_index(domain) == idx)
                .unwrap();
            body.push_str(&domain);
            body.push('\n');
        }
        std::fs::create_dir_all(dir.path().join("lists")).unwrap();
        std::fs::write(dir.path().join("lists/poison.txt"), body).unwrap();
        let signal = RefreshCancellation::default();
        let cancel = signal.clone();
        let hit = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let hit_hook = hit.clone();
        let mut seen = 0;
        manager.set_worker_hook_for_test(move |at| {
            if at == target {
                seen += 1;
                if seen == nth {
                    hit_hook.store(true, std::sync::atomic::Ordering::Release);
                    cancel.cancel();
                }
            }
        });
        let outcome = bounded(spawn_list_refresh_worker(manager, mode, signal))
            .await
            .unwrap();
        assert!(
            hit.load(std::sync::atomic::Ordering::Acquire),
            "missed {target}"
        );
        let RefreshWorkerOutcome::Cancelled { manager } = outcome else {
            panic!("{target} published after cancellation");
        };
        assert_eq!(manager.installed_corpus_digest, digest, "{target}");
        assert_eq!(registry.cycle().seq, seq, "{target}");
        assert_eq!(filter.filter_gen_ids(), generations, "{target}");
        assert!(filter.is_blocked("old.example"));
        assert!(!filter.is_blocked("new.example"));
        let after_files: BTreeSet<_> = std::fs::read_dir(&cache_dir)
            .unwrap()
            .map(|p| p.unwrap().file_name())
            .collect();
        assert_eq!(
            after_files, before_files,
            "{target}: leaked spill/staged body"
        );
        if let Some(before_meta) = before_meta {
            assert_eq!(
                std::fs::read(cache_dir.join(format!("{}.meta", source_to_cache_stem(&source))))
                    .unwrap(),
                before_meta
            );
        }
    }

    #[tokio::test]
    async fn accepted_304_defers_metadata_and_health_until_commit() {
        for (target, changed) in [
            ("source", true),
            ("before_commit", true),
            ("before_commit", false),
            ("after_swap", true),
            ("worker_return", false),
        ] {
            let (origin, pem, requests) = spawn_tls_origin_responses(vec![
                tls_ok_response("retained.example\n", "\"retained\""),
                tls_ok_response("old.example\n", "\"old\""),
                "HTTP/1.1 304 Not Modified\r\nConnection: close\r\n\r\n".to_string(),
                tls_ok_response(
                    if changed {
                        "new.example\n"
                    } else {
                        "old.example\n"
                    },
                    "\"later\"",
                ),
            ])
            .await;
            let earlier = "https://lists.test/earlier.txt".to_string();
            let later = "https://lists.test/later.txt".to_string();
            let sources = vec![earlier.clone(), later];
            let dir = tempfile::tempdir().unwrap();
            let cache_dir = dir.path().join("cache");
            let mut manager = ListManager::new(
                reqwest::Client::builder()
                    .no_proxy()
                    .resolve("lists.test", origin)
                    .add_root_certificate(reqwest::Certificate::from_pem(pem.as_bytes()).unwrap())
                    .timeout(Duration::from_secs(2))
                    .build()
                    .unwrap(),
                Arc::new(FilterEngine::new()),
                sources.clone(),
                Catalog::fallback(),
                Duration::from_secs(3600),
                build_source_bit_map(&sources).unwrap(),
                TEST_CAP,
                DEFAULT_MAX_LIST_ENTRIES,
                Some(cache_dir.clone()),
            );
            let id = crate::config::schema::Id::new("earlier").unwrap();
            manager.set_source_blocklist_map(HashMap::from([(earlier.clone(), (id.clone(), 2))]));
            let state_path = dir.path().join("list_state.toml");
            let schedule_path = dir.path().join("list_schedule_state.toml");
            manager.set_list_state(Default::default(), Some(state_path.clone()));
            manager.set_schedule_state(Default::default(), Some(schedule_path.clone()), false);
            let key = install_test_schedule(&mut manager, &earlier);
            let anchor = OffsetDateTime::now_utc() - time::Duration::hours(2);
            assert_eq!(bounded(manager.refresh_at(anchor)).await, 2);

            // A cancelled confirmation must not recover an unhealthy source.
            manager.record_blocklist_failure(&id, 2);
            manager.record_blocklist_failure(&id, 2);
            let previous = manager.status_registry.status_for_url(&earlier).unwrap();
            manager.status_registry.update_for_url(
                &earlier,
                ListStatus::from_failure(Some(&previous), "prior failure".to_string(), anchor),
            );
            manager.schedule_state.record_failure(key.clone(), anchor);
            manager.persist_schedule_state();
            manager.legacy_cache_timestamp_urls.insert(earlier.clone());
            let meta_path = cache_dir.join(format!("{}.meta", source_to_cache_stem(&earlier)));
            let meta_before = std::fs::read(&meta_path).unwrap();
            let state_bytes_before = std::fs::read(&state_path).unwrap();
            let schedule_bytes_before = std::fs::read(&schedule_path).unwrap();
            let cache_before = manager.cache[&earlier].clone();
            let legacy_before = manager.legacy_cache_timestamp_urls.clone();
            let state_before = manager.list_state_handle().lock().unwrap().clone();
            let schedule_before = manager.schedule_state.clone();
            let status_before = manager.status_registry.status_for_url(&earlier).unwrap();
            let generations = manager.filter.filter_gen_ids();
            let digest = manager.installed_corpus_digest;
            let cycle = manager.status_registry.cycle();
            assert!(digest.is_some());
            let files_before: BTreeSet<_> = std::fs::read_dir(&cache_dir)
                .unwrap()
                .map(|p| p.unwrap().file_name())
                .collect();

            let signal = RefreshCancellation::default();
            let cancel = signal.clone();
            let hit = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let hit_hook = hit.clone();
            let mut seen = 0;
            manager.set_worker_hook_for_test(move |at| {
                if at == target {
                    seen += 1;
                    if seen == if target == "source" { 2 } else { 1 } {
                        hit_hook.store(true, std::sync::atomic::Ordering::Release);
                        cancel.cancel();
                    }
                }
            });
            let outcome = bounded(spawn_list_refresh_worker(
                manager,
                RefreshMode::Force,
                signal,
            ))
            .await
            .unwrap();
            assert!(
                hit.load(std::sync::atomic::Ordering::Acquire),
                "missed {target}"
            );
            let requests = requests.lock().unwrap();
            assert_eq!(requests.len(), if target == "source" { 3 } else { 4 });
            assert!(requests[2].starts_with("get /earlier.txt "));
            assert!(requests[2].contains("if-none-match: \"retained\""));

            match outcome {
                RefreshWorkerOutcome::Cancelled { manager } => {
                    assert!(matches!(target, "source" | "before_commit"));
                    assert_eq!(std::fs::read(&meta_path).unwrap(), meta_before, "{target}");
                    assert_eq!(manager.cache[&earlier], cache_before);
                    assert_eq!(manager.legacy_cache_timestamp_urls, legacy_before);
                    assert_eq!(*manager.list_state_handle().lock().unwrap(), state_before);
                    assert_eq!(std::fs::read(&state_path).unwrap(), state_bytes_before);
                    assert_eq!(manager.schedule_state, schedule_before);
                    assert_eq!(
                        std::fs::read(&schedule_path).unwrap(),
                        schedule_bytes_before
                    );
                    assert_eq!(
                        manager.status_registry.status_for_url(&earlier).unwrap(),
                        status_before
                    );
                    assert_eq!(manager.filter.filter_gen_ids(), generations);
                    assert_eq!(manager.installed_corpus_digest, digest);
                    assert_eq!(manager.status_registry.cycle(), cycle);
                    assert!(manager.filter.is_blocked("retained.example"));
                    assert!(manager.filter.is_blocked("old.example"));
                    assert!(!manager.filter.is_blocked("new.example"));
                    let files_after: BTreeSet<_> = std::fs::read_dir(&cache_dir)
                        .unwrap()
                        .map(|p| p.unwrap().file_name())
                        .collect();
                    assert_eq!(files_after, files_before);
                }
                RefreshWorkerOutcome::Completed {
                    manager,
                    completion,
                } => {
                    assert!(matches!(target, "after_swap" | "worker_return"));
                    let fetched_at = manager.cache[&earlier].fetched_at;
                    assert!(fetched_at > anchor);
                    assert_eq!(load_meta_file(&meta_path).fetched_at, Some(fetched_at));
                    assert!(!manager.legacy_cache_timestamp_urls.contains(&earlier));
                    let state = manager.list_state_handle().lock().unwrap().clone();
                    assert_eq!(state.lists[&id].consecutive_failures, 0);
                    assert_eq!(
                        state.lists[&id].status,
                        crate::config::list_state::ListStatus::Active
                    );
                    assert!(state.lists[&id].last_success > state_before.lists[&id].last_success);
                    assert_eq!(
                        state.lists[&id].cache_path,
                        state_before.lists[&id].cache_path
                    );
                    assert_eq!(
                        crate::config::list_state::ListState::read_or_default(&state_path).unwrap(),
                        state
                    );
                    assert_eq!(
                        manager.schedule_state.lookup(&key).unwrap().outcome,
                        CanonicalScheduleOutcome::Success
                    );
                    assert_eq!(
                        manager.schedule_state.lookup(&key).unwrap().last_attempt,
                        fetched_at
                    );
                    assert_eq!(
                        ListScheduleState::read_or_default(&schedule_path).unwrap(),
                        manager.schedule_state
                    );
                    assert_eq!(
                        manager
                            .status_registry
                            .status_for_url(&earlier)
                            .unwrap()
                            .last_outcome,
                        LastOutcome::Ok
                    );
                    assert_eq!(completion.snapshot.cycle.seq, cycle.seq + 1);
                    assert_eq!(completion.snapshot.domain_count, 2);
                    assert!(!completion.snapshot.cycle.generation_degraded);
                    assert!(manager.filter.is_blocked("retained.example"));
                    assert_eq!(manager.filter.is_blocked("new.example"), changed);
                    assert_eq!(manager.filter.is_blocked("old.example"), !changed);
                    let ids = manager.filter.filter_gen_ids();
                    assert!(ids.iter().all(|id| *id == ids[0]));
                    assert_eq!(ids == generations, !changed);
                    assert!(manager.installed_corpus_digest.is_some());
                    assert_eq!(manager.installed_corpus_digest == digest, !changed);
                    assert!(!cache_dir.join(SHARD_SPILL_DIR).exists());
                }
            }
        }
    }

    #[tokio::test]
    async fn cancellation_during_local_read_parse_and_staging_preserves_publication() {
        for (target, nth) in [
            ("local_read", 2),
            ("sniff", 2),
            ("parse_line", 2),
            ("parse_read", 2),
            ("staged_body", 1),
        ] {
            cancel_prepublication_at(target, nth, RefreshMode::Force, true).await;
        }
    }

    #[tokio::test]
    async fn cancellation_during_retained_hash_and_parse_preserves_publication() {
        cancel_prepublication_at("cache_hash", 1, RefreshMode::CacheOnly, true).await;
        cancel_prepublication_at("parse_line", 1, RefreshMode::CacheOnly, false).await;
    }

    async fn retire_stalled_http(headers: bool) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let _ = rustls::crypto::ring::default_provider().install_default();
        let cert = rcgen::generate_simple_self_signed(vec!["lists.test".to_string()]).unwrap();
        let client_cert = reqwest::Certificate::from_pem(cert.cert.pem().as_bytes()).unwrap();
        let key = rustls::pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
        let server = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.cert.der().clone()],
                rustls::pki_types::PrivateKeyDer::Pkcs8(key),
            )
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server));
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let (request_tx, request_rx) = oneshot::channel();
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut tls = acceptor.accept(tcp).await.unwrap();
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                request.push(tls.read_u8().await.unwrap());
            }
            request_tx.send(()).unwrap();
            if !headers {
                tls.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 100000\r\n\r\npartial.example\n",
                )
                .await
                .unwrap();
                tls.flush().await.unwrap();
            }
            // Keep the socket open until the cancelled client drops it.
            let mut byte = [0];
            let _ = tls.read(&mut byte).await;
        });
        let client = reqwest::Client::builder()
            .no_proxy()
            .add_root_certificate(client_cert)
            .resolve("lists.test", addr)
            .timeout(Duration::from_secs(600))
            .build()
            .unwrap();
        let source = format!("https://lists.test:{}/list.txt", addr.port());
        let dir = tempfile::tempdir().unwrap();
        let mut manager = ListManager::new(
            client,
            Arc::new(FilterEngine::new()),
            vec![source.clone()],
            Catalog::fallback(),
            Duration::from_secs(3600),
            build_source_bit_map(&[source]).unwrap(),
            TEST_CAP,
            DEFAULT_MAX_LIST_ENTRIES,
            Some(dir.path().to_path_buf()),
        );
        let (body_tx, body_rx) = oneshot::channel();
        let mut body_tx = Some(body_tx);
        manager.set_worker_hook_for_test(move |at| {
            if at == "http_body_chunk" {
                if let Some(tx) = body_tx.take() {
                    let _ = tx.send(());
                }
            }
        });
        let filter = manager.filter.clone();
        let registry = manager.status_registry();
        let generations = filter.filter_gen_ids();
        let task = manager.spawn_refresh_loop();
        bounded(request_rx).await.unwrap();
        if !headers {
            bounded(body_rx).await.unwrap();
        }
        bounded(task.retire()).await.unwrap();
        assert_eq!(registry.cycle().seq, 0);
        assert_eq!(filter.filter_gen_ids(), generations);
        assert_eq!(filter.domain_count(), 0);
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
        bounded(server).await.unwrap();
    }

    #[tokio::test]
    async fn retirement_cancels_http_while_waiting_for_headers() {
        retire_stalled_http(true).await;
    }

    #[tokio::test]
    async fn retirement_cancels_http_while_waiting_for_more_body() {
        retire_stalled_http(false).await;
    }

    #[tokio::test]
    async fn cancellation_before_first_swap_and_during_spill_work_preserves_publication() {
        for disk in [true, false] {
            for target in [
                "spill_validate",
                "before_sort",
                "after_sort",
                "before_commit",
            ] {
                cancel_prepublication_at(target, 1, RefreshMode::Force, disk).await;
            }
            cancel_prepublication_at(
                if disk { "spill_read" } else { "spill_count" },
                1,
                RefreshMode::Force,
                disk,
            )
            .await;
        }
        cancel_prepublication_at("spill_load", 1, RefreshMode::Force, false).await;
        cancel_prepublication_at("spill_flush", 1, RefreshMode::Force, true).await;
    }

    #[tokio::test]
    async fn cancellation_cannot_interrupt_an_empty_commit_or_change_its_digest() {
        for target in ["before_commit", "after_swap"] {
            let (mut manager, _, dir) = bridge_manager("old.example\n");
            manager.refresh().await;
            manager.set_shrink_guard(false, 90);
            let digest = manager.installed_corpus_digest;
            let generations = manager.filter.filter_gen_ids();
            let seq = manager.status_registry.cycle().seq;
            std::fs::write(dir.path().join("lists/poison.txt"), "").unwrap();
            let signal = RefreshCancellation::default();
            let cancel = signal.clone();
            manager.set_worker_hook_for_test(move |at| {
                if at == target {
                    cancel.cancel();
                }
            });
            match bounded(spawn_list_refresh_worker(
                manager,
                RefreshMode::Force,
                signal,
            ))
            .await
            .unwrap()
            {
                RefreshWorkerOutcome::Cancelled { manager } => {
                    assert_eq!(target, "before_commit");
                    assert_eq!(manager.installed_corpus_digest, digest);
                    assert_eq!(manager.filter.filter_gen_ids(), generations);
                    assert_eq!(manager.status_registry.cycle().seq, seq);
                }
                RefreshWorkerOutcome::Completed {
                    manager,
                    completion,
                } => {
                    assert_eq!(target, "after_swap");
                    assert_ne!(manager.installed_corpus_digest, digest);
                    assert!(manager.installed_corpus_digest.is_some());
                    assert_eq!(completion.snapshot.cycle.seq, seq + 1);
                    assert_eq!(completion.snapshot.domain_count, 0);
                    let ids = manager.filter.filter_gen_ids();
                    assert_ne!(ids, generations);
                    assert!(ids.iter().all(|id| *id == ids[0]));
                }
            }
        }
    }

    #[tokio::test]
    async fn cancellation_at_spill_open_failure_does_not_publish_a_cycle() {
        let (mut manager, _, _dir) = bridge_manager("old.example\n");
        let signal = RefreshCancellation::default();
        let cancel = signal.clone();
        manager.set_worker_hook_for_test(move |at| {
            if at == "start" {
                fail_next_shard_spill_dir_create_for_test();
            }
            if at == "before_commit" {
                cancel.cancel();
            }
        });
        let RefreshWorkerOutcome::Cancelled { manager } = bounded(spawn_list_refresh_worker(
            manager,
            RefreshMode::Force,
            signal,
        ))
        .await
        .unwrap() else {
            panic!("cancelled spill failure published a cycle");
        };
        assert_eq!(manager.status_registry.cycle().seq, 0);
        assert!(manager.installed_corpus_digest.is_none());
        assert_eq!(manager.filter.domain_count(), 0);
    }

    #[tokio::test]
    async fn retirement_after_first_swap_waits_for_the_complete_commit() {
        let (mut manager, source, dir) = bridge_manager("old.example\n");
        manager.refresh().await;
        let filter = manager.filter.clone();
        let registry = manager.status_registry();
        let generations = filter.filter_gen_ids();
        let seq = registry.cycle().seq;
        std::fs::write(
            dir.path().join("lists/poison.txt"),
            "new.example\nother.example\n",
        )
        .unwrap();
        let (swapped, release) = pause_worker(&mut manager, "after_swap", 1);
        let (tx, rx) = mpsc::channel(8);
        manager.set_command_channel(rx);
        let task = manager.spawn_refresh_loop_after_refresh();
        let (command, accepted, result) = force();
        tx.send(command).await.unwrap();
        bounded(accepted).await.unwrap();
        bounded(swapped).await.unwrap();
        let retirement = task.retire();
        tokio::pin!(retirement);
        bounded(async {
            tokio::select! {
                biased;
                _ = &mut retirement => panic!("commit must finish first"),
                _ = tx.closed() => {}
            }
        })
        .await;
        assert_eq!(registry.cycle().seq, seq);
        release.send(()).unwrap();
        bounded(retirement).await.unwrap();
        let completion = bounded(result).await.unwrap();
        assert_eq!(completion.snapshot.cycle.seq, seq + 1);
        assert_eq!(completion.snapshot.domain_count, 2);
        assert!(filter.is_blocked("new.example"));
        assert!(!filter.is_blocked("old.example"));
        let committed = filter.filter_gen_ids();
        assert!(committed.iter().all(|id| *id == committed[0]));
        assert_ne!(committed, generations);
        let path = selected_cache_body_path(&dir.path().join("cache"), &source).unwrap();
        assert_eq!(
            std::fs::read_to_string(path).unwrap(),
            "new.example\nother.example\n"
        );
        assert!(!dir.path().join("cache").join(SHARD_SPILL_DIR).exists());
    }
}

#[tokio::test]
async fn refresh_with_no_sources_keeps_empty() {
    let client = reqwest::Client::new();
    let filter = Arc::new(FilterEngine::new());
    let catalog = Catalog::fallback();
    let mut mgr = ListManager::new(
        client,
        filter.clone(),
        vec![],
        catalog,
        Duration::from_secs(3600),
        SourceBitMap::default(),
        TEST_CAP,
        DEFAULT_MAX_LIST_ENTRIES,
        None,
    );
    let count = mgr.refresh().await;
    assert_eq!(count, 0);
    assert_eq!(filter.domain_count(), 0);
}

#[tokio::test]
async fn refresh_with_unknown_source_logs_warning() {
    let client = reqwest::Client::new();
    let filter = Arc::new(FilterEngine::new());
    let catalog = Catalog::fallback();
    let mut mgr = ListManager::new(
        client,
        filter.clone(),
        vec!["nonexistent/list".to_string()],
        catalog,
        Duration::from_secs(3600),
        SourceBitMap::default(),
        TEST_CAP,
        DEFAULT_MAX_LIST_ENTRIES,
        None,
    );
    let count = mgr.refresh().await;
    assert_eq!(count, 0);
}

#[tokio::test]
async fn download_real_purge_cc_list() {
    let client = reqwest::Client::builder()
        .user_agent("purge-warden/test")
        .timeout(Duration::from_secs(15))
        .build()
        .unwrap();
    let filter = Arc::new(FilterEngine::new());
    let catalog = Catalog::fallback();
    let source_bits = build_source_bit_map(&["privacy/ads".into()]).expect("at-cap accept");
    let mut mgr = ListManager::new(
        client,
        filter.clone(),
        vec!["privacy/ads".to_string()],
        catalog,
        Duration::from_secs(3600),
        source_bits,
        TEST_CAP,
        DEFAULT_MAX_LIST_ENTRIES,
        None,
    );
    let count = mgr.refresh().await;
    assert!(filter.domain_count() == count);
}

#[tokio::test]
async fn download_raw_url_source() {
    let client = reqwest::Client::builder()
        .user_agent("purge-warden/test")
        .timeout(Duration::from_secs(15))
        .build()
        .unwrap();
    let filter = Arc::new(FilterEngine::new());
    let catalog = Catalog::fallback();
    let url = "https://lists.purge.cc/base_ads.txt".to_string();
    let source_bits = build_source_bit_map(std::slice::from_ref(&url)).expect("at-cap accept");
    let mut mgr = ListManager::new(
        client,
        filter.clone(),
        vec![url],
        catalog,
        Duration::from_secs(3600),
        source_bits,
        TEST_CAP,
        DEFAULT_MAX_LIST_ENTRIES,
        None,
    );
    let count = mgr.refresh().await;
    assert!(filter.domain_count() == count);
}

#[test]
fn build_source_bit_map_assigns_sequential_bits() {
    let sources = vec!["a".into(), "b".into(), "c".into()];
    let map = build_source_bit_map(&sources).expect("at-cap accept");
    assert_eq!(map.bit_for_url("a"), Some(0));
    assert_eq!(map.bit_for_url("b"), Some(1));
    assert_eq!(map.bit_for_url("c"), Some(2));
}

#[test]
fn build_source_bit_map_accepts_at_cap_64() {
    let sources: Vec<String> = (0..64).map(|i| format!("list/{i}")).collect();
    let map = build_source_bit_map(&sources).expect("64 sources is the boundary");
    assert_eq!(map.len(), 64);
    assert_eq!(map.bit_for_url("list/0"), Some(0));
    assert_eq!(map.bit_for_url("list/63"), Some(63));
}

#[test]
fn build_source_bit_map_errors_one_over_cap() {
    let sources: Vec<String> = (0..65).map(|i| format!("list/{i}")).collect();
    let err = build_source_bit_map(&sources).expect_err("65 sources exceeds u64 cap");
    let msg = err.to_string();
    assert!(
        msg.contains("65"),
        "message must report actual count: {msg}"
    );
    assert!(msg.contains("64"), "message must report cap: {msg}");
    assert!(
        msg.contains("config.toml"),
        "message must point to config.toml: {msg}"
    );
}

// §4.24 Phase C — `build_source_bit_map_with_v1_aliases` (May 6
// hotfix workaround) and its two manager-level regression pins are
// gone. Equivalent coverage now lives in
// `src/lists/source_key.rs::tests` against the typed
// [`SourceBitMap`] surface (`build_pure_v1_config_seeds_v1_id_alias_
// from_blocklist`, `build_skips_disabled_blocklists`).

// --- read_bounded_body (P0-1) ---

/// Mock HTTP server helper used by streaming-body tests.
///
/// Spawns a task that accepts one TCP connection, reads (and discards)
/// the request, writes the given headers, then streams `total_bytes`
/// bytes of `0x61` ('a') in 1 MiB chunks. Closes the connection when
/// done or aborts if the client gives up.
async fn spawn_mock_stream_server(
    headers: &'static str,
    total_bytes: usize,
) -> std::net::SocketAddr {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        let (mut stream, _) = match listener.accept().await {
            Ok(pair) => pair,
            Err(_) => return,
        };

        // Drain the request line + headers (enough for reqwest to be happy).
        let mut buf = [0u8; 2048];
        let _ = stream.read(&mut buf).await;

        if stream.write_all(headers.as_bytes()).await.is_err() {
            return;
        }

        let chunk = vec![b'a'; 1024 * 1024];
        let mut sent = 0;
        while sent < total_bytes {
            let remaining = total_bytes - sent;
            let to_send = remaining.min(chunk.len());
            if stream.write_all(&chunk[..to_send]).await.is_err() {
                return;
            }
            sent += to_send;
        }
    });

    addr
}

/// Oversized body with no `Content-Length` — the historical OOM vector.
/// The streaming reader must abort mid-stream rather than buffer all
/// 60 MiB before checking.
#[tokio::test]
async fn read_bounded_body_aborts_on_oversized_stream_no_content_length() {
    // 60 MiB, no Content-Length, connection: close — server signals EOF by
    // closing the socket. `resp.text()` would have read to EOF; we must not.
    let addr = spawn_mock_stream_server(
        "HTTP/1.1 200 OK\r\n\
         Connection: close\r\n\
         Content-Type: text/plain\r\n\
         \r\n",
        60 * 1024 * 1024,
    )
    .await;

    let client = reqwest::Client::new();
    let url = format!("http://{addr}/blocklist.txt");
    let resp = client.get(&url).send().await.unwrap();
    // Use a small cap so the 60 MiB stream trips it.
    let result = read_bounded_body(resp, &url, TEST_SMALL_CAP).await;

    match result {
        Err(ListError::TooLarge { size, .. }) => {
            // We should have aborted on the first chunk past the cap,
            // not after reading all 60 MiB into memory.
            assert!(
                size > TEST_SMALL_CAP,
                "size {size} should exceed cap {TEST_SMALL_CAP}"
            );
            assert!(
                size <= TEST_SMALL_CAP + 1024 * 1024,
                "size {size} should be close to cap + one chunk (not the full 60 MiB)"
            );
        }
        other => panic!("expected TooLarge, got {other:?}"),
    }
}

#[test]
fn bounded_body_growth_refuses_integer_overflow() {
    assert_eq!(bounded_body_growth(8, 2, 10), Ok(10));
    assert_eq!(bounded_body_growth(8, 3, 10), Err(11));
    assert_eq!(
        bounded_body_growth(usize::MAX - 1, 1, usize::MAX),
        Ok(usize::MAX)
    );
    assert_eq!(
        bounded_body_growth(usize::MAX, 1, usize::MAX),
        Err(usize::MAX)
    );
}

#[test]
fn resident_body_content_length_hint_has_an_independent_cap() {
    assert_eq!(bounded_body_initial_capacity(None, usize::MAX), 0);
    assert_eq!(bounded_body_initial_capacity(Some(12), 10), 10);
    assert_eq!(
        bounded_body_initial_capacity(Some(u64::MAX), usize::MAX),
        if usize::BITS < 64 {
            0
        } else {
            RESIDENT_BODY_INITIAL_CAPACITY_MAX
        }
    );
    assert_eq!(
        bounded_body_initial_capacity(
            Some((RESIDENT_BODY_INITIAL_CAPACITY_MAX as u64) * 8),
            usize::MAX,
        ),
        RESIDENT_BODY_INITIAL_CAPACITY_MAX
    );
}

/// Small body well under the cap — happy path.
#[tokio::test]
async fn read_bounded_body_accepts_small_body() {
    // 1 KiB body — trivially under the cap.
    let headers = "HTTP/1.1 200 OK\r\n\
                   Content-Length: 1024\r\n\
                   Content-Type: text/plain\r\n\
                   \r\n";
    let addr = spawn_mock_stream_server(headers, 1024).await;

    let client = reqwest::Client::new();
    let url = format!("http://{addr}/blocklist.txt");
    let resp = client.get(&url).send().await.unwrap();
    let body = read_bounded_body(resp, &url, TEST_CAP).await.unwrap();
    assert_eq!(body.len(), 1024);
    assert!(body.chars().all(|c| c == 'a'));
}

/// M-22: a `Content-Length` larger than `max_bytes` must NOT translate
/// into a `Vec::with_capacity(huge)` — the hint is clamped to `max_bytes`
/// before pre-allocation. The streaming bound then trips on actual
/// chunks. Server announces a body 4× the cap and streams accordingly;
/// the abort comes from the streaming check, not from an OOM allocation.
#[tokio::test]
async fn read_bounded_body_clamps_oversized_content_length_hint() {
    let oversized = TEST_SMALL_CAP * 4;
    let headers = format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Length: {oversized}\r\n\
         Content-Type: text/plain\r\n\
         \r\n",
    );
    // SAFETY: tests Box::leak the format!()-d header so spawn_mock_stream_server
    // can take a 'static str. Test-only; one allocation per test invocation.
    let headers_static: &'static str = Box::leak(headers.into_boxed_str());
    let addr = spawn_mock_stream_server(headers_static, oversized).await;

    let client = reqwest::Client::new();
    let url = format!("http://{addr}/blocklist.txt");
    let resp = client.get(&url).send().await.unwrap();
    let result = read_bounded_body(resp, &url, TEST_SMALL_CAP).await;
    match result {
        Err(ListError::TooLarge { size, max, .. }) => {
            assert_eq!(max, TEST_SMALL_CAP);
            assert!(
                size > TEST_SMALL_CAP,
                "size {size} should exceed cap {TEST_SMALL_CAP}"
            );
        }
        other => panic!("expected TooLarge for oversized Content-Length stream, got {other:?}"),
    }
}

/// Mock server variant that streams a fixed raw-byte payload once, then
/// closes. Unlike [`spawn_mock_stream_server`] (which only sends `'a'`),
/// this lets a test deliver bytes that are NOT valid UTF-8.
async fn spawn_mock_bytes_server(payload: &'static [u8]) -> std::net::SocketAddr {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        let (mut stream, _) = match listener.accept().await {
            Ok(pair) => pair,
            Err(_) => return,
        };
        let mut buf = [0u8; 2048];
        let _ = stream.read(&mut buf).await;
        let header = format!(
            "HTTP/1.1 200 OK\r\n\
             Connection: close\r\n\
             Content-Length: {}\r\n\
             Content-Type: text/plain\r\n\
             \r\n",
            payload.len()
        );
        if stream.write_all(header.as_bytes()).await.is_err() {
            return;
        }
        let _ = stream.write_all(payload).await;
    });

    addr
}

/// A single invalid UTF-8 byte must NOT fail the whole download (the
/// prior strict `from_utf8` behaviour). Lossy decode turns the bad byte
/// into U+FFFD, so only the line carrying it is dropped by
/// `is_valid_domain` — the rest of the list still blocks. "One bad byte
/// costs one domain, not the list."
#[tokio::test]
async fn read_bounded_body_lossy_keeps_list_on_bad_byte() {
    // 0xFF is invalid UTF-8. Line 1 is a clean domain; line 2 carries the
    // bad byte at its head.
    let addr = spawn_mock_bytes_server(b"good.com\n\xFFbad.example\n").await;

    let client = reqwest::Client::new();
    let url = format!("http://{addr}/blocklist.txt");
    let resp = client.get(&url).send().await.unwrap();

    // Does NOT error — strict `String::from_utf8` would have failed here.
    let body = read_bounded_body(resp, &url, TEST_CAP).await.unwrap();
    assert!(
        body.contains('\u{FFFD}'),
        "bad byte should decode to U+FFFD"
    );

    // Blast radius is one line: good.com survives, the U+FFFD-mangled
    // line is rejected by is_valid_domain.
    let parsed = crate::lists::parser::parse_domain_list(&body);
    assert!(parsed.contains("good.com"), "clean domain must survive");
    assert_eq!(parsed.len(), 1, "only the clean domain should parse");
}

/// Invalid URL validation at the pre-flight step. Ensures private-IP
/// literal URLs are rejected by `download_list` before any HTTP is sent.
#[tokio::test]
async fn download_list_rejects_loopback_literal() {
    let catalog = Catalog::fallback();
    let filter = Arc::new(FilterEngine::new());
    let url = "https://127.0.0.1/blocklist.txt".to_string();
    let source_bits = build_source_bit_map(std::slice::from_ref(&url)).expect("at-cap accept");
    let mut mgr = ListManager::new(
        reqwest::Client::new(),
        filter.clone(),
        vec![url],
        catalog,
        Duration::from_secs(3600),
        source_bits,
        TEST_CAP,
        DEFAULT_MAX_LIST_ENTRIES,
        None,
    );
    // refresh() does not propagate per-URL errors; it logs and continues.
    // So we assert that the download fails by observing zero domains
    // merged (the only source was rejected).
    let count = mgr.refresh().await;
    assert_eq!(count, 0);
    assert_eq!(filter.domain_count(), 0);
}

/// `http://` URLs are rejected by the pre-flight scheme check.
#[tokio::test]
async fn download_list_rejects_http_scheme() {
    let catalog = Catalog::fallback();
    let filter = Arc::new(FilterEngine::new());
    let url = "http://lists.purge.cc/base_ads.txt".to_string();
    let source_bits = build_source_bit_map(std::slice::from_ref(&url)).expect("at-cap accept");
    let mut mgr = ListManager::new(
        reqwest::Client::new(),
        filter.clone(),
        vec![url],
        catalog,
        Duration::from_secs(3600),
        source_bits,
        TEST_CAP,
        DEFAULT_MAX_LIST_ENTRIES,
        None,
    );
    let count = mgr.refresh().await;
    assert_eq!(count, 0);
}

// --- disk cache ---

#[test]
fn source_to_cache_stem_catalog_id() {
    // Stem now ends with `-<hash8>` (T3.4 M-23). The sanitised prefix is
    // preserved verbatim; only the suffix is new.
    let privacy = source_to_cache_stem("privacy/ads");
    assert!(privacy.starts_with("privacy_ads-"), "got {privacy}");
    let suffix = privacy.strip_prefix("privacy_ads-").unwrap();
    assert_eq!(suffix.len(), 8);
    assert!(suffix.chars().all(|c| c.is_ascii_hexdigit()));

    let security = source_to_cache_stem("security/malicious");
    assert!(
        security.starts_with("security_malicious-"),
        "got {security}"
    );
}

#[test]
fn source_to_cache_stem_raw_url() {
    let stem = source_to_cache_stem("https://lists.purge.cc/ads.txt");
    assert!(
        stem.starts_with("https___lists.purge.cc_ads.txt-"),
        "got {stem}"
    );
    // No path separators or colons — safe as a filename
    assert!(!stem.contains('/'));
    assert!(!stem.contains(':'));
}

/// M-23: two distinct sources whose sanitised forms collide must
/// produce distinct stems. Pre-fix `https://a.example/list.txt` and
/// `https://b.example/list.txt` sanitised to different stems already,
/// but `privacy/ads` and `privacy@ads` BOTH sanitised to `privacy_ads`
/// and silently overwrote each other on disk. The hash suffix breaks
/// the collision by keying on the original (un-sanitised) bytes.
#[test]
fn source_to_cache_stem_disambiguates_sanitisation_collisions() {
    let a = source_to_cache_stem("privacy/ads");
    let b = source_to_cache_stem("privacy@ads");
    let c = source_to_cache_stem("privacy:ads");
    // All sanitise to the same prefix...
    assert!(a.starts_with("privacy_ads-"));
    assert!(b.starts_with("privacy_ads-"));
    assert!(c.starts_with("privacy_ads-"));
    // ...but the suffixes disambiguate.
    assert_ne!(a, b);
    assert_ne!(a, c);
    assert_ne!(b, c);
}

/// M-23: same source must always produce the same stem (deterministic
/// across binaries). SHA-256 is stable; `Hasher::default()` is not.
#[test]
fn source_to_cache_stem_is_deterministic() {
    let a = source_to_cache_stem("privacy/ads");
    let b = source_to_cache_stem("privacy/ads");
    assert_eq!(a, b);
}

// ── is_cache_fresh (s24 Phase 1.2) ────────────────────────────

#[test]
fn is_cache_fresh_recent_entry_is_fresh() {
    let now = OffsetDateTime::now_utc();
    let just_now = now - time::Duration::seconds(30);
    assert!(is_cache_fresh(just_now, now, Duration::from_secs(3600)));
}

#[test]
fn is_cache_fresh_old_entry_is_stale() {
    let now = OffsetDateTime::now_utc();
    let two_hours_ago = now - time::Duration::hours(2);
    assert!(!is_cache_fresh(
        two_hours_ago,
        now,
        Duration::from_secs(3600)
    ));
}

#[test]
fn is_cache_fresh_at_exact_interval_is_stale() {
    // Boundary: age == interval → stale, so a refresh fires
    // exactly at the interval mark instead of one cycle later.
    let now = OffsetDateTime::now_utc();
    let one_hour_ago = now - time::Duration::hours(1);
    assert!(!is_cache_fresh(
        one_hour_ago,
        now,
        Duration::from_secs(3600)
    ));
}

/// `mem2608-t0`, the unit half. A tick one full interval after the
/// cycle that stamped the body must find it stale — including when
/// the stamp is a hair short of a full interval old, which is the only
/// case production ever produces.
///
/// `is_cache_fresh_at_exact_interval_is_stale` above pins `age ==
/// interval`, an instant the daemon cannot reach: the anchor is read
/// after the tick fires, so the age is always `interval − δ`. That
/// test was green for the whole time the defect was live.
#[test]
fn is_cache_fresh_a_hair_under_the_interval_is_stale() {
    let now = OffsetDateTime::now_utc();
    let interval = Duration::from_secs(43_200);
    for short_by_ms in [1i64, 900, 2_000, 4_999] {
        let fetched_at =
            now - time::Duration::seconds(43_200) + time::Duration::milliseconds(short_by_ms);
        assert!(
            !is_cache_fresh(fetched_at, now, interval),
            "a body {short_by_ms} ms short of a full interval read as fresh — this is the \
             tick that can never fetch"
        );
    }
}

/// The margin shortens a cycle; it must not collapse one. At the
/// tightest interval the config accepts, a body from the middle of the
/// previous cycle is still fresh.
#[test]
fn is_cache_fresh_margin_does_not_swallow_the_minimum_interval() {
    let now = OffsetDateTime::now_utc();
    let half_a_minimum = now - time::Duration::seconds(30);
    assert!(is_cache_fresh(half_a_minimum, now, MIN_REFRESH_INTERVAL));
}

/// A margin at or above the interval must not invert the predicate
/// into "always fresh" — saturating, not wrapping.
#[test]
fn is_cache_fresh_degenerate_interval_never_reads_fresh() {
    let now = OffsetDateTime::now_utc();
    let a_moment_ago = now - time::Duration::milliseconds(1);
    assert!(!is_cache_fresh(
        a_moment_ago,
        now,
        CACHE_FRESHNESS_MARGIN / 2
    ));
}

#[test]
fn is_cache_fresh_future_timestamp_is_stale() {
    // Clock skew or corrupt meta file: fetched_at in the future
    // must NOT freeze updates. Treat as stale to force a fetch.
    let now = OffsetDateTime::now_utc();
    let in_an_hour = now + time::Duration::hours(1);
    assert!(!is_cache_fresh(in_an_hour, now, Duration::from_secs(3600)));
}

// ── atomic_write (s24 Phase 1.2) ──────────────────────────────

#[test]
fn atomic_write_writes_through_tmp_file() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("data.cache");
    atomic_write(&target, b"hello").unwrap();
    assert_eq!(std::fs::read_to_string(&target).unwrap(), "hello");
    // Tmp file should be gone after a successful rename.
    assert!(!dir.path().join("data.cache.tmp").exists());
}

#[test]
fn atomic_write_overwrites_existing_target() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("data.cache");
    std::fs::write(&target, "old").unwrap();
    atomic_write(&target, b"new").unwrap();
    assert_eq!(std::fs::read_to_string(&target).unwrap(), "new");
}

#[test]
fn meta_file_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let source = "privacy/ads";
    let stamp = OffsetDateTime::now_utc();
    write_cache_to_disk(
        dir.path(),
        source,
        "https://lists.purge.cc/ads.txt",
        "example.com\nads.tracker.io\n",
        Some("W/\"abc123\""),
        Some("Thu, 10 Apr 2026 12:00:00 GMT"),
        stamp,
    )
    .unwrap();
    let stem = source_to_cache_stem(source);
    let meta_path = dir.path().join(format!("{stem}.meta"));
    let parsed = load_meta_file(&meta_path);
    let cache_path = selected_body_path(dir.path(), &stem, &parsed).unwrap();
    assert!(cache_path.exists());
    assert!(meta_path.exists());
    assert_eq!(
        std::fs::read_to_string(&cache_path).unwrap(),
        "example.com\nads.tracker.io\n"
    );
    assert_eq!(
        parsed.body.as_deref(),
        cache_path.file_name().and_then(|name| name.to_str())
    );
    assert_eq!(parsed.sha256.as_deref().map(str::len), Some(64));
    assert_eq!(parsed.etag.as_deref(), Some("W/\"abc123\""));
    assert_eq!(
        parsed.last_modified.as_deref(),
        Some("Thu, 10 Apr 2026 12:00:00 GMT")
    );
    // RFC 3339 round-trip preserves second-precision; the time
    // crate's default OffsetDateTime is nanosecond, so we compare
    // via re-formatting both sides through RFC 3339 to drop
    // sub-second noise that the on-disk format does not carry
    // (the formatter does, but parser keeps it). Asserting the
    // re-parsed value equals the formatted-then-parsed version is
    // the cleanest round-trip pin.
    let parsed_ts = parsed
        .fetched_at
        .expect("fetched_at must be present after a Phase-1.1 write");
    let stamp_str = stamp.format(&Rfc3339).unwrap();
    let stamp_round = OffsetDateTime::parse(&stamp_str, &Rfc3339).unwrap();
    assert_eq!(parsed_ts, stamp_round);
}

#[test]
fn meta_file_missing_returns_empty() {
    let parsed = load_meta_file(Path::new("/nonexistent/path.meta"));
    assert!(parsed.etag.is_none());
    assert!(parsed.last_modified.is_none());
    assert!(parsed.fetched_at.is_none());
}

#[test]
fn meta_file_empty_values() {
    let dir = tempfile::tempdir().unwrap();
    let meta_path = dir.path().join("test.meta");
    std::fs::write(&meta_path, "etag=\nlast-modified=\nfetched-at=\n").unwrap();

    let parsed = load_meta_file(&meta_path);
    assert!(parsed.etag.is_none(), "empty etag should be None");
    assert!(
        parsed.last_modified.is_none(),
        "empty last-modified should be None"
    );
    assert!(
        parsed.fetched_at.is_none(),
        "empty fetched-at should be None"
    );
}

#[test]
fn build_meta_content_strips_control_chars_from_header_values() {
    // rev-2606 §06 manager-04a: a newline smuggled into an ETag must
    // not forge an extra .meta line. The line-oriented parser must see
    // exactly four logical fields, none of them an injected size= /
    // fetched-at=.
    let now = OffsetDateTime::now_utc();
    let hostile_etag = "\"abc\"\nsize=999999999\nfetched-at=2000-01-01T00:00:00Z";
    let content = build_meta_content(
        Some(hostile_etag),
        Some("Mon,\r\n01 Jan 2024"),
        "https://lists.example.test/list.txt",
        now,
        Some(42),
        None,
    );
    // Round-trip through the real parser: the forged values must NOT
    // take effect.
    let dir = tempfile::tempdir().unwrap();
    let meta_path = dir.path().join("hostile.meta");
    std::fs::write(&meta_path, &content).unwrap();
    let parsed = load_meta_file(&meta_path);
    assert_eq!(
        parsed.size,
        Some(42),
        "the real size= line must win, not the injected one"
    );
    assert_eq!(
        parsed.etag.as_deref(),
        Some("\"abc\"size=999999999fetched-at=2000-01-01T00:00:00Z"),
        "control chars stripped, value flattened onto one line"
    );
    // The legitimate fetched-at must parse (the forged one was inert).
    assert!(parsed.fetched_at.is_some());
    // No raw control byte survived into the file.
    assert!(!content.bytes().any(|b| b == b'\r'));
}

#[test]
fn meta_file_legacy_format_has_no_fetched_at() {
    // Pre-Sprint-24 .meta files only have etag + last-modified lines.
    // load_meta_file must parse them without losing the existing
    // fields and return fetched_at = None so the load_disk_cache
    // path can fall back to now_utc() instead of crashing.
    let dir = tempfile::tempdir().unwrap();
    let meta_path = dir.path().join("legacy.meta");
    std::fs::write(
        &meta_path,
        "etag=\"old\"\nlast-modified=Thu, 01 Jan 1970 00:00:00 GMT\n",
    )
    .unwrap();

    let parsed = load_meta_file(&meta_path);
    assert_eq!(parsed.etag.as_deref(), Some("\"old\""));
    assert_eq!(
        parsed.last_modified.as_deref(),
        Some("Thu, 01 Jan 1970 00:00:00 GMT")
    );
    assert!(
        parsed.fetched_at.is_none(),
        "legacy meta has no fetched-at line"
    );
}

#[test]
fn legacy_meta_is_usable_only_for_a_raw_url_representative() {
    let dir = tempfile::tempdir().unwrap();
    let meta_path = dir.path().join("legacy.meta");
    std::fs::write(&meta_path, "etag=\"old\"\n").unwrap();
    let parsed = load_meta_file(&meta_path);

    assert!(cache_identity_matches(
        "https://example.test/ads.txt",
        "https://example.test/ads.txt",
        &parsed
    ));
    assert!(!cache_identity_matches(
        "privacy/ads",
        "https://example.test/ads.txt",
        &parsed
    ));
}

#[test]
fn meta_file_invalid_fetched_at_is_ignored() {
    // Garbage in the fetched-at field must not crash parsing —
    // load_meta_file logs a warning and returns None for that
    // field, leaving the other fields intact.
    let dir = tempfile::tempdir().unwrap();
    let meta_path = dir.path().join("bad.meta");
    std::fs::write(
        &meta_path,
        "etag=\"x\"\nlast-modified=\nfetched-at=not-a-timestamp\n",
    )
    .unwrap();

    let parsed = load_meta_file(&meta_path);
    assert_eq!(parsed.etag.as_deref(), Some("\"x\""));
    assert!(parsed.fetched_at.is_none());
}

#[test]
fn load_disk_cache_loads_headers_only() {
    let dir = tempfile::tempdir().unwrap();
    let source = "privacy/ads";

    // Write a cached list to disk
    write_cache_to_disk(
        dir.path(),
        source,
        "https://lists.purge.cc/ads.txt",
        "cached.example.com\n",
        Some("\"etag1\""),
        None,
        OffsetDateTime::now_utc(),
    )
    .unwrap();

    let client = reqwest::Client::new();
    let filter = Arc::new(FilterEngine::new());
    let catalog = Catalog::fallback();
    let source_bits = build_source_bit_map(&[source.to_string()]).expect("at-cap accept");

    let mut mgr = ListManager::new(
        client,
        filter,
        vec![source.to_string()],
        catalog,
        Duration::from_secs(3600),
        source_bits,
        TEST_CAP,
        DEFAULT_MAX_LIST_ENTRIES,
        Some(dir.path().to_path_buf()),
    );

    assert!(mgr.cache.is_empty(), "cache should start empty");
    mgr.load_disk_cache();

    // Headers loaded, body deferred to refresh() for on-demand disk read
    let url = "https://lists.purge.cc/ads.txt";
    let entry = mgr.cache.get(url).expect("cache entry should exist");
    assert!(
        entry.body.is_none(),
        "body should NOT be loaded into memory"
    );
    assert_eq!(entry.etag.as_deref(), Some("\"etag1\""));
    assert!(entry.last_modified.is_none());

    // Body is still readable from disk via resolve_body
    let body = mgr.read_body_from_disk(source);
    assert_eq!(body.as_deref(), Some("cached.example.com\n"));

    // Phase 1.1: fetched_at must be populated to a real value, not
    // the UNIX_EPOCH sentinel a derive(Default) would have left.
    // The Phase 1.2 freshness check reads this field, so it has
    // to be load-bearing on round-trip.
    let entry = mgr.cache.get("https://lists.purge.cc/ads.txt").unwrap();
    assert!(
        entry.fetched_at > OffsetDateTime::UNIX_EPOCH,
        "fetched_at must be a real timestamp after round-trip"
    );
}

#[test]
fn load_disk_cache_legacy_raw_url_meta_falls_back_to_now() {
    // A pre-Sprint-24 .meta file (no fetched-at line) should NOT
    // crash load_disk_cache. The cache entry should get a fresh
    // now_utc() stamp so the freshness check (Phase 1.2) treats
    // the legacy cache as just-stamped, avoiding a startup HTTP
    // burst on the first run after a binary upgrade.
    let dir = tempfile::tempdir().unwrap();
    let source = "https://lists.purge.cc/ads.txt";

    // Manually write a legacy-format cache pair (no fetched-at line).
    let stem = source_to_cache_stem(source);
    std::fs::write(
        dir.path().join(format!("{stem}.cache")),
        "legacy.example.com\n",
    )
    .unwrap();
    std::fs::write(
        dir.path().join(format!("{stem}.meta")),
        "etag=\"old\"\nlast-modified=\n",
    )
    .unwrap();

    let before = OffsetDateTime::now_utc();
    let client = reqwest::Client::new();
    let filter = Arc::new(FilterEngine::new());
    let catalog = Catalog::fallback();
    let source_bits = build_source_bit_map(&[source.to_string()]).expect("at-cap accept");

    let mut mgr = ListManager::new(
        client,
        filter,
        vec![source.to_string()],
        catalog,
        Duration::from_secs(3600),
        source_bits,
        TEST_CAP,
        DEFAULT_MAX_LIST_ENTRIES,
        Some(dir.path().to_path_buf()),
    );
    mgr.load_disk_cache();

    let entry = mgr
        .cache
        .get(source)
        .expect("legacy cache should still load");
    assert_eq!(entry.etag.as_deref(), Some("\"old\""));
    assert!(
        entry.fetched_at >= before,
        "legacy cache should get a fresh now_utc() stamp on load"
    );
}

#[tokio::test]
async fn refresh_skips_http_when_cache_is_fresh() {
    // The crash-loop fix in action. The configured URL is a
    // loopback literal that download_list() validates and
    // rejects (see download_list_rejects_loopback_literal). If
    // the freshness check correctly skips download_list, the
    // body is read straight from the on-disk .cache file and
    // parsed into the filter engine. If the freshness check
    // does NOT fire, download_list runs first, the URL is
    // rejected, and the filter engine ends up empty — the
    // assertion catches that regression.
    let dir = tempfile::tempdir().unwrap();
    let url = "https://127.0.0.1/blocklist.txt".to_string();

    // Write a body for the source so resolve_body() can read it
    // from disk during the freshness skip path.
    let stem = source_to_cache_stem(&url);
    std::fs::write(
        dir.path().join(format!("{stem}.cache")),
        "skipfresh.example.com\n",
    )
    .unwrap();
    // Also write a meta file so load_disk_cache populates the
    // in-memory entry with a real fetched_at — load_disk_cache
    // requires the .cache file to exist before reading meta.
    let now = OffsetDateTime::now_utc();
    let now_rfc3339 = now.format(&Rfc3339).unwrap();
    std::fs::write(
        dir.path().join(format!("{stem}.meta")),
        format!("etag=\nlast-modified=\nfetched-at={now_rfc3339}\n"),
    )
    .unwrap();

    let client = reqwest::Client::new();
    let filter = Arc::new(FilterEngine::new());
    let catalog = Catalog::fallback();
    let source_bits = build_source_bit_map(std::slice::from_ref(&url)).expect("at-cap accept");

    let mut mgr = ListManager::new(
        client,
        filter.clone(),
        vec![url.clone()],
        catalog,
        Duration::from_secs(3600),
        source_bits,
        TEST_CAP,
        DEFAULT_MAX_LIST_ENTRIES,
        Some(dir.path().to_path_buf()),
    );
    mgr.load_disk_cache();

    // Sanity: cache has the entry and fetched_at is recent.
    let entry_before = mgr.cache.get(&url).expect("entry should be loaded");
    assert!(entry_before.fetched_at >= now - time::Duration::seconds(2));
    let fetched_at_before = entry_before.fetched_at;

    let count = mgr.refresh().await;

    // Freshness skip path read the body from disk and parsed it,
    // so the filter engine ends up with the one domain. If the
    // skip had failed, download_list would have rejected the
    // loopback URL and count would be 0.
    assert_eq!(count, 1);
    assert!(filter.is_blocked("skipfresh.example.com"));

    // The entry's fetched_at should be unchanged because no
    // download (200 or 304) actually happened.
    let entry_after = mgr.cache.get(&url).unwrap();
    assert_eq!(entry_after.fetched_at, fetched_at_before);
}

/// CacheOnly must serve a 30-day-old cache without touching the
/// network.
///
/// The URL is a loopback literal that `download_list` REFUSES
/// (`download_list_rejects_loopback_literal`), but **`count` cannot
/// be the discriminator here**: the manager's pre-existing
/// crash-loop-resilience behaviour re-parses the retained on-disk
/// cache whenever `download_list` fails (see the `Err(e)` arm in
/// `refresh_with_mode`, and the module doc comment — "On 304 Not
/// Modified or download failure, the manager re-uses the previously
/// cached response body"). Since this fixture's `.cache` file is
/// exactly what both CacheOnly's skip path AND that HTTP-failure
/// fallback would parse, `count == 1` either way. Verified
/// empirically: hardcoding `mode = RefreshMode::Scheduled` at the top
/// of `refresh_with_mode` still passes a `count`/`is_blocked`-only
/// version of this test.
///
/// The real discriminator is the status registry — but not "does
/// `last_outcome` read `Ok`". A CacheOnly cache-hit is not a
/// verified-fresh refresh (the body may be this old on purpose,
/// §2.3), so per `boot_list_persistence.md` §2.8 it must not be
/// *recorded* as one: the registry is left exactly as it was
/// pre-seeded (`NeverFetched`, `last_refresh_at: None`), not stamped
/// `Ok` with `last_refresh_at = now`. A genuine HTTP attempt, by
/// contrast, always moves the registry off that default — `Ok` via
/// `update_list_status_ok` on success, `Failed` via `from_failure` on
/// the sibling test below (`refresh_records_failure_in_status`). See
/// `cache_only_leaves_prior_status_untouched` for the sharper pin:
/// a *non-default* prior status also survives this cycle byte for
/// byte, which a bug that merely swapped `Ok` for some other stamp
/// could otherwise slip past a `NeverFetched`-only check.
///
/// The cache is deliberately far outside `refresh_interval`, which
/// is the whole point — this pins `boot_list_persistence.md` §2.3
/// (age is never a reason to refuse) against a future re-introduction
/// of an age gate.
#[tokio::test]
async fn cache_only_refresh_serves_a_stale_cache_without_http() {
    use crate::lists::status::LastOutcome;

    let dir = tempfile::tempdir().unwrap();
    let url = "https://127.0.0.1/blocklist.txt".to_string();
    let stem = source_to_cache_stem(&url);
    std::fs::write(
        dir.path().join(format!("{stem}.cache")),
        "stale.example.com\n",
    )
    .unwrap();
    let old = OffsetDateTime::now_utc() - time::Duration::days(30);
    std::fs::write(
        dir.path().join(format!("{stem}.meta")),
        format!(
            "etag=\nlast-modified=\nfetched-at={}\n",
            old.format(&Rfc3339).unwrap()
        ),
    )
    .unwrap();

    let filter = Arc::new(FilterEngine::new());
    let source_bits = build_source_bit_map(std::slice::from_ref(&url)).expect("at-cap accept");
    let mut mgr = ListManager::new(
        reqwest::Client::new(),
        filter.clone(),
        vec![url.clone()],
        Catalog::fallback(),
        Duration::from_secs(3600),
        source_bits,
        TEST_CAP,
        DEFAULT_MAX_LIST_ENTRIES,
        Some(dir.path().to_path_buf()),
    );
    mgr.load_disk_cache();
    let reg = mgr.status_registry();

    let count = mgr.refresh_with_mode(RefreshMode::CacheOnly).await;

    assert_eq!(
        count, 1,
        "CacheOnly must load a 30-day-old cache — age is not a gate"
    );
    assert!(filter.is_blocked("stale.example.com"));
    let status = reg.status_for_url(&url).unwrap();
    assert!(
        matches!(status.last_outcome, LastOutcome::NeverFetched),
        "CacheOnly must not claim a verified-fresh refresh for a \
         cache that may be months old (§2.8) — the registry must \
         stay at its pre-seeded default, not be stamped Ok: got {:?}",
        status.last_outcome
    );
    assert!(
        status.last_refresh_at.is_none(),
        "CacheOnly must not stamp last_refresh_at — that is the \
         field the TUI stale badge reads, and stamping it `now` for \
         a 30-day-old body is the exact lie §2.8 prohibits"
    );
    assert_eq!(
        status.entries, 1,
        "the installed cache body must report its served contribution"
    );
}

/// Sharper than the test above: seeds a **non-default** prior status
/// (as if a real refresh had already run earlier in this process's
/// lifetime) and asserts CacheOnly changes only its served contribution.
#[tokio::test]
async fn cache_only_leaves_prior_status_untouched() {
    use crate::lists::status::LastOutcome;

    let dir = tempfile::tempdir().unwrap();
    let url = "https://127.0.0.1/blocklist.txt".to_string();
    let stem = source_to_cache_stem(&url);
    std::fs::write(
        dir.path().join(format!("{stem}.cache")),
        "stale.example.com\n",
    )
    .unwrap();
    let old = OffsetDateTime::now_utc() - time::Duration::days(30);
    std::fs::write(
        dir.path().join(format!("{stem}.meta")),
        format!(
            "etag=\nlast-modified=\nfetched-at={}\n",
            old.format(&Rfc3339).unwrap()
        ),
    )
    .unwrap();

    let filter = Arc::new(FilterEngine::new());
    let source_bits = build_source_bit_map(std::slice::from_ref(&url)).expect("at-cap accept");
    let mut mgr = ListManager::new(
        reqwest::Client::new(),
        filter.clone(),
        vec![url.clone()],
        Catalog::fallback(),
        Duration::from_secs(3600),
        source_bits,
        TEST_CAP,
        DEFAULT_MAX_LIST_ENTRIES,
        Some(dir.path().to_path_buf()),
    );
    mgr.load_disk_cache();
    let reg = mgr.status_registry();

    // Seed a known, non-default prior status — as if this process had
    // already recorded a real refresh outcome earlier in its
    // lifetime — so "unchanged" is a meaningful claim rather than a
    // restatement of the freshly-constructed default.
    let seeded_last_refresh = OffsetDateTime::now_utc() - time::Duration::hours(9);
    let prior = ListStatus {
        entries: 42,
        parsed_ok: 17,
        unique_domains: 4,
        parsed_skipped: 3,
        parsed_skipped_samples: vec!["bad row".to_string()],
        parsed_truncated: 2,
        last_outcome: LastOutcome::Failed {
            reason: "prior network attempt failed".to_string(),
        },
        fetched_at: Some(seeded_last_refresh),
        last_refresh_at: Some(seeded_last_refresh),
        delta_pct_vs_prev: Some(12.5),
        prev_entries: Some(37),
    };
    reg.update_for_url(&url, prior.clone());

    mgr.refresh_with_mode(RefreshMode::CacheOnly).await;

    // The list still contributes its domains to the map ...
    assert!(filter.is_blocked("stale.example.com"));
    // ... while its health/freshness reporting stays exactly as it was.
    let status = reg.status_for_url(&url).unwrap();
    let mut expected = prior;
    expected.entries = 1;
    assert_eq!(
        *status, expected,
        "CacheOnly may reconcile served entries but must not claim health"
    );
}

/// The discriminating half. Identical fixture, `Network` mode: the
/// cache is stale, so the freshness shortcut does NOT fire and
/// `download_list` genuinely runs.
///
/// It refuses the loopback literal — but the manager's pre-existing
/// (and correct) crash-loop-resilience behaviour then falls back to
/// the retained on-disk cache in the `Err(e)` arm, so `count` comes
/// out to 1, identical to the CacheOnly test above. That fallback is
/// intentional (it is what lets a source keep blocking through a
/// transient failure) and this test must not weaken it to force a 0.
/// `count` therefore cannot be the discriminator; the fact that HTTP
/// was attempted and refused shows up only in the status registry,
/// which the failed download attempt stamps `Failed` regardless of
/// whether the fallback parse succeeds (see
/// `refresh_records_failure_in_status`, same `Err(e)` arm, same
/// `ListStatus::from_failure` call, unconditional).
///
/// Without the `last_outcome` assertion, this test (and the one
/// above) both pass on a `refresh_with_mode` that ignores `mode`
/// entirely — confirmed by temporarily hardcoding
/// `RefreshMode::Scheduled` at the top of `refresh_with_mode` and
/// re-running the CacheOnly test above alone.
#[tokio::test]
async fn network_refresh_with_a_stale_cache_still_reaches_http() {
    use crate::lists::status::LastOutcome;

    let dir = tempfile::tempdir().unwrap();
    let url = "https://127.0.0.1/blocklist.txt".to_string();
    let stem = source_to_cache_stem(&url);
    std::fs::write(
        dir.path().join(format!("{stem}.cache")),
        "stale.example.com\n",
    )
    .unwrap();
    let old = OffsetDateTime::now_utc() - time::Duration::days(30);
    std::fs::write(
        dir.path().join(format!("{stem}.meta")),
        format!(
            "etag=\nlast-modified=\nfetched-at={}\n",
            old.format(&Rfc3339).unwrap()
        ),
    )
    .unwrap();

    let filter = Arc::new(FilterEngine::new());
    let source_bits = build_source_bit_map(std::slice::from_ref(&url)).expect("at-cap accept");
    let mut mgr = ListManager::new(
        reqwest::Client::new(),
        filter.clone(),
        vec![url.clone()],
        Catalog::fallback(),
        Duration::from_secs(3600),
        source_bits,
        TEST_CAP,
        DEFAULT_MAX_LIST_ENTRIES,
        Some(dir.path().to_path_buf()),
    );
    mgr.load_disk_cache();
    let reg = mgr.status_registry();

    // Establish the cached body as the live corpus first. The following
    // failed Network attempt then has usable inputs identical to what is
    // already live; calling that an install would be false even though the
    // per-source attempt remains Failed.
    assert_eq!(mgr.refresh_with_mode(RefreshMode::CacheOnly).await, 1);
    let live_digest = mgr.installed_corpus_digest;
    let count = mgr.refresh_with_mode(RefreshMode::Scheduled).await;

    assert_eq!(
        count, 1,
        "Network mode falls back to the retained cache on a failed \
         download, same as CacheOnly for this fixture — the \
         discriminator is last_outcome, not count"
    );
    let status = reg.status_for_url(&url).unwrap();
    assert!(
        matches!(status.last_outcome, LastOutcome::Failed { .. }),
        "Network mode must have attempted HTTP and recorded the \
         refusal: got {:?}",
        status.last_outcome
    );
    assert_eq!(
        reg.cycle().outcome,
        Some(CycleOutcome::SkippedUnchanged),
        "a retained fallback that reproduces the live corpus is not a new install"
    );
    assert!(!reg.cycle().source_coverage_incomplete);
    assert_eq!(mgr.installed_corpus_digest, live_digest);
}

/// Closes a gap the two tests above cannot: both their fixtures have
/// a `.cache` file to fall back on, so neither one exercises the
/// branch that actually enforces zero HTTP — `refresh_with_mode`'s
/// explicit `continue` for a source with no usable disk cache
/// (`boot_list_persistence.md` §2.2 test obligation 1: "CacheOnly
/// performs zero HTTP").
///
/// With nothing on disk to fall back to, a genuine HTTP attempt is
/// distinguishable from no attempt at all: `download_list` failing
/// with no cache to swallow the failure stamps `Failed` (there is
/// nothing else the Err(e) arm's `else` branch — "download failed,
/// no cache available" — can record); CacheOnly's explicit
/// zero-HTTP exit never touches the status registry at all, leaving
/// it at its pre-seeded `NeverFetched` default.
#[tokio::test]
async fn cache_only_with_no_disk_cache_makes_zero_http_calls() {
    use crate::lists::status::LastOutcome;

    let dir = tempfile::tempdir().unwrap();
    let url = "https://127.0.0.1/blocklist.txt".to_string();
    // Deliberately no .cache / .meta written: this source has never
    // been fetched, so there is nothing to fall back to.

    let filter = Arc::new(FilterEngine::new());
    let source_bits = build_source_bit_map(std::slice::from_ref(&url)).expect("at-cap accept");
    let mut mgr = ListManager::new(
        reqwest::Client::new(),
        filter,
        vec![url.clone()],
        Catalog::fallback(),
        Duration::from_secs(3600),
        source_bits,
        TEST_CAP,
        DEFAULT_MAX_LIST_ENTRIES,
        Some(dir.path().to_path_buf()),
    );
    let reg = mgr.status_registry();

    let count = mgr.refresh_with_mode(RefreshMode::CacheOnly).await;

    assert_eq!(count, 0, "no cache on disk, nothing to serve");
    let status = reg.status_for_url(&url).unwrap();
    assert!(
        matches!(status.last_outcome, LastOutcome::NeverFetched),
        "CacheOnly must not call download_list even when there is no \
         cache to fall back on — the registry must stay at its \
         pre-seeded NeverFetched default (a Failed outcome would mean \
         HTTP was attempted, and an Ok outcome would be just as wrong): \
         got {:?}",
        status.last_outcome
    );
}

// ── ListStatusRegistry wiring (s43-t1) ──────────────────────

/// `ListManager::status_registry()` exposes a registry pre-seeded
/// with one slot per configured source, all in `NeverFetched` state.
#[test]
fn status_registry_pre_populated_for_each_source() {
    use crate::lists::status::LastOutcome;
    let client = reqwest::Client::new();
    let filter = Arc::new(FilterEngine::new());
    let catalog = Catalog::fallback();
    let sources = vec!["privacy/ads".to_string(), "security/malicious".into()];
    let bits = build_source_bit_map(&sources).expect("at-cap accept");
    let mgr = ListManager::new(
        client,
        filter,
        sources.clone(),
        catalog,
        Duration::from_secs(3600),
        bits,
        TEST_CAP,
        DEFAULT_MAX_LIST_ENTRIES,
        None,
    );
    let reg = mgr.status_registry();
    assert_eq!(reg.len(), 2);
    for src in &sources {
        let s = reg.status_for_url(src).unwrap();
        assert_eq!(s.entries, 0);
        assert_eq!(s.last_outcome, LastOutcome::NeverFetched);
    }
}

/// After a refresh that pulls a real list (privacy/ads from the
/// purge.cc test endpoint), the registry slot for that source
/// transitions to `Ok` with non-zero entries and a populated
/// `fetched_at`. This is the end-to-end T1 acceptance: refresh
/// updates entries + fetched_at atomically.
/// Hits the real `privacy/ads` source (`https://lists.purge.cc/ads.txt`)
/// — needs egress. Excluded from the default `cargo test` leg per
/// `tests-depend-on-live-cdn-gate-hostage` (P2): a CDN fault must never
/// fail this repo's own merge gate. Run explicitly, with egress, via:
/// `cargo test --lib -- --ignored lists::manager::tests::refresh_populates_list_status_for_real_source`
#[tokio::test]
#[ignore = "hits real https://lists.purge.cc — run with `cargo test -- --ignored`"]
async fn refresh_populates_list_status_for_real_source() {
    use crate::lists::status::LastOutcome;
    let client = reqwest::Client::builder()
        .user_agent("purge-warden/test")
        .timeout(Duration::from_secs(15))
        .build()
        .unwrap();
    let filter = Arc::new(FilterEngine::new());
    let catalog = Catalog::fallback();
    let source = "privacy/ads".to_string();
    let bits = build_source_bit_map(std::slice::from_ref(&source)).expect("at-cap accept");
    let mut mgr = ListManager::new(
        client,
        filter,
        vec![source.clone()],
        catalog,
        Duration::from_secs(3600),
        bits,
        TEST_CAP,
        DEFAULT_MAX_LIST_ENTRIES,
        None,
    );
    let reg = mgr.status_registry();
    let count = mgr.refresh().await;
    let status = reg.status_for_url(&source).unwrap();
    assert_eq!(status.entries as usize, count);
    assert!(status.entries > 0, "real upstream must contribute domains");
    assert_eq!(status.last_outcome, LastOutcome::Ok);
    assert!(status.fetched_at.is_some());
    // First refresh — no prior data to compute delta against.
    assert!(status.delta_pct_vs_prev.is_none());
}

/// Persistence round-trip: refresh once, drop the manager,
/// reconstruct, set persistence path → registry pre-seeded with
/// `prev_entries` from the prior cycle.
/// Hits the real `privacy/ads` source twice (fresh refresh + reload) —
/// needs egress. Excluded from the default `cargo test` leg per
/// `tests-depend-on-live-cdn-gate-hostage` (P2). Run explicitly, with
/// egress, via:
/// `cargo test --lib -- --ignored lists::manager::tests::list_stats_persistence_round_trip`
#[tokio::test]
#[ignore = "hits real https://lists.purge.cc — run with `cargo test -- --ignored`"]
async fn list_stats_persistence_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let stats_path = dir.path().join("list_stats.json");

    // First lifecycle: refresh, persist.
    {
        let client = reqwest::Client::builder()
            .user_agent("purge-warden/test")
            .timeout(Duration::from_secs(15))
            .build()
            .unwrap();
        let filter = Arc::new(FilterEngine::new());
        let catalog = Catalog::fallback();
        let source = "privacy/ads".to_string();
        let bits = build_source_bit_map(std::slice::from_ref(&source)).expect("at-cap accept");
        let mut mgr = ListManager::new(
            client,
            filter,
            vec![source.clone()],
            catalog,
            Duration::from_secs(3600),
            bits,
            TEST_CAP,
            DEFAULT_MAX_LIST_ENTRIES,
            None,
        );
        mgr.set_status_persistence_path(stats_path.clone());
        let count = mgr.refresh().await;
        assert!(count > 0);
        assert!(stats_path.exists(), "refresh must persist list_stats.json");
    }

    // Second lifecycle: fresh manager, set persistence path,
    // registry must be pre-seeded with prev_entries for the source.
    {
        let client = reqwest::Client::new();
        let filter = Arc::new(FilterEngine::new());
        let catalog = Catalog::fallback();
        let source = "privacy/ads".to_string();
        let bits = build_source_bit_map(std::slice::from_ref(&source)).expect("at-cap accept");
        let mut mgr = ListManager::new(
            client,
            filter,
            vec![source.clone()],
            catalog,
            Duration::from_secs(3600),
            bits,
            TEST_CAP,
            DEFAULT_MAX_LIST_ENTRIES,
            None,
        );
        mgr.set_status_persistence_path(stats_path.clone());
        let reg = mgr.status_registry();
        let seeded = reg.status_for_url(&source).unwrap();
        // No refresh yet, so entries=0 + NeverFetched, but
        // prev_entries was loaded from disk.
        assert!(
            seeded.prev_entries.is_some(),
            "second-lifecycle manager must pre-load prev_entries from disk"
        );
        assert!(seeded.prev_entries.unwrap() > 0);
    }
}

/// A failed download with no cached body still updates the registry
/// — last_outcome flips to Failed and fetched_at is bumped.
#[tokio::test]
async fn refresh_records_failure_in_status() {
    use crate::lists::status::LastOutcome;
    let catalog = Catalog::fallback();
    let filter = Arc::new(FilterEngine::new());
    // Loopback URL is rejected at validate_list_url before any
    // HTTP — same regression hook used by other tests in this file.
    let url = "https://127.0.0.1/blocklist.txt".to_string();
    let bits = build_source_bit_map(std::slice::from_ref(&url)).expect("at-cap accept");
    let mut mgr = ListManager::new(
        reqwest::Client::new(),
        filter,
        vec![url.clone()],
        catalog,
        Duration::from_secs(3600),
        bits,
        TEST_CAP,
        DEFAULT_MAX_LIST_ENTRIES,
        None,
    );
    let reg = mgr.status_registry();
    mgr.refresh().await;
    let status = reg.status_for_url(&url).unwrap();
    assert!(matches!(status.last_outcome, LastOutcome::Failed { .. }));
    assert!(status.fetched_at.is_some());
    // First-ever attempt with no prior data → entries stays 0.
    assert_eq!(status.entries, 0);
}

/// A failed download must NOT stamp `fetched_at`.
///
/// The tempting "optimisation" is to stamp it anyway so the
/// freshness check skips the HTTP next time. It suppresses
/// legitimate retries and poisons freshness: a list dead for six
/// months would read as fresh at every boot. The fix for a slow boot
/// is that boot does not consult the network, not that failures are
/// recorded dishonestly. See `boot_list_persistence.md` §2.8.
///
/// `before == after` alone is reachable two ways: a download was
/// attempted and correctly did not stamp on failure (what this pins),
/// or no download was ever attempted (the freshness gate took the
/// cache-hit path and `download_list` was never reached — `fetched_at`
/// is just as untouched then, for a reason this test does not care
/// about). The fixture defeats the second cause on its own — the cache
/// is 30 days old against a 1 h `refresh_interval`, so
/// `is_cache_fresh` is false and `Network` mode cannot take the
/// cache-hit path — but "the fixture happens to defeat it" is not the
/// same as "the test asserts it". The registry check below is that
/// assertion: `last_outcome` only leaves its `NeverFetched` default on
/// a genuine attempt (`update_list_status_ok` on success,
/// `ListStatus::from_failure` here), so `Failed` proves `download_list`
/// was actually entered — every `from_failure` site sits inside its
/// match. (Two of the three follow a download that succeeded and was
/// then refused downstream — a parse refusal or a shrink-guard trip;
/// neither is reachable from this fixture's loopback URL, which only
/// reaches the download-`Err` site.) That is enough to close the gap
/// a mutated freshness gate would otherwise slip through underneath
/// the `fetched_at` assertion alone.
#[tokio::test]
async fn a_failed_download_does_not_stamp_fetched_at() {
    use crate::lists::status::LastOutcome;

    let dir = tempfile::tempdir().unwrap();
    // Loopback literal: `download_list` refuses it, which is a
    // failure without needing a server that hangs.
    let url = "https://127.0.0.1/blocklist.txt".to_string();
    let stem = source_to_cache_stem(&url);
    std::fs::write(
        dir.path().join(format!("{stem}.cache")),
        "kept.example.com\n",
    )
    .unwrap();
    let old = OffsetDateTime::now_utc() - time::Duration::days(30);
    std::fs::write(
        dir.path().join(format!("{stem}.meta")),
        format!(
            "etag=\nlast-modified=\nfetched-at={}\n",
            old.format(&Rfc3339).unwrap()
        ),
    )
    .unwrap();

    let filter = Arc::new(FilterEngine::new());
    let source_bits = build_source_bit_map(std::slice::from_ref(&url)).expect("at-cap accept");
    let mut mgr = ListManager::new(
        reqwest::Client::new(),
        filter.clone(),
        vec![url.clone()],
        Catalog::fallback(),
        Duration::from_secs(3600),
        source_bits,
        TEST_CAP,
        DEFAULT_MAX_LIST_ENTRIES,
        Some(dir.path().to_path_buf()),
    );
    mgr.load_disk_cache();
    let blocklist_id = crate::config::schema::Id::new("remote-retained").unwrap();
    mgr.set_list_state(crate::config::list_state::ListState::default(), None);
    mgr.set_source_blocklist_map(HashMap::from([(url.clone(), (blocklist_id.clone(), 1))]));
    let before = mgr.cache.get(&url).expect("entry loaded").fetched_at;
    let reg = mgr.status_registry();

    mgr.refresh_with_mode(RefreshMode::Scheduled).await;

    // Proves `download_list` was actually reached and actually
    // failed — without this, a mutated freshness gate that always
    // takes the cache-hit path would leave `fetched_at` untouched
    // for an unrelated reason and this test would still pass.
    assert!(
        matches!(
            reg.status_for_url(&url)
                .expect("status seeded")
                .last_outcome,
            LastOutcome::Failed { .. }
        ),
        "fixture must actually reach download_list and fail; a \
         cache-hit skip would leave fetched_at unchanged for the \
         wrong reason"
    );

    let after = mgr.cache.get(&url).expect("entry still present").fetched_at;
    assert_eq!(
        before, after,
        "a failed download must leave fetched_at alone — stamping it \
         would make a permanently-dead list read as fresh forever"
    );
    assert!(
        filter.is_blocked("kept.example.com"),
        "the generic remote failure must retain only a cache body that parsed successfully"
    );
    let state = mgr.list_state_handle().lock().unwrap().clone();
    let entry = state.lists.get(&blocklist_id).unwrap();
    let expected_cache_path = dir.path().join(format!("{stem}.cache"));
    assert_eq!(entry.status, crate::config::list_state::ListStatus::Failed);
    assert_eq!(entry.consecutive_failures, 1);
    assert_eq!(
        entry.cache_path.as_deref(),
        Some(expected_cache_path.as_path())
    );
}

// ── Sprint C T2 (lists_categories_v2 §14.2.b) ─────────────────────
// Refresh-loop wire-in for `record_blocklist_*`. Pre-Sprint-C the
// refresh loop kept its source-string keys but never drove the
// canonical-id state machine, leaving `consecutive_failures` and
// `status` permanently at their defaults. These three pins cover
// the failure path (single increment), the threshold transition
// to Failed, and the cache-fresh success path that recovers a
// prior Failed back to Active per D9.

fn lc2_t2_setup(
    url: &str,
    max_consec: u32,
) -> (
    ListManager,
    crate::config::schema::Id,
    std::path::PathBuf,
    tempfile::TempDir,
) {
    let dir = tempfile::tempdir().unwrap();
    let bits = build_source_bit_map(std::slice::from_ref(&url.to_string())).expect("at-cap accept");
    let mut mgr = ListManager::new(
        reqwest::Client::new(),
        Arc::new(FilterEngine::new()),
        vec![url.to_string()],
        Catalog::fallback(),
        Duration::from_secs(3600),
        bits,
        TEST_CAP,
        DEFAULT_MAX_LIST_ENTRIES,
        Some(dir.path().to_path_buf()),
    );
    let state_path = dir.path().join("list_state.toml");
    mgr.set_list_state(
        crate::config::list_state::ListState::default(),
        Some(state_path.clone()),
    );
    let blocklist_id = crate::config::schema::Id::new("test-blocklist").unwrap();
    let mut map = HashMap::new();
    map.insert(url.to_string(), (blocklist_id.clone(), max_consec));
    mgr.set_source_blocklist_map(map);
    (mgr, blocklist_id, state_path, dir)
}

/// Sprint C T2 row 1: a single failed refresh increments
/// `consecutive_failures` to 1 and stamps `last_attempt`, but
/// stays under the threshold so the status remains `Pending`
/// (default for a never-succeeded list). Persisted to disk so the
/// daemon can survive a restart without losing the counter.
#[tokio::test]
async fn refresh_failure_persists_consecutive_count() {
    let url = "https://127.0.0.1/lc2-c-t2-blocklist.txt";
    let (mut mgr, blocklist_id, state_path, _dir) = lc2_t2_setup(url, 5);
    mgr.refresh().await;
    let state = mgr
        .list_state_handle()
        .lock()
        .expect("list_state lock")
        .clone();
    let entry = state
        .lists
        .get(&blocklist_id)
        .expect("state machine must have an entry after refresh");
    assert_eq!(entry.consecutive_failures, 1);
    assert!(entry.last_attempt.is_some());
    assert_eq!(
        entry.status,
        crate::config::list_state::ListStatus::Pending,
        "1 of 5 failures must NOT flip to Failed yet",
    );
    // Persisted to disk per write_atomic.
    assert!(state_path.exists(), "list_state.toml must be persisted");
}

/// Sprint C T2 row 2: at the per-list `max_consecutive_failures`
/// threshold, the Nth failure flips the status to `Failed` (D8).
/// Pin the boundary so a future regression that off-by-ones the
/// counter or fails to flip surfaces here.
#[tokio::test]
async fn refresh_failure_max_consecutive_flips_to_failed() {
    let url = "https://127.0.0.1/lc2-c-t2-flip.txt";
    let (mut mgr, blocklist_id, _state_path, _dir) = lc2_t2_setup(url, 3);
    // Three consecutive failures = threshold reached.
    mgr.refresh().await;
    mgr.refresh().await;
    mgr.refresh().await;
    let state = mgr
        .list_state_handle()
        .lock()
        .expect("list_state lock")
        .clone();
    let entry = state.lists.get(&blocklist_id).expect("state machine entry");
    assert_eq!(entry.consecutive_failures, 3);
    assert_eq!(
        entry.status,
        crate::config::list_state::ListStatus::Failed,
        "3 of 3 failures must flip to Failed",
    );
}

/// Sprint C T2 row 3: the cache-fresh path (Phase 1.2 freshness
/// skip) is also a successful refresh from the state machine's
/// POV — the cache is healthy, the list is healthy. A list that
/// was previously `Failed` recovers to `Active` when its cache
/// outlives the failure window (D9 stale-cache fallback turned
/// recovery path).
#[tokio::test]
async fn refresh_success_persists_active_state() {
    // Reuse the cache-fresh harness — pre-seed a real disk cache
    // so the freshness skip path engages, parse_and_account runs,
    // and Sprint C T2 records the success.
    let dir = tempfile::tempdir().unwrap();
    let url = "https://127.0.0.1/lc2-c-t2-fresh.txt";

    let stem = source_to_cache_stem(url);
    std::fs::write(
        dir.path().join(format!("{stem}.cache")),
        "fresh.example.com\n",
    )
    .unwrap();
    let now = OffsetDateTime::now_utc();
    let now_rfc3339 = now.format(&Rfc3339).unwrap();
    std::fs::write(
        dir.path().join(format!("{stem}.meta")),
        format!("etag=\nlast-modified=\nfetched-at={now_rfc3339}\n"),
    )
    .unwrap();

    let bits = build_source_bit_map(std::slice::from_ref(&url.to_string())).expect("at-cap accept");
    let mut mgr = ListManager::new(
        reqwest::Client::new(),
        Arc::new(FilterEngine::new()),
        vec![url.to_string()],
        Catalog::fallback(),
        Duration::from_secs(3600),
        bits,
        TEST_CAP,
        DEFAULT_MAX_LIST_ENTRIES,
        Some(dir.path().to_path_buf()),
    );
    let state_path = dir.path().join("list_state.toml");
    // Pre-seed the state with a Failed entry so this test pins
    // the recovery-from-Failed transition explicitly.
    let mut prior = crate::config::list_state::ListState::default();
    let blocklist_id = crate::config::schema::Id::new("recovers").unwrap();
    let prior_entry = crate::config::list_state::ListStatusEntry {
        status: crate::config::list_state::ListStatus::Failed,
        last_success: None,
        last_attempt: Some(now),
        consecutive_failures: 5,
        cache_path: None,
    };
    prior.lists.insert(blocklist_id.clone(), prior_entry);
    mgr.set_list_state(prior, Some(state_path));
    let mut map = HashMap::new();
    map.insert(url.to_string(), (blocklist_id.clone(), 5));
    mgr.set_source_blocklist_map(map);

    mgr.load_disk_cache();
    mgr.refresh().await;
    let state = mgr
        .list_state_handle()
        .lock()
        .expect("list_state lock")
        .clone();
    let entry = state.lists.get(&blocklist_id).expect("state machine entry");
    assert_eq!(
        entry.status,
        crate::config::list_state::ListStatus::Active,
        "cache-fresh refresh must recover Failed → Active",
    );
    assert_eq!(entry.consecutive_failures, 0);
    assert!(entry.last_success.is_some());
    assert!(
        entry.cache_path.is_some(),
        "cache_path must be stamped so D9 stale-cache fallback works",
    );
}

/// The CacheOnly mirror of the test above: a list that was previously
/// `Failed` must NOT recover to `Active` when the only thing that
/// happened is a stale cache getting reloaded at boot.
///
/// Sprint C T2's recovery reasoning (D9: "the cache outlived the
/// failure") depends on the cache being verified fresh —
/// `Network`'s `is_cache_fresh` gate is exactly that verification,
/// and `refresh_success_persists_active_state` above pins the
/// recovery it authorises. `CacheOnly` has no such gate (§2.3: age is
/// never a reason to refuse), so recording the same "success" would
/// let an upstream that has been dead for months disarm
/// `max_consecutive_failures` forever on a box that restarts more
/// often than one refresh cycle
/// (`_docs/features/boot_list_persistence.md` §2.8).
///
/// Before this fix, `source_to_blocklist` being empty in every other
/// CacheOnly fixture meant `record_blocklist_success` was never
/// actually exercised by this cycle's cache-hit arm — this test wires
/// `set_source_blocklist_map` specifically so it is.
#[tokio::test]
async fn cache_only_stale_cache_does_not_recover_failed_list_state() {
    let dir = tempfile::tempdir().unwrap();
    let url = "https://127.0.0.1/lc2-c-t2-stale-cacheonly.txt";

    let stem = source_to_cache_stem(url);
    std::fs::write(
        dir.path().join(format!("{stem}.cache")),
        "stale-failed.example.com\n",
    )
    .unwrap();
    let old = OffsetDateTime::now_utc() - time::Duration::days(30);
    std::fs::write(
        dir.path().join(format!("{stem}.meta")),
        format!(
            "etag=\nlast-modified=\nfetched-at={}\n",
            old.format(&Rfc3339).unwrap()
        ),
    )
    .unwrap();

    let bits = build_source_bit_map(std::slice::from_ref(&url.to_string())).expect("at-cap accept");
    let filter = Arc::new(FilterEngine::new());
    let mut mgr = ListManager::new(
        reqwest::Client::new(),
        filter.clone(),
        vec![url.to_string()],
        Catalog::fallback(),
        Duration::from_secs(3600),
        bits,
        TEST_CAP,
        DEFAULT_MAX_LIST_ENTRIES,
        Some(dir.path().to_path_buf()),
    );
    let state_path = dir.path().join("list_state.toml");
    // Pre-seed a Failed entry, same shape as the Network recovery
    // test above, so this pins the opposite outcome under CacheOnly.
    let mut prior = crate::config::list_state::ListState::default();
    let blocklist_id = crate::config::schema::Id::new("stays-failed").unwrap();
    let prior_entry = crate::config::list_state::ListStatusEntry {
        status: crate::config::list_state::ListStatus::Failed,
        last_success: None,
        last_attempt: Some(old),
        consecutive_failures: 5,
        cache_path: None,
    };
    prior.lists.insert(blocklist_id.clone(), prior_entry);
    mgr.set_list_state(prior, Some(state_path));
    let mut map = HashMap::new();
    map.insert(url.to_string(), (blocklist_id.clone(), 5));
    mgr.set_source_blocklist_map(map);

    mgr.load_disk_cache();
    let count = mgr.refresh_with_mode(RefreshMode::CacheOnly).await;

    assert_eq!(count, 1, "the stale cache must still load and filter");
    assert!(filter.is_blocked("stale-failed.example.com"));

    let state = mgr
        .list_state_handle()
        .lock()
        .expect("list_state lock")
        .clone();
    let entry = state.lists.get(&blocklist_id).expect("state machine entry");
    assert_eq!(
        entry.status,
        crate::config::list_state::ListStatus::Failed,
        "a CacheOnly load of a stale cache must NOT recover Failed → \
         Active — that recovery is only earned by a verified-fresh \
         cache under Network (D9)",
    );
    assert_eq!(
        entry.consecutive_failures, 5,
        "record_blocklist_success must not run under CacheOnly"
    );
    assert!(entry.last_success.is_none());
}

/// The gate opens on a cycle that installs a generation, and stays
/// open across a later cycle that installs nothing.
///
/// Assert 2 is what still discriminates: `open()`'s call site
/// hoisted above `swap_shard`, guard left intact (the M4 mutation).
/// On this fixture's cold boot the engine is empty until the swap,
/// so the guard is false at the hoisted position, the open never
/// fires, and this assertion — which expects the gate open right
/// after a successful install — is what catches it. `ReadinessGate`
/// cannot forbid this on its own: `open()` compiles at any call
/// site, so only a test that watches *when* it runs can.
///
/// Assert 3 ("a cycle that installs nothing must not close the
/// gate") is, since the newtype, in the same position as
/// `readiness_gate_is_never_closed_by_an_empty_cycle` below — the
/// implementation it was written against no longer compiles. It
/// stays as a regression net on that axis, not because it still
/// discriminates.
#[tokio::test]
async fn readiness_gate_latches_open_across_a_failing_cycle() {
    let dir = tempfile::tempdir().unwrap();
    let url = "https://127.0.0.1/blocklist.txt".to_string();
    let stem = source_to_cache_stem(&url);
    std::fs::write(
        dir.path().join(format!("{stem}.cache")),
        "latch.example.com\n",
    )
    .unwrap();
    let now = OffsetDateTime::now_utc();
    std::fs::write(
        dir.path().join(format!("{stem}.meta")),
        format!(
            "etag=\nlast-modified=\nfetched-at={}\n",
            now.format(&Rfc3339).unwrap()
        ),
    )
    .unwrap();

    let filter = Arc::new(FilterEngine::new());
    let source_bits = build_source_bit_map(std::slice::from_ref(&url)).expect("at-cap accept");
    let mut mgr = ListManager::new(
        reqwest::Client::new(),
        filter.clone(),
        vec![url.clone()],
        Catalog::fallback(),
        Duration::from_secs(3600),
        source_bits,
        TEST_CAP,
        DEFAULT_MAX_LIST_ENTRIES,
        Some(dir.path().to_path_buf()),
    );
    let gate = ReadinessGate::new(false);
    mgr.set_filter_ready_gate(gate.clone());
    mgr.load_disk_cache();

    assert!(
        !gate.is_open(),
        "gate must start closed — nothing is installed yet"
    );

    let count = mgr.refresh_with_mode(RefreshMode::CacheOnly).await;
    assert_eq!(count, 1);
    assert!(
        gate.is_open(),
        "a cycle that installs a generation opens the gate — and opens \
         it AFTER the generation is installed: hoisting the open above \
         `swap_shard` leaves `domain_count()` at 0 on this cold-boot \
         cycle, so the gate never opens and this assertion fires"
    );

    // Now a cycle that installs nothing: delete the cache body so
    // CacheOnly finds no usable source at all.
    std::fs::remove_file(dir.path().join(format!("{stem}.cache"))).unwrap();
    mgr.refresh_with_mode(RefreshMode::CacheOnly).await;

    assert!(
        gate.is_open(),
        "a cycle that installs nothing must NOT close the gate — the \
         previous generation is still live and filtering"
    );
}

/// The latch, tested where it could actually fail — a **regression
/// net**, no longer a discriminating test, and that demotion is the
/// deliverable of Task 3b rather than a weakening.
///
/// It was written to kill `gate.store(self.filter.domain_count() > 0)`
/// — an implementation with an `else` that closes the gate. The test
/// above cannot see that one, because after the cache is removed the
/// engine still holds the domain it installed, so `domain_count() > 0`
/// stays true. Here the engine is empty when the empty cycle runs, so
/// the bad implementation stored `false` and this assertion caught it.
///
/// Since the gate became a [`ReadinessGate`] that implementation does
/// not **compile**: there is no `store`, no `close` — both pinned by
/// the type's two `compile_fail` doctests — and the atomic is private
/// to a sibling module too. That last part is NOT something a doctest
/// can pin (it only ever sees the crate boundary, never a module
/// boundary inside it); `scripts/check_readiness_gate_placement.sh`
/// does instead. So the honest answer to "which wrong implementation
/// does this kill" is now: none that are expressible. It stays
/// because the type could be loosened — a `pub` field, a `close`
/// method — and this is the test that would then catch the loosening
/// being *used*.
#[tokio::test]
async fn readiness_gate_is_never_closed_by_an_empty_cycle() {
    let dir = tempfile::tempdir().unwrap();
    // No .cache and no .meta written at all: CacheOnly finds
    // nothing, installs nothing, and the engine stays empty.
    let url = "https://127.0.0.1/blocklist.txt".to_string();

    let filter = Arc::new(FilterEngine::new());
    let source_bits = build_source_bit_map(std::slice::from_ref(&url)).expect("at-cap accept");
    let mut mgr = ListManager::new(
        reqwest::Client::new(),
        filter.clone(),
        vec![url.clone()],
        Catalog::fallback(),
        Duration::from_secs(3600),
        source_bits,
        TEST_CAP,
        DEFAULT_MAX_LIST_ENTRIES,
        Some(dir.path().to_path_buf()),
    );
    // Pre-opened, as it would be after any earlier successful cycle
    // in a long-running daemon.
    let gate = ReadinessGate::new(true);
    mgr.set_filter_ready_gate(gate.clone());
    mgr.load_disk_cache();

    mgr.refresh_with_mode(RefreshMode::CacheOnly).await;

    assert_eq!(filter.domain_count(), 0, "fixture sanity: engine is empty");
    assert!(
        gate.is_open(),
        "the gate is LATCHING — an empty cycle must not close it even \
         when the engine holds nothing. A daemon that has served a \
         generation must never go back to SERVFAILing every query."
    );
}

#[test]
fn cleanup_stale_caches_removes_old_files() {
    let dir = tempfile::tempdir().unwrap();

    // Write cache for a source that IS still configured
    let active_body = write_cache_to_disk(
        dir.path(),
        "privacy/ads",
        "https://lists.purge.cc/ads.txt",
        "body",
        None,
        None,
        OffsetDateTime::now_utc(),
    )
    .unwrap();
    let active_stem = source_to_cache_stem("privacy/ads");
    let active_orphan = dir.path().join(generation_basename(
        &active_stem,
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    ));
    std::fs::write(&active_orphan, "orphan").unwrap();
    // Write cache for a source that is NOT configured
    write_cache_to_disk(
        dir.path(),
        "content/adult",
        "https://lists.purge.cc/adult.txt",
        "body",
        None,
        None,
        OffsetDateTime::now_utc(),
    )
    .unwrap();

    let client = reqwest::Client::new();
    let filter = Arc::new(FilterEngine::new());
    let catalog = Catalog::fallback();
    let source_bits = build_source_bit_map(&["privacy/ads".to_string()]).expect("at-cap accept");

    let mgr = ListManager::new(
        client,
        filter,
        vec!["privacy/ads".to_string()],
        catalog,
        Duration::from_secs(3600),
        source_bits,
        TEST_CAP,
        DEFAULT_MAX_LIST_ENTRIES,
        Some(dir.path().to_path_buf()),
    );

    mgr.cleanup_stale_caches();

    // privacy/ads files should remain (active source).
    assert!(dir.path().join(format!("{active_stem}.meta")).exists());
    assert!(
        active_body.exists(),
        "cleanup must preserve the selected body"
    );
    assert!(
        !active_orphan.exists(),
        "cleanup must remove an active-stem orphan"
    );
    // content/adult files should be removed (no longer in config).
    let stale_stem = source_to_cache_stem("content/adult");
    assert!(!dir.path().join(format!("{stale_stem}.meta")).exists());
    assert_eq!(generation_body_paths(dir.path(), &active_stem).len(), 1);
    assert!(generation_body_paths(dir.path(), &stale_stem).is_empty());
}

fn cleanup_manager(cache_dir: &Path, source: &str) -> ListManager {
    ListManager::new(
        reqwest::Client::new(),
        Arc::new(FilterEngine::new()),
        vec![source.to_string()],
        Catalog::fallback(),
        Duration::from_secs(3600),
        build_source_bit_map(&[source.to_string()]).unwrap(),
        TEST_CAP,
        DEFAULT_MAX_LIST_ENTRIES,
        Some(cache_dir.to_path_buf()),
    )
}

fn write_generation_body(cache_dir: &Path, source: &str, body: &[u8]) -> PathBuf {
    use sha2::Digest;

    let stem = source_to_cache_stem(source);
    let sha256 = hex::encode(sha2::Sha256::digest(body));
    let path = cache_dir.join(generation_basename(&stem, &sha256));
    std::fs::write(&path, body).unwrap();
    path
}

#[test]
fn cleanup_preserves_generations_when_manifest_is_invalid_utf8() {
    let dir = tempfile::tempdir().unwrap();
    let source = "https://lists.example.test/unreadable.txt";
    let body = write_generation_body(dir.path(), source, b"kept\n");
    let stem = source_to_cache_stem(source);
    std::fs::write(dir.path().join(format!("{stem}.meta")), [0xff]).unwrap();

    let parsed = load_meta_file(&dir.path().join(format!("{stem}.meta")));
    assert_eq!(parsed.load_state, MetaLoadState::Unreadable);
    assert!(selected_body_path(dir.path(), &stem, &parsed).is_none());
    cleanup_manager(dir.path(), source).cleanup_stale_caches();
    assert!(body.exists());
}

#[test]
fn cleanup_preserves_generations_for_duplicate_or_partial_manifest_fields() {
    let source = "https://lists.example.test/malformed.txt";
    for manifest in [
        "body=partial\n",
        "body=first\nbody=second\nsha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
    ] {
        let dir = tempfile::tempdir().unwrap();
        let body = write_generation_body(dir.path(), source, b"kept\n");
        let stem = source_to_cache_stem(source);
        std::fs::write(dir.path().join(format!("{stem}.meta")), manifest).unwrap();

        cleanup_manager(dir.path(), source).cleanup_stale_caches();
        assert!(body.exists(), "cleanup deleted body for {manifest:?}");
    }
}

#[test]
fn cleanup_removes_active_generation_orphans_when_meta_is_missing() {
    let dir = tempfile::tempdir().unwrap();
    let source = "https://lists.example.test/missing.txt";
    let body = write_generation_body(dir.path(), source, b"orphan\n");

    cleanup_manager(dir.path(), source).cleanup_stale_caches();
    assert!(!body.exists());
}

// ── S50 T5.5: imported.local loader-bridge ─────────────────────────
//
// The bridge intercepts synthetic `imported.local` URLs in
// `download_list` and reads from `<config_dir>/lists/<id>.<ext>` on
// disk. Tests here cover the four contract clauses spelled out in
// the kickoff brief:
//   (1) Local trust + file present → Loaded.
//   (2) Local trust + file missing → Refused with the path in the
//       error message.
//   (3) Non-local trust → Refused (defence-in-depth W2.1) even
//       though the validator should already have caught it.
//   (4) Path → id extraction is correct for the `.txt` happy path
//       and refuses the no-segment / sub-path / root edge cases.
//
// The bridge is a pure free function (no `ListManager`, no async,
// no HTTP client), so each test stands up a `tempdir`, writes a
// file, calls `try_bridge_imported_local`, and asserts on the
// outcome.

/// Convenience: build the `<dir>/lists/` directory under a tempdir
/// and write `body` into `<dir>/lists/<filename>`. Returns the
/// tempdir handle so the caller controls cleanup.
fn write_imported_local_file(filename: &str, body: &str) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let lists_dir = dir.path().join("lists");
    std::fs::create_dir_all(&lists_dir).unwrap();
    std::fs::write(lists_dir.join(filename), body).unwrap();
    dir
}

#[test]
fn imported_local_url_with_trust_local_loads_from_disk() {
    let body = "mycompany.example\ninternal.example\n";
    let dir = write_imported_local_file("mycompany.txt", body);
    let outcome = try_bridge_imported_local(
        "https://imported.local/mycompany.txt",
        BlocklistTrust::Local,
        dir.path(),
        TEST_CAP,
    );
    match outcome {
        LocalBridgeOutcome::Loaded { body: got, path } => {
            assert_eq!(got, body);
            assert_eq!(path, dir.path().join("lists").join("mycompany.txt"));
        }
        other => panic!("expected Loaded, got {other:?}"),
    }
}

/// neutrality-06, end to end — a `base = allow` list must reach the
/// engine as an ALLOW, and the contested domain must come out
/// forwarded.
///
/// This is the whole chain in one test: config `[[blocklists]]` →
/// `SourceBitMap::allow_bits` → the manager's refresh → the shard
/// builder → `FilterEngine`. It runs entirely on the `imported.local`
/// bridge, so no network: fitting, since `base = allow` requires
/// `trust = local` anyway.
///
/// Before the fix the allow list's domains were merged into
/// `block_mask`, so importing an allow list *blocked* what it was
/// meant to permit.
#[tokio::test]
async fn neutrality06_allow_direction_list_reaches_engine_as_allow() {
    let dir = tempfile::tempdir().unwrap();
    let lists_dir = dir.path().join("lists");
    std::fs::create_dir_all(&lists_dir).unwrap();
    std::fs::write(
        lists_dir.join("ads.txt"),
        "shared.example\nblocked.example\n",
    )
    .unwrap();
    std::fs::write(lists_dir.join("compat.txt"), "shared.example\n").unwrap();

    let deny_url = "https://imported.local/ads.txt".to_string();
    let allow_url = "https://imported.local/compat.txt".to_string();

    let mk = |id: &str, url: &str, base: crate::config::schema::BlocklistBase| {
        crate::config::schema::Blocklist {
            id: crate::config::schema::id::Id::new(id).unwrap(),
            display_name: id.to_string(),
            url: url.to_string(),
            format: Default::default(),
            update_interval_hours: None,
            max_entries: None,
            enabled: true,
            auth_token_ref: None,
            base,
            trust: BlocklistTrust::Local,
            accept_unsigned_allow: false,
            max_consecutive_failures: 5,
        }
    };
    let blocklists = vec![
        mk("ads", &deny_url, crate::config::schema::BlocklistBase::Deny),
        mk(
            "compat",
            &allow_url,
            crate::config::schema::BlocklistBase::Allow,
        ),
    ];

    let sources = vec![deny_url.clone(), allow_url.clone()];
    let source_bits = SourceBitMap::build(&sources, &blocklists).unwrap();
    let policy = source_bits.project_policy(&blocklists, &std::collections::BTreeMap::new());
    assert_eq!(
        policy.base.allow, 0b10,
        "compat must own bit 1 as allow-direction"
    );

    let filter = Arc::new(FilterEngine::new());
    let mut mgr = ListManager::new(
        reqwest::Client::new(),
        filter.clone(),
        sources,
        Catalog::fallback(),
        Duration::from_secs(3600),
        source_bits,
        TEST_CAP,
        DEFAULT_MAX_LIST_ENTRIES,
        None,
    );
    mgr.set_local_bridge(SourceTrustMap::build(&blocklists), dir.path().to_path_buf());
    mgr.set_list_policy(policy);
    mgr.refresh().await;

    let shared = filter.list_membership("shared.example");
    assert_eq!(
        shared.allow_mask, 0b10,
        "the allow list's bit must land in allow_mask, not block_mask"
    );
    assert_eq!(
        shared.block_mask, 0b01,
        "the deny list's bit must still land in block_mask"
    );

    let blocked = filter.list_membership("blocked.example");
    assert_eq!(blocked.allow_mask, 0);
    assert_eq!(blocked.block_mask, 0b01);
}

/// neutrality-06 in the `cluster` build — the same guarantee as
/// `neutrality06_allow_direction_list_reaches_engine_as_allow`, exercised
/// in the feature configuration where the install path used to fork.
///
/// A clustering primary used to accumulate the whole corpus into one flat
/// block-mask map to publish its sync artifact, and the local install rode
/// that same flat map. Direction was dropped on the way, so a primary
/// silently reverted to the inversion the sharded path had just been fixed
/// for. Cluster sync S1 deleted the artifact and with it the fork — every
/// node now installs shard-at-a-time via `swap_shard`.
///
/// **The `cluster` gate stays deliberately.** Nothing in the body needs the
/// feature any more, but the defect this pins was invisible with `cluster`
/// off: it lived inside a `#[cfg(feature = "cluster")]` branch. The ungated
/// sibling covers the default build; this covers the build where the
/// install used to be conditional, so a cluster-only install path
/// reintroduced later fails here rather than shipping unnoticed.
#[cfg(feature = "cluster")]
#[tokio::test]
async fn cluster_build_allow_direction_survives_sharded_install() {
    let dir = tempfile::tempdir().unwrap();
    let lists_dir = dir.path().join("lists");
    std::fs::create_dir_all(&lists_dir).unwrap();
    std::fs::write(lists_dir.join("ads.txt"), "shared.example\n").unwrap();
    std::fs::write(lists_dir.join("compat.txt"), "shared.example\n").unwrap();

    let deny_url = "https://imported.local/ads.txt".to_string();
    let allow_url = "https://imported.local/compat.txt".to_string();
    let mk = |id: &str, url: &str, base: crate::config::schema::BlocklistBase| {
        crate::config::schema::Blocklist {
            id: crate::config::schema::id::Id::new(id).unwrap(),
            display_name: id.to_string(),
            url: url.to_string(),
            format: Default::default(),
            update_interval_hours: None,
            max_entries: None,
            enabled: true,
            auth_token_ref: None,
            base,
            trust: BlocklistTrust::Local,
            accept_unsigned_allow: false,
            max_consecutive_failures: 5,
        }
    };
    let blocklists = vec![
        mk("ads", &deny_url, crate::config::schema::BlocklistBase::Deny),
        mk(
            "compat",
            &allow_url,
            crate::config::schema::BlocklistBase::Allow,
        ),
    ];
    let sources = vec![deny_url, allow_url];
    let source_bits = SourceBitMap::build(&sources, &blocklists).unwrap();
    let policy = source_bits.project_policy(&blocklists, &std::collections::BTreeMap::new());

    let filter = Arc::new(FilterEngine::new());
    let mut mgr = ListManager::new(
        reqwest::Client::new(),
        filter.clone(),
        sources,
        Catalog::fallback(),
        Duration::from_secs(3600),
        source_bits,
        TEST_CAP,
        DEFAULT_MAX_LIST_ENTRIES,
        None,
    );
    mgr.set_local_bridge(SourceTrustMap::build(&blocklists), dir.path().to_path_buf());
    mgr.set_list_policy(policy);
    mgr.refresh().await;

    let shared = filter.list_membership("shared.example");
    assert_eq!(
        shared.allow_mask, 0b10,
        "a sharded rebuild must install the allow direction"
    );
    assert_eq!(shared.block_mask, 0b01);
}

#[test]
fn imported_local_url_with_trust_local_missing_file_errors() {
    // No `lists/` directory at all: tempdir is bare.
    let dir = tempfile::tempdir().unwrap();
    let outcome = try_bridge_imported_local(
        "https://imported.local/missing.txt",
        BlocklistTrust::Local,
        dir.path(),
        TEST_CAP,
    );
    match outcome {
        LocalBridgeOutcome::Refused(reason) => {
            let expected_path = dir.path().join("lists").join("missing.txt");
            assert!(
                reason.contains(&expected_path.display().to_string()),
                "error message should include the missing path; got: {reason}"
            );
            assert!(
                reason.contains("not readable"),
                "error message should explain why; got: {reason}"
            );
        }
        other => panic!("expected Refused, got {other:?}"),
    }
}

#[test]
fn imported_local_url_with_trust_remote_unsigned_refuses() {
    // File exists, but trust is wrong — defence-in-depth.
    let dir = write_imported_local_file("mycompany.txt", "should.not.read.example\n");
    let outcome = try_bridge_imported_local(
        "https://imported.local/mycompany.txt",
        BlocklistTrust::RemoteUnsigned,
        dir.path(),
        TEST_CAP,
    );
    match outcome {
        LocalBridgeOutcome::Refused(reason) => {
            assert!(
                reason.contains("requires trust=local"),
                "error message should explain the W2.1 violation; got: {reason}"
            );
            assert!(
                reason.contains("W2.1"),
                "error message should reference the invariant id; got: {reason}"
            );
        }
        other => panic!("expected Refused for non-local trust, got {other:?}"),
    }
}

#[test]
fn imported_local_url_with_trust_signed_also_refuses() {
    // `signed` is parked S51+ but defence-in-depth covers it too —
    // a future agent who flips trust to "signed" should see the
    // same refusal until signing is actually implemented.
    let dir = write_imported_local_file("mycompany.txt", "should.not.read.example\n");
    let outcome = try_bridge_imported_local(
        "https://imported.local/mycompany.txt",
        BlocklistTrust::Signed,
        dir.path(),
        TEST_CAP,
    );
    assert!(matches!(outcome, LocalBridgeOutcome::Refused(_)));
}

#[test]
fn imported_local_url_extracts_id_correctly_from_path() {
    // Happy path: single .txt segment.
    assert_eq!(
        imported_local_id_from_path("/mycompany.txt").as_deref(),
        Some("mycompany.txt")
    );
    // Without leading slash too (defensive — Url::parse always
    // produces a leading slash, but the helper is more useful as a
    // pure function on raw strings).
    assert_eq!(
        imported_local_id_from_path("mycompany.txt").as_deref(),
        Some("mycompany.txt")
    );
    // Root-only path: no id segment.
    assert_eq!(imported_local_id_from_path("/"), None);
    // Empty path.
    assert_eq!(imported_local_id_from_path(""), None);
    // Sub-path: refuse so a typo can't traverse into a nested dir.
    assert_eq!(imported_local_id_from_path("/sub/mycompany.txt"), None);
    // Trailing-slash form is also a sub-path attempt.
    assert_eq!(imported_local_id_from_path("/mycompany/"), None);
    // Non-`.txt` extensions still pass through — T3 picks `.txt`
    // today but the bridge stays format-agnostic.
    assert_eq!(
        imported_local_id_from_path("/internal.toml").as_deref(),
        Some("internal.toml")
    );
}

#[test]
fn imported_local_id_rejects_dotdot_segment() {
    // rev-2606 §06 roundup nit: a bare `..` segment must be refused so
    // non-traversal is a property of the function, not merely of "a
    // directory isn't readable as a file".
    assert_eq!(imported_local_id_from_path(".."), None);
    assert_eq!(imported_local_id_from_path("/.."), None);
    assert_eq!(imported_local_id_from_path("//.."), None);
    // A normal single segment still resolves.
    assert_eq!(
        imported_local_id_from_path("/list.txt").as_deref(),
        Some("list.txt")
    );
}

#[test]
fn pure_v1_auth_token_ref_attaches_bearer_via_v1_id_fallback() {
    // rev-2606 §06 source_key-02: a pure-v1 blocklist's source string is
    // the raw URL, so the slash-form `by_url` token key misses. The
    // fallback through `source_to_blocklist` → `token_for_v1_id` must still
    // supply the bearer instead of fetching anonymously.
    use crate::config::schema::{
        Blocklist, BlocklistBase, BlocklistFormat, BlocklistTrust, ConfigV1, Id,
    };

    // A real `Secrets` via the public load path (entries are private).
    fn secrets_with(name: &str, value: &str) -> crate::config::secrets::Secrets {
        use std::io::Write as _;
        use std::os::unix::fs::PermissionsExt as _;
        use std::sync::atomic::{AtomicUsize, Ordering};
        static SEQ: AtomicUsize = AtomicUsize::new(0);
        let pid = std::process::id();
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("purge-mgr-stkn-{pid}-{n}"));
        std::fs::create_dir_all(&dir).unwrap();
        let sp = dir.join("secrets.toml");
        {
            let mut f = std::fs::File::create(&sp).unwrap();
            writeln!(f, "{name} = \"{value}\"").unwrap();
        }
        let mut perm = std::fs::metadata(&sp).unwrap().permissions();
        perm.set_mode(0o600);
        std::fs::set_permissions(&sp, perm).unwrap();
        let secrets = crate::config::secrets::load_secrets(&sp).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        secrets
    }

    let url = "https://corp.example.com/private.txt";
    let mut config = ConfigV1::test_scaffold();
    config.blocklists.push(Blocklist {
        id: Id::new("security-malicious").unwrap(),
        display_name: "sec".to_string(),
        url: url.to_string(),
        format: BlocklistFormat::Domains,
        update_interval_hours: None,
        max_entries: None,
        enabled: true,
        auth_token_ref: Some("sec-token".to_string()),
        base: BlocklistBase::Deny,
        trust: BlocklistTrust::RemoteUnsigned,
        accept_unsigned_allow: false,
        max_consecutive_failures: 5,
    });
    let secrets = secrets_with("sec-token", "bearer-xyz");
    let tokens = SourceTokenMap::build(&config, &secrets);

    // Pure-v1 source == raw URL → the slash-form by_url key misses.
    assert_eq!(tokens.token_for_url(url), None);

    // start.rs maps the raw URL to the canonical Id in source_to_blocklist.
    let mut s2b: HashMap<String, (Id, u32)> = HashMap::new();
    s2b.insert(url.to_string(), (Id::new("security-malicious").unwrap(), 5));

    // Fallback resolves the bearer; an unknown source still yields nothing.
    assert_eq!(resolve_bearer_token(&tokens, &s2b, url), Some("bearer-xyz"));
    assert_eq!(
        resolve_bearer_token(&tokens, &s2b, "https://other.example/x"),
        None
    );
}

#[test]
fn imported_local_url_non_imported_host_falls_through_to_http() {
    // A regular https URL must NOT be intercepted — the bridge has
    // to be invisible to the existing fetch path.
    let dir = tempfile::tempdir().unwrap();
    let outcome = try_bridge_imported_local(
        "https://lists.purge.cc/ads.txt",
        BlocklistTrust::RemoteUnsigned,
        dir.path(),
        TEST_CAP,
    );
    assert!(matches!(outcome, LocalBridgeOutcome::NotLocal));
}

#[test]
fn imported_local_url_unparseable_falls_through_to_http() {
    // Malformed URLs are not the bridge's problem — the existing
    // URL guard / HTTP client surfaces those errors with their
    // existing error vocabulary. Bridge stays out of the way.
    let dir = tempfile::tempdir().unwrap();
    let outcome = try_bridge_imported_local(
        "not a url at all",
        BlocklistTrust::Local,
        dir.path(),
        TEST_CAP,
    );
    assert!(matches!(outcome, LocalBridgeOutcome::NotLocal));
}

#[test]
fn imported_local_url_missing_id_segment_refuses() {
    // `https://imported.local/` (no segment) must NOT silently
    // resolve to `<config_dir>/lists/` itself — a typo must surface
    // as a refusal, not a directory read.
    let dir = tempfile::tempdir().unwrap();
    let outcome = try_bridge_imported_local(
        "https://imported.local/",
        BlocklistTrust::Local,
        dir.path(),
        TEST_CAP,
    );
    match outcome {
        LocalBridgeOutcome::Refused(reason) => {
            assert!(
                reason.contains("missing list id segment"),
                "error should explain the empty-segment case; got: {reason}"
            );
        }
        other => panic!("expected Refused for empty path, got {other:?}"),
    }
}

#[test]
fn imported_local_url_exactly_at_body_cap_is_loaded() {
    let body = "cap!";
    let dir = write_imported_local_file("cap.txt", body);
    let outcome = try_bridge_imported_local(
        "https://imported.local/cap.txt",
        BlocklistTrust::Local,
        dir.path(),
        body.len(),
    );
    assert!(matches!(outcome, LocalBridgeOutcome::Loaded { body: got, .. } if got == body));
}

#[test]
fn imported_local_url_cap_plus_one_refuses() {
    let dir = write_imported_local_file("oversize.txt", "12345");
    let outcome = try_bridge_imported_local(
        "https://imported.local/oversize.txt",
        BlocklistTrust::Local,
        dir.path(),
        4,
    );
    match outcome {
        LocalBridgeOutcome::Refused(reason) => {
            assert!(
                reason.contains("5 bytes"),
                "error message should report the actual size; got: {reason}"
            );
            assert!(
                reason.contains("max 4 bytes"),
                "error message should report the cap; got: {reason}"
            );
        }
        other => panic!("expected Refused for oversize file, got {other:?}"),
    }
}

#[test]
fn imported_local_url_reads_the_opened_handle_after_path_replacement() {
    let original = "cap!";
    let dir = write_imported_local_file("replace.txt", original);
    let on_disk = dir.path().join("lists").join("replace.txt");
    let replacement = dir.path().join("lists").join("replacement.tmp");
    set_imported_local_after_metadata_hook_for_test(move || {
        std::fs::write(&replacement, "replacement is deliberately over the cap").unwrap();
        std::fs::rename(&replacement, &on_disk).unwrap();
    });

    let outcome = try_bridge_imported_local(
        "https://imported.local/replace.txt",
        BlocklistTrust::Local,
        dir.path(),
        original.len(),
    );
    assert!(matches!(outcome, LocalBridgeOutcome::Loaded { body: got, .. } if got == original));
}

#[test]
fn imported_local_url_growth_after_metadata_cannot_bypass_body_cap() {
    let original = "cap!";
    let dir = write_imported_local_file("grow.txt", original);
    let on_disk = dir.path().join("lists").join("grow.txt");
    set_imported_local_after_metadata_hook_for_test(move || {
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&on_disk)
            .unwrap();
        file.write_all(b"+").unwrap();
    });

    let outcome = try_bridge_imported_local(
        "https://imported.local/grow.txt",
        BlocklistTrust::Local,
        dir.path(),
        original.len(),
    );
    assert!(
        matches!(outcome, LocalBridgeOutcome::Refused(reason) if reason.contains("5 bytes") && reason.contains("max 4 bytes"))
    );
}

#[test]
fn imported_local_url_invalid_utf8_refuses() {
    let dir = write_imported_local_file("invalid.txt", "placeholder");
    std::fs::write(
        dir.path().join("lists").join("invalid.txt"),
        b"valid.example\n\xff",
    )
    .unwrap();

    let outcome = try_bridge_imported_local(
        "https://imported.local/invalid.txt",
        BlocklistTrust::Local,
        dir.path(),
        TEST_CAP,
    );
    assert!(
        matches!(outcome, LocalBridgeOutcome::Refused(reason) if reason.contains("invalid UTF-8"))
    );
}

#[test]
fn stat_local_source_none_for_non_local_url() {
    let dir = write_imported_local_file("mycompany.txt", "a.example\n");
    assert!(
        stat_local_source("https://lists.example.invalid/a.txt", dir.path()).is_none(),
        "a non-imported.local URL has no file to stamp"
    );
}

#[test]
fn stat_local_source_none_for_missing_file() {
    let dir = tempfile::tempdir().unwrap();
    assert!(
        stat_local_source("https://imported.local/absent.txt", dir.path()).is_none(),
        "a missing file stamps as None, same as a non-local URL — both mean \
         'nothing to compare', and the transition INTO this state still \
         changes the fingerprint by construction (Some -> None)"
    );
}

#[test]
fn stat_local_source_changes_on_content_edit() {
    let dir = write_imported_local_file("mycompany.txt", "a.example\n");
    let before = stat_local_source("https://imported.local/mycompany.txt", dir.path());
    assert!(before.is_some());

    std::thread::sleep(std::time::Duration::from_millis(10));
    std::fs::write(
        dir.path().join("lists/mycompany.txt"),
        "a.example\nb.example\n",
    )
    .unwrap();
    let after = stat_local_source("https://imported.local/mycompany.txt", dir.path());

    assert_ne!(
        before, after,
        "a size+mtime change on the same file must move the stamp"
    );
}

#[test]
fn stat_local_source_stable_across_repeat_reads() {
    let dir = write_imported_local_file("mycompany.txt", "a.example\n");
    let a = stat_local_source("https://imported.local/mycompany.txt", dir.path());
    let b = stat_local_source("https://imported.local/mycompany.txt", dir.path());
    assert_eq!(
        a, b,
        "reading an unchanged file twice must stamp identically"
    );
}

#[test]
fn set_local_bridge_attaches_trust_map_and_dir() {
    // Builder-method smoke: after `.set_local_bridge(...)`, the
    // manager's bridge fields are populated and a subsequent
    // construction via `new` (no builder call) leaves them empty.
    // §4.24 Phase 2 (P2-A): the trust map is now the typed
    // `SourceTrustMap` — fixture builds it via `::build(blocklists)`
    // (no hand-constructed HashMap) per §11.4 test discipline.
    let client = reqwest::Client::new();
    let filter = Arc::new(FilterEngine::new());
    let catalog = Catalog::fallback();
    let dir = tempfile::tempdir().unwrap();

    let imported_url = "https://imported.local/mycompany.txt".to_string();
    let blocklists = vec![crate::config::schema::Blocklist {
        id: crate::config::schema::id::Id::new("mycompany").unwrap(),
        display_name: "mycompany".to_string(),
        url: imported_url.clone(),
        format: Default::default(),
        update_interval_hours: None,
        max_entries: None,
        enabled: true,
        auth_token_ref: None,
        base: crate::config::schema::BlocklistBase::Allow,
        trust: BlocklistTrust::Local,
        accept_unsigned_allow: false,
        max_consecutive_failures: 5,
    }];
    let trust = SourceTrustMap::build(&blocklists);

    let mgr_no_bridge = ListManager::new(
        client.clone(),
        filter.clone(),
        vec![],
        catalog.clone(),
        Duration::from_secs(3600),
        SourceBitMap::default(),
        TEST_CAP,
        DEFAULT_MAX_LIST_ENTRIES,
        None,
    );
    assert!(mgr_no_bridge.local_bridge_dir.is_none());
    assert!(mgr_no_bridge.source_trust.is_empty());

    let mut mgr_with_bridge = ListManager::new(
        client,
        filter,
        vec![],
        catalog,
        Duration::from_secs(3600),
        SourceBitMap::default(),
        TEST_CAP,
        DEFAULT_MAX_LIST_ENTRIES,
        None,
    );
    mgr_with_bridge.set_local_bridge(trust.clone(), dir.path().to_path_buf());

    assert_eq!(
        mgr_with_bridge.local_bridge_dir.as_deref(),
        Some(dir.path())
    );
    // Trust was wired by URL; the typed lookup confirms it.
    assert_eq!(
        mgr_with_bridge.source_trust.trust_for_url(&imported_url),
        Some(BlocklistTrust::Local),
    );
    // And by canonical v1 id — the symmetry Phase 2 unlocked.
    assert_eq!(
        mgr_with_bridge
            .source_trust
            .trust_for_v1_id(&crate::config::schema::id::Id::new("mycompany").unwrap()),
        Some(BlocklistTrust::Local),
    );
}

#[test]
fn merge_sources_with_blocklists_appends_url_and_records_trust() {
    // Helper used by start.rs / update.rs to unify legacy
    // `lists.sources` with v1 `[[blocklists]]` URLs in one place.
    // T3's `import-local` only writes the `[[blocklists]]` row; this
    // helper ensures the URL also reaches the manager AND its trust
    // is wired for the loader-bridge defence-in-depth check.
    use crate::config::schema::id::Id;
    use crate::config::schema::{Blocklist, BlocklistBase, BlocklistTrust};

    let legacy = vec!["privacy/ads".to_string()];
    let blocklists = vec![
        Blocklist {
            id: Id::new("mycompany").unwrap(),
            display_name: "mycompany".to_string(),
            url: "https://imported.local/mycompany.txt".to_string(),
            format: Default::default(),
            update_interval_hours: None,
            max_entries: None,
            enabled: true,
            auth_token_ref: None,
            base: BlocklistBase::Allow,
            trust: BlocklistTrust::Local,
            accept_unsigned_allow: false,
            max_consecutive_failures: 5,
        },
        Blocklist {
            // Disabled — must NOT appear in merged sources.
            id: Id::new("paused").unwrap(),
            display_name: "paused".to_string(),
            url: "https://example.com/paused.txt".to_string(),
            format: Default::default(),
            update_interval_hours: None,
            max_entries: None,
            enabled: false,
            auth_token_ref: None,
            base: BlocklistBase::Deny,
            trust: BlocklistTrust::RemoteUnsigned,
            accept_unsigned_allow: false,
            max_consecutive_failures: 5,
        },
    ];

    let (sources, trust) = merge_sources_with_blocklists(&legacy, &blocklists);
    assert_eq!(sources.len(), 2, "legacy + 1 enabled blocklist URL");
    assert_eq!(sources[0], "privacy/ads");
    assert_eq!(sources[1], "https://imported.local/mycompany.txt");
    // §4.24 Phase 2 (P2-A): trust map is now the typed `SourceTrustMap`.
    // Lookups go through `trust_for_url` / `trust_for_v1_id` instead
    // of HashMap::get — pinning the call-site contract.
    assert_eq!(
        trust.trust_for_url("https://imported.local/mycompany.txt"),
        Some(BlocklistTrust::Local),
    );
    assert_eq!(
        trust.trust_for_v1_id(&Id::new("mycompany").unwrap()),
        Some(BlocklistTrust::Local),
        "v1-id lookup is the new Phase 2 contract",
    );
    // Disabled entries are excluded from sources but DO surface in
    // the trust map — a future enable-then-reload should pick up
    // the right trust without recomputing.
    assert_eq!(
        trust.trust_for_url("https://example.com/paused.txt"),
        Some(BlocklistTrust::RemoteUnsigned),
    );
    assert_eq!(
        trust.trust_for_v1_id(&Id::new("paused").unwrap()),
        Some(BlocklistTrust::RemoteUnsigned),
    );
}

#[test]
fn merge_sources_with_blocklists_does_not_duplicate_when_url_already_in_sources() {
    // If an operator listed the URL in BOTH legacy `lists.sources`
    // AND `[[blocklists]]` (forward-compat for the post-T6 world
    // where `lists.sources` becomes the canonical view), the merge
    // must not duplicate.
    use crate::config::schema::id::Id;
    use crate::config::schema::{Blocklist, BlocklistBase, BlocklistTrust};

    let legacy = vec![
        "privacy/ads".to_string(),
        "https://imported.local/mycompany.txt".to_string(),
    ];
    let blocklists = vec![Blocklist {
        id: Id::new("mycompany").unwrap(),
        display_name: "mycompany".to_string(),
        url: "https://imported.local/mycompany.txt".to_string(),
        format: Default::default(),
        update_interval_hours: None,
        max_entries: None,
        enabled: true,
        auth_token_ref: None,
        base: BlocklistBase::Allow,
        trust: BlocklistTrust::Local,
        accept_unsigned_allow: false,
        max_consecutive_failures: 5,
    }];

    let (sources, _) = merge_sources_with_blocklists(&legacy, &blocklists);
    assert_eq!(sources, legacy, "no duplicate URL after merge");
}

/// §4.7 Phase 2 T1: `forget_source` removes any in-memory cache
/// entry for a configured source, regardless of whether the
/// HashMap was keyed by slug or by catalog-resolved URL.
#[test]
fn forget_removes_in_memory_entry() {
    let client = reqwest::Client::new();
    let filter = Arc::new(FilterEngine::new());
    let catalog = Catalog::fallback();
    let mut mgr = ListManager::new(
        client,
        filter,
        vec!["privacy/ads".to_string()],
        catalog,
        Duration::from_secs(3600),
        SourceBitMap::default(),
        TEST_CAP,
        DEFAULT_MAX_LIST_ENTRIES,
        None,
    );

    let resolved_url = mgr
        .fetch_urls
        .get("privacy/ads")
        .cloned()
        .expect("privacy/ads has a resolved fetch URL");
    mgr.cache.insert(
        resolved_url.clone(),
        ListCache {
            etag: Some("\"abc\"".into()),
            last_modified: None,
            body: Some("example.com".into()),
            fetched_at: OffsetDateTime::now_utc(),
        },
    );
    assert!(mgr.cache.contains_key(&resolved_url));

    let was_cached = mgr.forget_source("privacy/ads");
    assert!(was_cached, "in-memory entry was present before forget");
    assert!(
        !mgr.cache.contains_key(&resolved_url),
        "in-memory entry must be gone after forget"
    );
}

/// §4.7 Phase 2 T1: when a cache_dir is wired, `forget_source`
/// unlinks both the `<stem>.cache` body file and the `<stem>.meta`
/// sidecar. Files not present are absorbed silently.
#[test]
fn forget_deletes_cache_and_meta_files() {
    let tmp = tempfile::tempdir().unwrap();
    let client = reqwest::Client::new();
    let filter = Arc::new(FilterEngine::new());
    let catalog = Catalog::fallback();
    let mut mgr = ListManager::new(
        client,
        filter,
        vec!["privacy/ads".to_string()],
        catalog,
        Duration::from_secs(3600),
        SourceBitMap::default(),
        TEST_CAP,
        DEFAULT_MAX_LIST_ENTRIES,
        Some(tmp.path().to_path_buf()),
    );

    let stem = source_to_cache_stem("privacy/ads");
    let cache_path = tmp.path().join(format!("{stem}.cache"));
    let meta_path = tmp.path().join(format!("{stem}.meta"));
    std::fs::write(&cache_path, b"example.com\nads.example.org\n").unwrap();
    std::fs::write(&meta_path, b"etag=\"abc\"\nfetched-at=\n").unwrap();
    assert!(cache_path.exists());
    assert!(meta_path.exists());

    let was_cached = mgr.forget_source("privacy/ads");
    assert!(was_cached, "disk files were present before forget");
    assert!(!cache_path.exists(), "<stem>.cache must be unlinked");
    assert!(!meta_path.exists(), "<stem>.meta must be unlinked");
}

/// §4.7 Phase 2 T1: idempotency — forgetting a source we never
/// cached (no HashMap entry, no disk files) returns `false`
/// without error. A second call after a successful forget also
/// returns `false`.
#[test]
fn forget_returns_false_when_source_not_cached() {
    let tmp = tempfile::tempdir().unwrap();
    let client = reqwest::Client::new();
    let filter = Arc::new(FilterEngine::new());
    let catalog = Catalog::fallback();
    let mut mgr = ListManager::new(
        client,
        filter,
        vec!["privacy/ads".to_string()],
        catalog,
        Duration::from_secs(3600),
        SourceBitMap::default(),
        TEST_CAP,
        DEFAULT_MAX_LIST_ENTRIES,
        Some(tmp.path().to_path_buf()),
    );

    // Never-cached source.
    assert!(!mgr.forget_source("privacy/never-seen"));

    // Cache an entry, forget once (true), forget again (false).
    let url = mgr
        .fetch_urls
        .get("privacy/ads")
        .cloned()
        .expect("privacy/ads has a resolved fetch URL");
    mgr.cache.insert(url, ListCache::default());
    assert!(mgr.forget_source("privacy/ads"));
    assert!(
        !mgr.forget_source("privacy/ads"),
        "second forget on already-cleared source returns false"
    );
}

#[test]
fn planned_forget_routes_slug_id_and_url_aliases_to_the_representative_cache() {
    use crate::config::schema::{Blocklist, BlocklistBase, BlocklistFormat, Id};
    use std::collections::BTreeMap;

    let row = Blocklist {
        id: Id::new("team-ads").unwrap(),
        display_name: "Team ads".to_string(),
        url: "https://example.test/team-ads.txt".to_string(),
        format: BlocklistFormat::Domains,
        update_interval_hours: None,
        max_entries: None,
        enabled: true,
        auth_token_ref: None,
        base: BlocklistBase::Deny,
        trust: BlocklistTrust::RemoteUnsigned,
        accept_unsigned_allow: false,
        max_consecutive_failures: 5,
    };
    let plan = ResolvedSourcePlan::build(
        &Catalog::fallback(),
        &["team/ads".to_string()],
        &[row],
        &BTreeMap::new(),
    )
    .unwrap();
    let bits = SourceBitMap::from_plan(&plan).unwrap();

    for alias in [
        "team/ads",
        "team-ads",
        "https://example.test/team-ads.txt",
        "https://EXAMPLE.test:443/team-ads.txt/",
    ] {
        let cache_dir = tempfile::tempdir().unwrap();
        let representative = plan.representatives().pop().unwrap();
        let fetch_url = plan
            .fetch_url_for_source(&representative)
            .unwrap()
            .to_string();
        write_cache_to_disk(
            cache_dir.path(),
            &representative,
            &fetch_url,
            "ads.example\n",
            None,
            None,
            OffsetDateTime::now_utc(),
        )
        .unwrap();
        let mut manager = ListManager::with_plan_and_tokens(
            reqwest::Client::new(),
            Arc::new(FilterEngine::new()),
            plan.clone(),
            Duration::from_secs(3600),
            bits.clone(),
            SourceTokenMap::default(),
            TEST_CAP,
            DEFAULT_MAX_LIST_ENTRIES,
            Some(cache_dir.path().to_path_buf()),
        );
        manager.cache.insert(fetch_url, ListCache::default());

        assert!(manager.forget_source(alias), "alias {alias}");
        let stem = source_to_cache_stem(&representative);
        assert!(!cache_dir.path().join(format!("{stem}.cache")).exists());
        assert!(!cache_dir.path().join(format!("{stem}.meta")).exists());
    }
}

async fn spawn_unconditional_304_tls_origin() -> (
    std::net::SocketAddr,
    String,
    Arc<std::sync::Mutex<Option<String>>>,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    if rustls::crypto::CryptoProvider::get_default().is_none() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }
    let cert = rcgen::generate_simple_self_signed(vec!["lists.test".to_string()]).unwrap();
    let pem = cert.cert.pem();
    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
    let server = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.cert.der().clone()],
            rustls::pki_types::PrivateKeyDer::Pkcs8(key),
        )
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server));
    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();
    let request_seen = Arc::new(std::sync::Mutex::new(None));
    let request_for_task = request_seen.clone();
    tokio::spawn(async move {
        let Ok((tcp, _)) = listener.accept().await else {
            return;
        };
        let Ok(mut tls) = acceptor.accept(tcp).await else {
            return;
        };
        let mut request = [0_u8; 4096];
        if let Ok(read) = tls.read(&mut request).await {
            *request_for_task.lock().unwrap() =
                Some(String::from_utf8_lossy(&request[..read]).to_ascii_lowercase());
        }
        let _ = tls
            .write_all(b"HTTP/1.1 304 Not Modified\r\nConnection: close\r\n\r\n")
            .await;
        let _ = tls.shutdown().await;
    });
    (addr, pem, request_seen)
}

async fn spawn_tls_origin_responses(
    responses: Vec<String>,
) -> (
    std::net::SocketAddr,
    String,
    Arc<std::sync::Mutex<Vec<String>>>,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    if rustls::crypto::CryptoProvider::get_default().is_none() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }
    let cert = rcgen::generate_simple_self_signed(vec!["lists.test".to_string()]).unwrap();
    let pem = cert.cert.pem();
    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
    let server = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.cert.der().clone()],
            rustls::pki_types::PrivateKeyDer::Pkcs8(key),
        )
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server));
    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();
    let requests = Arc::new(std::sync::Mutex::new(Vec::new()));
    let requests_for_task = requests.clone();
    tokio::spawn(async move {
        for response in responses {
            let Ok((tcp, _)) = listener.accept().await else {
                return;
            };
            let Ok(mut tls) = acceptor.accept(tcp).await else {
                return;
            };
            let mut request = [0_u8; 4096];
            if let Ok(read) = tls.read(&mut request).await {
                requests_for_task
                    .lock()
                    .unwrap()
                    .push(String::from_utf8_lossy(&request[..read]).to_ascii_lowercase());
            }
            let _ = tls.write_all(response.as_bytes()).await;
            let _ = tls.shutdown().await;
        }
    });
    (addr, pem, requests)
}

async fn spawn_etag_precedence_tls_origin() -> (
    std::net::SocketAddr,
    String,
    Arc<std::sync::Mutex<Option<String>>>,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    if rustls::crypto::CryptoProvider::get_default().is_none() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }
    let cert = rcgen::generate_simple_self_signed(vec!["lists.test".to_string()]).unwrap();
    let pem = cert.cert.pem();
    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
    let server = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.cert.der().clone()],
            rustls::pki_types::PrivateKeyDer::Pkcs8(key),
        )
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server));
    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();
    let request_seen = Arc::new(std::sync::Mutex::new(None));
    let request_for_task = request_seen.clone();
    tokio::spawn(async move {
        let Ok((tcp, _)) = listener.accept().await else {
            return;
        };
        let Ok(mut tls) = acceptor.accept(tcp).await else {
            return;
        };
        let mut request = [0_u8; 4096];
        let Ok(read) = tls.read(&mut request).await else {
            return;
        };
        let request = String::from_utf8_lossy(&request[..read]).to_ascii_lowercase();
        *request_for_task.lock().unwrap() = Some(request.clone());
        let response = if request.contains("if-modified-since:") {
            "HTTP/1.1 304 Not Modified\r\nConnection: close\r\n\r\n".to_string()
        } else {
            tls_ok_response_with_last_modified(
                "changed.example\n",
                "\"new\"",
                "Thu, 01 Jan 1970 00:00:00 GMT",
            )
        };
        let _ = tls.write_all(response.as_bytes()).await;
        let _ = tls.shutdown().await;
    });
    (addr, pem, request_seen)
}

fn tls_ok_response(body: &str, etag: &str) -> String {
    format!(
        "HTTP/1.1 200 OK\r\nETag: {etag}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

fn tls_ok_response_with_last_modified(body: &str, etag: &str, last_modified: &str) -> String {
    format!(
        "HTTP/1.1 200 OK\r\nETag: {etag}\r\nLast-Modified: {last_modified}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

#[tokio::test]
async fn download_list_returns_an_uncommitted_validator_candidate() {
    let last_modified = "Thu, 01 Jan 1970 00:00:00 GMT";
    let (origin, pem, _) = spawn_tls_origin_responses(vec![tls_ok_response_with_last_modified(
        "candidate.example\n",
        "\"candidate\"",
        last_modified,
    )])
    .await;
    let url = "https://lists.test/candidate.txt".to_string();
    let mut mgr = ListManager::new(
        reqwest::Client::builder()
            .resolve("lists.test", origin)
            .add_root_certificate(reqwest::Certificate::from_pem(pem.as_bytes()).unwrap())
            .build()
            .unwrap(),
        Arc::new(FilterEngine::new()),
        vec![],
        Catalog::fallback(),
        Duration::from_secs(3600),
        SourceBitMap::default(),
        TEST_CAP,
        DEFAULT_MAX_LIST_ENTRIES,
        None,
    );
    let prior = ListCache {
        etag: Some("\"retained\"".into()),
        last_modified: Some("Wed, 31 Dec 1969 00:00:00 GMT".into()),
        body: Some("retained.example\n".into()),
        fetched_at: time::macros::datetime!(2026-09-04 12:00:00 UTC),
    };
    mgr.cache.insert(url.clone(), prior.clone());

    let FetchResult::Fresh(candidate) = mgr.download_list(&url, &url).await.unwrap() else {
        panic!("200 must return a fresh candidate");
    };
    assert!(matches!(
        candidate.body,
        FreshBody::Resident(ref body) if body == "candidate.example\n"
    ));
    assert_eq!(candidate.etag.as_deref(), Some("\"candidate\""));
    assert_eq!(candidate.last_modified.as_deref(), Some(last_modified));
    assert_eq!(mgr.cache.get(&url), Some(&prior));
}

#[tokio::test]
async fn download_list_prefers_etag_over_last_modified() {
    let last_modified = "Thu, 01 Jan 1970 00:00:00 GMT";
    let (origin, pem, requests) = spawn_tls_origin_responses(vec![
        tls_ok_response_with_last_modified("etag.example\n", "\"new-etag\"", last_modified),
        tls_ok_response_with_last_modified("date.example\n", "\"new-date\"", last_modified),
    ])
    .await;
    let etag_url = "https://lists.test/etag.txt".to_string();
    let date_url = "https://lists.test/date.txt".to_string();
    let mut mgr = ListManager::new(
        reqwest::Client::builder()
            .resolve("lists.test", origin)
            .add_root_certificate(reqwest::Certificate::from_pem(pem.as_bytes()).unwrap())
            .build()
            .unwrap(),
        Arc::new(FilterEngine::new()),
        vec![],
        Catalog::fallback(),
        Duration::from_secs(3600),
        SourceBitMap::default(),
        TEST_CAP,
        DEFAULT_MAX_LIST_ENTRIES,
        None,
    );
    mgr.cache.insert(
        etag_url.clone(),
        ListCache {
            etag: Some("\"old-etag\"".into()),
            last_modified: Some(last_modified.into()),
            body: None,
            fetched_at: OffsetDateTime::UNIX_EPOCH,
        },
    );
    mgr.cache.insert(
        date_url.clone(),
        ListCache {
            etag: None,
            last_modified: Some(last_modified.into()),
            body: None,
            fetched_at: OffsetDateTime::UNIX_EPOCH,
        },
    );

    mgr.download_list(&etag_url, &etag_url).await.unwrap();
    mgr.download_list(&date_url, &date_url).await.unwrap();

    let requests = requests.lock().unwrap();
    assert!(requests[0].contains("if-none-match: \"old-etag\""));
    assert!(!requests[0].contains("if-modified-since:"));
    assert!(!requests[1].contains("if-none-match:"));
    assert!(requests[1].contains("if-modified-since: thu, 01 jan 1970 00:00:00 gmt"));
}

#[tokio::test]
async fn an_etag_mismatch_with_the_same_last_modified_returns_the_new_body() {
    let last_modified = "Thu, 01 Jan 1970 00:00:00 GMT";
    let (origin, pem, request_seen) = spawn_etag_precedence_tls_origin().await;
    let url = "https://lists.test/changed.txt".to_string();
    let mut mgr = ListManager::new(
        reqwest::Client::builder()
            .resolve("lists.test", origin)
            .add_root_certificate(reqwest::Certificate::from_pem(pem.as_bytes()).unwrap())
            .build()
            .unwrap(),
        Arc::new(FilterEngine::new()),
        vec![],
        Catalog::fallback(),
        Duration::from_secs(3600),
        SourceBitMap::default(),
        TEST_CAP,
        DEFAULT_MAX_LIST_ENTRIES,
        None,
    );
    mgr.cache.insert(
        url.clone(),
        ListCache {
            etag: Some("\"old\"".into()),
            last_modified: Some(last_modified.into()),
            body: Some("retained.example\n".into()),
            fetched_at: OffsetDateTime::UNIX_EPOCH,
        },
    );

    let FetchResult::Fresh(candidate) = mgr.download_list(&url, &url).await.unwrap() else {
        panic!("an ETag mismatch must return 200");
    };
    assert!(matches!(
        candidate.body,
        FreshBody::Resident(ref body) if body == "changed.example\n"
    ));
    assert_eq!(candidate.etag.as_deref(), Some("\"new\""));
    assert_eq!(candidate.last_modified.as_deref(), Some(last_modified));
    assert!(
        !request_seen
            .lock()
            .unwrap()
            .as_deref()
            .unwrap()
            .contains("if-modified-since:"),
        "the origin returns 304 when a date validator is sent"
    );
}

/// The disk-backed production branch must carry only a staged generation;
/// restoring `read_bounded_body(...)->String` here makes this pattern fail.
#[tokio::test]
async fn disk_backed_http_fresh_is_staged_and_refresh_parses_the_generation() {
    let body = "staged.example\n";
    let (origin, pem, _) = spawn_tls_origin_responses(vec![
        tls_ok_response(body, "\"staged-one\""),
        tls_ok_response(body, "\"staged-two\""),
    ])
    .await;
    let cache_dir = tempfile::tempdir().unwrap();
    let source = "https://lists.test/staged-fresh.txt".to_string();
    let mut mgr = ListManager::new(
        reqwest::Client::builder()
            .no_proxy()
            .resolve("lists.test", origin)
            .add_root_certificate(reqwest::Certificate::from_pem(pem.as_bytes()).unwrap())
            .build()
            .unwrap(),
        Arc::new(FilterEngine::new()),
        vec![source.clone()],
        Catalog::fallback(),
        Duration::from_secs(3600),
        build_source_bit_map(std::slice::from_ref(&source)).unwrap(),
        TEST_CAP,
        DEFAULT_MAX_LIST_ENTRIES,
        Some(cache_dir.path().to_path_buf()),
    );

    let FetchResult::Fresh(candidate) = mgr.download_list(&source, &source).await.unwrap() else {
        panic!("200 must produce a fresh candidate");
    };
    let FreshBody::Staged(staged) = &candidate.body else {
        panic!("disk-backed HTTP FreshDownload retained a resident body");
    };
    assert_eq!(staged.len, body.len());
    assert_eq!(std::fs::read(&staged.body_path).unwrap(), body.as_bytes());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(
            std::fs::metadata(&staged.body_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o640
        );
    }
    drop(candidate);
    assert_eq!(
        std::fs::read_dir(cache_dir.path()).unwrap().count(),
        0,
        "dropping an unselected fresh generation must reclaim it"
    );

    assert_eq!(mgr.refresh().await, 1);
    assert!(mgr.filter.is_blocked("staged.example"));
    assert_eq!(mgr.read_body_from_disk(&source).as_deref(), Some(body));
}

#[test]
fn fresh_staged_equal_length_edit_is_refused_and_rolls_back() {
    let dir = tempfile::tempdir().unwrap();
    let source = "https://lists.test/fresh-stage-edit.txt";
    let mut streamed = StreamedCacheBody::new(dir.path(), source).unwrap();
    streamed.write_chunk(b"good.example\n").unwrap();
    let staged = streamed.finish().unwrap();
    std::fs::write(&staged.body_path, b"evil.example\n").unwrap();

    let candidate = FreshDownload {
        body: FreshBody::Staged(staged),
        etag: None,
        last_modified: None,
    };
    let mut spill = ShardSpill::open(Some(dir.path())).unwrap();
    spill.push("kept.example", 1).unwrap();
    let before = spill.mark();

    let error = parse_fresh_download_into_spill_counted(
        &candidate,
        2,
        &mut spill,
        100,
        source,
        Some(ListFormat::DomainOnly),
        UniqueCount::Measure(None),
    )
    .expect_err("equal-length edits must not be admitted from a staged generation");

    assert_eq!(error.kind(), std::io::ErrorKind::Other);
    assert_eq!(spill.mark(), before, "the altered source escaped rollback");
}

#[test]
fn fresh_staged_length_plus_one_edit_is_refused_and_rolls_back() {
    let dir = tempfile::tempdir().unwrap();
    let source = "https://lists.test/fresh-stage-length.txt";
    let mut streamed = StreamedCacheBody::new(dir.path(), source).unwrap();
    streamed.write_chunk(b"good.example\n").unwrap();
    let staged = streamed.finish().unwrap();
    let staged_path = staged.body_path.clone();
    set_staged_cache_reader_constructed_hook_for_test(move || {
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(staged_path)
            .unwrap();
        file.write_all(b"x").unwrap();
    });

    let candidate = FreshDownload {
        body: FreshBody::Staged(staged),
        etag: None,
        last_modified: None,
    };
    let mut spill = ShardSpill::open(Some(dir.path())).unwrap();
    spill.push("kept.example", 1).unwrap();
    let before = spill.mark();

    assert!(
        parse_fresh_download_into_spill_counted(
            &candidate,
            2,
            &mut spill,
            100,
            source,
            Some(ListFormat::DomainOnly),
            UniqueCount::Measure(None),
        )
        .is_err(),
        "the bounded reader must retain an overflow witness"
    );
    assert_eq!(
        spill.mark(),
        before,
        "the overlong candidate escaped rollback"
    );
}

#[cfg(unix)]
#[test]
fn fresh_staged_path_replacement_is_refused_without_removing_replacement() {
    use std::os::unix::fs::PermissionsExt as _;

    let dir = tempfile::tempdir().unwrap();
    let source = "https://lists.test/fresh-stage-replacement.txt";
    let mut streamed = StreamedCacheBody::new(dir.path(), source).unwrap();
    streamed.write_chunk(b"good.example\n").unwrap();
    let staged = streamed.finish().unwrap();
    let body_path = staged.body_path.clone();
    let replacement = dir.path().join("replacement.body");
    std::fs::write(&replacement, b"evil.example\n").unwrap();
    std::fs::set_permissions(&replacement, std::fs::Permissions::from_mode(0o640)).unwrap();
    std::fs::rename(&replacement, &body_path).unwrap();

    let candidate = FreshDownload {
        body: FreshBody::Staged(staged),
        etag: None,
        last_modified: None,
    };
    let mut spill = ShardSpill::open(Some(dir.path())).unwrap();
    let before = spill.mark();
    assert!(
        parse_fresh_download_into_spill_counted(
            &candidate,
            1,
            &mut spill,
            100,
            source,
            Some(ListFormat::DomainOnly),
            UniqueCount::Measure(None),
        )
        .is_err(),
        "a replacement pathname must not be parsed through the original handle"
    );
    assert_eq!(spill.mark(), before);
    drop(candidate);
    assert_eq!(std::fs::read(&body_path).unwrap(), b"evil.example\n");
}

#[cfg(unix)]
#[test]
fn streamed_temp_path_replacement_survives_ordinary_drop() {
    let dir = tempfile::tempdir().unwrap();
    let source = "https://lists.test/streamed-temp-drop.txt";
    let streamed = StreamedCacheBody::new(dir.path(), source).unwrap();
    let temp_path = streamed.temp_path.clone().unwrap();

    replace_path_with_mode_0640(&temp_path, b"replacement.example\n");
    drop(streamed);

    assert_eq!(std::fs::read(temp_path).unwrap(), b"replacement.example\n");
}

#[cfg(unix)]
#[test]
fn streamed_promotion_authenticates_destination_before_accepting_it() {
    let dir = tempfile::tempdir().unwrap();
    let source = "https://lists.test/streamed-destination.txt";
    let body = b"good.example\n";
    let digest = hash_body(std::io::Cursor::new(body)).unwrap();
    let destination = dir.path().join(generation_basename(
        &source_to_cache_stem(source),
        &hex::encode(digest),
    ));
    let expected_destination = destination.clone();
    set_streamed_cache_body_after_persist_hook_for_test(move |path| {
        assert_eq!(path, expected_destination.as_path());
        replace_path_with_mode_0640(path, b"replacement.example\n");
    });

    let mut streamed = StreamedCacheBody::new(dir.path(), source).unwrap();
    streamed.write_chunk(body).unwrap();
    assert!(
        streamed.finish().is_err(),
        "a destination substituted after promotion must not be accepted"
    );
    assert_eq!(
        std::fs::read(destination).unwrap(),
        b"replacement.example\n"
    );
}

#[cfg(unix)]
#[test]
fn streamed_temp_replacement_before_selected_collision_preserves_both_paths() {
    let dir = tempfile::tempdir().unwrap();
    let source = "https://lists.test/streamed-temp-collision.txt";
    let body = "good.example\n";
    let selected = stage_cache_body(dir.path(), source, body).unwrap();
    commit_staged_cache_body(
        dir.path(),
        source,
        source,
        &selected,
        None,
        None,
        OffsetDateTime::now_utc(),
    )
    .unwrap();
    let selected_path = selected.body_path.clone();
    drop(selected);

    let mut streamed = StreamedCacheBody::new(dir.path(), source).unwrap();
    streamed.write_chunk(body.as_bytes()).unwrap();
    let temp_path = streamed.temp_path.clone().unwrap();
    replace_path_with_mode_0640(&temp_path, b"replacement.example\n");

    assert!(
        streamed.finish().is_err(),
        "a substituted spool must not reach a selected-generation collision"
    );
    assert_eq!(std::fs::read(&temp_path).unwrap(), b"replacement.example\n");
    assert_eq!(std::fs::read(&selected_path).unwrap(), body.as_bytes());
}

#[cfg(unix)]
#[test]
fn streamed_stage_rejects_existing_generation_symlink() {
    use std::os::unix::fs::PermissionsExt as _;

    let dir = tempfile::tempdir().unwrap();
    let external = tempfile::tempdir().unwrap();
    let source = "https://lists.test/streamed-symlink.txt";
    let body = b"good.example\n";
    let target = external.path().join("external.body");
    std::fs::write(&target, body).unwrap();
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o640)).unwrap();
    let digest = hash_body(std::io::Cursor::new(body)).unwrap();
    let basename = generation_basename(&source_to_cache_stem(source), &hex::encode(digest));
    std::os::unix::fs::symlink(&target, dir.path().join(basename)).unwrap();

    let mut streamed = StreamedCacheBody::new(dir.path(), source).unwrap();
    streamed.write_chunk(body).unwrap();
    assert!(
        streamed.finish().is_err(),
        "a content-addressed collision must not adopt a symlink"
    );
    assert_eq!(std::fs::read(&target).unwrap(), body);
}

#[cfg(unix)]
#[test]
fn streamed_stage_rejects_matching_collision_without_the_staging_mode() {
    use std::os::unix::fs::PermissionsExt as _;

    let dir = tempfile::tempdir().unwrap();
    let source = "https://lists.test/streamed-mode.txt";
    let body = b"good.example\n";
    let digest = hash_body(std::io::Cursor::new(body)).unwrap();
    let basename = generation_basename(&source_to_cache_stem(source), &hex::encode(digest));
    let collision = dir.path().join(basename);
    std::fs::write(&collision, body).unwrap();
    std::fs::set_permissions(&collision, std::fs::Permissions::from_mode(0o600)).unwrap();

    let mut streamed = StreamedCacheBody::new(dir.path(), source).unwrap();
    streamed.write_chunk(body).unwrap();
    assert!(
        streamed.finish().is_err(),
        "a matching collision without the owned 0640 contract must be rejected"
    );
    assert_eq!(std::fs::read(&collision).unwrap(), body);
}

#[test]
fn streamed_stage_reuses_a_selected_matching_regular_generation() {
    let dir = tempfile::tempdir().unwrap();
    let source = "https://lists.test/streamed-reuse.txt";
    let body = "good.example\n";
    let selected = stage_cache_body(dir.path(), source, body).unwrap();
    commit_staged_cache_body(
        dir.path(),
        source,
        source,
        &selected,
        None,
        None,
        OffsetDateTime::now_utc(),
    )
    .unwrap();
    let selected_path = selected.body_path.clone();
    drop(selected);

    let mut streamed = StreamedCacheBody::new(dir.path(), source).unwrap();
    streamed.write_chunk(body.as_bytes()).unwrap();
    let reused = streamed.finish().unwrap();
    assert_eq!(reused.body_path, selected_path);
    drop(reused);
    assert_eq!(std::fs::read(&selected_path).unwrap(), body.as_bytes());
}

#[test]
fn streamed_collision_mutation_is_refused_without_deleting_selected_generation() {
    let dir = tempfile::tempdir().unwrap();
    let source = "https://lists.test/streamed-collision-mutation.txt";
    let body = "good.example\n";
    let selected = stage_cache_body(dir.path(), source, body).unwrap();
    commit_staged_cache_body(
        dir.path(),
        source,
        source,
        &selected,
        None,
        None,
        OffsetDateTime::now_utc(),
    )
    .unwrap();
    let selected_path = selected.body_path.clone();
    drop(selected);

    let mut streamed = StreamedCacheBody::new(dir.path(), source).unwrap();
    streamed.write_chunk(body.as_bytes()).unwrap();
    let reused = streamed.finish().unwrap();
    std::fs::write(&reused.body_path, b"evil.example\n").unwrap();

    let candidate = FreshDownload {
        body: FreshBody::Staged(reused),
        etag: None,
        last_modified: None,
    };
    let mut spill = ShardSpill::open(Some(dir.path())).unwrap();
    let before = spill.mark();
    assert!(
        parse_fresh_download_into_spill_counted(
            &candidate,
            1,
            &mut spill,
            100,
            source,
            Some(ListFormat::DomainOnly),
            UniqueCount::Measure(None),
        )
        .is_err(),
        "a reused collision must be authenticated through its retained handle"
    );
    assert_eq!(spill.mark(), before);
    drop(candidate);
    assert_eq!(std::fs::read(&selected_path).unwrap(), b"evil.example\n");
}

#[tokio::test]
async fn restored_staged_mutation_cannot_publish_or_commit_the_wrong_corpus() {
    let old = "kept.example\n";
    let fresh = "fresh.example\n";
    let altered = "other.example\n";
    assert_eq!(fresh.len(), altered.len());
    let (origin, pem, _) = spawn_tls_origin_responses(vec![
        tls_ok_response(old, "\"old\""),
        tls_ok_response(fresh, "\"fresh\""),
    ])
    .await;
    let cache_dir = tempfile::tempdir().unwrap();
    let source = "https://lists.test/restored-stage-mutation.txt".to_string();
    let mut mgr = ListManager::new(
        reqwest::Client::builder()
            .no_proxy()
            .resolve("lists.test", origin)
            .add_root_certificate(reqwest::Certificate::from_pem(pem.as_bytes()).unwrap())
            .build()
            .unwrap(),
        Arc::new(FilterEngine::new()),
        vec![source.clone()],
        Catalog::fallback(),
        Duration::from_secs(3600),
        build_source_bit_map(std::slice::from_ref(&source)).unwrap(),
        TEST_CAP,
        DEFAULT_MAX_LIST_ENTRIES,
        Some(cache_dir.path().to_path_buf()),
    );

    assert_eq!(mgr.refresh().await, 1);
    let selected = selected_cache_body_path(cache_dir.path(), &source).unwrap();
    let meta_path = cache_dir
        .path()
        .join(format!("{}.meta", source_to_cache_stem(&source)));
    let old_meta = std::fs::read(&meta_path).unwrap();
    let old_cache = mgr.cache.get(&source).unwrap().clone();
    let candidate_path = Arc::new(std::sync::Mutex::new(None));
    let candidate_path_for_hook = Arc::clone(&candidate_path);
    let cache_dir_for_hook = cache_dir.path().to_path_buf();
    let source_for_hook = source.clone();
    let selected_for_hook = selected.clone();
    mgr.set_worker_hook_for_test(move |at| {
        if at == "staged_body" {
            let path =
                generation_body_paths(&cache_dir_for_hook, &source_to_cache_stem(&source_for_hook))
                    .into_iter()
                    .find(|path| path != &selected_for_hook)
                    .expect("fresh candidate must be staged before it is parsed");
            std::fs::write(&path, altered).unwrap();
            *candidate_path_for_hook.lock().unwrap() = Some(path);
        } else if at == "parsed" {
            if let Some(path) = candidate_path_for_hook.lock().unwrap().as_ref() {
                // The vulnerable path still has a pending candidate here;
                // restore it so commit cannot expose the earlier mutation.
                if path.is_file() {
                    std::fs::write(path, fresh).unwrap();
                }
            }
        }
    });

    let RefreshWorkerOutcome::Completed { manager, .. } =
        spawn_list_refresh_worker(mgr, RefreshMode::Force, RefreshCancellation::default())
            .await
            .unwrap()
    else {
        panic!("a rejected candidate with a retained body should complete the cycle");
    };

    assert!(manager.filter.is_blocked("kept.example"));
    assert!(!manager.filter.is_blocked("fresh.example"));
    assert!(!manager.filter.is_blocked("other.example"));
    assert_eq!(
        selected_cache_body_path(cache_dir.path(), &source),
        Some(selected.clone())
    );
    assert_eq!(std::fs::read(&selected).unwrap(), old.as_bytes());
    assert_eq!(std::fs::read(&meta_path).unwrap(), old_meta);
    assert_eq!(manager.cache.get(&source), Some(&old_cache));
    assert_eq!(
        generation_body_paths(cache_dir.path(), &source_to_cache_stem(&source)),
        vec![selected],
        "the rejected candidate must not survive the cycle"
    );
}

#[tokio::test]
async fn streamed_shrink_refusal_retains_selected_body_without_an_orphan() {
    let old: String = (0..20).map(|n| format!("old-{n}.example\n")).collect();
    let replacement = "replacement.example\n";
    let (origin, pem, _) = spawn_tls_origin_responses(vec![
        tls_ok_response(&old, "\"old\""),
        tls_ok_response(replacement, "\"replacement\""),
    ])
    .await;
    let cache_dir = tempfile::tempdir().unwrap();
    let source = "https://lists.test/streamed-shrink.txt".to_string();
    let mut mgr = ListManager::new(
        reqwest::Client::builder()
            .no_proxy()
            .resolve("lists.test", origin)
            .add_root_certificate(reqwest::Certificate::from_pem(pem.as_bytes()).unwrap())
            .build()
            .unwrap(),
        Arc::new(FilterEngine::new()),
        vec![source.clone()],
        Catalog::fallback(),
        Duration::from_secs(3600),
        build_source_bit_map(std::slice::from_ref(&source)).unwrap(),
        TEST_CAP,
        DEFAULT_MAX_LIST_ENTRIES,
        Some(cache_dir.path().to_path_buf()),
    );

    assert_eq!(mgr.refresh().await, 20);
    let selected = selected_cache_body_path(cache_dir.path(), &source).unwrap();
    let meta_path = cache_dir
        .path()
        .join(format!("{}.meta", source_to_cache_stem(&source)));
    let old_meta = std::fs::read(&meta_path).unwrap();
    let old_bytes = std::fs::read(&selected).unwrap();
    age_cache_entries(&mut mgr);

    assert_eq!(mgr.refresh().await, 20);
    assert_eq!(
        selected_cache_body_path(cache_dir.path(), &source),
        Some(selected.clone())
    );
    assert_eq!(std::fs::read(&selected).unwrap(), old_bytes);
    assert_eq!(std::fs::read(&meta_path).unwrap(), old_meta);
    assert_eq!(
        generation_body_paths(cache_dir.path(), &source_to_cache_stem(&source)),
        vec![selected],
        "a refused streamed candidate must not leave an unselected generation"
    );
    assert!(mgr.filter.is_blocked("old-0.example"));
    assert!(!mgr.filter.is_blocked("replacement.example"));
}

#[tokio::test]
async fn streamed_cache_write_failure_keeps_selected_body_and_leaves_no_temp() {
    let old = "old.example\n";
    let replacement = "replacement.example\n";
    let (origin, pem, _) = spawn_tls_origin_responses(vec![
        tls_ok_response(old, "\"old\""),
        tls_ok_response(replacement, "\"replacement\""),
    ])
    .await;
    let cache_dir = tempfile::tempdir().unwrap();
    let source = "https://lists.test/streamed-write-failure.txt".to_string();
    let mut mgr = ListManager::new(
        reqwest::Client::builder()
            .no_proxy()
            .resolve("lists.test", origin)
            .add_root_certificate(reqwest::Certificate::from_pem(pem.as_bytes()).unwrap())
            .build()
            .unwrap(),
        Arc::new(FilterEngine::new()),
        vec![source.clone()],
        Catalog::fallback(),
        Duration::from_secs(3600),
        build_source_bit_map(std::slice::from_ref(&source)).unwrap(),
        TEST_CAP,
        DEFAULT_MAX_LIST_ENTRIES,
        Some(cache_dir.path().to_path_buf()),
    );

    assert_eq!(mgr.refresh().await, 1);
    let selected = selected_cache_body_path(cache_dir.path(), &source).unwrap();
    let before: BTreeSet<_> = std::fs::read_dir(cache_dir.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    age_cache_entries(&mut mgr);
    fail_nth_streamed_cache_body_write_for_test(1);

    assert_eq!(mgr.refresh_with_mode(RefreshMode::Force).await, 1);
    let after: BTreeSet<_> = std::fs::read_dir(cache_dir.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert_eq!(after, before);
    assert_eq!(std::fs::read(&selected).unwrap(), old.as_bytes());
    assert_eq!(mgr.read_body_from_disk(&source).as_deref(), Some(old));
    assert!(mgr.filter.is_blocked("old.example"));
    assert!(!mgr.filter.is_blocked("replacement.example"));
}

#[tokio::test]
async fn cancellation_after_streamed_stage_reclaims_the_unselected_generation() {
    let old = "old.example\n";
    let replacement = "replacement.example\n";
    let (origin, pem, _) = spawn_tls_origin_responses(vec![
        tls_ok_response(old, "\"old\""),
        tls_ok_response(replacement, "\"replacement\""),
    ])
    .await;
    let cache_dir = tempfile::tempdir().unwrap();
    let source = "https://lists.test/streamed-cancel.txt".to_string();
    let mut mgr = ListManager::new(
        reqwest::Client::builder()
            .no_proxy()
            .resolve("lists.test", origin)
            .add_root_certificate(reqwest::Certificate::from_pem(pem.as_bytes()).unwrap())
            .build()
            .unwrap(),
        Arc::new(FilterEngine::new()),
        vec![source.clone()],
        Catalog::fallback(),
        Duration::from_secs(3600),
        build_source_bit_map(std::slice::from_ref(&source)).unwrap(),
        TEST_CAP,
        DEFAULT_MAX_LIST_ENTRIES,
        Some(cache_dir.path().to_path_buf()),
    );

    assert_eq!(mgr.refresh().await, 1);
    let selected = selected_cache_body_path(cache_dir.path(), &source).unwrap();
    let before: BTreeSet<_> = std::fs::read_dir(cache_dir.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    let signal = RefreshCancellation::default();
    let cancel = signal.clone();
    mgr.set_worker_hook_for_test(move |at| {
        if at == "staged_body" {
            cancel.cancel();
        }
    });

    let RefreshWorkerOutcome::Cancelled { manager } =
        spawn_list_refresh_worker(mgr, RefreshMode::Force, signal)
            .await
            .unwrap()
    else {
        panic!("cancellation after a staged body must prevent publication");
    };
    let after: BTreeSet<_> = std::fs::read_dir(cache_dir.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert_eq!(after, before);
    assert_eq!(std::fs::read(&selected).unwrap(), old.as_bytes());
    assert!(manager.filter.is_blocked("old.example"));
    assert!(!manager.filter.is_blocked("replacement.example"));
}

#[cfg(unix)]
#[tokio::test]
async fn cancellation_after_streamed_temp_substitution_preserves_replacement_and_prior_state() {
    let old = "old.example\n";
    let fresh = "fresh.example\n";
    let (origin, pem, _) = spawn_tls_origin_responses(vec![
        tls_ok_response(old, "\"old\""),
        tls_ok_response(fresh, "\"fresh\""),
    ])
    .await;
    let cache_dir = tempfile::tempdir().unwrap();
    let source = "https://lists.test/streamed-temp-cancel.txt".to_string();
    let mut mgr = ListManager::new(
        reqwest::Client::builder()
            .no_proxy()
            .resolve("lists.test", origin)
            .add_root_certificate(reqwest::Certificate::from_pem(pem.as_bytes()).unwrap())
            .build()
            .unwrap(),
        Arc::new(FilterEngine::new()),
        vec![source.clone()],
        Catalog::fallback(),
        Duration::from_secs(3600),
        build_source_bit_map(std::slice::from_ref(&source)).unwrap(),
        TEST_CAP,
        DEFAULT_MAX_LIST_ENTRIES,
        Some(cache_dir.path().to_path_buf()),
    );

    assert_eq!(mgr.refresh().await, 1);
    let selected = selected_cache_body_path(cache_dir.path(), &source).unwrap();
    let meta_path = cache_dir
        .path()
        .join(format!("{}.meta", source_to_cache_stem(&source)));
    let old_meta = std::fs::read(&meta_path).unwrap();
    let old_cache = mgr.cache.get(&source).unwrap().clone();
    let substituted_temp = Arc::new(std::sync::Mutex::new(None));
    let substituted_temp_for_hook = Arc::clone(&substituted_temp);
    let cache_dir_for_hook = cache_dir.path().to_path_buf();
    let signal = RefreshCancellation::default();
    let cancel = signal.clone();
    mgr.set_worker_hook_for_test(move |at| {
        if at == "staged_body_write" {
            let temp_path = streamed_temp_path_in(&cache_dir_for_hook);
            replace_path_with_mode_0640(&temp_path, b"replacement.example\n");
            *substituted_temp_for_hook.lock().unwrap() = Some(temp_path);
            cancel.cancel();
        }
    });

    let RefreshWorkerOutcome::Cancelled { manager } =
        spawn_list_refresh_worker(mgr, RefreshMode::Force, signal)
            .await
            .unwrap()
    else {
        panic!("cancellation after a substituted streamed spool must stop publication");
    };
    let temp_path = substituted_temp.lock().unwrap().take().unwrap();
    assert_eq!(std::fs::read(temp_path).unwrap(), b"replacement.example\n");
    assert_eq!(std::fs::read(&selected).unwrap(), old.as_bytes());
    assert_eq!(std::fs::read(&meta_path).unwrap(), old_meta);
    assert_eq!(manager.cache.get(&source), Some(&old_cache));
    assert!(manager.filter.is_blocked("old.example"));
    assert!(!manager.filter.is_blocked("fresh.example"));
}

#[tokio::test]
async fn cancellation_at_each_streamed_cache_io_boundary_reclaims_the_candidate() {
    let old = "old.example\n";
    let replacement = "replacement.example\n";
    let (origin, pem, _) = spawn_tls_origin_responses(
        std::iter::once(tls_ok_response(old, "\"old\""))
            .chain(
                [
                    "staged_body_write",
                    "staged_body_flush",
                    "staged_body_sync",
                    "staged_body_promote",
                    "staged_body_parent_fsync",
                ]
                .into_iter()
                .map(|_| tls_ok_response(replacement, "\"replacement\"")),
            )
            .collect(),
    )
    .await;
    let cache_dir = tempfile::tempdir().unwrap();
    let source = "https://lists.test/streamed-io-cancel.txt".to_string();
    let mut mgr = ListManager::new(
        reqwest::Client::builder()
            .no_proxy()
            .resolve("lists.test", origin)
            .add_root_certificate(reqwest::Certificate::from_pem(pem.as_bytes()).unwrap())
            .build()
            .unwrap(),
        Arc::new(FilterEngine::new()),
        vec![source.clone()],
        Catalog::fallback(),
        Duration::from_secs(3600),
        build_source_bit_map(std::slice::from_ref(&source)).unwrap(),
        TEST_CAP,
        DEFAULT_MAX_LIST_ENTRIES,
        Some(cache_dir.path().to_path_buf()),
    );

    assert_eq!(mgr.refresh().await, 1);
    let selected = selected_cache_body_path(cache_dir.path(), &source).unwrap();
    let before: BTreeSet<_> = std::fs::read_dir(cache_dir.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();

    for target in [
        "staged_body_write",
        "staged_body_flush",
        "staged_body_sync",
        "staged_body_promote",
        "staged_body_parent_fsync",
    ] {
        let signal = RefreshCancellation::default();
        let cancel = signal.clone();
        mgr.set_worker_hook_for_test(move |at| {
            if at == target {
                cancel.cancel();
            }
        });
        let RefreshWorkerOutcome::Cancelled { manager } =
            spawn_list_refresh_worker(mgr, RefreshMode::Force, signal)
                .await
                .unwrap()
        else {
            panic!("cancellation at {target} must prevent publication");
        };
        mgr = manager;
        let after: BTreeSet<_> = std::fs::read_dir(cache_dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(
            after, before,
            "cancellation at {target} leaked a cache file"
        );
        assert_eq!(std::fs::read(&selected).unwrap(), old.as_bytes());
        assert!(mgr.filter.is_blocked("old.example"));
        assert!(!mgr.filter.is_blocked("replacement.example"));
    }
}

#[tokio::test]
async fn streamed_cache_body_caps_decompressed_response_and_cleans_up() {
    const CAP: usize = 1024 * 1024;
    let body = "bomb.example\n".repeat((2 * CAP) / "bomb.example\n".len());
    let origin = MockOrigin::new(&body, true);
    let addr = spawn_mock_origin(Arc::clone(&origin)).await;
    let url = format!("http://{addr}/over-cap.txt");
    let response = test_bulk_client().get(&url).send().await.unwrap();
    let cache_dir = tempfile::tempdir().unwrap();
    let source = "https://lists.test/over-cap.txt";
    let old = stage_cache_body(cache_dir.path(), source, "old.example\n").unwrap();
    commit_staged_cache_body(
        cache_dir.path(),
        source,
        source,
        &old,
        Some("\"old\""),
        None,
        OffsetDateTime::now_utc(),
    )
    .unwrap();
    let selected = selected_cache_body_path(cache_dir.path(), source).unwrap();
    let meta = cache_dir
        .path()
        .join(format!("{}.meta", source_to_cache_stem(source)));
    let old_meta = std::fs::read(&meta).unwrap();
    let before: BTreeSet<_> = std::fs::read_dir(cache_dir.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();

    let result = stage_bounded_response_body(response, &url, source, cache_dir.path(), CAP).await;
    assert!(matches!(result, Err(ListError::TooLarge { max: CAP, .. })));
    assert_eq!(
        std::fs::read_dir(cache_dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<BTreeSet<_>>(),
        before,
        "an over-cap decoded stream must not leave staging or alter the selected generation"
    );
    assert_eq!(std::fs::read(&selected).unwrap(), b"old.example\n");
    assert_eq!(std::fs::read(&meta).unwrap(), old_meta);
    assert!(
        origin.body_bytes_on_wire() < CAP / 10,
        "fixture must be compressed enough to exercise decoded-byte accounting"
    );
}

#[test]
fn streamed_cache_lossy_utf8_matches_whole_body_across_split_invalid_sequence() {
    use sha2::Digest;

    let raw = b"good.example\ninvalid-\xF0\x9F\xFF.example\nalso.example\n";
    let expected = String::from_utf8_lossy(raw).into_owned();
    let source = "https://lists.test/lossy-chunks.txt";
    for split in 0..=raw.len() {
        let cache_dir = tempfile::tempdir().unwrap();
        let mut streamed = StreamedCacheBody::new(cache_dir.path(), source).unwrap();
        streamed.write_chunk(&raw[..split]).unwrap();
        streamed.write_chunk(&raw[split..]).unwrap();
        let staged = streamed.finish().unwrap();
        let stored = std::fs::read(&staged.body_path).unwrap();

        assert_eq!(
            stored,
            expected.as_bytes(),
            "lossy bytes differ at split {split}"
        );
        assert_eq!(
            staged.sha256,
            hex::encode(sha2::Sha256::digest(&stored)),
            "content address differs at split {split}"
        );
        let parsed = crate::lists::parser::parse_domain_list(std::str::from_utf8(&stored).unwrap());
        assert!(parsed.contains("good.example"));
        assert!(parsed.contains("also.example"));
        assert_eq!(parsed.len(), 2, "only the malformed line is discarded");
        drop(staged);
        assert!(
            generation_body_paths(cache_dir.path(), &source_to_cache_stem(source)).is_empty(),
            "dropping an unselected lossy generation must reclaim it"
        );
    }
}

#[tokio::test]
async fn accepted_fresh_refresh_commits_candidate_validators_at_the_cycle_anchor() {
    let last_modified = "Thu, 01 Jan 1970 00:00:00 GMT";
    let (origin, pem, _) = spawn_tls_origin_responses(vec![tls_ok_response_with_last_modified(
        "accepted.example\n",
        "\"accepted\"",
        last_modified,
    )])
    .await;
    let url = "https://lists.test/accepted.txt".to_string();
    let anchor = time::macros::datetime!(2026-09-05 12:00:00 UTC);
    let mut mgr = ListManager::new(
        reqwest::Client::builder()
            .resolve("lists.test", origin)
            .add_root_certificate(reqwest::Certificate::from_pem(pem.as_bytes()).unwrap())
            .build()
            .unwrap(),
        Arc::new(FilterEngine::new()),
        vec![url.clone()],
        Catalog::fallback(),
        Duration::from_secs(3600),
        build_source_bit_map(std::slice::from_ref(&url)).unwrap(),
        TEST_CAP,
        DEFAULT_MAX_LIST_ENTRIES,
        None,
    );
    mgr.cache.insert(
        url.clone(),
        ListCache {
            etag: Some("\"retained\"".into()),
            last_modified: Some("Wed, 31 Dec 1969 00:00:00 GMT".into()),
            body: Some("retained.example\n".into()),
            fetched_at: anchor - time::Duration::hours(2),
        },
    );

    assert_eq!(mgr.refresh_at(anchor).await, 1);
    let entry = mgr.cache.get(&url).unwrap();
    assert_eq!(entry.etag.as_deref(), Some("\"accepted\""));
    assert_eq!(entry.last_modified.as_deref(), Some(last_modified));
    assert_eq!(entry.fetched_at, anchor);
}

#[tokio::test]
async fn stage_write_failure_records_a_schedule_failure() {
    use sha2::Digest;

    let old = "old.example\n";
    let candidate = "candidate.example\n";
    let (origin, pem, _) = spawn_tls_origin_responses(vec![
        tls_ok_response(old, "\"old\""),
        tls_ok_response(candidate, "\"candidate\""),
    ])
    .await;
    let url = "https://lists.test/stage-write-fault.txt".to_string();
    let cache_dir = tempfile::tempdir().unwrap();
    let mut mgr = ListManager::new(
        reqwest::Client::builder()
            .resolve("lists.test", origin)
            .add_root_certificate(reqwest::Certificate::from_pem(pem.as_bytes()).unwrap())
            .build()
            .unwrap(),
        Arc::new(FilterEngine::new()),
        vec![url.clone()],
        Catalog::fallback(),
        Duration::from_secs(3600),
        build_source_bit_map(std::slice::from_ref(&url)).unwrap(),
        TEST_CAP,
        DEFAULT_MAX_LIST_ENTRIES,
        Some(cache_dir.path().to_path_buf()),
    );
    let key = install_test_schedule(&mut mgr, &url);
    let anchor = time::macros::datetime!(2026-09-05 12:00:00 UTC);
    assert_eq!(mgr.refresh_at(anchor).await, 1);
    let candidate_sha = hex::encode(sha2::Sha256::digest(candidate.as_bytes()));
    let blocked_path = cache_dir.path().join(generation_basename(
        &source_to_cache_stem(&url),
        &candidate_sha,
    ));
    std::fs::create_dir(&blocked_path).unwrap();
    mgr.schedule_state
        .record_success(key.clone(), anchor - time::Duration::hours(2));

    assert_eq!(mgr.refresh_at(anchor + time::Duration::hours(2)).await, 1);
    let entry = mgr.schedule_state.lookup(&key).unwrap();
    assert_eq!(entry.last_attempt, anchor + time::Duration::hours(2));
    assert_eq!(entry.outcome, CanonicalScheduleOutcome::Failure);
    assert!(mgr.filter.is_blocked("old.example"));
    assert!(!mgr.filter.is_blocked("candidate.example"));
}

#[tokio::test]
async fn deferred_persistence_failure_keeps_durable_cache_and_records_failure() {
    let (origin, pem, _) = spawn_tls_origin_responses(vec![
        tls_ok_response("old.example\n", "\"old\""),
        tls_ok_response("new.example\n", "\"new\""),
    ])
    .await;
    let url = "https://lists.test/persist.txt".to_string();
    let cache_dir = tempfile::tempdir().unwrap();
    let id = crate::config::schema::Id::new("persist-fault").unwrap();
    let mut mgr = ListManager::new(
        reqwest::Client::builder()
            .resolve("lists.test", origin)
            .add_root_certificate(reqwest::Certificate::from_pem(pem.as_bytes()).unwrap())
            .build()
            .unwrap(),
        Arc::new(FilterEngine::new()),
        vec![url.clone()],
        Catalog::fallback(),
        Duration::from_secs(3600),
        build_source_bit_map(std::slice::from_ref(&url)).unwrap(),
        TEST_CAP,
        DEFAULT_MAX_LIST_ENTRIES,
        Some(cache_dir.path().to_path_buf()),
    );
    mgr.set_source_blocklist_map(HashMap::from([(url.clone(), (id.clone(), 2))]));
    let schedule_key = install_test_schedule(&mut mgr, &url);
    let anchor = time::macros::datetime!(2026-09-05 12:00:00 UTC);
    assert_eq!(mgr.refresh_at(anchor).await, 1);
    let old_digest = mgr.installed_corpus_digest;
    let stem = source_to_cache_stem(&url);
    let meta_path = cache_dir.path().join(format!("{stem}.meta"));
    let meta = std::fs::read_to_string(&meta_path).unwrap();
    age_cache_entries(&mut mgr);
    let retained = mgr.cache.get(&url).unwrap().clone();
    let retained_retry = mgr.list_state_handle().lock().unwrap().lists[&id].clone();
    mgr.schedule_state
        .record_success(schedule_key.clone(), anchor - time::Duration::hours(2));
    fail_next_cache_manifest_write_for_test();

    assert_eq!(mgr.refresh_at(anchor + time::Duration::hours(2)).await, 1);
    assert_eq!(mgr.cache.get(&url), Some(&retained));
    assert_eq!(std::fs::read_to_string(meta_path).unwrap(), meta);
    assert!(mgr.filter.list_membership("old.example").is_empty());
    assert!(!mgr.filter.list_membership("new.example").is_empty());
    assert_ne!(mgr.installed_corpus_digest, old_digest);
    assert_eq!(
        mgr.status_registry.cycle().outcome,
        Some(CycleOutcome::Installed),
        "the candidate corpus is live even though its cache commit failed"
    );
    assert!(matches!(
        mgr.status_registry
            .status_for_url(&url)
            .unwrap()
            .last_outcome,
        LastOutcome::Failed { .. }
    ));
    let retry = mgr.list_state_handle().lock().unwrap().lists[&id].clone();
    assert_eq!(
        retry.consecutive_failures,
        retained_retry.consecutive_failures + 1
    );
    assert_eq!(retry.last_success, retained_retry.last_success);
    assert_eq!(retry.cache_path, retained_retry.cache_path);
    let schedule = mgr.schedule_state.lookup(&schedule_key).unwrap();
    assert_eq!(schedule.last_attempt, anchor + time::Duration::hours(2));
    assert_eq!(schedule.outcome, CanonicalScheduleOutcome::Failure);
}

#[tokio::test]
async fn unusable_304_retries_unconditionally_and_commits_replacement() {
    let (origin, pem, requests) = spawn_tls_origin_responses(vec![
        tls_ok_response(
            "old-one.example\nold-two.example\nold-three.example\n",
            "\"old\"",
        ),
        "HTTP/1.1 304 Not Modified\r\nConnection: close\r\n\r\n".to_string(),
        tls_ok_response("replacement.example\n", "\"new\""),
    ])
    .await;
    let url = "https://lists.test/retry.txt".to_string();
    let cache_dir = tempfile::tempdir().unwrap();
    let mut mgr = ListManager::new(
        reqwest::Client::builder()
            .resolve("lists.test", origin)
            .add_root_certificate(reqwest::Certificate::from_pem(pem.as_bytes()).unwrap())
            .build()
            .unwrap(),
        Arc::new(FilterEngine::new()),
        vec![url.clone()],
        Catalog::fallback(),
        Duration::from_secs(3600),
        build_source_bit_map(std::slice::from_ref(&url)).unwrap(),
        TEST_CAP,
        4,
        Some(cache_dir.path().to_path_buf()),
    );
    assert_eq!(mgr.refresh().await, 3);
    mgr.set_source_max_entries(HashMap::from([(url.clone(), 2)]));
    age_cache_entries(&mut mgr);
    assert_eq!(mgr.refresh().await, 1);
    let requests = requests.lock().unwrap();
    assert_eq!(requests.len(), 3);
    assert!(requests[1].contains("if-none-match: \"old\""));
    assert!(!requests[2].contains("if-none-match:") && !requests[2].contains("if-modified-since:"));
    assert!(!mgr.filter.list_membership("replacement.example").is_empty());
    assert_eq!(mgr.cache[&url].etag.as_deref(), Some("\"new\""));
}

#[tokio::test]
async fn retry_200_staged_mutation_cannot_publish_or_commit_the_wrong_corpus() {
    let old = "old-one.example\nold-two.example\nold-three.example\n";
    let fresh = "fresh.example\n";
    let altered = "other.example\n";
    assert_eq!(fresh.len(), altered.len());
    let (origin, pem, requests) = spawn_tls_origin_responses(vec![
        tls_ok_response(old, "\"old\""),
        "HTTP/1.1 304 Not Modified\r\nConnection: close\r\n\r\n".to_string(),
        tls_ok_response(fresh, "\"new\""),
    ])
    .await;
    let source = "https://lists.test/retry-mutation.txt".to_string();
    let cache_dir = tempfile::tempdir().unwrap();
    let mut mgr = ListManager::new(
        reqwest::Client::builder()
            .no_proxy()
            .resolve("lists.test", origin)
            .add_root_certificate(reqwest::Certificate::from_pem(pem.as_bytes()).unwrap())
            .build()
            .unwrap(),
        Arc::new(FilterEngine::new()),
        vec![source.clone()],
        Catalog::fallback(),
        Duration::from_secs(3600),
        build_source_bit_map(std::slice::from_ref(&source)).unwrap(),
        TEST_CAP,
        4,
        Some(cache_dir.path().to_path_buf()),
    );

    assert_eq!(mgr.refresh().await, 3);
    let selected = selected_cache_body_path(cache_dir.path(), &source).unwrap();
    let meta_path = cache_dir
        .path()
        .join(format!("{}.meta", source_to_cache_stem(&source)));
    let old_meta = std::fs::read(&meta_path).unwrap();
    mgr.set_source_max_entries(HashMap::from([(source.clone(), 2)]));
    age_cache_entries(&mut mgr);
    let old_cache = mgr.cache.get(&source).unwrap().clone();

    let staged_path = Arc::new(std::sync::Mutex::new(None));
    let staged_path_for_hook = Arc::clone(&staged_path);
    let cache_dir_for_hook = cache_dir.path().to_path_buf();
    let source_for_hook = source.clone();
    let selected_for_hook = selected.clone();
    mgr.set_worker_hook_for_test(move |at| {
        if at == "staged_body" {
            let path =
                generation_body_paths(&cache_dir_for_hook, &source_to_cache_stem(&source_for_hook))
                    .into_iter()
                    .find(|path| path != &selected_for_hook)
                    .expect("the unconditional retry must stage a fresh candidate");
            std::fs::write(&path, altered).unwrap();
            *staged_path_for_hook.lock().unwrap() = Some(path);
        }
    });

    let RefreshWorkerOutcome::Completed { manager, .. } =
        spawn_list_refresh_worker(mgr, RefreshMode::Force, RefreshCancellation::default())
            .await
            .unwrap()
    else {
        panic!("a rejected retry candidate must complete the cycle");
    };
    assert!(staged_path.lock().unwrap().is_some());
    assert_eq!(std::fs::read(&selected).unwrap(), old.as_bytes());
    assert_eq!(std::fs::read(&meta_path).unwrap(), old_meta);
    assert_eq!(manager.cache.get(&source), Some(&old_cache));
    assert!(manager.filter.is_blocked("old-one.example"));
    assert!(!manager.filter.is_blocked("fresh.example"));
    assert!(!manager.filter.is_blocked("other.example"));
    assert_eq!(
        generation_body_paths(cache_dir.path(), &source_to_cache_stem(&source)),
        vec![selected],
        "the rejected retry generation must not survive"
    );
    let requests = requests.lock().unwrap();
    assert_eq!(requests.len(), 3);
    assert!(requests[1].contains("if-none-match: \"old\""));
    assert!(!requests[2].contains("if-none-match:") && !requests[2].contains("if-modified-since:"));
}

#[tokio::test]
async fn metadata_failure_after_valid_304_keeps_timestamp_and_records_failure() {
    let (origin, pem, _) = spawn_tls_origin_responses(vec![
        tls_ok_response("old.example\n", "\"old\""),
        "HTTP/1.1 304 Not Modified\r\nConnection: close\r\n\r\n".to_string(),
    ])
    .await;
    let url = "https://lists.test/meta.txt".to_string();
    let cache_dir = tempfile::tempdir().unwrap();
    let id = crate::config::schema::Id::new("meta-fault").unwrap();
    let mut mgr = ListManager::new(
        reqwest::Client::builder()
            .resolve("lists.test", origin)
            .add_root_certificate(reqwest::Certificate::from_pem(pem.as_bytes()).unwrap())
            .build()
            .unwrap(),
        Arc::new(FilterEngine::new()),
        vec![url.clone()],
        Catalog::fallback(),
        Duration::from_secs(3600),
        build_source_bit_map(std::slice::from_ref(&url)).unwrap(),
        TEST_CAP,
        DEFAULT_MAX_LIST_ENTRIES,
        Some(cache_dir.path().to_path_buf()),
    );
    mgr.set_source_blocklist_map(HashMap::from([(url.clone(), (id.clone(), 2))]));
    let schedule_key = install_test_schedule(&mut mgr, &url);
    assert_eq!(mgr.refresh().await, 1);
    let meta_path = cache_dir
        .path()
        .join(format!("{}.meta", source_to_cache_stem(&url)));
    let old_meta = std::fs::read_to_string(&meta_path).unwrap();
    age_cache_entries(&mut mgr);
    let old_time = mgr.cache[&url].fetched_at;
    let old_digest = mgr.installed_corpus_digest;
    let generations = mgr.filter.filter_gen_ids();
    // Force a rebuild so retained membership cannot pass via the old generation.
    mgr.installed_corpus_digest = None;
    mgr.legacy_cache_timestamp_urls.insert(url.clone());
    mgr.record_blocklist_failure(&id, 2);
    let old_state = mgr.list_state_handle().lock().unwrap().lists[&id].clone();
    mgr.schedule_state.record_success(
        schedule_key.clone(),
        OffsetDateTime::now_utc() - time::Duration::hours(2),
    );
    fail_next_cache_manifest_write_for_test();

    assert_eq!(mgr.refresh().await, 1);
    assert_eq!(mgr.cache[&url].fetched_at, old_time);
    assert_eq!(std::fs::read_to_string(meta_path).unwrap(), old_meta);
    assert!(!mgr.filter.list_membership("old.example").is_empty());
    let ids = mgr.filter.filter_gen_ids();
    assert_ne!(ids, generations);
    assert!(ids.iter().all(|id| *id == ids[0]));
    assert_eq!(mgr.installed_corpus_digest, old_digest);
    assert!(mgr.legacy_cache_timestamp_urls.contains(&url));
    assert!(matches!(
        &mgr.status_registry
            .status_for_url(&url)
            .unwrap()
            .last_outcome,
        LastOutcome::Failed { reason }
            if reason == "validated cache body but failed to update cache metadata"
    ));
    let state = mgr.list_state_handle().lock().unwrap().lists[&id].clone();
    assert_eq!(
        state.consecutive_failures,
        old_state.consecutive_failures + 1
    );
    assert_eq!(state.status, crate::config::list_state::ListStatus::Failed);
    assert_eq!(state.last_success, old_state.last_success);
    assert_eq!(state.cache_path, old_state.cache_path);
    assert_eq!(
        mgr.status_registry.cycle().outcome,
        Some(CycleOutcome::Installed)
    );
    assert_eq!(
        mgr.schedule_state.lookup(&schedule_key).unwrap().outcome,
        CanonicalScheduleOutcome::Failure
    );
}

#[tokio::test]
async fn rejected_fresh_candidates_keep_the_retained_validators_and_freshness() {
    let last_modified = "Thu, 01 Jan 1970 00:00:00 GMT";
    let (origin, pem, _) = spawn_tls_origin_responses(vec![
        tls_ok_response_with_last_modified(
            "old-one.example\nold-two.example\nold-three.example\n",
            "\"retained\"",
            last_modified,
        ),
        tls_ok_response_with_last_modified("candidate.example\n", "\"candidate\"", last_modified),
    ])
    .await;
    let url = "https://lists.test/refused.txt".to_string();
    let anchor = time::macros::datetime!(2026-09-05 12:00:00 UTC);
    let mut mgr = ListManager::new(
        reqwest::Client::builder()
            .resolve("lists.test", origin)
            .add_root_certificate(reqwest::Certificate::from_pem(pem.as_bytes()).unwrap())
            .build()
            .unwrap(),
        Arc::new(FilterEngine::new()),
        vec![url.clone()],
        Catalog::fallback(),
        Duration::from_secs(3600),
        build_source_bit_map(std::slice::from_ref(&url)).unwrap(),
        TEST_CAP,
        DEFAULT_MAX_LIST_ENTRIES,
        None,
    );

    assert_eq!(mgr.refresh_at(anchor).await, 3);
    let retained = mgr.cache.get(&url).unwrap().clone();
    mgr.set_shrink_guard(true, 50);

    assert_eq!(mgr.refresh_at(anchor + time::Duration::hours(2)).await, 3);
    assert_eq!(mgr.cache.get(&url), Some(&retained));
}

#[tokio::test]
async fn cap_refused_fresh_candidate_keeps_the_retained_validators_and_freshness() {
    let (origin, pem, _) = spawn_tls_origin_responses(vec![tls_ok_response(
        "candidate-one.example\ncandidate-two.example\n",
        "\"candidate\"",
    )])
    .await;
    let url = "https://lists.test/cap-refused.txt".to_string();
    let anchor = time::macros::datetime!(2026-09-05 12:00:00 UTC);
    let mut mgr = ListManager::new(
        reqwest::Client::builder()
            .resolve("lists.test", origin)
            .add_root_certificate(reqwest::Certificate::from_pem(pem.as_bytes()).unwrap())
            .build()
            .unwrap(),
        Arc::new(FilterEngine::new()),
        vec![url.clone()],
        Catalog::fallback(),
        Duration::from_secs(3600),
        build_source_bit_map(std::slice::from_ref(&url)).unwrap(),
        TEST_CAP,
        1,
        None,
    );
    let retained = ListCache {
        etag: Some("\"retained\"".into()),
        last_modified: Some("Wed, 31 Dec 1969 00:00:00 GMT".into()),
        body: Some("retained.example\n".into()),
        fetched_at: anchor - time::Duration::hours(2),
    };
    mgr.cache.insert(url.clone(), retained.clone());

    assert_eq!(mgr.refresh_at(anchor).await, 1);
    assert_eq!(mgr.cache.get(&url), Some(&retained));
}

#[tokio::test]
async fn disk_backed_corpus_refusal_keeps_old_generations_and_cache_only_recovers_them() {
    let (origin, pem, _) = spawn_tls_origin_responses(vec![
        tls_ok_response("old-a.example\n", "\"a-old\""),
        tls_ok_response("old-b.example\n", "\"b-old\""),
        tls_ok_response("new-a-one.example\nnew-a-two.example\n", "\"a-new\""),
        tls_ok_response("new-b.example\n", "\"b-new\""),
    ])
    .await;
    let a = "https://lists.test/corpus-a.txt".to_string();
    let b = "https://lists.test/corpus-b.txt".to_string();
    let cache_dir = tempfile::tempdir().unwrap();
    let mut mgr = ListManager::new(
        reqwest::Client::builder()
            .resolve("lists.test", origin)
            .add_root_certificate(reqwest::Certificate::from_pem(pem.as_bytes()).unwrap())
            .build()
            .unwrap(),
        Arc::new(FilterEngine::new()),
        vec![a.clone(), b.clone()],
        Catalog::fallback(),
        Duration::from_secs(3600),
        build_source_bit_map(&[a.clone(), b.clone()]).unwrap(),
        TEST_CAP,
        DEFAULT_MAX_LIST_ENTRIES,
        Some(cache_dir.path().to_path_buf()),
    );
    let a_id = crate::config::schema::Id::new("corpus-a").unwrap();
    let b_id = crate::config::schema::Id::new("corpus-b").unwrap();
    mgr.set_list_state(crate::config::list_state::ListState::default(), None);
    mgr.set_source_blocklist_map(HashMap::from([
        (a.clone(), (a_id.clone(), 3)),
        (b.clone(), (b_id.clone(), 3)),
    ]));

    assert_eq!(mgr.refresh().await, 2);
    let old_retry = mgr.list_state_handle().lock().unwrap().clone();
    let old_meta: Vec<_> = [&a, &b]
        .into_iter()
        .map(|source| {
            let stem = source_to_cache_stem(source);
            (
                std::fs::read_to_string(cache_dir.path().join(format!("{stem}.meta"))).unwrap(),
                selected_cache_body_path(cache_dir.path(), source).unwrap(),
            )
        })
        .collect();

    age_cache_entries(&mut mgr);
    let old_cache = mgr.cache.clone();
    mgr.set_max_total_domains(2);
    assert_eq!(mgr.refresh().await, 2);

    assert_eq!(
        mgr.cache, old_cache,
        "refusal must not publish fresh validators"
    );
    assert_eq!(
        *mgr.list_state_handle().lock().unwrap(),
        old_retry,
        "refusal must not record list retry success"
    );
    for ((meta, body), source) in old_meta.iter().zip([&a, &b]) {
        let stem = source_to_cache_stem(source);
        assert_eq!(
            std::fs::read_to_string(cache_dir.path().join(format!("{stem}.meta"))).unwrap(),
            *meta,
            "refusal rewrote {source}'s manifest"
        );
        assert!(body.is_file(), "refusal collected {source}'s selected body");
        assert_eq!(
            generation_body_paths(cache_dir.path(), &stem),
            vec![body.clone()],
            "refusal left an unselected {source} body behind"
        );
    }

    let mut boot = ListManager::new(
        reqwest::Client::new(),
        Arc::new(FilterEngine::new()),
        vec![a.clone(), b.clone()],
        Catalog::fallback(),
        Duration::from_secs(3600),
        build_source_bit_map(&[a.clone(), b.clone()]).unwrap(),
        TEST_CAP,
        DEFAULT_MAX_LIST_ENTRIES,
        Some(cache_dir.path().to_path_buf()),
    );
    boot.load_disk_cache();
    boot.set_max_total_domains(2);
    assert_eq!(boot.refresh_with_mode(RefreshMode::CacheOnly).await, 2);
    assert!(boot.filter.is_blocked("old-a.example"));
    assert!(boot.filter.is_blocked("old-b.example"));
    assert!(!boot.filter.is_blocked("new-a-one.example"));
    assert!(!boot.filter.is_blocked("new-a-two.example"));
    assert!(!boot.filter.is_blocked("new-b.example"));
}

#[tokio::test]
async fn disk_backed_unconditional_retry_waits_for_the_corpus_verdict() {
    let (origin, pem, _) = spawn_tls_origin_responses(vec![
        tls_ok_response("old-a.example\n", "\"a-old\""),
        tls_ok_response("old-a.example\nold-b.example\n", "\"b-old\""),
        tls_ok_response("old-a.example\n", "\"c-old\""),
        tls_ok_response("new-a.example\n", "\"a-new\""),
        "HTTP/1.1 304 Not Modified\r\nConnection: close\r\n\r\n".to_string(),
        tls_ok_response("new-b.example\n", "\"b-new\""),
        tls_ok_response("new-c.example\n", "\"c-new\""),
    ])
    .await;
    let a = "https://lists.test/retry-a.txt".to_string();
    let b = "https://lists.test/retry-b.txt".to_string();
    let c = "https://lists.test/retry-c.txt".to_string();
    let cache_dir = tempfile::tempdir().unwrap();
    let mut mgr = ListManager::new(
        reqwest::Client::builder()
            .resolve("lists.test", origin)
            .add_root_certificate(reqwest::Certificate::from_pem(pem.as_bytes()).unwrap())
            .build()
            .unwrap(),
        Arc::new(FilterEngine::new()),
        vec![a.clone(), b.clone(), c.clone()],
        Catalog::fallback(),
        Duration::from_secs(3600),
        build_source_bit_map(&[a.clone(), b.clone(), c.clone()]).unwrap(),
        TEST_CAP,
        DEFAULT_MAX_LIST_ENTRIES,
        Some(cache_dir.path().to_path_buf()),
    );
    let b_id = crate::config::schema::Id::new("retry-b").unwrap();
    mgr.set_list_state(crate::config::list_state::ListState::default(), None);
    mgr.set_source_blocklist_map(HashMap::from([(b.clone(), (b_id, 3))]));

    assert_eq!(mgr.refresh().await, 2);
    let old_b_retry = mgr.list_state_handle().lock().unwrap().clone();
    let stem = source_to_cache_stem(&b);
    let old_b_meta =
        std::fs::read_to_string(cache_dir.path().join(format!("{stem}.meta"))).unwrap();
    let old_b_body = selected_cache_body_path(cache_dir.path(), &b).unwrap();

    mgr.max_entries = 1;
    mgr.set_max_total_domains(2);
    age_cache_entries(&mut mgr);
    let old_b_cache = mgr.cache[&b].clone();
    assert_eq!(mgr.refresh().await, 2);

    assert_eq!(mgr.cache[&b], old_b_cache);
    assert_eq!(*mgr.list_state_handle().lock().unwrap(), old_b_retry);
    assert_eq!(
        std::fs::read_to_string(cache_dir.path().join(format!("{stem}.meta"))).unwrap(),
        old_b_meta
    );
    assert!(old_b_body.is_file());
}

/// The 304 body is itself the retained fallback. If a lowered cap makes it
/// unusable, a fresh A response must not replace the hot A+B generation.
#[tokio::test]
async fn a_304_cached_body_cap_refusal_keeps_the_complete_hot_generation() {
    let responses = vec![
        tls_ok_response("old-a.example\n", "\"a0\""),
        tls_ok_response(
            "old-b-one.example\nold-b-two.example\nold-b-three.example\n",
            "\"b0\"",
        ),
        tls_ok_response("old-a.example\nnew-a.example\n", "\"a1\""),
        "HTTP/1.1 304 Not Modified\r\nConnection: close\r\n\r\n".to_string(),
        "HTTP/1.1 304 Not Modified\r\nConnection: close\r\n\r\n".to_string(),
    ];
    let (origin, pem, requests) = spawn_tls_origin_responses(responses).await;
    let client = reqwest::Client::builder()
        .resolve("lists.test", origin)
        .add_root_certificate(reqwest::Certificate::from_pem(pem.as_bytes()).unwrap())
        .build()
        .unwrap();
    let a = "https://lists.test/a.txt".to_string();
    let b = "https://lists.test/b.txt".to_string();
    let bits = build_source_bit_map(&[a.clone(), b.clone()]).unwrap();
    let cache_dir = tempfile::tempdir().unwrap();
    let mut mgr = ListManager::new(
        client,
        Arc::new(FilterEngine::new()),
        vec![a.clone(), b.clone()],
        Catalog::fallback(),
        Duration::from_secs(3600),
        bits,
        TEST_CAP,
        4,
        Some(cache_dir.path().to_path_buf()),
    );
    let blocklist_id = crate::config::schema::Id::new("304-cap").unwrap();
    mgr.set_list_state(crate::config::list_state::ListState::default(), None);
    mgr.set_source_blocklist_map(HashMap::from([(b.clone(), (blocklist_id.clone(), 2))]));

    assert_eq!(mgr.refresh().await, 4);
    assert!(mgr.installed_corpus_digest.is_some());
    mgr.set_source_max_entries(HashMap::from([(a.clone(), 4), (b.clone(), 2)]));
    age_cache_entries(&mut mgr);

    assert_eq!(mgr.refresh().await, 4);
    for domain in [
        "old-a.example",
        "old-b-one.example",
        "old-b-two.example",
        "old-b-three.example",
    ] {
        assert!(
            !mgr.filter.list_membership(domain).is_empty(),
            "{domain} vanished from the prior generation"
        );
    }
    assert!(mgr.filter.list_membership("new-a.example").is_empty());
    assert!(mgr.installed_corpus_digest.is_none());
    assert_eq!(
        mgr.status_registry.cycle().outcome,
        Some(CycleOutcome::SpillRollbackFailed)
    );
    assert!(mgr.status_registry.cycle().source_coverage_incomplete);
    let a_status = mgr.status_registry.status_for_url(&a).unwrap();
    assert_eq!(a_status.entries, 1);
    assert_eq!(a_status.unique_domains, 1);
    let b_status = mgr.status_registry.status_for_url(&b).unwrap();
    assert_eq!(b_status.entries, 3);
    assert_eq!(b_status.unique_domains, 3);
    assert_eq!(b_status.parsed_truncated, 1);
    assert!(matches!(b_status.last_outcome, LastOutcome::Failed { .. }));
    let state = mgr.list_state_handle().lock().unwrap().clone();
    assert_eq!(
        state.lists.get(&blocklist_id).unwrap().consecutive_failures,
        1
    );
    let requests = requests.lock().unwrap();
    assert_eq!(requests.len(), 5, "the unusable 304 gets one retry");
    assert!(requests[3].contains("get /b.txt"));
    assert!(requests[3].contains("if-none-match: \"b0\""));
    assert!(requests[4].contains("get /b.txt"));
    assert!(!requests[4].contains("if-none-match:"));
}

#[tokio::test]
async fn canonically_equal_catalog_url_and_unconditional_304_never_relabel_the_old_cache() {
    use crate::config::schema::BlocklistFormat;
    use crate::lists::catalog::CatalogEntry;
    use std::collections::BTreeMap;

    let old_catalog = Catalog::from_entries(vec![CatalogEntry {
        scope: "team".to_string(),
        topic: Some("ads".to_string()),
        name: "Team ads".to_string(),
        url: "https://lists.test/ads.txt/".to_string(),
        entries: 0,
        updated_at: String::new(),
        format: BlocklistFormat::Domains,
    }]);
    let new_catalog = Catalog::from_entries(vec![CatalogEntry {
        scope: "team".to_string(),
        topic: Some("ads".to_string()),
        name: "Team ads".to_string(),
        url: "https://lists.test/ads.txt".to_string(),
        entries: 0,
        updated_at: String::new(),
        format: BlocklistFormat::Domains,
    }]);
    let legacy = vec!["team/ads".to_string()];
    let old_plan = ResolvedSourcePlan::build(&old_catalog, &legacy, &[], &BTreeMap::new()).unwrap();
    let new_plan = ResolvedSourcePlan::build(&new_catalog, &legacy, &[], &BTreeMap::new()).unwrap();
    assert_eq!(
        crate::lists::source_key::canonical_url_key(
            old_plan.fetch_url_for_source("team/ads").unwrap()
        ),
        crate::lists::source_key::canonical_url_key(
            new_plan.fetch_url_for_source("team/ads").unwrap()
        ),
        "the regression requires canonical-equivalent but exact-different URLs"
    );
    let cache_dir = tempfile::tempdir().unwrap();
    write_cache_to_disk(
        cache_dir.path(),
        "team/ads",
        old_plan.fetch_url_for_source("team/ads").unwrap(),
        "ads.example\n",
        Some("\"old\""),
        None,
        OffsetDateTime::now_utc(),
    )
    .unwrap();

    let (origin, pem, request_seen) = spawn_unconditional_304_tls_origin().await;
    let client = reqwest::Client::builder()
        .resolve("lists.test", origin)
        .add_root_certificate(reqwest::Certificate::from_pem(pem.as_bytes()).unwrap())
        .build()
        .unwrap();
    let bits = SourceBitMap::from_plan(&new_plan).unwrap();
    let mut manager = ListManager::with_plan_and_tokens(
        client,
        Arc::new(FilterEngine::new()),
        new_plan,
        Duration::from_secs(3600),
        bits,
        SourceTokenMap::default(),
        TEST_CAP,
        DEFAULT_MAX_LIST_ENTRIES,
        Some(cache_dir.path().to_path_buf()),
    );
    manager.load_disk_cache();

    assert!(manager.cache.is_empty(), "the old URL was not admitted");
    assert!(manager.open_body_from_disk("team/ads").is_none());
    assert_eq!(manager.refresh().await, 0);
    let request = request_seen
        .lock()
        .unwrap()
        .clone()
        .expect("the planned manager must reach the test origin");
    assert!(
        !request.contains("if-none-match:") && !request.contains("if-modified-since:"),
        "the moved URL has no admitted cache entry, so this was an unconditional 304"
    );
    assert!(
        manager.cache.is_empty(),
        "an unconditional 304 must not create a cache entry for the new URL"
    );
    assert!(
        matches!(
            manager
                .status_registry()
                .status_for_url("team/ads")
                .unwrap()
                .last_outcome,
            LastOutcome::Failed { .. }
        ),
        "the invalid 304 must never be recorded as source success"
    );
    assert!(
        manager.open_body_from_disk("team/ads").is_none(),
        "the old body must remain rejected under the moved catalog URL"
    );
    let meta = std::fs::read_to_string(
        cache_dir
            .path()
            .join(format!("{}.meta", source_to_cache_stem("team/ads"))),
    )
    .unwrap();
    assert!(meta.contains("resolved-url=https://lists.test/ads.txt/"));
    assert!(
        !meta.contains("resolved-url=https://lists.test/ads.txt\n"),
        "rejecting the unconditional 304 must leave the old sidecar unmodified"
    );
}

#[tokio::test]
async fn a_conditional_304_with_an_over_cap_cached_body_reports_typed_refusal() {
    let dir = tempfile::tempdir().unwrap();
    let url = "https://lists.test/cap.txt".to_string();
    let old = OffsetDateTime::now_utc() - time::Duration::days(1);
    write_cache_to_disk(
        dir.path(),
        &url,
        &url,
        "one.example\ntwo.example\nthree.example\n",
        Some("\"cap\""),
        None,
        old,
    )
    .unwrap();

    let (origin, pem, request_seen) = spawn_unconditional_304_tls_origin().await;
    let client = reqwest::Client::builder()
        .resolve("lists.test", origin)
        .add_root_certificate(reqwest::Certificate::from_pem(pem.as_bytes()).unwrap())
        .build()
        .unwrap();
    let bits = build_source_bit_map(std::slice::from_ref(&url)).expect("at-cap accept");
    let mut mgr = ListManager::new(
        client,
        Arc::new(FilterEngine::new()),
        vec![url.clone()],
        Catalog::fallback(),
        Duration::from_secs(3600),
        bits,
        TEST_CAP,
        4,
        Some(dir.path().to_path_buf()),
    );
    mgr.load_disk_cache();
    mgr.set_source_max_entries(HashMap::from([(url.clone(), 2)]));
    let blocklist_id = crate::config::schema::Id::new("conditional-304-cap").unwrap();
    mgr.set_list_state(crate::config::list_state::ListState::default(), None);
    mgr.set_source_blocklist_map(HashMap::from([(url.clone(), (blocklist_id.clone(), 2))]));

    assert_eq!(mgr.refresh().await, 0);
    let request = request_seen.lock().unwrap().clone().unwrap();
    assert!(
        request.contains("if-none-match: \"cap\""),
        "the test must exercise a conditional, not unconditional, 304: {request}"
    );
    let status = mgr.status_registry.status_for_url(&url).unwrap();
    assert_eq!(status.parsed_truncated, 1);
    assert!(matches!(status.last_outcome, LastOutcome::Failed { .. }));
    let state = mgr.list_state_handle().lock().unwrap().clone();
    let entry = state.lists.get(&blocklist_id).unwrap();
    assert_eq!(entry.consecutive_failures, 1);
    assert_eq!(entry.status, crate::config::list_state::ListStatus::Pending);
}

#[test]
fn cache_sidecar_identity_requires_the_exact_fetch_url() {
    let old = "https://lists.test/ads.txt/";
    let new = "https://lists.test/ads.txt";
    assert_eq!(
        crate::lists::source_key::canonical_url_key(old),
        crate::lists::source_key::canonical_url_key(new),
        "test targets must share the canonical routing identity"
    );

    let exact = ParsedMeta {
        load_state: MetaLoadState::Loaded,
        etag: Some("\"old\"".to_string()),
        last_modified: None,
        fetched_at: None,
        size: None,
        resolved_url: Some(old.to_string()),
        has_resolved_url: true,
        body: None,
        sha256: None,
        manifest_invalid: false,
    };
    assert!(cache_identity_matches("team/ads", old, &exact));
    assert!(
        !cache_identity_matches("team/ads", new, &exact),
        "canonical-equivalent fetch targets must not share validators"
    );

    let legacy_raw = ParsedMeta {
        load_state: MetaLoadState::Loaded,
        etag: Some("\"legacy\"".to_string()),
        last_modified: None,
        fetched_at: None,
        size: None,
        resolved_url: None,
        has_resolved_url: false,
        body: None,
        sha256: None,
        manifest_invalid: false,
    };
    assert!(cache_identity_matches(old, old, &legacy_raw));
    assert!(
        !cache_identity_matches(old, new, &legacy_raw),
        "a legacy raw-URL sidecar is accepted only for its exact source URL"
    );
}

#[test]
fn cache_sidecar_persists_the_exact_fetch_url() {
    let tmp = tempfile::tempdir().unwrap();
    let fetch_url = "https://LISTS.test:443/ads.txt/";
    write_cache_to_disk(
        tmp.path(),
        "team/ads",
        fetch_url,
        "ads.example\n",
        None,
        None,
        OffsetDateTime::now_utc(),
    )
    .unwrap();

    let meta = std::fs::read_to_string(
        tmp.path()
            .join(format!("{}.meta", source_to_cache_stem("team/ads"))),
    )
    .unwrap();
    assert!(meta.contains(&format!("resolved-url={fetch_url}\n")));
}

/// §4.7 Phase 2 T3: `write_cache_to_disk` stamps `size=<bytes>`
/// into the `.meta` sidecar, and `load_meta_file` parses it back
/// into `ParsedMeta.size`.
#[test]
fn meta_size_field_serializes_and_deserializes() {
    let tmp = tempfile::tempdir().unwrap();
    let body = "example.com\nads.example.org\n";
    let now = OffsetDateTime::now_utc();
    write_cache_to_disk(
        tmp.path(),
        "privacy/ads",
        "https://lists.purge.cc/ads.txt",
        body,
        Some("\"etag\""),
        Some("Wed, 21 Oct 2024 07:28:00 GMT"),
        now,
    )
    .unwrap();

    let stem = source_to_cache_stem("privacy/ads");
    let meta_path = tmp.path().join(format!("{stem}.meta"));
    let parsed = load_meta_file(&meta_path);
    assert_eq!(parsed.size, Some(body.len()));

    // Round-trip sanity: meta file contains the size= line verbatim.
    let raw = std::fs::read_to_string(&meta_path).unwrap();
    assert!(
        raw.contains(&format!("size={}\n", body.len())),
        "meta missing size= line: {raw}"
    );
}

/// §4.7 Phase 2 T3: actual within 1 % of expected passes the
/// validator — supply-chain churn at typical list size is allowed
/// through without forcing a re-download.
#[test]
fn validate_size_within_one_percent_passes() {
    // 0.5 % drift on a 5 MB list — well within tolerance.
    let expected = 5_000_000_usize;
    let actual = expected + 25_000; // +0.5 %
    assert!(validate_cached_body_size(Some(expected), actual));
    // And the symmetric shrink case (a list that lost a few entries).
    assert!(validate_cached_body_size(Some(expected), expected - 25_000));
    // Exact match always passes.
    assert!(validate_cached_body_size(Some(expected), expected));
}

/// §4.7 Phase 2 T3: a 1.5 % size drift fails the validator and
/// triggers the re-download path on the next refresh cycle. Floor
/// edge case: exactly 1 % must reject (the predicate is `< 1 %`).
#[test]
fn validate_size_one_point_five_percent_diff_fails() {
    let expected = 5_000_000_usize;
    // +1.5 % drift — outside tolerance.
    let actual = expected + 75_000;
    assert!(!validate_cached_body_size(Some(expected), actual));
    // Symmetric shrink case.
    assert!(!validate_cached_body_size(
        Some(expected),
        expected - 75_000
    ));
    // Exact 1 % must reject (boundary is strictly less than).
    assert!(!validate_cached_body_size(
        Some(expected),
        expected + 50_000
    ));
}

/// §4.7 Phase 2 T3: pre-T3 `.meta` files have no `size=` line.
/// `ParsedMeta.size == None` must be treated as "trust the body"
/// so an upgrade from Phase 1 to Phase 2 does not force a
/// re-download burst.
#[test]
fn validate_missing_meta_size_passes_legacy_compat() {
    // None expected => always pass, irrespective of actual size.
    assert!(validate_cached_body_size(None, 0));
    assert!(validate_cached_body_size(None, 1));
    assert!(validate_cached_body_size(None, usize::MAX));
    // Zero expected => degenerate but accepted (the empty-body
    // case is rare; falsely rejecting it adds no signal).
    assert!(validate_cached_body_size(Some(0), 0));
    assert!(validate_cached_body_size(Some(0), 1_000_000));
}

/// §4.7 Phase 2 T3: when `.meta` records `size=N` but the
/// `.cache` file on disk has been truncated by > 1 % (corruption,
/// partial write, ENOSPC mid-fsync), `read_body_from_disk`
/// returns `None` so the next refresh forces an HTTP re-fetch.
#[test]
fn load_disk_cache_skips_invalidated_body() {
    let tmp = tempfile::tempdir().unwrap();
    let client = reqwest::Client::new();
    let filter = Arc::new(FilterEngine::new());
    let catalog = Catalog::fallback();
    let mgr = ListManager::new(
        client,
        filter,
        vec!["privacy/ads".to_string()],
        catalog,
        Duration::from_secs(3600),
        SourceBitMap::default(),
        TEST_CAP,
        DEFAULT_MAX_LIST_ENTRIES,
        Some(tmp.path().to_path_buf()),
    );

    let stem = source_to_cache_stem("privacy/ads");
    let cache_path = tmp.path().join(format!("{stem}.cache"));
    let meta_path = tmp.path().join(format!("{stem}.meta"));

    // Write a small body but record a meta size that claims the
    // body is 10x larger — simulates on-disk truncation.
    let body = "example.com\n";
    std::fs::write(&cache_path, body).unwrap();
    std::fs::write(
        &meta_path,
        format!(
            "etag=\nlast-modified=\nresolved-url=https://lists.purge.cc/ads.txt\nfetched-at=\nsize={}\n",
            body.len() * 10
        ),
    )
    .unwrap();

    // `.cache` body is 10x smaller than expected — validator
    // rejects, read returns None, next refresh re-downloads.
    let result = mgr.read_body_from_disk("privacy/ads");
    assert!(
        result.is_none(),
        "size-diff body must be rejected; read returned Some()"
    );

    // Cross-check: a body within tolerance is accepted.
    std::fs::write(
        &meta_path,
        format!(
            "etag=\nlast-modified=\nresolved-url=https://lists.purge.cc/ads.txt\nfetched-at=\nsize={}\n",
            body.len()
        ),
    )
    .unwrap();
    let result_ok = mgr.read_body_from_disk("privacy/ads");
    assert_eq!(result_ok.as_deref(), Some(body));
}

/// A committed manifest selects a complete immutable generation body.
#[test]
fn write_cache_to_disk_leaves_no_new_files_on_success() {
    let tmp = tempfile::tempdir().unwrap();
    let source = "privacy/ads";
    let stem = source_to_cache_stem(source);
    let body = "tracker.example\nads.example\n";

    write_cache_to_disk(
        tmp.path(),
        source,
        "https://lists.purge.cc/ads.txt",
        body,
        Some("\"etag-123\""),
        Some("Wed, 14 May 2026 00:00:00 GMT"),
        OffsetDateTime::now_utc(),
    )
    .unwrap();

    let meta_path = tmp.path().join(format!("{stem}.meta"));
    let parsed = load_meta_file(&meta_path);
    let cache_path = selected_body_path(tmp.path(), &stem, &parsed).unwrap();

    assert_eq!(std::fs::read_to_string(&cache_path).unwrap(), body);
    assert!(
        std::fs::read_to_string(&meta_path)
            .unwrap()
            .contains(&format!("size={}", body.len())),
        "meta must stamp the body size"
    );
    assert!(!tmp.path().join(format!("{stem}.cache")).exists());

    // The promoted pair is internally consistent — the §4.7-T3
    // size predicate accepts it (no spurious re-download).
    let client = reqwest::Client::new();
    let filter = Arc::new(FilterEngine::new());
    let catalog = Catalog::fallback();
    let mgr = ListManager::new(
        client,
        filter,
        vec![source.to_string()],
        catalog,
        Duration::from_secs(3600),
        SourceBitMap::default(),
        TEST_CAP,
        DEFAULT_MAX_LIST_ENTRIES,
        Some(tmp.path().to_path_buf()),
    );
    assert_eq!(mgr.read_body_from_disk(source).as_deref(), Some(body));
}

#[test]
fn legacy_cache_body_remains_readable() {
    let dir = tempfile::tempdir().unwrap();
    let source = "https://lists.example.test/legacy.txt";
    let stem = source_to_cache_stem(source);
    std::fs::write(dir.path().join(format!("{stem}.cache")), "legacy.example\n").unwrap();
    std::fs::write(
        dir.path().join(format!("{stem}.meta")),
        format!("resolved-url={source}\n"),
    )
    .unwrap();
    let mgr = ListManager::new(
        reqwest::Client::new(),
        Arc::new(FilterEngine::new()),
        vec![source.to_string()],
        Catalog::fallback(),
        Duration::from_secs(3600),
        build_source_bit_map(&[source.to_string()]).unwrap(),
        TEST_CAP,
        DEFAULT_MAX_LIST_ENTRIES,
        Some(dir.path().to_path_buf()),
    );
    assert_eq!(
        mgr.read_body_from_disk(source).as_deref(),
        Some("legacy.example\n")
    );
}

#[test]
fn generation_commit_retires_legacy_body_only_after_manifest_commit() {
    let dir = tempfile::tempdir().unwrap();
    let source = "https://lists.example.test/migrate.txt";
    let stem = source_to_cache_stem(source);
    let legacy = dir.path().join(format!("{stem}.cache"));
    std::fs::write(&legacy, "legacy.example\n").unwrap();
    std::fs::write(
        dir.path().join(format!("{stem}.meta")),
        format!("resolved-url={source}\n"),
    )
    .unwrap();
    let before = ListManager::new(
        reqwest::Client::new(),
        Arc::new(FilterEngine::new()),
        vec![source.to_string()],
        Catalog::fallback(),
        Duration::from_secs(3600),
        build_source_bit_map(&[source.to_string()]).unwrap(),
        TEST_CAP,
        DEFAULT_MAX_LIST_ENTRIES,
        Some(dir.path().to_path_buf()),
    );
    assert_eq!(
        before.read_body_from_disk(source).as_deref(),
        Some("legacy.example\n")
    );
    assert!(legacy.exists());

    let generation = write_cache_to_disk(
        dir.path(),
        source,
        source,
        "generation.example\n",
        None,
        None,
        OffsetDateTime::now_utc(),
    )
    .unwrap();
    assert!(!legacy.exists());
    assert!(generation.exists());
}

#[test]
fn generation_manifest_rejects_partial_malformed_and_traversal_fields() {
    let stem = source_to_cache_stem("privacy/ads");
    for manifest in [
        "body=x\n",
        "sha256=0123\n",
        "body=../escape\nsha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
        "body=privacy_ads.body-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\nsha256=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n",
        "body=wrong.body-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\nsha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
    ] {
        let dir = tempfile::tempdir().unwrap();
        let meta_path = dir.path().join(format!("{stem}.meta"));
        std::fs::write(&meta_path, manifest).unwrap();
        let parsed = load_meta_file(&meta_path);
        assert!(selected_body_path(dir.path(), &stem, &parsed).is_none(), "{manifest}");
    }
}

#[test]
fn generation_size_must_match_exactly() {
    let dir = tempfile::tempdir().unwrap();
    let source = "https://lists.example.test/exact.txt";
    let body = format!("{}\n", "a".repeat(128));
    let body_path = write_cache_to_disk(
        dir.path(),
        source,
        source,
        &body,
        None,
        None,
        OffsetDateTime::now_utc(),
    )
    .unwrap();
    std::fs::write(&body_path, format!("{body}x")).unwrap();
    assert!(validate_cached_body_size(Some(body.len()), body.len() + 1));
    let mgr = ListManager::new(
        reqwest::Client::new(),
        Arc::new(FilterEngine::new()),
        vec![source.to_string()],
        Catalog::fallback(),
        Duration::from_secs(3600),
        build_source_bit_map(&[source.to_string()]).unwrap(),
        TEST_CAP,
        DEFAULT_MAX_LIST_ENTRIES,
        Some(dir.path().to_path_buf()),
    );
    assert!(mgr.read_body_from_disk(source).is_none());
}

#[test]
fn generation_body_confirmation_streams_length_and_hash() {
    use sha2::Digest;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("body");
    let body = b"streamed body";
    std::fs::write(&path, body).unwrap();
    let digest: [u8; 32] = sha2::Sha256::digest(body).into();
    assert!(generation_body_matches(&path, body.len(), digest));
    assert!(!generation_body_matches(&path, body.len() + 1, digest));
    assert!(file_matches_content(&path, body));
    assert!(!file_matches_content(&path, b"streamed body plus one byte"));
}

#[test]
fn meta_only_update_preserves_generation_fields_and_gc_keeps_selected_body() {
    let dir = tempfile::tempdir().unwrap();
    let source = "https://lists.example.test/update.txt";
    let first = write_cache_to_disk(
        dir.path(),
        source,
        source,
        "first.example\n",
        None,
        None,
        OffsetDateTime::now_utc(),
    )
    .unwrap();
    let second = write_cache_to_disk(
        dir.path(),
        source,
        source,
        "second.example\n",
        None,
        None,
        OffsetDateTime::now_utc(),
    )
    .unwrap();
    assert!(
        !first.exists(),
        "only a committed replacement may collect the old body"
    );
    let stem = source_to_cache_stem(source);
    let meta_path = dir.path().join(format!("{stem}.meta"));
    let before = load_meta_file(&meta_path);
    write_meta_file(
        &meta_path,
        None,
        None,
        source,
        OffsetDateTime::now_utc(),
        before.size,
        manifest_from_meta(&stem, &before),
    )
    .unwrap();
    let after = load_meta_file(&meta_path);
    assert_eq!(after.body, before.body);
    assert_eq!(after.sha256, before.sha256);
    assert_eq!(selected_body_path(dir.path(), &stem, &after), Some(second));
}

#[test]
fn manifest_generation_survives_restart_and_load_disk_cache() {
    let dir = tempfile::tempdir().unwrap();
    let source = "https://lists.example.test/restart.txt";
    let body = write_cache_to_disk(
        dir.path(),
        source,
        source,
        "restart.example\n",
        Some("\"restart\""),
        None,
        OffsetDateTime::now_utc(),
    )
    .unwrap();
    let mut mgr = ListManager::new(
        reqwest::Client::new(),
        Arc::new(FilterEngine::new()),
        vec![source.to_string()],
        Catalog::fallback(),
        Duration::from_secs(3600),
        build_source_bit_map(&[source.to_string()]).unwrap(),
        TEST_CAP,
        DEFAULT_MAX_LIST_ENTRIES,
        Some(dir.path().to_path_buf()),
    );
    mgr.load_disk_cache();
    assert_eq!(mgr.cache[source].etag.as_deref(), Some("\"restart\""));
    assert_eq!(
        mgr.read_body_from_disk(source).as_deref(),
        Some("restart.example\n")
    );
    assert!(body.exists());
}

#[test]
fn orphan_generation_cannot_replace_committed_manifest_before_meta_commit() {
    use sha2::Digest;

    let dir = tempfile::tempdir().unwrap();
    let source = "https://lists.example.test/order.txt";
    let old = write_cache_to_disk(
        dir.path(),
        source,
        source,
        "old.example\n",
        None,
        None,
        OffsetDateTime::now_utc(),
    )
    .unwrap();
    let stem = source_to_cache_stem(source);
    let new_body = b"new.example\n";
    let new_sha = hex::encode(sha2::Sha256::digest(new_body));
    let orphan = dir.path().join(generation_basename(&stem, &new_sha));
    std::fs::write(&orphan, new_body).unwrap();

    let mgr = ListManager::new(
        reqwest::Client::new(),
        Arc::new(FilterEngine::new()),
        vec![source.to_string()],
        Catalog::fallback(),
        Duration::from_secs(3600),
        build_source_bit_map(&[source.to_string()]).unwrap(),
        TEST_CAP,
        DEFAULT_MAX_LIST_ENTRIES,
        Some(dir.path().to_path_buf()),
    );
    assert_eq!(
        mgr.read_body_from_disk(source).as_deref(),
        Some("old.example\n")
    );
    assert!(old.exists());
    assert!(orphan.exists());
}

#[test]
fn manifest_write_failure_retains_prior_selected_body() {
    let dir = tempfile::tempdir().unwrap();
    let source = "https://lists.example.test/failure.txt";
    let old = write_cache_to_disk(
        dir.path(),
        source,
        source,
        "old.example\n",
        None,
        None,
        OffsetDateTime::now_utc(),
    )
    .unwrap();
    fail_next_cache_manifest_write_for_test();
    assert!(write_cache_to_disk(
        dir.path(),
        source,
        source,
        "new.example\n",
        None,
        None,
        OffsetDateTime::now_utc(),
    )
    .is_err());

    let mgr = ListManager::new(
        reqwest::Client::new(),
        Arc::new(FilterEngine::new()),
        vec![source.to_string()],
        Catalog::fallback(),
        Duration::from_secs(3600),
        build_source_bit_map(&[source.to_string()]).unwrap(),
        TEST_CAP,
        DEFAULT_MAX_LIST_ENTRIES,
        Some(dir.path().to_path_buf()),
    );
    assert_eq!(
        mgr.read_body_from_disk(source).as_deref(),
        Some("old.example\n")
    );
    assert!(old.exists());
    let stem = source_to_cache_stem(source);
    assert_eq!(generation_body_paths(dir.path(), &stem), vec![old]);
}

#[test]
fn uncertain_manifest_commit_keeps_legacy_and_previous_bodies_for_restart_recovery() {
    let dir = tempfile::tempdir().unwrap();
    let source = "https://lists.example.test/fsync-ambiguity.txt";
    let old = write_cache_to_disk(
        dir.path(),
        source,
        source,
        "old.example\n",
        Some("\"old\""),
        None,
        OffsetDateTime::now_utc(),
    )
    .unwrap();
    let stem = source_to_cache_stem(source);
    let meta_path = dir.path().join(format!("{stem}.meta"));
    let old_meta = std::fs::read_to_string(&meta_path).unwrap();
    let legacy = dir.path().join(format!("{stem}.cache"));
    std::fs::write(&legacy, "legacy.example\n").unwrap();

    fail_next_cache_manifest_parent_fsync_for_test();
    let new = write_cache_to_disk(
        dir.path(),
        source,
        source,
        "new.example\n",
        Some("\"new\""),
        None,
        OffsetDateTime::now_utc(),
    )
    .unwrap();
    assert_eq!(
        selected_cache_body_path(dir.path(), source),
        Some(new.clone()),
        "the landed manifest is selected in this process"
    );
    assert!(old.is_file(), "old manifest may return after power loss");
    assert!(
        legacy.is_file(),
        "uncertain commit must not retire legacy body"
    );

    // Model recovery of the old directory entry after a power loss. The old
    // manifest must still have a complete selected body to load.
    std::fs::write(&meta_path, old_meta).unwrap();
    let mgr = ListManager::new(
        reqwest::Client::new(),
        Arc::new(FilterEngine::new()),
        vec![source.to_string()],
        Catalog::fallback(),
        Duration::from_secs(3600),
        build_source_bit_map(&[source.to_string()]).unwrap(),
        TEST_CAP,
        DEFAULT_MAX_LIST_ENTRIES,
        Some(dir.path().to_path_buf()),
    );
    assert_eq!(
        mgr.read_body_from_disk(source).as_deref(),
        Some("old.example\n")
    );
}

fn cache_transaction_admission(
    source: &str,
    url: &str,
    staged: StagedCacheBody,
) -> PendingCacheAdmission {
    PendingCacheAdmission {
        source: source.to_string(),
        url: url.to_string(),
        etag: Some(format!("\"{source}\"")),
        last_modified: None,
        staged: Some(staged),
        body: None,
        previous_cache_path: PathBuf::new(),
    }
}

#[tokio::test]
async fn second_manifest_failure_rolls_back_all_cache_admissions_without_partial_state() {
    let old = "old-1.example\nold-2.example\nold-3.example\nold-4.example\nold-5.example\n";
    let new_a = "new-1.example\nnew-2.example\nnew-3.example\nnew-4.example\n";
    let (origin, pem, _) = spawn_tls_origin_responses(vec![
        tls_ok_response(old, "\"old-a\""),
        tls_ok_response(old, "\"old-b\""),
        tls_ok_response(new_a, "\"new-a\""),
        tls_ok_response("", "\"new-b\""),
    ])
    .await;
    let dir = tempfile::tempdir().unwrap();
    let sources = vec![
        "https://lists.test/txn-a.txt".to_string(),
        "https://lists.test/txn-b.txt".to_string(),
    ];
    let mut mgr = ListManager::new(
        reqwest::Client::builder()
            .resolve("lists.test", origin)
            .add_root_certificate(reqwest::Certificate::from_pem(pem.as_bytes()).unwrap())
            .build()
            .unwrap(),
        Arc::new(FilterEngine::new()),
        sources.clone(),
        Catalog::fallback(),
        Duration::from_secs(3600),
        build_source_bit_map(&sources).unwrap(),
        TEST_CAP,
        DEFAULT_MAX_LIST_ENTRIES,
        Some(dir.path().to_path_buf()),
    );
    let ids = [
        crate::config::schema::Id::new("txn-a").unwrap(),
        crate::config::schema::Id::new("txn-b").unwrap(),
    ];
    mgr.set_source_blocklist_map(HashMap::from([
        (sources[0].clone(), (ids[0].clone(), 3)),
        (sources[1].clone(), (ids[1].clone(), 3)),
    ]));
    let schedule_keys: Vec<_> = sources
        .iter()
        .map(|source| install_test_schedule(&mut mgr, source))
        .collect();
    assert_eq!(mgr.refresh().await, 5);
    let cache_dir = dir.path().to_path_buf();
    let old_meta: Vec<Vec<u8>> = sources
        .iter()
        .map(|source| {
            std::fs::read(cache_dir.join(format!("{}.meta", source_to_cache_stem(source)))).unwrap()
        })
        .collect();
    let old_bodies: Vec<PathBuf> = sources
        .iter()
        .map(|source| selected_cache_body_path(&cache_dir, source).unwrap())
        .collect();
    let retained_retry: Vec<_> = ids
        .iter()
        .map(|id| mgr.list_state_handle().lock().unwrap().lists[id].clone())
        .collect();

    age_cache_entries(&mut mgr);
    mgr.set_shrink_guard(false, 90);
    mgr.set_max_total_domains(4);
    let retained_cache = mgr.cache.clone();
    for key in &schedule_keys {
        mgr.schedule_state.record_success(
            key.clone(),
            OffsetDateTime::now_utc() - time::Duration::hours(2),
        );
    }
    fail_nth_cache_manifest_write_for_test(2);

    assert_eq!(
        mgr.refresh().await,
        4,
        "the globally accepted corpus is live"
    );
    assert!(!mgr.filter.list_membership("new-1.example").is_empty());
    assert!(!rollback_journal_path(&cache_dir).try_exists().unwrap());
    for (i, source) in sources.iter().enumerate() {
        let stem = source_to_cache_stem(source);
        assert_eq!(
            std::fs::read(cache_dir.join(format!("{stem}.meta"))).unwrap(),
            old_meta[i]
        );
        assert_eq!(
            selected_cache_body_path(&cache_dir, source),
            Some(old_bodies[i].clone())
        );
        assert_eq!(
            generation_body_paths(&cache_dir, &stem),
            vec![old_bodies[i].clone()]
        );
        assert_eq!(mgr.cache.get(source), retained_cache.get(source));
        let retry = mgr.list_state_handle().lock().unwrap().lists[&ids[i]].clone();
        assert_eq!(
            retry.consecutive_failures,
            retained_retry[i].consecutive_failures + 1
        );
        assert_eq!(retry.last_success, retained_retry[i].last_success);
        assert_eq!(retry.cache_path, retained_retry[i].cache_path);
        assert_eq!(
            mgr.schedule_state
                .lookup(&schedule_keys[i])
                .unwrap()
                .outcome,
            CanonicalScheduleOutcome::Failure,
            "transaction failure must leave {source}'s scheduler row retryable"
        );
    }

    let filter = Arc::new(FilterEngine::new());
    let mut boot = ListManager::new(
        reqwest::Client::new(),
        filter.clone(),
        sources.clone(),
        Catalog::fallback(),
        Duration::from_secs(3600),
        build_source_bit_map(&sources).unwrap(),
        TEST_CAP,
        DEFAULT_MAX_LIST_ENTRIES,
        Some(cache_dir),
    );
    boot.set_max_total_domains(4);
    boot.load_disk_cache();
    assert_eq!(boot.refresh_with_mode(RefreshMode::CacheOnly).await, 5);
    assert!(!filter.list_membership("old-1.example").is_empty());
    assert!(filter.list_membership("new-1.example").is_empty());
}

#[tokio::test]
async fn interrupted_manifest_transaction_recovers_the_complete_old_corpus_before_cache_only_boot()
{
    let dir = tempfile::tempdir().unwrap();
    let sources = [
        "https://lists.example.test/txn-a.txt",
        "https://lists.example.test/txn-b.txt",
    ];
    let old = "old-1.example\nold-2.example\nold-3.example\nold-4.example\nold-5.example\n";
    for source in sources {
        write_cache_to_disk(
            dir.path(),
            source,
            source,
            old,
            Some("\"old\""),
            None,
            OffsetDateTime::now_utc(),
        )
        .unwrap();
    }
    let new_a = "new-1.example\nnew-2.example\nnew-3.example\nnew-4.example\n";
    let staged_a = stage_cache_body(dir.path(), sources[0], new_a).unwrap();
    let staged_b = stage_cache_body(dir.path(), sources[1], "").unwrap();
    let admissions = vec![
        cache_transaction_admission(sources[0], sources[0], staged_a),
        cache_transaction_admission(sources[1], sources[1], staged_b),
    ];

    crash_after_nth_cache_manifest_commit_for_test(1);
    let interrupted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        commit_cache_admissions_transaction(dir.path(), &admissions, OffsetDateTime::now_utc())
    }));
    assert!(interrupted.is_err());
    assert!(rollback_journal_path(dir.path()).is_file());
    assert_eq!(
        selected_cache_body_path(dir.path(), sources[0]),
        Some(admissions[0].staged.as_ref().unwrap().body_path.clone())
    );
    let old_b = selected_cache_body_path(dir.path(), sources[1]).unwrap();
    assert_eq!(std::fs::read_to_string(old_b).unwrap(), old);
    assert!(
        9 > cold_start_hard_cap(4),
        "the 4-new plus 5-old hybrid would exceed the cold hard cap"
    );

    let filter = Arc::new(FilterEngine::new());
    let mut boot = ListManager::new(
        reqwest::Client::new(),
        filter.clone(),
        sources.iter().map(ToString::to_string).collect(),
        Catalog::fallback(),
        Duration::from_secs(3600),
        build_source_bit_map(&sources.map(str::to_string)).unwrap(),
        TEST_CAP,
        DEFAULT_MAX_LIST_ENTRIES,
        Some(dir.path().to_path_buf()),
    );
    boot.set_max_total_domains(4);
    boot.load_disk_cache();
    assert!(!rollback_journal_path(dir.path()).exists());
    assert_eq!(boot.refresh_with_mode(RefreshMode::CacheOnly).await, 5);
    assert!(!filter.list_membership("old-1.example").is_empty());
    assert!(filter.list_membership("new-1.example").is_empty());
}

#[test]
fn malformed_rollback_journal_refuses_disk_cache_and_blocks_cleanup() {
    let dir = tempfile::tempdir().unwrap();
    let source = "https://lists.example.test/malformed-journal.txt";
    let old = write_cache_to_disk(
        dir.path(),
        source,
        source,
        "old.example\n",
        None,
        None,
        OffsetDateTime::now_utc(),
    )
    .unwrap();
    let hybrid = write_cache_to_disk(
        dir.path(),
        source,
        source,
        "new.example\n",
        None,
        None,
        OffsetDateTime::now_utc(),
    )
    .unwrap();
    std::fs::write(rollback_journal_path(dir.path()), b"not a journal").unwrap();

    let mut mgr = cleanup_manager(dir.path(), source);
    mgr.load_disk_cache();
    assert!(mgr.cache.is_empty(), "a malformed journal must fail closed");
    mgr.cleanup_stale_caches();
    assert!(
        hybrid.exists(),
        "cleanup deleted a body needed to inspect recovery"
    );
    assert!(
        !old.exists(),
        "fixture sanity: the selected hybrid manifest replaced the old body"
    );
}

#[test]
fn unreadable_rollback_journal_refuses_disk_cache_and_blocks_cleanup() {
    let dir = tempfile::tempdir().unwrap();
    let source = "https://lists.example.test/unreadable-journal.txt";
    let body = write_cache_to_disk(
        dir.path(),
        source,
        source,
        "kept.example\n",
        None,
        None,
        OffsetDateTime::now_utc(),
    )
    .unwrap();
    std::fs::create_dir(rollback_journal_path(dir.path())).unwrap();

    let mut mgr = cleanup_manager(dir.path(), source);
    mgr.load_disk_cache();
    assert!(
        mgr.cache.is_empty(),
        "an unreadable journal must fail closed"
    );
    mgr.cleanup_stale_caches();
    assert!(body.exists(), "cleanup deleted a recovery body");
}

#[test]
fn metadata_write_fault_is_deterministic_and_preserves_generation_fields() {
    let dir = tempfile::tempdir().unwrap();
    let source = "https://lists.example.test/meta-fault.txt";
    write_cache_to_disk(
        dir.path(),
        source,
        source,
        "old.example\n",
        Some("\"old\""),
        None,
        OffsetDateTime::now_utc(),
    )
    .unwrap();
    let stem = source_to_cache_stem(source);
    let meta_path = dir.path().join(format!("{stem}.meta"));
    let before = std::fs::read_to_string(&meta_path).unwrap();
    let parsed = load_meta_file(&meta_path);
    fail_next_cache_manifest_write_for_test();
    assert!(write_meta_file(
        &meta_path,
        Some("\"old\""),
        None,
        source,
        OffsetDateTime::now_utc(),
        parsed.size,
        manifest_from_meta(&stem, &parsed),
    )
    .is_err());
    assert_eq!(std::fs::read_to_string(meta_path).unwrap(), before);
}

#[test]
fn confirmed_commit_reclaims_active_stem_orphans_but_keeps_selected_body() {
    use sha2::Digest;

    let dir = tempfile::tempdir().unwrap();
    let source = "https://lists.example.test/gc.txt";
    let stem = source_to_cache_stem(source);
    let orphan_bytes = b"orphan.example\n";
    let orphan_sha = hex::encode(sha2::Sha256::digest(orphan_bytes));
    let orphan = dir.path().join(generation_basename(&stem, &orphan_sha));
    std::fs::write(&orphan, orphan_bytes).unwrap();
    let selected = write_cache_to_disk(
        dir.path(),
        source,
        source,
        "selected.example\n",
        None,
        None,
        OffsetDateTime::now_utc(),
    )
    .unwrap();
    assert!(!orphan.exists());
    assert!(selected.exists());
    assert_eq!(generation_body_paths(dir.path(), &stem), vec![selected]);
}

#[test]
fn forget_removes_exact_generation_bodies() {
    let dir = tempfile::tempdir().unwrap();
    let source = "https://lists.example.test/forget.txt";
    let body = write_cache_to_disk(
        dir.path(),
        source,
        source,
        "forget.example\n",
        None,
        None,
        OffsetDateTime::now_utc(),
    )
    .unwrap();
    let mut mgr = ListManager::new(
        reqwest::Client::new(),
        Arc::new(FilterEngine::new()),
        vec![source.to_string()],
        Catalog::fallback(),
        Duration::from_secs(3600),
        build_source_bit_map(&[source.to_string()]).unwrap(),
        TEST_CAP,
        DEFAULT_MAX_LIST_ENTRIES,
        Some(dir.path().to_path_buf()),
    );
    assert!(mgr.forget_source(source));
    assert!(!body.exists());
    assert!(!dir
        .path()
        .join(format!("{}.meta", source_to_cache_stem(source)))
        .exists());
}

// ── rev-2606 §06 manager-01: retention guard ──────────────────

fn prev_with_unique(unique: u64) -> ListStatus {
    ListStatus {
        entries: unique,
        unique_domains: unique,
        last_outcome: crate::lists::status::LastOutcome::Ok,
        ..ListStatus::default()
    }
}

#[test]
fn shrink_verdict_first_fetch_always_accepts() {
    // No prior status → no baseline → accept even an empty body, so
    // initial provisioning is never bricked.
    assert!(matches!(
        compute_shrink_verdict(true, 90, None, 0, usize::MAX),
        ShrinkVerdict::Accept { .. }
    ));
}

#[test]
fn shrink_verdict_disabled_accepts_catastrophic_drop() {
    let prev = prev_with_unique(1000);
    assert!(matches!(
        compute_shrink_verdict(false, 90, Some(&prev), 0, usize::MAX),
        ShrinkVerdict::Accept { .. }
    ));
}

#[test]
fn shrink_verdict_trips_on_collapse_to_zero() {
    let prev = prev_with_unique(1000);
    match compute_shrink_verdict(true, 90, Some(&prev), 0, usize::MAX) {
        ShrinkVerdict::Refuse {
            drop_pct,
            got,
            kept,
        } => {
            assert_eq!((drop_pct, got, kept), (100, 0, 1000));
        }
        other => panic!("expected Refuse, got {other:?}"),
    }
}

#[test]
fn shrink_verdict_boundary_exact_threshold_accepts_just_over_trips() {
    let prev = prev_with_unique(1000);
    // Exactly 90% drop (fresh = 100 = 10% of baseline) → accept.
    assert!(matches!(
        compute_shrink_verdict(true, 90, Some(&prev), 100, usize::MAX),
        ShrinkVerdict::Accept { .. }
    ));
    // Just over 90% (fresh = 99) → trip.
    assert!(matches!(
        compute_shrink_verdict(true, 90, Some(&prev), 99, usize::MAX),
        ShrinkVerdict::Refuse { .. }
    ));
}

#[test]
fn shrink_verdict_legitimate_prune_accepts() {
    // An 80% upstream prune is below the 90% threshold → accepted.
    let prev = prev_with_unique(1000);
    assert!(matches!(
        compute_shrink_verdict(true, 90, Some(&prev), 200, usize::MAX),
        ShrinkVerdict::Accept { .. }
    ));
}

#[test]
fn shrink_verdict_large_swing_accepts_with_delta_warn() {
    let prev = prev_with_unique(1000);
    // 60% shrink: under the 90% refusal but over the 50% canary.
    match compute_shrink_verdict(true, 90, Some(&prev), 400, usize::MAX) {
        ShrinkVerdict::Accept { delta_warn } => {
            let d = delta_warn.expect("a 60% shrink must arm the canary");
            assert!(d <= -DELTA_WARN_THRESHOLD_PCT);
        }
        other => panic!("expected Accept, got {other:?}"),
    }
    // A 1000x GROWTH is also a canary signal.
    match compute_shrink_verdict(true, 90, Some(&prev), 1_000_000, usize::MAX) {
        ShrinkVerdict::Accept { delta_warn } => {
            assert!(delta_warn.expect("growth canary").abs() >= DELTA_WARN_THRESHOLD_PCT);
        }
        other => panic!("expected Accept, got {other:?}"),
    }
}

#[test]
fn shrink_verdict_falls_back_to_prev_entries_when_no_unique_baseline() {
    // v1→v2 upgrade: prior cycle has only the persisted entries
    // baseline (unique_domains == 0). The guard still trips.
    let prev = ListStatus {
        unique_domains: 0,
        prev_entries: Some(1000),
        ..ListStatus::default()
    };
    assert!(matches!(
        compute_shrink_verdict(true, 90, Some(&prev), 0, usize::MAX),
        ShrinkVerdict::Refuse { .. }
    ));
}

#[test]
fn shrink_verdict_uses_the_effective_source_cap_for_a_live_baseline() {
    let prev = prev_with_unique(100);
    assert!(matches!(
        compute_shrink_verdict(true, 50, Some(&prev), 2, 2),
        ShrinkVerdict::Accept { .. }
    ));
    assert!(matches!(
        compute_shrink_verdict(true, 50, Some(&prev), 2, usize::MAX),
        ShrinkVerdict::Refuse { .. }
    ));
}

/// Pins the `RefreshMode` → cache-hit message mapping.
///
/// Swapping the two arms of `cache_hit_message` previously compiled
/// and passed every test in this file — the distinction is not
/// cosmetic, it is what stops a boot logging "list fresh, skipping
/// HTTP" (a phrase implying a recent, interval-bounded confirmation,
/// per `PendingStatus::message`'s doc) about a cache that may be
/// months old. This test does NOT cover whether the cache-hit call
/// site in `refresh_with_mode` passes the `mode` the cycle is
/// actually running under — only that the mapping itself is correct
/// once a `mode` reaches it.
#[test]
fn cache_hit_message_pins_the_mode_mapping() {
    assert_eq!(
        cache_hit_message(RefreshMode::CacheOnly),
        "boot: loaded from disk cache, no HTTP",
    );
    assert_eq!(
        cache_hit_message(RefreshMode::Scheduled),
        "list not due, reusing retained cache",
    );
}

/// A manager whose single source is served by the imported.local
/// bridge from a file on disk — lets a test control the "downloaded"
/// body byte-for-byte without HTTP (the URL guard rejects a loopback
/// mock). The bridge file lives at `<dir>/lists/poison.txt`; the cache
/// is a SEPARATE `<dir>/cache` so a retained `.cache` survives a
/// bridge-file overwrite.
fn bridge_manager(body: &str) -> (ListManager, String, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let url = "https://imported.local/poison.txt".to_string();
    let lists_dir = dir.path().join("lists");
    std::fs::create_dir_all(&lists_dir).unwrap();
    std::fs::write(lists_dir.join("poison.txt"), body).unwrap();
    let cache_dir = dir.path().join("cache");
    std::fs::create_dir_all(&cache_dir).unwrap();

    let bits = build_source_bit_map(std::slice::from_ref(&url)).expect("at-cap accept");
    let mut mgr = ListManager::new(
        reqwest::Client::new(),
        Arc::new(FilterEngine::new()),
        vec![url.clone()],
        Catalog::fallback(),
        Duration::from_secs(3600),
        bits,
        TEST_CAP,
        DEFAULT_MAX_LIST_ENTRIES,
        Some(cache_dir),
    );
    let bl = bridge_blocklist(&url, BlocklistTrust::Local);
    mgr.set_local_bridge(SourceTrustMap::build(&[bl]), dir.path().to_path_buf());
    (mgr, url, dir)
}

fn bridge_blocklist(url: &str, trust: BlocklistTrust) -> crate::config::schema::Blocklist {
    crate::config::schema::Blocklist {
        id: crate::config::schema::id::Id::new("poison").unwrap(),
        display_name: "poison".to_string(),
        url: url.to_string(),
        format: Default::default(),
        update_interval_hours: None,
        max_entries: None,
        enabled: true,
        auth_token_ref: None,
        base: crate::config::schema::BlocklistBase::Deny,
        trust,
        accept_unsigned_allow: false,
        max_consecutive_failures: 5,
    }
}

/// Construct the production restart shape: only the accepted disk cache and
/// its fresh metadata are restored before the next refresh.
fn restarted_bridge_manager(
    dir: &tempfile::TempDir,
    url: &str,
    trust: BlocklistTrust,
    max_body_bytes: usize,
) -> ListManager {
    let bits = build_source_bit_map(&[url.to_string()]).expect("at-cap accept");
    let mut mgr = ListManager::new(
        reqwest::Client::new(),
        Arc::new(FilterEngine::new()),
        vec![url.to_string()],
        Catalog::fallback(),
        Duration::from_secs(3600),
        bits,
        max_body_bytes,
        DEFAULT_MAX_LIST_ENTRIES,
        Some(dir.path().join("cache")),
    );
    mgr.set_local_bridge(
        SourceTrustMap::build(&[bridge_blocklist(url, trust)]),
        dir.path().to_path_buf(),
    );
    mgr.load_disk_cache();
    mgr
}

fn write_bridge_body(dir: &tempfile::TempDir, body: &str) {
    std::fs::write(dir.path().join("lists").join("poison.txt"), body).unwrap();
}

#[tokio::test]
async fn a_refused_local_bridge_stamps_the_accepted_retained_cache_path() {
    use crate::lists::status::LastOutcome;

    let good = "a.example.com\nb.example.com\n";
    let (mut mgr, url, dir) = bridge_manager(good);
    let blocklist_id = crate::config::schema::Id::new("bridge-retained").unwrap();
    mgr.set_source_blocklist_map(HashMap::from([(url.clone(), (blocklist_id.clone(), 1))]));
    assert_eq!(mgr.refresh().await, 2);
    let stem = source_to_cache_stem(&url);
    let cache_path = selected_cache_body_path(&dir.path().join("cache"), &url).unwrap();
    assert!(
        cache_path.is_file(),
        "the successful bridge cycle writes a cache"
    );
    let first_success = mgr.list_state_handle().lock().unwrap().clone();
    assert_eq!(
        first_success.lists[&blocklist_id].cache_path.as_deref(),
        Some(cache_path.as_path()),
        "first fetch must stamp the manifest-selected generation body"
    );
    assert!(
        !cache_path.ends_with(format!("{stem}.cache")),
        "a fresh manifest commit must not stamp a synthetic legacy path"
    );

    // Reset after the cache write: this failure path has to stamp the path.
    mgr.set_list_state(crate::config::list_state::ListState::default(), None);
    mgr.set_source_blocklist_map(HashMap::from([(url.clone(), (blocklist_id.clone(), 1))]));
    std::fs::remove_file(dir.path().join("lists").join("poison.txt")).unwrap();

    assert_eq!(
        mgr.refresh().await,
        2,
        "a refused bridge may retain only a cache body that parses successfully"
    );
    match &mgr
        .status_registry
        .status_for_url(&url)
        .unwrap()
        .last_outcome
    {
        LastOutcome::Failed { reason } => assert!(reason.contains("not readable"), "{reason}"),
        other => panic!("expected the bridge refusal, got {other:?}"),
    }
    let state = mgr.list_state_handle().lock().unwrap().clone();
    let entry = state.lists.get(&blocklist_id).unwrap();
    assert_eq!(entry.status, crate::config::list_state::ListStatus::Failed);
    assert_eq!(entry.consecutive_failures, 1);
    assert_eq!(entry.cache_path.as_deref(), Some(cache_path.as_path()));
}

#[tokio::test]
async fn retained_body_reader_never_opens_the_live_bridge_file() {
    let (mut mgr, url, _dir) = bridge_manager("live.example.com\n");
    assert_eq!(mgr.refresh().await, 1);

    let reader = mgr.resolve_retained_body_reader(&url, &url).unwrap();
    assert!(matches!(&reader, BodyReader::RetainedCache { .. }));
    assert!(reader.retained_cache_path().is_some());
}

#[tokio::test]
async fn fresh_disk_cache_with_oversized_imported_local_candidate_retains_last_good_body() {
    use crate::lists::status::LastOutcome;

    let good = "old-a.example\nold-b.example\n";
    let (mut initial, url, dir) = bridge_manager(good);
    assert_eq!(initial.refresh().await, 2);

    write_bridge_body(
        &dir,
        "candidate-a.example\ncandidate-b.example\ncandidate-c.example\n",
    );
    let mut mgr = restarted_bridge_manager(&dir, &url, BlocklistTrust::Local, good.len());
    assert!(
        mgr.cache.contains_key(&url),
        "load_disk_cache must restore the fresh retained entry before Network refresh"
    );
    assert!(
        is_cache_fresh(
            mgr.cache.get(&url).unwrap().fetched_at,
            OffsetDateTime::now_utc(),
            mgr.refresh_interval,
        ),
        "the fixture must exercise the Network fresh-cache bypass"
    );

    assert_eq!(mgr.refresh_with_mode(RefreshMode::Force).await, 2);
    for domain in ["old-a.example", "old-b.example"] {
        assert!(
            !mgr.filter.list_membership(domain).is_empty(),
            "{domain} vanished"
        );
    }
    assert!(mgr.filter.list_membership("candidate-a.example").is_empty());
    let status = mgr.status_registry().status_for_url(&url).unwrap();
    match &status.last_outcome {
        LastOutcome::Failed { reason } => assert!(reason.contains("max"), "{reason}"),
        other => panic!("expected oversized live candidate failure, got {other:?}"),
    }
}

#[tokio::test]
async fn fresh_disk_cache_with_untrusted_imported_local_candidate_retains_last_good_body() {
    use crate::lists::status::LastOutcome;

    let good = "old-a.example\nold-b.example\n";
    let (mut initial, url, dir) = bridge_manager(good);
    assert_eq!(initial.refresh().await, 2);
    write_bridge_body(&dir, "candidate-a.example\ncandidate-b.example\n");
    let mut mgr = restarted_bridge_manager(&dir, &url, BlocklistTrust::RemoteUnsigned, TEST_CAP);
    assert!(
        mgr.cache.contains_key(&url),
        "load_disk_cache must restore the fresh retained entry before Network refresh"
    );
    assert!(
        is_cache_fresh(
            mgr.cache.get(&url).unwrap().fetched_at,
            OffsetDateTime::now_utc(),
            mgr.refresh_interval,
        ),
        "the fixture must exercise the Network fresh-cache bypass"
    );

    assert_eq!(mgr.refresh_with_mode(RefreshMode::Force).await, 2);
    for domain in ["old-a.example", "old-b.example"] {
        assert!(
            !mgr.filter.list_membership(domain).is_empty(),
            "{domain} vanished"
        );
    }
    assert!(mgr.filter.list_membership("candidate-a.example").is_empty());
    let status = mgr.status_registry().status_for_url(&url).unwrap();
    match &status.last_outcome {
        LastOutcome::Failed { reason } => assert!(reason.contains("trust=local"), "{reason}"),
        other => panic!("expected untrusted live candidate failure, got {other:?}"),
    }
}

#[cfg(unix)]
#[test]
fn cache_dir_lax_mode_flags_group_world_writable() {
    // rev-2606 §06 carryover-3.
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
    assert_eq!(cache_dir_lax_mode(dir.path()), Some(0o777));
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o750)).unwrap();
    assert_eq!(cache_dir_lax_mode(dir.path()), None, "0750 is not lax");
    // A non-existent dir is not flagged (first boot creates it).
    assert_eq!(cache_dir_lax_mode(&dir.path().join("nope")), None);
}

/// A Network refresh bypasses both generic cache shortcuts for an
/// `imported.local` source and validates the current file through the bridge.
#[tokio::test]
async fn network_refresh_with_fresh_cache_reads_the_edited_local_body() {
    let old = "a.example.com\nb.example.com\nc.example.com\n";
    let (mut mgr, url, dir) = bridge_manager(old);
    assert_eq!(mgr.refresh().await, 3);

    // The operator edits their file...
    write_bridge_body(
        &dir,
        "a.example.com\nb.example.com\nc.example.com\nd.example.com\n",
    );

    // Seed the generic fresh-cache state that Network must ignore for the
    // imported.local sentinel.
    mgr.cache.insert(
        url.clone(),
        ListCache {
            etag: None,
            last_modified: None,
            body: Some(old.into()),
            fetched_at: OffsetDateTime::now_utc(),
        },
    );

    assert_eq!(
        mgr.refresh_with_mode(RefreshMode::Force).await,
        4,
        "a fresh cache entry must not hide the operator's edit — 3 means the \
         seeded body was parsed instead of the file on disk"
    );
}

/// A normal Network cycle applies a local edit through the validated bridge.
#[tokio::test]
async fn a_local_body_edit_is_picked_up_by_the_next_refresh() {
    let (mut mgr, _url, dir) = bridge_manager("a.example.com\nb.example.com\nc.example.com\n");

    assert_eq!(
        mgr.refresh().await,
        3,
        "the initial body defines the corpus"
    );

    // The operator edits their own file — the exact scenario, no network.
    write_bridge_body(
        &dir,
        "a.example.com\nb.example.com\nc.example.com\nd.example.com\n",
    );

    assert_eq!(
        mgr.refresh().await,
        4,
        "an edited local body must reach the corpus; 3 means the cached copy \
         was re-read instead of the operator's file"
    );
}

/// CacheOnly boot reads the retained accepted cache for imported.local and
/// never opens the current operator file.
#[tokio::test]
async fn cache_only_boot_uses_retained_imported_local_cache_not_live_file() {
    let good = "old-a.example\nold-b.example\n";
    let (mut initial, url, dir) = bridge_manager(good);
    assert_eq!(initial.refresh().await, 2);
    write_bridge_body(&dir, "candidate-a.example\ncandidate-b.example\n");

    let mut boot = restarted_bridge_manager(&dir, &url, BlocklistTrust::Local, TEST_CAP);
    assert_eq!(boot.refresh_with_mode(RefreshMode::CacheOnly).await, 2);
    for domain in ["old-a.example", "old-b.example"] {
        assert!(
            !boot.filter.list_membership(domain).is_empty(),
            "{domain} vanished"
        );
    }
    assert!(boot
        .filter
        .list_membership("candidate-a.example")
        .is_empty());
}

#[tokio::test]
async fn retention_guard_keeps_prior_cache_on_empty_200() {
    use crate::lists::status::LastOutcome;
    let good = "a.example.com\nb.example.com\nc.example.com\nd.example.com\n";
    let (mut mgr, url, dir) = bridge_manager(good);

    // Refresh 1: good body accepted, cache written, domains in the map.
    assert_eq!(mgr.refresh().await, 4);
    let cache_file = selected_cache_body_path(&dir.path().join("cache"), &url).unwrap();
    assert_eq!(std::fs::read_to_string(&cache_file).unwrap(), good);
    let st = mgr.status_registry().status_for_url(&url).unwrap();
    assert!(matches!(st.last_outcome, LastOutcome::Ok));
    assert_eq!(st.unique_domains, 4);

    // Upstream goes bad: empty 200.
    write_bridge_body(&dir, "");

    // Refresh 2: guard trips. (The bridge path leaves no in-memory
    // cache entry, so the freshness shortcut does not fire and the
    // empty body is re-fetched and measured.)
    let total2 = mgr.refresh().await;
    // Prior list retained on disk...
    assert_eq!(
        std::fs::read_to_string(&cache_file).unwrap(),
        good,
        "good cache must survive a poisoned refresh"
    );
    // ...and still in the merged map (re-parsed from the retained cache).
    assert_eq!(total2, 4, "merged map keeps the prior list's domains");
    // ...status reflects the refusal with an operator-readable reason.
    match &mgr
        .status_registry()
        .status_for_url(&url)
        .unwrap()
        .last_outcome
    {
        LastOutcome::Failed { reason } => {
            assert!(reason.contains("refresh refused"), "got: {reason}");
            assert!(
                reason.contains("forget"),
                "reason must name the recovery verb"
            );
        }
        other => panic!("expected Failed, got {other:?}"),
    }

    // Simulated restart: a fresh manager over the same cache_dir loads
    // the retained good cache and still serves it.
    let bits = build_source_bit_map(std::slice::from_ref(&url)).expect("at-cap");
    let mut mgr2 = ListManager::new(
        reqwest::Client::new(),
        Arc::new(FilterEngine::new()),
        vec![url.clone()],
        Catalog::fallback(),
        Duration::from_secs(3600),
        bits,
        TEST_CAP,
        DEFAULT_MAX_LIST_ENTRIES,
        Some(dir.path().join("cache")),
    );
    mgr2.load_disk_cache();
    assert_eq!(
        mgr2.refresh().await,
        4,
        "after restart the retained list is still served from cache"
    );
}

/// A legitimate large-but-sub-threshold prune (75% < 90%) is accepted
/// and DOES overwrite the cache — the guard must not block real upstream
/// pruning.
#[tokio::test]
async fn retention_guard_accepts_legitimate_prune() {
    use crate::lists::status::LastOutcome;
    let good = "a.example.com\nb.example.com\nc.example.com\nd.example.com\n";
    let (mut mgr, url, dir) = bridge_manager(good);
    assert_eq!(mgr.refresh().await, 4);

    // 4 → 1 domain = 75% drop, under the 90% threshold.
    let pruned = "a.example.com\n";
    write_bridge_body(&dir, pruned);
    assert_eq!(mgr.refresh().await, 1);
    let cache_file = selected_cache_body_path(&dir.path().join("cache"), &url).unwrap();
    assert_eq!(
        std::fs::read_to_string(&cache_file).unwrap(),
        pruned,
        "an accepted prune overwrites the cache"
    );
    assert!(matches!(
        mgr.status_registry()
            .status_for_url(&url)
            .unwrap()
            .last_outcome,
        LastOutcome::Ok
    ));
}

/// First fetch of a brand-new source that returns an empty 200 is
/// accepted (no baseline) — provisioning must not be bricked.
#[tokio::test]
async fn retention_guard_first_fetch_empty_accepts() {
    use crate::lists::status::LastOutcome;
    let (mut mgr, url, _dir) = bridge_manager("");
    mgr.status_registry()
        .note_refused_cycle(OffsetDateTime::now_utc());
    assert_eq!(mgr.refresh().await, 0);
    let cycle = mgr.status_registry().cycle();
    assert_eq!(cycle.outcome, Some(CycleOutcome::Installed));
    assert!(!cycle.source_coverage_incomplete);
    assert!(!cycle.generation_degraded);
    assert!(mgr.installed_corpus_digest.is_some());
    assert!(mgr.status_registry().corpus_freeze().is_none());
    assert!(matches!(
        mgr.status_registry()
            .status_for_url(&url)
            .unwrap()
            .last_outcome,
        LastOutcome::Ok
    ));
}

/// `warden lists forget <source>` disarms the guard: after a trip, a
/// forget resets the baseline (and removes the cache the operator chose
/// to discard), so the next fetch is treated as a first fetch and
/// accepted even though it is tiny.
#[tokio::test]
async fn forget_disarms_retention_guard() {
    use crate::lists::status::LastOutcome;
    let good = "a.example.com\nb.example.com\nc.example.com\nd.example.com\n";
    let (mut mgr, url, dir) = bridge_manager(good);
    // Persist baselines so we can prove the disarm survives a restart.
    let stats_path = dir.path().join("list_stats.json");
    mgr.set_status_persistence_path(stats_path.clone());
    assert_eq!(mgr.refresh().await, 4);

    // Poison → trip.
    write_bridge_body(&dir, "");
    mgr.refresh().await;
    assert!(matches!(
        mgr.status_registry()
            .status_for_url(&url)
            .unwrap()
            .last_outcome,
        LastOutcome::Failed { .. }
    ));

    // Operator forgets the list: baseline reset, cache removed, stats
    // file rewritten so the disarm survives a restart.
    assert!(mgr.forget_source(&url));
    let persisted = std::fs::read_to_string(&stats_path).unwrap();
    assert!(
        !persisted.contains("imported.local"),
        "forget must drop the source's baseline from list_stats.json, got: {persisted}"
    );

    // Next fetch is tiny but accepted (guard disarmed → first fetch).
    write_bridge_body(&dir, "only.example.com\n");
    assert_eq!(mgr.refresh().await, 1);
    assert!(matches!(
        mgr.status_registry()
            .status_for_url(&url)
            .unwrap()
            .last_outcome,
        LastOutcome::Ok
    ));
}

// ── classify_fetch_error (tests-offline-cdn) ────────────────────

/// A dead-host / proxy-fault outage (2026-07-23 `lists.purge.cc`) and a
/// slow peer under load both used to render as the same opaque
/// `"error sending request for url ..."` text. This asserts the
/// connect-refused case is now labelled distinctly. Offline-safe: binds
/// a local port then drops the listener before connecting, so nothing
/// leaves the host.
#[tokio::test]
async fn classify_fetch_error_labels_connection_refused() {
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener); // nothing listens on `addr` anymore

    let client = reqwest::Client::new();
    let err = client
        .get(format!("http://{addr}/x"))
        .send()
        .await
        .unwrap_err();

    let msg = classify_fetch_error(&err);
    assert!(
        msg.starts_with("connection refused"),
        "expected a connection-refused label, got: {msg}"
    );
}

/// Same distinguishability check for the timeout case: a peer that
/// accepts the connection but never responds must be labelled
/// "timeout", not the same generic text as a refused connection.
#[tokio::test]
async fn classify_fetch_error_labels_timeout() {
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    // Accept the connection and then just hold it open, sending nothing.
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        std::mem::forget(stream); // keep the socket open, never respond
    });

    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(100))
        .build()
        .unwrap();
    let err = client
        .get(format!("http://{addr}/x"))
        .send()
        .await
        .unwrap_err();

    let msg = classify_fetch_error(&err);
    assert!(
        msg.starts_with("timeout"),
        "expected a timeout label, got: {msg}"
    );
    assert!(
        msg.contains("peer did not respond"),
        "a silent peer must keep the peer-side label, got: {msg}"
    );
}

/// The body-phase sibling. A peer that answers promptly and then streams
/// too slowly must NOT be described as one that "did not respond" — that
/// text sent a real diagnosis to the wrong end of the wire while four
/// 100-180 MB lists failed every refresh on a 1 MB/s link.
///
/// The distinguishing needle is the phrase, not merely the word
/// "timeout": both branches start with it, so asserting `starts_with`
/// would pass on the very bug this pins.
#[tokio::test]
async fn classify_fetch_error_labels_body_stream_timeout_distinctly() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    // Answer immediately, promise a body, then never finish sending it.
    tokio::spawn(async move {
        let (mut stream, _) = match listener.accept().await {
            Ok(p) => p,
            Err(_) => return,
        };
        let mut buf = [0u8; 2048];
        let _ = stream.read(&mut buf).await;
        let _ = stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4096\r\n\r\nabc")
            .await;
        tokio::time::sleep(Duration::from_secs(30)).await;
    });

    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(300))
        .build()
        .unwrap();
    let resp = client
        .get(format!("http://{addr}/list.txt"))
        .send()
        .await
        .expect("headers arrive promptly");
    let err = resp
        .bytes()
        .await
        .expect_err("the body never completes within 300ms");

    assert!(err.is_timeout(), "expected a timeout, got: {err}");
    let msg = classify_fetch_error(&err);
    assert!(
        msg.contains("streaming the response body"),
        "expected the body-stream label, got: {msg}"
    );
    assert!(
        !msg.contains("peer did not respond"),
        "the peer DID respond — that label is false here: {msg}"
    );
}

// ── Shard-spill producer (§11 T3) ─────────────────────────────────

/// A manager whose sources are all served from the `imported.local`
/// bridge, so a refresh can be driven end-to-end with byte-exact
/// bodies and no HTTP. Returns the manager, the source URLs in bit
/// order, and the temp dir (kept alive by the caller).
fn spill_manager(bodies: &[&str]) -> (ListManager, Vec<String>, tempfile::TempDir) {
    spill_manager_with_cap(bodies, DEFAULT_MAX_LIST_ENTRIES)
}

/// [`spill_manager`] with an explicit per-list entry cap, so a test can
/// drive the cap's fail-closed path on a six-line fixture instead of a
/// ten-million-line one. The cap the refresh path reads is the
/// manager's own field — `Blocklist::max_entries` below is inert here.
fn spill_manager_with_cap(
    bodies: &[&str],
    max_entries: usize,
) -> (ListManager, Vec<String>, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let lists_dir = dir.path().join("lists");
    std::fs::create_dir_all(&lists_dir).unwrap();
    let cache_dir = dir.path().join("cache");
    std::fs::create_dir_all(&cache_dir).unwrap();

    let mut urls = Vec::new();
    let mut blocklists = Vec::new();
    for (i, body) in bodies.iter().enumerate() {
        let name = format!("src{i}");
        std::fs::write(lists_dir.join(format!("{name}.txt")), body).unwrap();
        let url = format!("https://imported.local/{name}.txt");
        blocklists.push(crate::config::schema::Blocklist {
            id: crate::config::schema::id::Id::new(&name).unwrap(),
            display_name: name.clone(),
            url: url.clone(),
            format: Default::default(),
            update_interval_hours: None,
            max_entries: None,
            enabled: true,
            auth_token_ref: None,
            base: crate::config::schema::BlocklistBase::Deny,
            trust: BlocklistTrust::Local,
            accept_unsigned_allow: false,
            max_consecutive_failures: 5,
        });
        urls.push(url);
    }

    let bits = build_source_bit_map(&urls).expect("at-cap accept");
    let mut mgr = ListManager::new(
        reqwest::Client::new(),
        Arc::new(FilterEngine::new()),
        urls.clone(),
        Catalog::fallback(),
        Duration::from_secs(3600),
        bits,
        TEST_CAP,
        max_entries,
        Some(cache_dir),
    );
    mgr.set_local_bridge(SourceTrustMap::build(&blocklists), dir.path().to_path_buf());
    (mgr, urls, dir)
}

#[tokio::test]
async fn source_cap_refuses_only_its_fresh_candidate() {
    let (mut mgr, urls, _dir) =
        spill_manager_with_cap(&["one.test\ntwo.test\n", "three.test\nfour.test\n"], 2);
    assert_eq!(mgr.refresh().await, 4, "seed a safe retained generation");
    mgr.set_source_max_entries(HashMap::from([
        (urls[0].clone(), 1),
        (urls[1].clone(), usize::MAX),
    ]));
    assert_eq!(
        mgr.source_max_entries_for(&urls[1]),
        2,
        "manager wiring cannot widen the global hard ceiling"
    );
    assert_eq!(
        mgr.refresh().await,
        4,
        "a source whose candidate and retained body exceed its new cap keeps the safe generation"
    );
    let refused = mgr.status_registry().status_for_url(&urls[0]).unwrap();
    assert!(refused.parsed_truncated > 0);
    assert_eq!(
        refused.entries, 2,
        "refused source retains its old status rather than contributing the candidate"
    );
    let healthy = mgr.status_registry().status_for_url(&urls[1]).unwrap();
    assert_eq!(healthy.parsed_ok, 2);
    assert_eq!(
        healthy.entries, 2,
        "healthy source retains its exact contribution"
    );
}

#[tokio::test]
async fn reload_cap_narrowing_bounds_live_baseline_consumers_in_either_wiring_order() {
    let (mut mgr, urls, _dir) = spill_manager_with_cap(&["one.test\ntwo.test\n"], 10);
    let source = urls[0].clone();
    let shared = Arc::new(ListStatusRegistry::new(&urls));
    let now = OffsetDateTime::now_utc();
    shared.update_for_url(
        &source,
        ListStatus {
            entries: 100,
            parsed_ok: 100,
            unique_domains: 100,
            fetched_at: Some(now),
            last_outcome: LastOutcome::Ok,
            prev_entries: Some(100),
            last_refresh_at: Some(now),
            ..ListStatus::default()
        },
    );

    // Reload builds a replacement manager, wires its plan caps, then attaches
    // the daemon's already-populated registry. The live status remains the
    // served generation; guard and allocation consumers apply the new cap.
    mgr.set_source_max_entries(HashMap::from([(source.clone(), 2)]));
    mgr.attach_status_registry(shared.clone());
    let narrowed = shared.status_for_url(&source).unwrap();
    assert_eq!(narrowed.entries, 100, "the served count remains truthful");
    assert_eq!(narrowed.parsed_ok, 100);
    assert_eq!(narrowed.prev_entries, Some(100));
    assert_eq!(narrowed.unique_domains, 100);
    assert_eq!(narrowed.last_outcome, LastOutcome::Ok);
    assert_eq!(narrowed.fetched_at, Some(now));
    assert_eq!(narrowed.last_refresh_at, Some(now));
    match UniqueCount::measure(Some(narrowed.as_ref()), 2) {
        UniqueCount::Measure(Some(hint)) => assert_eq!(hint.get(), 2),
        other => panic!("narrowed status must bound the allocation hint: {other:?}"),
    }
    assert!(matches!(
        compute_shrink_verdict(true, 50, Some(narrowed.as_ref()), 2, 2),
        ShrinkVerdict::Accept { .. }
    ));

    mgr.set_shrink_guard(true, 50);
    assert_eq!(
        mgr.refresh().await,
        2,
        "a candidate at the narrowed cap must not be refused against the old live baseline"
    );
    assert_eq!(
        mgr.status_registry()
            .status_for_url(&source)
            .unwrap()
            .entries,
        2,
        "the accepted candidate replaces the now-obsolete served count"
    );

    // The same consumption seams make the setter order irrelevant.
    let (mut reverse, reverse_urls, _dir) = spill_manager_with_cap(&["one.test\ntwo.test\n"], 10);
    let reverse_source = reverse_urls[0].clone();
    let reverse_shared = Arc::new(ListStatusRegistry::new(&reverse_urls));
    reverse_shared.update_for_url(
        &reverse_source,
        ListStatus {
            entries: 100,
            unique_domains: 100,
            last_outcome: LastOutcome::Ok,
            prev_entries: Some(100),
            ..ListStatus::default()
        },
    );
    reverse.attach_status_registry(reverse_shared.clone());
    reverse.set_source_max_entries(HashMap::from([(reverse_source.clone(), 2)]));
    let reverse_status = reverse_shared.status_for_url(&reverse_source).unwrap();
    assert_eq!(reverse_status.entries, 100);
    assert_eq!(reverse_status.prev_entries, Some(100));
    assert_eq!(reverse_status.unique_domains, 100);
    match UniqueCount::carry_or_measure(Some(reverse_status.as_ref()), 2) {
        UniqueCount::Carried(hint) => assert_eq!(hint.get(), 2),
        other => panic!("reverse wiring must bound the carried baseline: {other:?}"),
    }
    assert!(matches!(
        compute_shrink_verdict(true, 50, Some(reverse_status.as_ref()), 2, 2),
        ShrinkVerdict::Accept { .. }
    ));
}

/// A manager whose sources are ordinary remote URLs already present in
/// the on-disk cache, with in-memory entries stamped `fetched_at`.
///
/// This is the harness for anything that exercises the **fresh-cache
/// arm** or the T3 probe, and it exists because `spill_manager` cannot:
/// its sources go through the `imported.local` bridge, which returns
/// before any cache entry is created and therefore never takes the
/// freshness shortcut at all (see `download_list`). A test built on the
/// bridge would either not reach the arm, or reach it only because
/// something stamped `fetched_at` that should not have — which is
/// exactly the regression that broke three `retention_guard_*` tests.
///
/// No HTTP is possible here and none should happen: every source is
/// cache-fresh, so the loop must never reach `download_list`. If a
/// change makes it fall through, the test fails with a network error
/// rather than passing quietly — a loud failure, which is what we want
/// from a harness whose whole point is "the request was not made".
fn cached_manager(bodies: &[&str]) -> (ListManager, Vec<String>, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let cache_dir = dir.path().join("cache");
    std::fs::create_dir_all(&cache_dir).unwrap();

    let urls: Vec<String> = (0..bodies.len())
        .map(|i| format!("https://lists.invalid/src{i}.txt"))
        .collect();
    let bits = build_source_bit_map(&urls).expect("at-cap accept");
    let mut mgr = ListManager::new(
        reqwest::Client::new(),
        Arc::new(FilterEngine::new()),
        urls.clone(),
        Catalog::fallback(),
        Duration::from_secs(3600),
        bits,
        TEST_CAP,
        DEFAULT_MAX_LIST_ENTRIES,
        Some(cache_dir.clone()),
    );
    for (url, body) in urls.iter().zip(bodies) {
        write_cache_to_disk(
            &cache_dir,
            url,
            url,
            body,
            None,
            None,
            OffsetDateTime::now_utc(),
        )
        .unwrap();
        mgr.cache.insert(
            url.clone(),
            ListCache {
                etag: None,
                last_modified: None,
                body: None,
                fetched_at: OffsetDateTime::now_utc(),
            },
        );
    }
    (mgr, urls, dir)
}

/// Rewrite a cached source's body on disk, keeping `.meta` consistent
/// so the §4.7-T3 size check still accepts it.
fn rewrite_cached_body(dir: &tempfile::TempDir, url: &str, body: &str) {
    write_cache_to_disk(
        &dir.path().join("cache"),
        url,
        url,
        body,
        None,
        None,
        OffsetDateTime::now_utc(),
    )
    .unwrap();
}

/// The precondition three `retention_guard_*` tests state in their own
/// comments, pinned so it cannot be "fixed" again.
///
/// An `imported.local` source must be re-read from the operator's file
/// on every cycle. `mem2608-t0` briefly stamped `fetched_at` on that
/// arm — reasoning that a source which never records a validation time
/// is an oversight — and the stamp created a cache entry, which armed
/// the freshness shortcut, which meant a poisoned local body was never
/// re-read and the retention guard never saw it. Every gate said `Ok`.
///
/// The absence of that stamp is load-bearing, not an oversight.
#[tokio::test]
async fn a_bridge_source_never_takes_the_freshness_shortcut() {
    let (mut mgr, urls, dir) = spill_manager(&["a.example\n"]);
    assert_eq!(mgr.refresh().await, 1);
    assert!(
        !mgr.cache.contains_key(&urls[0]),
        "the bridge arm created a cache entry — that arms the freshness shortcut for a \
         local file, so the operator's next edit goes unseen and a poisoned body never \
         reaches the retention guard"
    );

    // The operator edits the file; the very next cycle must see it,
    // with no interval to wait out.
    std::fs::write(
        dir.path().join("lists").join("src0.txt"),
        "a.example\nb.example\n",
    )
    .unwrap();
    assert_eq!(
        mgr.refresh().await,
        2,
        "an edited local list was not re-read on the next cycle"
    );
}

/// The partition and the probe must agree.
///
/// `FilterEngine::shard_index` is seeded per process, and the engine
/// probes exactly the shard it names — so a producer that routed a
/// domain anywhere else stores it where nothing will ever look. That
/// failure is invisible to a `domain_count()` assertion (the entry
/// exists, it is just unreachable) and shows up only as a lookup miss.
#[tokio::test]
async fn refresh_routes_every_domain_to_the_shard_the_engine_probes() {
    let a = "alpha.example\nbeta.example\nshared.example\n";
    let b = "gamma.example\nshared.example\ndelta.example\n";
    let (mut mgr, _urls, _dir) = spill_manager(&[a, b]);

    let total = mgr.refresh().await;
    assert_eq!(total, 5, "alpha/beta/gamma/delta/shared, shared deduped");
    assert_eq!(mgr.filter.domain_count(), 5);

    for d in [
        "alpha.example",
        "beta.example",
        "gamma.example",
        "delta.example",
        "shared.example",
    ] {
        let masks = mgr.filter.list_membership(d);
        assert!(
            !masks.is_empty(),
            "{d} was spilled but is unreachable — producer and engine disagree on its shard"
        );
    }
    // A domain nobody listed must still miss, or the assertion above
    // would pass for a map that matched everything.
    assert!(mgr.filter.list_membership("absent.example").is_empty());

    // Bits are per source and OR together on the shared domain.
    let shared = mgr.filter.list_membership("shared.example");
    assert_eq!(
        shared.block_mask.count_ones(),
        2,
        "shared.example must carry both sources' bits"
    );
    assert_eq!(shared.allow_mask, 0, "block_only semantics preserved");
}

/// Spill files are a per-process artefact and must never outlive the
/// cycle that wrote them.
#[tokio::test]
async fn refresh_leaves_no_spill_behind() {
    let (mut mgr, _urls, dir) = spill_manager(&["a.example\nb.example\n"]);
    let spill_dir = dir.path().join("cache").join(SHARD_SPILL_DIR);
    mgr.refresh().await;
    assert!(
        !spill_dir.exists(),
        "spill dir survived the cycle that created it"
    );
}

/// A partition written by a previous process is garbage to this one —
/// `shard_index` reseeds, so ~15/16 of it would land in the wrong
/// shard. It must be deleted both at construction and on cycle entry,
/// never resumed.
#[tokio::test]
async fn stale_spill_is_purged_and_never_resumed() {
    let dir = tempfile::tempdir().unwrap();
    let cache_dir = dir.path().join("cache");
    let spill_dir = cache_dir.join(SHARD_SPILL_DIR);
    std::fs::create_dir_all(&spill_dir).unwrap();
    // A plausible-looking spill from a crashed daemon.
    let stale = spill_dir.join(spill_file_name(3));
    std::fs::write(&stale, b"\xffgarbage-from-a-dead-process").unwrap();
    // A file this module never creates must be left alone — cleanup
    // deletes constructed names only, never the directory wholesale.
    let foreign = spill_dir.join("not-ours.txt");
    std::fs::write(&foreign, b"keep me").unwrap();

    let urls = vec!["https://example.invalid/list.txt".to_string()];
    let bits = build_source_bit_map(&urls).expect("at-cap accept");
    let _mgr = ListManager::new(
        reqwest::Client::new(),
        Arc::new(FilterEngine::new()),
        urls,
        Catalog::fallback(),
        Duration::from_secs(3600),
        bits,
        TEST_CAP,
        DEFAULT_MAX_LIST_ENTRIES,
        Some(cache_dir),
    );

    assert!(!stale.exists(), "stale spill survived construction");
    assert!(
        foreign.exists(),
        "cleanup deleted a file it did not create — scoping is wrong"
    );
}

/// `entries` is the source's *net-new* contribution in iteration
/// order — the `merged.len()` delta the flat producer reported. With
/// shard-at-a-time that number only exists in pass 2, so this pins
/// that it is still reconstructed exactly rather than quietly
/// replaced by the source's own deduped count.
#[tokio::test]
async fn entries_still_counts_only_net_new_domains() {
    let a = "one.example\ntwo.example\n";
    let b = "two.example\nthree.example\n";
    let (mut mgr, urls, _dir) = spill_manager(&[a, b]);
    mgr.refresh().await;

    let s0 = mgr.status_registry.status_for_url(&urls[0]).unwrap();
    let s1 = mgr.status_registry.status_for_url(&urls[1]).unwrap();

    assert_eq!(s0.entries, 2, "first source contributes both its domains");
    assert_eq!(
        s1.entries, 1,
        "two.example was already in the map — only three.example is net-new"
    );
    // unique_domains is order-independent and counts each source's own
    // deduped contribution, so both sources report 2.
    assert_eq!(s0.unique_domains, 2);
    assert_eq!(s1.unique_domains, 2);
}

#[tokio::test]
async fn retained_failure_reconciles_served_overlap_without_recovering_health() {
    let (mut mgr, urls, dir) = spill_manager(&["shared.example\n", "shared.example\nb.example\n"]);
    assert_eq!(mgr.refresh().await, 2);
    assert_eq!(
        mgr.status_registry
            .status_for_url(&urls[0])
            .unwrap()
            .entries,
        1
    );
    assert_eq!(
        mgr.status_registry
            .status_for_url(&urls[1])
            .unwrap()
            .entries,
        1
    );

    rewrite_body(&dir, 0, "a.example\n");
    std::fs::remove_file(dir.path().join("lists/src1.txt")).unwrap();
    expire_bodies(&mut mgr);

    assert_eq!(mgr.refresh().await, 3);
    let a = mgr.status_registry.status_for_url(&urls[0]).unwrap();
    let b = mgr.status_registry.status_for_url(&urls[1]).unwrap();
    assert_eq!(a.entries, 1);
    assert_eq!(
        b.entries, 2,
        "the retained source now owns shared.example as well as b.example"
    );
    assert!(
        matches!(b.last_outcome, LastOutcome::Failed { .. }),
        "retaining a body does not recover the failed fetch"
    );
}

/// The retention guard trips on `unique_domains`, which must stay
/// immune to a body that repeats one domain N times. The frozen
/// [`DomainSink::accept`] hands the skeleton no way to learn a domain
/// was already seen, so the skeleton cannot compute this — the sink
/// does, and this is what proves it.
#[tokio::test]
async fn unique_domains_ignores_in_list_duplicates() {
    let body = "dup.example\ndup.example\ndup.example\nother.example\n";
    let (mut mgr, urls, _dir) = spill_manager(&[body]);
    mgr.refresh().await;

    let s = mgr.status_registry.status_for_url(&urls[0]).unwrap();
    assert_eq!(
        s.unique_domains, 2,
        "three copies of dup.example are one unique domain"
    );
    assert_eq!(
        s.parsed_ok, 4,
        "parsed_ok stays pre-dedup — that difference is the point"
    );
    assert_eq!(mgr.filter.domain_count(), 2);
}

/// The entry cap must count domains, never candidate lines.
///
/// A Hosts body carries rows a format extractor discards outright: an
/// IPv6 line with no `0.0.0.0`/`127.0.0.1` prefix, a loopback alias, a
/// broadcast row. None of them is a domain the source contributes, so
/// none may be charged against its cap. Counting them meant a body
/// whose real domain count sat *at or under* the cap could still push
/// the "dropped" tally above zero — and since the cap became
/// fail-closed, above zero refuses the **whole source**: spill rolled
/// back, previous generation retained, that blocklist gone from the
/// merged map until an operator noticed.
///
/// Driven through `refresh()` on purpose. The counter that had this
/// defect lived in a private copy of the parse skeleton that only
/// `refresh()` reached, so every test that hand-built a `ShardSpill`
/// and called the inner function was blind to it by construction —
/// which is how a silent 19% corpus drop shipped with a green suite.
#[tokio::test]
async fn refresh_installs_a_hosts_source_whose_noise_lines_reach_the_cap() {
    use crate::lists::status::LastOutcome;
    // Three accepted lines meet a cap of three exactly — the duplicate
    // keeps the *unique* domain count at two, strictly under it. The
    // three rows that follow are pure hosts noise.
    let body = concat!(
        "0.0.0.0 alpha.example\n",
        "0.0.0.0 alpha.example\n",
        "0.0.0.0 beta.example\n",
        "::1 ip6-localhost\n",
        "127.0.0.1 localhost\n",
        "255.255.255.255 broadcast\n",
    );
    let (mut mgr, urls, _dir) = spill_manager_with_cap(&[body], 3);
    let count = mgr.refresh().await;

    let s = mgr.status_registry.status_for_url(&urls[0]).unwrap();
    // This is the load-bearing assertion. `parsed_truncated` below is
    // NOT: the refusal path builds its status with
    // `ListStatus::from_failure`, which carries the *previous* cycle's
    // counters forward, so the fresh over-count never reaches the
    // registry and that field reads 0 on broken code too.
    assert_eq!(
        s.last_outcome,
        LastOutcome::Ok,
        "the source was refused whole over lines that carry no domain"
    );
    assert_eq!(count, 2, "both unique domains must reach the merged map");
    assert!(mgr.filter.is_blocked("alpha.example"));
    assert!(mgr.filter.is_blocked("beta.example"));
    assert_eq!(s.parsed_ok, 3, "the duplicate line still parses");
    assert_eq!(s.unique_domains, 2, "under the cap of 3, not at it");
    assert_eq!(
        s.parsed_truncated, 0,
        "an installed source under its cap must report nothing dropped"
    );
}

/// The control arm for the test above: when the domains *themselves*
/// run past the cap the source must still be refused whole. Without
/// this, "count domains, not lines" could be satisfied by a counter
/// that never fires at all.
#[tokio::test]
async fn refresh_refuses_a_hosts_source_whose_domains_exceed_the_cap() {
    use crate::lists::status::LastOutcome;
    let body = concat!(
        "0.0.0.0 one.example\n",
        "0.0.0.0 two.example\n",
        "0.0.0.0 three.example\n",
        "0.0.0.0 four.example\n",
        "0.0.0.0 five.example\n",
    );
    let (mut mgr, urls, _dir) = spill_manager_with_cap(&[body], 3);
    let count = mgr.refresh().await;

    assert_eq!(count, 0, "a source over its cap must be refused whole");
    assert!(!mgr.filter.is_blocked("one.example"));
    let s = mgr.status_registry.status_for_url(&urls[0]).unwrap();
    match &s.last_outcome {
        LastOutcome::Failed { reason } => assert!(
            reason.contains("max_entries"),
            "the refusal must name the knob to raise: {reason}"
        ),
        other => panic!("expected a cap refusal, got {other:?}"),
    }
}

/// A reader that fails mid-body must leave the spill byte-identical to
/// its pre-call state.
///
/// This is the invariant `read_to_string` used to provide for free by
/// failing before the parse began. Without it a truncated download
/// ingests partially and can read as a legitimate sub-threshold
/// shrink, ratcheting the retention guard's baseline down on exactly
/// the supply-chain failure the guard exists to catch.
#[test]
fn partial_stream_error_rolls_the_spill_back() {
    /// Yields `head`, then errors — a truncated body, not a short one.
    struct FailAfter {
        head: std::io::Cursor<Vec<u8>>,
    }
    impl Read for FailAfter {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            match self.head.read(buf)? {
                0 => Err(std::io::Error::other("simulated mid-body I/O failure")),
                n => Ok(n),
            }
        }
    }
    impl BufRead for FailAfter {
        fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
            if self.head.position() as usize >= self.head.get_ref().len() {
                return Err(std::io::Error::other("simulated mid-body I/O failure"));
            }
            self.head.fill_buf()
        }
        fn consume(&mut self, amt: usize) {
            self.head.consume(amt);
        }
    }

    let dir = tempfile::tempdir().unwrap();
    let mut spill = ShardSpill::open(Some(dir.path())).unwrap();
    assert!(spill.is_disk(), "test must exercise the disk path");

    // A first, complete source.
    let good = std::io::Cursor::new(b"kept.example\n".to_vec());
    parse_source_into_spill(
        good,
        1,
        &mut spill,
        100,
        "good",
        Some(ListFormat::DomainOnly),
    )
    .expect("complete body parses");
    let after_good = spill.mark();

    // A second source that dies part-way through.
    let bad = FailAfter {
        head: std::io::Cursor::new(b"dropped.example\nalso-dropped.example\n".to_vec()),
    };
    let err = parse_source_into_spill(bad, 2, &mut spill, 100, "bad", Some(ListFormat::DomainOnly))
        .expect_err("a mid-body failure must surface");
    assert_eq!(err.kind(), std::io::ErrorKind::Other);

    assert_eq!(
        spill.mark(),
        after_good,
        "the failed source left bytes in the spill"
    );

    // And the built shards contain only the first source.
    spill.flush().unwrap();
    let mut found = Vec::new();
    let policy = ListPolicy::publish_uniform(0);
    for idx in 0..DOMAIN_SHARDS {
        let shard = spill.build_shard(idx, 4, &policy).unwrap().shard;
        for (d, bits) in shard.iter() {
            found.push((d.to_string(), shard.split_base(bits).block_mask));
        }
    }
    assert_eq!(found, vec![("kept.example".to_string(), 1)]);
}

#[test]
fn disk_spill_overlong_line_after_valid_prefix_rolls_back_whole_source() {
    let dir = tempfile::tempdir().unwrap();
    let mut spill = ShardSpill::open(Some(dir.path())).unwrap();
    assert!(spill.is_disk(), "test must exercise the disk spill path");

    parse_source_into_spill(
        std::io::Cursor::new(b"kept.example\n".to_vec()),
        1,
        &mut spill,
        100,
        "retained",
        Some(ListFormat::DomainOnly),
    )
    .unwrap();
    let before = spill.mark();

    let overlong = format!("new.example\n#{}\nlate.example\n", "x".repeat(64 * 1024));
    let error = parse_source_into_spill(
        std::io::Cursor::new(overlong.into_bytes()),
        2,
        &mut spill,
        100,
        "candidate",
        Some(ListFormat::DomainOnly),
    )
    .expect_err("a valid prefix cannot survive an overlong physical line");
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    assert_eq!(
        spill.mark(),
        before,
        "the candidate left partial spill rows"
    );

    spill.flush().unwrap();
    let policy = ListPolicy::publish_uniform(0);
    let mut found = Vec::new();
    for idx in 0..DOMAIN_SHARDS {
        let shard = spill.build_shard(idx, 4, &policy).unwrap().shard;
        for (domain, bits) in shard.iter() {
            found.push((domain.to_string(), shard.split_base(bits).block_mask));
        }
    }
    assert_eq!(found, vec![("kept.example".to_string(), 1)]);
}

#[test]
fn manifest_hash_mismatch_rolls_back_every_retained_parse_row() {
    let dir = tempfile::tempdir().unwrap();
    let body_path = dir.path().join("retained.body");
    std::fs::write(&body_path, "tampered.example\n").unwrap();
    let mut spill = ShardSpill::open(Some(dir.path())).unwrap();
    let before = spill.mark();
    let reader = BodyReader::RetainedCache {
        reader: std::io::BufReader::new(std::fs::File::open(&body_path).unwrap()),
        path: body_path,
        expected_sha256: Some([0; 32]),
    };

    let error = parse_retained_source_into_spill_counted(
        reader,
        1,
        &mut spill,
        100,
        "retained",
        Some(ListFormat::DomainOnly),
        UniqueCount::Measure(None),
    )
    .expect_err("manifest hash mismatch must reject the retained body");
    assert_eq!(error.kind(), std::io::ErrorKind::Other);
    assert_eq!(spill.mark(), before, "mismatched rows escaped the rollback");
}

/// neutrality-06 — a source whose blocklist row carries `base = allow`
/// must contribute to `allow_mask`, never to `block_mask`.
///
/// Before this test the shard builder stamped
/// `DomainMasks::block_only(bit)` on every entry regardless of
/// direction, so an allow-direction list did not merely fail to allow:
/// it **blocked** the domains it was imported to permit. Direction is a
/// per-source property, so it rides in as a bitmask of allow-direction
/// bits — the spill record format is unchanged.
#[test]
fn neutrality06_allow_direction_source_populates_allow_mask() {
    let dir = tempfile::tempdir().unwrap();
    let mut spill = ShardSpill::open(Some(dir.path())).unwrap();

    // bit 0 — a deny list carrying two domains.
    parse_source_into_spill(
        std::io::Cursor::new(b"shared.example\nblocked.example\n".to_vec()),
        1 << 0,
        &mut spill,
        100,
        "deny-list",
        Some(ListFormat::DomainOnly),
    )
    .unwrap();

    // bit 1 — an allow list that re-opens one of them.
    parse_source_into_spill(
        std::io::Cursor::new(b"shared.example\n".to_vec()),
        1 << 1,
        &mut spill,
        100,
        "allow-list",
        Some(ListFormat::DomainOnly),
    )
    .unwrap();

    spill.flush().unwrap();

    let allow_bits: u64 = 1 << 1;
    let mut found: HashMap<String, DomainMasks> = HashMap::new();
    let policy = ListPolicy::publish_uniform(allow_bits);
    for idx in 0..DOMAIN_SHARDS {
        let shard = spill.build_shard(idx, 4, &policy).unwrap().shard;
        for (d, bits) in shard.iter() {
            found.insert(d.to_string(), shard.split_base(bits));
        }
    }

    let shared = found
        .get("shared.example")
        .copied()
        .expect("shared.example must be present");
    assert_eq!(
        shared.allow_mask, 0b10,
        "the allow-direction source's bit belongs in allow_mask"
    );
    assert_eq!(
        shared.block_mask, 0b01,
        "the deny-direction source's bit belongs in block_mask"
    );

    let blocked = found
        .get("blocked.example")
        .copied()
        .expect("blocked.example must be present");
    assert_eq!(
        blocked.allow_mask, 0,
        "a domain no allow list carries must have an empty allow_mask"
    );
    assert_eq!(blocked.block_mask, 0b01);
}

/// Direction routing must not depend on the order sources reach the
/// spill — and an allow-direction source must be able to create an
/// entry, not only decorate one that a deny source already made.
///
/// `build_shard`'s insert closure has two arms: a *vacant* arm that
/// stamps the direction on a brand-new entry, and an *occupied* arm
/// that ORs a bit into the existing entry. The sibling test above
/// spills the deny source first, so its allow bit only ever reaches
/// the occupied arm and the vacant arm is only ever exercised with a
/// block bit. This test spills the **allow source first**, which:
///
///   - drives the contested domain through the mirror path (vacant
///     with an allow bit, then occupied with a block bit), and
///   - covers a domain carried *only* by the allow source, the one
///     shape that reaches `v.insert` with `allow_mask` non-zero.
///
/// That second case is what a regression to unconditional
/// `block_only` stamping would hit first: a pure allow-list domain
/// would come back blocked, which is the exact neutrality-06 defect.
#[test]
fn allow_direction_routing_survives_reversed_spill_order() {
    let dir = tempfile::tempdir().unwrap();
    let mut spill = ShardSpill::open(Some(dir.path())).unwrap();

    // bit 1 — the allow list, spilled FIRST this time.
    parse_source_into_spill(
        std::io::Cursor::new(b"shared.example\nallow-only.example\n".to_vec()),
        1 << 1,
        &mut spill,
        100,
        "allow-list",
        Some(ListFormat::DomainOnly),
    )
    .unwrap();

    // bit 0 — the deny list, arriving after.
    parse_source_into_spill(
        std::io::Cursor::new(b"shared.example\nblocked.example\n".to_vec()),
        1 << 0,
        &mut spill,
        100,
        "deny-list",
        Some(ListFormat::DomainOnly),
    )
    .unwrap();

    spill.flush().unwrap();

    let allow_bits: u64 = 1 << 1;
    let mut found: HashMap<String, DomainMasks> = HashMap::new();
    let policy = ListPolicy::publish_uniform(allow_bits);
    for idx in 0..DOMAIN_SHARDS {
        let shard = spill.build_shard(idx, 4, &policy).unwrap().shard;
        for (d, bits) in shard.iter() {
            found.insert(d.to_string(), shard.split_base(bits));
        }
    }

    // The contested domain lands with BOTH masks populated regardless
    // of which source got there first.
    let shared = found
        .get("shared.example")
        .copied()
        .expect("shared.example must be present");
    assert_eq!(
        shared.allow_mask, 0b10,
        "allow-first ordering must still route the allow source's bit to allow_mask"
    );
    assert_eq!(
        shared.block_mask, 0b01,
        "the later deny source must OR its bit into block_mask, not overwrite the entry"
    );

    // A domain no deny source ever names: the vacant-insert allow arm.
    let allow_only = found
        .get("allow-only.example")
        .copied()
        .expect("allow-only.example must be present");
    assert_eq!(
        allow_only.allow_mask, 0b10,
        "a domain only an allow-direction source carries belongs in allow_mask"
    );
    assert_eq!(
        allow_only.block_mask, 0,
        "an allow-only domain must carry no block bits — stamping one here is \
         the neutrality-06 defect, where an allow list blocked what it should permit"
    );

    let blocked = found
        .get("blocked.example")
        .copied()
        .expect("blocked.example must be present");
    assert_eq!(blocked.allow_mask, 0);
    assert_eq!(blocked.block_mask, 0b01);
}

/// Explicit in-RAM mode (`cache_dir: None`) must partition identically
/// to the disk path — it costs more memory, never different domains.
#[test]
fn memory_mode_partitions_identically_to_disk() {
    let body = "one.example\ntwo.example\nthree.example\nfour.example\none.example\n";

    let build = |spill: &mut ShardSpill| {
        parse_source_into_spill(
            std::io::Cursor::new(body.as_bytes()),
            1,
            spill,
            100,
            "s",
            Some(ListFormat::DomainOnly),
        )
        .unwrap();
        spill.flush().unwrap();
        let mut added = [0u64; 64];
        let mut per_shard: Vec<Vec<String>> = Vec::new();
        let policy = ListPolicy::publish_uniform(0);
        for idx in 0..DOMAIN_SHARDS {
            let shard = spill
                .build_shard(idx, 4, &policy)
                .unwrap()
                .merge_added_by_bit(&mut added);
            let mut names: Vec<String> = shard.iter().map(|(k, _)| k.to_string()).collect();
            names.sort();
            per_shard.push(names);
        }
        (per_shard, added)
    };

    let dir = tempfile::tempdir().unwrap();
    let mut disk = ShardSpill::open(Some(dir.path())).unwrap();
    assert!(disk.is_disk());
    let mut mem = ShardSpill::open(None).unwrap();
    assert!(
        !mem.is_disk(),
        "memory arm must exercise explicit memory mode"
    );

    let (disk_shards, disk_added) = build(&mut disk);
    let (mem_shards, mem_added) = build(&mut mem);

    assert_eq!(disk_shards, mem_shards, "disk and memory partitions differ");
    assert_eq!(disk_added, mem_added);
    assert_eq!(
        disk_shards.iter().map(Vec::len).sum::<usize>(),
        4,
        "one.example appears twice in the body but once in the map"
    );
}

#[test]
fn disk_spill_setup_errors_never_select_memory() {
    let dir = tempfile::tempdir().unwrap();

    fail_next_shard_spill_dir_create_for_test();
    assert!(
        ShardSpill::open(Some(dir.path())).is_err(),
        "a configured spill directory failure must surface"
    );

    fail_nth_shard_spill_file_create_for_test(3);
    assert!(
        ShardSpill::open(Some(dir.path())).is_err(),
        "a configured spill file failure must surface"
    );
    assert!(
        !dir.path().join(SHARD_SPILL_DIR).exists(),
        "a failed spill setup must remove its partial partition"
    );

    assert!(
        !ShardSpill::open(None).unwrap().is_disk(),
        "memory mode remains an explicit cache_dir: None choice"
    );
}

#[tokio::test]
async fn disk_spill_setup_failure_publishes_one_degraded_completed_cycle() {
    let (mut mgr, _urls, _dir) = spill_manager(&["kept.example\n"]);
    assert_eq!(mgr.refresh().await, 1);
    let before = mgr.status_registry.cycle();
    assert_eq!(before.served_state, ServedState::Complete);

    fail_next_shard_spill_dir_create_for_test();
    assert_eq!(mgr.refresh().await, 1, "the prior corpus remains live");

    let after = mgr.status_registry.cycle();
    assert_eq!(
        after.seq,
        before.seq + 1,
        "one failed attempt publishes once"
    );
    assert_eq!(after.outcome, Some(CycleOutcome::SpillRollbackFailed));
    assert!(after.source_coverage_incomplete);
    assert!(after.generation_degraded);
    assert_eq!(after.served_state, ServedState::Complete);
    assert!(mgr.status_registry.corpus_refusal().is_none());
    assert!(mgr.filter.is_blocked("kept.example"));
}

#[test]
fn poisoned_spill_rejects_publication_operations_after_cleanup() {
    let dir = tempfile::tempdir().unwrap();
    let mut spill = ShardSpill::open(Some(dir.path())).unwrap();
    let mark = spill.mark();

    fail_nth_shard_spill_write_for_test(1);
    assert!(spill.push("candidate.example", 1).is_err());
    assert!(spill.is_poisoned(), "write failure must latch poison");
    assert!(
        spill.rollback(&mark, SpillRollbackSite::DirectTest).is_ok(),
        "cleanup remains available after a write failure"
    );
    assert!(
        spill.is_poisoned(),
        "successful cleanup must not clear poison"
    );
    assert!(spill.push("later.example", 1).is_err());
    assert!(spill.flush().is_err());
    assert!(spill.count_unique(0, &mut [0; 64]).is_err());
    assert!(spill
        .build_shard(0, 0, &ListPolicy::publish_uniform(0))
        .is_err());
}

#[test]
fn flush_and_sync_failures_latch_spill_poison() {
    let dir = tempfile::tempdir().unwrap();
    let mut flush_spill = ShardSpill::open(Some(dir.path())).unwrap();
    fail_nth_shard_spill_flush_for_test(1);
    assert!(flush_spill.flush().is_err());
    assert!(
        flush_spill.is_poisoned(),
        "injected flush failure must latch poison"
    );

    let dir = tempfile::tempdir().unwrap();
    let mut sync_spill = ShardSpill::open(Some(dir.path())).unwrap();
    fail_nth_shard_spill_sync_for_test(1);
    assert!(sync_spill.flush().is_err());
    assert!(
        sync_spill.is_poisoned(),
        "injected sync failure must latch poison"
    );
}

#[test]
fn guard_count_failure_after_prepare_validate_latches_spill_poison() {
    let dir = tempfile::tempdir().unwrap();
    let mut spill = ShardSpill::open(Some(dir.path())).unwrap();
    spill.push("candidate.example", 1).unwrap();
    spill.flush().unwrap();
    spill.prepare_validate().unwrap();

    fail_nth_shard_spill_guard_count_for_test(1);
    assert!(spill.count_unique(0, &mut [0; 64]).is_err());
    assert!(spill.is_poisoned());
    assert!(spill
        .build_shard(0, 0, &ListPolicy::publish_uniform(0))
        .is_err());
}

#[test]
fn exact_boundary_truncation_is_not_accepted_as_clean_spill_eof() {
    let dir = tempfile::tempdir().unwrap();
    let mut spill = ShardSpill::open(Some(dir.path())).unwrap();
    spill.push("complete.example", 1).unwrap();
    spill.flush().unwrap();

    // This removes only the final domain record and leaves its preceding
    // valid bit tag at EOF. A decoder alone can mistake that for clean EOF;
    // the writer-tracked extent must refuse it first.
    truncate_final_shard_spill_record_before_validate_for_test();
    let err = spill
        .prepare_validate()
        .expect_err("a complete final record must not disappear at a valid boundary");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    assert!(spill.is_poisoned());
}

#[test]
fn spill_validation_rejects_malformed_framing_bits_domains_and_routing() {
    let add_raw = |spill: &mut ShardSpill, idx: usize, raw: &[u8]| match spill {
        ShardSpill::Disk { writers, .. } => {
            writers[idx].file.write_all(raw).unwrap();
            writers[idx].written += raw.len() as u64;
        }
        ShardSpill::Memory { .. } => unreachable!("raw framing needs a disk spill"),
    };
    let tagged = |bit: u64, domain: &str| {
        let mut raw = vec![SPILL_BIT_TAG];
        raw.extend_from_slice(&bit.to_le_bytes());
        raw.push(domain.len() as u8);
        raw.extend_from_slice(domain.as_bytes());
        raw
    };

    let valid = "valid.example";
    let cases = [
        (
            0,
            vec![valid.len() as u8]
                .into_iter()
                .chain(valid.bytes())
                .collect(),
        ),
        (
            0,
            vec![SPILL_BIT_TAG]
                .into_iter()
                .chain(0u64.to_le_bytes())
                .collect(),
        ),
        (
            0,
            vec![SPILL_BIT_TAG]
                .into_iter()
                .chain(3u64.to_le_bytes())
                .collect(),
        ),
        (0, vec![SPILL_BIT_TAG, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0xff]),
        (
            FilterEngine::shard_index("bad..example"),
            tagged(1, "bad..example"),
        ),
        (
            (FilterEngine::shard_index(valid) + 1) % DOMAIN_SHARDS,
            tagged(1, valid),
        ),
    ];

    for (idx, raw) in cases {
        let dir = tempfile::tempdir().unwrap();
        let mut spill = ShardSpill::open(Some(dir.path())).unwrap();
        add_raw(&mut spill, idx, &raw);
        spill.flush().unwrap();
        assert!(
            spill.prepare_validate().is_err(),
            "malformed shard was accepted"
        );
        assert!(spill.is_poisoned());
    }
}

#[test]
fn memory_spill_validation_checks_records_without_flattening_buckets() {
    let domain = "memory-validated.example";
    let idx = FilterEngine::shard_index(domain);
    let mut spill = ShardSpill::memory();
    let (ptr, len, capacity) = match &mut spill {
        ShardSpill::Memory { buckets, .. } => {
            buckets[idx].push((CompactString::new(domain), 1));
            (
                buckets[idx].as_ptr(),
                buckets[idx].len(),
                buckets[idx].capacity(),
            )
        }
        ShardSpill::Disk { .. } => unreachable!(),
    };
    spill.prepare_validate().unwrap();
    match &spill {
        ShardSpill::Memory { buckets, .. } => {
            assert_eq!(buckets[idx].as_ptr(), ptr);
            assert_eq!(buckets[idx].len(), len);
            assert_eq!(buckets[idx].capacity(), capacity);
        }
        ShardSpill::Disk { .. } => unreachable!(),
    }

    let mut malformed = ShardSpill::memory();
    if let ShardSpill::Memory { buckets, .. } = &mut malformed {
        buckets[idx].push((CompactString::new(domain), 3));
    }
    assert!(malformed.prepare_validate().is_err());
    assert!(malformed.is_poisoned());
}

fn domain_for_spill_shard(idx: usize) -> String {
    domain_for_named_spill_shard(idx, "spill-shard")
}

fn domain_for_named_spill_shard(idx: usize, name: &str) -> String {
    (0usize..)
        .map(|n| format!("{name}-{idx}-{n}.example"))
        .find(|domain| FilterEngine::shard_index(domain) == idx)
        .unwrap()
}

#[tokio::test]
async fn late_spill_validation_failure_swaps_nothing_or_admits_no_cache_on_hot_or_cold_cycles() {
    let shard_zero = domain_for_spill_shard(0);
    let late_idx = DOMAIN_SHARDS - 1;
    let late = domain_for_spill_shard(late_idx);
    let candidate = format!("{shard_zero}\n{late}\n");

    let (mut mgr, filter, cache_dir, url, _requests) = remote_spill_manager(vec![
        tls_ok_response("old.example\n", "\"old\""),
        tls_ok_response(&candidate, "\"candidate\""),
    ])
    .await;
    assert_eq!(mgr.refresh().await, 1);
    let hot_ids = filter.filter_gen_ids();
    let stem = source_to_cache_stem(&url);
    let manifest = std::fs::read_to_string(cache_dir.path().join(format!("{stem}.meta"))).unwrap();

    age_cache_entries(&mut mgr);
    let hot_cache = mgr.cache.clone();
    // The first validated record belongs to shard zero. The injected second
    // read therefore proves a later shard blocks every swap.
    fail_nth_shard_spill_validation_read_for_test(2);
    assert_eq!(mgr.refresh().await, 1);
    assert_eq!(
        filter.filter_gen_ids(),
        hot_ids,
        "a late validation failure swapped a shard"
    );
    assert_eq!(
        mgr.cache, hot_cache,
        "validation failure admitted candidate cache"
    );
    assert_eq!(
        std::fs::read_to_string(cache_dir.path().join(format!("{stem}.meta"))).unwrap(),
        manifest,
        "validation failure committed a candidate manifest"
    );
    assert!(filter.list_membership(&late).is_empty());
    assert!(
        mgr.installed_corpus_digest.is_none(),
        "a poisoned spill retained a digest that could authorise reuse"
    );

    let (mut cold_mgr, cold_filter, cold_cache, _url, _requests) =
        remote_spill_manager(vec![tls_ok_response(&candidate, "\"candidate\"")]).await;
    fail_nth_shard_spill_validation_read_for_test(2);
    assert_eq!(cold_mgr.refresh().await, 0);
    assert_eq!(cold_filter.filter_gen_ids(), vec![0; DOMAIN_SHARDS]);
    assert!(
        cold_mgr.cache.is_empty(),
        "cold validation failure admitted cache"
    );
    assert!(generation_body_paths(
        cold_cache.path(),
        &source_to_cache_stem("https://lists.test/spill-storage-failure.txt")
    )
    .is_empty());
}

#[tokio::test]
async fn late_guard_count_failure_rejects_whole_candidate_before_any_shard_publishes() {
    let candidates: Vec<String> = (0..DOMAIN_SHARDS).map(domain_for_spill_shard).collect();
    let candidate = format!("{}\n", candidates.join("\n"));

    let (mut mgr, filter, cache_dir, url, _requests) = remote_spill_manager(vec![
        tls_ok_response("old.example\n", "\"old\""),
        tls_ok_response(&candidate, "\"candidate\""),
    ])
    .await;
    assert_eq!(mgr.refresh().await, 1);
    let hot_ids = filter.filter_gen_ids();
    let stem = source_to_cache_stem(&url);
    let manifest = std::fs::read_to_string(cache_dir.path().join(format!("{stem}.meta"))).unwrap();

    age_cache_entries(&mut mgr);
    let hot_cache = mgr.cache.clone();
    mgr.set_max_total_domains(1_000_000);
    // The count pass runs only after prepare_validate; 16 is the final
    // per-shard invocation, so no earlier shard may have published.
    fail_nth_shard_spill_guard_count_for_test(DOMAIN_SHARDS);
    assert_eq!(mgr.refresh().await, 1);
    assert_eq!(filter.filter_gen_ids(), hot_ids);
    assert!(!filter.list_membership("old.example").is_empty());
    for domain in &candidates {
        assert!(
            filter.list_membership(domain).is_empty(),
            "{domain} published"
        );
    }
    assert_eq!(
        mgr.cache, hot_cache,
        "guard failure admitted candidate cache"
    );
    assert_eq!(
        std::fs::read_to_string(cache_dir.path().join(format!("{stem}.meta"))).unwrap(),
        manifest,
        "guard failure committed a candidate manifest"
    );
    assert!(
        mgr.installed_corpus_digest.is_none(),
        "guard failure retained a digest that could authorise reuse"
    );
    let cycle = mgr.status_registry().cycle();
    assert_eq!(cycle.outcome, Some(CycleOutcome::SpillRollbackFailed));
    assert!(cycle.generation_degraded);

    let (mut cold_mgr, cold_filter, cold_cache, cold_url, _requests) =
        remote_spill_manager(vec![tls_ok_response(&candidate, "\"candidate\"")]).await;
    cold_mgr.set_max_total_domains(1_000_000);
    fail_nth_shard_spill_guard_count_for_test(DOMAIN_SHARDS);
    assert_eq!(cold_mgr.refresh().await, 0);
    assert_eq!(cold_filter.filter_gen_ids(), vec![0; DOMAIN_SHARDS]);
    for domain in &candidates {
        assert!(
            cold_filter.list_membership(domain).is_empty(),
            "{domain} published"
        );
    }
    assert!(
        cold_mgr.cache.is_empty(),
        "cold guard failure admitted cache"
    );
    assert!(cold_mgr.installed_corpus_digest.is_none());
    let cold_stem = source_to_cache_stem(&cold_url);
    assert!(!cold_cache.path().join(format!("{cold_stem}.meta")).exists());
    assert!(generation_body_paths(cold_cache.path(), &cold_stem).is_empty());
    let cycle = cold_mgr.status_registry().cycle();
    assert_eq!(cycle.outcome, Some(CycleOutcome::SpillRollbackFailed));
    assert!(cycle.generation_degraded);
}

#[tokio::test]
async fn spill_validation_refuses_when_max_total_domains_is_disabled() {
    let (mut mgr, filter, cache_dir, url, _requests) = remote_spill_manager(vec![
        tls_ok_response("old.example\n", "\"old\""),
        tls_ok_response("candidate.example\n", "\"candidate\""),
    ])
    .await;
    assert_eq!(mgr.refresh().await, 1);
    let hot_ids = filter.filter_gen_ids();
    let stem = source_to_cache_stem(&url);
    let manifest = std::fs::read_to_string(cache_dir.path().join(format!("{stem}.meta"))).unwrap();

    mgr.set_max_total_domains(0);
    age_cache_entries(&mut mgr);
    let hot_cache = mgr.cache.clone();
    fail_nth_shard_spill_validation_read_for_test(1);
    assert_eq!(mgr.refresh().await, 1);
    assert_eq!(filter.filter_gen_ids(), hot_ids);
    assert_eq!(mgr.cache, hot_cache, "disabled ceiling bypassed validation");
    assert_eq!(
        std::fs::read_to_string(cache_dir.path().join(format!("{stem}.meta"))).unwrap(),
        manifest
    );
    assert!(filter.list_membership("candidate.example").is_empty());
}

#[test]
fn rollback_truncate_and_seek_failures_latch_spill_poison() {
    for fail in [
        fail_nth_shard_spill_rollback_truncate_for_test as fn(usize),
        fail_nth_shard_spill_rollback_seek_for_test as fn(usize),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let mut spill = ShardSpill::open(Some(dir.path())).unwrap();
        let mark = spill.mark();
        spill.push("candidate.example", 1).unwrap();
        fail(1);

        assert!(spill
            .rollback(&mark, SpillRollbackSite::DirectTest)
            .is_err());
        assert!(
            spill.is_poisoned(),
            "rollback storage failure must latch poison"
        );
        assert!(spill.flush().is_err());
        assert!(spill.count_unique(0, &mut [0; 64]).is_err());
        assert!(spill
            .build_shard(0, 0, &ListPolicy::publish_uniform(0))
            .is_err());
    }
}

#[tokio::test]
async fn disk_spill_dir_failure_keeps_hot_generation_and_cache_unchanged() {
    let (origin, pem, requests) =
        spawn_tls_origin_responses(vec![tls_ok_response("old.example\n", "\"old\"")]).await;
    let url = "https://lists.test/spill-hot.txt".to_string();
    let cache_dir = tempfile::tempdir().unwrap();
    let filter = Arc::new(FilterEngine::new());
    let mut mgr = ListManager::new(
        reqwest::Client::builder()
            .resolve("lists.test", origin)
            .add_root_certificate(reqwest::Certificate::from_pem(pem.as_bytes()).unwrap())
            .build()
            .unwrap(),
        filter.clone(),
        vec![url.clone()],
        Catalog::fallback(),
        Duration::from_secs(3600),
        build_source_bit_map(std::slice::from_ref(&url)).unwrap(),
        TEST_CAP,
        DEFAULT_MAX_LIST_ENTRIES,
        Some(cache_dir.path().to_path_buf()),
    );
    let now = time::macros::datetime!(2026-09-05 12:00:00 UTC);
    assert_eq!(mgr.refresh_at(now).await, 1);
    let hot_ids = filter.filter_gen_ids();
    let stem = source_to_cache_stem(&url);
    let manifest = std::fs::read_to_string(cache_dir.path().join(format!("{stem}.meta"))).unwrap();
    let body = selected_cache_body_path(cache_dir.path(), &url).unwrap();

    age_cache_entries(&mut mgr);
    let hot_cache = mgr.cache.clone();
    fail_next_shard_spill_dir_create_for_test();

    assert_eq!(mgr.refresh_at(now + time::Duration::hours(2)).await, 1);
    assert_eq!(filter.filter_gen_ids(), hot_ids, "no hot shard may publish");
    assert_eq!(
        mgr.cache, hot_cache,
        "setup failure must not admit cache data"
    );
    assert_eq!(
        std::fs::read_to_string(cache_dir.path().join(format!("{stem}.meta"))).unwrap(),
        manifest,
        "setup failure must not commit a cache manifest"
    );
    assert!(body.is_file(), "the retained cache generation must survive");
    assert_eq!(
        requests.lock().unwrap().len(),
        1,
        "setup failure must stop before fetching sources"
    );
}

#[tokio::test]
async fn disk_spill_file_failure_leaves_cold_start_empty() {
    let (origin, pem, requests) = spawn_tls_origin_responses(vec![tls_ok_response(
        "candidate.example\n",
        "\"candidate\"",
    )])
    .await;
    let url = "https://lists.test/spill-cold.txt".to_string();
    let stem = source_to_cache_stem(&url);
    let cache_dir = tempfile::tempdir().unwrap();
    let filter = Arc::new(FilterEngine::new());
    let mut mgr = ListManager::new(
        reqwest::Client::builder()
            .resolve("lists.test", origin)
            .add_root_certificate(reqwest::Certificate::from_pem(pem.as_bytes()).unwrap())
            .build()
            .unwrap(),
        filter.clone(),
        vec![url.clone()],
        Catalog::fallback(),
        Duration::from_secs(3600),
        build_source_bit_map(std::slice::from_ref(&url)).unwrap(),
        TEST_CAP,
        DEFAULT_MAX_LIST_ENTRIES,
        Some(cache_dir.path().to_path_buf()),
    );

    fail_nth_shard_spill_file_create_for_test(3);

    assert_eq!(mgr.refresh().await, 0);
    assert_eq!(filter.domain_count(), 0, "cold start must stay empty");
    assert_eq!(
        filter.filter_gen_ids(),
        vec![0; DOMAIN_SHARDS],
        "cold shards must remain unpublished"
    );
    assert!(
        mgr.cache.is_empty(),
        "setup failure must not admit a cache body"
    );
    assert!(!cache_dir.path().join(format!("{stem}.meta")).exists());
    assert!(generation_body_paths(cache_dir.path(), &stem).is_empty());
    assert!(
        !cache_dir.path().join(SHARD_SPILL_DIR).exists(),
        "a failed setup must not leave a partial spill"
    );
    assert_eq!(
        requests.lock().unwrap().len(),
        0,
        "cold setup failure must stop before fetching sources"
    );
    let cycle = mgr.status_registry.cycle();
    assert_eq!(cycle.seq, 1, "one failed attempt publishes once");
    assert_eq!(cycle.outcome, Some(CycleOutcome::SpillRollbackFailed));
    assert!(cycle.source_coverage_incomplete);
    assert!(cycle.generation_degraded);
    assert_eq!(cycle.served_state, ServedState::Uninitialized);
}

async fn remote_spill_manager(
    responses: Vec<String>,
) -> (
    ListManager,
    Arc<FilterEngine>,
    tempfile::TempDir,
    String,
    Arc<std::sync::Mutex<Vec<String>>>,
) {
    let (origin, pem, requests) = spawn_tls_origin_responses(responses).await;
    let url = "https://lists.test/spill-storage-failure.txt".to_string();
    let cache_dir = tempfile::tempdir().unwrap();
    let filter = Arc::new(FilterEngine::new());
    let mgr = ListManager::new(
        reqwest::Client::builder()
            .resolve("lists.test", origin)
            .add_root_certificate(reqwest::Certificate::from_pem(pem.as_bytes()).unwrap())
            .build()
            .unwrap(),
        filter.clone(),
        vec![url.clone()],
        Catalog::fallback(),
        Duration::from_secs(3600),
        build_source_bit_map(std::slice::from_ref(&url)).unwrap(),
        TEST_CAP,
        DEFAULT_MAX_LIST_ENTRIES,
        Some(cache_dir.path().to_path_buf()),
    );
    (mgr, filter, cache_dir, url, requests)
}

#[tokio::test]
async fn spill_write_failure_preserves_hot_generation_and_refuses_candidate_cache() {
    let (mut mgr, filter, cache_dir, url, requests) = remote_spill_manager(vec![
        tls_ok_response("old.example\n", "\"old\""),
        tls_ok_response("candidate.example\n", "\"candidate\""),
    ])
    .await;
    let now = time::macros::datetime!(2026-09-05 12:00:00 UTC);
    assert_eq!(mgr.refresh_at(now).await, 1);
    let hot_ids = filter.filter_gen_ids();
    let stem = source_to_cache_stem(&url);
    let manifest = std::fs::read_to_string(cache_dir.path().join(format!("{stem}.meta"))).unwrap();

    age_cache_entries(&mut mgr);
    let hot_cache = mgr.cache.clone();
    fail_nth_shard_spill_write_for_test(1);

    assert_eq!(mgr.refresh_at(now + time::Duration::hours(2)).await, 1);
    assert_eq!(filter.filter_gen_ids(), hot_ids, "no hot shard may publish");
    assert_eq!(
        mgr.cache, hot_cache,
        "write failure admitted candidate cache"
    );
    assert_eq!(
        std::fs::read_to_string(cache_dir.path().join(format!("{stem}.meta"))).unwrap(),
        manifest,
        "write failure committed a candidate manifest"
    );
    assert!(filter.list_membership("candidate.example").is_empty());
    assert_eq!(requests.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn spill_write_failure_leaves_cold_generation_and_cache_empty() {
    let (mut mgr, filter, cache_dir, url, _requests) = remote_spill_manager(vec![tls_ok_response(
        "candidate.example\n",
        "\"candidate\"",
    )])
    .await;
    let stem = source_to_cache_stem(&url);
    fail_nth_shard_spill_write_for_test(1);

    assert_eq!(mgr.refresh().await, 0);
    assert_eq!(filter.filter_gen_ids(), vec![0; DOMAIN_SHARDS]);
    assert!(
        mgr.cache.is_empty(),
        "write failure admitted candidate cache"
    );
    assert!(!cache_dir.path().join(format!("{stem}.meta")).exists());
    assert!(generation_body_paths(cache_dir.path(), &stem).is_empty());
}

#[tokio::test]
async fn spill_flush_and_sync_failures_preserve_hot_generation_and_cache() {
    for fail in [
        fail_nth_shard_spill_flush_for_test as fn(usize),
        fail_nth_shard_spill_sync_for_test as fn(usize),
    ] {
        let (mut mgr, filter, cache_dir, url, _requests) = remote_spill_manager(vec![
            tls_ok_response("old.example\n", "\"old\""),
            tls_ok_response("candidate.example\n", "\"candidate\""),
        ])
        .await;
        let now = time::macros::datetime!(2026-09-05 12:00:00 UTC);
        assert_eq!(mgr.refresh_at(now).await, 1);
        let hot_ids = filter.filter_gen_ids();
        let stem = source_to_cache_stem(&url);
        let manifest =
            std::fs::read_to_string(cache_dir.path().join(format!("{stem}.meta"))).unwrap();

        age_cache_entries(&mut mgr);
        let hot_cache = mgr.cache.clone();
        fail(1);

        assert_eq!(mgr.refresh_at(now + time::Duration::hours(2)).await, 1);
        assert_eq!(filter.filter_gen_ids(), hot_ids, "no hot shard may publish");
        assert_eq!(
            mgr.cache, hot_cache,
            "storage failure admitted candidate cache"
        );
        assert_eq!(
            std::fs::read_to_string(cache_dir.path().join(format!("{stem}.meta"))).unwrap(),
            manifest,
            "storage failure committed a candidate manifest"
        );
        assert!(filter.list_membership("candidate.example").is_empty());
    }
}

// ── The global corpus guard, driven through `refresh()` ───────────

/// A manager that re-reads every body from the `imported.local` bridge
/// on **every** cycle (zero refresh interval), so a test can change the
/// corpus between refreshes instead of being served the disk cache.
///
/// `on_disk == false` leaves `cache_dir` unset, which is what selects
/// [`ShardSpill::Memory`] — the F14 divergence the DoD requires every
/// case to cover.
fn guard_manager(bodies: &[&str], on_disk: bool) -> (ListManager, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let lists_dir = dir.path().join("lists");
    std::fs::create_dir_all(&lists_dir).unwrap();
    let cache_dir = dir.path().join("cache");
    std::fs::create_dir_all(&cache_dir).unwrap();

    let mut urls = Vec::new();
    let mut blocklists = Vec::new();
    for (i, body) in bodies.iter().enumerate() {
        let name = format!("src{i}");
        std::fs::write(lists_dir.join(format!("{name}.txt")), body).unwrap();
        let url = format!("https://imported.local/{name}.txt");
        blocklists.push(crate::config::schema::Blocklist {
            id: crate::config::schema::id::Id::new(&name).unwrap(),
            display_name: name.clone(),
            url: url.clone(),
            format: Default::default(),
            update_interval_hours: None,
            max_entries: None,
            enabled: true,
            auth_token_ref: None,
            base: crate::config::schema::BlocklistBase::Deny,
            trust: BlocklistTrust::Local,
            accept_unsigned_allow: false,
            max_consecutive_failures: 5,
        });
        urls.push(url);
    }

    let bits = build_source_bit_map(&urls).expect("at-cap accept");
    let mut mgr = ListManager::new(
        reqwest::Client::new(),
        Arc::new(FilterEngine::new()),
        urls,
        Catalog::fallback(),
        // Note this does NOT become zero: `ListManager::new` clamps it
        // up to `MIN_REFRESH_INTERVAL` (60 s). A second cycle therefore
        // cannot be made to re-read by shortening the interval — see
        // `expire_bodies`.
        Duration::ZERO,
        bits,
        TEST_CAP,
        DEFAULT_MAX_LIST_ENTRIES,
        on_disk.then(|| cache_dir.clone()),
    );
    mgr.set_local_bridge(SourceTrustMap::build(&blocklists), dir.path().to_path_buf());
    (mgr, dir)
}

/// Rewrite one bridge body in place, for a second cycle.
fn rewrite_body(dir: &tempfile::TempDir, i: usize, body: &str) {
    std::fs::write(dir.path().join("lists").join(format!("src{i}.txt")), body).unwrap();
}

/// Drop the in-memory cache so the next cycle re-reads the bridge.
///
/// Needed only on the `cache_dir: None` (memory-spill) arm, and it is
/// not a contrivance: with a cache dir bodies are not retained in memory.
/// Without one the body is retained and `MIN_REFRESH_INTERVAL` (60 s,
/// clamped in `new`) makes it fresh, so a second cycle in the same test
/// second would silently re-parse the old corpus. Calling this on both
/// arms keeps them symmetric.
fn expire_bodies(mgr: &mut ListManager) {
    mgr.cache.clear();
}

/// **The regression the reverted implementation caused.**
///
/// `7611767` accumulated a *pre-dedup* line count and compared it to a
/// ceiling derived from the *deduplicated* map. Live, that is
/// Σ`parsed_ok` 29,542,862 against a merged unique 12,346,316 — a
/// ~2.4× overlap — so the budget emptied mid-cycle and refused sources
/// nowhere near any real limit.
///
/// Here: 8 records pre-dedup, 5 distinct domains, ceiling 6. A guard
/// measuring the pre-dedup sum refuses; a guard measuring the union
/// accepts. **Driving `refresh()` end to end is the whole point** —
/// the reverted code's own test carried four assertions and still
/// could not see this, because it hand-built the budget struct and
/// called `parse_source_into_spill` directly, so the real
/// `spilled`-versus-ceiling computation was never exercised.
#[tokio::test]
async fn refresh_accepts_a_corpus_whose_pre_dedup_sum_exceeds_the_budget() {
    for on_disk in [true, false] {
        let (mut mgr, _dir) = guard_manager(
            &[
                "a.example\nb.example\nc.example\nd.example\n",
                "a.example\nb.example\nc.example\ne.example\n",
            ],
            on_disk,
        );
        // 8 records spilled, 5 distinct. The ceiling sits between them.
        mgr.set_max_total_domains(6);

        let total = mgr.refresh().await;

        assert_eq!(
            total, 5,
            "the union is 5 and fits under 6; only a pre-dedup count \
             (8) refuses this (on_disk={on_disk})"
        );
        assert_eq!(mgr.filter.domain_count(), 5, "on_disk={on_disk}");
        for d in [
            "a.example",
            "b.example",
            "c.example",
            "d.example",
            "e.example",
        ] {
            assert!(
                !mgr.filter.list_membership(d).is_empty(),
                "{d} missing from the installed generation (on_disk={on_disk})"
            );
        }
        // A domain nobody listed must still miss, or the loop above
        // would pass against a map that matched everything.
        assert!(mgr.filter.list_membership("absent.example").is_empty());

        // And no source was blamed. This is the half the reverted code
        // got visibly wrong: it marked sources Failed for exceeding a
        // budget none of them had actually exhausted.
        use crate::lists::status::LastOutcome;
        let snap = mgr.status_registry.snapshot();
        assert_eq!(snap.len(), 2, "on_disk={on_disk}");
        for (source, st) in &snap {
            assert_eq!(
                st.last_outcome,
                LastOutcome::Ok,
                "{source} was refused under a budget the corpus fits (on_disk={on_disk})"
            );
        }
        assert_eq!(
            snap.iter().map(|(_, s)| s.entries).sum::<u64>(),
            5,
            "per-source novel contributions must sum to the union"
        );
    }
}

/// The control arm: a ceiling **below** the union must refuse the whole
/// cycle, keep the previous generation intact, and clear the digest.
///
/// The digest assertion is the one with teeth. `installed_corpus_digest`
/// is what lets a cycle decide "no body changed, skip the rebuild". Store
/// this cycle's digest without having installed it and the next cycle
/// computes the same digest, concludes nothing changed, and skips again —
/// the daemon then serves a stale corpus silently and indefinitely, even
/// after the operator raises the ceiling.
///
/// Paired with a `ceiling = 10` arm so the refusal is shown to be caused
/// by the ceiling rather than by anything else about the second cycle.
#[tokio::test]
async fn refresh_refuses_the_cycle_and_keeps_the_previous_generation() {
    const OLD: [&str; 5] = [
        "a.example",
        "b.example",
        "c.example",
        "d.example",
        "e.example",
    ];
    const NEW: [&str; 6] = [
        "f.example",
        "g.example",
        "h.example",
        "i.example",
        "j.example",
        "k.example",
    ];

    for on_disk in [true, false] {
        for ceiling in [4usize, 10] {
            let refuses = ceiling < NEW.len();
            let (mut mgr, dir) = guard_manager(
                &[
                    "a.example\nb.example\nc.example\n",
                    "d.example\ne.example\n",
                ],
                on_disk,
            );

            // Cycle 1, guard disabled: establish a generation to keep.
            assert_eq!(mgr.refresh().await, 5, "on_disk={on_disk}");
            assert!(
                mgr.installed_corpus_digest.is_some(),
                "cycle 1 installed, so its digest must be stored"
            );
            let entries_before: Vec<u64> = mgr
                .status_registry
                .snapshot()
                .iter()
                .map(|(_, s)| s.entries)
                .collect();

            // Cycle 2: a different, larger corpus.
            rewrite_body(&dir, 0, "f.example\ng.example\nh.example\n");
            rewrite_body(&dir, 1, "i.example\nj.example\nk.example\n");
            expire_bodies(&mut mgr);
            mgr.set_max_total_domains(ceiling);

            let total = mgr.refresh().await;

            if refuses {
                assert_eq!(
                    total, 5,
                    "a refused cycle must report the generation still serving, \
                     not the one it measured and discarded (on_disk={on_disk})"
                );
                assert_eq!(mgr.filter.domain_count(), 5, "on_disk={on_disk}");
                for d in OLD {
                    assert!(
                        !mgr.filter.list_membership(d).is_empty(),
                        "{d} was evicted by a refused cycle (on_disk={on_disk})"
                    );
                }
                for d in NEW {
                    assert!(
                        mgr.filter.list_membership(d).is_empty(),
                        "{d} from the refused corpus reached the engine (on_disk={on_disk})"
                    );
                }
                assert!(
                    mgr.installed_corpus_digest.is_none(),
                    "a refused cycle stored its digest — the next cycle would decide \
                     nothing changed and skip for ever (on_disk={on_disk})"
                );

                // The cycle-level refusal must actually reach the
                // registry, which is what every reporting surface
                // reads. Without this the assertions above are also
                // satisfied by the `unchanged` fast path, which keeps
                // the same generation for an entirely different reason
                // — they cannot tell "refused" from "nothing to do".
                let refusal = mgr
                    .status_registry
                    .corpus_refusal()
                    .expect("a refused cycle published no refusal state");
                assert_eq!(refusal.unique, 6, "on_disk={on_disk}");
                assert_eq!(refusal.ceiling, 4, "on_disk={on_disk}");
                // Actionable: the operator has to be told which list
                // to drop, per source, or the refusal is a dead end.
                assert_eq!(refusal.novel_by_source.len(), 2, "on_disk={on_disk}");
                assert_eq!(
                    refusal.novel_by_source.iter().map(|(_, n)| n).sum::<u64>(),
                    6,
                    "novel contributions must account for the whole refused corpus"
                );
                assert_eq!(
                    mgr.status_registry
                        .snapshot()
                        .iter()
                        .map(|(_, s)| s.entries)
                        .collect::<Vec<_>>(),
                    entries_before,
                    "`entries` must keep describing the generation that is serving \
                     (on_disk={on_disk})"
                );
            } else {
                // Same second cycle, same corpus, roomy ceiling: the
                // refusal above is attributable to the ceiling alone.
                assert_eq!(total, 6, "on_disk={on_disk}");
                for d in NEW {
                    assert!(
                        !mgr.filter.list_membership(d).is_empty(),
                        "{d} missing under a roomy ceiling (on_disk={on_disk})"
                    );
                }
                assert!(mgr.installed_corpus_digest.is_some());
                // Cleared on a successful install. A refusal left
                // standing after a later cycle installs would be the
                // same lie pointing the other way.
                assert!(
                    mgr.status_registry.corpus_refusal().is_none(),
                    "an installed cycle left a refusal set (on_disk={on_disk})"
                );
            }
        }
    }
}
/// Push every cached entry's `fetched_at` an hour into the past so the
/// freshness shortcut cannot fire, WITHOUT dropping the retained body the
/// way [`expire_bodies`] does. On the memory-spill arm there is no
/// `.cache` file, so that body is the only thing a refused cycle has to
/// fall back on — clearing it would make the fallback untestable there.
fn age_cache_entries(mgr: &mut ListManager) {
    for entry in mgr.cache.values_mut() {
        entry.fetched_at -= std::time::Duration::from_secs(3600);
    }
}

#[tokio::test]
async fn a_nonempty_refused_allow_candidate_never_reaches_the_next_generation() {
    const DENY_FIRST: &str = "protected.example\nother-protected.example\nold-unrelated.example\n";
    const DENY_SECOND: &str = "protected.example\nother-protected.example\nnew-unrelated.example\n";
    let retained_allow: String = (0..11)
        .map(|i| format!("retained-allow-{i}.example\n"))
        .collect();

    for on_disk in [true, false] {
        let (mut mgr, dir) = guard_manager(&[DENY_FIRST, &retained_allow], on_disk);
        mgr.set_list_policy(PolicyMasks {
            base: ProfileMasks {
                allow: 1 << 1,
                block: 1,
            },
            per_profile: Default::default(),
        });

        assert_eq!(mgr.refresh().await, 14, "on_disk={on_disk}");

        // Source zero changes independently, so this cycle must install.
        rewrite_body(&dir, 0, DENY_SECOND);
        rewrite_body(&dir, 1, "protected.example\n");
        age_cache_entries(&mut mgr);

        assert_eq!(mgr.refresh().await, 14, "on_disk={on_disk}");
        assert_eq!(mgr.rebuild_count, 2, "on_disk={on_disk}");
        assert_ne!(
            mgr.filter
                .list_membership("new-unrelated.example")
                .block_mask,
            0,
            "the unrelated source change was not installed (on_disk={on_disk})"
        );
        let protected = mgr.filter.list_membership("protected.example");
        assert_ne!(protected.block_mask, 0, "on_disk={on_disk}");
        assert_eq!(
            protected.allow_mask, 0,
            "the refused allow candidate unblocked a deny-list domain (on_disk={on_disk})"
        );
        assert_ne!(
            mgr.filter
                .list_membership("retained-allow-0.example")
                .allow_mask,
            0,
            "the retained allow body was not restored (on_disk={on_disk})"
        );
        assert!(matches!(
            mgr.status_registry
                .status_for_url("https://imported.local/src1.txt")
                .unwrap()
                .last_outcome,
            crate::lists::status::LastOutcome::Failed { .. }
        ));
        let digest_after_refusal = mgr
            .installed_corpus_digest
            .expect("the retained corpus installed without a digest");

        if !on_disk {
            assert_eq!(
                mgr.cache
                    .get("https://imported.local/src1.txt")
                    .and_then(|entry| entry.body.as_deref()),
                Some(retained_allow.as_str()),
                "the memory-only fallback lost its retained body"
            );
        }

        // Changing only a refused candidate cannot change the installed digest.
        rewrite_body(&dir, 1, "other-protected.example\n");
        age_cache_entries(&mut mgr);

        assert_eq!(mgr.refresh().await, 14, "on_disk={on_disk}");
        assert_eq!(
            mgr.rebuild_count, 2,
            "a refused candidate changed the installed digest (on_disk={on_disk})"
        );
        assert_eq!(
            mgr.installed_corpus_digest,
            Some(digest_after_refusal),
            "the digest includes a refused candidate (on_disk={on_disk})"
        );
        assert_eq!(
            mgr.filter
                .list_membership("other-protected.example")
                .allow_mask,
            0,
            "the next refused allow candidate reached the map (on_disk={on_disk})"
        );
    }
}

#[tokio::test]
async fn a_fresh_parse_rollback_failure_keeps_all_cycle_records_out_of_the_map() {
    for on_disk in [true, false] {
        let (mut mgr, dir) = guard_manager(
            &["old-a.example\n", "old-b-one.example\nold-b-two.example\n"],
            on_disk,
        );
        mgr.max_entries = 2;
        assert_eq!(mgr.refresh().await, 3, "on_disk={on_disk}");

        rewrite_body(&dir, 0, "old-a.example\nnew-a.example\n");
        rewrite_body(
            &dir,
            1,
            "candidate-b-one.example\ncandidate-b-two.example\ncandidate-b-three.example\n",
        );
        age_cache_entries(&mut mgr);
        fail_shard_spill_rollback_at_for_test(SpillRollbackSite::FreshParse);

        assert_eq!(mgr.refresh().await, 3, "on_disk={on_disk}");
        for domain in ["old-a.example", "old-b-one.example", "old-b-two.example"] {
            assert!(
                !mgr.filter.list_membership(domain).is_empty(),
                "{domain} was removed (on_disk={on_disk})"
            );
        }
        for domain in [
            "new-a.example",
            "candidate-b-one.example",
            "candidate-b-two.example",
            "candidate-b-three.example",
        ] {
            assert!(
                mgr.filter.list_membership(domain).is_empty(),
                "{domain} leaked from a poisoned spill (on_disk={on_disk})"
            );
        }
        assert!(
            mgr.installed_corpus_digest.is_none(),
            "a poisoned spill must not publish a digest (on_disk={on_disk})"
        );
        assert_eq!(
            mgr.status_registry.cycle().outcome,
            Some(CycleOutcome::SpillRollbackFailed),
            "the cycle must not report Installed (on_disk={on_disk})"
        );
    }
}

#[tokio::test]
async fn rollback_truncate_and_seek_failures_poison_the_hot_cycle() {
    for fail in [
        fail_nth_shard_spill_rollback_truncate_for_test as fn(usize),
        fail_nth_shard_spill_rollback_seek_for_test as fn(usize),
    ] {
        let (mut mgr, dir) = guard_manager(
            &["old-a.example\n", "old-b-one.example\nold-b-two.example\n"],
            true,
        );
        mgr.max_entries = 2;
        assert_eq!(mgr.refresh().await, 3);
        let hot_ids = mgr.filter.filter_gen_ids();

        rewrite_body(&dir, 0, "old-a.example\nnew-a.example\n");
        rewrite_body(
            &dir,
            1,
            "candidate-b-one.example\ncandidate-b-two.example\ncandidate-b-three.example\n",
        );
        age_cache_entries(&mut mgr);
        fail(1);

        assert_eq!(mgr.refresh().await, 3);
        assert_eq!(
            mgr.filter.filter_gen_ids(),
            hot_ids,
            "rollback storage failure swapped a hot shard"
        );
        assert!(mgr.filter.list_membership("new-a.example").is_empty());
        assert!(mgr
            .filter
            .list_membership("candidate-b-one.example")
            .is_empty());
        assert_eq!(
            mgr.status_registry.cycle().outcome,
            Some(CycleOutcome::SpillRollbackFailed)
        );
        assert!(mgr.status_registry.cycle().generation_degraded);
    }
}

#[tokio::test]
async fn a_retained_body_parse_rollback_failure_keeps_all_cycle_records_out_of_the_map() {
    for on_disk in [true, false] {
        let (mut mgr, dir) = guard_manager(
            &[
                "old-a.example\n",
                "old-b-one.example\nold-b-two.example\nold-b-three.example\n",
            ],
            on_disk,
        );
        mgr.max_entries = 3;
        assert_eq!(mgr.refresh().await, 4, "on_disk={on_disk}");

        mgr.max_entries = 2;
        mgr.set_shrink_guard(true, 49);
        rewrite_body(&dir, 0, "old-a.example\nnew-a.example\n");
        rewrite_body(&dir, 1, "candidate-b.example\n");
        age_cache_entries(&mut mgr);
        // The retained body trips the lower cap after guard fallback.
        // Target that rollback directly; unrelated rollback order must not matter.
        fail_shard_spill_rollback_at_for_test(SpillRollbackSite::RetainedParse);

        assert_eq!(mgr.refresh().await, 4, "on_disk={on_disk}");
        for domain in [
            "old-a.example",
            "old-b-one.example",
            "old-b-two.example",
            "old-b-three.example",
        ] {
            assert!(
                !mgr.filter.list_membership(domain).is_empty(),
                "{domain} was removed (on_disk={on_disk})"
            );
        }
        for domain in ["new-a.example", "candidate-b.example"] {
            assert!(
                mgr.filter.list_membership(domain).is_empty(),
                "{domain} leaked from a poisoned spill (on_disk={on_disk})"
            );
        }
        assert!(
            mgr.installed_corpus_digest.is_none(),
            "a poisoned spill must not publish a digest (on_disk={on_disk})"
        );
        assert_eq!(
            mgr.status_registry.cycle().outcome,
            Some(CycleOutcome::SpillRollbackFailed),
            "the cycle must not report Installed (on_disk={on_disk})"
        );
    }
}

#[tokio::test]
async fn a_refused_candidate_rollback_failure_keeps_all_cycle_records_out_of_the_map() {
    for on_disk in [true, false] {
        let (mut mgr, dir) = guard_manager(
            &[
                "old-a.example\n",
                "old-b-one.example\nold-b-two.example\nold-b-three.example\n",
            ],
            on_disk,
        );
        assert_eq!(mgr.refresh().await, 4, "on_disk={on_disk}");

        mgr.set_shrink_guard(true, 50);
        rewrite_body(&dir, 0, "old-a.example\nnew-a.example\n");
        rewrite_body(&dir, 1, "candidate-b.example\n");
        age_cache_entries(&mut mgr);
        fail_shard_spill_rollback_at_for_test(SpillRollbackSite::FreshRetentionGuard);

        assert_eq!(mgr.refresh().await, 4, "on_disk={on_disk}");
        for domain in [
            "old-a.example",
            "old-b-one.example",
            "old-b-two.example",
            "old-b-three.example",
        ] {
            assert!(
                !mgr.filter.list_membership(domain).is_empty(),
                "{domain} was removed (on_disk={on_disk})"
            );
        }
        for domain in ["new-a.example", "candidate-b.example"] {
            assert!(
                mgr.filter.list_membership(domain).is_empty(),
                "{domain} leaked from a poisoned spill (on_disk={on_disk})"
            );
        }
        assert!(
            mgr.installed_corpus_digest.is_none(),
            "a poisoned spill must not publish a digest (on_disk={on_disk})"
        );
        assert_eq!(
            mgr.status_registry.cycle().outcome,
            Some(CycleOutcome::SpillRollbackFailed),
            "the cycle must not report Installed (on_disk={on_disk})"
        );
    }
}

#[tokio::test]
async fn accepted_empty_spill_replaces_the_live_generation() {
    let (mut mgr, dir) = guard_manager(&["old-a.example\nold-b.example\n"], true);
    assert_eq!(mgr.refresh().await, 2);
    let before = mgr.filter.filter_gen_ids();
    mgr.set_shrink_guard(false, 0);
    rewrite_body(&dir, 0, "");
    age_cache_entries(&mut mgr);

    assert_eq!(mgr.refresh().await, 0);
    let mark = mgr.status_registry().consistent_snapshot().cycle;
    assert_eq!(mark.outcome, Some(CycleOutcome::Installed));
    assert!(!mark.generation_degraded);
    assert_eq!(mark.served_state, ServedState::IntentionalEmpty);
    let row = mgr
        .status_registry()
        .status_for_url("https://imported.local/src0.txt")
        .unwrap();
    assert_eq!(row.entries, 0, "the row must describe the empty generation");
    assert!(
        mgr.filter.list_membership("old-a.example").is_empty(),
        "an accepted empty source must clear the hot corpus"
    );
    let after = mgr.filter.filter_gen_ids();
    assert!(after.iter().all(|&id| id != 0));
    assert!(after.iter().all(|&id| id == after[0]));
    assert_ne!(after, before, "the empty replacement must publish");
}

#[tokio::test]
async fn complete_empty_cold_install_is_not_an_uninitialized_corpus() {
    let (mut mgr, _urls, _dir) = spill_manager(&[""]);

    assert_eq!(mgr.refresh().await, 0);
    let mark = mgr.status_registry().cycle();
    assert_eq!(mark.outcome, Some(CycleOutcome::Installed));
    assert_eq!(mark.served_state, ServedState::IntentionalEmpty);
    assert!(!mark.source_coverage_incomplete);
    assert!(!mark.generation_degraded);
}

#[tokio::test]
async fn comments_only_corpus_installs_an_empty_ready_generation() {
    let (mut mgr, _urls, _dir) = spill_manager(&["# no domains\n! comment\n"]);
    let gate = ReadinessGate::new(false);
    mgr.set_filter_ready_gate(gate.clone());

    assert_eq!(mgr.refresh().await, 0);
    assert_eq!(
        mgr.status_registry().cycle().served_state,
        ServedState::IntentionalEmpty
    );
    assert!(
        gate.is_open(),
        "an accepted empty generation is ready to serve"
    );
}

#[tokio::test]
async fn repeated_empty_corpus_skips_the_unchanged_rebuild() {
    let (mut mgr, _urls, _dir) = spill_manager(&[""]);

    assert_eq!(mgr.refresh().await, 0);
    let first_ids = mgr.filter.filter_gen_ids();
    assert_eq!(mgr.refresh().await, 0);

    let mark = mgr.status_registry().cycle();
    assert_eq!(mark.outcome, Some(CycleOutcome::SkippedUnchanged));
    assert_eq!(mark.served_state, ServedState::IntentionalEmpty);
    assert_eq!(mgr.filter.filter_gen_ids(), first_ids);
}

#[tokio::test]
async fn spill_flush_failure_keeps_prior_counts_and_never_reports_installed() {
    let (mut mgr, dir) = guard_manager(&["old-a.example\nold-b.example\n"], true);
    assert_eq!(mgr.refresh().await, 2);
    rewrite_body(&dir, 0, "old-a.example\nold-b.example\nnew.example\n");
    age_cache_entries(&mut mgr);
    fail_nth_shard_spill_flush_for_test(1);

    assert_eq!(mgr.refresh().await, 2);
    let mark = mgr.status_registry().consistent_snapshot().cycle;
    assert_eq!(mark.outcome, Some(CycleOutcome::SpillRollbackFailed));
    assert!(mark.generation_degraded);
    let row = mgr
        .status_registry()
        .status_for_url("https://imported.local/src0.txt")
        .unwrap();
    assert_eq!(
        row.entries, 2,
        "flush failure must retain live contribution counts"
    );
    assert!(mgr.filter.list_membership("new.example").is_empty());
}

#[tokio::test]
async fn disk_shard_build_retries_at_first_middle_and_last_positions() {
    let domains: Vec<String> = (0..DOMAIN_SHARDS).map(domain_for_spill_shard).collect();
    let body = format!("{}\n", domains.join("\n"));

    for failure_at in [1, 8, DOMAIN_SHARDS] {
        let (mut mgr, _dir) = guard_manager(&[&body], true);
        fail_nth_shard_build_for_test(failure_at);

        assert_eq!(
            mgr.refresh().await,
            DOMAIN_SHARDS,
            "failure_at={failure_at}"
        );
        let ids = mgr.filter.filter_gen_ids();
        assert!(ids.iter().all(|&id| id != 0), "failure_at={failure_at}");
        assert!(
            ids.iter().all(|&id| id == ids[0]),
            "retry left a hybrid generation at build {failure_at}"
        );
        for domain in &domains {
            assert!(
                !mgr.filter.list_membership(domain).is_empty(),
                "{domain} missing after retry at build {failure_at}"
            );
        }
        let row = mgr
            .status_registry()
            .status_for_url("https://imported.local/src0.txt")
            .unwrap();
        assert_eq!(row.entries, DOMAIN_SHARDS as u64, "failure_at={failure_at}");
        assert_eq!(
            row.unique_domains, DOMAIN_SHARDS as u64,
            "failure_at={failure_at}"
        );
        let cycle = mgr.status_registry().cycle();
        assert_eq!(cycle.outcome, Some(CycleOutcome::Installed));
        assert!(!cycle.generation_degraded);
    }
}

#[tokio::test]
async fn memory_shard_build_replays_a_borrowed_bucket() {
    let domains: Vec<String> = (0..DOMAIN_SHARDS).map(domain_for_spill_shard).collect();
    let body = format!("{}\n", domains.join("\n"));
    let (mut mgr, _dir) = guard_manager(&[&body], false);
    fail_nth_shard_build_for_test(8);

    assert_eq!(mgr.refresh().await, DOMAIN_SHARDS);
    let ids = mgr.filter.filter_gen_ids();
    assert!(ids.iter().all(|&id| id != 0));
    assert!(ids.iter().all(|&id| id == ids[0]));
    for domain in &domains {
        assert!(
            !mgr.filter.list_membership(domain).is_empty(),
            "{domain} missing"
        );
    }
    let row = mgr
        .status_registry()
        .status_for_url("https://imported.local/src0.txt")
        .unwrap();
    assert_eq!(row.entries, DOMAIN_SHARDS as u64);
    assert_eq!(row.unique_domains, DOMAIN_SHARDS as u64);
}

#[tokio::test]
async fn persistent_shard_build_failure_keeps_only_that_old_shard_and_candidate_cache_out() {
    let old: Vec<String> = (0..DOMAIN_SHARDS)
        .map(|idx| domain_for_named_spill_shard(idx, "old"))
        .collect();
    let candidate: Vec<String> = (0..DOMAIN_SHARDS)
        .map(|idx| domain_for_named_spill_shard(idx, "candidate"))
        .collect();
    let old_body = format!("{}\n", old.join("\n"));
    let candidate_body = format!("{}\n", candidate.join("\n"));
    let (mut mgr, filter, cache_dir, url, _requests) = remote_spill_manager(vec![
        tls_ok_response(&old_body, "\"old\""),
        tls_ok_response(&candidate_body, "\"candidate\""),
        tls_ok_response(&candidate_body, "\"candidate\""),
    ])
    .await;

    assert_eq!(mgr.refresh().await, DOMAIN_SHARDS);
    let before_ids = filter.filter_gen_ids();
    let stem = source_to_cache_stem(&url);
    let manifest = std::fs::read_to_string(cache_dir.path().join(format!("{stem}.meta"))).unwrap();
    let bodies = generation_body_paths(cache_dir.path(), &stem);

    mgr.set_list_policy(PolicyMasks {
        base: ProfileMasks { allow: 1, block: 0 },
        per_profile: Default::default(),
    });
    age_cache_entries(&mut mgr);
    let cache = mgr.cache.clone();
    let failed_idx = 7;
    fail_nth_shard_builds_for_test(failed_idx + 1, 2);

    assert_eq!(mgr.refresh().await, DOMAIN_SHARDS);
    let after_ids = filter.filter_gen_ids();
    for idx in 0..DOMAIN_SHARDS {
        if idx == failed_idx {
            assert_eq!(after_ids[idx], before_ids[idx], "failed shard changed");
        } else {
            assert_ne!(
                after_ids[idx], before_ids[idx],
                "shard {idx} did not publish"
            );
            let membership = filter.list_membership(&candidate[idx]);
            assert_eq!(
                membership.allow_mask, 1,
                "shard {idx} lost its policy pairing"
            );
            assert_eq!(membership.block_mask, 0, "shard {idx} used its old policy");
        }
    }
    assert_eq!(
        filter.list_membership(&old[failed_idx]).block_mask,
        1,
        "the failed shard did not retain its old policy and domain"
    );
    assert!(filter.list_membership(&candidate[failed_idx]).is_empty());
    let cycle = mgr.status_registry().cycle();
    assert_eq!(cycle.outcome, Some(CycleOutcome::SpillRollbackFailed));
    assert!(cycle.generation_degraded);
    assert_eq!(cycle.served_state, ServedState::Partial);
    assert_eq!(
        mgr.status_registry().status_for_url(&url).unwrap().entries,
        DOMAIN_SHARDS as u64,
        "the partial cycle must keep reporting the old complete source contribution"
    );
    assert!(mgr.installed_corpus_digest.is_none());
    assert_eq!(
        mgr.cache, cache,
        "persistent failure admitted candidate cache"
    );
    assert_eq!(
        std::fs::read_to_string(cache_dir.path().join(format!("{stem}.meta"))).unwrap(),
        manifest,
        "persistent failure committed a candidate manifest"
    );
    assert_eq!(generation_body_paths(cache_dir.path(), &stem), bodies);

    age_cache_entries(&mut mgr);
    assert_eq!(
        mgr.refresh().await,
        DOMAIN_SHARDS,
        "manager did not recover"
    );
    let recovered_ids = mgr.filter.filter_gen_ids();
    assert!(recovered_ids.iter().all(|&id| id != 0));
    assert!(recovered_ids.iter().all(|&id| id == recovered_ids[0]));
    for domain in &candidate {
        let membership = mgr.filter.list_membership(domain);
        assert_eq!(
            membership.allow_mask, 1,
            "{domain} did not recover as allow"
        );
        assert_eq!(
            membership.block_mask, 0,
            "{domain} recovered with an old policy"
        );
    }
    for domain in &old {
        assert!(
            mgr.filter.list_membership(domain).is_empty(),
            "{domain} survived recovery"
        );
    }
    let recovered = mgr.status_registry().cycle();
    assert_eq!(recovered.served_state, ServedState::Complete);
    assert!(!recovered.generation_degraded);
    assert!(mgr.installed_corpus_digest.is_some());
    assert_ne!(
        mgr.cache, cache,
        "recovery did not admit its candidate cache"
    );
    assert_ne!(
        std::fs::read_to_string(cache_dir.path().join(format!("{stem}.meta"))).unwrap(),
        manifest,
        "recovery did not commit its candidate manifest"
    );
}

/// A degraded cycle must retry on the bounded recovery cadence, then return
/// to the configured cadence once that retry builds a complete generation.
///
/// The first cycle deterministically loses its imported-local body. This is a
/// real degraded input path that crosses the blocking worker boundary; direct
/// refresh tests retain the thread-local shard-build fault coverage.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn degraded_refresh_retries_at_the_bounded_deadline_then_recovers_normal_cadence() {
    let domains: Vec<String> = (0..DOMAIN_SHARDS).map(domain_for_spill_shard).collect();
    let body = format!("{}\n", domains.join("\n"));
    let (mut mgr, dir) = guard_manager(&[&body], true);
    let configured = Duration::from_secs(10 * 60);
    mgr.refresh_interval = configured;
    let registry = mgr.status_registry();

    let body_path = dir.path().join("lists/src0.txt");
    std::fs::remove_file(&body_path).unwrap();
    let loop_handle = mgr.spawn_refresh_loop();

    wait_for_cycle_seq(&registry, 1).await;
    assert_eq!(
        registry.cycle().seq,
        1,
        "the first ticker tick is immediate"
    );
    assert!(
        registry.cycle().generation_degraded,
        "the missing imported-local body must degrade the first cycle"
    );

    std::fs::write(&body_path, &body).unwrap();

    tokio::time::sleep(Duration::from_secs(5 * 60 - 1)).await;
    wait_for_cycle_seq(&registry, 1).await;
    assert_eq!(
        registry.cycle().seq,
        1,
        "a degraded cycle retried before its bounded five-minute deadline"
    );

    tokio::time::sleep(Duration::from_secs(1)).await;
    wait_for_cycle_seq(&registry, 2).await;
    assert_eq!(
        registry.cycle().seq,
        2,
        "the recovery deadline did not tick"
    );
    assert!(
        !registry.cycle().generation_degraded,
        "the retry must recover once the one-shot build failure is consumed"
    );

    tokio::time::sleep(configured - Duration::from_secs(1)).await;
    tokio::task::yield_now().await;
    assert_eq!(
        registry.cycle().seq,
        2,
        "a clean recovery retained the bounded retry cadence"
    );

    tokio::time::sleep(Duration::from_secs(1)).await;
    wait_for_cycle_seq(&registry, 3).await;
    assert_eq!(
        registry.cycle().seq,
        3,
        "the configured cadence was not anchored from the recovery tick"
    );
    loop_handle.retire().await.unwrap();
}

/// The recovery shortcut is only for degraded cycles. A clean first cycle
/// must not wake at five minutes when its configured cadence is longer.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn clean_refresh_keeps_the_configured_cadence_not_the_recovery_deadline() {
    let domains: Vec<String> = (0..DOMAIN_SHARDS).map(domain_for_spill_shard).collect();
    let body = format!("{}\n", domains.join("\n"));
    let (mut mgr, _dir) = guard_manager(&[&body], true);
    let configured = Duration::from_secs(10 * 60);
    mgr.refresh_interval = configured;
    let registry = mgr.status_registry();
    let loop_handle = mgr.spawn_refresh_loop();

    wait_for_cycle_seq(&registry, 1).await;
    assert_eq!(
        registry.cycle().seq,
        1,
        "the first ticker tick is immediate"
    );
    assert!(
        !registry.cycle().generation_degraded,
        "fixture precondition: the first cycle must be clean"
    );

    tokio::time::sleep(Duration::from_secs(5 * 60)).await;
    tokio::task::yield_now().await;
    assert_eq!(
        registry.cycle().seq,
        1,
        "a clean cycle incorrectly retried at the five-minute recovery deadline"
    );

    tokio::time::sleep(configured - Duration::from_secs(5 * 60)).await;
    wait_for_cycle_seq(&registry, 2).await;
    assert_eq!(
        registry.cycle().seq,
        2,
        "a clean cycle did not retain the configured refresh cadence"
    );
    loop_handle.retire().await.unwrap();
}

/// A source whose fresh body is refused by the global entry cap keeps
/// filtering with the body it last ingested, instead of vanishing from
/// the corpus this cycle installs.
///
/// The cap is fail-closed: `parse_source_into_spill_counted` rolls the
/// spill back and returns `Err`. The arm that handles that `Err` used to
/// mark the source `Failed` and move on, so the cycle installed a corpus
/// **without** it — a list one domain past its cap stopped blocking the
/// millions it blocked yesterday, reported as one `Failed` row among many
/// and never at corpus level. The two neighbouring failure arms (the
/// retention guard, and a failed download) already re-parse the retained
/// body; this is the third.
///
/// Source A is the control. It gains a domain in the same cycle, so
/// "B's domains are still resolvable" cannot be satisfied by a cycle that
/// refused wholesale and left the previous generation standing — that is
/// a different mechanism with the same symptom, and it is what
/// [`refresh_refuses_the_cycle_and_keeps_the_previous_generation`] pins.
#[tokio::test]
async fn cap_refusal_reports_overshoot_advances_retry_state_once_and_recovers() {
    const FIRST: &str = "one.example\ntwo.example\nthree.example\n";
    const LAST_GOOD: &str = "one.example\ntwo.example\nthree.example\nfour.example\n";
    const OVERSIZED: &str = "one.example\ntwo.example\nthree.example\nfour.example\nfive.example\n";
    const CAP: usize = 4;

    let (mut mgr, dir) = guard_manager(&[FIRST], true);
    let source = "https://imported.local/src0.txt";
    let blocklist_id = crate::config::schema::Id::new("cap-retry").unwrap();
    mgr.set_list_state(crate::config::list_state::ListState::default(), None);
    mgr.set_source_blocklist_map(HashMap::from([(
        source.to_string(),
        (blocklist_id.clone(), 2),
    )]));
    mgr.max_entries = CAP;

    assert_eq!(mgr.refresh().await, 3);
    rewrite_body(&dir, 0, LAST_GOOD);
    assert_eq!(mgr.refresh().await, 4);
    let last_good = mgr.status_registry.status_for_url(source).unwrap();
    assert_eq!(last_good.entries, 4);
    assert_eq!(last_good.unique_domains, 4);
    assert_eq!(last_good.prev_entries, Some(3));
    let last_refresh_at = last_good.last_refresh_at;

    // Reset only after the last successful cache write. The next failure
    // must stamp its accepted retained-cache path itself.
    mgr.set_list_state(crate::config::list_state::ListState::default(), None);

    rewrite_body(&dir, 0, OVERSIZED);
    assert_eq!(
        mgr.refresh().await,
        4,
        "the retained body must keep filtering"
    );

    let refused = mgr.status_registry.status_for_url(source).unwrap();
    match &refused.last_outcome {
        crate::lists::status::LastOutcome::Failed { reason } => assert_eq!(
            reason,
            &crate::lists::status::format_blocklist_truncation_refused(CAP, 1)
        ),
        other => panic!("expected cap refusal, got {other:?}"),
    }
    assert_eq!(refused.entries, 4, "last-good entries survive refusal");
    assert_eq!(
        refused.unique_domains, 4,
        "last-good unique count survives refusal"
    );
    assert_eq!(refused.prev_entries, Some(3));
    assert_eq!(refused.last_refresh_at, last_refresh_at);
    assert_eq!(refused.parsed_truncated, 1, "five against four is one over");

    // `parsed_truncated` means the last uncleared cap-refusal overshoot,
    // not necessarily the most recent attempt. A generic fetch failure uses
    // the retained body and must leave that diagnostic intact.
    let bridge_body = dir.path().join("lists/src0.txt");
    std::fs::remove_file(&bridge_body).unwrap();
    assert_eq!(mgr.refresh().await, 4);
    let generic_failure = mgr.status_registry.status_for_url(source).unwrap();
    assert!(matches!(
        generic_failure.last_outcome,
        crate::lists::status::LastOutcome::Failed { .. }
    ));
    assert_eq!(
        generic_failure.parsed_truncated, 1,
        "a generic failure must retain the last uncleared cap-refusal overshoot"
    );
    std::fs::write(&bridge_body, OVERSIZED).unwrap();

    let dto = crate::lists::status::BlocklistStatusDto::from_status(
        source.to_string(),
        Some(blocklist_id.to_string()),
        &refused,
    );
    assert_eq!(
        dto.parsed_truncated, 1,
        "the IPC/API/CLI DTO exposes the overshoot"
    );

    let state = mgr.list_state_handle().lock().unwrap().clone();
    let entry = state.lists.get(&blocklist_id).unwrap();
    assert_eq!(
        entry.consecutive_failures, 2,
        "the cap refusal and generic failure are separate retry attempts"
    );
    assert_eq!(entry.status, crate::config::list_state::ListStatus::Failed);
    let cache_path = entry.cache_path.as_ref().expect("retained cache path");
    assert!(
        cache_path.is_file(),
        "retry state must name a real retained body"
    );

    assert_eq!(mgr.refresh().await, 4);
    let state = mgr.list_state_handle().lock().unwrap().clone();
    let entry = state.lists.get(&blocklist_id).unwrap();
    assert_eq!(entry.consecutive_failures, 3);
    assert_eq!(entry.status, crate::config::list_state::ListStatus::Failed);

    mgr.max_entries = 5;
    assert_eq!(mgr.refresh().await, 5);
    let recovered = mgr.status_registry.status_for_url(source).unwrap();
    assert!(matches!(
        recovered.last_outcome,
        crate::lists::status::LastOutcome::Ok
    ));
    assert_eq!(
        recovered.parsed_truncated, 0,
        "success clears the refusal count"
    );
    let state = mgr.list_state_handle().lock().unwrap().clone();
    let entry = state.lists.get(&blocklist_id).unwrap();
    assert_eq!(entry.consecutive_failures, 0);
    assert_eq!(entry.status, crate::config::list_state::ListStatus::Active);
}

#[tokio::test]
async fn cap_refusal_with_an_over_cap_retained_body_counts_one_attempt() {
    let (mut mgr, dir) = guard_manager(
        &["a1.example\n", "b1.example\nb2.example\nb3.example\n"],
        true,
    );
    let source = "https://imported.local/src1.txt";
    let blocklist_id = crate::config::schema::Id::new("cap-retained").unwrap();
    mgr.max_entries = 4;
    assert_eq!(mgr.refresh().await, 4);

    // Lost state must not invent a path merely because the cache opens:
    // the next retained parse also has to accept it before it is stamped.
    mgr.set_list_state(crate::config::list_state::ListState::default(), None);
    mgr.set_source_blocklist_map(HashMap::from([(
        source.to_string(),
        (blocklist_id.clone(), 2),
    )]));

    // B's fresh candidate is three entries over the new cap; its retained
    // cache is one. The incomplete hot cycle must keep A+B intact.
    rewrite_body(&dir, 0, "a1.example\na2.example\n");
    rewrite_body(
        &dir,
        1,
        "b1.example\nb2.example\nb3.example\nb4.example\nb5.example\n",
    );
    mgr.max_entries = 2;
    assert_eq!(mgr.refresh().await, 4);

    let status = mgr.status_registry.status_for_url(source).unwrap();
    assert_eq!(
        status.parsed_truncated, 3,
        "the published overshoot comes from the fresh candidate, not its retained fallback"
    );
    let state = mgr.list_state_handle().lock().unwrap().clone();
    let entry = state.lists.get(&blocklist_id).unwrap();
    assert_eq!(
        entry.consecutive_failures, 1,
        "candidate plus fallback is one attempt"
    );
    assert_eq!(entry.status, crate::config::list_state::ListStatus::Pending);
    assert!(
        entry.cache_path.is_none(),
        "an over-cap retained body must not stamp lost state with a fake cache path"
    );
}

#[tokio::test]
async fn cap_refusal_without_a_retained_body_does_not_stamp_a_cache_path() {
    let (mut mgr, urls, _dir) =
        spill_manager_with_cap(&["one.example\ntwo.example\nthree.example\n"], 2);
    let source = &urls[0];
    let blocklist_id = crate::config::schema::Id::new("cap-no-cache").unwrap();
    mgr.set_list_state(crate::config::list_state::ListState::default(), None);
    mgr.set_source_blocklist_map(HashMap::from([(source.clone(), (blocklist_id.clone(), 1))]));

    assert_eq!(mgr.refresh().await, 0);
    let state = mgr.list_state_handle().lock().unwrap().clone();
    let entry = state.lists.get(&blocklist_id).unwrap();
    assert_eq!(entry.status, crate::config::list_state::ListStatus::Failed);
    assert_eq!(entry.consecutive_failures, 1);
    assert!(
        entry.cache_path.is_none(),
        "no retained body must not create a fake path"
    );
}

#[tokio::test]
async fn a_source_over_its_entry_cap_keeps_its_last_good_body() {
    const A_FIRST: &str = "a1.example\na2.example\n";
    const B_FIRST: &str = "b1.example\nb2.example\nb3.example\n";
    const B_CACHED: [&str; 3] = ["b1.example", "b2.example", "b3.example"];
    /// Five domains against a cap of four: one over, so exactly one
    /// entry is dropped and the refusal reason is predictable.
    const B_OVERSIZED: &str = "c1.example\nc2.example\nc3.example\nc4.example\nc5.example\n";
    const CAP: usize = 4;

    for on_disk in [true, false] {
        let (mut mgr, dir) = guard_manager(&[A_FIRST, B_FIRST], on_disk);
        mgr.max_entries = CAP;

        // Cycle 1: both sources are under the cap and install.
        assert_eq!(mgr.refresh().await, 5, "on_disk={on_disk}");

        // Cycle 2: B's upstream crosses the cap; A grows by one.
        rewrite_body(&dir, 0, "a1.example\na2.example\na3.example\n");
        rewrite_body(&dir, 1, B_OVERSIZED);
        age_cache_entries(&mut mgr);

        let total = mgr.refresh().await;

        assert!(
            !mgr.filter.list_membership("a3.example").is_empty(),
            "the cycle did not install at all — this test cannot say anything \
             about B until A's new domain is serving (on_disk={on_disk})"
        );
        for d in B_CACHED {
            assert!(
                !mgr.filter.list_membership(d).is_empty(),
                "{d} vanished: a source refused by max_entries dropped out of the \
                 installed corpus instead of freezing at its last good body \
                 (on_disk={on_disk})"
            );
        }
        for d in ["c1.example", "c5.example"] {
            assert!(
                mgr.filter.list_membership(d).is_empty(),
                "{d} from the refused body reached the engine (on_disk={on_disk})"
            );
        }
        assert_eq!(
            total, 6,
            "3 from A plus B's 3 retained domains (on_disk={on_disk})"
        );
        assert_eq!(
            mgr.status_registry.cycle().outcome,
            Some(CycleOutcome::Installed),
            "an accepted retained body must let A's new generation install (on_disk={on_disk})"
        );

        // Loudly: the operator must be able to see WHY the source is
        // frozen, with the cap and the overshoot in the reason.
        use crate::lists::status::LastOutcome;
        let snap = mgr.status_registry.snapshot();
        let (_, b_status) = snap
            .iter()
            .find(|(s, _)| s.ends_with("src1.txt"))
            .expect("source B missing from the status registry");
        match &b_status.last_outcome {
            LastOutcome::Failed { reason } => assert_eq!(
                reason,
                &crate::lists::status::format_blocklist_truncation_refused(CAP, 1),
                "on_disk={on_disk}"
            ),
            other => panic!("B must be Failed with the cap reason, got {other:?}"),
        }
        assert_eq!(
            b_status.parsed_truncated, 1,
            "the status must expose the candidate's exact overshoot (on_disk={on_disk})"
        );

        // Per-source, not corpus-level: nothing here is a ceiling
        // refusal, and publishing one would send the operator to the
        // wrong knob.
        assert!(
            mgr.status_registry.corpus_refusal().is_none(),
            "a per-list cap refusal published a corpus refusal (on_disk={on_disk})"
        );

        // The retained body has to still BE the previous good one. The
        // `.cache` write sits at the tail of the fresh-download arm,
        // after the cap check that `continue`s past it — assert that
        // ordering rather than trusting it.
        if on_disk {
            assert_eq!(
                mgr.read_body_from_disk("https://imported.local/src1.txt")
                    .as_deref(),
                Some(B_FIRST),
                "the refused download overwrote the retained .cache body"
            );
        }
    }
}
/// A refused candidate whose retained body also exceeds a newly lowered
/// cap leaves source coverage incomplete. A hot refresh must preserve the
/// complete old generation, including unrelated source A's old body.
#[tokio::test]
async fn an_over_cap_retained_body_keeps_the_complete_hot_generation() {
    const B_CACHED: [&str; 3] = ["b1.example", "b2.example", "b3.example"];

    for on_disk in [true, false] {
        let (mut mgr, dir) = guard_manager(
            &["a1.example\n", "b1.example\nb2.example\nb3.example\n"],
            on_disk,
        );
        mgr.max_entries = 4;
        assert_eq!(mgr.refresh().await, 4, "on_disk={on_disk}");
        let digest_before = mgr.installed_corpus_digest;
        let blocklist_id = crate::config::schema::Id::new("cap-over-retained").unwrap();
        mgr.set_list_state(crate::config::list_state::ListState::default(), None);
        mgr.set_source_blocklist_map(HashMap::from([(
            "https://imported.local/src1.txt".to_string(),
            (blocklist_id.clone(), 2),
        )]));

        // The operator lowers the cap under B, and leaves B's upstream
        // alone: both the fresh body and the retained one are now over.
        rewrite_body(&dir, 0, "a1.example\na2.example\n");
        age_cache_entries(&mut mgr);
        mgr.max_entries = 2;

        assert_eq!(
            mgr.refresh().await,
            4,
            "an incomplete hot cycle must report the old complete corpus (on_disk={on_disk})"
        );
        assert!(
            !mgr.filter.list_membership("a1.example").is_empty(),
            "old A vanished (on_disk={on_disk})"
        );
        assert!(
            mgr.filter.list_membership("a2.example").is_empty(),
            "new A installed beside an unavailable B (on_disk={on_disk})"
        );
        for d in B_CACHED {
            assert!(
                !mgr.filter.list_membership(d).is_empty(),
                "{d} vanished from the complete prior generation (on_disk={on_disk})"
            );
        }

        use crate::lists::status::LastOutcome;
        let snap = mgr.status_registry.snapshot();
        let (_, b_status) = snap
            .iter()
            .find(|(s, _)| s.ends_with("src1.txt"))
            .expect("source B missing from the status registry");
        match &b_status.last_outcome {
            LastOutcome::Failed { reason } => assert_eq!(
                reason,
                &crate::lists::status::format_blocklist_truncation_refused(2, 1),
                "on_disk={on_disk}"
            ),
            other => panic!("B must be Failed with the cap reason, got {other:?}"),
        }
        assert_eq!(
            b_status.entries, 3,
            "B must report live entries (on_disk={on_disk})"
        );
        assert_eq!(
            b_status.unique_domains, 3,
            "B must report live uniques (on_disk={on_disk})"
        );
        assert_eq!(
            b_status.parsed_truncated, 1,
            "B must expose this attempt's overshoot"
        );
        let a_status = mgr
            .status_registry
            .status_for_url("https://imported.local/src0.txt")
            .unwrap();
        assert_eq!(
            a_status.entries, 1,
            "A must report the live old body (on_disk={on_disk})"
        );
        assert_eq!(
            a_status.unique_domains, 1,
            "A must report the live old body (on_disk={on_disk})"
        );
        assert_eq!(
            mgr.installed_corpus_digest,
            None,
            "an incomplete cycle must not publish a digest (was {digest_before:?}; on_disk={on_disk})"
        );
        assert_eq!(
            mgr.status_registry.cycle().outcome,
            Some(CycleOutcome::SpillRollbackFailed),
            "the cycle must not claim Installed (on_disk={on_disk})"
        );
        assert!(mgr.status_registry.cycle().source_coverage_incomplete);
        assert!(mgr.status_registry.corpus_refusal().is_none());
        let state = mgr.list_state_handle().lock().unwrap().clone();
        let retry = state.lists.get(&blocklist_id).unwrap();
        assert_eq!(
            retry.consecutive_failures, 1,
            "candidate plus fallback is one retry"
        );
        assert_eq!(retry.status, crate::config::list_state::ListStatus::Pending);
    }
}

/// A failed fetch with no usable retained body is the generic sibling of a
/// cap refusal. It must take the same hot-generation hold, not be mistaken
/// for a spill rollback failure.
#[tokio::test]
async fn a_missing_retained_body_after_download_failure_keeps_the_hot_generation() {
    for on_disk in [true, false] {
        let (mut mgr, dir) = guard_manager(
            &["old-a.example\n", "old-b-one.example\nold-b-two.example\n"],
            on_disk,
        );
        assert_eq!(mgr.refresh().await, 3, "on_disk={on_disk}");
        assert!(mgr.installed_corpus_digest.is_some());

        let blocklist_id = crate::config::schema::Id::new("missing-retained").unwrap();
        mgr.set_list_state(crate::config::list_state::ListState::default(), None);
        mgr.set_source_blocklist_map(HashMap::from([(
            "https://imported.local/src1.txt".to_string(),
            (blocklist_id.clone(), 2),
        )]));
        rewrite_body(&dir, 0, "old-a.example\nnew-a.example\n");
        let b_source = "https://imported.local/src1.txt";
        let b_stem = source_to_cache_stem(b_source);
        let _ = std::fs::remove_file(dir.path().join("lists/src1.txt"));
        if on_disk {
            let _ = std::fs::remove_file(dir.path().join("cache").join(format!("{b_stem}.cache")));
            let _ = std::fs::remove_file(dir.path().join("cache").join(format!("{b_stem}.meta")));
        } else {
            mgr.cache.clear();
        }
        age_cache_entries(&mut mgr);

        assert_eq!(mgr.refresh().await, 3, "on_disk={on_disk}");
        for domain in ["old-a.example", "old-b-one.example", "old-b-two.example"] {
            assert!(
                !mgr.filter.list_membership(domain).is_empty(),
                "{domain} vanished from the held generation (on_disk={on_disk})"
            );
        }
        assert!(mgr.filter.list_membership("new-a.example").is_empty());
        assert!(mgr.installed_corpus_digest.is_none());
        assert_eq!(
            mgr.status_registry.cycle().outcome,
            Some(CycleOutcome::SpillRollbackFailed)
        );
        assert!(mgr.status_registry.cycle().source_coverage_incomplete);
        let b_status = mgr.status_registry.status_for_url(b_source).unwrap();
        assert_eq!(b_status.entries, 2);
        assert_eq!(b_status.unique_domains, 2);
        assert!(matches!(b_status.last_outcome, LastOutcome::Failed { .. }));
        let state = mgr.list_state_handle().lock().unwrap().clone();
        assert_eq!(
            state.lists.get(&blocklist_id).unwrap().consecutive_failures,
            1
        );
    }
}

#[tokio::test]
async fn incomplete_hot_hold_clears_stale_refusal_but_keeps_freeze_visible() {
    let (mut mgr, dir) = guard_manager(&["old-a.example\nold-b.example\n"], true);
    assert_eq!(mgr.refresh().await, 2);
    let now = OffsetDateTime::now_utc();
    mgr.status_registry().note_refused_cycle(now);
    mgr.status_registry()
        .set_corpus_refusal(Some(CorpusRefusal {
            unique: 10,
            ceiling: 2,
            novel_by_source: vec![],
        }));
    mgr.status_registry()
        .record_cycle_with_qualifiers(CycleOutcome::Refused, false, false, 2);

    // This manager attempt cannot remeasure a corpus refusal: its only body
    // is gone, including the retained cache. It must clear the stale payload
    // but leave the independently tracked freeze age intact.
    std::fs::remove_file(dir.path().join("lists/src0.txt")).unwrap();
    let source = "https://imported.local/src0.txt";
    let cache_path = selected_cache_body_path(&dir.path().join("cache"), source).unwrap();
    std::fs::remove_file(cache_path).unwrap();
    let stem = source_to_cache_stem(source);
    std::fs::remove_file(dir.path().join("cache").join(format!("{stem}.meta"))).unwrap();
    age_cache_entries(&mut mgr);

    assert_eq!(mgr.refresh().await, 2);
    let snapshot = mgr.status_registry().consistent_snapshot();
    assert_eq!(
        snapshot.cycle.outcome,
        Some(CycleOutcome::SpillRollbackFailed)
    );
    assert!(snapshot.cycle.source_coverage_incomplete);
    assert!(snapshot.corpus_refusal.is_none());
    assert_eq!(snapshot.corpus_freeze.unwrap().since, Some(now));
}

/// The P0, end to end through `refresh()`: a **first** cycle over the
/// ceiling must install, not come up serving nothing.
///
/// Hit in production on 2026-08-05 during a routine restart. The
/// daemon logged `serving=0`, then logged `DNS server listening` and
/// answered every query — the house was entirely unfiltered and
/// nothing loud said so. Every existing corpus-guard test through
/// `refresh()` is cycle-1-installs → cycle-2-refuses, i.e. the
/// hot-reload shape, in which "keep the previous generation" is both
/// true and correct. **This is the first one that refuses on the
/// first cycle**, which is the only shape the bug lives in.
///
/// Both directions are asserted off the same corpus so the install is
/// attributable to the ceiling and not to the corpus being small: 5
/// domains install against a ceiling of 4, and refuse against a
/// ceiling of 2, whose hard cap of 4 they are genuinely past.
#[tokio::test]
async fn a_cold_start_over_the_ceiling_installs_instead_of_serving_nothing() {
    const CORPUS: [&str; 5] = [
        "a.example",
        "b.example",
        "c.example",
        "d.example",
        "e.example",
    ];
    let bodies = [
        "a.example\nb.example\nc.example\n",
        "d.example\ne.example\n",
    ];

    for on_disk in [true, false] {
        // 5 over a ceiling of 4, hard cap 8: install anyway.
        let (mut mgr, _dir) = guard_manager(&bodies, on_disk);
        mgr.set_max_total_domains(4);

        assert_eq!(
            mgr.refresh().await,
            5,
            "a first cycle over the ceiling served nothing — there was no previous \
             generation to keep, so the refusal unfiltered the whole network \
             (on_disk={on_disk})"
        );
        for d in CORPUS {
            assert!(
                !mgr.filter.list_membership(d).is_empty(),
                "{d} never reached the engine on a cold start (on_disk={on_disk})"
            );
        }
        assert!(
            mgr.status_registry.corpus_refusal().is_none(),
            "a cycle that installed published a refusal (on_disk={on_disk})"
        );
        // An installed cycle stores its digest, so the next one can
        // still take the unchanged fast path.
        assert!(
            mgr.installed_corpus_digest.is_some(),
            "the over-ceiling install stored no digest (on_disk={on_disk})"
        );

        // Same corpus, ceiling 2, hard cap 4: genuinely past the cap,
        // so the refusal stands and is reported.
        let (mut mgr, _dir) = guard_manager(&bodies, on_disk);
        mgr.set_max_total_domains(2);

        assert_eq!(
            mgr.refresh().await,
            0,
            "past the hard cap the guard must still refuse (on_disk={on_disk})"
        );
        for d in CORPUS {
            assert!(
                mgr.filter.list_membership(d).is_empty(),
                "{d} was installed past the hard cap (on_disk={on_disk})"
            );
        }
        let refusal = mgr
            .status_registry
            .corpus_refusal()
            .expect("a refused cold start published no refusal state");
        assert_eq!(refusal.unique, 5, "on_disk={on_disk}");
        assert_eq!(refusal.ceiling, 2, "on_disk={on_disk}");
    }
}

#[tokio::test]
async fn cold_incomplete_hard_cap_refusal_reports_nothing_installed() {
    for on_disk in [true, false] {
        let (mut mgr, dir) = guard_manager(
            &[
                "a.example\nb.example\nc.example\nd.example\ne.example\n",
                "missing.example\n",
            ],
            on_disk,
        );
        // Five usable domains exceed the hard cap (2 × 2). The other source
        // fails before contributing, so this combines cold coverage loss and
        // a corpus refusal.
        mgr.set_max_total_domains(2);
        std::fs::remove_file(dir.path().join("lists/src1.txt")).unwrap();

        assert_eq!(mgr.refresh().await, 0, "on_disk={on_disk}");
        let snapshot = mgr.status_registry().consistent_snapshot();
        assert_eq!(snapshot.cycle.outcome, Some(CycleOutcome::Refused));
        assert!(snapshot.cycle.source_coverage_incomplete);
        assert!(!snapshot.cycle.generation_degraded);
        assert!(snapshot.corpus_refusal.is_some());
        assert_eq!(mgr.filter.domain_count(), 0, "no prior corpus exists");
    }
}

/// All four bands off one spill, so each is shown to be reached by the
/// ceiling alone rather than by anything else about the corpus.
///
/// The 90 % band exists to warn *before* the wall, so the load-bearing
/// assertion is that it still yields `Install`. The threshold is always a
/// fraction of the **operator's** value, not a property of one host's
/// representation.
///
/// Every band here is measured with a generation **serving**, which is
/// the case in which the ceiling is a wall. `serving` used to be read
/// off the manager, where it was silently 0 — so this test asserted
/// reload semantics while exercising the boot path. The boot bands are
/// [`a_cold_start_has_no_generation_to_keep_so_the_ceiling_is_a_budget`].
#[test]
fn the_guard_bands_are_taken_against_the_operators_own_ceiling() {
    // Any non-zero count: the guard branches on "is anything
    // installed", never on how much.
    const SERVING: usize = 5;

    let dir = tempfile::tempdir().unwrap();
    let mut spill = ShardSpill::open(Some(dir.path())).unwrap();
    let body: String = (0..9).map(|i| format!("d{i}.example\n")).collect();
    parse_source_into_spill(
        std::io::Cursor::new(body.into_bytes()),
        1,
        &mut spill,
        100,
        "s",
        Some(ListFormat::DomainOnly),
    )
    .unwrap();
    spill.flush().unwrap();

    let (mut mgr, _d) = guard_manager(&["ignored.example\n"], true);

    // 9 of 12 = 75 %: install, quietly.
    mgr.set_max_total_domains(12);
    assert!(
        matches!(
            mgr.corpus_guard(&mut spill, SERVING).unwrap(),
            CorpusVerdict::Install {
                unique: 9,
                warn: false,
                ..
            }
        ),
        "75 % must not warn — the band would be noise at every ceiling"
    );

    // 9 of 10 = exactly 90 %: install, and warn.
    mgr.set_max_total_domains(10);
    assert!(
        matches!(
            mgr.corpus_guard(&mut spill, SERVING).unwrap(),
            CorpusVerdict::Install {
                unique: 9,
                warn: true,
                ..
            }
        ),
        "the warn band must still INSTALL — it is a warning, not a second wall"
    );

    // 9 over 8: refuse.
    mgr.set_max_total_domains(8);
    assert!(matches!(
        mgr.corpus_guard(&mut spill, SERVING).unwrap(),
        CorpusVerdict::Refuse {
            unique: 9,
            ceiling: 8,
            ..
        }
    ));

    // Exactly at the ceiling is NOT over it.
    mgr.set_max_total_domains(9);
    assert!(
        matches!(
            mgr.corpus_guard(&mut spill, SERVING).unwrap(),
            CorpusVerdict::Install { unique: 9, .. }
        ),
        "refusal must be strictly greater than the ceiling"
    );

    spill.prepare_validate().unwrap();
    // 0 disables. The armed hook must survive this call: `Unmeasured`
    // means no ceiling and no count, never a failed measurement.
    mgr.set_max_total_domains(0);
    fail_nth_shard_spill_guard_count_for_test(1);
    assert!(matches!(
        mgr.corpus_guard(&mut spill, SERVING).unwrap(),
        CorpusVerdict::Unmeasured
    ));
    mgr.set_max_total_domains(12);
    assert!(mgr.corpus_guard(&mut spill, SERVING).is_err());
    assert!(spill.is_poisoned());
}

/// The boot bands, off one spill, as the mirror of
/// [`the_guard_bands_are_taken_against_the_operators_own_ceiling`].
///
/// With nothing serving, refusing does not keep anything — it installs
/// nothing and the daemon answers unfiltered. So over the ceiling
/// becomes install-and-shout, and the wall moves out to
/// [`cold_start_hard_cap`]. Ten domains against ceilings of 12 / 8 / 5
/// / 4 walks under, over, exactly at 2×, and past 2×, so each band is
/// reached by the ceiling alone.
#[test]
fn a_cold_start_has_no_generation_to_keep_so_the_ceiling_is_a_budget() {
    // The whole discriminator. `refresh` passes
    // `self.filter.domain_count()`, which is 0 until a generation is
    // installed: the engine is built empty and the disk cache
    // restores ETag sidecars, never bodies.
    const NOTHING_SERVING: usize = 0;

    let dir = tempfile::tempdir().unwrap();
    let mut spill = ShardSpill::open(Some(dir.path())).unwrap();
    let body: String = (0..10).map(|i| format!("d{i}.example\n")).collect();
    parse_source_into_spill(
        std::io::Cursor::new(body.into_bytes()),
        1,
        &mut spill,
        100,
        "s",
        Some(ListFormat::DomainOnly),
    )
    .unwrap();
    spill.flush().unwrap();

    let (mut mgr, _d) = guard_manager(&["ignored.example\n"], true);

    // Under the ceiling: boot changes nothing about the fitting case.
    mgr.set_max_total_domains(12);
    assert!(
        matches!(
            mgr.corpus_guard(&mut spill, NOTHING_SERVING).unwrap(),
            CorpusVerdict::Install { unique: 10, .. }
        ),
        "an empty filter must not perturb a corpus that fits"
    );

    // 10 over 8 — a refusal here is the P0: it keeps nothing and
    // serves nothing.
    mgr.set_max_total_domains(8);
    assert!(
        matches!(
            mgr.corpus_guard(&mut spill, NOTHING_SERVING).unwrap(),
            CorpusVerdict::InstallOverCeiling {
                unique: 10,
                ceiling: 8,
                ..
            }
        ),
        "over the ceiling with nothing to fall back on must INSTALL, not serve zero"
    );

    // Exactly 2× the ceiling is NOT past the cap — the same
    // strictly-greater rule the ceiling itself uses.
    mgr.set_max_total_domains(5);
    assert!(
        matches!(
            mgr.corpus_guard(&mut spill, NOTHING_SERVING).unwrap(),
            CorpusVerdict::InstallOverCeiling { unique: 10, .. }
        ),
        "exactly at the hard cap must install; refusal is strictly past it"
    );

    // Past 2×: a real memory ceiling, refused as one.
    mgr.set_max_total_domains(4);
    assert!(
        matches!(
            mgr.corpus_guard(&mut spill, NOTHING_SERVING).unwrap(),
            CorpusVerdict::Refuse {
                unique: 10,
                ceiling: 4,
                ..
            }
        ),
        "past the hard cap the guard must still refuse — the cap is the memory wall"
    );

    // A ceiling of 0 disables the guard before any of this is reached,
    // so the boot branch cannot resurrect a measurement the operator
    // turned off.
    mgr.set_max_total_domains(0);
    assert!(matches!(
        mgr.corpus_guard(&mut spill, NOTHING_SERVING).unwrap(),
        CorpusVerdict::Unmeasured
    ));
}

/// The same spill and ceiling decided both ways by `serving` alone.
///
/// The two band tests above each hold one side fixed; this pins the
/// **discriminator itself**, so a future change that reads boot-ness
/// off something else — a generation counter, a boot flag — has to
/// keep this exact contrast working.
#[test]
fn serving_is_the_only_thing_that_separates_the_two_over_ceiling_verdicts() {
    let dir = tempfile::tempdir().unwrap();
    let mut spill = ShardSpill::open(Some(dir.path())).unwrap();
    let body: String = (0..10).map(|i| format!("d{i}.example\n")).collect();
    parse_source_into_spill(
        std::io::Cursor::new(body.into_bytes()),
        1,
        &mut spill,
        100,
        "s",
        Some(ListFormat::DomainOnly),
    )
    .unwrap();
    spill.flush().unwrap();

    let (mut mgr, _d) = guard_manager(&["ignored.example\n"], true);
    mgr.set_max_total_domains(8);

    assert!(
        matches!(
            mgr.corpus_guard(&mut spill, 0).unwrap(),
            CorpusVerdict::InstallOverCeiling { .. }
        ),
        "nothing serving → install"
    );
    assert!(
        matches!(
            mgr.corpus_guard(&mut spill, 1).unwrap(),
            CorpusVerdict::Refuse { .. }
        ),
        "a single domain serving is a generation to keep → refuse, exactly as before"
    );
}

/// F3 through `refresh()`: the counting pass must not shift what each
/// source reports as its contribution.
///
/// `added_by_bit` is what feeds `entries`, and `build_shard` mutates
/// it. Running a second pass over the same spill first is exactly the
/// kind of change that perturbs it silently, so the disabled guard —
/// which skips the pass entirely — is the control.
#[tokio::test]
async fn the_counting_pass_does_not_move_reported_entries() {
    let bodies = [
        "a.example\nb.example\nshared.example\n",
        "c.example\nshared.example\nd.example\n",
    ];

    let mut observed = Vec::new();
    for ceiling in [0usize, 1_000_000] {
        let (mut mgr, _dir) = guard_manager(&bodies, true);
        mgr.set_max_total_domains(ceiling);
        let total = mgr.refresh().await;
        let mut entries: Vec<(String, u64)> = mgr
            .status_registry
            .snapshot()
            .iter()
            .map(|(s, st)| (s.clone(), st.entries))
            .collect();
        entries.sort();
        observed.push((total, entries));
    }

    assert_eq!(
        observed[0], observed[1],
        "the counting pass changed reported entries"
    );
    // Pinned, so the equality above cannot be satisfied by both arms
    // being equally wrong.
    assert_eq!(observed[0].0, 5, "a,b,c,d,shared");
    assert_eq!(
        observed[0].1.iter().map(|(_, n)| n).sum::<u64>(),
        5,
        "net-new contributions must still sum to the map"
    );
}

// ── The counting pass (global corpus guard) ───────────────────────

/// Two sources with real cross-source overlap, spilled in bit order.
/// Pre-dedup 10 records, 8 distinct domains — the shape the whole
/// guard exists to tell apart.
fn overlapping_spill(spill: &mut ShardSpill) {
    parse_source_into_spill(
        std::io::Cursor::new(
            b"a.example\nb.example\nc.example\nshared1.example\nshared2.example\n".to_vec(),
        ),
        1,
        spill,
        100,
        "s0",
        Some(ListFormat::DomainOnly),
    )
    .unwrap();
    parse_source_into_spill(
        std::io::Cursor::new(
            b"d.example\ne.example\nshared1.example\nshared2.example\nf.example\n".to_vec(),
        ),
        2,
        spill,
        100,
        "s1",
        Some(ListFormat::DomainOnly),
    )
    .unwrap();
    spill.flush().unwrap();
}

/// F1: shards are hash-disjoint on the **domain alone**, so the
/// per-shard unique counts sum to the exact global unique count. That
/// is the load-bearing assumption of the whole design — if it were
/// false the guard would need cross-shard reconciliation it does not
/// do, and would silently under-count.
///
/// Asserted against the build loop rather than against a hand-written
/// constant, so the two producers cannot drift apart.
#[test]
fn count_unique_sums_to_the_build_loop_total_on_both_variants() {
    let check = |spill: &mut ShardSpill| {
        overlapping_spill(spill);

        let mut novel = [0u64; 64];
        let counted: u64 = (0..DOMAIN_SHARDS)
            .map(|idx| spill.count_unique(idx, &mut novel).unwrap())
            .sum();

        // The build loop is the reference implementation.
        let mut added = [0u64; 64];
        let policy = ListPolicy::publish_uniform(0);
        let built: usize = (0..DOMAIN_SHARDS)
            .map(|idx| {
                spill
                    .build_shard(idx, 4, &policy)
                    .unwrap()
                    .merge_added_by_bit(&mut added)
                    .len()
            })
            .sum();

        assert_eq!(
            counted, built as u64,
            "counting pass and build loop disagree on the unique total"
        );
        assert_eq!(counted, 8, "a,b,c,d,e,f,shared1,shared2");
        // Pre-dedup is 10 records: a count that matched it would mean
        // the pass is not deduplicating at all — the reverted bug.
        assert_ne!(counted, 10, "counted the pre-dedup record count");
        assert_eq!(
            novel, added,
            "per-bit novelty must match what build_shard attributes"
        );
        assert_eq!(
            &novel[..2],
            &[5, 3],
            "first-occurrence wins, in spill order"
        );
    };

    let dir = tempfile::tempdir().unwrap();
    let mut disk = ShardSpill::open(Some(dir.path())).unwrap();
    assert!(disk.is_disk(), "disk arm must exercise the disk path");
    check(&mut disk);

    let mut mem = ShardSpill::open(None).unwrap();
    assert!(
        !mem.is_disk(),
        "memory arm must exercise explicit memory mode"
    );
    check(&mut mem);
}

/// Counting leaves every shard available for the build pass.
#[test]
fn count_unique_leaves_the_spill_intact_for_the_build_pass() {
    let harvest = |spill: &mut ShardSpill, count_first: bool| {
        overlapping_spill(spill);
        if count_first {
            let mut novel = [0u64; 64];
            for idx in 0..DOMAIN_SHARDS {
                spill.count_unique(idx, &mut novel).unwrap();
            }
        }
        let mut added = [0u64; 64];
        let mut names: Vec<String> = Vec::new();
        let policy = ListPolicy::publish_uniform(0);
        for idx in 0..DOMAIN_SHARDS {
            let shard = spill
                .build_shard(idx, 4, &policy)
                .unwrap()
                .merge_added_by_bit(&mut added);
            names.extend(shard.iter().map(|(k, _)| k.to_string()));
        }
        names.sort();
        (names, added)
    };

    for is_disk in [true, false] {
        let dir = tempfile::tempdir().unwrap();
        let open = |sub: &str| {
            if is_disk {
                let p = dir.path().join(sub);
                std::fs::create_dir_all(&p).unwrap();
                ShardSpill::open(Some(&p)).unwrap()
            } else {
                ShardSpill::open(None).unwrap()
            }
        };

        let mut counted = open("counted");
        let (with_count, added_with) = harvest(&mut counted, true);
        let mut control = open("control");
        let (without_count, added_without) = harvest(&mut control, false);

        assert_eq!(
            with_count.len(),
            8,
            "the count pass consumed the spill (is_disk={is_disk})"
        );
        assert_eq!(
            with_count, without_count,
            "counting changed what the build pass produced (is_disk={is_disk})"
        );
        // F3: `added_by_bit` feeds each source's reported `entries`.
        // The counting pass must not perturb it.
        assert_eq!(
            added_with, added_without,
            "the count pass moved added_by_bit (is_disk={is_disk})"
        );
    }
}

/// Fail-closed on a cap hit, at the spill producer: a refused source
/// leaves the spill byte-identical, so the previous generation survives.
///
/// Producer-level, so it cannot see what `refresh()` decides on top —
/// the end-to-end arms are
/// `refresh_installs_a_hosts_source_whose_noise_lines_reach_the_cap` and
/// `refresh_refuses_a_hosts_source_whose_domains_exceed_the_cap`, and
/// they are the ones that matter. Until S2 this module carried a private
/// copy of `parse_list_streaming`, so a test at this level was blind to
/// the counter the daemon actually ran: the live daemon dropped
/// 2,370,261 domains while every parser test stayed green.
#[test]
fn spill_counts_the_entries_the_cap_drops() {
    let dir = tempfile::tempdir().unwrap();
    let mut spill = ShardSpill::open(Some(dir.path())).unwrap();

    // Comment and blank lines past the cap must NOT inflate the count —
    // otherwise a list with a long trailing licence header reports
    // phantom truncation and step 3 would reject it outright.
    let body = b"a.example\nb.example\nc.example\nd.example\ne.example\n# trailing comment\n\n";

    // Seed a prior good source, so the rollback assertion below is
    // about *retaining* a previous generation rather than about an
    // empty spill trivially staying empty.
    parse_source_into_spill(
        std::io::Cursor::new(b"kept.example\n".to_vec()),
        1,
        &mut spill,
        100,
        "prior",
        Some(ListFormat::DomainOnly),
    )
    .expect("prior source parses");
    let after_prior = spill.mark();

    // Step 3: a source that exceeds its cap is refused WHOLE, not
    // ingested half-way.
    let err = parse_source_into_spill(
        std::io::Cursor::new(body.to_vec()),
        2,
        &mut spill,
        3,
        "capped",
        Some(ListFormat::DomainOnly),
    )
    .expect_err("a truncated list must be refused, not silently half-loaded");

    assert_eq!(
        err.cap_refusal(),
        Some(SpillCapRefusal {
            max_entries: 3,
            dropped: 2,
        }),
        "the cap measurements must survive the spill rollback"
    );

    let msg = err.to_string();
    assert!(
        msg.contains('2'),
        "the reason must carry the dropped count so the operator can size the cap: {msg}"
    );
    assert!(
        msg.contains("max_entries"),
        "the reason must name the knob to change: {msg}"
    );
    assert_eq!(
        spill.mark(),
        after_prior,
        "the refused source left bytes in the spill — the prior generation was corrupted"
    );

    // Control arm: identical body, cap above the entry count. Proves
    // the refusal keys on truncation and not merely on this body.
    let mut spill_roomy = ShardSpill::open(Some(dir.path())).unwrap();
    let (roomy, _) = parse_source_into_spill(
        std::io::Cursor::new(body.to_vec()),
        1,
        &mut spill_roomy,
        100,
        "roomy",
        Some(ListFormat::DomainOnly),
    )
    .expect("an untruncated body must still be accepted");

    assert_eq!(roomy.parsed_ok, 5);
    assert_eq!(
        roomy.parsed_truncated, 0,
        "an untruncated list must report zero"
    );
}

/// Every partition decision must route through
/// [`FilterEngine::shard_index`]. A second implementation of
/// `hash % 16` would disagree with the probe side silently, so this
/// asserts the placement directly rather than trusting the call site.
#[test]
fn spill_places_each_domain_in_shard_index_s_shard() {
    let domains: Vec<String> = (0..500).map(|i| format!("host{i}.example")).collect();
    let body = format!("{}\n", domains.join("\n"));

    let dir = tempfile::tempdir().unwrap();
    let mut spill = ShardSpill::open(Some(dir.path())).unwrap();
    parse_source_into_spill(
        std::io::Cursor::new(body.as_bytes()),
        1,
        &mut spill,
        10_000,
        "s",
        Some(ListFormat::DomainOnly),
    )
    .unwrap();
    spill.flush().unwrap();

    let mut seen = 0usize;
    let policy = ListPolicy::publish_uniform(0);
    for idx in 0..DOMAIN_SHARDS {
        let shard = spill.build_shard(idx, 64, &policy).unwrap().shard;
        for (d, _) in shard.iter() {
            assert_eq!(
                FilterEngine::shard_index(d),
                idx,
                "{d} was spilled to shard {idx} but the engine probes \
                 shard {}",
                FilterEngine::shard_index(d)
            );
            seen += 1;
        }
    }
    assert_eq!(seen, domains.len());
}

/// §11 T5: a cycle whose list bodies are all byte-identical to the
/// installed generation must not rebuild or swap; a cycle where one
/// body changed must.
#[tokio::test]
async fn unchanged_corpus_skips_the_rebuild_and_a_changed_one_does_not() {
    let (mut mgr, _urls, dir) = spill_manager(&["a.example\nb.example\n"]);

    assert_eq!(mgr.refresh().await, 2);
    assert_eq!(mgr.rebuild_count, 1, "the first cycle must build the map");
    assert!(mgr.installed_corpus_digest.is_some());
    let digest_after_first = mgr.installed_corpus_digest;

    // Nothing touched the body: same bytes, same order, same settings.
    assert_eq!(mgr.refresh().await, 2, "the map still reports its size");
    assert_eq!(
        mgr.rebuild_count, 1,
        "an unchanged corpus rebuilt the map anyway — the T5 short-circuit did not fire"
    );
    assert_eq!(mgr.installed_corpus_digest, digest_after_first);
    // The map is intact, not merely un-rebuilt.
    assert!(!mgr.filter.list_membership("a.example").is_empty());
    assert_eq!(mgr.filter.domain_count(), 2);

    // One byte of one body changes -> the digest changes -> rebuild.
    std::fs::write(
        dir.path().join("lists").join("src0.txt"),
        "a.example\nb.example\nc.example\n",
    )
    .unwrap();
    // Expire the freshness shortcut so the bridge re-reads the file.
    for entry in mgr.cache.values_mut() {
        entry.fetched_at = OffsetDateTime::now_utc() - Duration::from_secs(86_400);
    }

    assert_eq!(mgr.refresh().await, 3);
    assert_eq!(
        mgr.rebuild_count, 2,
        "a changed body must force a rebuild — the short-circuit is not a cache"
    );
    assert_ne!(
        mgr.installed_corpus_digest, digest_after_first,
        "the digest must track the corpus"
    );
    assert!(!mgr.filter.list_membership("c.example").is_empty());
}

/// A fully covered empty candidate is a complete generation, including when
/// it replaces a non-empty one. Its digest makes the next identical cycle a
/// no-op instead of repeatedly rebuilding sixteen empty shards.
#[tokio::test]
async fn accepted_empty_replaces_live_and_stores_its_digest() {
    let (mut mgr, _url, dir) = bridge_manager("live.example.com\n");
    assert_eq!(mgr.refresh().await, 1);
    assert!(mgr.installed_corpus_digest.is_some());

    mgr.set_shrink_guard(false, 0);
    write_bridge_body(&dir, "");

    assert_eq!(mgr.refresh().await, 0);
    let cycle = mgr.status_registry().cycle();
    assert_eq!(cycle.outcome, Some(CycleOutcome::Installed));
    assert_eq!(cycle.served_state, ServedState::IntentionalEmpty);
    assert!(!cycle.generation_degraded);
    assert!(mgr.filter.list_membership("live.example.com").is_empty());
    let empty_digest = mgr
        .installed_corpus_digest
        .expect("the installed empty generation needs a digest");

    assert_eq!(mgr.refresh().await, 0);
    assert_eq!(
        mgr.status_registry().cycle().outcome,
        Some(CycleOutcome::SkippedUnchanged)
    );
    assert_eq!(mgr.installed_corpus_digest, Some(empty_digest));
}

/// Cold-start policy: install usable sources even when another source has
/// no cache, but do not publish a digest for that incomplete coverage.
///
/// Two sources, deliberately: `kept` has a `.cache` file and
/// contributes a domain; `missing` has none. A single-source fixture
/// cannot observe this property — with only one source there is no
/// "some accounted for, some not" state, only "accounted for" or
/// "nothing accounted for", and the latter (see
/// `cache_only_with_no_disk_cache_makes_zero_http_calls`) never
/// installs anything at all, so it can't tell a valid digest from a
/// merely-absent one either.
#[tokio::test]
async fn cache_only_boot_with_partial_cache_coverage_installs_usable_sources_without_a_digest() {
    let dir = tempfile::tempdir().unwrap();

    let kept_url = "https://127.0.0.1/kept.txt".to_string();
    let stem = source_to_cache_stem(&kept_url);
    std::fs::write(
        dir.path().join(format!("{stem}.cache")),
        "kept.example.com\n",
    )
    .unwrap();
    let old = OffsetDateTime::now_utc() - time::Duration::days(30);
    std::fs::write(
        dir.path().join(format!("{stem}.meta")),
        format!(
            "etag=\nlast-modified=\nfetched-at={}\n",
            old.format(&Rfc3339).unwrap()
        ),
    )
    .unwrap();

    let missing_url = "https://127.0.0.1/missing.txt".to_string();
    // Deliberately no .cache / .meta written for this one — never
    // fetched, so `load_disk_cache` below leaves no in-memory entry
    // for it and it reaches the no-usable-cache stop by the "no
    // cache entry at all" route.

    let filter = Arc::new(FilterEngine::new());
    let urls = vec![kept_url.clone(), missing_url.clone()];
    let source_bits = build_source_bit_map(&urls).expect("at-cap accept");
    let mut mgr = ListManager::new(
        reqwest::Client::new(),
        filter.clone(),
        urls,
        Catalog::fallback(),
        Duration::from_secs(3600),
        source_bits,
        TEST_CAP,
        DEFAULT_MAX_LIST_ENTRIES,
        Some(dir.path().to_path_buf()),
    );
    mgr.load_disk_cache();
    let count = mgr.refresh_with_mode(RefreshMode::CacheOnly).await;

    // Sanity: the fixture exercises both routes it claims to — one
    // domain installed (from `kept`), nothing from `missing`.
    assert_eq!(count, 1, "only `kept` has a body to contribute");
    assert!(filter.is_blocked("kept.example.com"));

    assert!(
        mgr.installed_corpus_digest.is_none(),
        "an incomplete cold-start corpus must not publish a digest"
    );
    assert_eq!(
        mgr.status_registry.cycle().outcome,
        Some(CycleOutcome::Installed),
        "a cold partial corpus is installed, but only as an explicitly qualified outcome"
    );
    assert!(mgr.status_registry.cycle().source_coverage_incomplete);
    let kept = mgr.status_registry.status_for_url(&kept_url).unwrap();
    let missing = mgr.status_registry.status_for_url(&missing_url).unwrap();
    assert_eq!(kept.entries, 1);
    assert_eq!(missing.entries, 0);
    assert!(matches!(kept.last_outcome, LastOutcome::NeverFetched));
    assert!(matches!(missing.last_outcome, LastOutcome::NeverFetched));
}

#[tokio::test]
async fn cache_only_cap_refusal_leaves_health_and_retry_state_untouched() {
    let dir = tempfile::tempdir().unwrap();
    let kept_url = "https://127.0.0.1/kept.txt".to_string();
    let refused_url = "https://127.0.0.1/refused.txt".to_string();
    let missing_url = "https://127.0.0.1/missing.txt".to_string();
    let old = OffsetDateTime::now_utc() - time::Duration::days(30);

    for (url, body) in [
        (&kept_url, "kept.example.com\n"),
        (
            &refused_url,
            "refused-one.example.com\nrefused-two.example.com\nrefused-three.example.com\n",
        ),
    ] {
        let stem = source_to_cache_stem(url);
        std::fs::write(dir.path().join(format!("{stem}.cache")), body).unwrap();
        std::fs::write(
            dir.path().join(format!("{stem}.meta")),
            format!(
                "etag=\nlast-modified=\nfetched-at={}\n",
                old.format(&Rfc3339).unwrap()
            ),
        )
        .unwrap();
    }

    let filter = Arc::new(FilterEngine::new());
    let urls = vec![kept_url.clone(), refused_url.clone(), missing_url];
    let source_bits = build_source_bit_map(&urls).expect("at-cap accept");
    let mut mgr = ListManager::new(
        reqwest::Client::new(),
        filter.clone(),
        urls,
        Catalog::fallback(),
        Duration::from_secs(3600),
        source_bits,
        TEST_CAP,
        4,
        Some(dir.path().to_path_buf()),
    );
    mgr.load_disk_cache();
    mgr.set_source_max_entries(HashMap::from([
        (kept_url.clone(), 4),
        (refused_url.clone(), 2),
    ]));

    let blocklist_id = crate::config::schema::Id::new("boot-refused").unwrap();
    let prior_entry = crate::config::list_state::ListStatusEntry {
        status: crate::config::list_state::ListStatus::Active,
        last_success: Some(old),
        last_attempt: Some(old),
        consecutive_failures: 1,
        cache_path: Some(dir.path().join("previous.cache")),
    };
    let mut prior_state = crate::config::list_state::ListState::default();
    prior_state
        .lists
        .insert(blocklist_id.clone(), prior_entry.clone());
    mgr.set_list_state(prior_state, None);
    mgr.set_source_blocklist_map(HashMap::from([(
        refused_url.clone(),
        (blocklist_id.clone(), 2),
    )]));
    let (notification_tx, mut notifications) = tokio::sync::broadcast::channel(8);
    mgr.set_notification_channel(notification_tx);

    assert_eq!(
        mgr.refresh_with_mode(RefreshMode::CacheOnly).await,
        1,
        "the accepted cached source installs while the refused and missing sources contribute zero"
    );
    assert!(filter.is_blocked("kept.example.com"));
    assert!(!filter.is_blocked("refused-one.example.com"));

    let refused = mgr.status_registry.status_for_url(&refused_url).unwrap();
    assert_eq!(
        refused.last_outcome,
        crate::lists::status::LastOutcome::NeverFetched
    );

    let state = mgr.list_state_handle().lock().unwrap().clone();
    assert_eq!(state.lists.get(&blocklist_id), Some(&prior_entry));
    assert!(notifications.try_recv().is_err());
}

/// A `kind` flip must reach the map even when no body changed.
///
/// `build_shard` routes by `allow_bits`, but until this fix the digest
/// that decides whether `build_shard` runs at all did not include them.
/// So `set_allow_bits` + reload on an unchanged corpus skipped the
/// rebuild and the flip did nothing — silently, and in the
/// allow→deny direction that means a revoked exemption keeps
/// exempting.
#[tokio::test]
async fn flipping_a_list_direction_forces_a_rebuild_on_an_unchanged_corpus() {
    let (mut mgr, _urls, _dir) = spill_manager(&["a.example\n"]);
    assert_eq!(mgr.refresh().await, 1);
    assert_eq!(mgr.rebuild_count, 1);

    // Nothing about the bodies changes — only the operator's policy.
    mgr.set_list_policy(PolicyMasks {
        base: crate::filter::engine::ProfileMasks { allow: 1, block: 0 },
        ..PolicyMasks::default()
    });

    assert_eq!(mgr.refresh().await, 1);
    assert_eq!(
        mgr.rebuild_count, 2,
        "the direction flip did not rebuild — the map still routes this source the \
         way the previous policy said, and nothing tells the operator"
    );
    assert_eq!(
        mgr.probe_skips, 0,
        "and the probe must not settle a cycle whose policy inputs moved"
    );
}

// ── mem2608-s7: the no-cache_dir path ─────────────────────────────

/// The warning has to name the cost, because a deployment that hits
/// this gets no other signal — it simply uses more memory. A warning
/// that said only "no cache directory configured" would be true and
/// useless.
#[test]
fn the_cache_dir_warning_names_the_cost() {
    let w = LIST_CACHE_DIR_UNSET_WARNING;
    assert!(
        w.contains("RAM"),
        "the warning must say where the cost lands"
    );
    assert!(
        w.contains("double"),
        "the warning must quantify: an operator cannot act on 'uses more memory'"
    );
    assert!(
        w.contains("lists.cache_dir"),
        "and it must name the knob that fixes it"
    );
}

/// Retention is the chosen behaviour, not an accident — pin it so a
/// later memory pass cannot "optimise" it into a coverage loss.
///
/// Without a `cache_dir` the in-memory body is the **only** copy: drop
/// it and the next 304, the next failed download, and every
/// freshness-skip lose that source's domains entirely. Trading
/// filtering coverage for RAM is the wrong trade for a filter, so the
/// body stays and the warning carries the cost instead.
#[tokio::test]
async fn without_a_cache_dir_the_body_is_retained_deliberately() {
    let (mut mgr, urls, _dir) = spill_manager(&["a.example\n"]);
    mgr.cache_dir = None;

    assert_eq!(mgr.refresh().await, 1);
    assert!(
        mgr.cache
            .get(&urls[0])
            .and_then(|c| c.body.as_ref())
            .is_some(),
        "the body was dropped with no disk copy to fall back on — this source \
         stops filtering on the next cycle that does not download"
    );
}

// ── mem2608-s1 T1: one body copy, not two ─────────────────────────

/// The single-copy property, pinned so the second copy cannot return.
///
/// Capacity is the observable: `String::from_utf8` moves the `Vec`'s
/// allocation, so the capacity survives; `from_utf8_lossy(&v)
/// .into_owned()` builds a fresh buffer sized to the content. At the
/// production 172 MB list the difference is 172 MB of transient
/// resident memory, which is not something a unit test can weigh —
/// but the copy that causes it is exactly what this measures.
#[test]
fn decode_body_reuses_the_download_buffer() {
    let mut body = Vec::with_capacity(4096);
    body.extend_from_slice(b"a.example\n");
    let decoded = decode_body(body);

    assert_eq!(decoded, "a.example\n");
    assert_eq!(
        decoded.capacity(),
        4096,
        "the decode allocated a second buffer — on a 172 MB list that is a full \
         second copy, live while the first is still borrowed"
    );
}

/// The lossy fallback still applies where it must, and only there.
/// `read_bounded_body_lossy_keeps_list_on_bad_byte` covers the same
/// property end-to-end through the HTTP path; this one pins the seam
/// itself, so a future refactor of `read_bounded_body` cannot quietly
/// turn a bad byte into a failed download.
#[test]
fn decode_body_falls_back_to_lossy_on_invalid_utf8() {
    let decoded = decode_body(vec![b'a', 0xff, b'\n']);
    assert!(
        decoded.contains('\u{FFFD}'),
        "invalid bytes must become U+FFFD, not fail the whole list"
    );
}

// ── mem2608-s1 T3: the fresh-cache probe ──────────────────────────

/// The saving, stated as the property that produces it: a cycle whose
/// sources are all cache-fresh and whose bodies are unchanged must not
/// parse a single one of them.
///
/// `rebuild_count` cannot express this — it is 1 on both sides of the
/// fix, because the §11 T5 short-circuit already skipped pass 2. What
/// changed is pass **1**, and the 220 MiB lives there.
#[tokio::test]
async fn an_all_fresh_cycle_parses_no_body() {
    let (mut mgr, _urls, _dir) = cached_manager(&["a.example\n", "b.example\n"]);

    assert_eq!(mgr.refresh().await, 2, "first cycle installs");
    assert_eq!(
        mgr.probe_skips, 0,
        "nothing is installed to compare against"
    );

    assert_eq!(mgr.refresh().await, 2, "the map still reports its size");
    assert_eq!(
        mgr.probe_skips, 1,
        "the probe did not fire on an all-fresh, unchanged cycle — every source was \
         re-parsed to rebuild a digest the daemon already held"
    );
    assert_eq!(mgr.rebuild_count, 1, "and pass 2 stayed skipped");
    assert_eq!(
        mgr.filter.domain_count(),
        2,
        "the map is intact, not merely unrebuilt"
    );
}

#[tokio::test]
async fn effective_cap_change_invalidates_the_fresh_cache_digest_probe() {
    let (mut mgr, urls, _dir) = cached_manager(&["a.example\n", "b.example\n"]);
    assert_eq!(mgr.refresh().await, 2, "first cycle installs the digest");
    let before = mgr.installed_corpus_digest.unwrap();

    mgr.set_source_max_entries(HashMap::from([
        (urls[0].clone(), DEFAULT_MAX_LIST_ENTRIES - 1),
        (urls[1].clone(), DEFAULT_MAX_LIST_ENTRIES),
    ]));
    assert_eq!(mgr.refresh().await, 2, "the unchanged bodies remain valid");
    assert_eq!(
        mgr.probe_skips, 0,
        "the old digest must not settle a source whose effective cap changed"
    );
    assert_eq!(mgr.rebuild_count, 2, "the changed parse semantics rebuild");
    assert_ne!(
        mgr.installed_corpus_digest,
        Some(before),
        "the parse path must fold the new effective cap too"
    );
}

/// The probe reaches `PendingStatus` by a different route than the
/// cache-hit arm, and must reach the same answer about `verified_fresh`.
///
/// The invariant: **no `CacheOnly` cycle stamps a verified refresh, by
/// any route.** The probe enforces `is_cache_fresh` itself, so it is
/// tempting to call its sources verified even on a boot — but a cycle
/// that issued no HTTP, and was never allowed to, reporting a refresh is
/// the freshness lie `boot_list_persistence.md` §2.8 prohibits: a dead
/// upstream reads green in the TUI.
///
/// This exists because the two branches that produced the probe and the
/// `verified_fresh` field never saw each other. The merge had to pick an
/// answer, and an unpinned merge decision is one the next merge picks
/// differently.
///
/// Mutation caught: `verified_fresh: matches!(mode, Network)` at the
/// probe's push site swapped for a bare `true` — the CacheOnly half goes
/// red. (A bare `false` is caught by the Network half.)
#[tokio::test]
async fn the_probe_does_not_stamp_a_refresh_on_a_cache_only_cycle() {
    for (mode, expected) in [
        (RefreshMode::Scheduled, true),
        (RefreshMode::CacheOnly, false),
    ] {
        let (mut mgr, urls, _dir) = cached_manager(&["a.example\n"]);
        assert_eq!(mgr.refresh().await, 1, "first cycle installs");

        let before = mgr
            .status_registry
            .status_for_url(&urls[0])
            .unwrap()
            .last_refresh_at;

        // Far enough ahead to be distinguishable, close enough that
        // `is_cache_fresh` still holds — or the probe returns None and
        // this test would pass for the wrong reason.
        let later = OffsetDateTime::now_utc() + std::time::Duration::from_secs(5);
        mgr.refresh_at_with_mode(later, mode).await;
        assert_eq!(
            mgr.probe_skips, 1,
            "fixture precondition: the probe must fire in {mode:?}, or this \
             test is asserting about a path it never took"
        );

        let after = mgr
            .status_registry
            .status_for_url(&urls[0])
            .unwrap()
            .last_refresh_at;
        assert_eq!(
            after != before,
            expected,
            "in {mode:?} the probe should{} have stamped a refresh",
            if expected { "" } else { " NOT" }
        );
    }
}

/// A manifest generation is content-addressed.  A constant-size edit must
/// fail the probe and retained parse, preserving the complete hot corpus.
#[tokio::test]
async fn a_planted_manifest_generation_edit_of_identical_size_is_rejected() {
    let (mut mgr, urls, dir) = cached_manager(&["aaa.example\n"]);
    assert_eq!(mgr.refresh().await, 1);
    assert_eq!(mgr.rebuild_count, 1);

    // Same byte count, different bytes, straight into the trusted
    // cache — the sidecar's size= still matches.
    let cache_path = selected_cache_body_path(&dir.path().join("cache"), &urls[0]).unwrap();
    let before = std::fs::metadata(&cache_path).unwrap().len();
    std::fs::write(&cache_path, "bbb.example\n").unwrap();
    assert_eq!(
        std::fs::metadata(&cache_path).unwrap().len(),
        before,
        "the fixture must keep the length identical or it proves nothing"
    );

    assert_eq!(mgr.refresh().await, 1, "the hot generation is preserved");
    assert_eq!(
        mgr.probe_skips, 0,
        "a mismatched manifest body must not settle the probe"
    );
    assert_eq!(
        mgr.rebuild_count, 1,
        "a rejected retained body must not rebuild a tampered corpus"
    );
    assert!(
        !mgr.filter.list_membership("aaa.example").is_empty(),
        "the trusted hot generation must remain installed"
    );
    assert!(mgr.filter.list_membership("bbb.example").is_empty());
}

#[tokio::test]
async fn cache_only_rejects_a_tampered_manifest_generation() {
    let (mut mgr, urls, dir) = cached_manager(&["old.example\n"]);
    assert_eq!(mgr.refresh().await, 1);
    let cache_path = selected_cache_body_path(&dir.path().join("cache"), &urls[0]).unwrap();
    std::fs::write(cache_path, "bad.example\n").unwrap();

    assert_eq!(mgr.refresh_with_mode(RefreshMode::CacheOnly).await, 1);
    assert!(!mgr.filter.list_membership("old.example").is_empty());
    assert!(mgr.filter.list_membership("bad.example").is_empty());
    assert_eq!(mgr.probe_skips, 0);
}

/// A retained reader that fails parsing is not a missing retained body.
#[tokio::test]
async fn cache_only_retained_parse_failure_does_not_log_missing_body() {
    use tracing_subscriber::layer::SubscriberExt;

    struct Messages(std::sync::Arc<std::sync::Mutex<Vec<String>>>);

    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Messages {
        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            struct Visitor(String);

            impl tracing::field::Visit for Visitor {
                fn record_debug(
                    &mut self,
                    field: &tracing::field::Field,
                    value: &dyn std::fmt::Debug,
                ) {
                    if field.name() == "message" {
                        self.0 = format!("{value:?}");
                    }
                }
            }

            let mut visitor = Visitor(String::new());
            event.record(&mut visitor);
            self.0.lock().unwrap().push(visitor.0);
        }
    }

    let (mut mgr, urls, dir) = cached_manager(&["old.example\n"]);
    assert_eq!(mgr.refresh().await, 1);
    let cache_path = selected_cache_body_path(&dir.path().join("cache"), &urls[0]).unwrap();
    std::fs::write(cache_path, "bad.example\n").unwrap();

    let messages = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let subscriber =
        tracing_subscriber::registry().with(Messages(std::sync::Arc::clone(&messages)));
    let _guard = tracing::subscriber::set_default(subscriber);
    mgr.refresh_with_mode(RefreshMode::CacheOnly).await;

    let messages = messages.lock().unwrap();
    assert_eq!(
        messages
            .iter()
            .filter(|message| message.contains("failed to stream fresh cache body"))
            .count(),
        1,
        "a retained parse failure must emit its stream-failure warning"
    );
    assert!(
        !messages
            .iter()
            .any(|message| message.contains("cache marked fresh but body missing")),
        "a retained parse failure must not also claim the body was missing"
    );
}

// ── mem2608-s1 T2: not counting must not mean counting zero ───────

/// The saving itself: an arm that re-reads an unchanged body must not
/// rebuild the ~144 MiB dedup set to reproduce a number it already has.
///
/// Fails on the unfixed code, where every arm measures. src1 is held
/// out of phase so the T3 probe cannot settle the cycle — otherwise
/// this would pass for T3's reason instead of T2's, which is the same
/// trap `an_all_fresh_cycle_parses_no_body` sets on purpose.
#[tokio::test]
async fn an_unchanged_body_is_not_re_counted() {
    let (mut mgr, urls, dir) = cached_manager(&["a.example\n", "solo.example\n"]);

    assert_eq!(mgr.refresh().await, 2);
    let after_first = SOURCES_MEASURED.with(|c| c.get());
    assert_eq!(
        after_first, 2,
        "the installing cycle must measure both sources — it has no prior count"
    );

    // One body changes on disk, so the probe cannot settle the cycle
    // and the walk runs. Both sources are still cache-fresh, so both
    // take the arm that re-reads a body whose count is already known.
    rewrite_cached_body(&dir, &urls[1], "solo.example\nextra.example\n");
    assert_eq!(mgr.refresh().await, 3);
    assert_eq!(
        mgr.probe_skips, 0,
        "the walk must have run for this to prove anything"
    );

    assert_eq!(
        SOURCES_MEASURED.with(|c| c.get()),
        after_first,
        "a body that did not change was counted again — that is the ~144 MiB T2 \
         removes, spent reproducing a number the previous cycle already recorded"
    );
}

/// The fail-open hazard T2 could have introduced, pinned.
///
/// `compute_shrink_verdict` reads `unique_domains == 0` as *no
/// baseline — accept anything*. So a cycle that stops measuring and
/// writes `0` does not merely lose a statistic: it disarms the
/// retention guard for the **next** download, which is the guard
/// written after the 19 % silent-truncation incident. The carried
/// count is a `NonZeroU64` for exactly this reason.
///
/// The property is in the type, so it is tested in the type: a count
/// may be carried only when it is a usable baseline, and zero is not.
///
/// Tested here rather than end-to-end because the end-to-end route
/// does not exist in-process: carrying happens on the fresh-cache /
/// 304 / download-failure arms, and the shrink that would expose a
/// disarmed guard has to arrive as a **200**, which no in-process test
/// can produce (the URL guard refuses loopback and plain http, and the
/// `imported.local` bridge deliberately never takes the fresh-cache
/// arm). What survives is the exact hazard — a zero reaching
/// `compute_shrink_verdict` as a baseline — asserted at the seam that
/// decides it.
#[test]
fn a_zero_count_is_never_carried_forward() {
    // The state that would disarm the guard: a prior status whose
    // `unique_domains` is 0. `compute_shrink_verdict` reads that as
    // "no baseline — accept anything", so carrying it would let the
    // next 200 shrink a list by 99% and install.
    //
    // Spelled as a struct literal rather than `default()` + reassignment
    // so the two fields the test is *about* are visible at the binding,
    // and so `clippy::field_reassign_with_default` stays satisfied.
    // Still `mut`: the second half of the test reuses this binding. The
    // lint fires on `default()` *immediately* followed by assignment,
    // which the literal above already avoids — so `mut` is not a leftover.
    let mut prev = ListStatus {
        unique_domains: 0,
        prev_entries: None,
        ..Default::default()
    };
    assert!(
        matches!(
            UniqueCount::carry_or_measure(Some(&prev), usize::MAX),
            UniqueCount::Measure(_)
        ),
        "a zero was carried forward — the next download's shrink guard would then have \
         no baseline and accept anything, which is the 19% silent-truncation class"
    );
    assert!(
        matches!(
            compute_shrink_verdict(true, 90, Some(&prev), 0, usize::MAX),
            ShrinkVerdict::Accept { .. }
        ),
        "this is why: a zero baseline accepts an empty body outright"
    );

    // A usable prior is carried, and carried exactly.
    prev.unique_domains = 5_000;
    match UniqueCount::carry_or_measure(Some(&prev), usize::MAX) {
        UniqueCount::Carried(n) => assert_eq!(n.get(), 5_000),
        other => panic!("a usable prior count must be carried, got {other:?}"),
    }

    // And the arm that must always measure does, prior or not.
    assert!(matches!(
        UniqueCount::measure(Some(&prev), usize::MAX),
        UniqueCount::Measure(Some(_))
    ));
    assert!(matches!(
        UniqueCount::measure(None, usize::MAX),
        UniqueCount::Measure(None)
    ));
}

// ── mem2608-t0: the tick that could never fetch ───────────────────
//
// These drive the healthy-ticker relationship the daemon has, not the
// predicate on its own: a fixed-period tick, and a stamp written while the
// cycle runs. A degraded cycle alone resets its next deadline to the bounded
// recovery cadence. `refresh_at` supplies the cycle anchor, so "the cycle began
// 456 s ago" is expressible without waiting 456 s. 456 s is measured
// — the 2026-08-15 13:22:52 cycle on the lab host took exactly that to
// fetch its 14 lists.
//
// Written against `is_cache_fresh`'s call site rather than against
// `is_cache_fresh`, because every unit-level formulation of this
// property passes on the broken code: the bug is which instant gets
// stamped, and a unit test hands that instant in ready-made.

/// A tick one full interval after a cycle that took 456 s must
/// re-fetch. On the pre-fix code the stamp is the download's
/// completion, so the age at the next tick is `interval − 456 s`,
/// `is_cache_fresh` says fresh, and the cycle reuses the cache — the
/// effective interval doubles and the operator is told nothing.
/// Which half of T0 actually makes the next tick fetch — asserted as a
/// difference, because the two halves are not interchangeable and the
/// tempting single-half fixes both fail here.
///
/// A cycle ticks at `tick` and takes 456 s (measured: the lab host,
/// 2026-08-15 13:22:52). The next healthy fixed-period tick lands at
/// `tick + interval`. The only thing that differs between the broken
/// and the fixed daemon is **which instant got stamped**.
///
/// The first assertion is the defect, and it must keep holding: it is
/// what stops someone from "fixing" T0 by inflating
/// `CACHE_FRESHNESS_MARGIN` past a cycle duration instead. That is SoT
/// option (b) standing alone, and it is unbounded — the margin would
/// have to exceed the slowest cycle on the slowest network, a number
/// that grows with the corpus. Measured on the two live hosts the
/// deficit differs by two orders of magnitude (4–36 s on proxmox,
/// 315–422 s on zima), so any margin large enough for one is either
/// wrong for the other or swallows a whole cycle.
#[test]
fn the_anchor_not_the_margin_is_what_makes_the_next_tick_stale() {
    let interval = Duration::from_secs(43_200);
    let tick = OffsetDateTime::now_utc() - time::Duration::seconds(43_200);
    let next_tick = tick + interval;
    let cycle_duration = time::Duration::seconds(456);

    assert!(
        is_cache_fresh(tick + cycle_duration, next_tick, interval),
        "a completion stamp read as STALE at the next tick — then the margin has been \
         grown to cover a whole cycle, which is the unbounded, per-host-tuned fix this \
         design rejected"
    );

    assert!(
        !is_cache_fresh(tick, next_tick, interval),
        "a cycle-anchor stamp still read as fresh one full interval later — the \
         scheduled refresh can never fetch"
    );
}

/// The stamping half, on a production path a test can actually reach.
///
/// No in-process test can drive the 200 / 304 arms — `validate_list_url`
/// refuses loopback and plain `http`, by design — but the
/// no-`cache_dir` arm stamps the same variable from the same cycle
/// anchor, one `match` away in the same function. Pre-fix all four
/// sites read `OffsetDateTime::now_utc()`, so this fails on today's
/// code; post-fix the stamp is the anchor the cycle was reckoned from,
/// whenever the body actually arrived.
#[tokio::test]
async fn a_cycle_stamps_its_anchor_not_its_completion() {
    let (mut mgr, urls, _dir) = spill_manager(&["a.example\n"]);
    mgr.cache_dir = None; // the arm that retains the body in memory
    let tick = OffsetDateTime::now_utc() - time::Duration::seconds(456);

    assert_eq!(mgr.refresh_at(tick).await, 1);

    let stamped = mgr
        .cache
        .get(&urls[0])
        .map(|c| c.fetched_at)
        .expect("this arm records a validation time");
    assert_eq!(
        stamped, tick,
        "the cycle stamped {stamped} instead of its anchor {tick} — any later instant \
         hands the next healthy fixed-period tick an age short of a full interval, which is \
         fresh by construction"
    );
}

/// The alternation is per-source, so the fix has to be per-source.
/// One list is deliberately out of phase — the state a failed download
/// or a differently-timed cycle leaves behind — and each must be judged
/// on its own clock. A test that drives every source in lockstep passes
/// while the defect survives.
#[tokio::test]
async fn an_out_of_phase_source_is_judged_on_its_own_clock() {
    let (mut mgr, urls, _dir) = cached_manager(&["a.example\n", "x.example\n"]);
    let interval = mgr.refresh_interval;
    let now = OffsetDateTime::now_utc();

    // src0 was validated at this cycle's anchor; src1 three hours
    // before it, so a full interval has already passed for src1 alone.
    mgr.cache.get_mut(&urls[0]).unwrap().fetched_at = now;
    mgr.cache.get_mut(&urls[1]).unwrap().fetched_at = now - interval - interval;

    assert!(
        is_cache_fresh(mgr.cache[&urls[0]].fetched_at, now, interval),
        "the in-phase source must still be served from cache"
    );
    assert!(
        !is_cache_fresh(mgr.cache[&urls[1]].fetched_at, now, interval),
        "the out-of-phase source must be judged stale on its OWN clock, not on the \
         cycle's — sources drift apart whenever one fails or lands in another cycle"
    );

    // And the loop acts on that difference: the stale one attempts a
    // fetch (which fails against an unresolvable host) and is recorded
    // Failed, while the fresh one is served from cache and stays Ok.
    mgr.refresh_at(now).await;
    assert!(matches!(
        mgr.status_registry
            .status_for_url(&urls[0])
            .unwrap()
            .last_outcome,
        LastOutcome::Ok
    ));
    assert!(
        matches!(
            mgr.status_registry
                .status_for_url(&urls[1])
                .unwrap()
                .last_outcome,
            LastOutcome::Failed { .. }
        ),
        "the out-of-phase source was not even attempted"
    );
}

// ── Reload peak measurement (§11 T3, the number this lane exists for)
//
// Run each arm in its OWN process — `VmHWM` is a high-water mark that
// never decreases, so measuring both arms in one process lets the
// first poison the second and reports "no improvement" on working
// code:
//
//   cargo test --lib -- --ignored --exact --nocapture \
//       lists::manager::tests::perf_reload_peak_flat_producer
//   cargo test --lib -- --ignored --exact --nocapture \
//       lists::manager::tests::perf_reload_peak_sharded_producer
//
// Both arms load the SAME corpus into the SAME engine state (a full
// previous generation already installed, so the coexistence the
// sharding exists to bound is real), then run one producer.

/// **The cost measurement for the global corpus guard.** The one
/// number that decides whether the design is acceptable, and it is
/// deliberately measured rather than estimated — the estimate was
/// 1-3 s at the production corpus, which is exactly the sort of claim
/// this workstream has repeatedly found to be wrong.
///
/// Run it on the CT, in its own process:
///
/// ```text
/// cargo test --lib -- --ignored --exact --nocapture \
///     lists::manager::tests::perf_corpus_guard_counting_pass
/// ```
///
/// It prints one `GUARD_COST` line. The absolute count time matters
/// less than `overhead_pct`: the build pass is work the cycle was
/// always going to do, and both passes read the same spill, so their
/// ratio is what the guard actually adds. Scale by roughly 6× for the
/// live 12.3 M corpus against this 2 M fixture, and note the whole
/// reload is dominated by download and parse, neither of which is
/// timed here.
#[cfg(target_os = "linux")]
#[test]
#[ignore = "measurement, not a gate: allocates ~0.2 GB and needs its own process"]
fn perf_corpus_guard_counting_pass() {
    let dir = tempfile::tempdir().unwrap();
    let corpus = perf_corpus(dir.path());
    let spill_dir = dir.path().join("spill");
    std::fs::create_dir_all(&spill_dir).unwrap();

    let mut spill = ShardSpill::open(Some(&spill_dir)).unwrap();
    assert!(spill.is_disk(), "the guard's cost is a disk-spill property");
    let body = std::fs::read_to_string(&corpus).unwrap();
    parse_source_into_spill(
        std::io::Cursor::new(body.as_bytes()),
        1,
        &mut spill,
        PERF_CORPUS_DOMAINS + 1,
        "perf",
        Some(ListFormat::DomainOnly),
    )
    .unwrap();
    drop(body);
    spill.flush().unwrap();

    // ── the pass the guard adds ──
    let t0 = std::time::Instant::now();
    let mut novel_by_bit = [0u64; 64];
    let mut unique = 0u64;
    for idx in 0..DOMAIN_SHARDS {
        unique += spill.count_unique(idx, &mut novel_by_bit).unwrap();
    }
    let count_ms = t0.elapsed().as_secs_f64() * 1000.0;

    // ── the pass it precedes, for scale ──
    let t1 = std::time::Instant::now();
    let mut added_by_bit = [0u64; 64];
    let mut built = 0usize;
    let policy = ListPolicy::publish_uniform(0);
    for idx in 0..DOMAIN_SHARDS {
        built += spill
            .build_shard(idx, unique as usize / DOMAIN_SHARDS + 1, &policy)
            .unwrap()
            .merge_added_by_bit(&mut added_by_bit)
            .len();
    }
    let build_ms = t1.elapsed().as_secs_f64() * 1000.0;

    println!(
        "GUARD_COST domains={unique} count_ms={count_ms:.0} build_ms={build_ms:.0} \
         overhead_pct={:.1}",
        count_ms / build_ms * 100.0
    );
    assert_eq!(
        unique as usize, PERF_CORPUS_DOMAINS,
        "counted the wrong corpus"
    );
    assert_eq!(
        built, PERF_CORPUS_DOMAINS,
        "the count pass consumed the spill"
    );
}

/// Peak resident set since process start, in KiB.
#[cfg(target_os = "linux")]
fn vm_hwm_kb() -> u64 {
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmHWM:") {
            return rest
                .split_whitespace()
                .next()
                .unwrap()
                .parse()
                .expect("VmHWM is a number");
        }
    }
    panic!("no VmHWM in /proc/self/status");
}

/// Drop the peak back to the current RSS.
///
/// Without this the *setup* — which installs the previous generation
/// the flat way — leaves a high-water mark the measured arm can never
/// read below, flooring the sharded arm at the flat arm's cost and
/// reporting no improvement on working code. Verified to work on this
/// kernel before being relied on; the assertion below keeps it that
/// way, because a silently-failing reset is worse than none.
#[cfg(target_os = "linux")]
fn reset_vm_hwm() {
    std::fs::write("/proc/self/clear_refs", "5").expect("clear_refs=5 must be writable");
}

/// Domains matching the production corpus's measured shape: 20 bytes
/// mean, i.e. inline in `CompactString` (§7 measured 20.3 B/domain).
#[cfg(target_os = "linux")]
const PERF_CORPUS_DOMAINS: usize = 2_000_000;

#[cfg(target_os = "linux")]
fn perf_corpus(dir: &Path) -> PathBuf {
    let path = dir.join("corpus.txt");
    let mut out = std::io::BufWriter::with_capacity(1 << 20, std::fs::File::create(&path).unwrap());
    for i in 0..PERF_CORPUS_DOMAINS {
        writeln!(out, "dom{i:07}xy.example").unwrap();
    }
    out.flush().unwrap();
    path
}

/// Install a full generation, the way a running daemon already holds
/// one when a reload starts.
#[cfg(target_os = "linux")]
fn perf_install_previous_generation(engine: &FilterEngine, path: &Path) {
    let body = std::fs::read_to_string(path).unwrap();
    let mut map: HashMap<CompactString, u64, RandomState> =
        HashMap::with_capacity_and_hasher(PERF_CORPUS_DOMAINS, RandomState::new());
    crate::lists::parser::parse_list_into_map(
        &body,
        1,
        &mut map,
        usize::MAX,
        "perf",
        Some(ListFormat::DomainOnly),
    );
    engine.swap_domain_map(map);
}

/// Baseline arm: exactly what `refresh()` used to do — one flat
/// full-corpus map, filled from a `read_to_string` of the body, handed
/// over whole.
#[cfg(target_os = "linux")]
#[test]
#[ignore = "measurement, not a gate: allocates ~0.5 GB and needs its own process"]
fn perf_reload_peak_flat_producer() {
    let dir = tempfile::tempdir().unwrap();
    let path = perf_corpus(dir.path());
    let engine = FilterEngine::new();
    perf_install_previous_generation(&engine, &path);
    let before_reset = vm_hwm_kb();
    reset_vm_hwm();
    let baseline = vm_hwm_kb();
    assert!(
        baseline < before_reset,
        "clear_refs did not reset VmHWM ({before_reset} -> {baseline}); \
         the measurement would be floored by the setup and is not valid"
    );

    // ── the old producer ──
    let body = std::fs::read_to_string(&path).unwrap();
    let mut merged: HashMap<CompactString, u64, RandomState> =
        HashMap::with_capacity_and_hasher(engine.domain_count(), RandomState::new());
    crate::lists::parser::parse_list_into_map(
        &body,
        1,
        &mut merged,
        usize::MAX,
        "perf",
        Some(ListFormat::DomainOnly),
    );
    drop(body);
    merged.shrink_to_fit();
    let total = merged.len();
    engine.swap_domain_map(merged);
    // ──────────────────────

    let peak = vm_hwm_kb();
    println!(
        "ARM=flat domains={total} baseline_hwm_kb={baseline} peak_hwm_kb={peak} \
         peak_mb={:.1}",
        peak as f64 / 1024.0
    );
    assert_eq!(total, PERF_CORPUS_DOMAINS);
    assert_eq!(engine.domain_count(), PERF_CORPUS_DOMAINS);
}

/// The shard-at-a-time producer: the same corpus, the same installed
/// generation, partitioned to spill and installed one sixteenth at a
/// time.
#[cfg(target_os = "linux")]
#[test]
#[ignore = "measurement, not a gate: allocates ~0.2 GB and needs its own process"]
fn perf_reload_peak_sharded_producer() {
    let dir = tempfile::tempdir().unwrap();
    let path = perf_corpus(dir.path());
    let engine = FilterEngine::new();
    perf_install_previous_generation(&engine, &path);
    let before_reset = vm_hwm_kb();
    reset_vm_hwm();
    let baseline = vm_hwm_kb();
    assert!(
        baseline < before_reset,
        "clear_refs did not reset VmHWM ({before_reset} -> {baseline}); \
         the measurement would be floored by the setup and is not valid"
    );

    // ── the new producer ──
    let estimated = engine.domain_count();
    let mut spill = ShardSpill::open(Some(dir.path())).unwrap();
    assert!(spill.is_disk(), "must measure the disk path");
    parse_source_into_spill(
        std::io::BufReader::with_capacity(SPILL_WRITE_BUF, std::fs::File::open(&path).unwrap()),
        1,
        &mut spill,
        usize::MAX,
        "perf",
        Some(ListFormat::DomainOnly),
    )
    .unwrap();
    spill.flush().unwrap();
    let mut added = [0u64; 64];
    let mut total = 0usize;
    let policy = ListPolicy::publish_uniform(0);
    for idx in 0..DOMAIN_SHARDS {
        let shard = spill
            .build_shard(idx, estimated / DOMAIN_SHARDS + 1, &policy)
            .unwrap()
            .merge_added_by_bit(&mut added);
        total += shard.len();
        engine.swap_shard_sorted(idx, shard);
    }
    // ──────────────────────

    let peak = vm_hwm_kb();
    println!(
        "ARM=sharded domains={total} baseline_hwm_kb={baseline} peak_hwm_kb={peak} \
         peak_mb={:.1}",
        peak as f64 / 1024.0
    );
    assert_eq!(total, PERF_CORPUS_DOMAINS);
    assert_eq!(engine.domain_count(), PERF_CORPUS_DOMAINS);
}

// ── S0c: HTTP compression on list downloads ───────────────────────
//
// warden built reqwest with no compression feature, so it advertised no
// `Accept-Encoding` and decoded nothing, while the origin had been
// serving compressed responses all along — ~3.3x across the published
// corpus (679.6 MB against ~206.9 MB).
//
// **What these tests reach, and what they do not.** They drive the real
// client constructors (`build_bulk_list_client_with`), the real body
// reader (`read_bounded_body`) and the real parser, over a real socket.
// They do NOT reach `ListManager::download_list`, which is where the
// conditional-GET headers are actually attached: that method runs
// `http_client::validate_list_url` first, which refuses `http://` AND
// refuses loopback IP literals, so no `TcpListener` on 127.0.0.1 is
// addressable from it by construction. Reaching it would take TLS plus a
// resolver override in the production builder — a test hook in an SSRF
// guard, which is a worse trade than this gap.
//
// So the 304 tests below pin the **protocol contract** `download_list`
// depends on (its header names and its 304 branch are transcribed from
// `manager.rs:2145-2168`), not `download_list`'s own bookkeeping. Where
// the real path can cross an encoding boundary is answered in NOTES.md
// by reading the code, which is the only honest instrument here.
//
// Verified by mutation on 2026-08-13, because a green test that cannot
// go red is decoration:
//
// | mutation | goes red |
// |---|---|
// | `.no_gzip()` on `base_builder` (kills the feature's effect, not the feature) | `list_client_advertises_gzip` ("sent no Accept-Encoding at all"), `gzip_shrinks_the_response_on_the_wire` ("56890 B not materially below 56890 B"), `gzip_body_round_trips_through_the_production_reader`, `unchanged_list_still_yields_304_under_gzip`, `decompressed_size_is_bounded_even_when_the_wire_is_tiny` |
// | mock answers 304 to ANY `If-None-Match` | `changed_content_survives_a_cross_encoding_validator`, `identity_era_validator_costs_a_refetch_not_a_false_304` |
//
// Note the split in that second row: `unchanged_list_still_yields_304_
// under_gzip` stays GREEN under a trust-any-validator server. It has to —
// it pins that 304 still HAPPENS. Only the pair covers both directions,
// which is why neither is redundant.

/// A mock origin shaped like the published one.
///
/// The load-bearing detail is that it recomputes its ETag from the
/// **current** body on every request and appends an encoding suffix when
/// it compresses — mirroring `"6a7c9943-8fcac6c-zstd"` under zstd against
/// `"6a7c9943-8fcac6c"` under identity. A mock that answered 304 to any
/// `If-None-Match` would make
/// [`changed_content_survives_a_cross_encoding_validator`] pass while
/// testing nothing; verified by mutation, see that test's comment.
struct MockOrigin {
    body: std::sync::Mutex<Vec<u8>>,
    compress: std::sync::atomic::AtomicBool,
    /// Bytes written to the socket for the most recent response body.
    /// Measured at the socket, not read back from a header the client
    /// could not independently verify.
    last_body_bytes: std::sync::atomic::AtomicUsize,
    /// `Accept-Encoding` as it arrived on the most recent request.
    last_accept_encoding: std::sync::Mutex<Option<String>>,
    last_status: std::sync::atomic::AtomicU16,
    requests: std::sync::atomic::AtomicUsize,
}

impl MockOrigin {
    fn new(body: &str, compress: bool) -> Arc<Self> {
        Arc::new(Self {
            body: std::sync::Mutex::new(body.as_bytes().to_vec()),
            compress: std::sync::atomic::AtomicBool::new(compress),
            last_body_bytes: std::sync::atomic::AtomicUsize::new(0),
            last_accept_encoding: std::sync::Mutex::new(None),
            last_status: std::sync::atomic::AtomicU16::new(0),
            requests: std::sync::atomic::AtomicUsize::new(0),
        })
    }

    fn set_body(&self, body: &str) {
        *self.body.lock().unwrap() = body.as_bytes().to_vec();
    }

    fn set_compress(&self, on: bool) {
        self.compress.store(on, std::sync::atomic::Ordering::SeqCst);
    }

    fn accept_encoding(&self) -> Option<String> {
        self.last_accept_encoding.lock().unwrap().clone()
    }

    fn body_bytes_on_wire(&self) -> usize {
        self.last_body_bytes
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    fn last_status(&self) -> u16 {
        self.last_status.load(std::sync::atomic::Ordering::SeqCst)
    }

    fn request_count(&self) -> usize {
        self.requests.load(std::sync::atomic::Ordering::SeqCst)
    }
}

/// Content-derived ETag plus the origin's encoding suffix.
///
/// Derived from the body so it tracks content — which is the property
/// that makes a false 304 impossible to manufacture merely by changing
/// encodings, and the property the test would silently lose if this
/// returned a constant.
fn origin_etag(body: &[u8], compress: bool) -> String {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    body.hash(&mut h);
    if compress {
        format!("\"{:x}-gzip\"", h.finish())
    } else {
        format!("\"{:x}\"", h.finish())
    }
}

fn gzip_bytes(raw: &[u8]) -> Vec<u8> {
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::Write;
    let mut enc = GzEncoder::new(Vec::new(), Compression::default());
    enc.write_all(raw).unwrap();
    enc.finish().unwrap()
}

/// A body with the shape of a real blocklist: many similar lines. Entropy
/// matters here — asserting a compression ratio against random bytes
/// would be asserting that gzip fails.
fn synthetic_blocklist(n: usize) -> String {
    (0..n)
        .map(|i| format!("tracker-{i}.ads.example.com\n"))
        .collect()
}

/// Case-insensitive single-header lookup over a raw request head.
fn header_of(head: &str, name: &str) -> Option<String> {
    head.lines()
        .filter_map(|l| l.split_once(':'))
        .find(|(k, _)| k.trim().eq_ignore_ascii_case(name))
        .map(|(_, v)| v.trim().to_string())
}

/// Serve [`MockOrigin`] on an ephemeral port. One response per
/// connection (`Connection: close`) — keep-alive would buy nothing here
/// and costs request-framing bugs in the mock.
async fn spawn_mock_origin(origin: Arc<MockOrigin>) -> std::net::SocketAddr {
    use std::sync::atomic::Ordering;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        loop {
            let (mut stream, _) = match listener.accept().await {
                Ok(pair) => pair,
                Err(_) => return,
            };
            let origin = Arc::clone(&origin);
            tokio::spawn(async move {
                // Read the request head. Loop until the terminator so a
                // split read cannot truncate the headers we assert on.
                let mut raw = Vec::new();
                let mut buf = [0u8; 1024];
                loop {
                    match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => raw.extend_from_slice(&buf[..n]),
                    }
                    if raw.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                let head = String::from_utf8_lossy(&raw).into_owned();

                *origin.last_accept_encoding.lock().unwrap() = header_of(&head, "accept-encoding");
                let inm = header_of(&head, "if-none-match");
                origin.requests.fetch_add(1, Ordering::SeqCst);

                // Snapshot the shared state and drop the guard BEFORE any
                // await — a MutexGuard held across an await point is both
                // a clippy error and a deadlock waiting to happen.
                let body_now = origin.body.lock().unwrap().clone();
                let compress = origin.compress.load(Ordering::SeqCst);

                // The origin compresses only when the client asked. This
                // is the negotiation the whole change depends on: with no
                // `Accept-Encoding`, an origin serves identity and warden
                // pays full price — which is exactly what it did.
                let client_accepts_gzip = origin
                    .accept_encoding()
                    .is_some_and(|v| v.to_ascii_lowercase().contains("gzip"));
                let compress = compress && client_accepts_gzip;

                let etag = origin_etag(&body_now, compress);

                // 304 only when the validator matches the representation
                // this request would produce RIGHT NOW.
                if inm.as_deref() == Some(etag.as_str()) {
                    origin.last_status.store(304, Ordering::SeqCst);
                    origin.last_body_bytes.store(0, Ordering::SeqCst);
                    let resp = format!(
                        "HTTP/1.1 304 Not Modified\r\n\
                         ETag: {etag}\r\n\
                         Connection: close\r\n\r\n"
                    );
                    let _ = stream.write_all(resp.as_bytes()).await;
                    return;
                }

                let payload = if compress {
                    gzip_bytes(&body_now)
                } else {
                    body_now
                };
                let encoding_header = if compress {
                    "Content-Encoding: gzip\r\n"
                } else {
                    ""
                };
                let head_out = format!(
                    "HTTP/1.1 200 OK\r\n\
                     Content-Type: text/plain\r\n\
                     Content-Length: {}\r\n\
                     {encoding_header}\
                     ETag: {etag}\r\n\
                     Vary: Accept-Encoding\r\n\
                     Connection: close\r\n\r\n",
                    payload.len()
                );
                if stream.write_all(head_out.as_bytes()).await.is_err() {
                    return;
                }
                if stream.write_all(&payload).await.is_err() {
                    return;
                }
                origin.last_status.store(200, Ordering::SeqCst);
                origin
                    .last_body_bytes
                    .store(payload.len(), Ordering::SeqCst);
            });
        }
    });

    addr
}

fn test_bulk_client() -> reqwest::Client {
    crate::lists::http_client::build_bulk_list_client_with(
        Duration::from_secs(20),
        Duration::from_secs(5),
        Duration::from_secs(5),
    )
    .unwrap()
}

/// DoD 1 — the request advertises gzip.
///
/// Asserted on the **inbound** request at the server, not on the client's
/// configuration: `reqwest` exposes no getter for its accepted encodings,
/// so the only observable proof that the `Cargo.toml` feature took effect
/// is the header that reached a socket.
///
/// This is also the test that fails if someone removes `gzip` from the
/// feature list — the feature is the entire mechanism, and there is no
/// line of warden code to break instead.
#[tokio::test]
async fn list_client_advertises_gzip() {
    let origin = MockOrigin::new(&synthetic_blocklist(10), true);
    let addr = spawn_mock_origin(Arc::clone(&origin)).await;

    let client = test_bulk_client();
    let url = format!("http://{addr}/list.txt");
    let resp = client.get(&url).send().await.unwrap();
    assert!(resp.status().is_success());
    let _ = resp.bytes().await.unwrap();

    let ae = origin
        .accept_encoding()
        .expect("production list client sent no Accept-Encoding at all");
    assert!(
        ae.to_ascii_lowercase().contains("gzip"),
        "Accept-Encoding must offer gzip, got: {ae}"
    );
}

/// DoD 2 — measurably fewer bytes on the wire.
///
/// The assertion is **relational**, deliberately. An absolute byte total
/// would encode one compression level over one body shape and would fail
/// while being correct the moment the origin changed either. `< half` is
/// far below the ~3.3x the corpus measures, so it cannot flake on
/// entropy, and it is still a claim gzip-off cannot satisfy.
#[tokio::test]
async fn gzip_shrinks_the_response_on_the_wire() {
    let body = synthetic_blocklist(2000);
    let uncompressed = body.len();
    let origin = MockOrigin::new(&body, true);
    let addr = spawn_mock_origin(Arc::clone(&origin)).await;

    let client = test_bulk_client();
    let url = format!("http://{addr}/list.txt");
    let resp = client.get(&url).send().await.unwrap();
    let got = resp.bytes().await.unwrap();

    let on_wire = origin.body_bytes_on_wire();
    assert!(
        on_wire < uncompressed / 2,
        "on-wire {on_wire} B not materially below uncompressed {uncompressed} B"
    );
    // The client still sees the full body: the saving is transport-only.
    assert_eq!(
        got.len(),
        uncompressed,
        "decoded body must be the full uncompressed length"
    );
    println!(
        "S0c wire measurement: uncompressed={uncompressed} B, on-wire={on_wire} B, \
         ratio={:.2}x",
        uncompressed as f64 / on_wire as f64
    );
}

/// DoD 3 — the content survives the round trip, exactly.
///
/// Runs the real `read_bounded_body` (the function `download_list` uses)
/// and the real parser, then compares the parsed domain set against the
/// set the uncompressed body contained. Byte-length equality alone would
/// not catch a codec that corrupts bytes in place.
#[tokio::test]
async fn gzip_body_round_trips_through_the_production_reader() {
    let body = synthetic_blocklist(500);
    let origin = MockOrigin::new(&body, true);
    let addr = spawn_mock_origin(Arc::clone(&origin)).await;

    let client = test_bulk_client();
    let url = format!("http://{addr}/list.txt");
    let resp = client.get(&url).send().await.unwrap();
    let text = read_bounded_body(resp, &url, TEST_CAP).await.unwrap();

    assert_eq!(text, body, "decompressed body differs from the original");

    let parsed = crate::lists::parser::parse_domain_list(&text);
    let expected = crate::lists::parser::parse_domain_list(&body);
    assert_eq!(parsed.len(), 500, "wrong domain count: {}", parsed.len());
    assert_eq!(parsed, expected, "parsed domain set differs");
    // Confirm the wire really was compressed, so this is not a green
    // round-trip over an identity response that proves nothing.
    assert!(
        origin.body_bytes_on_wire() < body.len(),
        "server served identity — the round trip did not cross the codec"
    );
}

/// DoD 4 — an unchanged list still yields 304 under compression.
///
/// The header names and the 304 detection mirror `download_list`
/// (`manager.rs:2145-2168`): `If-None-Match` from the cached validator,
/// `NOT_MODIFIED` short-circuits before any body read.
#[tokio::test]
async fn unchanged_list_still_yields_304_under_gzip() {
    let body = synthetic_blocklist(300);
    let origin = MockOrigin::new(&body, true);
    let addr = spawn_mock_origin(Arc::clone(&origin)).await;
    let client = test_bulk_client();
    let url = format!("http://{addr}/list.txt");

    let first = client.get(&url).send().await.unwrap();
    assert!(first.status().is_success());
    let etag = first
        .headers()
        .get("etag")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
        .expect("origin must send an ETag to cache");
    let _ = first.bytes().await.unwrap();
    assert!(
        etag.ends_with("-gzip\""),
        "expected the encoding-suffixed validator, got {etag}"
    );

    // Nothing changed — replay the validator.
    let second = client
        .get(&url)
        .header("If-None-Match", &etag)
        .send()
        .await
        .unwrap();
    assert_eq!(
        second.status(),
        reqwest::StatusCode::NOT_MODIFIED,
        "unchanged list must still 304 — conditional GET is what keeps a \
         refresh cycle cheap"
    );
    assert_eq!(origin.request_count(), 2);
    assert_eq!(origin.last_status(), 304);
}

/// DoD 5 — an encoding change must not manufacture a false 304.
///
/// The dangerous failure is silent: warden concluding a list is unchanged
/// when it changed, then serving stale filtering rules with no error and
/// no log. The validator is encoding-specific at the origin, so this
/// walks a validator across that boundary while the content also changes.
///
/// **Verified by mutation on 2026-08-13**, because a green test that
/// cannot go red is decoration. Replacing the mock's match check with
/// `if inm.is_some() { 304 }` — a server that trusts any validator —
/// fails this test on the status assertion, and would fail on the
/// stale-domain assertion below it too. The
/// [`unchanged_list_still_yields_304_under_gzip`] sibling stays green
/// under that mutation, which is precisely why both are needed: one pins
/// that 304 still happens, the other that it does not happen wrongly.
#[tokio::test]
async fn changed_content_survives_a_cross_encoding_validator() {
    let old_body = "stale-tracker.example.com\n";
    let origin = MockOrigin::new(old_body, true);
    let addr = spawn_mock_origin(Arc::clone(&origin)).await;
    let client = test_bulk_client();
    let url = format!("http://{addr}/list.txt");

    // 1. Cache a validator obtained under gzip.
    let first = client.get(&url).send().await.unwrap();
    let gzip_etag = first
        .headers()
        .get("etag")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
        .unwrap();
    let _ = first.bytes().await.unwrap();

    // 2. The list changes, AND the origin stops compressing — the
    //    encoding boundary the cached validator now has to cross.
    let new_body = "fresh-tracker.example.com\n";
    origin.set_body(new_body);
    origin.set_compress(false);

    // 3. Replay the gzip-era validator against the identity response.
    let second = client
        .get(&url)
        .header("If-None-Match", &gzip_etag)
        .send()
        .await
        .unwrap();
    assert_ne!(
        second.status(),
        reqwest::StatusCode::NOT_MODIFIED,
        "FALSE 304: a stale validator from another encoding suppressed a \
         body that actually changed — warden would filter on stale rules \
         with no error and no log"
    );
    assert!(second.status().is_success());

    // The body is the assertion that matters: a 200 carrying the old
    // content would be the same defect wearing a different status.
    let text = read_bounded_body(second, &url, TEST_CAP).await.unwrap();
    let parsed = crate::lists::parser::parse_domain_list(&text);
    assert!(
        parsed.contains("fresh-tracker.example.com"),
        "new domain missing after the encoding change: {parsed:?}"
    );
    assert!(
        !parsed.contains("stale-tracker.example.com"),
        "served the STALE domain across the encoding boundary: {parsed:?}"
    );
}

/// The post-upgrade transition, recorded because its cost is real and
/// its direction is the opposite of the one the risk was framed as.
///
/// A warden built before this change cached identity validators. The
/// first refresh after the upgrade replays them under gzip, and the
/// origin's suffixed ETag cannot match — so every list re-downloads in
/// full exactly once. That is a spurious **200**, not a false 304: an
/// encoding suffix makes a validator MORE specific, never less, so this
/// boundary can only cost bandwidth, never correctness. One cycle, then
/// the cache holds gzip-era validators and 304s resume.
#[tokio::test]
async fn identity_era_validator_costs_a_refetch_not_a_false_304() {
    let body = synthetic_blocklist(50);
    // The origin serves identity first — warden before this change.
    let origin = MockOrigin::new(&body, false);
    let addr = spawn_mock_origin(Arc::clone(&origin)).await;
    let url = format!("http://{addr}/list.txt");

    let plain = crate::lists::http_client::build_list_client(Duration::from_secs(10)).unwrap();
    let first = plain.get(&url).send().await.unwrap();
    let identity_etag = first
        .headers()
        .get("etag")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
        .unwrap();
    let _ = first.bytes().await.unwrap();
    assert!(
        !identity_etag.ends_with("-gzip\""),
        "identity leg must not carry the gzip suffix: {identity_etag}"
    );

    // Now the upgraded client, same unchanged content, replaying the
    // identity-era validator.
    origin.set_compress(true);
    let second = test_bulk_client()
        .get(&url)
        .header("If-None-Match", &identity_etag)
        .send()
        .await
        .unwrap();
    assert!(
        second.status().is_success(),
        "expected a full 200 refetch on the first post-upgrade cycle"
    );
    let text = read_bounded_body(second, &url, TEST_CAP).await.unwrap();
    assert_eq!(text, body, "the refetched body must still be correct");
}

/// The security property this change WEAKENS, pinned before it can rot.
///
/// `reqwest` removes `Content-Length` from a response it decodes
/// (documented at `async_impl/client.rs:1226`), so the early-fail guard
/// in `download_list` (`manager.rs:2191`) is **dead for every compressed
/// response** — `resp.content_length()` returns `None` and the check is
/// skipped entirely.
///
/// That is survivable only because the real bound was never that guard:
/// `read_bounded_body_bytes` counts the chunks it actually receives, and
/// after decoding those are **decompressed** bytes. So the cap still
/// measures the axis that can exhaust memory. What compression changes is
/// the attacker's cost — a few KB on the wire now buys the full
/// `max_body_bytes` of warden's allocator — which makes the streaming
/// bound load-bearing where it used to be defence in depth.
#[tokio::test]
async fn decompressed_size_is_bounded_even_when_the_wire_is_tiny() {
    const CAP: usize = 1024 * 1024;
    // ~4 MiB that gzips to a few KB: past the cap decompressed, trivial
    // compressed. The shape of a decompression bomb, at test scale.
    let body = "bomb.example.com\n".repeat(256 * 1024);
    assert!(body.len() > 4 * CAP);
    let origin = MockOrigin::new(&body, true);
    let addr = spawn_mock_origin(Arc::clone(&origin)).await;

    let client = test_bulk_client();
    let url = format!("http://{addr}/list.txt");
    let resp = client.get(&url).send().await.unwrap();

    // The dead guard, demonstrated rather than asserted from the docs.
    assert!(
        resp.content_length().is_none(),
        "reqwest kept Content-Length on a decoded response — the early \
         guard in download_list may be live again; re-check manager.rs:2191"
    );

    let result = read_bounded_body(resp, &url, CAP).await;
    match result {
        Err(ListError::TooLarge { size, max, .. }) => {
            assert_eq!(max, CAP);
            assert!(size > CAP, "size {size} should exceed cap {CAP}");
        }
        other => {
            panic!("a body that decompresses past max_body_bytes must be refused, got {other:?}")
        }
    }
    assert!(
        origin.body_bytes_on_wire() < CAP / 10,
        "the wire payload was not small — this did not model a bomb"
    );
}
