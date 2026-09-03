use super::*;
use std::net::Ipv4Addr;

fn sample_entry(domain: &str, blocked: bool) -> QueryLogEntry {
    QueryLogEntry {
        timestamp: "2026-04-08T15:00:00Z".into(),
        client_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
        client_name: Some("laptop".into()),
        domain: domain.into(),
        query_type: "A".into(),
        result: if blocked { "BLOCKED" } else { "ALLOWED" }.into(),
        response_time_us: 500,
        cname_chain_via: None,
        rewrote_from: None,
    }
}

#[test]
fn entry_serialization_roundtrip() {
    let entry = sample_entry("google.com", false);
    let json = serde_json::to_string(&entry).unwrap();
    let parsed: QueryLogEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.domain, "google.com");
    assert_eq!(parsed.result, "ALLOWED");
    assert_eq!(parsed.client_name, Some("laptop".into()));
}

#[test]
fn entry_without_client_name() {
    let mut entry = sample_entry("test.com", true);
    entry.client_name = None;
    let json = serde_json::to_string(&entry).unwrap();
    assert!(!json.contains("client_name")); // skip_serializing_if = None
    let parsed: QueryLogEntry = serde_json::from_str(&json).unwrap();
    assert!(parsed.client_name.is_none());
}

#[test]
fn entry_with_cname_chain_via_round_trips() {
    // §4.5 Sprint 2/2: a CNAME chain block populates
    // `cname_chain_via` with the offending hop. The TUI Query Log
    // renders this as `qname → offending` plus a `[CNAME]` badge.
    let mut entry = sample_entry("apex.example.com", true);
    entry.cname_chain_via = Some("offending.tracker.example".into());
    let json = serde_json::to_string(&entry).unwrap();
    assert!(json.contains("\"cname_chain_via\":\"offending.tracker.example\""));
    let parsed: QueryLogEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(
        parsed.cname_chain_via.as_deref(),
        Some("offending.tracker.example")
    );
}

#[test]
fn entry_without_cname_chain_via_skips_field() {
    // Pre-S4.5-P2 / non-CNAME-block entries must not surface a
    // spurious `cname_chain_via: null` line — `skip_serializing_if`
    // keeps the JSONL bytes byte-identical to legacy entries.
    let entry = sample_entry("google.com", false);
    let json = serde_json::to_string(&entry).unwrap();
    assert!(!json.contains("cname_chain_via"));
}

#[test]
fn legacy_entry_without_cname_chain_via_field_parses_as_none() {
    // Pre-S4.5-P2 JSONL files (and snapshots from older daemons)
    // do not carry the field. `#[serde(default)]` keeps them
    // readable — the field reads back as `None`.
    let legacy_json = r#"{
        "timestamp":"2026-04-08T15:00:00Z",
        "client_ip":"192.168.1.1",
        "client_name":"laptop",
        "domain":"google.com",
        "query_type":"A",
        "result":"ALLOWED",
        "response_time_us":500
    }"#;
    let parsed: QueryLogEntry = serde_json::from_str(legacy_json).unwrap();
    assert!(parsed.cname_chain_via.is_none());
}

#[test]
fn resolved_query_log_path_passes_through_absolute_input() {
    let out = resolved_query_log_path(
        Path::new("/srv/alt/query.log"),
        Path::new("/tmp/any/config.toml"),
    );
    assert_eq!(out, PathBuf::from("/srv/alt/query.log"));
}

#[test]
fn resolved_query_log_path_joins_relative_against_config_dir() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("config.toml");
    let out = resolved_query_log_path(Path::new("./query.log"), &config_path);
    assert_eq!(out, dir.path().join("query.log"));
}

#[test]
fn resolved_query_log_path_redirects_etc_master_to_var_lib() {
    // Preserves the Sprint 34 state-dir redirection so the reader
    // looks where the writer actually writes on an FHS v1 install.
    let out = resolved_query_log_path(
        Path::new("./query.log"),
        Path::new("/etc/purge-warden/config.toml"),
    );
    assert_eq!(out, PathBuf::from("/var/lib/purge-warden/query.log"));
}

#[test]
fn resolved_query_log_path_strips_embedded_curdir() {
    // Sprint 39: the legacy join of `./query.log` onto the state
    // dir leaked a `./` component into the final path, producing
    // cosmetically ugly log lines like
    // `/var/lib/purge-warden/./query.log`. The helper now
    // normalizes before returning.
    let out = resolved_query_log_path(
        Path::new("./query.log"),
        Path::new("/etc/purge-warden/config.toml"),
    );
    let s = out.to_string_lossy();
    assert!(
        !s.contains("/./"),
        "output {s} must not carry embedded `./` components"
    );
    assert_eq!(out, PathBuf::from("/var/lib/purge-warden/query.log"));
}

#[test]
fn resolved_query_log_path_ignores_daemon_cwd() {
    // The helper must resolve relative inputs against the config
    // directory, never against `std::env::current_dir`. Proven by
    // resolving under an isolated tempdir and asserting the output
    // is anchored there, regardless of what the test process cwd is.
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("config.toml");
    let out = resolved_query_log_path(Path::new("./query.log"), &config_path);
    assert!(
        out.starts_with(dir.path()),
        "output {} should be anchored to {}",
        out.display(),
        dir.path().display()
    );
    assert!(!out.starts_with(std::env::current_dir().unwrap_or_default()));
}

// ── Sprint 38 QLP2: daily rotation + backstop + prune ────

fn ymd(y: i32, m: u8, d: u8) -> time::Date {
    time::Date::from_calendar_date(y, time::Month::try_from(m).unwrap(), d).unwrap()
}

#[test]
fn daily_rotate_renames_current_to_dated_and_opens_fresh() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("query.log");
    std::fs::write(&log_path, "yesterday's lines\n").unwrap();

    rotate_daily(&log_path, ymd(2026, 4, 22));

    assert!(!log_path.exists(), "query.log moved aside");
    let dated = dir.path().join("query.log.2026-04-22");
    assert!(dated.exists(), "yesterday's dated file created");
    assert_eq!(
        std::fs::read_to_string(&dated).unwrap(),
        "yesterday's lines\n"
    );
}

#[test]
fn daily_rotate_is_idempotent_on_same_day() {
    // Second invocation is a safe no-op when the current file is
    // absent (already rotated). The writer re-creates it lazily on
    // next flush, so we just assert rotate_daily doesn't panic or
    // touch already-dated siblings.
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("query.log");
    let dated = dir.path().join("query.log.2026-04-22");
    std::fs::write(&log_path, "one\n").unwrap();

    rotate_daily(&log_path, ymd(2026, 4, 22));
    assert!(dated.exists());

    // Second call: no query.log to rename, so it's a no-op.
    rotate_daily(&log_path, ymd(2026, 4, 22));
    assert_eq!(std::fs::read_to_string(&dated).unwrap(), "one\n");
}

#[test]
fn daily_rotate_handles_collision_via_backstop_suffix() {
    // If a restart-across-midnight scenario produced a file named
    // `query.log.<yesterday>` already, the second rotate_daily
    // must not clobber it — it hands off to the numeric backstop.
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("query.log");
    let dated = dir.path().join("query.log.2026-04-22");
    std::fs::write(&dated, "earlier\n").unwrap();
    std::fs::write(&log_path, "later\n").unwrap();

    rotate_daily(&log_path, ymd(2026, 4, 22));

    assert!(!log_path.exists());
    assert_eq!(std::fs::read_to_string(&dated).unwrap(), "earlier\n");
    let collision = dir.path().join("query.log.2026-04-22.1");
    assert_eq!(std::fs::read_to_string(&collision).unwrap(), "later\n");
}

#[test]
fn same_day_size_backstop_produces_numeric_suffix() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("query.log");
    std::fs::write(&log_path, "overflow content\n").unwrap();

    rotate_on_size_backstop(&log_path, ymd(2026, 4, 23), 4);

    assert!(!log_path.exists());
    let first = dir.path().join("query.log.2026-04-23.1");
    assert!(first.exists(), "first backstop slot used");
    assert_eq!(
        std::fs::read_to_string(&first).unwrap(),
        "overflow content\n"
    );
}

#[test]
fn same_day_size_backstop_shifts_and_drops_oldest() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("query.log");
    // Pre-fill the four slots with "1", "2", "3", "4" — then a new
    // overflow comes in and must push 1 out, shift the rest up.
    for idx in 1..=4u32 {
        std::fs::write(
            dir.path().join(format!("query.log.2026-04-23.{idx}")),
            format!("{idx}\n"),
        )
        .unwrap();
    }
    std::fs::write(&log_path, "5\n").unwrap();

    rotate_on_size_backstop(&log_path, ymd(2026, 4, 23), 4);

    assert!(!log_path.exists());
    for (idx, expected) in [(1u32, "2"), (2, "3"), (3, "4"), (4, "5")] {
        let p = dir.path().join(format!("query.log.2026-04-23.{idx}"));
        assert_eq!(
            std::fs::read_to_string(&p).unwrap().trim_end(),
            expected,
            "slot {idx} should hold {expected}"
        );
    }
}

#[test]
fn prune_old_files_deletes_beyond_retention() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("query.log");

    let today = time::OffsetDateTime::now_utc().date();
    // Seed 10 dated files spanning 10 consecutive days up to today.
    for age in 0..10u32 {
        let date = today.checked_sub(time::Duration::days(age as i64)).unwrap();
        let name = format!(
            "query.log.{}",
            date.format(time::macros::format_description!("[year]-[month]-[day]"))
                .unwrap()
        );
        std::fs::write(dir.path().join(&name), format!("day{age}\n")).unwrap();
    }
    std::fs::write(&log_path, "current\n").unwrap();

    prune_old_files(&log_path, 3);

    let kept: Vec<String> = std::fs::read_dir(dir.path())
        .unwrap()
        .flatten()
        .filter_map(|e| e.file_name().into_string().ok())
        .collect();

    assert!(
        kept.iter().any(|n| n == "query.log"),
        "current file never pruned"
    );
    // Retention=3 keeps today + 2 days back (< cutoff test uses
    // strict less-than, so cutoff is today-3; anything >= cutoff
    // survives).
    let dated_kept = kept.iter().filter(|n| n.starts_with("query.log.2")).count();
    assert!(
        (3..=4).contains(&dated_kept),
        "expected 3-4 recent dated files to survive; kept: {kept:?}"
    );
}

#[test]
fn prune_old_files_ignores_unrecognised_siblings() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("query.log");
    std::fs::write(&log_path, "current\n").unwrap();
    std::fs::write(dir.path().join("query.log.backup"), "hand\n").unwrap();
    std::fs::write(dir.path().join("query.log.save"), "hand\n").unwrap();
    std::fs::write(dir.path().join("other.txt"), "unrelated\n").unwrap();
    // An ancient dated file THAT IS under the prefix gets pruned —
    // use a distant past so it falls outside any plausible
    // retention window.
    std::fs::write(dir.path().join("query.log.2000-01-01"), "ancient\n").unwrap();

    prune_old_files(&log_path, 7);

    assert!(dir.path().join("query.log.backup").exists());
    assert!(dir.path().join("query.log.save").exists());
    assert!(dir.path().join("other.txt").exists());
    assert!(
        !dir.path().join("query.log.2000-01-01").exists(),
        "old dated file pruned"
    );
}

#[test]
fn read_log_with_filters() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("query.log");

    let entries = vec![
        sample_entry("google.com", false),
        sample_entry("ads.com", true),
        sample_entry("facebook.com", false),
    ];

    let mut content = String::new();
    for e in &entries {
        content.push_str(&serde_json::to_string(e).unwrap());
        content.push('\n');
    }
    std::fs::write(&log_path, content).unwrap();

    // All entries
    let (all, state) = read_log_entries_tail(&log_path, 10, None, false, None, None);
    assert!(matches!(state, crate::ipc::protocol::QueryLogFileState::Ok));
    assert_eq!(all.len(), 3);

    // Blocked only
    let (blocked, _) = read_log_entries_tail(&log_path, 10, None, true, None, None);
    assert_eq!(blocked.len(), 1);
    assert_eq!(blocked[0].domain, "ads.com");

    // Domain filter
    let (google, _) = read_log_entries_tail(&log_path, 10, None, false, Some("google"), None);
    assert_eq!(google.len(), 1);

    // Limit
    let (limited, _) = read_log_entries_tail(&log_path, 2, None, false, None, None);
    assert_eq!(limited.len(), 2);
}

// ── qlog-paging-cursor: resume cursor ────────────────────

/// Domains long enough that the corpus below spans several 8 KB
/// chunks. Deliberately unique per index so a duplicated or skipped
/// row at a page boundary is detectable by set size alone.
fn paging_domain(prefix: &str, i: u32) -> String {
    format!("{prefix}-{i:04}.paging-corpus.example.invalid")
}

fn write_paging_file(path: &Path, prefix: &str, n: u32) {
    let mut content = String::new();
    for i in 0..n {
        let e = sample_entry(&paging_domain(prefix, i), false);
        content.push_str(&serde_json::to_string(&e).unwrap());
        content.push('\n');
    }
    std::fs::write(path, content).unwrap();
}

/// Project entries to a comparable key. `QueryLogEntry` derives
/// neither `Debug` nor `PartialEq` (M-39 — the fields are PII), so a
/// test compares projections rather than the rows themselves.
fn domains_of(entries: &[QueryLogEntry]) -> Vec<String> {
    entries.iter().map(|e| e.domain.clone()).collect()
}

/// Drain every page a cursor walk yields, newest to oldest.
/// Returns `(all domains in order, number of pages, cursor files touched)`.
fn drain_pages(
    path: &Path,
    limit: usize,
    filters: &QueryLogFilters,
    retention_days: u32,
) -> (Vec<String>, usize, Vec<String>) {
    let mut out = Vec::new();
    let mut pages = 0usize;
    let mut files = Vec::new();
    let mut cursor: Option<QueryLogCursor> = None;
    loop {
        let page = read_log_page(path, limit, filters, retention_days, cursor.as_ref());
        assert!(
            !page.cursor_stale,
            "no rotation happens in this test, so a stale cursor means the \
             inode guard is misfiring"
        );
        pages += 1;
        out.extend(domains_of(&page.entries));
        match page.next_cursor {
            Some(c) => {
                files.push(c.file.clone());
                cursor = Some(c);
            }
            None => break,
        }
        assert!(pages < 100, "cursor walk failed to terminate");
    }
    (out, pages, files)
}

/// **The discriminating test.** Every other paging assertion is
/// satisfiable by an off-by-one: "page 2 is non-empty and differs
/// from page 1" passes with a one-row skip *and* with a one-row
/// duplicate. Concatenating every page and demanding it equal the
/// unpaged read element-wise, in order, at the same length, does not.
///
/// The corpus is sized on purpose:
/// * `> 2 × 8 KB` in the primary file alone, so page boundaries land
///   both inside a chunk and across one — a corpus inside a single
///   chunk never exercises the carry reassembly the offsets ride on;
/// * `250` rows against a limit of `40`, i.e. `> 3 × limit`, so
///   there are real middle pages. A corpus of `≤ limit` makes page 2
///   empty and "paging works" vacuously true;
/// * split `100 / 150` across `query.log` and one rotated sibling,
///   so page 3 crosses BOF of the primary. That crossing is the only
///   thing that proves the cursor must be `(file, offset)` — a bare
///   offset cannot say which file offset 0 belongs to.
#[test]
fn paged_reads_concatenate_to_the_unpaged_read() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("query.log");
    write_paging_file(&log_path, "p", 100);
    write_paging_file(&dir.path().join("query.log.2026-04-07"), "s", 150);

    let primary_len = std::fs::metadata(&log_path).unwrap().len();
    assert!(
        primary_len > 2 * 8 * 1024,
        "corpus must span >2 chunks or the boundary cases go unexercised; \
         primary is {primary_len} B"
    );

    let filters = QueryLogFilters::default();
    let unpaged = read_log_page(&log_path, 10_000, &filters, 7, None);
    let expected = domains_of(&unpaged.entries);
    assert_eq!(expected.len(), 250, "seeded corpus must read back whole");
    assert!(
        unpaged.next_cursor.is_none(),
        "a read that exhausted the chain must not offer a resume point"
    );

    let (paged, pages, cursor_files) = drain_pages(&log_path, 40, &filters, 7);

    assert_eq!(
        paged.len(),
        expected.len(),
        "paged walk returned {} rows against {} unpaged — a skip or a \
         duplicate at a page boundary",
        paged.len(),
        expected.len()
    );
    assert_eq!(paged, expected, "paged walk must reproduce order exactly");
    assert_eq!(
        paged.iter().collect::<std::collections::HashSet<_>>().len(),
        250,
        "a duplicated row would keep the length right and the set wrong"
    );
    assert!(
        pages >= 6,
        "40-row pages over 250 rows must page, got {pages}"
    );

    // The cursor crosses into the sibling: a bare offset could not.
    assert!(
        cursor_files.iter().any(|f| f.ends_with("query.log")),
        "early pages resume inside the primary: {cursor_files:?}"
    );
    assert!(
        cursor_files
            .iter()
            .any(|f| f.ends_with("query.log.2026-04-07")),
        "a page must resume inside the rotated sibling: {cursor_files:?}"
    );
}

/// Filters are applied *during* the walk, so a filtered page is not a
/// fixed byte range — the walker keeps going until `limit` MATCHING
/// rows. The identity has to survive that.
///
/// The needle matches 100 of 250 rows against a limit of 40, so it is
/// well below the cap: a needle that saturated the limit would make
/// "same count" indistinguishable from "the filter is inert".
#[test]
fn paging_is_consistent_when_filters_run_during_the_walk() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("query.log");
    write_paging_file(&log_path, "p", 100);
    write_paging_file(&dir.path().join("query.log.2026-04-07"), "s", 150);

    // Every `p-` row and no `s-` row: 100 of 250.
    let filters = QueryLogFilters::new(None, false, Some("p-0"), None);
    let unpaged = read_log_page(&log_path, 10_000, &filters, 7, None);
    let expected = domains_of(&unpaged.entries);
    assert_eq!(
        expected.len(),
        100,
        "needle must select a strict subset well under the page limit, \
         or the comparison below is vacuous"
    );

    let (paged, pages, _) = drain_pages(&log_path, 40, &filters, 7);
    assert_eq!(paged, expected);
    assert!(pages >= 3, "100 matches at 40/page must span pages");

    // Negative control: a needle matching nothing must yield nothing
    // and offer no resume point. Without it, a walker that silently
    // ignored the filter would pass the assertion above by accident
    // on any corpus where the needle happens to match everything.
    let none = QueryLogFilters::new(None, false, Some("no-such-domain"), None);
    let empty = read_log_page(&log_path, 40, &none, 7, None);
    assert!(empty.entries.is_empty());
    assert!(empty.next_cursor.is_none());
}

/// Rotation renames `query.log` and opens a fresh one at the same
/// path. The path stays valid and the offset stops meaning anything,
/// so without the inode guard the operator is served unrelated rows
/// under the label of the page they asked for.
#[test]
fn a_cursor_whose_file_rotated_is_reported_stale_not_silently_honoured() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("query.log");
    write_paging_file(&log_path, "p", 100);

    let filters = QueryLogFilters::default();
    let first = read_log_page(&log_path, 40, &filters, 7, None);
    let cursor = first.next_cursor.expect("100 rows at 40/page must page");

    // Rotate: same path, new inode, different content.
    std::fs::rename(&log_path, dir.path().join("query.log.2026-04-07")).unwrap();
    write_paging_file(&log_path, "fresh", 5);

    let after = read_log_page(&log_path, 40, &filters, 7, Some(&cursor));
    assert!(
        after.cursor_stale,
        "a rotated-out cursor must be reported, not honoured"
    );
    assert_eq!(
        after.entries.first().map(|e| e.domain.clone()),
        Some(paging_domain("fresh", 4)),
        "a stale cursor falls back to the live tail"
    );
}

/// The pre-paging entry points are wrappers now. They must still
/// behave byte-identically, and the cheapest proof is that the
/// wrapper and the paged reader agree on the same corpus.
#[test]
fn the_unpaged_wrapper_still_matches_a_cursorless_page() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("query.log");
    write_paging_file(&log_path, "p", 60);
    write_paging_file(&dir.path().join("query.log.2026-04-07"), "s", 60);

    let (legacy, state) = read_log_entries_with_state(&log_path, 75, None, false, None, 7, None);
    let page = read_log_page(&log_path, 75, &QueryLogFilters::default(), 7, None);
    assert_eq!(domains_of(&legacy), domains_of(&page.entries));
    assert_eq!(state, page.file_state);
    assert_eq!(legacy.len(), 75);
}

// ── qlog-advanced-filter-form: Tier-1 client predicates ──

/// `*` semantics, the ASCII fold, and the two edge cases a
/// head/tail-anchored matcher gets wrong if written carelessly:
/// head and tail must not be allowed to overlap, and `**` must
/// constrain nothing.
#[test]
fn glob_matches_star_patterns_case_insensitively() {
    assert!(Glob::new("*ioel*").matches("marco-IOEL-laptop"));
    assert!(Glob::new("*IOEL*").matches("marco-ioel-laptop"));
    assert!(Glob::new("host-*").matches("HOST-01"));
    assert!(Glob::new("*.example").matches("a.b.EXAMPLE"));
    assert!(Glob::new("*").matches(""));
    assert!(Glob::new("**").matches("anything"));
    assert!(Glob::new("a*b*c").matches("aXXbYYc"));
    assert!(!Glob::new("a*b*c").matches("acb"));

    // Head and tail must not share bytes: `ab` has no room for both
    // an `a` prefix and a `b` suffix plus the `*` between… but `ab`
    // DOES, and `a` does not.
    assert!(Glob::new("a*b").matches("ab"));
    assert!(!Glob::new("a*b").matches("a"));

    // No `*` at all == substring, matching what `c` has always meant.
    assert!(Glob::new("ioel").matches("marco-IOEL-laptop"));
    assert!(!Glob::new("ioel").matches("marco-laptop"));

    // A `*`-bearing pattern is ANCHORED, so it is strictly narrower
    // than the substring form — the distinction the operator is
    // buying by typing the star.
    assert!(!Glob::new("ioel*").matches("marco-ioel"));
    assert!(Glob::new("ioel*").matches("ioel-laptop"));
}

/// Exclude is the include predicate negated, per predicate — the
/// operator's stated case is "everything except the IoT devices".
#[test]
fn exclude_polarity_inverts_only_its_own_predicate() {
    let mut e = sample_entry("one.example", false);
    e.client_name = Some("iot-bulb".into());
    e.client_ip = IpAddr::V4(Ipv4Addr::new(10, 10, 9, 4));

    let inc = QueryLogFilters::default()
        .with_advanced(AdvancedFilter::default().with_name("iot*", Polarity::Include));
    assert!(entry_matches_filters(&e, &inc));

    let exc = QueryLogFilters::default()
        .with_advanced(AdvancedFilter::default().with_name("iot*", Polarity::Exclude));
    assert!(!entry_matches_filters(&e, &exc));

    // AND across predicates: excluded by name, included by subnet →
    // still excluded. An OR would have kept it, which is exactly the
    // semantics that was declined.
    let both = QueryLogFilters::default().with_advanced(
        AdvancedFilter::default()
            .with_name("iot*", Polarity::Exclude)
            .with_subnets(["10.10.9.0/24"], Polarity::Include),
    );
    assert!(!entry_matches_filters(&e, &both));
}

/// A row with no `client_name` cannot match a name pattern, so under
/// EXCLUDE it is KEPT. "not the laptop" has to include every unnamed
/// device or the operator loses exactly the rows they were hunting.
#[test]
fn an_unnamed_client_survives_a_name_exclusion() {
    let mut e = sample_entry("one.example", false);
    e.client_name = None;

    let exc = QueryLogFilters::default()
        .with_advanced(AdvancedFilter::default().with_name("laptop", Polarity::Exclude));
    assert!(entry_matches_filters(&e, &exc));

    let inc = QueryLogFilters::default()
        .with_advanced(AdvancedFilter::default().with_name("laptop", Polarity::Include));
    assert!(!entry_matches_filters(&e, &inc));
}

/// **The reason subnet is a row-local CIDR test and not a resolved
/// set of known client IPs.** An unmapped device — one the operator
/// never put in `[[devices]]` — has no entry to resolve, so a set
/// built from the device table would silently drop its queries. The
/// device is exactly the one an operator paging the log is usually
/// looking for.
///
/// The `client_ip_set` arm below is the Tier-2 seam and is asserted
/// alongside so the two stay visibly distinct.
#[test]
fn a_subnet_predicate_matches_devices_that_are_not_in_any_device_table() {
    let mut unmapped = sample_entry("one.example", false);
    unmapped.client_name = None;
    unmapped.client_ip = IpAddr::V4(Ipv4Addr::new(10, 10, 1, 231));

    let by_subnet = QueryLogFilters::default()
        .with_advanced(AdvancedFilter::default().with_subnets(["10.10.1.0/24"], Polarity::Include));
    assert!(
        entry_matches_filters(&unmapped, &by_subnet),
        "a CIDR test reaches an unmapped device; a resolved IP set would not"
    );

    // The Tier-2 shape, for contrast: a set resolved before the walk
    // contains only what the join produced.
    let known: std::collections::HashSet<IpAddr> = [IpAddr::V4(Ipv4Addr::new(10, 10, 1, 5))]
        .into_iter()
        .collect();
    let by_set = QueryLogFilters::default()
        .with_advanced(AdvancedFilter::default().with_client_ip_set(known, Polarity::Include));
    assert!(!entry_matches_filters(&unmapped, &by_set));

    let outside = QueryLogFilters::default().with_advanced(
        AdvancedFilter::default().with_subnets(["192.168.0.0/16"], Polarity::Include),
    );
    assert!(!entry_matches_filters(&unmapped, &outside));
}

/// An all-blank form must install NOTHING. If it installed a
/// predicate that matched everything the cost would be per row for no
/// benefit; if it installed one that matched nothing the log would go
/// blank for an operator who never opened the form.
#[test]
fn an_empty_advanced_filter_is_not_installed() {
    let e = sample_entry("one.example", false);
    let f = QueryLogFilters::default().with_advanced(AdvancedFilter::default());
    assert!(f.advanced.is_none());
    assert!(entry_matches_filters(&e, &f));
}

/// The advanced predicates AND with the pre-existing controls rather
/// than replacing them — the additive property, at the filter level.
#[test]
fn advanced_predicates_and_with_the_existing_filters() {
    let mut e = sample_entry("ads.example.com", true);
    e.client_name = Some("laptop".into());

    let both = QueryLogFilters::new(None, true, Some("ads"), None)
        .with_advanced(AdvancedFilter::default().with_name("lap*", Polarity::Include));
    assert!(entry_matches_filters(&e, &both));

    // Same advanced predicate, but the pre-existing domain filter now
    // rejects: the row must be dropped.
    let domain_rejects = QueryLogFilters::new(None, true, Some("tracker"), None)
        .with_advanced(AdvancedFilter::default().with_name("lap*", Polarity::Include));
    assert!(!entry_matches_filters(&e, &domain_rejects));
}

/// An unparseable CIDR must not install a predicate that silently
/// matches nothing. The daemon drops it; the TUI refuses it outright
/// (`QLOG_FILTER_BAD_CIDR`), so a hand-built IPC call degrades to an
/// unfiltered view rather than an empty one.
#[test]
fn an_unparseable_cidr_installs_no_subnet_predicate() {
    let e = sample_entry("one.example", false);
    let f = AdvancedFilter::default().with_subnets(["not-a-cidr"], Polarity::Include);
    assert!(f.is_empty(), "a filter of only-bad CIDRs is empty");
    assert!(entry_matches_filters(
        &e,
        &QueryLogFilters::default().with_advanced(f)
    ));
}

// ── Sprint 38 QLP4: tail reader + rotated-file reader ────

fn write_entries(path: &Path, domains: &[(&str, bool)]) {
    let mut content = String::new();
    for (domain, blocked) in domains {
        content.push_str(&serde_json::to_string(&sample_entry(domain, *blocked)).unwrap());
        content.push('\n');
    }
    std::fs::write(path, content).unwrap();
}

#[test]
fn tail_reader_returns_last_n_entries_in_order() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("query.log");
    let events: Vec<(String, bool)> = (0..100u32)
        .map(|i| (format!("host-{i:03}.example"), false))
        .collect();
    let mut content = String::new();
    for (d, b) in &events {
        content.push_str(&serde_json::to_string(&sample_entry(d, *b)).unwrap());
        content.push('\n');
    }
    std::fs::write(&log_path, content).unwrap();

    let (entries, _state) = read_log_entries_tail(&log_path, 10, None, false, None, None);
    assert_eq!(entries.len(), 10);
    // Newest first: last 10 seeded entries are host-099 down to host-090.
    assert_eq!(entries[0].domain, "host-099.example");
    assert_eq!(entries[9].domain, "host-090.example");
}

#[test]
fn tail_reader_handles_partial_json_at_boundary() {
    // Write enough entries that the FIRST entry in the file lands
    // in the chunk before EOF — i.e. forces the reverse walker
    // through a chunk boundary. 8 KB chunk size + ~200 B per
    // entry → 50 entries is enough to span at least two chunks on
    // typical disks.
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("query.log");
    let mut content = String::new();
    for i in 0..200u32 {
        let mut e = sample_entry(&format!("boundary-{i:04}.example"), i % 7 == 0);
        // Pad domain to make each entry heavy enough that the chunk
        // boundary is very likely to split a line.
        e.domain = format!("{}-{}", e.domain, "x".repeat(60));
        content.push_str(&serde_json::to_string(&e).unwrap());
        content.push('\n');
    }
    std::fs::write(&log_path, content).unwrap();

    let (entries, _) = read_log_entries_tail(&log_path, 150, None, false, None, None);
    assert_eq!(entries.len(), 150);
    // The 150 most recent should be boundary-0050..0199 in reverse.
    assert!(entries[0].domain.starts_with("boundary-0199"));
    assert!(entries[149].domain.starts_with("boundary-0050"));
}

#[test]
fn tail_reader_applies_filters_before_limit() {
    // Mix blocked and allowed; the filter should keep scanning
    // backwards until it has `limit` BLOCKED entries, not just
    // `limit` total.
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("query.log");
    let mut events: Vec<(String, bool)> = Vec::new();
    for i in 0..30u32 {
        // Every 5th entry is blocked; we want 5 blocked overall.
        events.push((format!("e-{i:03}.example"), i % 5 == 0));
    }
    let mut content = String::new();
    for (d, b) in &events {
        content.push_str(&serde_json::to_string(&sample_entry(d, *b)).unwrap());
        content.push('\n');
    }
    std::fs::write(&log_path, content).unwrap();

    let (blocked, _) = read_log_entries_tail(&log_path, 5, None, true, None, None);
    assert_eq!(
        blocked.len(),
        5,
        "filter must pull 5 BLOCKED even if that means scanning past earlier allowed entries"
    );
    assert!(blocked.iter().all(|e| e.result == "BLOCKED"));
}

#[test]
fn rotated_reader_fills_across_files() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("query.log");
    write_entries(
        &log_path,
        &[
            ("current-a.example", false),
            ("current-b.example", false),
            ("current-c.example", false),
            ("current-d.example", false),
            ("current-e.example", false),
        ],
    );
    let today = time::OffsetDateTime::now_utc().date();
    let yesterday = today.previous_day().unwrap();
    let yesterday_name = format!(
        "query.log.{}",
        yesterday
            .format(time::macros::format_description!("[year]-[month]-[day]"))
            .unwrap()
    );
    let yesterday_path = dir.path().join(&yesterday_name);
    let mut y_events: Vec<(&str, bool)> = Vec::new();
    let y_domains: Vec<String> = (0..10u32)
        .map(|i| format!("yesterday-{i:02}.example"))
        .collect();
    for d in &y_domains {
        y_events.push((d.as_str(), false));
    }
    write_entries(&yesterday_path, &y_events);

    let (entries, state) = read_log_entries_with_state(&log_path, 12, None, false, None, 7, None);
    assert!(matches!(state, crate::ipc::protocol::QueryLogFileState::Ok));
    assert_eq!(entries.len(), 12);
    // 5 from current (newest-first), then 7 from yesterday.
    assert_eq!(entries[0].domain, "current-e.example");
    assert_eq!(entries[4].domain, "current-a.example");
    assert!(entries[5].domain.starts_with("yesterday-"));
}

#[test]
fn rotated_reader_respects_retention_cap() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("query.log");
    std::fs::write(&log_path, "").unwrap();
    let today = time::OffsetDateTime::now_utc().date();
    // Create 14 dated files. Each with 1 parseable entry.
    for age in 1..=14u32 {
        let date = today.checked_sub(time::Duration::days(age as i64)).unwrap();
        let name = format!(
            "query.log.{}",
            date.format(time::macros::format_description!("[year]-[month]-[day]"))
                .unwrap()
        );
        write_entries(
            &dir.path().join(&name),
            &[(&format!("dated-{age}.example"), false)],
        );
    }

    let (entries, _state) =
        read_log_entries_with_state(&log_path, 1000, None, false, None, 7, None);
    assert_eq!(
        entries.len(),
        7,
        "only retention_days={{7}} files should be scanned regardless of limit"
    );
}

#[test]
fn rotated_reader_returns_missing_when_all_absent() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("query.log");
    let (entries, state) = read_log_entries_with_state(&log_path, 10, None, false, None, 7, None);
    assert!(entries.is_empty());
    assert!(matches!(
        state,
        crate::ipc::protocol::QueryLogFileState::Missing
    ));
}

// ── Sprint 38 QLP6: legacy rotation migration ────────────

/// Set the mtime of a file to a target UTC date (noon UTC). Uses
/// a shell-friendly invocation of `touch -t` so the test works
/// identically on the Debian CT and locally.
fn set_mtime_to_noon(path: &Path, date: time::Date) {
    let stamp = format!(
        "{:04}{:02}{:02}1200.00",
        date.year(),
        u8::from(date.month()),
        date.day()
    );
    let status = std::process::Command::new("touch")
        .arg("-t")
        .arg(&stamp)
        .arg(path)
        .status()
        .expect("touch invocation");
    assert!(status.success(), "touch -t {stamp} {path:?} failed");
}

#[test]
fn migrate_legacy_rotated_files_renames_by_mtime() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("query.log");
    std::fs::write(&log_path, "current\n").unwrap();

    let legacy1 = dir.path().join("query.log.1");
    std::fs::write(&legacy1, "one\n").unwrap();
    set_mtime_to_noon(&legacy1, ymd(2026, 4, 20));

    let legacy2 = dir.path().join("query.log.2");
    std::fs::write(&legacy2, "two\n").unwrap();
    set_mtime_to_noon(&legacy2, ymd(2026, 4, 19));

    migrate_legacy_rotated_files(&log_path);

    assert!(!legacy1.exists(), "query.log.1 migrated");
    assert!(!legacy2.exists(), "query.log.2 migrated");
    assert_eq!(
        std::fs::read_to_string(dir.path().join("query.log.2026-04-20")).unwrap(),
        "one\n"
    );
    assert_eq!(
        std::fs::read_to_string(dir.path().join("query.log.2026-04-19")).unwrap(),
        "two\n"
    );
    // Current file untouched.
    assert_eq!(std::fs::read_to_string(&log_path).unwrap(), "current\n");
}

#[test]
fn migrate_legacy_rotated_files_is_noop_when_none_present() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("query.log");
    std::fs::write(&log_path, "current\n").unwrap();

    migrate_legacy_rotated_files(&log_path);

    // Only the current file should exist — no spurious files,
    // no panic, no deletion.
    let names: Vec<String> = std::fs::read_dir(dir.path())
        .unwrap()
        .flatten()
        .filter_map(|e| e.file_name().into_string().ok())
        .collect();
    assert_eq!(names, vec!["query.log"]);
}

#[test]
fn migrate_legacy_rotated_files_handles_mtime_collision() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("query.log");
    std::fs::write(&log_path, "current\n").unwrap();

    // Two legacy files with mtime on the same UTC day → second
    // must fall through to the .1 backstop suffix.
    let legacy1 = dir.path().join("query.log.1");
    std::fs::write(&legacy1, "first\n").unwrap();
    set_mtime_to_noon(&legacy1, ymd(2026, 4, 20));

    let legacy2 = dir.path().join("query.log.2");
    std::fs::write(&legacy2, "second\n").unwrap();
    set_mtime_to_noon(&legacy2, ymd(2026, 4, 20));

    migrate_legacy_rotated_files(&log_path);

    assert!(!legacy1.exists());
    assert!(!legacy2.exists());
    assert_eq!(
        std::fs::read_to_string(dir.path().join("query.log.2026-04-20")).unwrap(),
        "first\n"
    );
    assert_eq!(
        std::fs::read_to_string(dir.path().join("query.log.2026-04-20.1")).unwrap(),
        "second\n"
    );
}

#[test]
fn migrate_legacy_rotated_files_ignores_unrelated_siblings() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("query.log");
    std::fs::write(&log_path, "current\n").unwrap();
    std::fs::write(dir.path().join("query.log.backup"), "hand\n").unwrap();
    std::fs::write(dir.path().join("other.txt"), "unrelated\n").unwrap();
    std::fs::write(dir.path().join("logs.tar.gz"), "archive\n").unwrap();

    migrate_legacy_rotated_files(&log_path);

    assert!(dir.path().join("query.log.backup").exists());
    assert!(dir.path().join("other.txt").exists());
    assert!(dir.path().join("logs.tar.gz").exists());
}

// ── Sprint 41: client substring + since cutoff ────────────

/// Build an entry with a specific UTC timestamp offset (seconds from
/// "now") for the Sprint 41 cutoff tests. Positive `age_secs` = older.
fn entry_at_age(domain: &str, age_secs: i64, client_name: Option<&str>) -> QueryLogEntry {
    let ts_epoch = time::OffsetDateTime::now_utc().unix_timestamp() - age_secs;
    let ts = time::OffsetDateTime::from_unix_timestamp(ts_epoch).unwrap();
    let fmt = time::macros::format_description!("[year]-[month]-[day]T[hour]:[minute]:[second]Z");
    QueryLogEntry {
        timestamp: ts.format(fmt).unwrap(),
        client_ip: IpAddr::V4(Ipv4Addr::new(10, 10, 1, 84)),
        client_name: client_name.map(String::from),
        domain: domain.into(),
        query_type: "A".into(),
        result: "ALLOWED".into(),
        response_time_us: 100,
        cname_chain_via: None,
        rewrote_from: None,
    }
}

fn write_raw_entries(path: &Path, entries: &[QueryLogEntry]) {
    let mut content = String::new();
    for e in entries {
        content.push_str(&serde_json::to_string(e).unwrap());
        content.push('\n');
    }
    std::fs::write(path, content).unwrap();
}

#[test]
fn client_filter_substring_matches_partial_name() {
    let e_match = sample_entry("one.example", false);
    assert!(entry_matches_filters(
        &e_match,
        &QueryLogFilters::new(Some("lap"), false, None, None)
    ));
    let mut e_no = sample_entry("two.example", false);
    e_no.client_name = Some("phone-bob".into());
    assert!(!entry_matches_filters(
        &e_no,
        &QueryLogFilters::new(Some("lap"), false, None, None)
    ));
}

/// Domains are lowercased at ingestion (CLAUDE.md rule 3), so before this
/// fix a capital letter in the domain filter could never match anything —
/// the filter did not merely inconvenience the operator, it contradicted a
/// house rule and returned zero rows permanently.
#[test]
fn an_uppercase_domain_needle_matches_the_lowercased_stored_domain() {
    let e = sample_entry("ads.example.com", false);
    for needle in ["EXAMPLE", "Example", "eXaMpLe", "example"] {
        assert!(
            entry_matches_filters(&e, &QueryLogFilters::new(None, false, Some(needle), None)),
            "domain needle {needle:?} should match the stored `ads.example.com`"
        );
    }
    assert!(
        !entry_matches_filters(
            &e,
            &QueryLogFilters::new(None, false, Some("TRACKER"), None)
        ),
        "case-insensitivity must not turn into matching everything"
    );
}

/// Client names are operator-typed, so unlike domains they can carry
/// uppercase on BOTH sides. The fold has to reach the haystack too — a fix
/// that only lowered the needle would pass the domain test above and still
/// fail here.
#[test]
fn a_client_name_matches_whatever_case_either_side_carries() {
    let mut e = sample_entry("one.example", false);
    e.client_name = Some("Marco-iPhone".into());
    for needle in ["marco", "MARCO", "iphone", "IPHONE", "Marco-iPhone"] {
        assert!(
            entry_matches_filters(&e, &QueryLogFilters::new(Some(needle), false, None, None)),
            "client needle {needle:?} should match the stored `Marco-iPhone`"
        );
    }
    assert!(!entry_matches_filters(
        &e,
        &QueryLogFilters::new(Some("bob"), false, None, None)
    ));
}

#[test]
fn lowered_needle_actually_lowers() {
    assert_eq!(LoweredNeedle::new("MiXeD").as_str(), "mixed");
}

/// Pins the helper itself, including the two edge cases the windowing
/// implementation gets wrong if written carelessly.
#[test]
fn contains_ascii_ci_matches_regardless_of_haystack_case() {
    assert!(contains_ascii_ci("AdS.ExAmPlE.CoM", "example"));
    assert!(contains_ascii_ci("abc", "abc"));
    assert!(contains_ascii_ci("abc", ""), "empty needle matches");
    assert!(
        !contains_ascii_ci("ab", "abc"),
        "needle longer than haystack"
    );
    assert!(!contains_ascii_ci("abc", "xyz"));
    // A non-ASCII haystack must not panic or mis-slice: `windows` walks
    // BYTES, so this asserts the byte-wise fold stays sound on UTF-8.
    assert!(contains_ascii_ci("caffÈ-LATTE", "latte"));
    assert!(!contains_ascii_ci("caffÈ", "caffe"));
}

#[test]
fn client_filter_substring_matches_partial_ip() {
    let mut e = sample_entry("one.example", false);
    e.client_ip = IpAddr::V4(Ipv4Addr::new(10, 10, 1, 84));
    e.client_name = None;
    assert!(entry_matches_filters(
        &e,
        &QueryLogFilters::new(Some("10.10.1"), false, None, None)
    ));
    assert!(entry_matches_filters(
        &e,
        &QueryLogFilters::new(Some("1.84"), false, None, None)
    ));
    assert!(!entry_matches_filters(
        &e,
        &QueryLogFilters::new(Some("192.168"), false, None, None)
    ));
}

#[test]
fn parse_timestamp_epoch_round_trips() {
    let epoch = parse_timestamp_epoch("2026-04-08T15:32:01Z").unwrap();
    let parsed_back = time::OffsetDateTime::from_unix_timestamp(epoch).unwrap();
    assert_eq!(parsed_back.year(), 2026);
    assert_eq!(parsed_back.hour(), 15);
    assert!(parse_timestamp_epoch("not-a-timestamp").is_none());

    // query-log-02 (rev-2606): the writer formats RFC 3339 with
    // fractional seconds (production lines look like
    // `...:57.745067301Z`). The reader must accept that shape and
    // floor to whole seconds — the pre-fix hand-rolled `[second]Z`
    // description returned None here, the root of the silent
    // `since`-filter no-op.
    let sub = parse_timestamp_epoch("2026-06-10T00:02:57.745067301Z")
        .expect("subsecond production timestamp must parse");
    let whole = parse_timestamp_epoch("2026-06-10T00:02:57Z").unwrap();
    assert_eq!(sub, whole, "subsecond timestamp floors to the same epoch");
}

/// query-log-02 (rev-2606): the `since` cutoff must filter the
/// nanosecond-precision timestamps the writer actually emits. Every
/// other fixture in this module is second-precision — the one shape
/// production never writes — which is exactly what let the bug ship:
/// pre-fix the parser returned None on the fractional run, so the
/// cutoff branch never fired (older lines slipped through) and the
/// reverse scan never early-terminated.
#[test]
fn classify_line_cutoff_filters_subsecond_production_timestamps() {
    let make = |domain: &str, ts: &str| {
        let mut e = sample_entry(domain, false);
        e.timestamp = ts.into();
        serde_json::to_vec(&e).unwrap()
    };
    let cut = |c: i64| QueryLogFilters::new(None, false, None, Some(c));
    let cutoff = parse_timestamp_epoch("2026-06-10T00:02:30.000000000Z").unwrap();
    let old = make("old.example", "2026-06-10T00:02:10.123456789Z");
    let new = make("new.example", "2026-06-10T00:02:57.745067301Z");

    let mut entries = Vec::new();
    assert!(
        matches!(
            classify_line(&old, &mut entries, 10, &cut(cutoff), 0, &mut None),
            LineOutcome::OlderThanCutoff
        ),
        "a subsecond line older than the cutoff must be excluded + signal termination"
    );
    assert!(
        matches!(
            classify_line(&new, &mut entries, 10, &cut(cutoff), 0, &mut None),
            LineOutcome::Pushed
        ),
        "a subsecond line newer than the cutoff must be kept"
    );
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].domain, "new.example");
}

/// rev-2606 style roundup: `dated_siblings_newest_first` must window
/// by distinct DATE, not file count. A busy day with a size-backstop
/// sibling must not consume an extra day-slot and shrink the window.
#[test]
fn dated_siblings_window_by_distinct_date_not_file_count() {
    let dir = tempfile::tempdir().unwrap();
    let primary = dir.path().join("query.log");
    for name in [
        "query.log",
        "query.log.2026-06-10",
        "query.log.2026-06-10.1", // backstop sibling, same day
        "query.log.2026-06-09",
        "query.log.2026-06-08",
    ] {
        std::fs::write(dir.path().join(name), b"x").unwrap();
    }
    let names: Vec<String> = dated_siblings_newest_first(&primary, 2)
        .iter()
        .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
        .collect();
    // 2-day window: both 06-10 siblings + the 06-09 file (2 distinct
    // dates). Pre-fix the file-count truncate stopped after the two
    // 06-10 files — only one day reachable.
    assert!(names.contains(&"query.log.2026-06-10".to_string()));
    assert!(names.contains(&"query.log.2026-06-10.1".to_string()));
    assert!(
        names.contains(&"query.log.2026-06-09".to_string()),
        "second distinct date must stay reachable: {names:?}"
    );
    assert!(
        !names.contains(&"query.log.2026-06-08".to_string()),
        "third date is outside the 2-day window: {names:?}"
    );
}

#[test]
fn since_cutoff_excludes_older_entries() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("query.log");
    write_raw_entries(
        &log_path,
        &[
            entry_at_age("old-a.example", 10_800, None), // 3 h old
            entry_at_age("old-b.example", 7_200, None),  // 2 h old
            entry_at_age("recent.example", 600, None),   // 10 min old
        ],
    );

    // 1 h cutoff → only the 10-min entry is in-window.
    let cutoff = time::OffsetDateTime::now_utc().unix_timestamp() - 3_600;
    let (entries, _) = read_log_entries_tail(&log_path, 10, None, false, None, Some(cutoff));
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].domain, "recent.example");
}

#[test]
fn since_cutoff_none_means_no_cutoff() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("query.log");
    write_raw_entries(
        &log_path,
        &[
            entry_at_age("old.example", 10_800, None),
            entry_at_age("recent.example", 600, None),
        ],
    );
    let (entries, _) = read_log_entries_tail(&log_path, 10, None, false, None, None);
    assert_eq!(entries.len(), 2);
}

#[test]
fn since_cutoff_tolerance_absorbs_single_out_of_order_entry() {
    // The walker must not stop the first time it sees an older-
    // than-cutoff line, because clock skew can produce a single
    // stale line sandwiched between in-window ones. The tolerance
    // window (64 misses) keeps the scan going until we are sure
    // we've crossed the boundary.
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("query.log");
    write_raw_entries(
        &log_path,
        &[
            entry_at_age("recent-a.example", 1_200, None), // 20 min old (in)
            entry_at_age("stale.example", 10_000, None),   // 2h 46m old (out)
            entry_at_age("recent-b.example", 600, None),   // 10 min old (in)
        ],
    );
    let cutoff = time::OffsetDateTime::now_utc().unix_timestamp() - 3_600;
    let (entries, _) = read_log_entries_tail(&log_path, 10, None, false, None, Some(cutoff));
    // Both in-window entries must be returned; the stale one in
    // between must be silently skipped (not push, not terminate).
    let domains: Vec<_> = entries.iter().map(|e| e.domain.as_str()).collect();
    assert!(domains.contains(&"recent-a.example"));
    assert!(domains.contains(&"recent-b.example"));
    assert!(!domains.contains(&"stale.example"));
}

// ── T2.9 / H-20 silent-drop counters ────────────────────

/// Drop site 1: bounded mpsc channel saturated. We freeze the
/// writer task with a leaked `Notify` so it never drains, then
/// flood `LOG_CHANNEL_CAP + 50` entries through `log()` and assert
/// the overflow lands in `channel_full` exactly. The other two
/// counters stay at 0 because we never let the writer touch disk.
#[tokio::test(flavor = "current_thread")]
async fn h20_channel_full_drops_increment_counter() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("query.log");
    let ql = QueryLog::start(log_path, 1_024 * 1_024, 4, 7);

    // Pump the bounded channel to capacity + overflow without ever
    // yielding to the writer task. The writer is a `tokio::spawn`'d
    // task on the same single-threaded runtime, so as long as we
    // never `.await` it cannot drain — every send beyond
    // LOG_CHANNEL_CAP must hit the `channel_full` arm.
    let overflow = 50;
    for i in 0..(LOG_CHANNEL_CAP + overflow) {
        ql.log(sample_entry(&format!("d{i}.example"), false));
    }

    let snap = ql.drop_counters();
    assert_eq!(
        snap.channel_full, overflow as u64,
        "exactly {overflow} entries should have overflowed"
    );
    assert_eq!(snap.flush_open_errors, 0);
    assert_eq!(snap.flush_write_errors, 0);
}

/// Drop site 2: `OpenOptions::open` fails inside the writer task.
/// We point the writer at a path whose parent does not exist —
/// `create(true)` cannot conjure the missing directory, so every
/// flush attempt errors out and bumps `flush_open_errors`. We
/// drive a single flush via `shutdown()` (the channel-closed arm
/// flushes any buffered remainder) and assert the counter saw
/// exactly one flush failure.
#[tokio::test(flavor = "current_thread")]
async fn h20_flush_open_error_drops_increment_counter() {
    let dir = tempfile::tempdir().unwrap();
    // Parent dir intentionally absent — open() returns ENOENT.
    let log_path = dir.path().join("missing-subdir").join("query.log");
    assert!(!log_path.parent().unwrap().exists());

    let ql = QueryLog::start(log_path, 1_024 * 1_024, 4, 7);
    ql.log(sample_entry("only.example", false));

    // Snapshot the Arc before consuming `ql` so we can read after
    // shutdown drains the writer task.
    let snap_before = ql.drops.clone();
    ql.shutdown().await;

    let snap = snap_before.snapshot();
    assert_eq!(snap.channel_full, 0, "channel had room for the entry");
    assert!(
        snap.flush_open_errors >= 1,
        "missing parent dir should have blocked at least one open: {snap:?}"
    );
    assert_eq!(
        snap.flush_write_errors, 0,
        "no file ever opened, so no per-entry writeln! ran"
    );
}

/// Drop site 3: per-entry `writeln!` returns an `io::Error`.
/// `flush_buffer` is exercised directly with a fresh
/// `QueryLogDropCounters` and a path that's an existing directory
/// — `OpenOptions::append(true).open(<dir>)` succeeds on Linux
/// returning a fd whose `write()` syscall fails with EISDIR. That
/// drives the `writeln!` arm specifically, isolating
/// `flush_write_errors` from the open-error path.
#[test]
fn h20_flush_write_error_drops_increment_counter() {
    let dir = tempfile::tempdir().unwrap();
    // Pre-create a directory at the log path. `OpenOptions::append`
    // can open a directory fd on Linux; the subsequent `write()`
    // returns EISDIR — which is exactly the per-entry write-error
    // we want to count.
    let dir_as_log = dir.path().join("query.log");
    std::fs::create_dir(&dir_as_log).unwrap();

    let drops = QueryLogDropCounters::default();
    let mut buffer = vec![
        sample_entry("a.example", false),
        sample_entry("b.example", true),
        sample_entry("c.example", false),
    ];
    flush_buffer(
        &mut buffer,
        &dir_as_log,
        1_024 * 1_024,
        4,
        ymd(2026, 4, 26),
        &drops,
    );

    let snap = drops.snapshot();
    // On platforms where opening a directory for append succeeds
    // (Linux), every entry hits a writeln! error. On platforms
    // where the open itself fails (some BSDs / older glibc) the
    // open-error arm fires instead — both are valid expressions of
    // "the writer cannot land bytes here", so we accept either as
    // long as the union is non-zero and the buffer was drained.
    let total_drops = snap.flush_open_errors + snap.flush_write_errors;
    assert!(
        total_drops >= 1,
        "directory-as-log must surface at least one drop: {snap:?}"
    );
    assert!(
        buffer.is_empty(),
        "flush_buffer must drain or clear the buffer regardless of error path"
    );
    assert_eq!(
        snap.channel_full, 0,
        "drop site 1 untouched by direct flush"
    );
}

// ── file mode on create ────────────────────────────────

/// Scoped `umask(2)` override, restored on drop.
///
/// `umask` is per-PROCESS and `cargo test` runs tests as threads in a
/// single process, so a failing assertion that skipped the restore
/// would leave every later test in this binary at the loosened mask.
/// RAII, not a trailing statement.
struct UmaskGuard(libc::mode_t);

impl UmaskGuard {
    fn set(mask: libc::mode_t) -> Self {
        // SAFETY: `umask(2)` has no preconditions and cannot fail. It
        // returns the previous mask, which `drop` puts back.
        Self(unsafe { libc::umask(mask) })
    }
}

impl Drop for UmaskGuard {
    fn drop(&mut self) {
        // SAFETY: as in `set` — restoring the mask captured there.
        unsafe {
            libc::umask(self.0);
        }
    }
}

/// The query log must be CREATED `0o640`, never `0o666 & !umask`.
///
/// The umask is pinned inside the test on purpose, because the value of
/// this assertion must not depend on which mask the harness happens to
/// hand us:
///
/// * this dev box runs `0o022` (measured), where fixed gives `0o640`
///   and unfixed gives `0o644` — the arm discriminates, by luck;
/// * the systemd unit runs `UMask=0077`, where fixed gives
///   `0o640 & !0o077 == 0o600` and unfixed gives
///   `0o666 & !0o077 == 0o600` — IDENTICAL, and the arm would be
///   measuring nothing while still reading green.
///
/// Pinning removes the ambient dependency. `0o000` specifically, not a
/// conventional `0o022`, which would wave through a `.mode(0o660)`
/// regression (`0o660 & !0o022 == 0o640`).
#[test]
fn flush_buffer_creates_log_with_owner_group_only_mode() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("query.log");

    // `.mode()` applies only when `O_CREAT` actually creates the file.
    // If anything pre-created it we would be measuring its old mode and
    // proving nothing — the assertion must observe the CREATE path.
    assert!(
        !log_path.exists(),
        "test must observe the CREATE path, not a pre-existing file"
    );

    let drops = QueryLogDropCounters::default();
    let mut buffer = vec![sample_entry("mode.example", false)];
    {
        let _umask = UmaskGuard::set(0o000);
        flush_buffer(
            &mut buffer,
            &log_path,
            1_024 * 1_024,
            4,
            ymd(2026, 8, 14),
            &drops,
        );
    }

    let snap = drops.snapshot();
    assert_eq!(snap.flush_open_errors, 0, "log must have opened: {snap:?}");
    assert_eq!(
        snap.flush_write_errors, 0,
        "entry must have landed: {snap:?}"
    );

    let mode = std::fs::metadata(&log_path).unwrap().permissions().mode() & 0o777;
    // The expected value is a LITERAL, deliberately NOT
    // `QUERY_LOG_FILE_MODE`. Comparing the disk against the constant
    // that produced it is circular — swapping the constant to `0o644`
    // moves both sides and the arm stays green. Measured, not
    // theorised: this assertion passed under exactly that mutation
    // until the literal replaced it. The literal puts the policy
    // itself under test, so loosening the bits has to be a deliberate
    // edit here too.
    assert_eq!(
        mode, 0o640,
        "the query log records every domain every device on the network \
         asked for; it must not be created group-writable or \
         world-readable (got {mode:o})"
    );
}

// ── M-37: BufWriter + serde_json::to_writer ────────────

/// `flush_buffer` must produce one JSON object per line on disk —
/// the BufWriter swap in M-37 must not drop newlines, batch
/// entries onto the same line, or skip the final flush. Pin a
/// 3-entry healthy flush and assert the on-disk content
/// round-trips through the parser.
#[test]
fn m37_buf_writer_produces_one_json_per_line_and_flushes() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("query.log");
    let drops = QueryLogDropCounters::default();
    let mut buffer = vec![
        sample_entry("a.example", false),
        sample_entry("b.example", true),
        sample_entry("c.example", false),
    ];

    flush_buffer(
        &mut buffer,
        &log_path,
        1_024 * 1_024,
        4,
        ymd(2026, 4, 27),
        &drops,
    );

    let raw = std::fs::read_to_string(&log_path).unwrap();
    let lines: Vec<&str> = raw.lines().collect();
    assert_eq!(lines.len(), 3, "one line per entry: {raw}");
    for line in &lines {
        // Each line must be a complete, parseable JSON object.
        let _: QueryLogEntry =
            serde_json::from_str(line).unwrap_or_else(|e| panic!("line {line} did not parse: {e}"));
    }
    let domains: Vec<_> = lines
        .iter()
        .filter_map(|l| serde_json::from_str::<QueryLogEntry>(l).ok())
        .map(|e| e.domain)
        .collect();
    assert_eq!(domains, vec!["a.example", "b.example", "c.example"]);

    let snap = drops.snapshot();
    assert_eq!(snap.flush_open_errors, 0);
    assert_eq!(snap.flush_write_errors, 0);
}

// ── M-38: midnight collision exhaustion ─────────────────

/// Pre-fix: after 100 collision-suffix attempts (`query.log.<date>`,
/// `.1`, `.2`, …, `.100`), `rotate_daily` called `remove_file` on
/// the live `query.log` — destroying the day's data. Post-fix the
/// file must stay in place untouched so the writer keeps appending
/// and tomorrow's rotation can retry against a different date.
#[test]
fn m38_rotate_daily_preserves_current_log_on_collision_exhaustion() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("query.log");
    let original = b"todays-bytes-must-survive\n";
    std::fs::write(&log_path, original).unwrap();

    // Plant the primary dated sibling + every collision suffix
    // 1..=MAX_MIDNIGHT_COLLISION_SUFFIX so the rotation has nowhere
    // to land.
    let yesterday = ymd(2026, 4, 26);
    let primary = daily_path(&log_path, yesterday, None);
    std::fs::write(&primary, b"primary\n").unwrap();
    for idx in 1..=MAX_MIDNIGHT_COLLISION_SUFFIX {
        let candidate = daily_path(&log_path, yesterday, Some(idx));
        std::fs::write(&candidate, format!("slot-{idx}\n")).unwrap();
    }

    rotate_daily(&log_path, yesterday);

    assert!(
        log_path.exists(),
        "current query.log must NOT be removed on collision exhaustion"
    );
    assert_eq!(
        std::fs::read(&log_path).unwrap(),
        original,
        "current query.log content must be byte-identical post-rotation attempt"
    );
    // None of the planted slots should have been clobbered or
    // removed either — the rotation is meant to be a strict no-op
    // on exhaustion.
    assert_eq!(std::fs::read(&primary).unwrap(), b"primary\n");
    for idx in 1..=MAX_MIDNIGHT_COLLISION_SUFFIX {
        let candidate = daily_path(&log_path, yesterday, Some(idx));
        assert_eq!(
            std::fs::read(&candidate).unwrap(),
            format!("slot-{idx}\n").as_bytes(),
            "slot {idx} must be untouched"
        );
    }
}

// ── M-39: PII redaction in Display ──────────────────────

/// `QueryLogEntry::Display` must NOT surface client IP, client name,
/// or domain. Anyone logging `entry` via `tracing::error!(%entry, …)`
/// or `eprintln!("{entry}")` should see only the non-PII metadata.
#[test]
fn m39_display_redacts_pii_fields() {
    let entry = sample_entry("secret.internal.corp", true);
    let rendered = format!("{entry}");

    assert!(
        !rendered.contains("secret.internal.corp"),
        "domain must not appear in Display output: {rendered}"
    );
    assert!(
        !rendered.contains("192.168.1.1"),
        "client_ip must not appear in Display output: {rendered}"
    );
    assert!(
        !rendered.contains("laptop"),
        "client_name must not appear in Display output: {rendered}"
    );
    // Non-PII metadata stays visible for correlation.
    assert!(rendered.contains("BLOCKED"));
    assert!(rendered.contains("2026-04-08T15:00:00Z"));
    assert!(rendered.contains("response_time_us=500"));
}

/// Healthy path: no drop site fires. Counter snapshot must stay at
/// all-zeros after a normal flush. Pins that the increments are
/// gated on the failure arms, not unconditional.
#[test]
fn h20_counters_stay_zero_on_healthy_flush() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("query.log");
    let drops = QueryLogDropCounters::default();
    let mut buffer = vec![sample_entry("ok.example", false)];

    flush_buffer(
        &mut buffer,
        &log_path,
        1_024 * 1_024,
        4,
        ymd(2026, 4, 26),
        &drops,
    );

    let snap = drops.snapshot();
    assert_eq!(snap.channel_full, 0);
    assert_eq!(snap.flush_open_errors, 0);
    assert_eq!(snap.flush_write_errors, 0);
    assert!(log_path.exists(), "healthy flush must produce the file");
}
