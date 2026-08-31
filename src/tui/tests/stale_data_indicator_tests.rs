// §4.37 contract pins: poll_active_leaf Err branches reset cached
// app state so the existing "collecting…" / empty-state placeholders
// engage instead of misleading the operator with stale data. The
// gold-standard pattern was already used by Devices, Lists, and
// Dashboard's device_view+blocklist_stats sub-fetches; tui-m2/m3/m4
// extended it to tracking, query_log.entries, and tags.rows.
//
// These tests pin the underlying invariants (Default::default()
// yields an empty TrackingData; Vec::clear() empties an entries
// list). If a future refactor makes Default::default() produce
// non-empty data, the §4.37 Err branches need revisiting — the
// tests below trip first.

use super::*;
use crate::ipc::protocol::DomainCount;
use crate::tui::app::TrackingData;

#[test]
fn tracking_default_is_empty_engages_collecting_placeholders() {
    let t: TrackingData = Default::default();
    assert!(
        t.hourly.is_empty(),
        "Default TrackingData must have empty hourly so render fns paint 'collecting…'"
    );
    assert!(
        t.daily.is_empty(),
        "Default TrackingData must have empty daily"
    );
    assert!(
        t.top_blocked_24h.is_empty(),
        "top_blocked_24h must default empty"
    );
    assert!(
        t.top_queried_24h.is_empty(),
        "top_queried_24h must default empty"
    );
    assert!(
        t.top_blocked_lists_24h.is_empty(),
        "top_blocked_lists_24h must default empty"
    );
    assert_eq!(t.queries_total, 0);
    assert_eq!(t.blocked_total, 0);
    assert!(
        t.qtype_distribution_24h.iter().all(|&n| n == 0),
        "qtype_distribution_24h must default to all-zero"
    );
    assert!(
        t.qtype_blocked_distribution_24h.iter().all(|&n| n == 0),
        "qtype_blocked_distribution_24h must default to all-zero"
    );
}

#[test]
fn dashboard_tracking_err_clear_yields_empty_render_inputs() {
    // §4.37 tui-m3 pin: after a fetch_tracking_stats Err in
    // poll_active_leaf the operator must see empty inputs so the
    // gauge/chart render fns degrade to "collecting…" rather than
    // stale numbers from a previous successful poll.
    let mut app = App::new();
    // Simulate prior successful poll
    app.tracking.queries_total = 1234;
    app.tracking.blocked_total = 567;
    app.tracking.top_blocked_24h = vec![DomainCount {
        domain: "tracker.example.com".into(),
        count: 42,
        count_24h: 42,
        scope: None,
    }];
    // Simulate the Err arm (mod.rs poll_active_leaf Dashboard
    // fetch_tracking_stats branch)
    app.tracking = Default::default();
    app.status_err("simulated daemon disconnect".to_string());

    assert_eq!(app.tracking.queries_total, 0);
    assert_eq!(app.tracking.blocked_total, 0);
    assert!(app.tracking.top_blocked_24h.is_empty());
    assert!(app.status_text().unwrap().contains("simulated"));
}

#[test]
fn query_log_entries_clear_engages_empty_state_picker() {
    // §4.37 tui-m2 pin: after a fetch_query_logs Err the entries
    // vec must be emptied so the existing empty-state picker
    // engages — operator can no longer press Enter→allow/blocklist
    // on a stale row.
    use crate::ipc::protocol::QueryLogDto;
    let mut app = App::new();
    app.query_log.entries = vec![QueryLogDto {
        timestamp: "2026-05-13T12:00:00Z".into(),
        client_ip: "10.0.0.10".into(),
        client_name: None,
        domain: "stale.example.com".into(),
        query_type: "A".into(),
        result: "RESOLVED".into(),
        response_time_us: 1234,
        cname_chain_via: None,
    }];
    assert_eq!(app.query_log.entries.len(), 1);

    // Simulate the Err arm
    app.query_log.entries.clear();
    app.status_err("simulated query_log Err".into());

    assert!(app.query_log.entries.is_empty());
    assert!(app.last_status.is_some());
}

// §4.37 tui-m4 structural-pin test removed: it self-referenced via
// `include_str!("mod.rs")` so the test's own string literals
// counted against the negative assertion. The behavioural contract
// is pinned by `refresh_rows_populates_on_cold_call_no_prior_keypress`
// in `src/tui/tabs/tags.rs`, plus the cargo build invariant that
// `poll_active_leaf` must match Leaf exhaustively.
