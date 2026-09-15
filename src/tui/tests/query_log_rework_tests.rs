use super::*;

use std::path::Path;
use std::sync::Arc;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::backend::TestBackend;
use ratatui::buffer::Buffer;
use ratatui::Terminal;

use crate::ipc::protocol::{QueryLogDto, QueryLogFileState};
use crate::tracking::query_log::QueryLogCursor;
use crate::tui::ipc_poller::QueryLogPollResult;
use crate::tui::tabs::query_log::QLOG_HEADERS;

fn key(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

fn poller() -> IpcPoller {
    IpcPoller::new(Path::new("/tmp/purge-warden-query-log-rework-test.sock"))
}

fn row(n: usize) -> QueryLogDto {
    QueryLogDto {
        timestamp: format!("2026-09-08T10:{n:02}:00Z"),
        client_ip: format!("192.0.2.{}", n + 1),
        client_name: Some(format!("client-{n}")),
        domain: format!("q{n:02}.example.test"),
        query_type: "AAAA".into(),
        result: if n.is_multiple_of(2) {
            "ALLOWED"
        } else {
            "BLOCKED"
        }
        .into(),
        response_time_us: 1_250,
        cname_chain_via: None,
    }
}

fn dump(buffer: &Buffer) -> String {
    (buffer.area.y..buffer.area.bottom())
        .map(|y| {
            (buffer.area.x..buffer.area.right())
                .map(|x| buffer[(x, y)].symbol())
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn query_app(entries: usize) -> App {
    let mut app = App::new();
    app.active_leaf = Leaf::QueryLog;
    app.query_log.entries = (0..entries).map(row).collect();
    app.query_log.has_loaded = true;
    app
}

fn historical_page() -> QueryLogPollResult {
    QueryLogPollResult {
        entries: vec![row(90), row(91)],
        logging_enabled: true,
        file_state: QueryLogFileState::Ok,
        next_cursor: None,
        cursor_stale: false,
    }
}

#[test]
fn full_ui_render_at_80x24_keeps_headers_and_accessible_content() {
    let mut app = query_app(10);
    let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
    terminal
        .draw(|frame| crate::tui::ui::render(frame, &mut app))
        .unwrap();
    let rendered = dump(terminal.backend().buffer());

    for header in QLOG_HEADERS {
        assert!(
            rendered.contains(header),
            "missing {header} at 80x24:\n{rendered}"
        );
    }
    assert!(rendered.contains("QUERY FILTERS"));
    assert!(rendered.contains("Reset All"));
    assert!(app.query_log.visible_rows > 0);
    assert!(rendered.contains("q00.example.test"));
}

#[tokio::test]
async fn query_popups_consume_global_keys_and_esc_closes_them() {
    let mut app = query_app(1);
    let p = poller();

    filter_chips::activate(&mut app, 1);
    assert!(app.query_log.client_picker.is_some());
    handle_key(
        &mut app,
        key(KeyCode::Char('q')),
        &p,
        Path::new("/dev/null"),
    )
    .await;
    assert_eq!(app.active_leaf, Leaf::QueryLog);
    assert_eq!(app.query_log.client_picker.as_ref().unwrap().search, "q");
    handle_key(&mut app, key(KeyCode::Esc), &p, Path::new("/dev/null")).await;
    assert!(app.query_log.client_picker.is_none());

    app.query_log.table_state.select(Some(0));
    handle_key(
        &mut app,
        key(KeyCode::Char('i')),
        &p,
        Path::new("/dev/null"),
    )
    .await;
    assert!(app.query_log.detail.is_some());
    handle_key(
        &mut app,
        key(KeyCode::Char('q')),
        &p,
        Path::new("/dev/null"),
    )
    .await;
    assert!(
        app.query_log.detail.is_some(),
        "q leaked through detail overlay"
    );
    handle_key(&mut app, key(KeyCode::Esc), &p, Path::new("/dev/null")).await;
    assert!(app.query_log.detail.is_none());

    filter_chips::activate(&mut app, 2);
    assert!(app.query_log.period_menu);
    handle_key(
        &mut app,
        key(KeyCode::Char('q')),
        &p,
        Path::new("/dev/null"),
    )
    .await;
    assert!(app.query_log.period_menu, "q leaked through period menu");
    handle_key(&mut app, key(KeyCode::Esc), &p, Path::new("/dev/null")).await;
    assert!(!app.query_log.period_menu);
}

#[tokio::test]
async fn opening_client_picker_while_paused_requests_only_its_metadata() {
    let mut app = query_app(1);
    app.paused = true;
    app.query_log.page_index = 1;
    app.query_log.entries = vec![row(42)];
    app.read_jobs = Some(crate::tui::jobs::ReadScheduler::new(Arc::new(poller())));

    filter_chips::activate(&mut app, 1);

    let jobs = app.read_jobs.as_ref().unwrap();
    for &resource in crate::tui::jobs::ReadResource::ALL {
        assert_eq!(
            jobs.is_loading(resource),
            matches!(
                resource,
                crate::tui::jobs::ReadResource::Devices
                    | crate::tui::jobs::ReadResource::Status
                    | crate::tui::jobs::ReadResource::OperatorCatalog
            ),
            "unexpected pending resource: {resource:?}"
        );
    }
    assert!(!app.force_poll);
    assert_eq!(app.query_log.page_index, 1);
    assert_eq!(app.query_log.entries[0].domain, "q42.example.test");
}

#[tokio::test]
async fn per_filter_clear_never_resets_an_unrelated_filter() {
    let mut app = query_app(1);
    let p = poller();
    app.query_log.filter_domain = Some("ads.example".into());
    app.query_log.client_ips = vec!["192.0.2.7".into()];
    app.query_log.blocked_only = true;
    app.query_log.since = crate::tui::app::SincePreset::Last24Hours;
    app.query_log.advanced.name = Some("tablet*".into());

    app.filter_focus = Some((Leaf::QueryLog, 0));
    handle_key(&mut app, key(KeyCode::Delete), &p, Path::new("/dev/null")).await;
    assert!(app.query_log.filter_domain.is_none());
    assert_eq!(app.query_log.client_ips, ["192.0.2.7"]);
    assert!(app.query_log.blocked_only);

    app.filter_focus = Some((Leaf::QueryLog, 1));
    handle_key(&mut app, key(KeyCode::Delete), &p, Path::new("/dev/null")).await;
    assert!(app.query_log.client_ips.is_empty());
    assert!(app.query_log.blocked_only);
    assert_eq!(
        app.query_log.since,
        crate::tui::app::SincePreset::Last24Hours
    );

    app.filter_focus = Some((Leaf::QueryLog, 3));
    handle_key(&mut app, key(KeyCode::Delete), &p, Path::new("/dev/null")).await;
    assert!(!app.query_log.blocked_only);
    assert_eq!(
        app.query_log.since,
        crate::tui::app::SincePreset::Last24Hours
    );

    app.filter_focus = Some((Leaf::QueryLog, 2));
    handle_key(&mut app, key(KeyCode::Delete), &p, Path::new("/dev/null")).await;
    assert_eq!(app.query_log.since, crate::tui::app::SincePreset::Off);
    assert!(app.query_log.advanced.name.is_some());

    app.filter_focus = Some((Leaf::QueryLog, 4));
    handle_key(&mut app, key(KeyCode::Delete), &p, Path::new("/dev/null")).await;
    assert!(app.query_log.advanced.is_empty());
}

#[tokio::test]
async fn viewport_paging_uses_visible_rows_and_historical_refresh_stays_historical() {
    let mut app = query_app(20);
    let p = poller();
    app.query_log.visible_rows = 3;
    app.query_log.table_state.select(Some(10));

    handle_key(&mut app, key(KeyCode::PageUp), &p, Path::new("/dev/null")).await;
    assert_eq!(app.query_log.table_state.selected(), Some(7));
    handle_key(&mut app, key(KeyCode::PageDown), &p, Path::new("/dev/null")).await;
    assert_eq!(app.query_log.table_state.selected(), Some(10));

    app.query_log.table_state.select(Some(19));
    app.query_log.next_cursor = Some(QueryLogCursor {
        file: "/var/lib/purge-warden/query.log".into(),
        offset: 4_096,
        inode: 42,
    });
    // Test fixtures normally change selection through the key dispatcher,
    // which maintains this stable key. Keep the direct fixture mutation on
    // the same invariant so the re-anchor at the next key sees row 19.
    sync_query_log_selection(&mut app);
    handle_key(&mut app, key(KeyCode::PageDown), &p, Path::new("/dev/null")).await;
    assert_eq!(app.query_log.page_index, 1);
    assert!(app.query_log.entries.is_empty());

    apply_query_log_page(&mut app, historical_page());
    assert_eq!(app.query_log.page_index, 1);
    assert_eq!(app.query_log.entries[0].domain, "q90.example.test");

    // A second page-1 poll must refresh that historical page in place, not
    // silently reset to the live tail and discard the operator's context.
    apply_query_log_page(&mut app, historical_page());
    assert_eq!(app.query_log.page_index, 1);
    assert_eq!(app.query_log.entries[1].domain, "q91.example.test");
}

#[test]
fn paste_is_inert_behind_query_read_only_popups() {
    let mut app = query_app(1);
    app.input_mode = InputMode::FilterDomain("underneath".into());
    app.query_log.detail = Some(crate::tui::query_log_detail::QueryLogDetail::open(row(0)));
    handle_paste(&mut app, "must-not-leak".into());
    assert!(matches!(
        app.input_mode,
        InputMode::FilterDomain(ref value) if value == "underneath"
    ));

    app.query_log.detail = None;
    app.query_log.period_menu = true;
    handle_paste(&mut app, "must-not-leak".into());
    assert!(matches!(
        app.input_mode,
        InputMode::FilterDomain(ref value) if value == "underneath"
    ));
}

#[tokio::test]
async fn picker_tab_focus_and_search_draft_survive_full_ui_resize() {
    let mut app = query_app(1);
    let p = poller();
    app.query_log.client_ips = vec!["192.0.2.1".into()];
    filter_chips::activate(&mut app, 1);
    handle_key(&mut app, key(KeyCode::BackTab), &p, Path::new("/dev/null")).await;
    handle_paste(&mut app, "192.0.2.".into());
    for (width, height) in [(140, 52), (80, 24), (160, 24), (140, 52)] {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal
            .draw(|frame| crate::tui::ui::render(frame, &mut app))
            .unwrap();
        let rendered = dump(terminal.backend().buffer());
        assert!(
            rendered.contains("192.0.2.")
                && rendered.contains("Apply")
                && crate::tui::tabs::query_log::footer_hint(&app).starts_with("Search"),
            "{width}x{height}: {rendered}"
        );
        assert_eq!(app.active_leaf, Leaf::QueryLog);
        let picker = app.query_log.client_picker.as_ref().unwrap();
        assert_eq!(picker.search, "192.0.2.");
        assert!(picker.selected.contains("192.0.2.1"));
    }
    handle_key(&mut app, key(KeyCode::Tab), &p, Path::new("/dev/null")).await;
    assert!(crate::tui::tabs::query_log::footer_hint(&app).starts_with("List"));
    handle_key(&mut app, key(KeyCode::Esc), &p, Path::new("/dev/null")).await;
    assert!(app.query_log.client_picker.is_none());
    assert_eq!(app.query_log.client_ips, ["192.0.2.1"]);
}

#[tokio::test]
async fn query_log_domain_window_commits_only_on_apply_and_keeps_other_filters() {
    let mut app = query_app(3);
    let p = poller();
    app.paused = true;
    app.query_log.filter_domain = Some("before.example".into());
    app.query_log.client_ips = vec!["192.0.2.1".into()];
    app.query_log.blocked_only = true;
    app.query_log.page_index = 1;
    filter_chips::activate(&mut app, 0);
    handle_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL),
        &p,
        Path::new("/dev/null"),
    )
    .await;
    handle_paste(&mut app, "EXAMPLE.test".to_owned());
    assert_eq!(
        app.query_log.filter_domain.as_deref(),
        Some("before.example")
    );
    handle_key(&mut app, key(KeyCode::Tab), &p, Path::new("/dev/null")).await;
    handle_key(&mut app, key(KeyCode::Tab), &p, Path::new("/dev/null")).await;
    handle_key(&mut app, key(KeyCode::Enter), &p, Path::new("/dev/null")).await;
    assert_eq!(app.query_log.filter_domain.as_deref(), Some("EXAMPLE.test"));
    assert_eq!(app.query_log.client_ips, ["192.0.2.1"]);
    assert!(app.query_log.blocked_only);
    assert_eq!(app.query_log.page_index, 0);
    assert!(
        app.force_poll,
        "explicit apply while paused must fetch the new predicate"
    );
    assert!(matches!(app.input_mode, InputMode::Normal));
    filter_chips::activate(&mut app, 0);
    handle_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL),
        &p,
        Path::new("/dev/null"),
    )
    .await;
    handle_key(&mut app, key(KeyCode::Enter), &p, Path::new("/dev/null")).await;
    assert!(app.query_log.filter_domain.is_none());
    assert!(app.query_log.blocked_only);
}

#[tokio::test]
async fn query_log_period_window_applies_three_hours_and_discard_preserves_it() {
    let mut app = query_app(1);
    let p = poller();
    filter_chips::activate(&mut app, 2);
    handle_key(&mut app, key(KeyCode::Down), &p, Path::new("/dev/null")).await;
    handle_key(&mut app, key(KeyCode::Down), &p, Path::new("/dev/null")).await;
    assert_eq!(app.query_log.since, app::SincePreset::Off);
    handle_key(&mut app, key(KeyCode::Enter), &p, Path::new("/dev/null")).await;
    assert_eq!(app.query_log.since.as_secs(), Some(10_800));
    filter_chips::activate(&mut app, 2);
    handle_key(&mut app, key(KeyCode::Down), &p, Path::new("/dev/null")).await;
    handle_key(&mut app, key(KeyCode::Tab), &p, Path::new("/dev/null")).await;
    handle_key(&mut app, key(KeyCode::Enter), &p, Path::new("/dev/null")).await;
    assert_eq!(app.query_log.since.as_secs(), Some(10_800));
    assert!(!app.query_log.period_menu);
    let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
    terminal.draw(|frame| ui::render(frame, &mut app)).unwrap();
    let rendered = dump(terminal.backend().buffer());
    for control in [
        "Domain:",
        "Period: 3h",
        "Blocked:",
        "Advanced:",
        "Reset All",
    ] {
        assert!(
            rendered.contains(control),
            "filter control {control} is inaccessible:\n{rendered}"
        );
    }
}
