use super::*;

use crate::ipc::protocol::{QueryLogDto, QueryLogFileState};
use crate::tui::app::{ClientFilterMode, SincePreset};
use crate::tui::ipc_poller::QueryLogPollResult;
use crate::tui::tabs::query_log::{entry_key, QLOG_HEADERS};
use ratatui::backend::TestBackend;
use ratatui::buffer::Buffer;
use ratatui::Terminal;

fn entry() -> QueryLogDto {
    QueryLogDto {
        timestamp: "2026-09-08T10:00:00Z".into(),
        client_ip: "192.0.2.1".into(),
        client_name: Some("room alpha".into()),
        domain: "example.test".into(),
        query_type: "A".into(),
        result: "ALLOWED".into(),
        response_time_us: 12,
        cname_chain_via: None,
    }
}

fn query_app() -> App {
    let mut app = App::new();
    app.active_leaf = Leaf::QueryLog;
    app.query_log.has_loaded = true;
    app
}

fn draw(app: &mut App, width: u16, height: u16) -> (String, Buffer) {
    let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
    terminal.draw(|frame| ui::render(frame, app)).unwrap();
    let buffer = terminal.backend().buffer().clone();
    let mut rendered = String::new();
    for y in buffer.area.y..buffer.area.bottom() {
        for x in buffer.area.x..buffer.area.right() {
            rendered.push_str(buffer[(x, y)].symbol());
        }
        rendered.push('\n');
    }
    (rendered, buffer)
}

fn page(entries: Vec<QueryLogDto>) -> QueryLogPollResult {
    QueryLogPollResult {
        entries,
        logging_enabled: true,
        file_state: QueryLogFileState::Ok,
        next_cursor: None,
        cursor_stale: false,
    }
}

#[test]
fn full_render_keeps_all_filter_controls_with_long_applied_values() {
    let mut app = query_app();
    app.query_log.filter_domain = Some("very-long-domain.".repeat(30));
    app.query_log.client_ips = vec!["192.0.2.1".into(), "192.0.2.2".into()];
    app.query_log.blocked_only = true;
    app.query_log.advanced.name = Some("room*".into());
    app.query_log.advanced.ip = Some("192.0.*".into());
    app.query_log.advanced.subnet = Some("192.0.2.0/24".into());
    app.query_log.entries = (0..10)
        .map(|index| QueryLogDto {
            domain: format!("q{index:02}.example.test"),
            ..entry()
        })
        .collect();

    for (width, height) in [(140, 52), (80, 24), (100, 24), (160, 24), (140, 52)] {
        for preset in SincePreset::ALL {
            app.query_log.since = preset;
            let (rendered, _) = draw(&mut app, width, height);
            for control in [
                "Domain:",
                "Client:",
                "Period:",
                "Blocked:",
                "Advanced:",
                "Reset All",
            ] {
                assert!(
                    rendered.contains(control),
                    "missing {control} in the filter card at {width}×{height}:\n{rendered}"
                );
            }
            if width >= 100 {
                for value in ["Blocked Only", "3 Rules"] {
                    assert!(rendered.contains(value), "missing {value}:\n{rendered}");
                }
            }
            assert!(rendered.contains(preset.compact_label()));
            assert!(!rendered.contains("C text"));
            if width >= 100 {
                assert!(rendered.contains('…'), "long domain must be abbreviated");
            }
            for header in QLOG_HEADERS {
                assert!(rendered.contains(header), "missing {header}:\n{rendered}");
            }
            assert!(app.query_log.visible_rows > 0);
            assert!(
                rendered.contains("q00.example.test"),
                "no row content:\n{rendered}"
            );
        }
    }

    app.query_log.filter_client = None;
    app.query_log.client_mode = ClientFilterMode::Selected;
    app.query_log.client_ips = vec!["192.0.2.1".into(), "192.0.2.2".into(), "192.0.2.3".into()];
    let (rendered, _) = draw(&mut app, 80, 24);
    assert!(
        rendered.contains("Client: 3 Clients"),
        "hidden exact selection:\n{rendered}"
    );
}

#[tokio::test]
async fn domain_window_preserves_long_draft_focus_and_other_filters_through_resize() {
    let p = IpcPoller::new(Path::new("/tmp/warden-query-log-compliance-unused.sock"));
    let mut app = query_app();
    app.query_log.entries = vec![entry()];
    app.query_log.client_ips = vec!["192.0.2.1".into(), "192.0.2.2".into()];
    app.query_log.filter_domain = Some(format!("{}DOMAIN_END", "cafe\u{301}.界.".repeat(50)));
    let applied_domain = app.query_log.filter_domain.clone();
    filter_chips::activate(&mut app, 0);
    for (width, height) in [(140, 52), (80, 24), (160, 24), (140, 52)] {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal.draw(|frame| ui::render(frame, &mut app)).unwrap();
        let rendered = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|cell| cell.symbol())
            .collect::<String>();
        assert!(rendered.contains("DOMAIN_END"), "editing tail missing");
        assert!(rendered.contains("Case-insensitive"));
        assert!(rendered.contains("Discard"));
        assert!(rendered.contains("Apply"));
        let caret = terminal.get_cursor_position().unwrap();
        assert!(caret.x < width && caret.y < height);
        assert_eq!(app.query_log.filter_domain, applied_domain);
        assert_eq!(app.query_log.client_ips.len(), 2);
    }
    handle_key(&mut app, KeyCode::Tab.into(), &p, Path::new("/dev/null")).await;
    let draft_before = app.input_mode.clone();
    handle_paste(&mut app, "must not paste into a button".to_owned());
    assert!(
        matches!((&draft_before, &app.input_mode), (InputMode::FilterDomain(a), InputMode::FilterDomain(b)) if a == b)
    );
    handle_key(&mut app, KeyCode::Enter.into(), &p, Path::new("/dev/null")).await;
    assert!(matches!(app.input_mode, InputMode::Normal));
    assert_eq!(app.query_log.filter_domain, applied_domain);
    handle_query_log_key(&mut app, KeyCode::Char('C').into());
    assert!(
        matches!(app.input_mode, InputMode::Normal),
        "C must not open a second client mode"
    );
    filter_chips::activate(&mut app, 1);
    assert!(app.query_log.client_picker.is_some());
}

#[test]
fn full_render_prioritizes_availability_and_wraps_complete_empty_messages() {
    for (enabled, state, title, ending) in [
        (
            false,
            QueryLogFileState::Ok,
            "Query log disabled.",
            "run `warden reload`.",
        ),
        (
            false,
            QueryLogFileState::Unreadable,
            "Query log disabled.",
            "run `warden reload`.",
        ),
        (
            true,
            QueryLogFileState::Missing,
            "Query log file not yet created.",
            "`journalctl -u purge-warden`.",
        ),
        (
            true,
            QueryLogFileState::Unreadable,
            "Query log unreadable.",
            "`/var/lib/purge-warden/query.log`.",
        ),
    ] {
        for filtered in [false, true] {
            let mut app = query_app();
            app.query_log.logging_enabled = enabled;
            app.query_log.file_state = state.clone();
            app.query_log.blocked_only = filtered;
            for (width, height) in [(80, 24), (100, 24), (140, 52)] {
                let (rendered, _) = draw(&mut app, width, height);
                let prose = rendered.split_whitespace().collect::<Vec<_>>().join(" ");
                assert!(rendered.contains(title), "wrong availability:\n{rendered}");
                // Match words separately because borders separate wrapped rows.
                for word in ending.split_whitespace() {
                    assert!(prose.contains(word), "clipped {word}:\n{rendered}");
                }
                let (_, explanation) = tabs::query_log::pick_empty_state_message(enabled, &state);
                for word in explanation.split_whitespace() {
                    assert!(
                        prose.contains(word),
                        "clipped explanation word {word}:\n{rendered}"
                    );
                }
                assert!(
                    !rendered.contains("No requests match"),
                    "availability hidden:\n{rendered}"
                );
            }
        }
    }

    let mut app = query_app();
    let (rendered, _) = draw(&mut app, 80, 24);
    assert!(rendered.contains("No queries recorded yet."));
    app.query_log.blocked_only = true;
    let (rendered, _) = draw(&mut app, 80, 24);
    assert!(rendered.contains("No requests match the filters."));
    assert!(!rendered.contains("No queries recorded yet."));
    app.query_log.has_loaded = false;
    let (rendered, _) = draw(&mut app, 80, 24);
    assert!(rendered.contains("Loading Query Log"));
    app.query_log.read_failed = true;
    let (rendered, _) = draw(&mut app, 80, 24);
    assert!(rendered.contains("Query log read failed."));
}

#[test]
fn complete_record_identity_preserves_same_tuple_different_type_and_result() {
    let first = entry();
    let second = QueryLogDto {
        query_type: "AAAA".into(),
        ..first.clone()
    };
    let selected = QueryLogDto {
        result: "BLOCKED".into(),
        ..second.clone()
    };
    let mut app = query_app();
    apply_query_log_page(
        &mut app,
        page(vec![first.clone(), second.clone(), selected.clone()]),
    );
    // Only the type distinguishes these first two records.
    app.query_log.table_state.select(Some(1));
    sync_query_log_selection(&mut app);
    draw(&mut app, 80, 24);
    assert_eq!(
        app.query_log.table_state.selected(),
        Some(1),
        "query type was omitted from identity"
    );
    handle_query_log_key(&mut app, KeyCode::Char('i').into());
    let (rendered, _) = draw(&mut app, 80, 24);
    assert!(rendered
        .lines()
        .any(|line| line.contains("Type") && line.contains("AAAA")));
    assert!(rendered
        .lines()
        .any(|line| line.contains("Result") && line.contains("ALLOWED")));
    handle_query_log_detail_key(&mut app, KeyCode::Esc.into());
    // Only the result distinguishes the second and third records.
    app.query_log.table_state.select(Some(2));
    sync_query_log_selection(&mut app);

    for (width, height) in [(140, 52), (80, 24), (160, 24), (140, 52)] {
        draw(&mut app, width, height);
        assert_eq!(
            app.query_log.table_state.selected(),
            Some(2),
            "render selected the first tuple collision"
        );
    }
    // A real page completion shifts the selected record across both collisions.
    apply_query_log_page(&mut app, page(vec![second, selected.clone(), first]));
    draw(&mut app, 80, 24);
    assert_eq!(app.query_log.table_state.selected(), Some(1));
    handle_query_log_key(&mut app, KeyCode::Char('i').into());
    let captured = &app.query_log.detail.as_ref().unwrap().entry;
    assert_eq!(entry_key(captured), entry_key(&selected));
    let (rendered, _) = draw(&mut app, 80, 24);
    assert!(rendered
        .lines()
        .any(|line| line.contains("Type") && line.contains("AAAA")));
    assert!(rendered
        .lines()
        .any(|line| line.contains("Result") && line.contains("BLOCKED")));
}

#[test]
fn record_identity_also_distinguishes_name_response_time_and_cname() {
    let original = entry();
    for different in [
        QueryLogDto {
            client_name: None,
            ..original.clone()
        },
        QueryLogDto {
            response_time_us: 13,
            ..original.clone()
        },
        QueryLogDto {
            cname_chain_via: Some("blocked.example".into()),
            ..original.clone()
        },
    ] {
        assert_ne!(entry_key(&original), entry_key(&different));
    }
    let key = entry_key(&original);
    assert_eq!(key.0, original.timestamp);
    assert_eq!(key.1, original.domain);
    assert_eq!(key.2, original.client_ip);
}
