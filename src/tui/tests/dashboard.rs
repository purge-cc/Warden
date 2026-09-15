use super::*;
use crate::resource_budget::ResourceBudgetSnapshot;
use crate::tui::app::DaemonStatus;
use ratatui::{backend::TestBackend, style::Modifier, Terminal};

fn dump_buffer(buf: &Buffer) -> String {
    (buf.area.y..buf.area.bottom())
        .map(|y| {
            (buf.area.x..buf.area.right())
                .map(|x| buf[(x, y)].symbol())
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn draw(app: &mut App, width: u16, height: u16) -> String {
    let mut term = Terminal::new(TestBackend::new(width, height)).unwrap();
    term.draw(|frame| render(frame, frame.area(), app)).unwrap();
    dump_buffer(term.backend().buffer())
}

fn healthy_app() -> App {
    let mut app = App::new();
    app.connected = true;
    app.last_status_read = Some(Instant::now());
    app.last_tracking_read = Some(Instant::now());
    app.last_lists_read = Some(Instant::now());
    app.daemon_status = Some(DaemonStatus {
        domain_count: 500_000,
        ..Default::default()
    });
    app
}

#[test]
fn every_card_is_reachable_by_scrolling_in_the_full_shell_after_resize() {
    let mut app = healthy_app();
    for (width, height) in [
        (80, 24),
        (80, 50),
        (100, 24),
        (160, 24),
        (120, 40),
        (140, 52),
        (200, 60),
        (240, 80),
        (119, 31),
        (120, 32),
        (121, 33),
        (80, 24),
    ] {
        let mut term = Terminal::new(TestBackend::new(width, height)).unwrap();
        let mut seen = [false; 8];
        handle_key(&mut app, KeyCode::Home.into());
        for _ in 0..110 {
            term.draw(|f| crate::tui::ui::render(f, &mut app)).unwrap();
            let rendered = dump_buffer(term.backend().buffer());
            for (index, title) in TITLES.iter().enumerate() {
                seen[index] |= rendered.contains(title);
            }
            assert!(!rendered.contains("Enter details"));
            handle_key(&mut app, KeyCode::Down.into());
        }
        assert!(seen.iter().all(|seen| *seen), "{width}x{height}: {seen:?}");
    }
}

#[test]
fn switching_between_stacked_and_wide_keeps_the_visible_row() {
    let mut app = healthy_app();
    draw(&mut app, 120, 10);
    app.dashboard.scroll = 35;
    assert!(draw(&mut app, 120, 10).contains("DAILY QUERIES"));
    assert!(draw(&mut app, 80, 19).contains("TOP LISTS"));
    assert!(draw(&mut app, 120, 10).contains("DAILY QUERIES"));
}

#[test]
fn page_and_end_keys_scroll_without_selecting_or_opening_cards() {
    let mut app = healthy_app();
    draw(&mut app, 80, 19);
    handle_key(&mut app, KeyCode::PageDown.into());
    assert_eq!(app.dashboard.scroll, 17);
    handle_key(&mut app, KeyCode::End.into());
    assert!(draw(&mut app, 80, 19).contains("DAILY BLOCKED"));
    let scroll = app.dashboard.scroll;
    assert!(!handle_key(&mut app, KeyCode::Enter.into()));
    assert!(!handle_key(&mut app, KeyCode::Char('d').into()));
    assert_eq!(app.dashboard.scroll, scroll);
    handle_key(&mut app, KeyCode::Home.into());
    assert!(draw(&mut app, 80, 19).contains("SYSTEM"));
    assert_eq!(app.dashboard.scroll, 0);
}

#[test]
fn wide_dashboard_keeps_three_logical_rows_when_short() {
    let (rects, height) = panel_rects(120, 19);
    assert_eq!(height, 35);
    assert_eq!(rects[0].y, rects[2].y);
    assert_eq!(rects[3].y, rects[4].y);
    assert_eq!(rects[5].y, rects[7].y);
    assert!(rects[3].width > rects[4].width);
    let mut app = healthy_app();
    draw(&mut app, 120, 19);
    handle_key(&mut app, KeyCode::End.into());
    assert!(draw(&mut app, 120, 19).contains("DAILY BLOCKED"));
}

#[test]
fn zero_and_offset_rectangles_do_not_write_outside_their_viewport() {
    let mut app = App::new();
    for (width, height) in [(0, 0), (1, 1), (3, 2), (80, 24)] {
        let mut term = Terminal::new(TestBackend::new(100, 40)).unwrap();
        term.draw(|f| render(f, Rect::new(7, 5, width, height), &mut app))
            .unwrap();
        assert_eq!(term.backend().buffer()[(0, 0)].symbol(), " ");
    }
}

#[test]
fn query_types_keep_five_two_row_entries_in_dashboard_canvas() {
    let (rects, height) = panel_rects(80, 24);
    assert_eq!(rects[4].height, 14);
    assert_eq!(rects[5].y + 1, rects[4].bottom());
    assert!(height >= rects[7].bottom());
}

#[test]
fn top_list_subtitle_uses_the_full_copy_then_a_truthful_compact_copy() {
    assert_eq!(
        subtitle_text(top_lists_subtitle(Rect::new(0, 0, 44, 6))),
        "Attributed Last 24H Hits (Not Exclusive)"
    );
    assert_eq!(
        subtitle_text(top_lists_subtitle(Rect::new(0, 0, 38, 6))),
        "24H Attributed Hits (Nonexclusive)"
    );
}

#[test]
fn overview_has_no_hour_or_day_inspection_and_fits_the_wide_shell() {
    let mut app = healthy_app();
    app.dashboard.tracking_at = Some(100 * DAY + 12 * HOUR);
    assert!(!handle_key(&mut app, KeyCode::Left.into()));
    assert!(!handle_key(
        &mut app,
        KeyEvent::new(KeyCode::Left, crossterm::event::KeyModifiers::SHIFT)
    ));
    let rendered = draw(&mut app, 164, 46);
    for title in TITLES {
        assert!(rendered.contains(title), "missing {title}");
    }
    assert_eq!(app.dashboard.scroll, 0);
    assert!(app.dashboard.content_height <= app.dashboard.viewport_height);
    let (cards, height) = panel_rects(164, app.dashboard.viewport_height);
    for card in cards {
        assert!(card.bottom() <= height);
        assert!(card.height >= 10);
    }
}

#[test]
fn all_card_titles_use_filled_role_bands_and_page_gutters() {
    let mut app = healthy_app();
    let mut term = Terminal::new(TestBackend::new(160, 47)).unwrap();
    term.draw(|f| render(f, f.area(), &mut app)).unwrap();
    let buffer = term.backend().buffer();
    let rendered = dump_buffer(buffer);
    for text in [
        "SYSTEM",
        "Service Status & DNS Upstreams",
        "RESOURCES",
        "CPU & Memory Usage",
        "BLOCK RATE",
        "Hourly Estimates",
        "DNS TRAFFIC",
        "24H Queries · Total 0 · Blocked 0",
        "Total",
        "Blocked",
        "QUERY TYPES",
        "TOP LISTS",
        "Attributed Last 24H Hits (Not Exclusive)",
        "DAILY QUERIES",
        "0 Total Rolling Queries (Daily History)",
        "DAILY BLOCKED",
        "0 Total Rolling Blocked (Daily History)",
    ] {
        assert!(
            rendered.contains(text),
            "missing dashboard band text: {text}\n{rendered}"
        );
    }
    let (rects, _) = panel_rects(160, 47);
    for (index, rect) in rects.into_iter().enumerate() {
        assert_eq!(buffer[(rect.x, rect.y)].bg, T.bg_main);
        assert_eq!(buffer[(rect.x + 1, rect.y + 1)].fg, T.text_inverse);
        assert!(buffer[(rect.x + 1, rect.y + 1)]
            .modifier
            .contains(Modifier::BOLD));
        let role = match index {
            0..=2 => crate::tui::theme::CardRole::Summary,
            3 | 4 => crate::tui::theme::CardRole::Analytics,
            _ => crate::tui::theme::CardRole::History,
        };
        assert_eq!(buffer[(rect.x + 1, rect.y + 1)].bg, T.card_title_bg(role));
        assert_eq!(
            buffer[(rect.x + 1, rect.y + 2)].bg,
            T.card_subtitle_bg(role)
        );
    }
}

fn resources(app: &App) -> Buffer {
    let area = Rect::new(0, 0, 46, 13);
    let mut buffer = Buffer::empty(area);
    render_resources(&mut buffer, area, app);
    buffer
}

#[test]
fn ram_values_distinguish_missing_zero_and_list_allocations_from_resident_memory() {
    let mut app = healthy_app();
    let status = app.daemon_status.as_mut().unwrap();
    status.lists_memory_bytes = Some(600 * 1_048_576);
    status.resource_budget = Some(ResourceBudgetSnapshot {
        rss_mb: 25,
        swap_mb: Some(0),
        mem_total_mb: Some(8192),
        mem_available_mb: Some(6144),
        sampled_at: Some(now_secs()),
        ..Default::default()
    });
    let buffer = resources(&app);
    let rendered = dump_buffer(&buffer);
    for value in [
        "System RAM:",
        "2.0 GiB / 8.0 GiB",
        "Warden RAM:",
        "25 MiB",
        "List RAM:",
        "600.0 MiB",
        "Warden swap:",
        "0 MiB",
    ] {
        assert!(rendered.contains(value), "{rendered}");
    }
    assert!(!rendered.contains("part of Warden"));
    assert_eq!(buffer[(2, 4)].fg, T.text_muted);
    assert!(
        (15..30).any(|x| buffer[(x, 4)].fg == T.text_primary),
        "RAM value must retain a distinct primary style"
    );
    for removed in ["Available:", "Peak RSS", "TUI session", "Sample:"] {
        assert!(!rendered.contains(removed));
    }
    app.daemon_status.as_mut().unwrap().resource_budget = None;
    let rendered = dump_buffer(&resources(&app));
    assert!(rendered.contains("600.0 MiB"));
    assert!(rendered.contains("Resource sample unavailable"));
    assert!(rendered
        .lines()
        .any(|line| line.contains("Warden RAM:") && line.contains("—")));
}

#[test]
fn resource_warning_colors_use_the_budget_and_stale_is_exception_only() {
    assert_eq!(rss_color(81, 100), T.warning);
    assert_eq!(rss_color(101, 100), T.error);
    assert_eq!(rss_color(u64::MAX, 0), T.text_primary);
    assert_eq!(rss_color(u64::MAX, u64::MAX), T.warning);
    let mut app = healthy_app();
    app.daemon_status.as_mut().unwrap().resource_budget = Some(ResourceBudgetSnapshot {
        sampled_at: Some(now_secs() - 120),
        ..Default::default()
    });
    assert!(dump_buffer(&resources(&app)).contains("Resource data stale"));
    app.daemon_status
        .as_mut()
        .unwrap()
        .resource_budget
        .as_mut()
        .unwrap()
        .sampled_at = Some(now_secs());
    assert!(!dump_buffer(&resources(&app)).contains("Resource data stale"));
}

fn inject_read_failure(app: &mut App, resource: crate::tui::jobs::ReadRequest) {
    use crate::tui::jobs::{ReadReason, ReadScheduler};
    let poller = std::sync::Arc::new(crate::tui::ipc_poller::IpcPoller::new(
        std::path::Path::new("/tmp/warden-unused-socket"),
    ));
    let mut jobs = ReadScheduler::new(poller);
    jobs.request(resource, ReadReason::Explicit);
    let completion = jobs
        .take_ready()
        .pop()
        .unwrap()
        .complete_for_test(Err("test IPC timeout".into()));
    jobs.finish(completion);
    app.read_jobs = Some(jobs);
}

#[test]
fn normal_header_is_quiet_and_faults_remain_visible_after_scrolling() {
    let mut app = healthy_app();
    assert!(health_notice(&app).is_none());
    assert_eq!(connection_label(&app), "");
    let mut term = Terminal::new(TestBackend::new(80, 24)).unwrap();
    term.draw(|f| crate::tui::ui::render(f, &mut app)).unwrap();
    let normal = dump_buffer(term.backend().buffer());
    assert!(!normal.contains("Connected"));
    assert!(!normal.contains("List corpus loaded"));
    assert!(
        normal.lines().any(|line| line.contains("SYSTEM")),
        "{normal}"
    );
    app.daemon_status.as_mut().unwrap().lists_cycle = Some(crate::lists::status::CycleMark {
        outcome: Some(crate::lists::status::CycleOutcome::Refused),
        seq: 1,
        source_coverage_incomplete: false,
        generation_degraded: false,
        served_state: Default::default(),
    });
    handle_key(&mut app, KeyCode::End.into());
    term.draw(|f| crate::tui::ui::render(f, &mut app)).unwrap();
    let rendered = dump_buffer(term.backend().buffer());
    assert!(rendered
        .lines()
        .next()
        .unwrap()
        .contains("List update refused"));
    assert!(rendered.contains("DAILY BLOCKED"));
}

#[test]
fn failed_read_is_never_rendered_as_zero_and_shows_the_actual_error_without_popup() {
    let mut app = healthy_app();
    inject_read_failure(&mut app, crate::tui::jobs::ReadRequest::Tracking);
    draw(&mut app, 80, 19);
    handle_key(&mut app, KeyCode::End.into());
    let rendered = draw(&mut app, 80, 19);
    assert!(health_notice(&app)
        .unwrap()
        .0
        .contains("Tracking read failed"));
    assert!(rendered.contains("Tracking read failed"));
    assert!(rendered.contains("test IPC timeout"));
    assert!(!rendered.contains("No traffic"));
}

#[test]
fn connecting_disconnected_paused_and_stale_reads_are_distinct() {
    let mut app = App::new();
    assert_eq!(connection_label(&app), "Connecting");
    inject_read_failure(&mut app, crate::tui::jobs::ReadRequest::Status);
    assert_eq!(connection_label(&app), "Disconnected");
    app = healthy_app();
    app.last_tracking_read = Some(Instant::now() - std::time::Duration::from_secs(45));
    let notice = health_notice(&app).unwrap().0;
    assert!(notice.contains("Tracking data stale"));
    assert!(!notice.contains("Status data stale"));
    app.paused = true;
    assert_eq!(connection_label(&app), "Display paused");
    assert!(!health_notice(&app).unwrap().0.contains("stale"));
}

#[test]
fn tracking_disabled_and_empty_attribution_are_distinct() {
    let mut app = healthy_app();
    app.daemon_status.as_mut().unwrap().tracking_enabled = Some(false);
    let rendered = draw(&mut app, 160, 39);
    assert!(rendered.contains("Tracking disabled"));
    app.daemon_status.as_mut().unwrap().tracking_enabled = Some(true);
    let rendered = draw(&mut app, 160, 39);
    assert!(rendered.contains("attribution unavailable"));
    app.daemon_status.as_mut().unwrap().top_lists_24h_supported = true;
    assert!(draw(&mut app, 160, 39).contains("No recorded list blocks"));
}

#[test]
fn list_warnings_preserve_rejection_coverage_served_state_and_missing_corpus() {
    use crate::lists::status::{CycleMark, CycleOutcome, ServedState};
    let mut app = healthy_app();
    app.daemon_status.as_mut().unwrap().lists_cycle = Some(CycleMark {
        outcome: Some(CycleOutcome::ConfigRejected),
        source_coverage_incomplete: true,
        served_state: ServedState::Complete,
        seq: 1,
        generation_degraded: false,
    });
    let (message, color) = protection::issue(&app).unwrap();
    assert!(message.starts_with("List configuration rejected"));
    assert!(message.contains("serving previous corpus"));
    assert_eq!(color, T.error);
    let status = app.daemon_status.as_mut().unwrap();
    status.domain_count = 0;
    status.lists_cycle.as_mut().unwrap().served_state = ServedState::Partial;
    let message = protection::issue(&app).unwrap().0;
    assert!(message.contains("No list corpus"));
    assert!(message.contains("partial corpus"));
    assert!(!message.contains("sources"));
}

#[test]
fn empty_list_states_and_read_failures_remain_explicit() {
    use crate::lists::status::{CycleMark, CycleOutcome, ServedState};
    let mut app = healthy_app();
    app.daemon_status.as_mut().unwrap().domain_count = 0;
    for (state, message) in [
        (ServedState::IntentionalEmpty, "Lists intentionally empty"),
        (ServedState::Cleared, "Lists cleared; no list filtering"),
        (ServedState::Uninitialized, "List protection unavailable"),
    ] {
        app.daemon_status.as_mut().unwrap().lists_cycle = Some(CycleMark {
            seq: 1,
            outcome: Some(CycleOutcome::ConfigRejected),
            source_coverage_incomplete: true,
            generation_degraded: true,
            served_state: state,
        });
        assert!(protection::issue(&app).unwrap().0.contains(message));
    }
    inject_read_failure(&mut app, crate::tui::jobs::ReadRequest::Tracking);
    assert!(health_notice(&app)
        .unwrap()
        .0
        .starts_with("Tracking read failed"));
    let mut term = Terminal::new(TestBackend::new(80, 24)).unwrap();
    term.draw(|f| crate::tui::ui::render(f, &mut app)).unwrap();
    assert!(dump_buffer(term.backend().buffer())
        .lines()
        .next()
        .unwrap()
        .contains("Tracking read failed"));
}

#[test]
fn failed_list_refresh_cannot_look_healthy_from_a_recent_attempt_timestamp() {
    let mut app = healthy_app();
    app.lists
        .entries
        .push(crate::lists::status::BlocklistStatusDto {
            last_outcome: "failed: HTTP 502".into(),
            fetched_at: Some("2026-09-09T12:00:00Z".into()),
            last_refresh_at: None,
            ..Default::default()
        });
    assert!(protection::issue(&app)
        .unwrap()
        .0
        .contains("List refresh failures"));
}

#[test]
fn hourly_totals_share_timestamp_window_and_high_block_rate_is_not_an_alarm() {
    let mut app = healthy_app();
    app.dashboard.tracking_at = Some(100 * HOUR + 30);
    app.tracking.hourly = [
        (76 * HOUR, 999, 999),
        (77 * HOUR + 12, 2, 2),
        (100 * HOUR + 10, 8, 8),
        (101 * HOUR, 999, 999),
    ]
    .map(
        |(timestamp, queries, blocked)| crate::ipc::protocol::TimeBucketDto {
            timestamp,
            queries,
            blocked,
            cache_hits: 0,
        },
    )
    .into();
    assert_eq!(hour_totals(&app), (10, 10));
    assert!(protection::issue(&app).is_none());
}

#[test]
fn no_test_module_remains_inline_in_dashboard_rs() {
    crate::tui::cfg_scan::assert_no_inline_test_module(
        "dashboard.rs",
        include_str!("../tabs/dashboard.rs"),
    );
}
