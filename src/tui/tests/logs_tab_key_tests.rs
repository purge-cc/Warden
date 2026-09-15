use super::*;
use crate::ipc::protocol::DaemonLogDto;
use crate::tracking::log_ring::LogLevel;
use crate::tui::app::{App, LogsLevelFilter};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

fn key(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

fn ch(c: char) -> KeyEvent {
    KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE)
}

/// An app holding `n` rows, so the scroll clamps have something to
/// clamp against.
fn app_with(n: usize) -> App {
    let mut app = App::new();
    app.active_leaf = Leaf::Logs;
    app.logs.entries = (0..n)
        .map(|i| DaemonLogDto {
            timestamp: "2026-08-25T14:03:05Z".into(),
            level: LogLevel::Info,
            target: "purge_warden::test".into(),
            message: format!("line {i}"),
        })
        .collect();
    app
}

#[test]
fn arrows_select_one_row_and_clamp_at_both_ends() {
    let mut app = app_with(3);
    handle_logs_key(&mut app, key(KeyCode::Up));
    assert_eq!(tabs::logs::selected_index(&app), Some(0));
    for _ in 0..10 {
        handle_logs_key(&mut app, key(KeyCode::Down));
    }
    assert_eq!(
        tabs::logs::selected_index(&app),
        Some(2),
        "must not select past the last row"
    );
}

#[test]
fn identical_messages_remain_distinct_navigation_occurrences() {
    let mut app = app_with(1);
    let duplicate = app.logs.entries[0].clone();
    app.logs.entries = vec![duplicate.clone(), duplicate.clone(), duplicate];

    handle_logs_key(&mut app, key(KeyCode::Down));
    assert_eq!(tabs::logs::selected_index(&app), Some(1));
    handle_logs_key(&mut app, key(KeyCode::Down));
    assert_eq!(tabs::logs::selected_index(&app), Some(2));
}

#[test]
fn home_and_end_jump_to_the_ends() {
    let mut app = app_with(50);
    handle_logs_key(&mut app, key(KeyCode::End));
    assert_eq!(tabs::logs::selected_index(&app), Some(49));
    handle_logs_key(&mut app, key(KeyCode::Home));
    assert_eq!(tabs::logs::selected_index(&app), Some(0));
}

#[test]
fn page_keys_step_by_nav_page_and_clamp() {
    let mut app = app_with(50);
    handle_logs_key(&mut app, key(KeyCode::PageDown));
    assert_eq!(tabs::logs::selected_index(&app), Some(NAV_PAGE));
    handle_logs_key(&mut app, key(KeyCode::PageUp));
    assert_eq!(tabs::logs::selected_index(&app), Some(0));
    handle_logs_key(&mut app, key(KeyCode::PageUp));
    assert_eq!(
        tabs::logs::selected_index(&app),
        Some(0),
        "PgUp at the top is a no-op"
    );
}

#[test]
fn an_empty_page_cannot_scroll_anywhere() {
    // `last_row` on zero entries saturates to 0 rather than
    // underflowing to u16::MAX, which would let End park the viewport
    // 65 534 rows past an empty list.
    let mut app = App::new();
    handle_logs_key(&mut app, key(KeyCode::End));
    assert_eq!(app.logs.scroll_offset, 0);
    handle_logs_key(&mut app, key(KeyCode::PageDown));
    assert_eq!(app.logs.scroll_offset, 0);
}

#[test]
fn f_focuses_chips_and_applying_severity_resets_the_scroll() {
    // The reset is the load-bearing half: the daemon re-filters during
    // its own walk, so the next page is a DIFFERENT set of rows and an
    // offset minted against the old one points into nothing.
    let mut app = app_with(50);
    app.logs.scroll_offset = 30;
    filter_chips::handle_key(&mut app, ch('f'));
    assert_eq!(app.logs.level_filter, LogsLevelFilter::All);
    filter_chips::handle_key(&mut app, key(KeyCode::Right));
    filter_chips::handle_key(&mut app, key(KeyCode::Enter));
    filter_chips::handle_choice_key(&mut app, key(KeyCode::Down));
    filter_chips::handle_choice_key(&mut app, key(KeyCode::Enter));
    assert_eq!(app.logs.level_filter, LogsLevelFilter::Error);
    assert_eq!(app.logs.scroll_offset, 0, "a filter change resets scroll");
}

#[test]
fn search_chip_opens_the_search_seeded_with_the_committed_text() {
    let mut app = app_with(3);
    app.logs.filter_text = Some("refresh".into());
    filter_chips::handle_key(&mut app, ch('f'));
    filter_chips::handle_key(&mut app, key(KeyCode::Enter));
    match &app.input_mode {
        InputMode::FilterLogs(buf) => assert_eq!(buf, "refresh"),
        other => panic!("expected FilterLogs, got {other:?}"),
    }
}

#[test]
fn clear_chip_clears_both_filters_and_the_scroll() {
    let mut app = app_with(50);
    app.logs.level_filter = LogsLevelFilter::Warn;
    app.logs.filter_text = Some("boom".into());
    app.logs.scroll_offset = 12;
    filter_chips::handle_key(&mut app, ch('f'));
    filter_chips::handle_key(&mut app, key(KeyCode::End));
    filter_chips::handle_key(&mut app, key(KeyCode::Enter));
    assert_eq!(app.logs.level_filter, LogsLevelFilter::All);
    assert_eq!(app.logs.filter_text, None);
    assert_eq!(app.logs.scroll_offset, 0);
}

#[tokio::test]
async fn committing_a_search_resets_the_scroll_too() {
    // Same reason as `f`: the committed text goes DOWN with the next
    // request, so the page changes underneath the offset.
    let mut app = app_with(50);
    app.logs.scroll_offset = 25;
    app.input_mode = InputMode::FilterLogs("upstream".into());
    app.active_leaf = Leaf::Logs;
    let dir = tempfile::tempdir().unwrap();
    let poller = IpcPoller::new(&dir.path().join("ghost.sock"));
    let quit = handle_key(&mut app, key(KeyCode::Enter), &poller, dir.path()).await;
    assert!(!quit);
    assert_eq!(app.logs.filter_text.as_deref(), Some("upstream"));
    assert_eq!(app.logs.scroll_offset, 0);
}
