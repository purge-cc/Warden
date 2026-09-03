use super::*;
use crate::cli::commands::rules::Action;
use crate::ipc::protocol::QueryLogDto;
use crate::tui::tabs::query_log::{
    QUERY_NOT_ACTIONABLE_LOCAL, QUERY_NOT_ACTIONABLE_REFUSED, QUERY_NOT_ACTIONABLE_UNKNOWN,
};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use std::path::Path;

fn key(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

fn dummy_poller() -> IpcPoller {
    IpcPoller::new(Path::new(
        "/tmp/purge-warden-s47-t2-test-nonexistent-socket.sock",
    ))
}

fn entry_with_result(result: &str, domain: &str) -> QueryLogDto {
    QueryLogDto {
        timestamp: "2026-05-02T10:00:00Z".into(),
        client_ip: "10.10.1.50".into(),
        client_name: Some("iphone".into()),
        domain: domain.into(),
        query_type: "A".into(),
        result: result.into(),
        response_time_us: 1234,
        cname_chain_via: None,
    }
}

/// Park the app on Query Log with one row pre-selected so the
/// keypress-under-test does not trigger a tab-change poll (which
/// would touch `last_error` via the dummy poller's ENOENT failure).
fn app_on_query_log_with(entry: QueryLogDto) -> App {
    let mut app = App::new();
    app.active_leaf = Leaf::QueryLog;
    app.query_log.entries = vec![entry];
    app.query_log.table_state.select(Some(0));
    app
}

#[tokio::test]
async fn enter_on_blocked_row_opens_allow_modal() {
    let mut app = app_on_query_log_with(entry_with_result("BLOCKED", "ads.example"));
    let poller = dummy_poller();
    handle_key(
        &mut app,
        key(KeyCode::Enter),
        &poller,
        Path::new("/dev/null"),
    )
    .await;
    let modal = app
        .query_log_rule_modal
        .as_ref()
        .expect("Enter on BLOCKED must open the rule picker");
    assert_eq!(
        modal.action,
        Action::Allow,
        "BLOCKED row → operator wants to allowlist"
    );
    assert_eq!(modal.domain, "ads.example");
}

#[tokio::test]
async fn enter_on_allowed_row_opens_deny_modal() {
    let mut app = app_on_query_log_with(entry_with_result("ALLOWED", "tracker.example"));
    let poller = dummy_poller();
    handle_key(
        &mut app,
        key(KeyCode::Enter),
        &poller,
        Path::new("/dev/null"),
    )
    .await;
    let modal = app
        .query_log_rule_modal
        .as_ref()
        .expect("Enter on ALLOWED must open the rule picker");
    assert_eq!(
        modal.action,
        Action::Deny,
        "ALLOWED row → operator wants to blocklist"
    );
    assert_eq!(modal.domain, "tracker.example");
}

#[tokio::test]
async fn enter_on_local_row_surfaces_last_error_no_modal() {
    let mut app = app_on_query_log_with(entry_with_result("LOCAL", "router.lan"));
    let poller = dummy_poller();
    handle_key(
        &mut app,
        key(KeyCode::Enter),
        &poller,
        Path::new("/dev/null"),
    )
    .await;
    assert!(
        app.query_log_rule_modal.is_none(),
        "LOCAL is not actionable — modal must stay closed"
    );
    assert_eq!(
        app.status_text(),
        Some(QUERY_NOT_ACTIONABLE_LOCAL),
        "LOCAL row must surface the Local-DNS-tab redirect message in the footer"
    );
}

#[tokio::test]
async fn enter_on_refused_row_surfaces_specific_message() {
    let mut app = app_on_query_log_with(entry_with_result("REFUSED", "denied.example"));
    let poller = dummy_poller();
    handle_key(
        &mut app,
        key(KeyCode::Enter),
        &poller,
        Path::new("/dev/null"),
    )
    .await;
    assert!(app.query_log_rule_modal.is_none());
    assert_eq!(
        app.status_text(),
        Some(QUERY_NOT_ACTIONABLE_REFUSED),
        "REFUSED row must surface the upstream-rejected message"
    );
}

#[tokio::test]
async fn enter_with_no_selection_is_safe_noop() {
    let mut app = App::new();
    app.active_leaf = Leaf::QueryLog;
    // Empty entries + no selection — the early-returns in
    // `build_query_log_rule_modal` and the `_UNKNOWN` fallback
    // in `footer_message_for_neutral_row` must keep this safe.
    let poller = dummy_poller();
    handle_key(
        &mut app,
        key(KeyCode::Enter),
        &poller,
        Path::new("/dev/null"),
    )
    .await;
    assert!(
        app.query_log_rule_modal.is_none(),
        "no selection → no modal, no panic"
    );
    assert_eq!(
        app.status_text(),
        Some(QUERY_NOT_ACTIONABLE_UNKNOWN),
        "empty selection falls through to the generic _UNKNOWN footer message"
    );
}

#[tokio::test]
async fn a_key_no_longer_opens_modal_regression() {
    let mut app = app_on_query_log_with(entry_with_result("BLOCKED", "ads.example"));
    let poller = dummy_poller();
    handle_key(
        &mut app,
        key(KeyCode::Char('a')),
        &poller,
        Path::new("/dev/null"),
    )
    .await;
    assert!(
        app.query_log_rule_modal.is_none(),
        "`a` is not bound on this tab — it must not open the modal"
    );
}

#[tokio::test]
async fn d_key_no_longer_opens_modal_regression() {
    let mut app = app_on_query_log_with(entry_with_result("ALLOWED", "tracker.example"));
    let poller = dummy_poller();
    handle_key(
        &mut app,
        key(KeyCode::Char('d')),
        &poller,
        Path::new("/dev/null"),
    )
    .await;
    assert!(
        app.query_log_rule_modal.is_none(),
        "`d` is not bound on this tab — it must not open the modal"
    );
}
