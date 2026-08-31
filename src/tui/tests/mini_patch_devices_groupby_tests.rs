use super::*;
use crate::ipc::protocol::QueryLogDto;
use crate::tui::app::DeviceGroupBy;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use std::path::Path;

fn key_char(ch: char) -> KeyEvent {
    KeyEvent::new(KeyCode::Char(ch), KeyModifiers::NONE)
}

fn dummy_poller() -> IpcPoller {
    IpcPoller::new(Path::new(
        "/tmp/purge-warden-t4-test-nonexistent-socket.sock",
    ))
}

fn sample_entry(domain: &str) -> QueryLogDto {
    QueryLogDto {
        timestamp: "2026-05-01T00:00:00Z".into(),
        client_ip: "192.0.2.10".into(),
        client_name: None,
        domain: domain.into(),
        query_type: "A".into(),
        result: "ALLOWED".into(),
        response_time_us: 0,
        cname_chain_via: None,
    }
}

// mod-04: a finished catalog fetch (delivered as a UiJob off the
// render loop) caches the catalog and rebuilds the open picker,
// replacing the "Loading…" placeholder with real rows.
#[test]
fn apply_catalog_fetched_populates_cache_and_rebuilds_picker() {
    let mut app = App::new();
    app.lists.catalog_picker = Some(tabs::lists::loading_catalog_picker_modal());
    assert!(app.catalog_cache.is_none());
    let catalog = crate::lists::catalog::Catalog::fallback();
    apply_job_result(&mut app, app::UiJob::CatalogFetched(catalog));
    assert!(app.catalog_cache.is_some(), "fetched catalog cached");
    let picker = app
        .lists
        .catalog_picker
        .as_ref()
        .expect("picker still open");
    assert!(
        !picker.rows.is_empty(),
        "loading placeholder replaced with catalog rows"
    );
    assert!(
        picker.status_message.is_none(),
        "the Loading… status is cleared once rows land"
    );
}

// mod-04: if the operator Esc'd the picker while the fetch was in
// flight, still cache the result (next open is instant) but don't
// resurrect the closed picker.
#[test]
fn apply_catalog_fetched_caches_even_when_picker_closed() {
    let mut app = App::new();
    let catalog = crate::lists::catalog::Catalog::fallback();
    apply_job_result(&mut app, app::UiJob::CatalogFetched(catalog));
    assert!(app.catalog_cache.is_some());
    assert!(
        app.lists.catalog_picker.is_none(),
        "a closed picker stays closed"
    );
}

// qlog-06: the tail window slides on each 3s poll (oldest entry
// drops, a newer one appends). A bare TableState index would then
// point at a different row; the captured stable key must re-anchor
// the cursor onto the same entry.
#[test]
fn query_log_selection_follows_entry_across_tail_slide() {
    let mut app = App::new();
    app.query_log.entries = vec![
        sample_entry("a.example"),
        sample_entry("b.example"),
        sample_entry("c.example"),
    ];
    app.query_log.table_state.select(Some(1)); // operator highlights b
    sync_query_log_selection(&mut app);
    assert_eq!(
        app.query_log.selected_key.as_ref().map(|k| k.1.as_str()),
        Some("b.example")
    );

    // A poll slides the window: a.example drops, d.example appends.
    // b.example moves from index 1 to index 0.
    app.query_log.entries = vec![
        sample_entry("b.example"),
        sample_entry("c.example"),
        sample_entry("d.example"),
    ];
    anchor_query_log_cursor(&mut app);
    assert_eq!(
        app.query_log.table_state.selected(),
        Some(0),
        "cursor must follow b.example to its new index, not stay at 1"
    );
    let entry = &app.query_log.entries[app.query_log.table_state.selected().unwrap()];
    assert_eq!(entry.domain, "b.example");
}

#[tokio::test]
async fn capital_g_on_devices_cycles_group_by() {
    let mut app = App::new();
    app.active_leaf = Leaf::Devices;
    let poller = dummy_poller();

    // Default group_by is None → first press lands on Owner.
    assert_eq!(app.devices.group_by, DeviceGroupBy::None);
    handle_key(&mut app, key_char('G'), &poller, Path::new("/dev/null")).await;
    assert_eq!(app.devices.group_by, DeviceGroupBy::Owner);

    // Three more presses walk Department → Profile → None.
    handle_key(&mut app, key_char('G'), &poller, Path::new("/dev/null")).await;
    assert_eq!(app.devices.group_by, DeviceGroupBy::Department);
    handle_key(&mut app, key_char('G'), &poller, Path::new("/dev/null")).await;
    assert_eq!(app.devices.group_by, DeviceGroupBy::Profile);
    handle_key(&mut app, key_char('G'), &poller, Path::new("/dev/null")).await;
    assert_eq!(app.devices.group_by, DeviceGroupBy::None);

    // `G` is per-tab so it must NOT arm the global mnemonic prefix.
    assert!(
        !app.pending_goto,
        "G is the Devices group-by binding, not the global mnemonic prefix"
    );
}

#[tokio::test]
async fn lowercase_g_on_devices_does_not_cycle_group_by() {
    let mut app = App::new();
    app.active_leaf = Leaf::Devices;
    let poller = dummy_poller();

    assert_eq!(app.devices.group_by, DeviceGroupBy::None);
    handle_key(&mut app, key_char('g'), &poller, Path::new("/dev/null")).await;

    assert_eq!(
        app.devices.group_by,
        DeviceGroupBy::None,
        "lowercase g on Devices must NOT cycle group-by — it's the global mnemonic prefix"
    );
    assert!(
        app.pending_goto,
        "lowercase g must arm pending_goto for the next mnemonic letter"
    );
    assert_eq!(
        app.active_leaf,
        Leaf::Devices,
        "the bare g press leaves the active leaf alone — only the second key jumps"
    );
}

#[test]
fn clamp_query_log_cursor_snaps_when_entries_shrink() {
    let mut app = App::new();
    app.query_log.entries = vec![
        sample_entry("a.example"),
        sample_entry("b.example"),
        sample_entry("c.example"),
    ];
    app.query_log.table_state.select(Some(2));

    // A narrowed filter / shorter poll leaves the cursor past the end.
    app.query_log.entries.truncate(1);
    clamp_query_log_cursor(&mut app);
    assert_eq!(
        app.query_log.table_state.selected(),
        Some(0),
        "cursor past the end snaps to the last row"
    );

    // An empty log clears the selection entirely.
    app.query_log.entries.clear();
    clamp_query_log_cursor(&mut app);
    assert_eq!(
        app.query_log.table_state.selected(),
        None,
        "empty log clears the selection"
    );

    // An in-range cursor is left untouched.
    app.query_log.entries = vec![sample_entry("a.example"), sample_entry("b.example")];
    app.query_log.table_state.select(Some(1));
    clamp_query_log_cursor(&mut app);
    assert_eq!(
        app.query_log.table_state.selected(),
        Some(1),
        "in-range cursor is preserved"
    );
}

#[tokio::test]
async fn lowercase_g_on_query_log_does_not_move_cursor() {
    let mut app = App::new();
    app.active_leaf = Leaf::QueryLog;
    app.query_log.entries = vec![
        sample_entry("a.example"),
        sample_entry("b.example"),
        sample_entry("c.example"),
    ];
    // Park the cursor at the last row so the (now-removed)
    // jump-to-top handler would move it to Some(0) if it still fired.
    app.query_log.table_state.select(Some(2));
    let poller = dummy_poller();

    handle_key(&mut app, key_char('g'), &poller, Path::new("/dev/null")).await;

    assert_eq!(
        app.query_log.table_state.selected(),
        Some(2),
        "the dead jump-to-top handler must stay dead — cursor unchanged"
    );
    assert!(
        app.pending_goto,
        "g now belongs to the global mnemonic prefix and must arm pending_goto"
    );
    assert_eq!(
        app.active_leaf,
        Leaf::QueryLog,
        "bare g does not change the active leaf; the second key would"
    );
}
