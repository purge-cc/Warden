use super::*;
use crate::tui::app::{App, Leaf};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use std::path::{Path, PathBuf};

fn key(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

fn poller(dir: &Path) -> IpcPoller {
    IpcPoller::new(&dir.join("ghost.sock"))
}

/// Fifteen groups and fifteen owner labels — deliberately more than
/// [`NAV_PAGE`], so a page key that silently behaved like `↓` would
/// fail rather than pass by coincidence.
fn mk_master(dir: &tempfile::TempDir) -> PathBuf {
    let master = dir.path().join("config.toml");
    let mut t = String::from(
        "schema_version = 3\n\n\
             [upstream]\nservers = [\"192.0.2.1:53\"]\n\n\
             [server]\ndefault_profile = \"home\"\n\n\
             [profiles.home]\ndisplay_name = \"Home\"\n\n",
    );
    for i in 0..15 {
        t.push_str(&format!(
            "[[groups]]\nid = \"g{i:02}\"\ndisplay_name = \"G{i:02}\"\nprofile = \"home\"\n\n"
        ));
        t.push_str(&format!(
            "[[labels]]\nid = \"o{i:02}\"\nkind = \"owner\"\ndisplay_name = \"O{i:02}\"\n\n"
        ));
    }
    std::fs::write(&master, t).unwrap();
    master
}

fn app_on(master: &Path, leaf: Leaf) -> App {
    let mut app = App::new();
    app.loaded_config = load_v1_config(master);
    app.active_leaf = leaf;
    assert!(
        app.loaded_config.is_some(),
        "fixture must parse — every assertion below is vacuous otherwise"
    );
    app
}

async fn press(app: &mut App, code: KeyCode, master: &Path) {
    let dir = master.parent().unwrap();
    handle_key(app, key(code), &poller(dir), master).await;
}

// ── N4: clamp, not wrap ─────────────────────────────────────────

/// The Groups cursor used to be `(cur + 1) % ids.len()`. Walking off
/// the last row teleported the operator to the first, which reads as
/// a lost cursor rather than as navigation.
#[tokio::test]
async fn n4_groups_down_on_the_last_row_stays_put() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    let mut app = app_on(&master, Leaf::Groups);

    press(&mut app, KeyCode::End, &master).await;
    assert_eq!(app.groups.selected_id.as_deref(), Some("g14"), "End = last");

    press(&mut app, KeyCode::Down, &master).await;
    assert_eq!(
        app.groups.selected_id.as_deref(),
        Some("g14"),
        "Down on the last row is a no-op, NOT a wrap to the first"
    );
}

#[tokio::test]
async fn n4_groups_up_on_the_first_row_stays_put() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    let mut app = app_on(&master, Leaf::Groups);

    press(&mut app, KeyCode::Home, &master).await;
    assert_eq!(app.groups.selected_id.as_deref(), Some("g00"));
    press(&mut app, KeyCode::Up, &master).await;
    assert_eq!(
        app.groups.selected_id.as_deref(),
        Some("g00"),
        "Up on the first row is a no-op, NOT a wrap to the last"
    );
}

/// `PgDn` must travel a page, not a row — and then clamp. A page key
/// that quietly aliased `↓` would pass a "did it move" assertion, so
/// the landing index is asserted exactly.
#[tokio::test]
async fn n4_groups_page_keys_travel_a_page_and_then_clamp() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    let mut app = app_on(&master, Leaf::Groups);

    press(&mut app, KeyCode::Home, &master).await;
    press(&mut app, KeyCode::PageDown, &master).await;
    assert_eq!(
        app.groups.selected_id.as_deref(),
        Some("g10"),
        "PgDn moves NAV_PAGE rows, not one"
    );
    press(&mut app, KeyCode::PageDown, &master).await;
    assert_eq!(
        app.groups.selected_id.as_deref(),
        Some("g14"),
        "the second PgDn clamps at the last row"
    );
    press(&mut app, KeyCode::PageUp, &master).await;
    assert_eq!(app.groups.selected_id.as_deref(), Some("g04"));
    press(&mut app, KeyCode::PageUp, &master).await;
    assert_eq!(
        app.groups.selected_id.as_deref(),
        Some("g00"),
        "PgUp clamps at the first row"
    );
}

/// Same three properties on the Labels ENTRIES table. The kind menu
/// is a separate axis and is checked below.
#[tokio::test]
async fn n4_labels_entries_clamp_and_page() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    let mut app = app_on(&master, Leaf::Labels);
    press(&mut app, KeyCode::Right, &master).await; // focus the entries

    press(&mut app, KeyCode::End, &master).await;
    assert_eq!(app.labels.selected_id.as_deref(), Some("o14"));
    press(&mut app, KeyCode::Down, &master).await;
    assert_eq!(
        app.labels.selected_id.as_deref(),
        Some("o14"),
        "Down on the last entry is a no-op, NOT a wrap"
    );

    press(&mut app, KeyCode::Home, &master).await;
    assert_eq!(app.labels.selected_id.as_deref(), Some("o00"));
    press(&mut app, KeyCode::Up, &master).await;
    assert_eq!(
        app.labels.selected_id.as_deref(),
        Some("o00"),
        "Up on the first entry is a no-op, NOT a wrap"
    );

    press(&mut app, KeyCode::PageDown, &master).await;
    assert_eq!(app.labels.selected_id.as_deref(), Some("o10"));
}

/// **The Labels kind menu must KEEP wrapping.** It is a three-item
/// value cycler, the same class §6 names as load-bearing for the four
/// `rem_euclid` sites it tells this sprint not to touch. Clamping it
/// would strand the operator on the last kind.
#[tokio::test]
async fn n4_the_labels_kind_menu_still_wraps() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    let mut app = app_on(&master, Leaf::Labels);
    let first = app.labels.selected_kind;
    let n = crate::tui::tabs::labels::menu_kinds().len();
    assert!(n >= 2, "fixture assumes a multi-kind menu");

    for _ in 0..n {
        press(&mut app, KeyCode::Down, &master).await;
    }
    assert_eq!(
        app.labels.selected_kind, first,
        "a full lap of the kind menu returns to the first kind — it cycles, it is not a list"
    );
}

/// `Home` / `End` stay unbound on the kind menu: there is nothing to
/// jump past in a three-item cycler, and aliasing them to `↑`/`↓`
/// would make the menu the one place where a jump key means a step.
#[tokio::test]
async fn n4_home_and_end_are_inert_on_the_labels_kind_menu() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    let mut app = app_on(&master, Leaf::Labels);
    let kind_before = app.labels.selected_kind;

    press(&mut app, KeyCode::End, &master).await;
    assert_eq!(
        app.labels.selected_kind, kind_before,
        "End does not walk the kind menu"
    );
    press(&mut app, KeyCode::Home, &master).await;
    assert_eq!(app.labels.selected_kind, kind_before);
}

// ── N4: the header-aware page helper ────────────────────────────

/// `page_selectable_idx` is the one piece of N4 this lane had to
/// write itself, because Devices / Lists interleave non-selectable
/// group headers and their own step helper lives in another lane's
/// file. Exercised directly on a synthetic vector so the property is
/// pinned independently of either leaf's row builder.
#[test]
fn n4_page_over_headers_counts_only_selectable_rows_and_clamps() {
    // `false` = a group header. 22 rows, 15 of them selectable.
    let mut rows = Vec::new();
    for i in 0..15 {
        if i % 3 == 0 {
            rows.push(false);
        }
        rows.push(true);
    }
    let sel = |r: &bool| *r;
    let selectable: Vec<usize> = rows
        .iter()
        .enumerate()
        .filter(|(_, r)| **r)
        .map(|(i, _)| i)
        .collect();
    assert_eq!(selectable.len(), 15);

    assert_eq!(first_selectable_idx(&rows, sel), Some(selectable[0]));
    assert_eq!(last_selectable_idx(&rows, sel), Some(selectable[14]));

    // From the first selectable row, one page lands exactly NAV_PAGE
    // SELECTABLE rows later — headers crossed on the way do not count.
    assert_eq!(
        page_selectable_idx(&rows, Some(selectable[0]), true, sel),
        Some(selectable[NAV_PAGE]),
        "headers must not consume page steps"
    );
    // And the next page clamps at the last selectable row rather than
    // wrapping or landing on a header.
    assert_eq!(
        page_selectable_idx(&rows, Some(selectable[NAV_PAGE]), true, sel),
        Some(selectable[14]),
        "PgDn clamps at the last SELECTABLE row"
    );
    assert_eq!(
        page_selectable_idx(&rows, Some(selectable[0]), false, sel),
        Some(selectable[0]),
        "PgUp from the top is a no-op, not a wrap to the bottom"
    );
    // A cursor parked on a header (or out of range) seeds rather than
    // panicking — that is what `None` from the leaf helper looks like.
    assert_eq!(
        page_selectable_idx(&rows, None, true, sel),
        Some(selectable[0])
    );
    assert_eq!(
        page_selectable_idx(&rows, Some(999), false, sel),
        Some(selectable[14])
    );
    let empty: Vec<bool> = Vec::new();
    assert_eq!(page_selectable_idx(&empty, None, true, sel), None);
}

// ── N4: the Query Log boundary ──────────────────────────────────

/// **N4 makes a limit reachable that was previously only stumbled
/// into, and §6 forbids shipping that silently.** `End` on Query Log
/// lands on the oldest *loaded* row, which an operator reads as the
/// oldest *query*. It is not — the rows are whatever the last
/// `read_log_entries_with_state` returned.
///
/// The notice is on the status line rather than annotated onto the
/// row because the row renderer is another lane's file this wave. The
/// property §6 actually asks for is that the edge explains itself, and
/// this is that property.
#[tokio::test]
async fn n4_query_log_end_explains_the_loaded_window() {
    use crate::ipc::protocol::QueryLogDto;
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    let mut app = app_on(&master, Leaf::QueryLog);
    app.query_log.entries = (0..4)
        .map(|i| QueryLogDto {
            timestamp: format!("2026-08-24T00:00:0{i}Z"),
            client_ip: "192.0.2.9".into(),
            client_name: None,
            domain: format!("d{i}.test"),
            query_type: "A".into(),
            result: "ALLOWED".into(),
            response_time_us: 1,
            cname_chain_via: None,
        })
        .collect();

    press(&mut app, KeyCode::Home, &master).await;
    assert_eq!(app.query_log.table_state.selected(), Some(0));
    assert_ne!(
        app.status_text(),
        Some(QUERY_LOG_END_OF_PAGE),
        "Home must not claim an end-of-page"
    );

    press(&mut app, KeyCode::End, &master).await;
    assert_eq!(app.query_log.table_state.selected(), Some(3), "End = last");
    assert_eq!(
        app.status_text(),
        Some(QUERY_LOG_END_OF_PAGE),
        "reaching the loaded edge must say so — a limit made visible and \
             then left unexplained is worse than the silent version"
    );
}

// ── qlog-paging-cursor: the boundary now fetches ────────────────

fn qlog_rows(n: usize) -> Vec<crate::ipc::protocol::QueryLogDto> {
    (0..n)
        .map(|i| crate::ipc::protocol::QueryLogDto {
            timestamp: format!("2026-08-24T00:00:{i:02}Z"),
            client_ip: "192.0.2.9".into(),
            client_name: None,
            domain: format!("d{i}.test"),
            query_type: "A".into(),
            result: "ALLOWED".into(),
            response_time_us: 1,
            cname_chain_via: None,
        })
        .collect()
}

fn a_cursor(file: &str) -> crate::tracking::query_log::QueryLogCursor {
    crate::tracking::query_log::QueryLogCursor {
        file: file.into(),
        offset: 4096,
        inode: 7,
    }
}

/// **The bug this test exists for.** Filters are applied DURING the
/// walk, so a page boundary is a function of the predicate set that
/// produced it. A cursor minted under the old filters names a
/// boundary that no longer exists — serving it renders rows that do
/// not belong to the filters on screen. Silently wrong data in the
/// surface an operator uses to decide what to block.
///
/// Every filter mutation must land back on the live tail. All five
/// arms are checked because the defect is per-arm: covering `R` and
/// trusting the rest is how four of them would have shipped.
#[tokio::test]
async fn every_filter_mutation_drops_the_cursor_stack() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);

    // (key sequence, what it changes)
    let cases: Vec<(Vec<KeyCode>, &str)> = vec![
        (vec![KeyCode::Char('b')], "blocked-only toggle"),
        (vec![KeyCode::Char('t')], "time preset"),
        (vec![KeyCode::Char('R')], "reset-all"),
        (
            vec![KeyCode::Char('/'), KeyCode::Char('x'), KeyCode::Enter],
            "domain filter commit",
        ),
        (
            vec![KeyCode::Char('c'), KeyCode::Char('x'), KeyCode::Enter],
            "client filter commit",
        ),
    ];

    for (keys, what) in cases {
        let mut app = app_on(&master, Leaf::QueryLog);
        app.query_log.entries = qlog_rows(4);
        // Pretend the operator paged two deep.
        app.query_log.page_cursors = vec![None, Some(a_cursor("/q.log")), Some(a_cursor("/q.log"))];
        app.query_log.page_index = 2;
        app.query_log.next_cursor = Some(a_cursor("/q.log"));

        for k in keys {
            press(&mut app, k, &master).await;
        }

        assert_eq!(
            app.query_log.page_index, 0,
            "{what} must return to the live tail"
        );
        assert_eq!(
            app.query_log.page_cursors.len(),
            1,
            "{what} must drop cursors minted under the old predicates"
        );
        assert!(
            app.query_log.current_cursor().is_none(),
            "{what} must leave page 0 cursorless"
        );
        assert!(app.query_log.next_cursor.is_none(), "{what}");
    }
}

/// `PgDn` is within-page travel until the cursor is already on the
/// last row. One keystroke crossing a page boundary would turn every
/// scroll into an IPC round-trip.
#[tokio::test]
async fn pgdn_pages_only_from_the_last_row() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    let mut app = app_on(&master, Leaf::QueryLog);
    app.query_log.entries = qlog_rows(60);
    app.query_log.next_cursor = Some(a_cursor("/q.log"));

    press(&mut app, KeyCode::Home, &master).await;
    press(&mut app, KeyCode::PageDown, &master).await;
    assert_eq!(
        app.query_log.page_index, 0,
        "a PgDn from mid-page scrolls; it must not fetch"
    );
    assert!(!app.force_poll, "no fetch requested from mid-page");

    press(&mut app, KeyCode::End, &master).await;
    assert_eq!(
        app.query_log.page_index, 0,
        "End means oldest LOADED row — it must never fetch"
    );

    press(&mut app, KeyCode::PageDown, &master).await;
    assert_eq!(
        app.query_log.page_index, 1,
        "PgDn from the last row crosses the boundary"
    );
    assert!(app.force_poll, "crossing a boundary must request the page");
    assert_eq!(
        app.query_log.current_cursor(),
        Some(a_cursor("/q.log")),
        "the page must be requested with the daemon's resume point"
    );
    assert_eq!(app.query_log.table_state.selected(), Some(0));

    // …and back.
    app.force_poll = false;
    press(&mut app, KeyCode::PageUp, &master).await;
    assert_eq!(app.query_log.page_index, 0, "PgUp from the top returns");
    assert!(app.force_poll);
    assert_eq!(app.status_text(), Some(QUERY_LOG_LIVE_TAIL));
}

/// `QUERY_LOG_END_OF_PAGE` says "older entries not loaded". Before
/// paging that was unconditionally true. Now it is only true when
/// the daemon handed back no resume point — otherwise there ARE
/// older entries and one keystroke loads them.
#[tokio::test]
async fn the_end_of_page_notice_is_gated_on_the_resume_point() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);

    let mut exhausted = app_on(&master, Leaf::QueryLog);
    exhausted.query_log.entries = qlog_rows(4);
    exhausted.query_log.next_cursor = None;
    press(&mut exhausted, KeyCode::End, &master).await;
    assert_eq!(exhausted.status_text(), Some(QUERY_LOG_END_OF_PAGE));

    let mut more = app_on(&master, Leaf::QueryLog);
    more.query_log.entries = qlog_rows(4);
    more.query_log.next_cursor = Some(a_cursor("/q.log"));
    press(&mut more, KeyCode::End, &master).await;
    assert_eq!(
        more.status_text(),
        Some(QUERY_LOG_MORE_BELOW),
        "claiming nothing is loadable while holding a cursor is a lie"
    );
}

/// With no resume point, `PgDn` at the bottom says so rather than
/// advancing into a page that does not exist.
#[tokio::test]
async fn pgdn_at_the_oldest_page_refuses_instead_of_advancing() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    let mut app = app_on(&master, Leaf::QueryLog);
    app.query_log.entries = qlog_rows(4);
    app.query_log.next_cursor = None;

    press(&mut app, KeyCode::End, &master).await;
    press(&mut app, KeyCode::PageDown, &master).await;
    assert_eq!(app.query_log.page_index, 0);
    assert!(!app.force_poll);
    assert_eq!(app.status_text(), Some(QUERY_LOG_OLDEST));
}

/// **Proves `f` survives the real dispatcher, not just the leaf
/// handler.** `press` goes through `handle_key`, the same entry a live
/// keystroke takes, so this exercises the global arms
/// (`q`/`Ctrl+C`/`1`-`6`/`[`/`]`/`g`/`?`/`r`/`p`/`s`) and the
/// `pending_goto` mnemonic path ahead of leaf dispatch.
///
/// The precedent this guards against is in this file's own history:
/// `g` became a global mnemonic prefix that armed BEFORE per-tab
/// dispatch, which made the Query Log's `g`-jumps-to-top handler
/// unreachable — and nothing failed. A leaf-handler-only test would
/// have stayed green through exactly that.
#[tokio::test]
async fn f_reaches_the_query_log_leaf_and_opens_the_advanced_form() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    let mut app = app_on(&master, Leaf::QueryLog);
    assert!(app.query_log.advanced_modal.is_none());

    press(&mut app, KeyCode::Char('f'), &master).await;
    assert!(
        app.query_log.advanced_modal.is_some(),
        "`f` must reach handle_query_log_key through the real dispatcher"
    );

    press(&mut app, KeyCode::Esc, &master).await;
    assert!(app.query_log.advanced_modal.is_none(), "Esc closes it");
}

/// While the form is open it owns every keystroke. `b`, `t`, `c` and
/// `R` are Query Log verbs and the form has three text fields — all
/// four letters have to be typeable.
#[tokio::test]
async fn the_open_form_swallows_the_query_log_verbs() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    let mut app = app_on(&master, Leaf::QueryLog);
    press(&mut app, KeyCode::Char('f'), &master).await;

    for c in ['b', 't', 'c'] {
        press(&mut app, KeyCode::Char(c), &master).await;
    }
    // `R` arrives from a real terminal as Char('R') + SHIFT. Pressing
    // it with NONE would prove the handler accepts the char but not
    // that a real shifted keystroke reaches it — the narrower claim
    // this test's name does not make.
    let shift_r = KeyEvent::new(KeyCode::Char('R'), KeyModifiers::SHIFT);
    handle_key(&mut app, shift_r, &poller(dir.path()), &master).await;
    assert!(
        !app.query_log.blocked_only,
        "`b` must type into the form, not toggle blocked-only"
    );
    assert_eq!(
        app.query_log.since,
        crate::tui::app::SincePreset::Off,
        "`t` must type into the form, not cycle the time preset"
    );
    assert_eq!(
        app.query_log
            .advanced_modal
            .as_ref()
            .and_then(|m| m.draft.name.as_deref()),
        Some("btcR"),
        "all four letters land in the focused field"
    );
}

/// A `Ctrl`-chord must never be typed as text. Six sibling modals
/// submit on `Ctrl+S`, so an operator will press it here; without the
/// modifier guard it appended an `s` to whichever field had focus.
#[tokio::test]
async fn a_ctrl_chord_is_not_typed_into_the_form() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    let mut app = app_on(&master, Leaf::QueryLog);
    press(&mut app, KeyCode::Char('f'), &master).await;

    let ctrl_s = KeyEvent::new(KeyCode::Char('s'), KeyModifiers::CONTROL);
    handle_key(&mut app, ctrl_s, &poller(dir.path()), &master).await;
    assert_eq!(
        app.query_log
            .advanced_modal
            .as_ref()
            .and_then(|m| m.draft.name.as_deref()),
        None,
        "Ctrl+S must not leave an `s` in the name field"
    );
}

/// Applying the form is a filter mutation: it must land back on the
/// live tail and drop cursors minted under the previous predicates.
#[tokio::test]
async fn applying_the_form_resets_paging_and_requests_a_fetch() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    let mut app = app_on(&master, Leaf::QueryLog);
    app.query_log.page_cursors = vec![None, Some(a_cursor("/q.log"))];
    app.query_log.page_index = 1;
    app.query_log.next_cursor = Some(a_cursor("/q.log"));

    press(&mut app, KeyCode::Char('f'), &master).await;
    for c in ['i', 'o', 't'] {
        press(&mut app, KeyCode::Char(c), &master).await;
    }
    press(&mut app, KeyCode::Enter, &master).await;

    assert!(app.query_log.advanced_modal.is_none(), "Enter applies");
    assert_eq!(app.query_log.advanced.name.as_deref(), Some("iot"));
    assert_eq!(
        app.query_log.page_index, 0,
        "apply returns to the live tail"
    );
    assert_eq!(app.query_log.page_cursors.len(), 1);
    assert!(app.force_poll);
}

/// `R` is documented as "reset all filters", so it has to reach the
/// advanced form too — otherwise it is the one filter the reset key
/// cannot clear, and the card shows a single chip for it.
#[tokio::test]
async fn reset_all_clears_the_advanced_filter_too() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    let mut app = app_on(&master, Leaf::QueryLog);
    app.query_log.advanced.name = Some("iot*".into());
    app.query_log.advanced.name_exclude = true;

    press(&mut app, KeyCode::Char('R'), &master).await;
    assert!(
        app.query_log.advanced.is_empty(),
        "R must clear the advanced form, not just the four card controls"
    );
    assert!(!app.query_log.advanced.name_exclude);
}

fn a_page(
    entries: Vec<crate::ipc::protocol::QueryLogDto>,
    next_cursor: Option<crate::tracking::query_log::QueryLogCursor>,
    cursor_stale: bool,
) -> crate::tui::ipc_poller::QueryLogPollResult {
    crate::tui::ipc_poller::QueryLogPollResult {
        entries,
        logging_enabled: true,
        file_state: crate::ipc::protocol::QueryLogFileState::Ok,
        next_cursor,
        cursor_stale,
    }
}

/// **Page 0's boundary moves on every append.** A cursor minted when
/// page 0 ended at row N names a position that now has freshly-written
/// rows above it, so re-using it would page straight past them —
/// silent row-skipping in an audit surface.
///
/// Calls `apply_query_log_page`, the real code the poll arm runs. An
/// earlier version of this test inlined the two-line branch and
/// asserted on its own copy — which stays green if the branch is
/// deleted from the caller. A test that names a defect it cannot
/// detect is worse than none, because the next reader trusts the name.
#[test]
fn a_poll_on_the_live_tail_drops_cursors_minted_against_an_older_boundary() {
    let mut app = App::new();
    app.query_log.page_cursors = vec![None, Some(a_cursor("/q.log"))];
    app.query_log.page_index = 0;

    apply_query_log_page(&mut app, a_page(qlog_rows(3), None, false));

    assert_eq!(
        app.query_log.page_cursors.len(),
        1,
        "a stale page-1 cursor must not survive a page-0 refresh"
    );
    assert!(app.query_log.current_cursor().is_none());
    assert_eq!(app.query_log.entries.len(), 3);
}

/// The same call while paged back must NOT drop the stack — those
/// cursors are still valid, because only page 0's boundary moves.
#[test]
fn a_poll_on_a_paged_back_view_keeps_its_cursors() {
    let mut app = App::new();
    app.query_log.page_cursors = vec![None, Some(a_cursor("/q.log"))];
    app.query_log.page_index = 1;

    apply_query_log_page(&mut app, a_page(qlog_rows(3), None, false));

    assert_eq!(app.query_log.page_index, 1);
    assert_eq!(app.query_log.page_cursors.len(), 2);
}

/// A rotated-out cursor resets to the live tail and says so, rather
/// than presenting unrelated rows as the page that was asked for.
#[test]
fn a_stale_cursor_response_resets_to_the_live_tail() {
    let mut app = App::new();
    app.query_log.page_cursors = vec![None, Some(a_cursor("/q.log"))];
    app.query_log.page_index = 1;

    apply_query_log_page(&mut app, a_page(qlog_rows(2), None, true));

    assert_eq!(app.query_log.page_index, 0);
    assert_eq!(app.query_log.page_cursors.len(), 1);
    assert_eq!(app.status_text(), Some(QUERY_LOG_CURSOR_STALE));
}

/// An empty page beyond page 0 steps BACK and keeps the rows the
/// operator was reading, instead of blanking the table.
#[test]
fn an_empty_page_beyond_the_first_steps_back_and_keeps_its_rows() {
    let mut app = App::new();
    app.query_log.page_cursors = vec![None, Some(a_cursor("/q.log"))];
    app.query_log.page_index = 1;
    app.query_log.entries = qlog_rows(4);

    apply_query_log_page(&mut app, a_page(Vec::new(), None, false));

    assert_eq!(app.query_log.page_index, 0, "step back, do not blank");
    assert_eq!(
        app.query_log.entries.len(),
        4,
        "the page being read must survive an empty response"
    );
    assert!(
        app.query_log.next_cursor.is_none(),
        "the dead cursor is dropped so PgDn refuses instead of retrying"
    );
    assert_eq!(app.status_text(), Some(QUERY_LOG_OLDEST));
}

// ── N5: Enter = the focused row's primary action ────────────────

#[tokio::test]
async fn n5_enter_opens_the_edit_modal_on_groups() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    let mut app = app_on(&master, Leaf::Groups);
    assert!(app.groups.modal.is_none());

    press(&mut app, KeyCode::Enter, &master).await;
    assert!(
        app.groups.modal.is_some(),
        "Enter must open the same edit modal `e` does"
    );
}

#[tokio::test]
async fn n5_enter_opens_the_edit_modal_on_labels() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    let mut app = app_on(&master, Leaf::Labels);
    assert!(app.labels.modal.is_none());

    press(&mut app, KeyCode::Enter, &master).await;
    assert!(
        app.labels.modal.is_some(),
        "Enter must open the same edit modal `e` does"
    );
}

#[tokio::test]
async fn n5_enter_opens_the_edit_modal_on_profiles() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    let mut app = app_on(&master, Leaf::Profiles);
    assert!(app.profiles.modal.is_none());

    press(&mut app, KeyCode::Enter, &master).await;
    assert!(
        app.profiles.modal.is_some(),
        "Enter must open the same edit modal `e` does"
    );
}

/// N5 says Enter takes the SAME branch as `e` — not that it opens a
/// modal of its own. A second modal type would satisfy the three
/// tests above and still be the defect.
#[tokio::test]
async fn n5_enter_and_e_open_the_identical_modal_on_groups() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);

    let mut via_enter = app_on(&master, Leaf::Groups);
    press(&mut via_enter, KeyCode::Enter, &master).await;
    let mut via_e = app_on(&master, Leaf::Groups);
    press(&mut via_e, KeyCode::Char('e'), &master).await;

    assert_eq!(
        format!("{:?}", via_enter.groups.modal),
        format!("{:?}", via_e.groups.modal),
        "Enter must be the `e` branch, not a parallel one"
    );
}
