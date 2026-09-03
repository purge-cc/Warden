//! Log Messages tab (`Leaf::Logs`) — the daemon's own recent `tracing`
//! events, read over `IpcCommand::DaemonLogs`.
//!
//! Answers "what has the daemon been saying"; `Leaf::QueryLog` answers
//! "what did clients ask for". Two different questions, which is why the
//! leaf is labelled **Log Messages** rather than "Logs" sitting one
//! section away from "Query Log".
//!
//! Shape is deliberately borrowed rather than invented:
//!
//! - the **scroll convention is `tabs::file`'s** — `↑`/`↓` by one,
//!   `PgUp`/`PgDn` by [`NAV_PAGE`], `Home`/`End`, clamped against
//!   `len - 1` through a saturating `u16` conversion. A second scroll
//!   idiom in the same product is a bug an operator has to learn.
//! - the **filter card is shared** — `theme::render_filter_card`, `/`
//!   search, an `f`-cycled chip row, `[R] clear`, exactly as
//!   `tabs::lists` and `tabs::rules` render it.
//!
//! Neither filter is applied here. Both travel in the IPC request and are
//! applied during the daemon's walk of the ring, so filtering to `errors`
//! reaches the bottom of the buffer instead of searching only the newest
//! page and presenting that as "the errors".
//!
//! ```text
//! ┌ Search [/]: ______   Level [f]:  all  errors  warnings  info   [R] clear ┐
//! └──────────────────────────────────────────────────────────────────────────┘
//! ┌ Log Messages (47 of ≤1000) ──────────────────────────────────────────────┐
//! │ 14:03:05  ERROR  lists::manager   refresh failed source=oisd attempt=3   │
//! │ 14:02:58  INFO   cli::start       listening on 0.0.0.0:53                │
//! └──────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Not here
//! - Keys:  `mod.rs::handle_logs_key` (the borrowed scroll convention above)
//! - Form:  none — read-only, no modal
//! - State: `app::LogsState` (`entries`, `scroll_offset`, `level_filter`, `filter_text`)
//! - Tests: render + pure fns here; key handling in `tui/tests/`, declared from `mod.rs`

use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use crate::ipc::protocol::DaemonLogDto;
use crate::tracking::log_ring::LogLevel;
use crate::tui::app::{self, App, LogsFetch, LogsLevelFilter};
use crate::tui::theme::{self, T};
use crate::tui::ui::render_section_chrome;
// `NAV_PAGE` is private to `crate::tui`; reachable here because `tabs` is
// a descendant module, so the page step stays written once.
use crate::tui::NAV_PAGE;

/// Frozen strings for the filter card and the two empty states. Pinned by
/// `tests/frozen_strings_tui_logs.rs` — the empty states in particular,
/// because "nothing captured" and "nothing matched" are the two readings
/// an operator will draw the wrong conclusion from if they collapse into
/// one blank pane.
pub const SEARCH_PROMPT: &str = "Search [/]: ";
pub const LEVEL_PROMPT: &str = "   Level [f]: ";
pub const CLEAR_HINT: &str = "   [R] clear";
/// Shown when a poll succeeded and the daemon has captured nothing.
pub const NO_MESSAGES: &str = "  (no messages captured yet)";
/// Shown when the ring holds messages but none pass the current filters —
/// a different fact, and the one that tells the operator to press `R`.
pub const NO_MATCHES: &str = "  (no messages match the current filter — [R] clears)";
/// Shown before the first response lands. Says nothing about the daemon,
/// because nothing is known about it yet.
pub const WAITING: &str = "  (waiting for the daemon…)";
/// Shown when the last poll FAILED. The pane is empty because the read
/// failed, not because the daemon is quiet — a live daemon logs at boot,
/// so telling the operator it has said nothing would send them hunting
/// the wrong fault. The footer carries the underlying error.
pub const UNREADABLE: &str = "  (could not read the daemon's log buffer — see the footer)";

pub fn render(f: &mut Frame, area: Rect, app: &App) {
    let chunks = Layout::vertical([Constraint::Length(3), Constraint::Min(3)]).split(area);
    render_filters(f, chunks[0], app);
    render_body(f, chunks[1], app);
}

/// Shared filter card: `/` text search plus the `f`-cycled severity
/// chip. Mirrors `tabs::lists::render_filters` field for field.
fn render_filters(f: &mut Frame, area: Rect, app: &App) {
    let content_area = theme::render_filter_card(f, area);

    let (search_val, search_style) = match &app.input_mode {
        app::InputMode::FilterLogs(s) => (format!("{s}_"), Style::default().fg(T.info)),
        _ => (
            app.logs.filter_text.clone().unwrap_or_default(),
            Style::default().fg(T.text_secondary),
        ),
    };

    let chip = |label: &str, selected: bool| {
        let style = if selected {
            Style::default()
                .fg(T.text_inverse)
                .bg(T.brand_red)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(T.text_secondary)
        };
        Span::styled(format!(" {label} "), style)
    };

    let level = app.logs.level_filter;
    // Width budget: fixed spans first, the search value gets what is
    // left, tail-kept so the `_` edit cursor stays visible and the chips
    // never scroll off. Same arithmetic as tabs::lists.
    let lead = Span::styled(SEARCH_PROMPT, Style::default().fg(T.text_muted));
    let mut trailing = vec![Span::styled(
        LEVEL_PROMPT,
        Style::default().fg(T.text_muted),
    )];
    for chip_level in [
        LogsLevelFilter::All,
        LogsLevelFilter::Error,
        LogsLevelFilter::Warn,
        LogsLevelFilter::Info,
    ] {
        trailing.push(chip(chip_level.label(), level == chip_level));
        trailing.push(Span::raw(" "));
    }
    trailing.push(Span::styled(CLEAR_HINT, Style::default().fg(T.text_muted)));

    let fixed: usize = lead.width() + trailing.iter().map(Span::width).sum::<usize>();
    let budget = (content_area.width as usize).saturating_sub(fixed).max(11);
    let shown = if search_val.is_empty() {
        "___________".to_string()
    } else {
        crate::tui::tabs::query_log::truncate_tail(&search_val, budget)
    };
    let mut spans = Vec::with_capacity(trailing.len() + 2);
    spans.push(lead);
    spans.push(Span::styled(shown, search_style));
    spans.extend(trailing);
    f.render_widget(Paragraph::new(Line::from(spans)), content_area);
}

/// The scrolling event list, under a chrome title that carries the
/// counts.
fn render_body(f: &mut Frame, area: Rect, app: &App) {
    let content = render_section_chrome(f, area, &body_title(app), T.text_secondary);

    if app.logs.entries.is_empty() {
        let filtered =
            app.logs.level_filter != LogsLevelFilter::All || app.logs.filter_text.is_some();
        // FOUR readings of one empty list. Three are claims about the
        // daemon, one is a claim about the connection — and only one of
        // them is the operator's own filter. Collapsing them is how an
        // operator concludes the tab is broken when it is merely
        // filtered, or that the daemon is silent when the read failed.
        let msg = match app.logs.fetch {
            LogsFetch::Never => WAITING,
            LogsFetch::Failed => UNREADABLE,
            LogsFetch::Ok if filtered => NO_MATCHES,
            LogsFetch::Ok => NO_MESSAGES,
        };
        f.render_widget(
            Paragraph::new(Span::styled(msg, Style::default().fg(T.text_muted))),
            content,
        );
        return;
    }

    // Clamp before skipping: a poll that returns a SHORTER page (the
    // operator just narrowed the filter) leaves `scroll_offset` past the
    // end, and `.skip()` then consumes every row → a blank pane that
    // reads as "no messages". Same failure `tabs::file` documents.
    let offset = (app.logs.scroll_offset as usize).min(app.logs.entries.len().saturating_sub(1));
    let lines: Vec<Line> = app
        .logs
        .entries
        .iter()
        .skip(offset)
        .map(|e| entry_line(e, content.width))
        .collect();

    f.render_widget(Paragraph::new(lines), content);
}

/// `Log Messages (47 of ≤1000 · 3 dropped)`.
///
/// The capacity is stated rather than implied: the ring is bounded, and a
/// bare count would let an operator read the pane as the daemon's whole
/// history. `dropped` appears only when non-zero — a permanent `· 0
/// dropped` is noise that trains the eye to skip the field that matters.
fn body_title(app: &App) -> String {
    let mut title = if app.logs.capacity == 0 {
        format!("Log Messages ({})", app.logs.entries.len())
    } else {
        format!(
            "Log Messages ({} of ≤{})",
            app.logs.entries.len(),
            app.logs.capacity
        )
    };
    if app.logs.dropped > 0 {
        // "since start", not a bare count: the daemon's counter is
        // monotonic for its whole lifetime, and `· 3 dropped` next to a
        // page count reads as "3 dropped from THIS page".
        title = format!("{} · {} dropped since start", title, app.logs.dropped);
    }
    title
}

/// One rendered row: `HH:MM:SS  LEVEL  target  message`.
///
/// The message is truncated to whatever width the fixed columns leave,
/// never wrapped: `scroll_offset`, [`last_row`] and [`page_step`] all
/// count *entries*, and a wrapped message would make `PgDn`/`End` skip
/// whole screens or land mid-message instead of moving one pane.
fn entry_line(entry: &DaemonLogDto, width: u16) -> Line<'static> {
    let level_style = Style::default()
        .fg(level_color(entry.level))
        .add_modifier(Modifier::BOLD);
    // Target column scales with the pane: on a narrow terminal the
    // message is what the operator came for, so the module path is the
    // first thing to give up cells.
    let target_w = if width >= 100 { 22 } else { 14 };
    let clock_str = clock(&entry.timestamp);
    let level_str = format!("{:<5}", level_label(entry.level));
    let target_str = format!("{:<w$}", short_target(&entry.target), w = target_w);
    let fixed_w =
        clock_str.chars().count() + level_str.chars().count() + target_str.chars().count() + 6; // three 2-space gaps
    let msg_budget = (width as usize).saturating_sub(fixed_w);
    Line::from(vec![
        Span::styled(clock_str, Style::default().fg(T.text_muted)),
        Span::raw("  "),
        Span::styled(level_str, level_style),
        Span::raw("  "),
        Span::styled(target_str, Style::default().fg(T.text_secondary)),
        Span::raw("  "),
        Span::styled(
            truncate_message(&entry.message, msg_budget),
            Style::default().fg(T.text_primary),
        ),
    ])
}

/// Truncates to `max` chars with a trailing ellipsis, char-safe (never
/// splits a multibyte codepoint) — same shape as `cluster::truncate`,
/// kept local rather than shared because that helper is private to its
/// own module.
fn truncate_message(s: &str, max: usize) -> String {
    if max == 0 {
        return String::new();
    }
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max - 1).collect();
    out.push('\u{2026}');
    out
}

/// `2026-08-25T14:03:05Z` → `14:03:05`. Falls back to the whole string if
/// it is not the shape the daemon promised — a timestamp that renders
/// oddly is better than a row that vanishes.
pub fn clock(timestamp: &str) -> String {
    // `.get()` yields None when a slice boundary is not a char boundary,
    // so a malformed stamp falls back to the raw string instead of
    // panicking mid-codepoint — same contract as local_dns::trim_audit_ts
    // and cluster::short_hash.
    match timestamp
        .find('T')
        .and_then(|t| timestamp.get(t + 1..t + 9))
    {
        Some(hms) => hms.to_string(),
        None => timestamp.to_string(),
    }
}

/// `purge_warden::lists::manager` → `lists::manager`. The crate name is
/// on every row, so it carries no information and costs 14 cells.
pub fn short_target(target: &str) -> &str {
    target.strip_prefix("purge_warden::").unwrap_or(target)
}

pub fn level_label(level: LogLevel) -> &'static str {
    match level {
        LogLevel::Error => "ERROR",
        LogLevel::Warn => "WARN",
        LogLevel::Info => "INFO",
    }
}

fn level_color(level: LogLevel) -> Color {
    match level {
        LogLevel::Error => T.error,
        LogLevel::Warn => T.warning,
        LogLevel::Info => T.info,
    }
}

/// Last scrollable row index, saturating. A bare `as` on a page longer
/// than 65 535 rows would wrap the clamp to a small number and pin
/// scrolling near the top — the hazard `tabs::file` already names.
pub fn last_row(app: &App) -> u16 {
    u16::try_from(app.logs.entries.len().saturating_sub(1)).unwrap_or(u16::MAX)
}

/// `PgUp`/`PgDn`/`Home`/`End` step, shared with the key handler.
pub fn page_step() -> u16 {
    u16::try_from(NAV_PAGE).unwrap_or(u16::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::app::App;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    fn dto(level: LogLevel, target: &str, message: &str) -> DaemonLogDto {
        DaemonLogDto {
            timestamp: "2026-08-25T14:03:05Z".into(),
            level,
            target: target.into(),
            message: message.into(),
        }
    }

    /// True if any single row of `buf` contains `needle`. Reading the
    /// `TestBackend` buffer cell-by-cell sidesteps the ANSI-escape
    /// splitting that makes pty-captured frames unreliable to assert on.
    fn buffer_contains(buf: &ratatui::buffer::Buffer, needle: &str) -> bool {
        let area = *buf.area();
        (0..area.height).any(|y| {
            let row: String = (0..area.width).map(|x| buf[(x, y)].symbol()).collect();
            row.contains(needle)
        })
    }

    /// Count of rows containing `needle` — `buffer_contains` collapsed to
    /// a bool, which can't tell "one entry, one row" from "one entry
    /// wrapped onto several".
    fn rows_containing(buf: &ratatui::buffer::Buffer, needle: &str) -> usize {
        let area = *buf.area();
        (0..area.height)
            .filter(|&y| {
                let row: String = (0..area.width).map(|x| buf[(x, y)].symbol()).collect();
                row.contains(needle)
            })
            .count()
    }

    fn draw(app: &App, w: u16, h: u16) -> Terminal<TestBackend> {
        let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
        term.draw(|f| render(f, Rect::new(0, 0, w, h), app))
            .unwrap();
        term
    }

    #[test]
    fn the_tab_renders_a_captured_event() {
        let mut app = App::new();
        app.logs.entries = vec![dto(
            LogLevel::Error,
            "purge_warden::lists::manager",
            "refresh failed",
        )];
        app.logs.capacity = 1000;
        let term = draw(&app, 120, 12);
        let buf = term.backend().buffer();
        assert!(
            buffer_contains(buf, "refresh failed"),
            "message must render"
        );
        assert!(buffer_contains(buf, "ERROR"), "level must render");
        assert!(buffer_contains(buf, "lists::manager"), "target must render");
        assert!(buffer_contains(buf, "14:03:05"), "clock must render");
    }

    #[test]
    fn the_title_states_the_bound_and_any_drops() {
        // The ring is bounded; a bare count would read as "everything the
        // daemon ever said".
        let mut app = App::new();
        app.logs.entries = vec![dto(LogLevel::Info, "purge_warden::x", "hi")];
        app.logs.capacity = 1000;
        assert_eq!(body_title(&app), "Log Messages (1 of ≤1000)");
        app.logs.dropped = 3;
        assert_eq!(
            body_title(&app),
            "Log Messages (1 of ≤1000) · 3 dropped since start"
        );
    }

    #[test]
    fn an_empty_pane_says_which_kind_of_empty_it_is() {
        // One empty list, four different facts. Each must reach the
        // operator as its own sentence.
        let mut app = App::new();

        // 1. Nothing fetched yet — says nothing about the daemon.
        let term = draw(&app, 110, 10);
        assert!(
            buffer_contains(term.backend().buffer(), "waiting for the daemon"),
            "pre-fetch must not claim the daemon has been silent"
        );

        // 2. The poll FAILED. A live daemon logs at boot, so "no messages
        // captured yet" here sends the operator hunting the wrong fault.
        app.logs.fetch = LogsFetch::Failed;
        let term = draw(&app, 110, 10);
        assert!(
            buffer_contains(term.backend().buffer(), "could not read the daemon"),
            "a failed read must not be rendered as a quiet daemon"
        );

        // 3. Fetched fine, daemon genuinely quiet.
        app.logs.fetch = LogsFetch::Ok;
        let term = draw(&app, 110, 10);
        assert!(buffer_contains(
            term.backend().buffer(),
            "no messages captured"
        ));

        // 4. Nothing MATCHED — the one that tells the operator to press R.
        app.logs.level_filter = LogsLevelFilter::Error;
        let term = draw(&app, 110, 10);
        assert!(buffer_contains(
            term.backend().buffer(),
            "match the current filter"
        ));
    }

    #[test]
    fn the_filter_card_shows_the_selected_severity_chip() {
        let mut app = App::new();
        app.logs.level_filter = LogsLevelFilter::Warn;
        let term = draw(&app, 120, 10);
        let buf = term.backend().buffer();
        assert!(
            buffer_contains(buf, "Level [f]:"),
            "the chip row must render"
        );
        assert!(buffer_contains(buf, "warnings"));
        assert!(buffer_contains(buf, "[R] clear"));
    }

    #[test]
    fn truncate_message_keeps_the_head_and_marks_the_cut() {
        assert_eq!(truncate_message("short", 20), "short");
        assert_eq!(truncate_message("0123456789", 5), "0123\u{2026}");
        assert_eq!(truncate_message("anything", 0), "");
    }

    #[test]
    fn truncate_message_does_not_panic_on_a_multibyte_boundary() {
        let s = "\u{1f600}".repeat(5);
        assert_eq!(truncate_message(&s, 3), "\u{1f600}\u{1f600}\u{2026}");
    }

    /// `scroll_offset`/`last_row`/`page_step` all count *entries*. A
    /// message wrapping onto a second row would desync that count from
    /// what is actually on screen, making `PgDn`/`End` skip whole screens
    /// or land mid-message.
    #[test]
    fn a_long_message_is_truncated_not_wrapped_onto_a_second_row() {
        let mut app = App::new();
        let long = "refresh failed source=oisd attempt=3 backoff=30s reason=timeout while=fetching";
        app.logs.entries = vec![dto(LogLevel::Error, "purge_warden::lists::manager", long)];
        let term = draw(&app, 60, 10);
        let buf = term.backend().buffer();
        assert_eq!(
            rows_containing(buf, "ERROR"),
            1,
            "a long message must stay on the entry's single row, not wrap \
             onto a second"
        );
        assert!(
            buffer_contains(buf, "\u{2026}"),
            "a message too wide for the pane must say it was cut"
        );
    }

    #[test]
    fn a_stale_scroll_offset_does_not_blank_the_pane() {
        // A poll that returns a SHORTER page (the operator just narrowed
        // the filter) leaves the offset past the end. Without the clamp,
        // `.skip()` eats every row and the pane reads as "no messages"
        // while entries are present.
        let mut app = App::new();
        app.logs.entries = vec![dto(LogLevel::Info, "purge_warden::x", "still here")];
        app.logs.scroll_offset = 5_000;
        let term = draw(&app, 100, 10);
        assert!(buffer_contains(term.backend().buffer(), "still here"));
    }

    #[test]
    fn the_search_buffer_renders_its_edit_cursor_while_typing() {
        let mut app = App::new();
        app.input_mode = app::InputMode::FilterLogs("refre".into());
        let term = draw(&app, 120, 10);
        assert!(buffer_contains(term.backend().buffer(), "refre_"));
    }

    #[test]
    fn clock_extracts_the_time_and_tolerates_a_surprise() {
        assert_eq!(clock("2026-08-25T14:03:05Z"), "14:03:05");
        // Not the promised shape → render it whole rather than dropping
        // the row or panicking on a slice.
        assert_eq!(clock("whenever"), "whenever");
        assert_eq!(clock("2026-08-25T14"), "2026-08-25T14");
    }

    #[test]
    fn clock_does_not_panic_on_a_multibyte_boundary() {
        // Byte 9 after the `T` falls mid-codepoint here — `find`/`len` are
        // byte offsets, so a naive range index would panic. Mirrors
        // cluster::short_hash_does_not_panic_on_multibyte_boundary.
        let s = "T1234567\u{e9}9";
        assert_eq!(clock(s), s);
    }

    #[test]
    fn short_target_drops_only_the_crate_prefix() {
        assert_eq!(
            short_target("purge_warden::lists::manager"),
            "lists::manager"
        );
        assert_eq!(short_target("some_dep::client"), "some_dep::client");
    }

    #[test]
    fn every_binding_the_leaf_answers_to_has_a_help_row() {
        // Lane A's advisor caught this wave shipping two undocumented
        // bindings while it was deleting 44 aliases for exactly that
        // reason. Asserts on the DATA `?` renders, not on a source grep,
        // so a reworded description still passes and a DELETED row does
        // not.
        let rows = crate::tui::help::per_leaf_rows(crate::tui::app::Leaf::Logs);
        for key in ["Up/Down", "PgUp/PgDn", "Home/End", "/", "f", "R"] {
            assert!(
                rows.iter().any(|r| r.key == key),
                "`{key}` is handled by handle_logs_key but has no help row"
            );
        }
    }

    #[test]
    fn the_severity_chip_cycles_all_four_and_wraps() {
        let mut level = LogsLevelFilter::All;
        let mut seen = Vec::new();
        for _ in 0..4 {
            level = level.next();
            seen.push(level.label());
        }
        assert_eq!(seen, vec!["errors", "warnings", "info", "all"]);
    }

    #[test]
    fn every_chip_but_all_maps_to_one_wire_level() {
        assert_eq!(LogsLevelFilter::All.as_wire(), None);
        assert_eq!(LogsLevelFilter::Error.as_wire(), Some(LogLevel::Error));
        assert_eq!(LogsLevelFilter::Warn.as_wire(), Some(LogLevel::Warn));
        assert_eq!(LogsLevelFilter::Info.as_wire(), Some(LogLevel::Info));
    }
}
