//! Query Log tab — scrollable table with domain/client/blocked/time filters.

use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Cell, Paragraph, Row, Table};
use ratatui::Frame;

use crate::ipc::protocol::QueryLogFileState;
use crate::tui::app::{App, InputMode};
use crate::tui::theme::{self, T};

// ── Sprint 37 §3 D4 frozen empty-state strings ────────────────────
// These four pairs are the universal operator feedback for the Query
// Log tab. They must not drift: any future sprint that changes the
// daemon→TUI protocol extends the enum with new states, it does not
// rewrite these strings.

const EMPTY_DISABLED_LINE1: &str = "Query log disabled.";
const EMPTY_DISABLED_LINE2: &str = "Toggle it in Settings → Tracking, or set `tracking.query_log_enabled = true` in config.toml and run `warden reload`.";

const EMPTY_OK_LINE1: &str = "No queries recorded yet.";
const EMPTY_OK_LINE2: &str = "Waiting for the first DNS lookup from a configured client.";

const EMPTY_MISSING_LINE1: &str = "Query log file not yet created.";
const EMPTY_MISSING_LINE2: &str = "The writer starts on the first query. If this persists, check daemon logs with `journalctl -u purge-warden`.";

const EMPTY_UNREADABLE_LINE1: &str = "Query log unreadable.";
const EMPTY_UNREADABLE_LINE2: &str = "The daemon opened the file but reading failed. Check file permissions at `/var/lib/purge-warden/query.log`.";

// ── §4.5 Sprint 2/2 — CNAME chain block badge ─────────────────────
// Compact label rendered in the RESULT column when a row's
// `cname_chain_via` is populated (i.e. the block fired because a hop
// inside the CNAME chain matched a list/rule/admin-deny, not because
// the apex itself matched). Paired with a `qname → offending` rewrite
// of the DOMAIN cell so the operator sees both names in a single
// glance. Pinned in `tests/frozen_strings_s45_p2.rs`.
pub const CNAME_CHAIN_BLOCK_BADGE: &str = "[CNAME]";

// ── Sprint 47 T2 — footer messages on Enter for non-actionable rows ──
// When the operator presses Enter on a Query Log row whose `result`
// status maps to `inferred_action(...) == None`, the handler does NOT
// open the scope modal. Instead `app.last_error` is set to one of these
// frozen strings so the footer surfaces *why* nothing happened. T5 will
// pin them in `tests/frozen_strings_s47.rs`; do not rephrase.
// See `_docs/features/query_log_quick_action_ux.md` §3 for the full mapping.

/// Footer message when Enter is pressed on a Query Log row whose
/// `result` is `"LOCAL"` (local DNS record). Local records live in the
/// Local DNS tab — they're not filterable from here.
pub const QUERY_NOT_ACTIONABLE_LOCAL: &str = "Local DNS records are managed in the Local DNS tab.";

/// Footer message when Enter is pressed on a Query Log row whose
/// `result` is `"REFUSED"` or `"HINFO"` — a security or protocol check
/// answered it, not the filter, so no allow/deny rule applies.
///
/// The wording deliberately does **not** say "before filtering". Two
/// different sites emit `"REFUSED"`: the pre-query security checks
/// (`handler.rs`, before profile resolution) and the per-`(client, base)`
/// tunneling rate counter, which runs *after* the filter. The old text
/// was false for the second class, and it left the operator with no next
/// step at all — which is how a false positive on a legitimate CDN name
/// became unrecoverable from this screen.
pub const QUERY_NOT_ACTIONABLE_REFUSED: &str =
    "Refused by a security check, not by a filter rule — allow/deny do not apply. \
     False positive? warden security tunneling exempt <domain>";

/// Footer message when Enter is pressed on a Query Log row whose
/// `result` is anything else (unknown future status, empty selection).
/// Future-proof fallback per `_docs/features/query_log_quick_action_ux.md` §3.
pub const QUERY_NOT_ACTIONABLE_UNKNOWN: &str =
    "This query status is not actionable from the Query Log.";

/// Pick the two-line empty-state message keyed on the daemon-reported
/// `logging_enabled` + `file_state` pair. Pure function so the strings
/// are testable in isolation without a `Frame`.
pub fn pick_empty_state_message(
    enabled: bool,
    state: &QueryLogFileState,
) -> (&'static str, &'static str) {
    if !enabled {
        return (EMPTY_DISABLED_LINE1, EMPTY_DISABLED_LINE2);
    }
    match state {
        QueryLogFileState::Ok => (EMPTY_OK_LINE1, EMPTY_OK_LINE2),
        QueryLogFileState::Missing => (EMPTY_MISSING_LINE1, EMPTY_MISSING_LINE2),
        QueryLogFileState::Unreadable => (EMPTY_UNREADABLE_LINE1, EMPTY_UNREADABLE_LINE2),
    }
}

pub fn render(f: &mut Frame, area: Rect, app: &App) {
    // N13 (`_docs/features/tui_nav_and_help_v1.md` §10a): Query Log
    // rejoins the shared filter-card frame. qlog-scan had dropped the
    // frame to hand ~3 rows to the table on the theory that a frame
    // needs 3 rows minimum and this leaf couldn't spare them; N13
    // spends exactly those 3 rows on purpose so all four filterable
    // leaves read as one family. No interior title either way — the
    // per-control labels ("Domain [/]", "Time [t]", …) are self-describing.
    let chunks = Layout::vertical([Constraint::Length(3), Constraint::Min(5)]).split(area);

    render_filters(f, chunks[0], app);
    render_table(f, chunks[1], app);

    // The advanced-search form is a LEAF-local modal, so it renders from
    // the leaf — the same choice `tabs::lists` makes for its own modals,
    // rather than the `ui.rs` overlay stack, which exists for modals
    // reachable from more than one leaf (scope, resolver). Drawn last so
    // it lands over both the card and the table.
    if let Some(modal) = app.query_log.advanced_modal.as_ref() {
        crate::tui::query_log_filter_modal::render_overlay(f, area, modal);
    }
}

/// How many advanced predicates are currently applied. Drives the card's
/// `Adv` chip — an applied filter the operator cannot see is the defect
/// this whole card exists to prevent.
pub(crate) fn advanced_predicate_count(app: &App) -> usize {
    let a = &app.query_log.advanced;
    [a.name.as_ref(), a.ip.as_ref(), a.subnet.as_ref()]
        .into_iter()
        .filter(|v| v.is_some_and(|s| !s.trim().is_empty()))
        .count()
}

fn render_filters(f: &mut Frame, area: Rect, app: &App) {
    let content_area = theme::render_filter_card(f, area);

    let domain_val = match &app.input_mode {
        InputMode::FilterDomain(s) => format!("{s}_"),
        _ => app.query_log.filter_domain.clone().unwrap_or_default(),
    };

    let client_val = match &app.input_mode {
        InputMode::FilterClient(s) => format!("{s}_"),
        _ => app.query_log.filter_client.clone().unwrap_or_default(),
    };

    let blocked_marker = if app.query_log.blocked_only {
        "[x]"
    } else {
        "[ ]"
    };
    let since_label = app.query_log.since.label();

    const LABEL_DOMAIN: &str = "Domain [/]: ";
    const LABEL_CLIENT: &str = "  Client [c]: ";
    const LABEL_TIME: &str = "  Time [t]: [";
    // `Adv` chip. Shows the COUNT, not a checkbox: the operator needs to
    // know an advanced filter is narrowing what they are reading, and
    // "2" says more than "[x]" for the same cells.
    let adv_n = advanced_predicate_count(app);
    let adv_chip = if adv_n > 0 {
        format!("  Adv [f]: {adv_n}")
    } else {
        "  Adv [f]: \u{00b7}".to_string()
    };
    let tail = format!("]  Blocked only [b]: {blocked_marker}");

    // Width budget: the Time/Blocked chips must never scroll off the
    // right edge, so cap each search value to a share of the leftover
    // width — tail-kept so the trailing `_` edit cursor stays visible on
    // a long filter. The `{:<12}` below still min-pads short values,
    // so the normal-width look is unchanged; only a pathologically long
    // value truncates. (qlog-02 template shared with tabs::lists / rules.)
    let base_fixed =
        LABEL_DOMAIN.len() + LABEL_CLIENT.len() + LABEL_TIME.len() + since_label.len() + tail.len();
    // The chip costs cells this row does not comfortably have at 80
    // columns, so it yields — but ONLY while nothing is applied. An
    // ACTIVE advanced filter is never dropped for width: a filter that is
    // narrowing the log while being invisible is strictly worse than a
    // row that runs long. `adv_n > 0` is the whole condition.
    const MIN_FIELD: usize = 11;
    let chip_cells = adv_chip.chars().count();
    let room_for_chip = (content_area.width as usize) >= base_fixed + chip_cells + 2 * MIN_FIELD;
    let adv_shown = if adv_n > 0 || room_for_chip {
        adv_chip.as_str()
    } else {
        ""
    };
    let fixed = base_fixed + adv_shown.chars().count();
    let per_field = ((content_area.width as usize).saturating_sub(fixed) / 2).max(MIN_FIELD);
    let domain_capped = truncate_tail(&domain_val, per_field);
    let client_capped = truncate_tail(&client_val, per_field);

    let domain_shown = format!(
        "{:<12}",
        if domain_capped.is_empty() {
            "___________"
        } else {
            domain_capped.as_str()
        }
    );
    let client_shown = format!(
        "{:<12}",
        if client_capped.is_empty() {
            "___________"
        } else {
            client_capped.as_str()
        }
    );

    // N13: only the value actually being edited turns `T.info` with a
    // trailing `_` cursor — matches Lists/Rules. Query Log used to tint
    // the whole strip on any edit; that stops here.
    let domain_style = match &app.input_mode {
        InputMode::FilterDomain(_) => Style::default().fg(T.info),
        _ => Style::default().fg(T.text_secondary),
    };
    let client_style = match &app.input_mode {
        InputMode::FilterClient(_) => Style::default().fg(T.info),
        _ => Style::default().fg(T.text_secondary),
    };
    let muted = Style::default().fg(T.text_muted);

    let line = Line::from(vec![
        Span::styled(LABEL_DOMAIN, muted),
        Span::styled(domain_shown, domain_style),
        Span::styled(LABEL_CLIENT, muted),
        Span::styled(client_shown, client_style),
        Span::styled(format!("{LABEL_TIME}{since_label}{tail}"), muted),
        // Applied advanced filters take `T.info`, the same tint the card
        // gives a field being edited — it is the one chip whose control
        // lives off-screen, so it has to carry its own "this is on".
        Span::styled(
            adv_shown.to_string(),
            if adv_n > 0 {
                Style::default().fg(T.info)
            } else {
                muted
            },
        ),
    ]);
    f.render_widget(Paragraph::new(line), content_area);
}

/// Char-count truncation keeping the **tail**, with a leading ellipsis.
/// The Filters search fields append-edit at the end (the `_` cursor is the
/// last char), so when a long query exceeds its width budget we keep the
/// trailing window and drop the head — the operator always sees what they
/// are typing. Distinct from `tabs::rules::truncate`, which keeps the head
/// for id/rule labels. UTF-8-correct (counts chars, never byte-slices).
/// Shared by `tabs::lists` and `tabs::rules` filter cards (qlog-02 root).
pub(crate) fn truncate_tail(s: &str, max_chars: usize) -> String {
    let n = s.chars().count();
    if n <= max_chars {
        s.to_string()
    } else if max_chars == 0 {
        String::new()
    } else {
        // Keep the last `max_chars - 1` chars; the ellipsis takes one cell.
        let mut out = String::with_capacity(max_chars);
        out.push('\u{2026}');
        out.extend(s.chars().skip(n - (max_chars - 1)));
        out
    }
}

/// qlog-06: the stable selection key for a log entry — `(timestamp,
/// domain, client_ip)`. Used to re-anchor the cursor to the same row
/// after a 3s poll slides the tail window underneath it.
pub fn entry_key(e: &crate::ipc::protocol::QueryLogDto) -> (String, String, String) {
    (e.timestamp.clone(), e.domain.clone(), e.client_ip.clone())
}

/// Query Log table column headers, post qlog-scan: the standalone DATE
/// column was folded into a relative TIME column, leaving six. Named so
/// the scannable shape is guarded by one in-file assertion
/// (`header_columns_dropped_date_and_kept_time`) instead of a rendered
/// buffer scan that the 80×24 column squeeze would truncate.
pub(crate) const QLOG_HEADERS: [&str; 6] = ["TIME", "CLIENT", "DOMAIN", "TYPE", "RESULT", "RTT"];

fn render_table(f: &mut Frame, area: Rect, app: &App) {
    let block = theme::framed_block_colored(T.text_primary);
    let inner = block.inner(area);
    f.render_widget(block, area);

    let padded_x = inner.x.saturating_add(1);
    let padded_w = inner.width.saturating_sub(2);

    let title_area = Rect {
        x: padded_x,
        y: inner.y,
        width: padded_w,
        height: 1,
    };
    f.render_widget(
        Paragraph::new(Span::styled(
            "Query Log",
            Style::default()
                .fg(T.brand_red)
                .add_modifier(Modifier::BOLD),
        )),
        title_area,
    );

    let content_area = Rect {
        x: padded_x,
        y: inner.y.saturating_add(1),
        width: padded_w,
        height: inner.height.saturating_sub(1),
    };

    if app.query_log.entries.is_empty() {
        let (line1, line2) =
            pick_empty_state_message(app.query_log.logging_enabled, &app.query_log.file_state);
        let is_error = matches!(app.query_log.file_state, QueryLogFileState::Unreadable);
        let is_emphasised = !app.query_log.logging_enabled || is_error;

        let mut line1_style = Style::default().fg(T.text_primary);
        if is_error {
            line1_style = line1_style.fg(T.error);
        }
        if is_emphasised {
            line1_style = line1_style.add_modifier(Modifier::BOLD);
        }

        let paragraph = Paragraph::new(vec![
            Line::from(""),
            Line::from(Span::styled(line1, line1_style)),
            Line::from(""),
            Line::from(Span::styled(line2, Style::default().fg(T.text_secondary))),
        ])
        .alignment(Alignment::Center);
        f.render_widget(paragraph, content_area);
        return;
    }

    let header = Row::new(QLOG_HEADERS.map(Cell::from)).style(
        Style::default()
            .fg(T.brand_red)
            .add_modifier(Modifier::BOLD),
    );

    // qlog-scan: today's UTC date, captured once per render, so each
    // row's TIME cell can show a bare clock for same-day rows and fold
    // the date in for older ones. Both this and the DTO timestamps are
    // UTC, so the `date == today` comparison in `format_log_time` holds.
    let today = {
        use time::macros::format_description;
        const FMT: &[time::format_description::FormatItem<'static>] =
            format_description!("[year]-[month]-[day]");
        time::OffsetDateTime::now_utc()
            .format(&FMT)
            .unwrap_or_default()
    };

    let rows: Vec<Row> = app
        .query_log
        .entries
        .iter()
        .map(|entry| {
            // §4.5 Sprint 2/2: a CNAME chain block surfaces with two
            // changes from the standard BLOCKED row:
            //   - DOMAIN cell: `qname → offending` (U+2192 RIGHTWARDS
            //     ARROW) so the operator sees the apex AND the offending
            //     hop in a single glance, no detail panel needed.
            //   - RESULT cell: `[CNAME]` instead of `BLOCKED` so the
            //     row reads at a glance as a chain block (still red).
            // Pinned via `tests/frozen_strings_s45_p2.rs` so a future
            // rename of the badge silently can't reshape the audit view.
            let chain_via = entry.cname_chain_via.as_deref();
            // qlog-scan: the RESULT text is the CNAME badge for a chain
            // block, else the raw status; its colour now comes from the
            // tri-colour severity bucket (red = blocked, amber = degraded,
            // grey = clean serve) instead of the old red/green split.
            let badge_text = if chain_via.is_some() {
                CNAME_CHAIN_BLOCK_BADGE
            } else {
                entry.result.as_str()
            };
            let badge_style = severity_style(result_severity(&entry.result, chain_via.is_some()));

            let time_str = format_log_time(&entry.timestamp, &today);
            let rtt_str = format_response_time(entry.response_time_us);

            let domain_cell = match chain_via {
                Some(via) => format!("{} \u{2192} {}", entry.domain, via),
                None => entry.domain.clone(),
            };

            Row::new(vec![
                Cell::from(time_str),
                Cell::from(
                    entry
                        .client_name
                        .as_deref()
                        .unwrap_or(&entry.client_ip)
                        .to_string(),
                ),
                Cell::from(domain_cell),
                Cell::from(entry.query_type.clone()),
                Cell::from(Span::styled(badge_text, badge_style)),
                Cell::from(rtt_str),
            ])
        })
        .collect();

    // Column constraints — `domain` is the sole flexible (Min) column
    // and absorbs leftover width. The same array feeds both the Table
    // and the separator helper so the two layouts cannot diverge.
    // qlog-scan: DATE(10)+CLOCK(8) merged into a single TIME(11) column
    // (fits `MM-DD HH:MM`); the reclaimed width goes to CLIENT (16→20)
    // and, via the flex column, to DOMAIN.
    const TIME_W: u16 = 11;
    const CLIENT_W: u16 = 20;
    const TYPE_W: u16 = 6;
    const RESULT_W: u16 = 8;
    const RTT_W: u16 = 8;
    const COLUMN_SPACING: u16 = 3;

    let constraints = [
        Constraint::Length(TIME_W),
        Constraint::Length(CLIENT_W),
        Constraint::Min(20), // domain (flexible)
        Constraint::Length(TYPE_W),
        Constraint::Length(RESULT_W),
        Constraint::Length(RTT_W),
    ];

    let table = Table::new(rows, constraints)
        .header(header)
        .column_spacing(COLUMN_SPACING)
        .row_highlight_style(theme::highlight_style());

    // qlog-06: resolve the operator's stable entry key to the current
    // index so the highlight follows the row across the sliding tail
    // instead of staying on a fixed slot that now holds a different entry.
    let mut table_state = app.query_log.table_state.clone();
    if let Some(idx) = crate::tui::app::resolve_row_index(
        &app.query_log.entries,
        app.query_log.selected_key.as_ref(),
        |e| Some(entry_key(e)),
    ) {
        table_state.select(Some(idx));
    }
    f.render_stateful_widget(table, content_area, &mut table_state);

    // qlog-05: paint the inter-column separators by re-running ratatui's
    // own column layout (`draw_table_column_separators`) on the same
    // constraints the Table used, instead of hand-deriving x-positions
    // from the fixed widths. The manual derivation assumed a single flex
    // column absorbs all leftover width, but the solver squeezes the
    // trailing Length columns when the content rect is narrow — at the
    // documented 80x24 minimum (a 76-cell content rect) the hand-drawn
    // separators diverged from the real column edges and painted through
    // the TYPE/RESULT/RTT text.
    crate::tui::ui::draw_table_column_separators(f, content_area, &constraints, COLUMN_SPACING);
}

/// Compact per-row timestamp for the merged TIME column (qlog-scan: the
/// standalone DATE column was folded in here). `ts` is the ISO-8601 UTC
/// stamp (`2026-04-08T15:32:01Z`); `today` is the current UTC date
/// (`YYYY-MM-DD`, same source as the DTO's date substring) captured once
/// per render. Same-day rows show the wall clock `HH:MM:SS`; older rows
/// fold the day in as `MM-DD HH:MM` — day + minute places an old row and
/// keeps the cell within the 11-cell column. Pure so the mapping is
/// unit-testable without a clock; a malformed stamp degrades to a head
/// slice rather than panicking or blanking.
pub(crate) fn format_log_time(ts: &str, today: &str) -> String {
    let trimmed = ts.trim_end_matches('Z');
    let Some((date, time)) = trimmed.split_once('T') else {
        return trimmed.chars().take(8).collect();
    };
    if date == today {
        // HH:MM:SS
        time.chars().take(8).collect()
    } else {
        // `YYYY-MM-DD` → `MM-DD` (drop the `YYYY-`); `HH:MM:SS…` → `HH:MM`.
        let month_day = date.get(5..).unwrap_or(date);
        let hour_min: String = time.chars().take(5).collect();
        format!("{month_day} {hour_min}")
    }
}

/// Severity bucket a Query Log `result` maps to for the RESULT cell's
/// colour (qlog-scan). Colour carries severity only — the old
/// green-everything wall told the operator nothing at a glance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ResultSeverity {
    /// The query was stopped. Red. — `BLOCKED`, CNAME-chain block.
    Blocked,
    /// Served, but degraded. Amber. — `STALE` (expired cache served),
    /// `REFUSED` (declined before filtering).
    Degraded,
    /// Clean serve. No accent colour (grey). — `ALLOWED` / `CACHED` /
    /// `LOCAL`, plus any unknown future status.
    Clean,
}

/// Map a `result` status (+ the CNAME-chain flag) to its severity bucket.
/// `is_cname_chain` forces `Blocked` even when `result` is not the literal
/// `"BLOCKED"` — a chain block reports the offending hop and renders the
/// `[CNAME]` badge, but it is still a block. Pure + `Clean`-by-default so a
/// new daemon status is grey, never miscoloured red/amber.
pub(crate) fn result_severity(result: &str, is_cname_chain: bool) -> ResultSeverity {
    if is_cname_chain {
        return ResultSeverity::Blocked;
    }
    match result {
        "BLOCKED" => ResultSeverity::Blocked,
        "STALE" | "REFUSED" => ResultSeverity::Degraded,
        // ALLOWED / CACHED / LOCAL / HINFO / unknown future status
        _ => ResultSeverity::Clean,
    }
}

/// Style for a severity bucket. Split from `result_severity` so the
/// mapping stays a pure string→enum fn (testable without a theme).
fn severity_style(sev: ResultSeverity) -> Style {
    match sev {
        ResultSeverity::Blocked => Style::default().fg(T.error),
        ResultSeverity::Degraded => Style::default().fg(T.warning),
        ResultSeverity::Clean => Style::default().fg(T.text_secondary),
    }
}

fn format_response_time(us: u64) -> String {
    if us >= 1_000_000 {
        format!("{:.1}s", us as f64 / 1_000_000.0)
    } else if us >= 1_000 {
        format!("{:.1}ms", us as f64 / 1_000.0)
    } else {
        format!("{us}us")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // qlog-05 — separators are painted by re-running ratatui's Table
    // column solver on the same zero-origin rect the Table uses, so they
    // land in the inter-column gaps even at the documented 80x24 minimum
    // where the flex DOMAIN column can't reach its Min(20) and the
    // trailing columns are squeezed. The old hand-derived x-positions
    // assumed full-width columns and overdrew the squeezed text. Column
    // titles legitimately truncate under the squeeze (RESULT → RESU);
    // what must hold is that a separator never lands on column *content*.
    #[test]
    fn separators_only_paint_into_column_gaps_at_80x24() {
        use crate::ipc::protocol::QueryLogDto;
        use ratatui::backend::TestBackend;
        use ratatui::layout::{Constraint, Rect};
        use ratatui::widgets::{Cell, Row, Table};
        use ratatui::Terminal;

        let mut app = App::new();
        app.query_log.entries = vec![QueryLogDto {
            timestamp: "2026-06-14T12:00:00Z".to_string(),
            client_ip: "10.0.0.2".to_string(),
            client_name: None,
            domain: "example.com".to_string(),
            query_type: "A".to_string(),
            result: "BLOCKED".to_string(),
            response_time_us: 1200,
            cname_chain_via: None,
        }];

        // Real render path: table + separator overlay.
        let mut term = Terminal::new(TestBackend::new(80, 24)).unwrap();
        term.draw(|f| render_table(f, f.area(), &app)).unwrap();
        let with = term.backend().buffer().clone();

        // A bare Table with identical constraints + spacing, no separator
        // overlay, rendered into the same content rect. Its column
        // geometry (hence its inter-column gap cells) matches the real
        // table, with every column cell filled so a misplaced separator
        // would land on a non-space glyph. content_area in render_table
        // is (x=2, y=2, …): frame border + "Query Log" title row.
        let constraints = [
            Constraint::Length(11),
            Constraint::Length(20),
            Constraint::Min(20),
            Constraint::Length(6),
            Constraint::Length(8),
            Constraint::Length(8),
        ];
        let filled = ["WWWWWWWWWWWWWWWWWWWWWW"; 6];
        let bare = Table::new(vec![Row::new(filled.map(Cell::from)); 6], constraints)
            .header(Row::new(filled.map(Cell::from)))
            .column_spacing(3);
        let mut term2 = Terminal::new(TestBackend::new(80, 24)).unwrap();
        term2
            .draw(|f| f.render_widget(bare, Rect::new(2, 2, 76, 8)))
            .unwrap();
        let bare_buf = term2.backend().buffer().clone();

        let mut sep_count = 0;
        for y in 2..9u16 {
            for x in 2..78u16 {
                if with[(x, y)].symbol() == "\u{2502}" {
                    sep_count += 1;
                    assert_eq!(
                        bare_buf[(x, y)].symbol(),
                        " ",
                        "separator at ({x},{y}) overwrote column content, not a gap"
                    );
                }
            }
        }
        assert!(
            sep_count >= 5,
            "expected the five column separators to be drawn (got {sep_count})"
        );
    }

    // Byte-for-byte pin on the Sprint 37 §3 D4 frozen strings. Any
    // edit to the four pairs below must come with a design-doc update
    // in `_docs/features/query_log_ux_fix.md` §3 D4 — CT operators rely on
    // these to diagnose the four distinct failure modes.
    #[test]
    fn pick_empty_state_message_covers_all_four_combinations() {
        assert_eq!(
            pick_empty_state_message(false, &QueryLogFileState::Ok),
            (
                "Query log disabled.",
                "Toggle it in Settings → Tracking, or set `tracking.query_log_enabled = true` in config.toml and run `warden reload`.",
            )
        );
        // `false` + any state collapses to the disabled message —
        // proving the file_state is ignored when the flag is off.
        assert_eq!(
            pick_empty_state_message(false, &QueryLogFileState::Missing),
            pick_empty_state_message(false, &QueryLogFileState::Ok)
        );
        assert_eq!(
            pick_empty_state_message(false, &QueryLogFileState::Unreadable),
            pick_empty_state_message(false, &QueryLogFileState::Ok)
        );

        assert_eq!(
            pick_empty_state_message(true, &QueryLogFileState::Ok),
            (
                "No queries recorded yet.",
                "Waiting for the first DNS lookup from a configured client.",
            )
        );
        assert_eq!(
            pick_empty_state_message(true, &QueryLogFileState::Missing),
            (
                "Query log file not yet created.",
                "The writer starts on the first query. If this persists, check daemon logs with `journalctl -u purge-warden`.",
            )
        );
        assert_eq!(
            pick_empty_state_message(true, &QueryLogFileState::Unreadable),
            (
                "Query log unreadable.",
                "The daemon opened the file but reading failed. Check file permissions at `/var/lib/purge-warden/query.log`.",
            )
        );
    }

    // ── Sprint 41 / 41.1: SincePreset cycle + as_secs mapping ─────
    //
    // The S41 `filter_hint_line_is_frozen` test was retired in S41.1
    // together with the inline hint row — the hints live in the global
    // footer now (`ui.rs::footer_hints_for`), pinned by
    // `footer_hints_for_query_log_tab_carries_all_five_keys` there.

    #[test]
    fn since_preset_cycle_wraps_through_four_states() {
        use crate::tui::app::SincePreset;
        assert_eq!(SincePreset::Off.next(), SincePreset::LastHour);
        assert_eq!(SincePreset::LastHour.next(), SincePreset::Last6Hours);
        assert_eq!(SincePreset::Last6Hours.next(), SincePreset::Last24Hours);
        assert_eq!(SincePreset::Last24Hours.next(), SincePreset::Off);
    }

    #[test]
    fn since_preset_as_secs_matches_labels() {
        use crate::tui::app::SincePreset;
        assert_eq!(SincePreset::Off.as_secs(), None);
        assert_eq!(SincePreset::LastHour.as_secs(), Some(3_600));
        assert_eq!(SincePreset::Last6Hours.as_secs(), Some(21_600));
        assert_eq!(SincePreset::Last24Hours.as_secs(), Some(86_400));
    }

    // ── qlog-scan: merged TIME column formatting ──────────────────────

    #[test]
    fn format_log_time_same_day_shows_clock_only() {
        // Same UTC day → bare wall clock, seconds kept.
        assert_eq!(
            format_log_time("2026-04-08T15:32:01Z", "2026-04-08"),
            "15:32:01"
        );
    }

    #[test]
    fn format_log_time_older_folds_in_month_day() {
        // Different day → `MM-DD HH:MM`, seconds dropped, year never shown.
        assert_eq!(
            format_log_time("2026-04-07T09:05:59Z", "2026-04-08"),
            "04-07 09:05"
        );
        // A prior-year stamp still renders `MM-DD HH:MM` (no year leaks in).
        assert_eq!(
            format_log_time("2025-12-31T23:59:00Z", "2026-04-08"),
            "12-31 23:59"
        );
    }

    #[test]
    fn format_log_time_malformed_stamp_degrades_to_head_slice() {
        // No `T` separator → a deterministic 8-char head, never a panic
        // or a blank cell.
        assert_eq!(format_log_time("not-a-timestamp", "2026-04-08"), "not-a-ti");
    }

    // ── qlog-scan: RESULT tri-colour severity mapping ─────────────────

    #[test]
    fn result_severity_blocked_bucket() {
        assert_eq!(result_severity("BLOCKED", false), ResultSeverity::Blocked);
        // A CNAME-chain block forces Blocked even though result != "BLOCKED".
        assert_eq!(result_severity("ALLOWED", true), ResultSeverity::Blocked);
    }

    #[test]
    fn result_severity_degraded_bucket() {
        assert_eq!(result_severity("STALE", false), ResultSeverity::Degraded);
        assert_eq!(result_severity("REFUSED", false), ResultSeverity::Degraded);
    }

    #[test]
    fn result_severity_clean_bucket_and_unknown_fallback() {
        for r in ["ALLOWED", "CACHED", "LOCAL", "HINFO"] {
            assert_eq!(
                result_severity(r, false),
                ResultSeverity::Clean,
                "{r} should be a clean (grey) serve"
            );
        }
        // An unknown future status must fall to Clean — never miscoloured.
        assert_eq!(
            result_severity("FUTURE_STATUS", false),
            ResultSeverity::Clean
        );
    }

    // ── qlog-scan: table shape — DATE folded into TIME ────────────────

    #[test]
    fn header_columns_dropped_date_and_kept_time() {
        assert_eq!(
            QLOG_HEADERS,
            ["TIME", "CLIENT", "DOMAIN", "TYPE", "RESULT", "RTT"]
        );
        assert!(
            !QLOG_HEADERS.contains(&"DATE"),
            "the standalone DATE column must stay folded into TIME"
        );
    }
}
