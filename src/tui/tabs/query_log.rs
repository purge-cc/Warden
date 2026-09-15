//! Query Log tab — scrollable table with domain/client/blocked/time filters.
//!
//! ## Not here
//! - Keys:  `mod.rs::handle_query_log_key`
//! - Form:  `tui::query_log_filter_modal` (the advanced-filter popup)
//! - State: `app::QueryLogState` (`selected_key`, the filter fields, paging cursors)
//! - Tests: render + pure fns here; key handling in `tui/tests/`, declared from `mod.rs`

use ratatui::layout::{Alignment, Constraint, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Cell, Paragraph, Row, Table};
use ratatui::Frame;

use crate::ipc::protocol::QueryLogFileState;
use crate::tui::app::{App, InputMode};
use crate::tui::theme::{self, T};

// ── Frozen empty-state strings ──────────────────────────────────────
// These four pairs are the universal operator feedback for the Query
// Log tab. They must not drift: a future protocol change that extends
// the enum with new states adds to these strings, it does not rewrite
// them.

const EMPTY_DISABLED_LINE1: &str = "Query log disabled.";
const EMPTY_DISABLED_LINE2: &str = "Toggle it in Settings → Tracking, or set `tracking.query_log_enabled = true` in config.toml and run `warden reload`.";

const EMPTY_OK_LINE1: &str = "No queries recorded yet.";
const EMPTY_OK_LINE2: &str = "Waiting for the first DNS lookup from a configured client.";

const EMPTY_MISSING_LINE1: &str = "Query log file not yet created.";
const EMPTY_MISSING_LINE2: &str = "The writer starts on the first query. If this persists, check daemon logs with `journalctl -u purge-warden`.";

const EMPTY_UNREADABLE_LINE1: &str = "Query log unreadable.";
const EMPTY_UNREADABLE_LINE2: &str = "The daemon opened the file but reading failed. Check file permissions at `/var/lib/purge-warden/query.log`.";

// ── CNAME chain block badge ─────────────────────────────────────────
// Compact label rendered in the RESULT column when a row's
// `cname_chain_via` is populated (i.e. the block fired because a hop
// inside the CNAME chain matched a list/rule/admin-deny, not because
// the apex itself matched). Paired with a `qname → offending` rewrite
// of the DOMAIN cell so the operator sees both names in a single
// glance. Pinned in `tests/frozen_strings_s45_p2.rs`.
pub const CNAME_CHAIN_BLOCK_BADGE: &str = "[CNAME]";

// ── Footer messages on Enter for non-actionable rows ─────────────────
// When the operator presses Enter on a Query Log row whose `result`
// status maps to `inferred_action(...) == None`, the handler does NOT
// open the rule picker. Instead `app.last_error` is set to one of these
// frozen strings so the footer surfaces *why* nothing happened. Pinned
// in `tests/frozen_strings_s47.rs`; do not rephrase.

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
/// Future-proof fallback for a status this leaf does not yet know how
/// to act on.
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

pub fn render(f: &mut Frame, area: Rect, app: &mut App) {
    let table_area = crate::tui::filter_chips::render_card(f, area, app);
    let body = super::super::ui::render_card(
        f,
        table_area,
        "Query Log",
        &table_subtitle(app),
        theme::CardRole::Analytics,
    );
    render_table(f, body, app);

    // The advanced-search form is a LEAF-local modal, so it renders from
    // the leaf — the same choice `tabs::lists` makes for its own modals,
    // rather than the `ui.rs` overlay stack, which exists for modals
    // reachable from more than one leaf (the rule picker, resolver). Drawn last so
    // it lands over both the card and the table.
    if let Some(modal) = app.query_log.advanced_modal.as_ref() {
        crate::tui::query_log_filter_modal::render_overlay(f, area, modal);
    }
    let picker_reads = crate::tui::query_log_client_picker::PickerReadState {
        devices_loading: app
            .read_jobs
            .as_ref()
            .is_some_and(|jobs| jobs.is_loading(crate::tui::jobs::ReadResource::Devices)),
        devices_error: app
            .read_jobs
            .as_ref()
            .and_then(|jobs| jobs.error(crate::tui::jobs::ReadResource::Devices)),
        status_loading: app
            .read_jobs
            .as_ref()
            .is_some_and(|jobs| jobs.is_loading(crate::tui::jobs::ReadResource::Status)),
        status_error: app
            .read_jobs
            .as_ref()
            .and_then(|jobs| jobs.error(crate::tui::jobs::ReadResource::Status)),
        exact_client_ips_supported: app
            .daemon_status
            .as_ref()
            .map(|status| status.query_log_client_ips_supported),
    };
    let domain_anchor = crate::tui::filter_chips::chip_area(area, app, 0);
    let client_anchor = crate::tui::filter_chips::chip_area(area, app, 1);
    let period_anchor = crate::tui::filter_chips::chip_area(area, app, 2);
    if let Some(picker) = app.query_log.client_picker.as_mut() {
        crate::tui::query_log_client_picker::render(
            f,
            area,
            client_anchor,
            picker,
            app.device_view.as_ref(),
            picker_reads,
        );
    }
    if let Some(detail) = app.query_log.detail.as_mut() {
        crate::tui::query_log_detail::render(f, area, detail);
    }
    if let InputMode::FilterDomain(draft) = &app.input_mode {
        crate::tui::query_log_controls::render_domain(
            f,
            area,
            domain_anchor,
            draft,
            app.query_log.domain_focus,
        );
    }
    if app.query_log.period_menu {
        crate::tui::query_log_controls::render_period(
            f,
            area,
            period_anchor,
            app.query_log.period_draft,
            app.query_log.period_focus,
        );
    }
}

fn table_subtitle(app: &App) -> String {
    let total = app.query_log.entries.len();
    let blocked = app
        .query_log
        .entries
        .iter()
        .filter(|entry| entry.result == "BLOCKED" || entry.cname_chain_via.is_some())
        .count();
    format!("{total} of {total} Requests · {blocked} Blocked · Newest First · UTC")
}

/// Small UI integration seam: overlays rendered by this leaf are not in the
/// global modal stack, so the shell can suppress a toast/footer that would
/// cover their focused control.
pub(crate) fn overlay_open(app: &App) -> bool {
    matches!(app.input_mode, InputMode::FilterDomain(_))
        || app.query_log.client_picker.is_some()
        || app.query_log.detail.is_some()
        || app.query_log.period_menu
        || app.query_log.advanced_modal.is_some()
}

/// Contextual compact legend for the root footer. The shell owns the actual
/// spans/width elision; this leaf owns which keys are meaningful right now.
pub(crate) fn footer_hint(app: &App) -> &'static str {
    if matches!(app.input_mode, InputMode::FilterDomain(_)) {
        "Tab focus · Enter apply · Esc discard · Ctrl+U clear"
    } else if let Some(picker) = app.query_log.client_picker.as_ref() {
        picker.footer_hint()
    } else if app.query_log.detail.is_some() {
        "Up/Down scroll · Esc close"
    } else if app.query_log.period_menu {
        "Up/Down choose · Enter apply · Esc cancel"
    } else if app.query_log.advanced_modal.is_some() {
        "Tab focus · Enter apply · Esc cancel"
    } else if app.filter_focus.is_some() {
        "Tab/Shift+Tab chip · Enter edit · Del clear · Esc table"
    } else {
        "f filters · Enter allow/deny · i details · ↑/↓ select"
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

/// Char-count truncation keeping the **tail**, with a leading ellipsis.
/// The Filters search fields append-edit at the end (the `_` cursor is the
/// last char), so when a long query exceeds its width budget we keep the
/// trailing window and drop the head — the operator always sees what they
/// are typing. Distinct from `tabs::rules::truncate`, which keeps the head
/// for id/rule labels. UTF-8-correct (counts chars, never byte-slices).
/// Shared by `tabs::lists` and `tabs::rules` filter cards (qlog-02 root).
pub(crate) fn truncate_tail(s: &str, max_chars: usize) -> String {
    crate::tui::text::fit_tail(s, max_chars)
}

/// Re-anchor to the same complete record when polling shifts the page.
/// Timestamp/domain/IP alone collide for semantically different requests.
pub fn entry_key(e: &crate::ipc::protocol::QueryLogDto) -> crate::tui::app::QueryLogEntryKey {
    crate::tui::app::QueryLogEntryKey(
        e.timestamp.clone(),
        e.domain.clone(),
        e.client_ip.clone(),
        e.client_name.clone(),
        e.query_type.clone(),
        e.result.clone(),
        e.response_time_us,
        e.cname_chain_via.clone(),
    )
}

/// Query Log table column headers: the standalone DATE
/// column is folded into a relative TIME column, leaving six. Named so
/// the scannable shape is guarded by one in-file assertion
/// (`header_columns_dropped_date_and_kept_time`) instead of a rendered
/// buffer scan that the 80×24 column squeeze would truncate.
pub(crate) const QLOG_HEADERS: [&str; 6] = ["TIME", "CLIENT", "DOMAIN", "TYPE", "RESULT", "RTT"];

fn render_table(f: &mut Frame, content_area: Rect, app: &mut App) {
    if app.query_log.entries.is_empty() {
        if app.query_log.read_failed {
            f.render_widget(
                Paragraph::new("Query log read failed. Check daemon connection and try r.")
                    .alignment(Alignment::Center)
                    .style(Style::default().fg(T.error)),
                content_area,
            );
            return;
        }
        if !app.query_log.has_loaded {
            f.render_widget(
                Paragraph::new("Loading Query Log…")
                    .alignment(Alignment::Center)
                    .style(Style::default().fg(T.text_secondary)),
                content_area,
            );
            return;
        }
        if app.query_log.logging_enabled
            && matches!(app.query_log.file_state, QueryLogFileState::Ok)
            && app.query_log.has_active_filters()
        {
            f.render_widget(
                Paragraph::new(vec![
                    Line::from("No requests match the filters."),
                    Line::from(
                        "Press f, choose a chip, and use Delete to clear it; Reset All clears every filter.",
                    ),
                ])
                .alignment(Alignment::Center)
                .style(Style::default().fg(T.text_secondary)),
                content_area,
            );
            return;
        }
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

        let mut lines: Vec<Line> = crate::tui::text::wrap(line1, content_area.width as usize)
            .into_iter()
            .map(|line| Line::styled(line, line1_style))
            .collect();
        lines.push(Line::from(""));
        lines.extend(
            crate::tui::text::wrap(line2, content_area.width as usize)
                .into_iter()
                .map(|line| Line::styled(line, Style::default().fg(T.text_secondary))),
        );
        let paragraph = Paragraph::new(lines).alignment(Alignment::Center);
        f.render_widget(paragraph, content_area);
        return;
    }

    let header = Row::new(QLOG_HEADERS.map(Cell::from)).style(theme::table_heading_style(false));

    // Today's UTC date, captured once per render, so each
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

    let (constraints, spacing, widths) = table_columns(content_area.width);
    let rows: Vec<Row> = app
        .query_log
        .entries
        .iter()
        .map(|entry| {
            // A CNAME chain block surfaces with two
            // changes from the standard BLOCKED row:
            //   - DOMAIN cell: `qname → offending` (U+2192 RIGHTWARDS
            //     ARROW) so the operator sees the apex AND the offending
            //     hop in a single glance, no detail panel needed.
            //   - RESULT cell: `[CNAME]` instead of `BLOCKED` so the
            //     row reads at a glance as a chain block (still red).
            // Pinned via `tests/frozen_strings_s45_p2.rs` so a future
            // rename of the badge silently can't reshape the audit view.
            let chain_via = entry.cname_chain_via.as_deref();
            // The RESULT text is the CNAME badge for a chain
            // block, else the raw status; its colour comes from the
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
                Cell::from(crate::tui::text::fit(&time_str, widths[0] as usize)),
                Cell::from(crate::tui::text::fit(
                    entry.client_name.as_deref().unwrap_or(&entry.client_ip),
                    widths[1] as usize,
                )),
                Cell::from(crate::tui::text::fit(&domain_cell, widths[2] as usize)),
                Cell::from(crate::tui::text::fit(&entry.query_type, widths[3] as usize)),
                Cell::from(Span::styled(
                    crate::tui::text::fit(badge_text, widths[4] as usize),
                    badge_style,
                )),
                Cell::from(crate::tui::text::fit(&rtt_str, widths[5] as usize)),
            ])
        })
        .collect();

    let table = Table::new(rows, constraints)
        .header(header)
        .column_spacing(spacing)
        .row_highlight_style(theme::highlight_style());

    // qlog-06: resolve the operator's stable entry key to the current
    // index so the highlight follows the row across the sliding tail
    // instead of staying on a fixed slot that now holds a different entry.
    // Falls back to the already-selected row when the key doesn't resolve
    // (e.g. no key seeded yet) rather than clearing the cursor.
    let selected = crate::tui::app::resolve_row_index(
        &app.query_log.entries,
        app.query_log.selected_key.as_ref(),
        |e| Some(entry_key(e)),
    )
    .or_else(|| app.query_log.table_state.selected());
    super::render_table(
        f,
        content_area,
        table,
        &mut app.query_log.table_state,
        selected,
    );

    // qlog-05: paint the inter-column separators by re-running ratatui's
    // own column layout (`draw_table_column_separators`) on the same
    // constraints the Table used, instead of hand-deriving x-positions
    // from the fixed widths. The manual derivation assumed a single flex
    // column absorbs all leftover width, but the solver squeezes the
    // trailing Length columns when the content rect is narrow — at the
    // documented 80x24 minimum (a 76-cell content rect) the hand-drawn
    // separators diverged from the real column edges and painted through
    // the TYPE/RESULT/RTT text.
    crate::tui::ui::draw_table_column_separators(f, content_area, &constraints, spacing);
    app.query_log.visible_rows = usize::from(content_area.height.saturating_sub(1)).max(1);
    let offset = app.query_log.table_state.offset();
    for row in 0..content_area.height.saturating_sub(1) {
        let index = offset + row as usize;
        if index >= app.query_log.entries.len() {
            break;
        }
        super::super::mouse::register(
            app,
            Rect::new(
                content_area.x,
                content_area.y + 1 + row,
                content_area.width,
                1,
            ),
            super::super::mouse::MouseAction::Row(super::super::app::Leaf::QueryLog, index),
        );
    }
}

/// Six columns never disappear. Compact widths total 70 cells including five
/// one-cell gaps, leaving the domain at least 20 cells at the 80×24 floor.
fn table_columns(width: u16) -> ([Constraint; 6], u16, [u16; 6]) {
    let compact = width < 100;
    let wide = width >= 140;
    let spacing = if compact { 1 } else { 2 };
    let client = if compact {
        12
    } else if wide {
        32
    } else {
        20
    };
    let fixed = 11 + client + 6 + 8 + 8 + 5 * spacing;
    let domain = width
        .saturating_sub(fixed)
        .max(if compact { 20 } else { 24 });
    (
        [
            Constraint::Length(11),
            Constraint::Length(client),
            Constraint::Length(domain),
            Constraint::Length(6),
            Constraint::Length(8),
            Constraint::Length(8),
        ],
        spacing,
        [11, client, domain, 6, 8, 8],
    )
}

/// Compact per-row timestamp for the merged TIME column (the
/// standalone DATE column is folded in here). `ts` is the ISO-8601 UTC
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
/// colour. Colour carries severity only — the old
/// green-everything wall told the operator nothing at a glance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ResultSeverity {
    /// The query was stopped. Red. — `BLOCKED`, CNAME-chain block.
    Blocked,
    /// Served, but degraded. Amber. — `STALE` (expired cache served),
    /// `REFUSED` (declined by a security check).
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

    #[test]
    fn responsive_six_columns_keep_compact_contract_at_80_floor() {
        let (_constraints, spacing, widths) = table_columns(76);
        assert_eq!(spacing, 1);
        assert_eq!(widths, [11, 12, 26, 6, 8, 8]);
        assert_eq!(widths.iter().sum::<u16>() + 5 * spacing, 76);

        let (_constraints, spacing, widths) = table_columns(140);
        assert_eq!(spacing, 2);
        assert_eq!(widths[0], 11);
        assert_eq!(widths[1], 32);
        assert_eq!(widths[3..], [6, 8, 8]);
    }

    #[test]
    fn tail_truncation_uses_display_cells_and_keeps_graphemes() {
        let clipped = truncate_tail("cafe\u{301}-端末.example", 8);
        assert!(crate::tui::text::width(&clipped) <= 8);
        assert!(!clipped.contains('\u{fffd}'));
        assert!(clipped.starts_with('…'));
    }

    #[test]
    fn active_filter_empty_state_is_distinct_from_first_collection() {
        let mut state = crate::tui::app::QueryLogState::default();
        assert!(!state.has_active_filters());
        state.client_ips.push("192.0.2.1".into());
        assert!(state.has_active_filters());
        state.client_ips.clear();
        state.since = crate::tui::app::SincePreset::LastHour;
        assert!(state.has_active_filters());
    }

    #[test]
    fn table_subtitle_reports_loaded_and_blocked_counts_in_utc() {
        let mut app = App::new();
        let entry =
            |result: &str, cname_chain_via: Option<&str>| crate::ipc::protocol::QueryLogDto {
                timestamp: "2026-09-13T12:00:00Z".into(),
                client_ip: "192.0.2.1".into(),
                client_name: Some("client".into()),
                domain: "example.test".into(),
                query_type: "A".into(),
                result: result.into(),
                response_time_us: 10,
                cname_chain_via: cname_chain_via.map(str::to_owned),
            };
        app.query_log.entries = vec![
            entry("BLOCKED", None),
            entry("ALLOWED", None),
            entry("ALLOWED", Some("blocked-hop.example")),
        ];
        assert_eq!(
            table_subtitle(&app),
            "3 of 3 Requests · 2 Blocked · Newest First · UTC"
        );
    }

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
        use ratatui::layout::Rect;
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
        term.draw(|f| render_table(f, f.area(), &mut app)).unwrap();
        let with = term.backend().buffer().clone();

        // A bare Table with identical constraints + spacing, no separator
        // overlay, rendered into the same content rect. Its column
        // geometry (hence its inter-column gap cells) matches the real
        // table, with every column cell filled so a misplaced separator
        // would land on a non-space glyph. content_area in render_table
        // is (x=2, y=2, …): frame border + "Query Log" title row.
        let (constraints, spacing, _) = table_columns(80);
        let filled = ["WWWWWWWWWWWWWWWWWWWWWW"; 6];
        let bare = Table::new(vec![Row::new(filled.map(Cell::from)); 6], constraints)
            .header(Row::new(filled.map(Cell::from)))
            .column_spacing(spacing);
        let mut term2 = Terminal::new(TestBackend::new(80, 24)).unwrap();
        term2
            .draw(|f| f.render_widget(bare, Rect::new(0, 0, 80, 8)))
            .unwrap();
        let bare_buf = term2.backend().buffer().clone();

        let mut sep_count = 0;
        for y in 0..7u16 {
            for x in 0..80u16 {
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

    // Byte-for-byte pin on the frozen strings. CT operators rely on
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

    // ── SincePreset cycle + as_secs mapping ───────────────────────────
    //
    // `filter_hint_line_is_frozen` was retired together with the
    // inline hint row — the hints live in the global footer now
    // (`ui.rs::footer_hints_for`), pinned by
    // `footer_hints_for_query_log_tab_carries_all_five_keys` there.

    #[test]
    fn since_preset_cycle_wraps_through_all_five_states() {
        use crate::tui::app::SincePreset;
        assert_eq!(SincePreset::Off.next(), SincePreset::LastHour);
        assert_eq!(SincePreset::LastHour.next(), SincePreset::Last3Hours);
        assert_eq!(SincePreset::Last3Hours.next(), SincePreset::Last6Hours);
        assert_eq!(SincePreset::Last6Hours.next(), SincePreset::Last24Hours);
        assert_eq!(SincePreset::Last24Hours.next(), SincePreset::Off);
    }

    #[test]
    fn since_preset_as_secs_matches_labels() {
        use crate::tui::app::SincePreset;
        assert_eq!(SincePreset::Off.as_secs(), None);
        assert_eq!(SincePreset::LastHour.as_secs(), Some(3_600));
        assert_eq!(SincePreset::Last3Hours.as_secs(), Some(10_800));
        assert_eq!(SincePreset::Last6Hours.as_secs(), Some(21_600));
        assert_eq!(SincePreset::Last24Hours.as_secs(), Some(86_400));
    }

    // ── Merged TIME column formatting ───────────────────────────────

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

    // ── RESULT tri-colour severity mapping ──────────────────────────

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

    // ── Table shape — DATE folded into TIME ─────────────────────────

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
