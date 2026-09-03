//! Subnets tab — master/detail view of configured + discovered subnets.
//!
//! The left list mixes configured subnets with auto-discovered candidate
//! buckets; the right card splits 3-ways: linechart of per-subnet hourly
//! traffic on top, KV stats panel bottom-left, client list bottom-right.
//! `discover_candidates` buckets unmapped IPs by /24 (v4) / /64 (v6) with a
//! ≥2-host threshold; `filter_clients_in_subnet` resolves CIDR membership;
//! `aggregate_subnet_hourly` sums element-wise the per-device
//! `hourly_queries` rings. Add / Edit / Delete modals write through the
//! same `cli::commands::subnets::{add_inner,set_inner,remove_inner}` the
//! CLI uses, plus promote-from-suggestion on `Enter`.
//!
//! ## Data sources
//!
//! - [`App::loaded_config`] — offline source for `[[subnets]]` entries
//!   plus per-entry source-file provenance. Refreshed at TUI startup,
//!   on `r`, and after every successful modal submit. We do NOT
//!   consult the daemon for the list itself — the operator may be
//!   staging edits not yet hot-reloaded.
//! - [`App::device_view`] — IPC-fed mapped + unmapped device DTOs with
//!   per-device `hourly_queries` ring + OUI-resolved `vendor`. Drives
//!   the discovery bucketing, the chart, and the client list. Empty
//!   until the first IPC poll lands.
//!
//! ## Selection model (operator-stable)
//!
//! [`SubnetsState::selected_id`](crate::tui::app::SubnetsState::selected_id)
//! is the operator-stable selection key — for a configured subnet it's
//! the entity id, for a discovered
//! candidate it's the canonical CIDR string. The key survives sort
//! changes, list refreshes, and modal-driven CRUD; resolving it back
//! to a row index every render keeps the cursor on the same logical
//! row even when configured / discovered counts shift.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::str::FromStr;

use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::symbols::Marker;
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Axis, Cell, Chart, Dataset, GraphType, Paragraph, Row, Table, TableState, Wrap,
};
use ratatui::Frame;

use crate::config::cidr::Cidr;
use crate::config::loader::LoadedConfig;
use crate::config::schema::Subnet;
use crate::ipc::protocol::{DeviceViewDto, UnmappedDeviceDto};
use crate::tui::app::App;
use crate::tui::format::count as format_count;
use crate::tui::theme::{self, T};
use crate::tui::ui::render_section_chrome;

/// Operator-facing tag appended to every auto-discovered candidate row
/// in the master list. Frozen by `tests/frozen_strings_s51.rs` — every
/// byte is a guarantee, including the leading space.
pub const SUBNET_SUGGESTED_TAG: &str = " [suggested]";

/// Below this width the master/detail split collapses to a single
/// column (master only). Mirrors the Dashboard's narrow-screen
/// fallback policy: the right detail pane needs ≥60 cells for the
/// chart + KV rows + client list to stay legible, on top of the
/// fixed 38-cell master list card + 1-cell gutter — a conservative
/// margin, not an exact sum (60+38+1=99, not 110).
///
/// Measured against the pre-chrome `area.width`. The Profiles tab
/// branches on its own post-chrome `outer.width` instead, so the two
/// tabs' thresholds are not directly comparable even where the
/// numbers are close.
const NARROW_THRESHOLD: u16 = 110;

// ── Public render entry point ──────────────────────────────────────────────

pub fn render(f: &mut Frame, area: Rect, app: &mut App) {
    let Some(loaded) = app.loaded_config.as_ref() else {
        render_no_config(f, area);
        return;
    };

    let configured = &loaded.config.subnets;
    let device_view = app.device_view.as_ref();
    let candidates = discover_candidates(
        device_view.map(|dv| dv.unmapped.as_slice()).unwrap_or(&[]),
        configured,
    );
    let total = configured.len() + candidates.len();

    if total == 0 {
        // Single framed card, mirroring the Devices empty card.
        let content = render_section_chrome(f, area, "Subnets", T.brand_red);
        render_empty(f, content);
        return;
    }

    if area.width < NARROW_THRESHOLD {
        // Single-column fallback: only the master list (self-framed).
        // Operators on narrow terminals still see what's configured +
        // suggested, they just lose the per-subnet detail card until
        // they widen the window.
        render_master(
            f,
            area,
            device_view,
            configured,
            &candidates,
            app.subnets.selected_id.as_deref(),
            &mut app.subnets.table_state,
        );
        return;
    }

    // Two independent framed cards (master + detail), mirroring the
    // Devices tab: each panel self-frames and the 1-cell gutter stays
    // blank (no divider glyph). The master list card is fixed at 38
    // cells — the same width as the Devices device-details card
    // (`tabs/devices.rs`) — and the detail pane takes the rest.
    let cols = Layout::horizontal([
        Constraint::Length(38),
        Constraint::Length(1),
        Constraint::Min(60),
    ])
    .split(area);

    render_master(
        f,
        cols[0],
        device_view,
        configured,
        &candidates,
        app.subnets.selected_id.as_deref(),
        &mut app.subnets.table_state,
    );
    render_detail(f, cols[2], app, configured, &candidates);
}

/// Paint a 1-cell-wide vertical separator (`│`) for every row of `area`.
/// Mirrors the post-Table separator pass at `tabs/query_log.rs:291` so
/// the operator reads the master/detail and stats/clients gutters with
/// the same column-divider glyph the Query Log table uses.
fn draw_v_divider(f: &mut Frame, area: Rect) {
    let style = Style::default().fg(T.text_muted);
    let buf = f.buffer_mut();
    for y in area.y..area.y.saturating_add(area.height) {
        if area.x < buf.area.right() && y < buf.area.bottom() {
            buf.set_string(area.x, y, "\u{2502}", style);
        }
    }
}

/// Paint a 1-cell-tall horizontal separator (`─`) for every column of `area`.
fn draw_h_divider(f: &mut Frame, area: Rect) {
    let style = Style::default().fg(T.text_muted);
    let buf = f.buffer_mut();
    let line: String = "\u{2500}".repeat(area.width as usize);
    if area.y < buf.area.bottom() {
        buf.set_string(area.x, area.y, &line, style);
    }
}

// ── Master pane ────────────────────────────────────────────────────────────

fn render_master(
    f: &mut Frame,
    area: Rect,
    device_view: Option<&DeviceViewDto>,
    configured: &[Subnet],
    candidates: &[CandidateSubnet],
    selected_id: Option<&str>,
    table_state: &mut TableState,
) {
    // Self-framed card. Compact title (configured\u{00b7}suggested) — the long
    // "N configured \u{00b7} M suggested" form clips in the narrow master column.
    let title = format!("Subnets ({}\u{00b7}{})", configured.len(), candidates.len());
    let content = render_section_chrome(f, area, &title, T.brand_red);

    let header = Row::new(vec![
        Cell::from("ID / CIDR"),
        Cell::from("DEV"),
        Cell::from("PROFILE"),
    ])
    .style(
        Style::default()
            .fg(T.brand_red)
            .add_modifier(Modifier::BOLD),
    );

    let rows: Vec<Row> = master_rows(configured, candidates, device_view).collect();

    // Resolve `selected_id` back to a row index every frame — the row
    // count moves with each refresh (configured CRUD + new candidates
    // appearing), so an index from the previous frame is unreliable.
    //
    // The scroll *offset* carries over regardless (via the persisted
    // `table_state` `super::render_table` writes into), and that is safe
    // even across a refresh that changes the row count: ratatui clamps
    // both `offset` and `selected` to the current row count before it
    // computes the visible window, so a value left over from a larger or
    // reordered set can never point past the end or land on the wrong
    // row — worst case it re-derives the window from scratch, same as a
    // fresh `TableState` would.
    let selected = resolve_selected_index(configured, candidates, selected_id)
        .or_else(|| (!rows.is_empty()).then_some(0));

    let table = Table::new(
        rows,
        [
            Constraint::Min(20),
            Constraint::Length(5),
            Constraint::Length(14),
        ],
    )
    .header(header)
    .row_highlight_style(theme::highlight_style());

    super::render_table(f, content, table, table_state, selected);
}

/// Build the master list rows: configured subnets first (by id, the
/// stable insertion order from the TOML), then discovered candidates
/// (populous-first, ties by CIDR ascending — see `discover_candidates`).
fn master_rows<'a>(
    configured: &'a [Subnet],
    candidates: &'a [CandidateSubnet],
    device_view: Option<&'a DeviceViewDto>,
) -> impl Iterator<Item = Row<'a>> + 'a {
    let configured_rows = configured.iter().map(move |s| {
        let dev_count = device_view
            .map(|dv| count_devices_in_cidrs(dv, &s.cidrs))
            .unwrap_or(0);
        Row::new(vec![
            Cell::from(s.id.as_str().to_string()),
            Cell::from(dev_count.to_string()),
            Cell::from(s.profile.as_str().to_string()),
        ])
    });

    let candidate_rows = candidates.iter().map(|c| {
        Row::new(vec![
            Cell::from(Span::styled(
                format!("{}{}", c.cidr, SUBNET_SUGGESTED_TAG),
                Style::default()
                    .fg(T.text_muted)
                    .add_modifier(Modifier::ITALIC),
            )),
            Cell::from(c.host_count.to_string()),
            Cell::from(Span::styled("—", Style::default().fg(T.text_muted))),
        ])
    });

    configured_rows.chain(candidate_rows)
}

/// Count how many mapped + unmapped devices currently sit inside any
/// of `cidrs`. Bad CIDRs and bad IP strings both fall through silently
/// — the loaded config has already passed the validator and live IP
/// strings come from the DNS hot path; either way the count is best-
/// effort and correctness is bounded by the data, not by parser
/// strictness.
fn count_devices_in_cidrs(dv: &DeviceViewDto, cidrs: &[String]) -> usize {
    let parsed: Vec<Cidr> = cidrs.iter().filter_map(|c| Cidr::parse(c).ok()).collect();
    if parsed.is_empty() {
        return 0;
    }
    let mut n = 0;
    for m in &dv.mapped {
        if let Ok(ip) = IpAddr::from_str(&m.ip) {
            if parsed.iter().any(|c| c.contains(ip)) {
                n += 1;
            }
        }
    }
    for u in &dv.unmapped {
        if let Ok(ip) = IpAddr::from_str(&u.ip) {
            if parsed.iter().any(|c| c.contains(ip)) {
                n += 1;
            }
        }
    }
    n
}

/// Resolve `selected_id` (entity id OR canonical CIDR) back to its
/// index in the combined master row list. `None` when the selection
/// key no longer matches any row (e.g. the subnet was just removed)
/// — the caller falls back to row 0.
fn resolve_selected_index(
    configured: &[Subnet],
    candidates: &[CandidateSubnet],
    selected: Option<&str>,
) -> Option<usize> {
    let key = selected?;
    if let Some(i) = configured.iter().position(|s| s.id.as_str() == key) {
        return Some(i);
    }
    candidates
        .iter()
        .position(|c| c.cidr == key)
        .map(|i| configured.len() + i)
}

// ── Detail pane (3-way split) ──────────────────────────────────────────────

fn render_detail(
    f: &mut Frame,
    area: Rect,
    app: &App,
    configured: &[Subnet],
    candidates: &[CandidateSubnet],
) {
    let selection = app
        .subnets
        .selected_id
        .as_deref()
        .and_then(|key| find_selection(key, configured, candidates));

    // Self-framed card. Title mirrors the master row's primary label —
    // entity id for a configured subnet, CIDR for a candidate — the way
    // the Devices "device details" card titles itself.
    let title = match &selection {
        Some(Selection::Configured(s)) => format!("Subnet \u{00b7} {}", s.id.as_str()),
        Some(Selection::Candidate(c)) => format!("Subnet \u{00b7} {}", c.cidr),
        None => "Subnet".to_string(),
    };
    let content = render_section_chrome(f, area, &title, T.brand_red);

    let Some(sel) = selection else {
        render_detail_placeholder(f, content, "Select a subnet on the left to see traffic");
        return;
    };

    let rows = Layout::vertical([
        Constraint::Length(8),
        Constraint::Length(1),
        Constraint::Min(10),
    ])
    .split(content);

    let bottom = Layout::horizontal([
        Constraint::Percentage(45),
        Constraint::Length(1),
        Constraint::Percentage(55),
    ])
    .split(rows[2]);

    match sel {
        Selection::Configured(s) => {
            render_chart(f, rows[0], app, &s.cidrs);
            render_stats_for_configured(f, bottom[0], app, s);
            render_clients(f, bottom[2], app, &s.cidrs);
        }
        Selection::Candidate(c) => {
            render_chart_for_candidate(f, rows[0], app, c);
            render_stats_for_candidate(f, bottom[0], c);
            render_clients_for_candidate(f, bottom[2], app, c);
        }
    }

    draw_h_divider(f, rows[1]);
    draw_v_divider(f, bottom[1]);
}

enum Selection<'a> {
    Configured(&'a Subnet),
    Candidate(&'a CandidateSubnet),
}

fn find_selection<'a>(
    key: &str,
    configured: &'a [Subnet],
    candidates: &'a [CandidateSubnet],
) -> Option<Selection<'a>> {
    if let Some(s) = configured.iter().find(|s| s.id.as_str() == key) {
        return Some(Selection::Configured(s));
    }
    candidates
        .iter()
        .find(|c| c.cidr == key)
        .map(Selection::Candidate)
}

fn render_detail_placeholder(f: &mut Frame, area: Rect, text: &str) {
    if area.height == 0 {
        return;
    }
    let para = Paragraph::new(Span::styled(
        text.to_string(),
        Style::default().fg(T.text_muted),
    ))
    .wrap(Wrap { trim: false });
    f.render_widget(para, area);
}

// ── Chart sub-pane ─────────────────────────────────────────────────────────

fn render_chart(f: &mut Frame, area: Rect, app: &App, cidrs: &[String]) {
    let dv = app.device_view.as_ref();
    let buckets = dv
        .map(|d| aggregate_subnet_hourly(d, cidrs))
        .unwrap_or_else(|| vec![0u64; 24]);

    // A compact block-rate gauge sits beside the 24h linechart, but only
    // when the row is wide enough to keep the braille line legible. Below
    // the threshold the gauge is dropped and the chart stays full-width —
    // graceful degradation for narrow terminals (verified via CT pty
    // smoke, not unit tests: a split that clips is invisible to a
    // default-width render).
    const GAUGE_W: u16 = 24;
    const MIN_CHART_W: u16 = 46;
    if area.width >= MIN_CHART_W + 1 + GAUGE_W {
        let cols = Layout::horizontal([
            Constraint::Min(MIN_CHART_W),
            Constraint::Length(1),
            Constraint::Length(GAUGE_W),
        ])
        .split(area);
        paint_chart(f, cols[0], &buckets);
        draw_v_divider(f, cols[1]);
        let parsed: Vec<Cidr> = cidrs.iter().filter_map(|c| Cidr::parse(c).ok()).collect();
        let blocked_24h = dv.map(|d| blocked_24h_in(d, &parsed)).unwrap_or(0);
        let queries_24h: u64 = buckets.iter().sum();
        paint_block_gauge(f, cols[2], blocked_24h, queries_24h);
    } else {
        paint_chart(f, area, &buckets);
    }
}

fn render_chart_for_candidate(f: &mut Frame, area: Rect, app: &App, c: &CandidateSubnet) {
    // Candidates are unmapped-only by definition (mapped IPs already
    // sit in their owner's `[[devices]]` row). Aggregate just the
    // unmapped ring intersecting the candidate CIDR.
    let dv = app.device_view.as_ref();
    let buckets = dv
        .map(|d| aggregate_subnet_hourly_unmapped_only(d, std::slice::from_ref(&c.cidr)))
        .unwrap_or_else(|| vec![0u64; 24]);
    paint_chart(f, area, &buckets);
}

fn paint_chart(f: &mut Frame, area: Rect, buckets: &[u64]) {
    if area.height < 4 {
        return;
    }
    let total: u64 = buckets.iter().sum();
    if total == 0 {
        let para = Paragraph::new(Span::styled(
            "  no traffic in the last 24h",
            Style::default().fg(T.text_muted),
        ));
        f.render_widget(para, area);
        return;
    }

    let series: Vec<(f64, f64)> = buckets
        .iter()
        .enumerate()
        .map(|(i, n)| (i as f64, *n as f64))
        .collect();
    let max_y = buckets.iter().copied().max().unwrap_or(1) as f64;
    let x_max = (buckets.len().max(1) - 1) as f64;

    let datasets = vec![Dataset::default()
        .name("queries")
        .marker(Marker::Braille)
        .graph_type(GraphType::Line)
        .style(Style::default().fg(T.chart_2))
        .data(&series)];

    let x_labels: Vec<Span> = vec![
        "-24h".into(),
        "-18h".into(),
        "-12h".into(),
        "-6h".into(),
        "now".into(),
    ];

    let chart = Chart::new(datasets)
        .x_axis(
            Axis::default()
                .style(Style::default().fg(T.axis_label))
                .bounds([0.0, x_max])
                .labels(x_labels),
        )
        .y_axis(
            Axis::default()
                .style(Style::default().fg(T.axis_label))
                .bounds([0.0, (max_y * 1.1).max(1.0)])
                .labels::<Vec<Span>>(vec!["0".into(), max_y.to_string().into()]),
        );

    // 1-cell gutters on each side so the leftmost braille column
    // doesn't paint glued to the section frame — same idiom dashboard
    // uses for its 24h chart.
    let chart_cols = Layout::horizontal([
        Constraint::Length(1),
        Constraint::Min(1),
        Constraint::Length(1),
    ])
    .split(area);
    f.render_widget(chart, chart_cols[1]);
}

/// Block rate as a percentage, clamped to `[0, 100]`; `total` of 0 → 0.0.
/// Both counts are rolling-24h (`Σ blocked_24h` ÷ `Σ hourly_queries`); the
/// clamp guards the window-skew case where a device's `blocked_24h` briefly
/// outruns the summed `hourly_queries` between IPC polls, which would
/// otherwise paint a >100% bar / stat.
fn block_rate_pct(blocked: u64, total: u64) -> f64 {
    if total == 0 {
        0.0
    } else {
        (blocked as f64 / total as f64 * 100.0).clamp(0.0, 100.0)
    }
}

/// Compact block-rate gauge shown beside the 24h linechart for a
/// configured subnet. `blocked` and `total` are both rolling-24h counts
/// (`Σ blocked_24h` and `Σ hourly_queries` over the subnet's devices),
/// so the ratio is window-consistent with the chart it sits next to and
/// can never exceed 100% — unlike the old lifetime-blocked ÷ queries-today
/// stat, which could render >100%.
fn paint_block_gauge(f: &mut Frame, area: Rect, blocked: u64, total: u64) {
    if area.height < 4 || area.width < 8 {
        return;
    }
    let pct = block_rate_pct(blocked, total);
    let bar_w = area.width.saturating_sub(1) as usize;
    let filled = ((pct / 100.0) * bar_w as f64).round() as usize;
    let bar: String = "█".repeat(filled) + &"░".repeat(bar_w.saturating_sub(filled));
    let rate_line = if total == 0 {
        "  —".to_string()
    } else {
        format!("  {pct:.1}%")
    };
    let lines = vec![
        Line::from(Span::styled(
            "  Block rate",
            Style::default().fg(T.text_muted),
        )),
        Line::from(Span::styled(
            rate_line,
            Style::default()
                .fg(T.brand_red)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(Span::styled(
            format!(" {bar}"),
            Style::default().fg(T.brand_red),
        )),
        Line::from(Span::styled(
            format!("  {} / {}", format_count(blocked), format_count(total)),
            Style::default().fg(T.text_muted),
        )),
    ];
    f.render_widget(Paragraph::new(lines), area);
}

// ── Stats sub-pane (KV table, 6-8 metrics) ─────────────────────────────────

fn render_stats_for_configured(f: &mut Frame, area: Rect, app: &App, s: &Subnet) {
    let dv = app.device_view.as_ref();
    let parsed: Vec<Cidr> = s.cidrs.iter().filter_map(|c| Cidr::parse(c).ok()).collect();
    let device_counts = dv.map(|d| device_counts_in(d, &parsed));
    let queries_today = dv.map(|d| queries_today_in(d, &parsed)).unwrap_or(0);
    let buckets = dv.map(|d| aggregate_subnet_hourly(d, &s.cidrs));
    // `b.last()` is `hourly_queries[23]` — the CURRENT wall-clock hour
    // bucket, not a trailing 60-minute window. At :01 past the hour this
    // holds one minute of traffic. Labelled accordingly below rather than
    // pro-rated, so the number never implies a window it isn't.
    let queries_this_hour = buckets
        .as_ref()
        .and_then(|b| b.last().copied())
        .unwrap_or(0);
    // Block rate over the rolling 24h window — same numerator/denominator
    // as the gauge beside the chart (Σ blocked_24h ÷ Σ hourly_queries),
    // so the two never disagree and the ratio is clamped to ≤100%.
    let queries_24h: u64 = buckets.as_ref().map(|b| b.iter().sum()).unwrap_or(0);
    let blocked_24h = dv.map(|d| blocked_24h_in(d, &parsed)).unwrap_or(0);
    let block_pct = if queries_24h == 0 {
        "—".to_string()
    } else {
        format!("{:.1}%", block_rate_pct(blocked_24h, queries_24h))
    };
    let top_vendor = dv.and_then(|d| top_vendor_in(d, &parsed));

    let source = subnet_source_label(app, s);
    let device_label = match device_counts {
        Some((online, total)) => format!("{} online / {} total", online, total),
        None => "—".to_string(),
    };

    let lines: Vec<(&str, String)> = vec![
        ("Profile", s.profile.as_str().to_string()),
        ("Source", source),
        ("Devices", device_label),
        ("Queries today", format_count(queries_today)),
        ("Queries (hour)", format_count(queries_this_hour)),
        (
            "Blocked 24h",
            format!("{} ({})", format_count(blocked_24h), block_pct),
        ),
        ("Top vendor", top_vendor.unwrap_or_else(|| "—".into())),
    ];
    paint_kv_table(f, area, &lines);
}

fn render_stats_for_candidate(f: &mut Frame, area: Rect, c: &CandidateSubnet) {
    let vendor_breakdown = if c.vendor_tally.is_empty() {
        "—".to_string()
    } else {
        c.vendor_tally
            .iter()
            .take(3)
            .map(|(v, n)| format!("{} ({})", v, n))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let lines: Vec<(&str, String)> = vec![
        ("Status", "discovered (not yet configured)".into()),
        ("CIDR", c.cidr.clone()),
        ("Hosts", c.host_count.to_string()),
        ("Queries today", format_count(c.queries_today)),
        ("Top vendors", vendor_breakdown),
        ("Action", "press Enter to add as a configured subnet".into()),
    ];
    paint_kv_table(f, area, &lines);
}

fn paint_kv_table(f: &mut Frame, area: Rect, lines: &[(&str, String)]) {
    let rows: Vec<Row> = lines
        .iter()
        .map(|(k, v)| {
            Row::new(vec![
                Cell::from(Span::styled(
                    format!("{:<14}", k),
                    Style::default().fg(T.text_secondary),
                )),
                Cell::from(Span::styled(v.clone(), Style::default().fg(T.text_primary))),
            ])
        })
        .collect();
    let table = Table::new(rows, [Constraint::Length(15), Constraint::Min(10)]);
    f.render_widget(table, area);
}

// ── Clients sub-pane ───────────────────────────────────────────────────────

fn render_clients(f: &mut Frame, area: Rect, app: &App, cidrs: &[String]) {
    let Some(dv) = app.device_view.as_ref() else {
        render_detail_placeholder(f, area, "  waiting for daemon\u{2026}");
        return;
    };
    let clients = filter_clients_in_subnet(dv, cidrs);
    if clients.is_empty() {
        render_detail_placeholder(f, area, "  no clients in this subnet");
        return;
    }
    paint_client_table(f, area, &clients);
}

fn render_clients_for_candidate(f: &mut Frame, area: Rect, app: &App, c: &CandidateSubnet) {
    let Some(dv) = app.device_view.as_ref() else {
        render_detail_placeholder(f, area, "  waiting for daemon\u{2026}");
        return;
    };
    // Candidate CIDRs are by construction unmapped-only; filter just
    // the unmapped slice for the row list.
    let parsed: Vec<Cidr> = Cidr::parse(&c.cidr).ok().into_iter().collect();
    let mut rows: Vec<ClientRow> = Vec::new();
    for u in &dv.unmapped {
        if let Ok(ip) = IpAddr::from_str(&u.ip) {
            if parsed.iter().any(|c| c.contains(ip)) {
                rows.push(ClientRow {
                    ip: u.ip.clone(),
                    name: "(unmapped)".into(),
                    vendor: u.vendor.clone(),
                    queries: u.queries_today,
                });
            }
        }
    }
    if rows.is_empty() {
        render_detail_placeholder(f, area, "  no observed clients");
        return;
    }
    paint_client_table(f, area, &rows);
}

/// One row in the per-subnet client list. Kept `pub` so the
/// `filter_clients_in_subnet` helper can be exercised from sibling
/// integration tests without re-implementing the projection.
#[derive(Debug, Clone)]
pub struct ClientRow {
    pub ip: String,
    pub name: String,
    pub vendor: Option<String>,
    pub queries: u64,
}

fn paint_client_table(f: &mut Frame, area: Rect, clients: &[ClientRow]) {
    let header = Row::new(vec![
        Cell::from("IP"),
        Cell::from("NAME"),
        Cell::from("VENDOR"),
        Cell::from("Q.TODAY"),
    ])
    .style(
        Style::default()
            .fg(T.brand_red)
            .add_modifier(Modifier::BOLD),
    );
    let rows: Vec<Row> = clients
        .iter()
        .map(|c| {
            Row::new(vec![
                Cell::from(c.ip.clone()),
                Cell::from(c.name.clone()),
                Cell::from(c.vendor.clone().unwrap_or_else(|| "—".into())),
                Cell::from(format_count(c.queries)),
            ])
        })
        .collect();
    let table = Table::new(
        rows,
        [
            Constraint::Length(15),
            Constraint::Min(10),
            Constraint::Length(16),
            Constraint::Length(8),
        ],
    )
    .header(header);
    f.render_widget(table, area);
}

// ── Discovery + aggregation ────────────────────────────────────────────────

/// One auto-discovered candidate: a /24 (v4) or /64 (v6) bucket of
/// unmapped IPs that does NOT yet sit inside any configured CIDR.
#[derive(Debug, Clone)]
pub struct CandidateSubnet {
    pub cidr: String,
    pub host_count: usize,
    pub queries_today: u64,
    /// Vendor tally, descending by frequency. `None` vendors are
    /// dropped before the tally — they collapse into a single
    /// "(unknown)" bucket the renderer can choose to surface or skip.
    pub vendor_tally: Vec<(String, usize)>,
}

/// Group unmapped IPs into bucket candidates. The `configured`
/// argument is the live `[[subnets]]` list — buckets that intersect
/// any already-configured CIDR are dropped (the IPs there are already
/// covered, no point suggesting them again).
///
/// Bucketing rule:
/// - IPv4 → `/24` (256 hosts; matches a typical DHCP pool).
/// - IPv6 → `/64` (the standard SLAAC subnet boundary).
///
/// Threshold: ≥2 hosts per bucket. A single rogue device in an
/// otherwise-empty /24 is more likely to be noise than a subnet the
/// operator forgot to configure.
///
/// Output sort: populous-first (more hosts → higher priority),
/// ties broken by CIDR ascending so the order is stable across
/// frames.
pub fn discover_candidates(
    unmapped: &[UnmappedDeviceDto],
    configured: &[Subnet],
) -> Vec<CandidateSubnet> {
    let configured_cidrs: Vec<Cidr> = configured
        .iter()
        .flat_map(|s| s.cidrs.iter())
        .filter_map(|c| Cidr::parse(c).ok())
        .collect();

    // BTreeMap so the bucket key (canonical CIDR string) iterates in
    // deterministic order — relied on for tie-breaking + tests.
    let mut buckets: BTreeMap<String, BucketAccum> = BTreeMap::new();
    for u in unmapped {
        let Ok(ip) = IpAddr::from_str(&u.ip) else {
            continue;
        };
        if configured_cidrs.iter().any(|c| c.contains(ip)) {
            continue;
        }
        let bucket_cidr = bucket_for(ip);
        let entry = buckets.entry(bucket_cidr).or_default();
        entry.host_count += 1;
        entry.queries_today += u.queries_today;
        if let Some(v) = u.vendor.clone() {
            *entry.vendors.entry(v).or_insert(0) += 1;
        }
    }

    let mut out: Vec<CandidateSubnet> = buckets
        .into_iter()
        .filter(|(_, b)| b.host_count >= 2)
        .map(|(cidr, b)| {
            let mut tally: Vec<(String, usize)> = b.vendors.into_iter().collect();
            tally.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
            CandidateSubnet {
                cidr,
                host_count: b.host_count,
                queries_today: b.queries_today,
                vendor_tally: tally,
            }
        })
        .collect();

    out.sort_by(|a, b| b.host_count.cmp(&a.host_count).then(a.cidr.cmp(&b.cidr)));
    out
}

#[derive(Debug, Default)]
struct BucketAccum {
    host_count: usize,
    queries_today: u64,
    vendors: BTreeMap<String, usize>,
}

/// Canonical bucket CIDR string for an IP. IPv4 → `/24`, IPv6 → `/64`.
fn bucket_for(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{}.{}.{}.0/24", o[0], o[1], o[2])
        }
        IpAddr::V6(v6) => {
            let segs = v6.segments();
            format!(
                "{:x}:{:x}:{:x}:{:x}::/64",
                segs[0], segs[1], segs[2], segs[3]
            )
        }
    }
}

/// Return mapped+unmapped clients whose IP falls inside any of `cidrs`.
/// Used by the right-card client list. Bad CIDRs / bad IPs are dropped
/// silently — see `count_devices_in_cidrs` for the rationale.
pub fn filter_clients_in_subnet(dv: &DeviceViewDto, cidrs: &[String]) -> Vec<ClientRow> {
    let parsed: Vec<Cidr> = cidrs.iter().filter_map(|c| Cidr::parse(c).ok()).collect();
    if parsed.is_empty() {
        return Vec::new();
    }
    let mut out: Vec<ClientRow> = Vec::new();
    for m in &dv.mapped {
        if let Ok(ip) = IpAddr::from_str(&m.ip) {
            if parsed.iter().any(|c| c.contains(ip)) {
                out.push(ClientRow {
                    ip: m.ip.clone(),
                    name: m.name.clone(),
                    vendor: m.vendor.clone(),
                    queries: m.queries_today,
                });
            }
        }
    }
    for u in &dv.unmapped {
        if let Ok(ip) = IpAddr::from_str(&u.ip) {
            if parsed.iter().any(|c| c.contains(ip)) {
                out.push(ClientRow {
                    ip: u.ip.clone(),
                    name: "(unmapped)".into(),
                    vendor: u.vendor.clone(),
                    queries: u.queries_today,
                });
            }
        }
    }
    out
}

/// Sum element-wise the per-device `hourly_queries` ring across every
/// mapped + unmapped device whose IP sits inside `cidrs`. Returns a
/// 24-slot vec.
///
/// **Empty-ring tolerance**: pre-S44 daemons (and devices with no
/// queries since startup) emit `hourly_queries: []`. We sum what's
/// present and ignore the empties — never panic, never push partial
/// sums into the wrong slot.
pub fn aggregate_subnet_hourly(dv: &DeviceViewDto, cidrs: &[String]) -> Vec<u64> {
    let parsed: Vec<Cidr> = cidrs.iter().filter_map(|c| Cidr::parse(c).ok()).collect();
    let mut out = vec![0u64; 24];
    if parsed.is_empty() {
        return out;
    }
    for m in &dv.mapped {
        if let Ok(ip) = IpAddr::from_str(&m.ip) {
            if parsed.iter().any(|c| c.contains(ip)) {
                add_ring(&mut out, &m.hourly_queries);
            }
        }
    }
    for u in &dv.unmapped {
        if let Ok(ip) = IpAddr::from_str(&u.ip) {
            if parsed.iter().any(|c| c.contains(ip)) {
                add_ring(&mut out, &u.hourly_queries);
            }
        }
    }
    out
}

/// Same as [`aggregate_subnet_hourly`] but only walks the unmapped
/// slice. Used by candidate buckets — mapped devices that happen to
/// sit inside a candidate CIDR are by definition already covered by
/// some other configured subnet.
fn aggregate_subnet_hourly_unmapped_only(dv: &DeviceViewDto, cidrs: &[String]) -> Vec<u64> {
    let parsed: Vec<Cidr> = cidrs.iter().filter_map(|c| Cidr::parse(c).ok()).collect();
    let mut out = vec![0u64; 24];
    if parsed.is_empty() {
        return out;
    }
    for u in &dv.unmapped {
        if let Ok(ip) = IpAddr::from_str(&u.ip) {
            if parsed.iter().any(|c| c.contains(ip)) {
                add_ring(&mut out, &u.hourly_queries);
            }
        }
    }
    out
}

/// Add `src` into `dst` slot-by-slot. `src` shorter than 24 contributes
/// only its prefix; `src` longer contributes the first 24 (wire format
/// guarantees `[0]` = oldest, `[23]` = current hour, so a >24 ring
/// would be a daemon bug, but truncating is safer than panicking).
fn add_ring(dst: &mut [u64], src: &[u64]) {
    for (i, v) in src.iter().enumerate().take(dst.len()) {
        dst[i] = dst[i].saturating_add(*v);
    }
}

// ── Stats helpers (configured-subnet pane) ─────────────────────────────────

/// `(online, total)` device count for a configured subnet.
fn device_counts_in(dv: &DeviceViewDto, parsed: &[Cidr]) -> (usize, usize) {
    let mut online = 0usize;
    let mut total = 0usize;
    for m in &dv.mapped {
        if let Ok(ip) = IpAddr::from_str(&m.ip) {
            if parsed.iter().any(|c| c.contains(ip)) {
                total += 1;
                if m.online {
                    online += 1;
                }
            }
        }
    }
    for u in &dv.unmapped {
        if let Ok(ip) = IpAddr::from_str(&u.ip) {
            if parsed.iter().any(|c| c.contains(ip)) {
                total += 1;
                if u.online {
                    online += 1;
                }
            }
        }
    }
    (online, total)
}

fn queries_today_in(dv: &DeviceViewDto, parsed: &[Cidr]) -> u64 {
    let mut n = 0u64;
    for m in &dv.mapped {
        if let Ok(ip) = IpAddr::from_str(&m.ip) {
            if parsed.iter().any(|c| c.contains(ip)) {
                n = n.saturating_add(m.queries_today);
            }
        }
    }
    for u in &dv.unmapped {
        if let Ok(ip) = IpAddr::from_str(&u.ip) {
            if parsed.iter().any(|c| c.contains(ip)) {
                n = n.saturating_add(u.queries_today);
            }
        }
    }
    n
}

/// Rolling-24h blocked-query count summed over the subnet's devices
/// (`MappedDeviceDto::blocked_24h` + `UnmappedDeviceDto::blocked_24h`).
/// Pairs with `Σ hourly_queries` (via [`aggregate_subnet_hourly`]) for a
/// window-consistent block rate — see [`paint_block_gauge`].
fn blocked_24h_in(dv: &DeviceViewDto, parsed: &[Cidr]) -> u64 {
    let mut n = 0u64;
    for m in &dv.mapped {
        if let Ok(ip) = IpAddr::from_str(&m.ip) {
            if parsed.iter().any(|c| c.contains(ip)) {
                n = n.saturating_add(m.blocked_24h);
            }
        }
    }
    for u in &dv.unmapped {
        if let Ok(ip) = IpAddr::from_str(&u.ip) {
            if parsed.iter().any(|c| c.contains(ip)) {
                n = n.saturating_add(u.blocked_24h);
            }
        }
    }
    n
}

fn top_vendor_in(dv: &DeviceViewDto, parsed: &[Cidr]) -> Option<String> {
    let mut tally: BTreeMap<String, usize> = BTreeMap::new();
    for m in &dv.mapped {
        if let Ok(ip) = IpAddr::from_str(&m.ip) {
            if parsed.iter().any(|c| c.contains(ip)) {
                if let Some(v) = m.vendor.clone() {
                    *tally.entry(v).or_insert(0) += 1;
                }
            }
        }
    }
    for u in &dv.unmapped {
        if let Ok(ip) = IpAddr::from_str(&u.ip) {
            if parsed.iter().any(|c| c.contains(ip)) {
                if let Some(v) = u.vendor.clone() {
                    *tally.entry(v).or_insert(0) += 1;
                }
            }
        }
    }
    tally.into_iter().max_by_key(|(_, n)| *n).map(|(v, _)| v)
}

fn subnet_source_label(app: &App, s: &Subnet) -> String {
    let Some(loaded) = app.loaded_config.as_ref() else {
        return "—".into();
    };
    let key = format!("subnets.{}", s.id.as_str());
    loaded
        .provenance
        .get(&key)
        .and_then(|(p, _line)| p.file_name())
        .and_then(|n| n.to_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| "—".into())
}

// ── Empty / error states ───────────────────────────────────────────────────

fn render_no_config(f: &mut Frame, area: Rect) {
    let content = render_section_chrome(f, area, "Subnets", T.brand_red);
    f.render_widget(
        Paragraph::new(Span::styled(
            "  could not load config — fix it and press r to retry",
            Style::default().fg(T.text_muted),
        )),
        content,
    );
}

fn render_empty(f: &mut Frame, area: Rect) {
    let lines = vec![
        Line::from(Span::styled(
            "  no subnets configured and no auto-discovery candidates yet.",
            Style::default().fg(T.text_muted),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "  press `a` to add one, or wait for unmapped devices to appear in the network.",
            Style::default().fg(T.text_muted),
        )),
    ];
    f.render_widget(Paragraph::new(lines), area);
}

// ── Loaded-config helper for tests ─────────────────────────────────────────

#[allow(dead_code)] // used by sibling integration test helpers
pub(crate) fn loaded_subnets(loaded: &LoadedConfig) -> &[Subnet] {
    &loaded.config.subnets
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::schema::Id;
    use crate::ipc::protocol::MappedDeviceDto;

    fn mk_subnet(id: &str, cidrs: &[&str], profile: &str) -> Subnet {
        Subnet {
            id: Id::new(id).unwrap(),
            display_name: id.to_string(),
            cidrs: cidrs.iter().map(|s| s.to_string()).collect(),
            profile: Id::new(profile).unwrap(),
            priority: 0,
        }
    }

    fn mk_unmapped(ip: &str, vendor: Option<&str>, queries_today: u64) -> UnmappedDeviceDto {
        mk_unmapped_with_ring(ip, vendor, queries_today, Vec::new())
    }

    fn mk_unmapped_with_ring(
        ip: &str,
        vendor: Option<&str>,
        queries_today: u64,
        hourly: Vec<u64>,
    ) -> UnmappedDeviceDto {
        UnmappedDeviceDto {
            ip: ip.into(),
            mac: None,
            queries: queries_today,
            queries_today,
            blocked: 0,
            blocked_24h: 0,
            last_seen: 0,
            online: false,
            vendor: vendor.map(|s| s.into()),
            hourly_queries: hourly,
        }
    }

    fn mk_mapped_with_ring(ip: &str, name: &str, hourly: Vec<u64>) -> MappedDeviceDto {
        MappedDeviceDto {
            ip: ip.into(),
            name: name.into(),
            mac: None,
            mac_aliases: Vec::new(),
            profile: "default".into(),
            owner: None,
            device_type: None,
            department: None,
            queries: 0,
            queries_today: 0,
            blocked: 0,
            blocked_24h: 0,
            cache_hits: 0,
            last_seen: 0,
            online: false,
            vendor: None,
            groups: Vec::new(),
            notes: None,
            network_name: None,
            network_name_wildcard: false,
            id: None,
            hourly_queries: hourly,
            unfiltered: false,
        }
    }

    // ── Block-rate gauge math (Onda-1) ─────────────────────────────────

    #[test]
    fn block_rate_pct_clamps_zero_and_overflow() {
        // total == 0 → 0.0 (no divide-by-zero, no NaN).
        assert_eq!(block_rate_pct(0, 0), 0.0);
        assert_eq!(block_rate_pct(7, 0), 0.0);
        // Normal case.
        assert!((block_rate_pct(38, 100) - 38.0).abs() < 1e-9);
        // Window-skew guard: a stale `hourly_queries` sum can momentarily
        // trail `blocked_24h` between polls — the ratio must clamp to 100,
        // never paint a >100% bar (the bug that sank the old
        // lifetime-blocked ÷ queries-today stat).
        assert_eq!(block_rate_pct(500, 100), 100.0);
    }

    #[test]
    fn blocked_24h_in_sums_rolling_window_not_lifetime() {
        // Two devices inside the /24, one outside. The aggregate must sum
        // `blocked_24h` (30 + 5) and ignore lifetime `blocked` (999) plus
        // the out-of-CIDR device entirely.
        let mut inside_a = mk_mapped_with_ring("10.0.0.5", "a", vec![]);
        inside_a.blocked_24h = 30;
        inside_a.blocked = 999;
        let mut inside_b = mk_unmapped("10.0.0.9", None, 0);
        inside_b.blocked_24h = 5;
        inside_b.blocked = 42;
        let mut outside = mk_mapped_with_ring("10.9.0.1", "z", vec![]);
        outside.blocked_24h = 7;
        let dv = DeviceViewDto {
            mapped: vec![inside_a, outside],
            unmapped: vec![inside_b],
        };
        let parsed = vec![Cidr::parse("10.0.0.0/24").unwrap()];
        assert_eq!(blocked_24h_in(&dv, &parsed), 35);
    }

    /// True if any single row of `buf`, read left-to-right, contains
    /// `needle`. Reading the `TestBackend` buffer cell-by-cell sidesteps
    /// the ANSI-escape splitting that makes pty-captured frames unreliable
    /// to assert against.
    fn buffer_contains(buf: &ratatui::buffer::Buffer, needle: &str) -> bool {
        let area = *buf.area();
        (0..area.height).any(|y| {
            let row: String = (0..area.width).map(|x| buf[(x, y)].symbol()).collect();
            row.contains(needle)
        })
    }

    #[test]
    fn render_chart_shows_gauge_only_when_wide() {
        use ratatui::backend::TestBackend;
        use ratatui::layout::Rect;
        use ratatui::Terminal;

        let app = App::new();
        let cidrs = vec!["10.0.0.0/24".to_string()];

        // Wide row (≥ MIN_CHART_W + 1 + GAUGE_W) → gauge renders beside
        // the linechart; its "Block rate" label must appear.
        let mut wide = Terminal::new(TestBackend::new(90, 8)).unwrap();
        wide.draw(|f| render_chart(f, Rect::new(0, 0, 90, 8), &app, &cidrs))
            .unwrap();
        assert!(
            buffer_contains(wide.backend().buffer(), "Block rate"),
            "gauge must render beside the chart on a wide row"
        );

        // Narrow row → gauge dropped so the braille linechart stays
        // legible; the label must be absent (the clip that unit tests at
        // default width would silently miss).
        let mut narrow = Terminal::new(TestBackend::new(60, 8)).unwrap();
        narrow
            .draw(|f| render_chart(f, Rect::new(0, 0, 60, 8), &app, &cidrs))
            .unwrap();
        assert!(
            !buffer_contains(narrow.backend().buffer(), "Block rate"),
            "gauge must be dropped on a narrow row"
        );
    }

    // ── T1: master pane / detail layout ────────────────────────────────

    #[test]
    fn s51_master_pane_lists_configured_subnets() {
        // Configured subnets land first in the master row list, in the
        // order they appear in the TOML (deterministic). Discovered
        // candidates land after — when present — and never reorder
        // configured rows.
        let configured = vec![
            mk_subnet("lan-corp", &["10.10.0.0/16"], "default"),
            mk_subnet("lan-guest", &["192.0.2.0/24"], "default"),
        ];
        let candidates: Vec<CandidateSubnet> = Vec::new();
        let rows: Vec<Row> = master_rows(&configured, &candidates, None).collect();
        assert_eq!(
            rows.len(),
            2,
            "master list yields one row per configured subnet"
        );
    }

    #[test]
    fn s51_detail_renders_placeholder_when_no_selection() {
        // When `selected_id` doesn't resolve to any configured subnet
        // OR any candidate, `find_selection` returns None and the
        // detail pane falls back to the placeholder copy. This is the
        // first-frame state before the cursor lands on row 0.
        let configured = vec![mk_subnet("lan", &["10.0.0.0/8"], "default")];
        let candidates: Vec<CandidateSubnet> = Vec::new();
        let sel = find_selection("nonexistent", &configured, &candidates);
        assert!(sel.is_none(), "missing key must surface as None");
    }

    #[test]
    fn s51_detail_panels_split_3_ways() {
        // The detail pane splits into chart (Length 8) on top, a 1-row
        // horizontal divider, then a bottom row that further splits
        // 45/1/55 horizontally with a vertical divider in the gutter.
        // Walk the same Layout primitives with a fixed area to verify
        // the chunks land at the documented sizes.
        let area = Rect::new(0, 0, 60, 30);
        let rows = Layout::vertical([
            Constraint::Length(8),
            Constraint::Length(1),
            Constraint::Min(10),
        ])
        .split(area);
        assert_eq!(rows[0].height, 8, "chart sub-pane is 8 rows tall");
        assert_eq!(rows[1].height, 1, "horizontal divider is exactly 1 row");
        assert_eq!(rows[2].height, 21, "bottom row claims the remainder");

        let bottom = Layout::horizontal([
            Constraint::Percentage(45),
            Constraint::Length(1),
            Constraint::Percentage(55),
        ])
        .split(rows[2]);
        assert_eq!(
            bottom.len(),
            3,
            "bottom row is three chunks (stats / gutter / clients)"
        );
        assert_eq!(bottom[1].width, 1, "middle gutter is exactly 1 cell");
        assert!(
            bottom[0].width > 0 && bottom[2].width > 0,
            "stats + clients both painted"
        );
    }

    #[test]
    fn s51_selection_persists_across_renders() {
        // `selected_id` is operator-stable: removing a sibling
        // configured subnet shouldn't invalidate the cursor on the
        // remaining one. Resolve "lan-b" twice — once with both
        // configured, once after "lan-a" is gone — and assert the
        // index updates without losing the selection.
        let cfg_full = vec![
            mk_subnet("lan-a", &["10.0.0.0/24"], "default"),
            mk_subnet("lan-b", &["10.1.0.0/24"], "default"),
        ];
        let candidates: Vec<CandidateSubnet> = Vec::new();
        let idx_full = resolve_selected_index(&cfg_full, &candidates, Some("lan-b"));
        assert_eq!(idx_full, Some(1));

        let cfg_post = vec![mk_subnet("lan-b", &["10.1.0.0/24"], "default")];
        let idx_post = resolve_selected_index(&cfg_post, &candidates, Some("lan-b"));
        assert_eq!(
            idx_post,
            Some(0),
            "selection key survives sibling removal — index slides to the new position"
        );
    }

    // ── T2: discovery + aggregation ────────────────────────────────────

    #[test]
    fn s51_discover_skips_ips_already_in_configured_cidr() {
        // 192.168.5.10 and 192.168.5.20 both sit inside the configured
        // 192.168.0.0/16 — they must NOT bubble up as a candidate
        // /24 even though, on their own, they'd cross the 2-host
        // threshold for the 192.168.5.0/24 bucket.
        let configured = vec![mk_subnet("lan", &["192.168.0.0/16"], "default")];
        let unmapped = vec![
            mk_unmapped("192.168.5.10", Some("Apple"), 1),
            mk_unmapped("192.168.5.20", Some("Apple"), 2),
        ];
        let cands = discover_candidates(&unmapped, &configured);
        assert!(
            cands.is_empty(),
            "buckets fully inside a configured CIDR must be dropped, got {cands:?}"
        );
    }

    #[test]
    fn s51_discover_buckets_ipv4_by_24() {
        // 10.14.0.x — three hosts in the same /24 → one bucket.
        let unmapped = vec![
            mk_unmapped("10.14.0.10", None, 0),
            mk_unmapped("10.14.0.11", None, 0),
            mk_unmapped("10.14.0.12", None, 0),
        ];
        let cands = discover_candidates(&unmapped, &[]);
        assert_eq!(cands.len(), 1, "three hosts in /24 collapse to one bucket");
        assert_eq!(cands[0].cidr, "10.14.0.0/24");
        assert_eq!(cands[0].host_count, 3);
    }

    #[test]
    fn s51_discover_buckets_ipv6_by_64() {
        let unmapped = vec![
            mk_unmapped("2001:db8::1", None, 0),
            mk_unmapped("2001:db8::5", None, 0),
        ];
        let cands = discover_candidates(&unmapped, &[]);
        assert_eq!(cands.len(), 1, "two v6 hosts in /64 → one bucket");
        assert_eq!(cands[0].cidr, "2001:db8:0:0::/64");
        assert_eq!(cands[0].host_count, 2);
    }

    #[test]
    fn s51_discover_skips_single_host_outliers() {
        // One host alone in a /24 is below the threshold — drop.
        let unmapped = vec![mk_unmapped("172.16.99.5", None, 0)];
        let cands = discover_candidates(&unmapped, &[]);
        assert!(cands.is_empty(), "single-host bucket must NOT surface");
    }

    #[test]
    fn s51_discover_tallies_vendors_descending() {
        // Two Apples + one Lenovo + one None → tally: Apple(2), Lenovo(1).
        // None must be dropped (it doesn't carry a vendor name).
        let unmapped = vec![
            mk_unmapped("10.14.0.10", Some("Apple"), 0),
            mk_unmapped("10.14.0.11", Some("Apple"), 0),
            mk_unmapped("10.14.0.12", Some("Lenovo"), 0),
            mk_unmapped("10.14.0.13", None, 0),
        ];
        let cands = discover_candidates(&unmapped, &[]);
        assert_eq!(cands.len(), 1);
        let tally = &cands[0].vendor_tally;
        assert_eq!(tally[0], ("Apple".into(), 2), "most frequent vendor first");
        assert_eq!(tally[1], ("Lenovo".into(), 1));
        assert!(
            !tally.iter().any(|(v, _)| v.is_empty()),
            "None vendors must NOT collapse into an empty-string bucket"
        );
    }

    #[test]
    fn s51_client_filter_returns_only_matching_ips() {
        // Two unmapped + one mapped — only the IP inside the CIDR
        // makes it through. Mapped + unmapped are both eligible.
        let dv = DeviceViewDto {
            mapped: vec![mk_mapped_with_ring("10.0.0.5", "router", vec![])],
            unmapped: vec![
                mk_unmapped("10.0.0.50", None, 0),
                mk_unmapped("172.16.0.1", None, 0),
            ],
        };
        let clients = filter_clients_in_subnet(&dv, &["10.0.0.0/24".into()]);
        assert_eq!(
            clients.len(),
            2,
            "the /24 contains the mapped + one unmapped"
        );
        assert!(clients.iter().any(|c| c.ip == "10.0.0.5"));
        assert!(clients.iter().any(|c| c.ip == "10.0.0.50"));
        assert!(!clients.iter().any(|c| c.ip == "172.16.0.1"));
    }

    #[test]
    fn s51_hourly_aggregation_handles_empty_ring() {
        // Pre-S44 daemons emit an empty `hourly_queries` vec. Summing
        // over a device with [] must yield the zero ring, not panic.
        let dv = DeviceViewDto {
            mapped: vec![],
            unmapped: vec![mk_unmapped_with_ring("10.0.0.5", None, 0, Vec::new())],
        };
        let agg = aggregate_subnet_hourly(&dv, &["10.0.0.0/24".into()]);
        assert_eq!(agg.len(), 24);
        assert!(agg.iter().all(|n| *n == 0));
    }

    #[test]
    fn s51_hourly_aggregation_sums_across_devices() {
        // Two unmapped devices, both with full 24-slot rings, both
        // inside the CIDR → element-wise sum.
        let ring_a: Vec<u64> = (1..=24).collect();
        let ring_b: Vec<u64> = (24..=47).collect();
        let dv = DeviceViewDto {
            mapped: vec![],
            unmapped: vec![
                mk_unmapped_with_ring("10.0.0.5", None, 0, ring_a.clone()),
                mk_unmapped_with_ring("10.0.0.6", None, 0, ring_b.clone()),
            ],
        };
        let agg = aggregate_subnet_hourly(&dv, &["10.0.0.0/24".into()]);
        for i in 0..24 {
            assert_eq!(agg[i], ring_a[i] + ring_b[i], "slot {i} sums element-wise");
        }
    }

    // ── Public constant — frozen string ────────────────────────────────

    #[test]
    fn s51_subnet_suggested_tag_is_frozen() {
        // Locked copy — mirror the integration assertion in
        // `tests/frozen_strings_s51.rs` so a same-file regression
        // surfaces inside the `cargo test --lib` cohort too.
        assert_eq!(SUBNET_SUGGESTED_TAG, " [suggested]");
    }

    // ── Review subnets-01: first-render selection seeding ──────────────

    #[test]
    fn s51_resolve_index_falls_back_to_first_row_when_unseeded() {
        // When `selected_id` is None the resolver returns None, but
        // the renderer auto-places the cursor on row 0. Locks the
        // contract `ensure_subnet_selection_seeded` relies on:
        // configured subnets are at indices 0..configured.len(), so a
        // first-row seed walks index 0 of `configured`, and only
        // falls through to candidates if `configured` is empty.
        let configured = vec![mk_subnet("lan-a", &["10.0.0.0/24"], "default")];
        let candidates: Vec<CandidateSubnet> = Vec::new();
        assert!(
            resolve_selected_index(&configured, &candidates, None).is_none(),
            "None key must surface as None — caller does the seed"
        );
        assert_eq!(
            resolve_selected_index(&configured, &candidates, Some("lan-a")),
            Some(0),
            "after seeding, the first row's id resolves to index 0"
        );
    }
}
