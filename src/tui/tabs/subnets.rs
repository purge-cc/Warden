//! Subnets tab — master/detail view of configured + discovered subnets.
//!
//! The left list mixes configured subnets with auto-discovered candidate
//! buckets. Traffic and clients share the wider center column; block rate
//! and subnet details share the fixed-width right column.
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

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::str::FromStr;

use crossterm::event::KeyCode;
use ratatui::buffer::Buffer;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::symbols::Marker;
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Axis, Cell, Chart, Dataset, Gauge, GraphType, Paragraph, Row, Table, TableState, Widget, Wrap,
};
use ratatui::Frame;

use crate::config::cidr::Cidr;
use crate::config::loader::LoadedConfig;
use crate::config::schema::Subnet;
use crate::ipc::protocol::{DeviceViewDto, UnmappedDeviceDto};
use crate::tui::app::{App, Leaf};
use crate::tui::format::count as format_count;
use crate::tui::mouse::{self, MouseAction, SortOrder};
use crate::tui::tabs::devices::DETAIL_COLUMN_WIDTH;
use crate::tui::theme::{self, T};

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
// Three-column mode starts only when the traffic/clients column can remain
// wider than the shared 42-cell details column: 38 master + 1 gutter +
// 42 details + 1 extra middle cell on either side of the split.
const NARROW_THRESHOLD: u16 = 120;
const DETAIL_MIN_HEIGHT: u16 = 27;

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
        // Keep the empty state inside the same card as the populated list.
        let content = theme::filled_card(
            f.buffer_mut(),
            area,
            "SUBNETS",
            "Configured & Suggested Address Ranges",
            theme::CardRole::Summary,
        );
        render_empty(f, content);
        return;
    }

    if area.width < NARROW_THRESHOLD || area.height < DETAIL_MIN_HEIGHT {
        app.mouse.subnet_panel = 0;
        render_master(
            f,
            area,
            device_view,
            configured,
            &candidates,
            app.subnets.selected_id.as_deref(),
            &mut app.subnets.table_state,
        );
        mouse::register(app, area, MouseAction::SubnetPanel(0));
        register_master_mouse(app, area, total);
        return;
    }

    let detail_width = DETAIL_COLUMN_WIDTH.min(area.width);
    let list_width = (area.width / 3 + 1)
        .min(area.width.saturating_sub(detail_width.saturating_mul(2)) + 1)
        .max(32);
    let list_area = Rect::new(area.x, area.y, list_width, area.height);
    let right_area = Rect::new(
        area.x + list_width.saturating_sub(1),
        area.y,
        area.width.saturating_sub(list_width) + 1,
        area.height,
    );

    render_master(
        f,
        list_area,
        device_view,
        configured,
        &candidates,
        app.subnets.selected_id.as_deref(),
        &mut app.subnets.table_state,
    );
    mouse::register(app, list_area, MouseAction::SubnetPanel(0));
    register_master_mouse(app, list_area, configured.len() + candidates.len());
    render_detail(f, right_area, app, configured, &candidates);
}

/// Handle focus navigation for the five subnet panels. The root dispatcher
/// calls this before the legacy Lists-style key handler, so arrows in a
/// focused detail panel can never move the master subnet accidentally.
pub fn handle_panel_key(app: &mut App, key: KeyCode) -> bool {
    let panel = app.mouse.subnet_panel.min(4);
    let max_scroll = app.mouse.subnet_clients_max_scroll.get();
    app.mouse.subnet_clients_scroll = app.mouse.subnet_clients_scroll.min(max_scroll);
    match key {
        KeyCode::Up | KeyCode::Down | KeyCode::PageUp | KeyCode::PageDown if panel == 2 => {
            match key {
                KeyCode::Up => {
                    app.mouse.subnet_clients_scroll =
                        app.mouse.subnet_clients_scroll.saturating_sub(1)
                }
                KeyCode::Down => {
                    app.mouse.subnet_clients_scroll =
                        app.mouse.subnet_clients_scroll.saturating_add(1)
                }
                KeyCode::PageUp => {
                    app.mouse.subnet_clients_scroll =
                        app.mouse.subnet_clients_scroll.saturating_sub(8)
                }
                KeyCode::PageDown => {
                    app.mouse.subnet_clients_scroll =
                        app.mouse.subnet_clients_scroll.saturating_add(8)
                }
                _ => unreachable!(),
            }
            app.mouse.subnet_clients_scroll = app.mouse.subnet_clients_scroll.min(max_scroll);
            true
        }
        KeyCode::Home | KeyCode::End if panel == 2 => {
            app.mouse.subnet_clients_scroll = if matches!(key, KeyCode::Home) {
                0
            } else {
                max_scroll
            };
            true
        }
        _ => false,
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
    let content = theme::filled_card(
        f.buffer_mut(),
        area,
        &title,
        &format!(
            "{} Configured · {} Suggested",
            configured.len(),
            candidates.len()
        ),
        theme::CardRole::Summary,
    );

    let header = Row::new(vec![
        Cell::from("ID / CIDR"),
        Cell::from("DEV"),
        Cell::from("PROFILE"),
    ])
    .style(theme::table_heading_style(false));

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

fn register_master_mouse(app: &App, area: Rect, row_count: usize) {
    let offset = app.subnets.table_state.offset();
    for (area, index) in master_row_hit_areas(area, row_count, offset) {
        mouse::register(app, area, MouseAction::Row(Leaf::Subnets, index));
    }
}

fn master_row_hit_areas(
    area: Rect,
    row_count: usize,
    offset: usize,
) -> impl Iterator<Item = (Rect, usize)> {
    let content = card_body_area(area);
    let visible_rows = content.height.saturating_sub(1) as usize / 2;
    let count = visible_rows.min(row_count.saturating_sub(offset));
    (0..count).map(move |visible| {
        (
            Rect::new(
                content.x,
                content.y + 1 + visible as u16 * 2,
                content.width,
                2,
            ),
            offset + visible,
        )
    })
}

fn card_body_area(area: Rect) -> Rect {
    Rect::new(
        area.x.saturating_add(2),
        area.y.saturating_add(3),
        area.width.saturating_sub(4),
        area.height.saturating_sub(4),
    )
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
            Cell::from(vec![
                Line::from(s.id.as_str().to_string()),
                Line::styled(s.cidrs.join(", "), Style::default().fg(T.text_muted)),
            ]),
            Cell::from(dev_count.to_string()),
            Cell::from(s.profile.as_str().to_string()),
        ])
        .height(2)
    });

    let candidate_rows = candidates.iter().map(|c| {
        Row::new(vec![
            Cell::from(vec![
                Line::styled(c.cidr.clone(), Style::default().fg(T.text_muted)),
                Line::from(Span::styled(
                    SUBNET_SUGGESTED_TAG,
                    Style::default()
                        .fg(T.text_muted)
                        .add_modifier(Modifier::ITALIC),
                )),
            ]),
            Cell::from(c.host_count.to_string()),
            Cell::from(Span::styled("—", Style::default().fg(T.text_muted))),
        ])
        .height(2)
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

    let Some(sel) = selection else {
        render_detail_placeholder(f, area, "Select a subnet on the left to see traffic");
        return;
    };

    let detail_width = DETAIL_COLUMN_WIDTH.min(area.width);
    let center_width = area.width.saturating_sub(detail_width) + 1;
    let top_height = (area.height * 2 / 5).clamp(12, 18).min(area.height);
    let center = Rect::new(area.x, area.y, center_width, area.height);
    let right = Rect::new(
        area.x + center_width.saturating_sub(1),
        area.y,
        area.width.saturating_sub(center_width) + 1,
        area.height,
    );
    let rows = theme::split_card_rows(center, top_height);
    let right_rows = theme::split_card_rows(right, top_height);

    // Register the broad panel targets before the nested table header and
    // sort targets. Mouse wheel resolution uses these rectangles to focus
    // the panel before forwarding the wheel key.
    mouse::register(app, rows[0], MouseAction::SubnetPanel(1));
    mouse::register(app, rows[1], MouseAction::SubnetPanel(2));
    mouse::register(app, right_rows[0], MouseAction::SubnetPanel(3));
    mouse::register(app, right_rows[1], MouseAction::SubnetPanel(4));

    match sel {
        Selection::Configured(s) => {
            render_traffic(f, rows[0], app, &s.cidrs);
            render_clients(f, rows[1], app, &s.cidrs);
            render_block_rate(f, right_rows[0], app, &s.cidrs);
            render_stats_for_configured(f, right_rows[1], app, s);
        }
        Selection::Candidate(c) => {
            render_traffic_for_candidate(f, rows[0], app, c);
            render_clients_for_candidate(f, rows[1], app, c);
            render_block_rate_for_candidate(f, right_rows[0], app, c);
            render_stats_for_candidate(f, right_rows[1], c);
        }
    }
}

/// Render the keyboard-opened subnet inspection surface. Narrow layouts keep
/// the master list uncluttered and expose these views through `i` and `c`;
/// wide layouts use the same surface for a focused, full-height inspection.
pub fn render_inspect_overlay(f: &mut Frame, area: Rect, app: &App) {
    use crate::tui::app::SubnetInspect;

    let Some(loaded) = app.loaded_config.as_ref() else {
        return;
    };
    let configured = loaded.config.subnets.as_slice();
    let candidates = discover_candidates(
        app.device_view
            .as_ref()
            .map(|view| view.unmapped.as_slice())
            .unwrap_or(&[]),
        configured,
    );
    let Some(selection) = app
        .subnets
        .selected_id
        .as_deref()
        .and_then(|key| find_selection(key, configured, &candidates))
    else {
        return;
    };

    let height = area.height.saturating_sub(2).min(34);
    let mut inner =
        crate::tui::modal_form::render_chrome_in(f, area, 88, height, "", T.text_primary, true);
    if inner.is_empty() {
        return;
    }

    crate::tui::modal_form::close_footer(f, crate::tui::modal_form::content_rect(inner));
    inner.height = inner.height.saturating_sub(2);
    match app.subnets.inspect {
        Some(SubnetInspect::Clients) => match selection {
            Selection::Configured(subnet) => {
                render_clients_content(f, inner, app, &subnet.cidrs, true)
            }
            Selection::Candidate(candidate) => {
                render_clients_for_candidate_content(f, inner, app, candidate, true)
            }
        },
        Some(SubnetInspect::Details) => {
            let detail_height = inner.height.min(12);
            let rows = theme::split_card_rows(inner, detail_height);
            match selection {
                Selection::Configured(subnet) => {
                    render_stats_for_configured_content(f, rows[0], app, subnet, true);
                    render_clients_content(f, rows[1], app, &subnet.cidrs, true);
                }
                Selection::Candidate(candidate) => {
                    render_stats_for_candidate_content(f, rows[0], candidate, true);
                    render_clients_for_candidate_content(f, rows[1], app, candidate, true);
                }
            }
        }
        None => {}
    }
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

fn render_traffic(f: &mut Frame, area: Rect, app: &App, cidrs: &[String]) {
    let dv = app.device_view.as_ref();
    let buckets = dv
        .map(|d| aggregate_subnet_hourly(d, cidrs))
        .unwrap_or_else(|| vec![0u64; 24]);
    let blocked = dv.and_then(|d| aggregate_subnet_blocked_hourly(d, cidrs));
    render_traffic_card(f, area, &buckets, blocked.as_deref(), false, dv.is_some());
}

fn render_traffic_for_candidate(f: &mut Frame, area: Rect, app: &App, c: &CandidateSubnet) {
    // Candidates are unmapped-only by definition (mapped IPs already
    // sit in their owner's `[[devices]]` row). Aggregate just the
    // unmapped ring intersecting the candidate CIDR.
    let dv = app.device_view.as_ref();
    let buckets = dv
        .map(|d| aggregate_subnet_hourly_unmapped_only(d, std::slice::from_ref(&c.cidr)))
        .unwrap_or_else(|| vec![0u64; 24]);
    let blocked = dv.and_then(|d| {
        aggregate_subnet_blocked_hourly_unmapped_only(d, std::slice::from_ref(&c.cidr))
    });
    render_traffic_card(f, area, &buckets, blocked.as_deref(), true, dv.is_some());
}

fn render_traffic_card(
    f: &mut Frame,
    area: Rect,
    buckets: &[u64],
    blocked: Option<&[u64]>,
    suggested: bool,
    available: bool,
) {
    let total = buckets
        .iter()
        .fold(0u64, |sum, value| sum.saturating_add(*value));
    let blocked_total = blocked.map(|values| {
        values
            .iter()
            .fold(0u64, |sum, value| sum.saturating_add(*value))
    });
    let prefix = if suggested { "Suggested · " } else { "" };
    let description = if available {
        format!(
            "{prefix}24H Queries · Total {} · Blocked {}",
            format_count(total),
            blocked_total
                .map(format_count)
                .unwrap_or_else(|| "Unavailable".to_string())
        )
    } else {
        "Waiting for Daemon".to_string()
    };
    let legend = Line::from(vec![
        Span::styled("⠿ Total", Style::default().fg(T.chart_2)),
        Span::raw("  "),
        Span::styled(
            if blocked.is_some() {
                "⠿ Blocked"
            } else {
                "⠿ Blocked N/A"
            },
            Style::default().fg(T.brand_red),
        ),
    ]);
    let body = theme::filled_card_with_subtitle(
        f.buffer_mut(),
        area,
        "SUBNET TRAFFIC",
        theme::card_subtitle_with_legend(area, &description, legend),
        theme::CardRole::Analytics,
    );
    if available {
        paint_chart(f, body, buckets, blocked);
    } else {
        f.render_widget(
            Paragraph::new("Hourly data unavailable").style(Style::default().fg(T.text_muted)),
            body,
        );
    }
}

fn paint_chart(f: &mut Frame, area: Rect, buckets: &[u64], blocked: Option<&[u64]>) {
    if area.height < 4 {
        return;
    }
    let total: u64 = buckets.iter().sum();
    let blocked_total = blocked
        .map(|values| values.iter().sum::<u64>())
        .unwrap_or(0);
    if total == 0 && blocked_total == 0 {
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
    let max_y = buckets
        .iter()
        .copied()
        .chain(blocked.unwrap_or(&[]).iter().copied())
        .max()
        .unwrap_or(1) as f64;
    let x_max = (buckets.len().max(1) - 1) as f64;

    let mut datasets = vec![Dataset::default()
        .marker(Marker::Braille)
        .graph_type(GraphType::Line)
        .style(Style::default().fg(T.chart_2))
        .data(&series)];
    let blocked_series: Vec<(f64, f64)> = blocked
        .unwrap_or(&[])
        .iter()
        .enumerate()
        .map(|(i, n)| (i as f64, *n as f64))
        .collect();
    if blocked.is_some() {
        datasets.push(
            Dataset::default()
                .marker(Marker::Braille)
                .graph_type(GraphType::Line)
                .style(Style::default().fg(T.brand_red))
                .data(&blocked_series),
        );
    }

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
        )
        .style(Style::default().fg(T.text_primary).bg(T.bg_elevated));

    let chart_cols = Layout::horizontal([
        Constraint::Length(1),
        Constraint::Min(1),
        Constraint::Length(1),
    ])
    .split(area);
    f.render_widget(chart, chart_cols[1]);
}

fn render_block_rate(f: &mut Frame, area: Rect, app: &App, cidrs: &[String]) {
    let Some(dv) = app.device_view.as_ref() else {
        let body = theme::filled_card(
            f.buffer_mut(),
            area,
            "BLOCK RATE",
            "Hourly Estimates",
            theme::CardRole::History,
        );
        f.render_widget(
            Paragraph::new("Hourly data unavailable").style(Style::default().fg(T.text_muted)),
            body,
        );
        return;
    };
    let queries = aggregate_subnet_hourly(dv, cidrs);
    let blocked = aggregate_subnet_blocked_hourly(dv, cidrs);
    let body = theme::filled_card(
        f.buffer_mut(),
        area,
        "BLOCK RATE",
        "Hourly Estimates",
        theme::CardRole::History,
    );
    paint_subnet_block_rate(f, body, &queries, blocked.as_deref());
}

fn render_block_rate_for_candidate(
    f: &mut Frame,
    area: Rect,
    app: &App,
    candidate: &CandidateSubnet,
) {
    let queries = app
        .device_view
        .as_ref()
        .map(|dv| aggregate_subnet_hourly_unmapped_only(dv, std::slice::from_ref(&candidate.cidr)));
    let blocked = app.device_view.as_ref().and_then(|dv| {
        aggregate_subnet_blocked_hourly_unmapped_only(dv, std::slice::from_ref(&candidate.cidr))
    });
    let subtitle = if blocked.is_some() {
        "Hourly Estimates · 24 UTC hours"
    } else {
        "Hourly Estimates · Blocked Unavailable"
    };
    let body = theme::filled_card(
        f.buffer_mut(),
        area,
        "BLOCK RATE",
        subtitle,
        theme::CardRole::History,
    );
    match queries {
        Some(queries) => paint_subnet_block_rate(f, body, &queries, blocked.as_deref()),
        None => f.render_widget(
            Paragraph::new("Hourly data unavailable").style(Style::default().fg(T.text_muted)),
            body,
        ),
    }
}

fn paint_subnet_block_rate(f: &mut Frame, area: Rect, queries: &[u64], blocked: Option<&[u64]>) {
    if blocked.is_some_and(|values| values.len() != queries.len()) {
        f.render_widget(
            Paragraph::new("Hourly data unavailable (window mismatch)")
                .style(Style::default().fg(T.text_muted)),
            area,
        );
        return;
    }
    for (index, (label, hours)) in [("1h", 1usize), ("3h", 3), ("12h", 12), ("24h", 24)]
        .into_iter()
        .enumerate()
    {
        let y = area.y + index as u16 * 2;
        if y + 1 >= area.bottom() {
            break;
        }
        let start = queries.len().saturating_sub(hours);
        let total: u64 = queries[start..].iter().sum();
        let Some(blocked) = blocked else {
            f.render_widget(
                Paragraph::new(format!("{label:<3} — blocked unavailable"))
                    .style(Style::default().fg(T.text_muted)),
                Rect::new(area.x, y, area.width, 1),
            );
            continue;
        };
        let blocked_total: u64 = blocked[start..].iter().sum();
        let ratio = if total == 0 {
            0.0
        } else {
            (blocked_total as f64 / total as f64).clamp(0.0, 1.0)
        };
        f.render_widget(
            Paragraph::new(format!(
                "{label:<3} {:>5.1}% {} / {}",
                ratio * 100.0,
                format_count(blocked_total),
                format_count(total)
            ))
            .style(Style::default().fg(T.text_primary)),
            Rect::new(area.x, y, area.width, 1),
        );
        percentage_bar(
            f.buffer_mut(),
            Rect::new(area.x, y + 1, area.width, 1),
            ratio,
            T.brand_red,
        );
    }
}

fn percentage_bar(buf: &mut Buffer, area: Rect, ratio: f64, color: Color) {
    let ratio = ratio.clamp(0.0, 1.0);
    Gauge::default()
        .ratio(ratio)
        .label("")
        .use_unicode(true)
        .gauge_style(Style::default().fg(color).bg(T.border_default))
        .render(area, buf);
    let full_cells = (f64::from(area.width) * ratio).floor() as u16;
    for y in area.y..area.bottom() {
        for x in area.x..area.x + full_cells {
            buf[(x, y)]
                .set_symbol("░")
                .set_fg(color)
                .set_bg(T.border_default);
        }
    }
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

// ── Stats sub-pane (KV table, 6-8 metrics) ─────────────────────────────────

fn detail_frame(
    f: &mut Frame,
    area: Rect,
    title: &str,
    description: &str,
    role: theme::CardRole,
    modal: bool,
) -> Rect {
    if modal {
        crate::tui::modal_form::render_header(f, area, title, description)
    } else {
        theme::filled_card(f.buffer_mut(), area, title, description, role)
    }
}

fn render_stats_for_configured(f: &mut Frame, area: Rect, app: &App, s: &Subnet) {
    render_stats_for_configured_content(f, area, app, s, false);
}

fn render_stats_for_configured_content(
    f: &mut Frame,
    area: Rect,
    app: &App,
    s: &Subnet,
    modal: bool,
) {
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
        ("ID", s.id.as_str().to_string()),
        (
            "Name",
            if s.display_name.is_empty() {
                s.id.as_str().to_string()
            } else {
                s.display_name.clone()
            },
        ),
        ("CIDRs", s.cidrs.join(", ")),
        ("Profile", s.profile.as_str().to_string()),
        ("Priority", s.priority.to_string()),
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
    let body = detail_frame(
        f,
        area,
        "SUBNET DETAILS",
        "Identity, Policy & Activity",
        theme::CardRole::History,
        modal,
    );
    paint_kv_table(f, body, &lines);
}

fn render_stats_for_candidate(f: &mut Frame, area: Rect, c: &CandidateSubnet) {
    render_stats_for_candidate_content(f, area, c, false);
}

fn render_stats_for_candidate_content(f: &mut Frame, area: Rect, c: &CandidateSubnet, modal: bool) {
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
    let body = detail_frame(
        f,
        area,
        "SUBNET DETAILS",
        "Suggested Subnet · Not Configured",
        theme::CardRole::History,
        modal,
    );
    paint_kv_table(f, body, &lines);
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
    render_clients_content(f, area, app, cidrs, false);
}

fn render_clients_content(f: &mut Frame, area: Rect, app: &App, cidrs: &[String], modal: bool) {
    let Some(dv) = app.device_view.as_ref() else {
        let body = detail_frame(
            f,
            area,
            "SUBNET CLIENTS",
            "Waiting for Daemon",
            theme::CardRole::Analytics,
            modal,
        );
        render_detail_placeholder(f, body, "waiting for daemon\u{2026}");
        return;
    };
    let clients = filter_clients_in_subnet(dv, cidrs);
    let body = detail_frame(
        f,
        area,
        "SUBNET CLIENTS",
        &format!("{} Clients · Queries Today (UTC)", clients.len()),
        theme::CardRole::Analytics,
        modal,
    );
    if clients.is_empty() {
        render_detail_placeholder(f, body, "no clients in this subnet");
    } else {
        paint_client_table(f, body, &clients, app);
    }
}

fn render_clients_for_candidate(f: &mut Frame, area: Rect, app: &App, c: &CandidateSubnet) {
    render_clients_for_candidate_content(f, area, app, c, false);
}

fn render_clients_for_candidate_content(
    f: &mut Frame,
    area: Rect,
    app: &App,
    c: &CandidateSubnet,
    modal: bool,
) {
    let Some(dv) = app.device_view.as_ref() else {
        let body = detail_frame(
            f,
            area,
            "SUBNET CLIENTS",
            "Suggested · Queries Today (UTC)",
            theme::CardRole::Analytics,
            modal,
        );
        render_detail_placeholder(f, body, "waiting for daemon\u{2026}");
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
    let body = detail_frame(
        f,
        area,
        "SUBNET CLIENTS",
        &format!("{} Clients · Queries Today (UTC)", rows.len()),
        theme::CardRole::Analytics,
        modal,
    );
    if rows.is_empty() {
        render_detail_placeholder(f, body, "no observed clients");
    } else {
        paint_client_table(f, body, &rows, app);
    }
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

fn paint_client_table(f: &mut Frame, area: Rect, clients: &[ClientRow], app: &App) {
    let mut sorted = clients.to_vec();
    if let Some(sort) = app.mouse.subnet_client_sort {
        sorted.sort_by(|a, b| compare_client(a, b, sort));
    }
    let header = Row::new(
        ["IP", "NAME", "VENDOR", "Q.TODAY"]
            .into_iter()
            .enumerate()
            .map(|(column, label)| {
                Cell::from(mouse::sort_label(
                    label,
                    column,
                    app.mouse.subnet_client_sort,
                ))
                .style(theme::table_heading_style(
                    app.subnets.client_sort_focus == Some(column)
                        || app
                            .mouse
                            .subnet_client_sort
                            .is_some_and(|sort| sort.column == column),
                ))
            }),
    )
    .style(theme::table_heading_style(false));
    let visible_rows = area.height.saturating_sub(1) as usize;
    app.mouse
        .subnet_clients_max_scroll
        .set(sorted.len().saturating_sub(visible_rows));
    let (offset, end) =
        client_window_bounds(sorted.len(), visible_rows, app.mouse.subnet_clients_scroll);
    let rows: Vec<Row> = sorted
        .iter()
        .skip(offset)
        .take(end.saturating_sub(offset))
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
    let constraints = [
        Constraint::Length(15),
        Constraint::Min(10),
        Constraint::Length(16),
        Constraint::Length(8),
    ];
    for (column, column_area) in crate::tui::ui::table_column_rects(area, &constraints, 1, 0)
        .into_iter()
        .enumerate()
    {
        mouse::register(app, column_area, MouseAction::SubnetClientSort(column));
    }
}

fn client_window_bounds(total: usize, visible: usize, requested: usize) -> (usize, usize) {
    let max_scroll = total.saturating_sub(visible);
    let offset = requested.min(max_scroll);
    (offset, total.min(offset.saturating_add(visible)))
}

fn compare_client(a: &ClientRow, b: &ClientRow, sort: SortOrder) -> Ordering {
    let primary = match sort.column {
        0 => compare_ip(&a.ip, &b.ip),
        1 => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
        2 => a
            .vendor
            .as_deref()
            .unwrap_or("")
            .to_lowercase()
            .cmp(&b.vendor.as_deref().unwrap_or("").to_lowercase()),
        3 => a.queries.cmp(&b.queries),
        _ => Ordering::Equal,
    };
    let primary = if sort.descending {
        primary.reverse()
    } else {
        primary
    };
    primary.then_with(|| a.ip.cmp(&b.ip))
}

fn compare_ip(a: &str, b: &str) -> Ordering {
    match (IpAddr::from_str(a), IpAddr::from_str(b)) {
        (Ok(a), Ok(b)) => a.cmp(&b),
        _ => a.cmp(b),
    }
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

/// Sum the optional per-device blocked ring using the same CIDR projection
/// as queries. `None` is deliberately contagious: an old daemon or a
/// partially unavailable device must remain visibly unavailable rather than
/// becoming an invented zero-valued series.
pub fn aggregate_subnet_blocked_hourly(dv: &DeviceViewDto, cidrs: &[String]) -> Option<Vec<u64>> {
    let parsed: Vec<Cidr> = cidrs.iter().filter_map(|c| Cidr::parse(c).ok()).collect();
    if parsed.is_empty() {
        return Some(vec![0; 24]);
    }
    let mut out = vec![0u64; 24];
    for m in &dv.mapped {
        if let Ok(ip) = IpAddr::from_str(&m.ip) {
            if parsed.iter().any(|c| c.contains(ip)) {
                add_optional_ring(&mut out, m.hourly_blocked.as_deref())?;
            }
        }
    }
    for u in &dv.unmapped {
        if let Ok(ip) = IpAddr::from_str(&u.ip) {
            if parsed.iter().any(|c| c.contains(ip)) {
                add_optional_ring(&mut out, u.hourly_blocked.as_deref())?;
            }
        }
    }
    Some(out)
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

fn aggregate_subnet_blocked_hourly_unmapped_only(
    dv: &DeviceViewDto,
    cidrs: &[String],
) -> Option<Vec<u64>> {
    let parsed: Vec<Cidr> = cidrs.iter().filter_map(|c| Cidr::parse(c).ok()).collect();
    if parsed.is_empty() {
        return Some(vec![0; 24]);
    }
    let mut out = vec![0u64; 24];
    for u in &dv.unmapped {
        if let Ok(ip) = IpAddr::from_str(&u.ip) {
            if parsed.iter().any(|c| c.contains(ip)) {
                add_optional_ring(&mut out, u.hourly_blocked.as_deref())?;
            }
        }
    }
    Some(out)
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

fn add_optional_ring(dst: &mut [u64], src: Option<&[u64]>) -> Option<()> {
    let src = src?;
    add_ring(dst, src);
    Some(())
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
/// window-consistent block rate — see [`paint_subnet_block_rate`].
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
    let content = theme::filled_card(
        f.buffer_mut(),
        area,
        "SUBNETS",
        "Configuration unavailable",
        theme::CardRole::Summary,
    );
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
            hourly_blocked: None,
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
            hourly_blocked: None,
            unfiltered: false,
        }
    }

    fn with_blocked<T>(mut dto: T, hourly_blocked: Vec<u64>) -> T
    where
        T: SetHourlyBlocked,
    {
        dto.set_hourly_blocked(hourly_blocked);
        dto
    }

    trait SetHourlyBlocked {
        fn set_hourly_blocked(&mut self, value: Vec<u64>);
    }

    impl SetHourlyBlocked for MappedDeviceDto {
        fn set_hourly_blocked(&mut self, value: Vec<u64>) {
            self.hourly_blocked = Some(value);
        }
    }

    impl SetHourlyBlocked for UnmappedDeviceDto {
        fn set_hourly_blocked(&mut self, value: Vec<u64>) {
            self.hourly_blocked = Some(value);
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

    fn buffer_row(buf: &ratatui::buffer::Buffer, y: u16) -> String {
        let area = *buf.area();
        (area.x..area.right())
            .map(|x| buf[(x, y)].symbol())
            .collect()
    }

    #[test]
    fn traffic_chart_paints_the_elevated_card_surface() {
        use ratatui::{backend::TestBackend, Terminal};

        let mut terminal = Terminal::new(TestBackend::new(30, 8)).unwrap();
        terminal
            .draw(|f| paint_chart(f, f.area(), &[1, 3, 2], Some(&[0, 1, 1])))
            .unwrap();
        let buffer = terminal.backend().buffer();
        for y in 0..8 {
            for x in 1..29 {
                assert_eq!(buffer[(x, y)].bg, T.bg_elevated, "cell ({x}, {y})");
            }
        }
    }

    #[test]
    fn percentage_bar_keeps_track_and_fractional_endpoint() {
        let mut buffer = Buffer::empty(Rect::new(0, 0, 10, 1));
        percentage_bar(&mut buffer, Rect::new(0, 0, 10, 1), 0.25, T.brand_red);

        assert_eq!(buffer[(0, 0)].symbol(), "░");
        assert_eq!(buffer[(1, 0)].symbol(), "░");
        assert_ne!(buffer[(2, 0)].symbol(), " ");
        assert_ne!(buffer[(2, 0)].symbol(), "░");
        assert_eq!(buffer[(9, 0)].bg, T.border_default);
    }

    #[test]
    fn traffic_legend_stays_in_the_subtitle_with_both_series_colors() {
        use ratatui::{backend::TestBackend, Terminal};
        for width in [44, 80, 125] {
            let mut terminal = Terminal::new(TestBackend::new(width, 12)).unwrap();
            terminal
                .draw(|f| {
                    render_traffic_card(f, f.area(), &[4, 3, 1], Some(&[2, 1, 1]), false, true);
                })
                .unwrap();
            let buffer = terminal.backend().buffer();
            let subtitle = theme::card_subtitle_area(*buffer.area());
            let row: String = (subtitle.x..subtitle.right())
                .map(|x| buffer[(x, subtitle.y)].symbol())
                .collect();
            assert!(row.ends_with("⠿ Total  ⠿ Blocked"), "{row}");
            assert_eq!(buffer[(subtitle.right() - 18, subtitle.y)].fg, T.chart_2);
            assert_eq!(buffer[(subtitle.right() - 9, subtitle.y)].fg, T.brand_red);
            for y in 3..11 {
                let row: String = (0..width).map(|x| buffer[(x, y)].symbol()).collect();
                assert!(!row.contains("Total") && !row.contains("Blocked"));
            }
            for color in [T.chart_2, T.brand_red] {
                assert!(
                    (3..11).any(|y| (0..width).any(|x| {
                        let cell = &buffer[(x, y)];
                        cell.fg == color
                            && cell
                                .symbol()
                                .chars()
                                .any(|ch| ('\u{2801}'..='\u{28ff}').contains(&ch))
                    })),
                    "missing plotted series {color:?}"
                );
            }
        }
    }

    #[test]
    fn traffic_distinguishes_missing_blocked_history_and_missing_daemon() {
        use ratatui::{backend::TestBackend, Terminal};
        for available in [false, true] {
            let mut terminal = Terminal::new(TestBackend::new(44, 12)).unwrap();
            terminal
                .draw(|f| render_traffic_card(f, f.area(), &[4, 3, 1], None, false, available))
                .unwrap();
            let buffer = terminal.backend().buffer();
            assert!(buffer_contains(buffer, "Blocked N/A"));
            assert_eq!(
                buffer_contains(buffer, "Hourly data unavailable"),
                !available
            );
        }
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
    fn master_pane_renders_each_subnet_as_two_lines() {
        use ratatui::{backend::TestBackend, Terminal};

        let configured = vec![mk_subnet(
            "lan-corp",
            &["10.10.0.0/16", "fd00:10::/64"],
            "default",
        )];
        let candidates = vec![CandidateSubnet {
            cidr: "192.168.50.0/24".into(),
            host_count: 2,
            queries_today: 3,
            vendor_tally: Vec::new(),
        }];
        let mut table_state = TableState::default();
        let mut terminal = Terminal::new(TestBackend::new(60, 14)).unwrap();
        terminal
            .draw(|f| {
                render_master(
                    f,
                    f.area(),
                    None,
                    &configured,
                    &candidates,
                    Some("lan-corp"),
                    &mut table_state,
                );
            })
            .unwrap();
        let buffer = terminal.backend().buffer();
        assert!(buffer_row(buffer, 4).contains("lan-corp"));
        assert!(buffer_row(buffer, 5).contains("10.10.0.0/16, fd00:10::/64"));
        assert!(buffer_row(buffer, 6).contains("192.168.50.0/24"));
        assert!(buffer_row(buffer, 7).contains(SUBNET_SUGGESTED_TAG));
    }

    #[test]
    fn configured_details_include_config_identity_and_precedence() {
        use ratatui::{backend::TestBackend, Terminal};

        let mut subnet = mk_subnet("lan-corp", &["10.10.0.0/16"], "strict");
        subnet.display_name = "Corporate LAN".into();
        subnet.priority = 50;
        let app = App::new();
        let mut terminal = Terminal::new(TestBackend::new(48, 18)).unwrap();
        terminal
            .draw(|f| render_stats_for_configured(f, f.area(), &app, &subnet))
            .unwrap();
        let buffer = terminal.backend().buffer();
        for value in ["lan-corp", "Corporate LAN", "10.10.0.0/16", "strict", "50"] {
            assert!(
                buffer_contains(buffer, value),
                "missing detail value {value}"
            );
        }
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
    fn detail_grid_uses_a_shared_gutter_and_fixed_right_column() {
        use ratatui::{backend::TestBackend, Terminal};
        let area = Rect::new(0, 0, 100, 30);
        let center_width = area.width - DETAIL_COLUMN_WIDTH + 1;
        let columns = [
            Rect::new(area.x, area.y, center_width, area.height),
            Rect::new(
                area.x + center_width - 1,
                area.y,
                DETAIL_COLUMN_WIDTH,
                area.height,
            ),
        ];
        assert_eq!(columns[1].width, DETAIL_COLUMN_WIDTH);
        assert!(columns[0].width > columns[1].width);
        let top_height = (area.height * 2 / 5).clamp(12, 18);
        let rows = theme::split_card_rows(columns[0], top_height);
        assert_eq!(rows[0].height, 12);
        assert_eq!(rows[1].y, rows[0].bottom() - 1);
        assert_eq!(rows[1].height, 19);
        let mut app = App::new();
        app.subnets.selected_id = Some("lan".into());
        let configured = vec![mk_subnet("lan", &["10.0.0.0/8"], "default")];
        let mut terminal = Terminal::new(TestBackend::new(100, 30)).unwrap();
        terminal
            .draw(|f| render_detail(f, f.area(), &app, &configured, &[]))
            .unwrap();
        let buffer = terminal.backend().buffer();
        for y in 0..30 {
            let cell = &buffer[(columns[1].x, y)];
            assert_eq!(cell.symbol(), " ");
            assert_eq!(cell.bg, T.bg_main);
        }
        for x in 0..100 {
            assert_eq!(buffer[(x, 11)].symbol(), " ");
            assert_eq!(buffer[(x, 11)].bg, T.bg_main);
        }
        for x in [columns[0].x + 1, columns[1].x + 1] {
            let role = if x == 1 {
                theme::CardRole::Analytics
            } else {
                theme::CardRole::History
            };
            for y in [1, 12] {
                assert_eq!(buffer[(x, y)].bg, T.card_title_bg(role));
                assert_eq!(buffer[(x, y + 1)].bg, T.card_subtitle_bg(role));
            }
        }
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
    fn s51_client_sort_is_numeric_textual_and_stable() {
        let clients = vec![
            ClientRow {
                ip: "10.0.0.2".into(),
                name: "same".into(),
                vendor: Some("Acme".into()),
                queries: 2,
            },
            ClientRow {
                ip: "10.0.0.10".into(),
                name: "same".into(),
                vendor: Some("Acme".into()),
                queries: 2,
            },
            ClientRow {
                ip: "10.0.0.3".into(),
                name: "Other".into(),
                vendor: None,
                queries: 9,
            },
        ];
        let mut by_ip = clients.clone();
        by_ip.sort_by(|a, b| {
            compare_client(
                a,
                b,
                SortOrder {
                    column: 0,
                    descending: false,
                },
            )
        });
        assert_eq!(
            by_ip.iter().map(|c| c.ip.as_str()).collect::<Vec<_>>(),
            vec!["10.0.0.2", "10.0.0.3", "10.0.0.10"]
        );
        let mut by_queries = clients.clone();
        by_queries.sort_by(|a, b| {
            compare_client(
                a,
                b,
                SortOrder {
                    column: 3,
                    descending: true,
                },
            )
        });
        assert_eq!(by_queries[0].queries, 9);
        assert_eq!(by_queries[1].ip, "10.0.0.10");
        assert_eq!(by_queries[2].ip, "10.0.0.2");

        for descending in [false, true] {
            let mut by_equal_name = clients[..2].to_vec();
            by_equal_name.sort_by(|a, b| {
                compare_client(
                    a,
                    b,
                    SortOrder {
                        column: 1,
                        descending,
                    },
                )
            });
            assert_eq!(
                by_equal_name
                    .iter()
                    .map(|client| client.ip.as_str())
                    .collect::<Vec<_>>(),
                ["10.0.0.10", "10.0.0.2"],
                "equal primary values retain an ascending immutable-IP tie"
            );
        }
    }

    #[test]
    fn s51_subnet_mouse_geometry_has_exact_headers_and_separate_rows() {
        let body = card_body_area(Rect::new(10, 4, 70, 16));
        assert_eq!(body, Rect::new(12, 7, 66, 12));
        let columns = Layout::horizontal([
            Constraint::Length(15),
            Constraint::Min(10),
            Constraint::Length(16),
            Constraint::Length(8),
        ])
        .split(Rect::new(body.x, body.y, body.width, 1));
        assert_eq!(columns.iter().map(|c| c.width).sum::<u16>(), body.width);
        assert_eq!(columns[0].x, body.x);
        assert_eq!(columns[1].x, body.x + 15);
        assert_eq!(columns[2].x, body.right() - 24);
        assert_eq!(columns[3].x, body.right() - 8);
        let first_client_row = body.y + 1;
        assert_ne!(first_client_row, body.y, "client rows are below headers");
        let targets = master_row_hit_areas(Rect::new(10, 4, 70, 16), 10, 3).collect::<Vec<_>>();
        assert_eq!(targets.len(), 5);
        assert_eq!(targets[0], (Rect::new(12, 8, 66, 2), 3));
        assert_eq!(targets[1], (Rect::new(12, 10, 66, 2), 4));
        assert_eq!(targets[4], (Rect::new(12, 16, 66, 2), 7));
        assert!(targets
            .windows(2)
            .all(|pair| pair[0].0.bottom() == pair[1].0.y));
        const {
            assert!(NARROW_THRESHOLD > 38 + 1 + DETAIL_COLUMN_WIDTH + 1);
        }
    }

    #[test]
    fn detail_panel_arrows_do_not_swallow_master_navigation() {
        let mut app = App::new();
        app.subnets.table_state.select(Some(3));
        app.mouse.subnet_panel = 4;
        assert!(!handle_panel_key(&mut app, KeyCode::Left));
        assert!(!handle_panel_key(&mut app, KeyCode::Right));
        assert!(!handle_panel_key(&mut app, KeyCode::PageDown));
        assert!(!handle_panel_key(&mut app, KeyCode::Esc));
        assert_eq!(app.subnets.table_state.selected(), Some(3));

        app.mouse.subnet_panel = 2;
        app.mouse.subnet_clients_max_scroll.set(8);
        assert!(handle_panel_key(&mut app, KeyCode::PageDown));
        assert_eq!(app.mouse.subnet_clients_scroll, 8);
    }

    #[test]
    fn s51_client_panel_scroll_clamps_and_reaches_the_last_visible_page() {
        assert_eq!(client_window_bounds(20, 5, 0), (0, 5));
        assert_eq!(client_window_bounds(20, 5, usize::MAX), (15, 20));
        let mut app = App::new();
        app.mouse.subnet_panel = 2;
        app.mouse.subnet_clients_max_scroll.set(15);
        for _ in 0..4 {
            assert!(handle_panel_key(&mut app, KeyCode::PageDown));
        }
        assert_eq!(app.mouse.subnet_clients_scroll, 15);
        assert_eq!(
            client_window_bounds(20, 5, app.mouse.subnet_clients_scroll),
            (15, 20)
        );
        assert!(handle_panel_key(&mut app, KeyCode::Home));
        assert_eq!(app.mouse.subnet_clients_scroll, 0);
        assert!(handle_panel_key(&mut app, KeyCode::End));
        assert!(handle_panel_key(&mut app, KeyCode::Up));
        assert_eq!(app.mouse.subnet_clients_scroll, 14);
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

    #[test]
    fn s51_blocked_hourly_aggregation_preserves_order_and_maps_both_slices() {
        let mapped = with_blocked(
            mk_mapped_with_ring("10.0.0.5", "mapped", vec![4, 3, 1]),
            vec![2, 1, 0],
        );
        let unmapped = with_blocked(
            mk_unmapped_with_ring("10.0.0.6", None, 0, vec![8, 7, 6]),
            vec![3, 2, 1],
        );
        let outside = with_blocked(
            mk_unmapped_with_ring("10.0.1.6", None, 0, vec![99, 99, 99]),
            vec![99, 99, 99],
        );
        let dv = DeviceViewDto {
            mapped: vec![mapped],
            unmapped: vec![unmapped, outside],
        };
        let queries = aggregate_subnet_hourly(&dv, &["10.0.0.0/24".into()]);
        let blocked = aggregate_subnet_blocked_hourly(&dv, &["10.0.0.0/24".into()]).unwrap();
        assert_eq!(&queries[..3], &[12, 10, 7]);
        assert_eq!(&blocked[..3], &[5, 3, 1]);
        assert_eq!(queries[3..].iter().sum::<u64>(), 0);
        assert_eq!(blocked[3..].iter().sum::<u64>(), 0);
    }

    #[test]
    fn s51_blocked_hourly_aggregation_is_unavailable_when_matching_device_lacks_series() {
        let known = with_blocked(
            mk_unmapped_with_ring("10.0.0.5", None, 0, vec![1; 24]),
            vec![1; 24],
        );
        let old_daemon = mk_unmapped_with_ring("10.0.0.6", None, 0, vec![2; 24]);
        let dv = DeviceViewDto {
            mapped: vec![],
            unmapped: vec![known, old_daemon],
        };
        assert_eq!(
            aggregate_subnet_blocked_hourly(&dv, &["10.0.0.0/24".into()]),
            None,
            "missing hourly_blocked must not be converted into zeroes"
        );
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
