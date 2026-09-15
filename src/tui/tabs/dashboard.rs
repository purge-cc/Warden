//! Dashboard: service and RAM usage, traffic composition and daily history.
mod charts;
mod protection;

use std::time::Instant;

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::buffer::Buffer;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Widget};
use ratatui::Frame;

use crate::tui::app::App;
use crate::tui::jobs::ReadResource;
use crate::tui::{format, text, theme};
use protection::{format_age_short, format_uptime};
use theme::T;

const TITLES: [&str; 8] = [
    "SYSTEM",
    "RESOURCES",
    "BLOCK RATE",
    "DNS TRAFFIC",
    "QUERY TYPES",
    "TOP LISTS",
    "DAILY QUERIES",
    "DAILY BLOCKED",
];
const SUBTITLES: [&str; 8] = [
    "Service Status & DNS Upstreams",
    "CPU & Memory Usage",
    "Hourly Estimates",
    "24H Queries",
    "% of 24H Queries",
    "Attributed Last 24H Hits (Not Exclusive)",
    "Rolling Daily Queries",
    "Rolling Daily Blocked",
];
#[cfg(test)]
const HOUR: u64 = 3_600;
#[cfg(test)]
const DAY: u64 = 86_400;

#[derive(Debug, Clone, Default)]
pub struct DashboardState {
    scroll: u16,
    viewport_height: u16,
    content_height: u16,
    layout_width: u16,
    tracking_at: Option<u64>,
}

pub fn observe_tracking(app: &mut App) {
    app.dashboard.tracking_at = Some(now_secs());
}

fn now_secs() -> u64 {
    time::OffsetDateTime::now_utc().unix_timestamp().max(0) as u64
}

fn anchor(app: &App) -> u64 {
    app.dashboard.tracking_at.unwrap_or_else(now_secs)
}

pub fn handle_key(app: &mut App, key: KeyEvent) -> bool {
    let max_scroll = app
        .dashboard
        .content_height
        .saturating_sub(app.dashboard.viewport_height);
    let page = app.dashboard.viewport_height.saturating_sub(2).max(1);
    match key.code {
        KeyCode::Down => {
            app.dashboard.scroll = app.dashboard.scroll.saturating_add(1).min(max_scroll)
        }
        KeyCode::Up => app.dashboard.scroll = app.dashboard.scroll.saturating_sub(1),
        KeyCode::PageDown => {
            app.dashboard.scroll = app.dashboard.scroll.saturating_add(page).min(max_scroll)
        }
        KeyCode::PageUp => app.dashboard.scroll = app.dashboard.scroll.saturating_sub(page),
        KeyCode::Home => app.dashboard.scroll = 0,
        KeyCode::End => app.dashboard.scroll = max_scroll,
        _ => return false,
    }
    true
}

fn panel_rects(width: u16, viewport_height: u16) -> ([Rect; 8], u16) {
    let mut rects = [Rect::default(); 8];
    if width >= 120 {
        let extra = viewport_height.saturating_sub(35);
        let traffic_height = 14 + extra.div_ceil(2);
        let daily_height = 10 + extra / 2;
        let first = Layout::horizontal([
            Constraint::Percentage(34),
            Constraint::Percentage(33),
            Constraint::Percentage(33),
        ])
        .split(Rect::new(0, 0, width, 13));
        rects[..3].copy_from_slice(&first);
        let second = Layout::horizontal([Constraint::Percentage(67), Constraint::Percentage(33)])
            .split(Rect::new(0, 12, width, traffic_height));
        rects[3..5].copy_from_slice(&second);
        let third = Layout::horizontal([
            Constraint::Percentage(34),
            Constraint::Percentage(33),
            Constraint::Percentage(33),
        ])
        .split(Rect::new(0, 11 + traffic_height, width, daily_height));
        rects[5..].copy_from_slice(&third);
        for index in [0, 1, 3, 5, 6] {
            rects[index].width += 1;
        }
        (rects, 11 + traffic_height + daily_height)
    } else {
        let mut y = 0;
        for (index, rect) in rects.iter_mut().enumerate() {
            let height = if index < 3 {
                13
            } else if matches!(index, 3 | 4) {
                14
            } else {
                12
            };
            *rect = Rect::new(0, y, width, height);
            y += height - 1;
        }
        (rects, y + 1)
    }
}

pub fn render(f: &mut Frame, area: Rect, app: &mut App) {
    if area.is_empty() {
        return;
    }
    let width = area.width.min(320);
    let body = Rect::new(
        area.x + (area.width - width) / 2,
        area.y,
        width,
        area.height,
    );
    let (rects, height) = panel_rects(width, body.height);
    if app.dashboard.layout_width > 0 && (app.dashboard.layout_width < 120) != (width < 120) {
        let (previous, _) = panel_rects(app.dashboard.layout_width, app.dashboard.viewport_height);
        if let Some((index, rect)) = previous
            .iter()
            .enumerate()
            .find(|(_, rect)| rect.bottom().saturating_sub(1) > app.dashboard.scroll)
        {
            let offset = app
                .dashboard
                .scroll
                .saturating_sub(rect.y)
                .min(rects[index].height.saturating_sub(1));
            app.dashboard.scroll = rects[index].y.saturating_add(offset);
        }
    }
    app.dashboard.layout_width = width;
    let scroll = app.dashboard.scroll.min(height.saturating_sub(body.height));
    app.dashboard.scroll = scroll;
    app.dashboard.viewport_height = body.height;
    app.dashboard.content_height = height;

    let mut canvas = Buffer::empty(Rect::new(0, 0, width, height));
    render_system(&mut canvas, rects[0], app);
    render_resources(&mut canvas, rects[1], app);
    let reference = anchor(app);
    if read_error(app, ReadResource::Tracking).is_some() || tracking_disabled(app) {
        for index in [2, 3, 4, 5, 6, 7] {
            unavailable_panel(
                &mut canvas,
                rects[index],
                TITLES[index],
                SUBTITLES[index],
                index,
                app,
            );
        }
    } else {
        charts::render_block_rate(&mut canvas, rects[2], app, reference);
        charts::render_traffic(&mut canvas, rects[3], app, reference, None);
        charts::render_qtypes(&mut canvas, rects[4], app);
        render_top_lists(&mut canvas, rects[5], app);
        charts::render_daily(&mut canvas, rects[6], app, reference, None, false);
        charts::render_daily(&mut canvas, rects[7], app, reference, None, true);
    }
    for row in 0..body.height.min(height.saturating_sub(scroll)) {
        for column in 0..width {
            f.buffer_mut()[(body.x + column, body.y + row)] =
                canvas[(column, scroll + row)].clone();
        }
    }
}

fn card(buf: &mut Buffer, area: Rect, title: &str, subtitle: &str, role: theme::CardRole) -> Rect {
    theme::filled_card(buf, area, title, subtitle, role)
}

fn card_with_subtitle(
    buf: &mut Buffer,
    area: Rect,
    title: &str,
    subtitle: Line<'_>,
    role: theme::CardRole,
) -> Rect {
    theme::filled_card_with_subtitle(buf, area, title, subtitle, role)
}

fn rows(buf: &mut Buffer, area: Rect, lines: Vec<Line<'static>>) {
    Paragraph::new(lines).render(area, buf);
}

fn note(value: impl Into<String>, color: Color, width: u16) -> Line<'static> {
    Line::styled(
        text::fit(&value.into(), width as usize),
        Style::default().fg(color),
    )
}

fn field(area: Rect, label: &str, value: impl Into<String>, color: Color) -> Line<'static> {
    let label = text::pad(&format!("{label}:"), 13.min(area.width as usize));
    let budget = (area.width as usize).saturating_sub(text::width(&label));
    Line::from(vec![
        Span::styled(label, Style::default().fg(T.text_muted)),
        Span::styled(text::fit(&value.into(), budget), Style::default().fg(color)),
    ])
}

/// Normal connectivity is shown once in System; the header carries exceptions.
pub(crate) fn connection_label(app: &App) -> &'static str {
    if app.connected {
        if app.paused {
            "Display paused"
        } else {
            ""
        }
    } else if app.last_status_read.is_none() && read_error(app, ReadResource::Status).is_none() {
        "Connecting"
    } else {
        "Disconnected"
    }
}

/// Fits in the existing header so a warning remains visible while scrolling.
pub(crate) fn health_notice(app: &App) -> Option<(String, Color)> {
    let mut issues = Vec::new();
    let connection = connection_label(app);
    if !connection.is_empty() {
        issues.push(connection.to_owned());
    }
    let mut color = T.warning;
    if app.active_leaf == crate::tui::app::Leaf::Dashboard {
        for (resource, name, last) in [
            (ReadResource::Status, "Status", app.last_status_read),
            (ReadResource::Tracking, "Tracking", app.last_tracking_read),
            (ReadResource::Blocklists, "Lists", app.last_lists_read),
        ] {
            if read_error(app, resource).is_some() {
                issues.push(format!("{name} read failed"));
            } else if !app.paused && last.is_some_and(|at| at.elapsed().as_secs() > 30) {
                issues.push(format!("{name} data stale"));
            }
        }
        if let Some(sample) = app
            .daemon_status
            .as_ref()
            .and_then(|status| status.resource_budget)
        {
            if !app.paused
                && sample
                    .sampled_at
                    .is_some_and(|at| now_secs().saturating_sub(at) > 30)
            {
                issues.push("Resource data stale".into());
            }
        }
        if let Some((message, severity)) = protection::issue(app) {
            issues.push(message);
            color = severity;
        }
    }
    (!issues.is_empty()).then(|| (issues.join(" · "), color))
}

fn read_error(app: &App, resource: ReadResource) -> Option<&str> {
    app.read_jobs.as_ref().and_then(|jobs| jobs.error(resource))
}

fn tracking_available(app: &App) -> bool {
    app.last_tracking_read.is_some()
        && read_error(app, ReadResource::Tracking).is_none()
        && !tracking_disabled(app)
}

fn tracking_disabled(app: &App) -> bool {
    app.daemon_status
        .as_ref()
        .and_then(|status| status.tracking_enabled)
        == Some(false)
}

fn unavailable_panel(
    buf: &mut Buffer,
    area: Rect,
    title: &str,
    subtitle: &str,
    index: usize,
    app: &App,
) {
    let role = match index {
        2 => theme::CardRole::Summary,
        3 | 4 => theme::CardRole::Analytics,
        _ => theme::CardRole::History,
    };
    let inner = if index == 5 {
        card_with_subtitle(buf, area, title, top_lists_subtitle(area), role)
    } else {
        card(buf, area, title, subtitle, role)
    };
    let mut lines = vec![note(
        if tracking_disabled(app) {
            "Tracking disabled"
        } else {
            "Tracking read failed"
        },
        T.warning,
        inner.width,
    )];
    if let Some(error) = read_error(app, ReadResource::Tracking) {
        lines.extend(
            text::wrap(error, inner.width as usize)
                .into_iter()
                .map(|line| note(line, T.text_secondary, inner.width)),
        );
    }
    lines.push(note(
        format!("Last success: {}", freshness(app.last_tracking_read)),
        T.text_muted,
        inner.width,
    ));
    rows(buf, inner, lines);
}

fn freshness(last: Option<Instant>) -> String {
    last.map_or_else(
        || "not received".into(),
        |at| format_age_short(at.elapsed().as_secs() as i64),
    )
}

fn render_system(buf: &mut Buffer, area: Rect, app: &App) {
    let inner = card(buf, area, TITLES[0], SUBTITLES[0], theme::CardRole::Summary);
    let Some(status) = app.daemon_status.as_ref() else {
        let message = read_error(app, ReadResource::Status).unwrap_or("Waiting for daemon status…");
        rows(
            buf,
            inner,
            text::wrap(message, inner.width as usize)
                .into_iter()
                .map(|line| note(line, T.text_muted, inner.width))
                .collect(),
        );
        return;
    };
    let state = if app.connected {
        if app.paused {
            "Paused"
        } else {
            "Online"
        }
    } else {
        "Disconnected"
    };
    let mut lines = vec![
        field(
            inner,
            "Status",
            state,
            if app.connected && !app.paused {
                T.success
            } else {
                T.warning
            },
        ),
        field(
            inner,
            "Uptime",
            format_uptime(status.uptime_secs),
            T.text_primary,
        ),
        field(
            inner,
            "Domains",
            format::count(status.domain_count as u64),
            T.text_primary,
        ),
    ];
    let total = hour_totals(app);
    let cache = if tracking_disabled(app) {
        "tracking disabled".into()
    } else if !tracking_available(app) {
        "unavailable".into()
    } else if app.tracking.hourly.is_empty() {
        "no recorded traffic".into()
    } else if total.0 <= total.1 {
        "— (no eligible queries)".into()
    } else {
        format!("{:.1}% · 24h", app.tracking.cache_hit_rate_24h)
    };
    lines.push(field(inner, "Cache hits", cache, T.text_primary));
    if status.upstream_servers.is_empty() {
        lines.push(field(
            inner,
            "Upstreams",
            format!(
                "{} · {} resolver(s)",
                status.upstream_mode, status.upstream_count
            ),
            T.text_primary,
        ));
    } else {
        for (index, upstream) in status.upstream_servers.iter().take(3).enumerate() {
            lines.push(field(
                inner,
                &format!("Upstream {}", index + 1),
                format!("{} · {}", upstream.kind, upstream.address),
                T.text_primary,
            ));
        }
        if status.upstream_servers.len() > 3 {
            lines.push(note(
                format!(
                    "+{} upstreams · see Settings",
                    status.upstream_servers.len() - 3
                ),
                T.text_muted,
                inner.width,
            ));
        }
    }
    if let Some((issue, color)) = protection::issue(app) {
        lines.extend(
            text::wrap(&issue, inner.width as usize)
                .into_iter()
                .map(|line| note(line, color, inner.width)),
        );
    }
    rows(buf, inner, lines);
}

fn mib(value: Option<u64>) -> String {
    value.map_or_else(
        || "—".into(),
        |value| {
            if value >= 1024 {
                format!("{:.1} GiB", value as f64 / 1024.0)
            } else {
                format!("{value} MiB")
            }
        },
    )
}

fn render_resources(buf: &mut Buffer, area: Rect, app: &App) {
    let inner = card(buf, area, TITLES[1], SUBTITLES[1], theme::CardRole::Summary);
    let Some(status) = app.daemon_status.as_ref() else {
        rows(
            buf,
            inner,
            vec![note("Waiting for resources…", T.text_muted, inner.width)],
        );
        return;
    };
    let sample = status.resource_budget;
    let system = sample.map_or_else(
        || "—".into(),
        |sample| match (sample.mem_total_mb, sample.mem_available_mb) {
            (Some(total), Some(available)) => format!(
                "{} / {}",
                mib(Some(total.saturating_sub(available))),
                mib(Some(total))
            ),
            _ => "—".into(),
        },
    );
    let estimate = status.lists_memory_bytes.map_or_else(
        || "—".into(),
        |bytes| {
            let value = bytes as f64 / 1_048_576.0;
            if value >= 1024.0 {
                format!("{:.1} GiB", value / 1024.0)
            } else {
                format!("{value:.1} MiB")
            }
        },
    );
    let mut lines = vec![
        field(
            inner,
            "CPU (user)",
            sample.map_or_else(|| "—".into(), |s| format!("{}%", s.cpu_user_pct)),
            T.text_primary,
        ),
        field(inner, "System RAM", system, T.text_primary),
        field(
            inner,
            "Warden RAM",
            mib(sample.map(|s| s.rss_mb)),
            sample.map_or(T.text_primary, |s| rss_color(s.rss_mb, s.rss_warn_mb)),
        ),
        field(inner, "List RAM", estimate, T.text_primary),
        field(
            inner,
            "Warden swap",
            mib(sample.and_then(|s| s.swap_mb)),
            T.text_primary,
        ),
    ];
    if sample.is_none_or(|s| s.sampled_at.is_none()) {
        lines.push(note("Resource sample unavailable", T.warning, inner.width));
    } else if !app.paused
        && sample
            .and_then(|s| s.sampled_at)
            .is_some_and(|at| now_secs().saturating_sub(at) > 30)
    {
        lines.push(note("Resource data stale", T.warning, inner.width));
    }
    rows(buf, inner, lines);
}

fn rss_color(rss: u64, warn: u64) -> Color {
    if warn == 0 {
        T.text_primary
    } else if rss > warn {
        T.error
    } else if rss as u128 * 5 > warn as u128 * 4 {
        T.warning
    } else {
        T.text_primary
    }
}

fn hour_totals(app: &App) -> (u64, u64) {
    app.tracking
        .hourly
        .iter()
        .filter(|b| crate::tracking::time_series::hour_in_24h_window(b.timestamp, anchor(app)))
        .fold((0u64, 0u64), |(q, b), row| {
            (q.saturating_add(row.queries), b.saturating_add(row.blocked))
        })
}

fn render_top_lists(buf: &mut Buffer, area: Rect, app: &App) {
    let inner = card_with_subtitle(
        buf,
        area,
        TITLES[5],
        top_lists_subtitle(area),
        theme::CardRole::History,
    );
    let mut lines = Vec::new();
    if app.last_tracking_read.is_none() {
        lines.push(note("Waiting for tracking…", T.text_muted, inner.width));
    } else if app.tracking.top_blocked_lists_24h.is_empty() {
        lines.push(note(
            if app
                .daemon_status
                .as_ref()
                .is_some_and(|s| s.top_lists_24h_supported)
            {
                "No recorded list blocks"
            } else {
                "24h list attribution unavailable"
            },
            T.text_muted,
            inner.width,
        ));
    } else {
        for (index, row) in app
            .tracking
            .top_blocked_lists_24h
            .iter()
            .take(5)
            .enumerate()
        {
            let count = format::count(row.count_24h);
            let budget = (inner.width as usize).saturating_sub(text::width(&count) + 4);
            lines.push(Line::from(vec![
                Span::styled(format!("{} ", index + 1), Style::default().fg(T.text_muted)),
                Span::styled(
                    text::pad(&row.label, budget),
                    Style::default().fg(T.text_secondary),
                ),
                Span::styled(format!("  {count}"), Style::default().fg(T.text_primary)),
            ]));
        }
    }
    rows(buf, inner, lines);
}

fn top_lists_subtitle(area: Rect) -> Line<'static> {
    let cells = theme::card_subtitle_area(area).width as usize;
    let full = "Attributed Last 24H Hits (Not Exclusive)";
    let compact = "24H Attributed Hits (Nonexclusive)";
    Line::raw(if text::width(full) <= cells {
        full.to_owned()
    } else {
        text::fit(compact, cells)
    })
}

#[cfg(test)]
fn subtitle_text(line: Line<'_>) -> String {
    line.spans
        .iter()
        .map(|span| span.content.as_ref())
        .collect()
}

#[cfg(test)]
#[path = "../tests/dashboard.rs"]
mod tests;
