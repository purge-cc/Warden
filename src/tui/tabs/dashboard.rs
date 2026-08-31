//! Dashboard tab — wide-layout port of the design spec from
//! `purge-tui/project/Purge Shield TUI - Dashboard.html`.
//!
//! Reading order (Sprint A + B + C + D of `_docs/features/dashboard_v2.md`):
//!   row 1  KPI strip (System 34 | Block Rate 33 | Cache Hit Rate 33)
//!   row 2  Trend chart 67% + QType chart 33%
//!   row 3  Daily Queries 34% + Daily Blocked 33% + Global Pulse 33%
//!   row 4  Top Lists 33% + Top Devices 33% + Top Blocked Domains 34%
//!
//! Below `WIDE_THRESHOLD` cols the layout falls back to the pre-v2
//! shape (no row 3 cards; bottom holds Pulse + Top Domains + Top
//! Blocked at 40/30/30). Sprint D retired the 7×24 heatmap that used
//! to occupy 60% of row 3 — the heatmap palette tokens (`heat_*`) are
//! kept dormant in `theme.rs` for possible future re-introduction.

use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::symbols::Marker;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Axis, Chart, Dataset, GraphType, Paragraph};
use ratatui::Frame;

use crate::ipc::protocol::DomainCount;
use crate::tui::app::App;
use crate::tui::format;
use crate::tui::theme::{self, T};

/// Above this width the design renders the two KPI gauges and the
/// trend chart side-by-side on one row, and the top-blocked + clients
/// panels side-by-side on the next. Below it we stack to avoid cutting
/// off labels.
const WIDE_THRESHOLD: u16 = 120;

/// The wide branch lays out four rows — `Length(11) + Length(14) +
/// Length(11) + Min(7)` = 43 — to honour the bottom card's minimum. On a
/// wide-but-short pane (≥120 cols, <43 rows) ratatui distributes top-down
/// and the lower cards collapse to zero-height rects (silent loss of the
/// Daily/Pulse/Top cards). Gate on height too so such panes fall back to
/// the graceful narrow stacked layout instead (dash-02).
const WIDE_MIN_HEIGHT: u16 = 43;

pub fn render(f: &mut Frame, area: Rect, app: &App) {
    let wide = area.width >= WIDE_THRESHOLD && area.height >= WIDE_MIN_HEIGHT;

    if wide {
        // 4-row v2 layout (D1 / D7).
        //   row 1 KPI         Length(11) — 3 panels (System | Block | Cache)
        //   row 2 Trend+QType Length(14) — Trend chart 67 % | QType chart 33 %
        //   row 3 Daily+Pulse Length(11) — Daily Queries 34 / Daily Blocked 33 / Pulse 33
        //   row 4 Bottom      Min(7)     — Top Lists 33 / Devices 33 / Blocked 34
        // Row 2 split mirrors the row-1 KPI percentages: Trend chart
        // sits under System + Block Rate combined (67 %), QType chart
        // under Cache Hit Rate (33 %). Sprint D fixup #4 promoted the
        // QTYPE row from the Pulse card to its own panel.
        // KPI strip height. Poll moved to the Global Pulse card (2026-06-06),
        // so the System card holds 8 rows even with the cluster dot shown — a
        // constant 11 fits both builds (no cluster-conditional grow).
        let chunks = Layout::vertical([
            Constraint::Length(11),
            Constraint::Length(14),
            Constraint::Length(11),
            Constraint::Min(7),
        ])
        .split(area);
        render_kpi_row(f, chunks[0], app, true);
        let row2_cols =
            Layout::horizontal([Constraint::Percentage(67), Constraint::Percentage(33)])
                .split(chunks[1]);
        render_trend_chart(f, row2_cols[0], app);
        render_qtype_chart_card(f, row2_cols[1], app);
        render_row3(f, chunks[2], app);
        render_bottom_row(f, chunks[3], app, true);

        if !app.connected {
            dim_disconnected_data(f, chunks[0], &[chunks[1], chunks[2], chunks[3]]);
        }
    } else {
        // Pre-v2 narrow fallback. Heatmap dropped — the 7×24 matrix
        // needs ≥53 cols and the Pulse-40 split doesn't leave enough
        // canvas at narrow widths.
        // Narrow KPI strip: System is compact (no Uptime row) and Poll now
        // lives in Global Pulse, so a constant 10 fits both builds.
        let chunks = Layout::vertical([
            Constraint::Length(10),
            Constraint::Min(3),
            Constraint::Min(6),
        ])
        .split(area);
        render_kpi_row(f, chunks[0], app, false);
        render_trend_chart(f, chunks[1], app);
        render_bottom_row(f, chunks[2], app, false);

        if !app.connected {
            dim_disconnected_data(f, chunks[0], &[chunks[1], chunks[2]]);
        }
    }
}

/// Grey out the data widgets while the daemon link is down, leaving the
/// System panel (first KPI column) bright so the operator's status anchor
/// and the `◌ stale` badge stay legible. Called after the widgets have
/// rendered so the cells exist to dim in place.
fn dim_disconnected_data(f: &mut Frame, kpi_row: Rect, full_rows: &[Rect]) {
    // Re-derive the KPI 34/33/33 split (identical to render_kpi_row) so we
    // dim Block Rate + Cache Hit but not the System panel (kpi[0]).
    let kpi = Layout::horizontal([
        Constraint::Percentage(34),
        Constraint::Percentage(33),
        Constraint::Percentage(33),
    ])
    .split(kpi_row);
    let buf = f.buffer_mut();
    dim_rect(buf, kpi[1]);
    dim_rect(buf, kpi[2]);
    for r in full_rows {
        dim_rect(buf, *r);
    }
}

/// OR `Modifier::DIM` into every cell of `rect`, preserving each cell's
/// symbol and colours (`set_style` patches the modifier, leaving fg/bg
/// untouched). Mirrors the `Modifier::DIM` idiom used by the scope modal.
fn dim_rect(buf: &mut ratatui::buffer::Buffer, rect: Rect) {
    let area = rect.intersection(buf.area);
    let dim = Style::default().add_modifier(Modifier::DIM);
    for y in area.top()..area.bottom() {
        for x in area.left()..area.right() {
            buf[(x, y)].set_style(dim);
        }
    }
}

// ─── 1. System panel ───────────────────────────────────────────────────────

/// One-info-per-row KV panel matching the Gauge Anatomy framing
/// (white border, title inside as first row, blank after title).
/// Lives as the third column of the KPI row, alongside Cache Hit
/// Rate and Block Rate. Replaces the pre-2026-04-29 full-width
/// `render_system_strip` that crammed 6 fields onto two lines.
///
/// Wide: 8 fields (Status / Listen / Upstream / Cache / Uptime / RAM /
/// CPU / Poll). Narrow/compact: 7 fields (drops Uptime). Status sits up
/// top in both modes because daemon liveness is the most operator-
/// critical signal. 2026-05-22 rework: RAM/CPU (the daemon's own
/// RSS·FDs / CPU%) moved here from Global Pulse so the System card owns
/// host vitals; the Lists/Domains counts moved the other way (to Pulse);
/// the daemon-version row was dropped (the footer already prints it).
fn render_system_panel(f: &mut Frame, area: Rect, app: &App, compact: bool) {
    let block = theme::framed_block_colored(T.text_primary);
    let inner = block.inner(area);
    f.render_widget(block, area);

    let mut lines: Vec<Line<'static>> = Vec::with_capacity(10);

    // Title row — tabular panel, no blank after (Gauge Anatomy split
    // rule: charts get a blank, KV/data tables don't).
    lines.push(Line::from(vec![
        Span::raw(" "),
        Span::styled(
            "System",
            Style::default().fg(T.info).add_modifier(Modifier::BOLD),
        ),
    ]));

    let Some(status) = &app.daemon_status else {
        // No status yet → the first poll is still in flight. Explicit
        // STARTING badge (dotted ◌, info-blue) + a muted explainer, instead
        // of the old bare "waiting…" line, so a cold launch reads as
        // "booting" rather than "broken".
        lines.push(Line::from(vec![
            Span::raw(" "),
            Span::styled(
                "\u{25cc} STARTING",
                Style::default().fg(T.info).add_modifier(Modifier::BOLD),
            ),
        ]));
        lines.push(Line::from(Span::styled(
            "  waiting for first daemon poll\u{2026}",
            Style::default().fg(T.text_muted),
        )));
        f.render_widget(Paragraph::new(lines), inner);
        return;
    };

    // KV row helper: ` Label    Value` with label padded to 9 chars
    // (longest label "Upstream" = 8 chars + 1 space = 9). Vertical
    // alignment of the 7 rows depends on this fixed-width prefix.
    //
    // `value` is ellipsised to what is actually left after the 1-cell
    // lead and the 9-char label column — `s-4.13-row-narrow-mode-suppress`:
    // at the System card's real floor share (34 % of an 80-col row, ~25
    // cells inside the border) `RAM      4096 MB · 512 FDs` silently lost
    // its last two characters to `Paragraph`'s hard clip (`512 F`, not
    // `512 FDs` or `512 …`) — a cut that doesn't say it is one, same class
    // as `render_bottom_row`'s top-lists label column a few hundred lines
    // down, which already ellipsises for the same reason. `Cache`'s
    // `12345 / 20000`-shaped value and a long `Listen` address share the
    // same column, so the guard sits in the shared helper rather than on
    // the two rows that happened to be measured overflowing first.
    let value_budget = (inner.width as usize).saturating_sub(10);
    let kv = |label: &'static str, value: Span<'static>| -> Line<'static> {
        Line::from(vec![
            Span::raw(" "),
            Span::styled(format!("{label:<9}"), Style::default().fg(T.text_muted)),
            fit_span(value, value_budget),
        ])
    };

    // Status row — mirrors the Poll row's signal styling so the operator
    // sees daemon liveness up top. Was previously a header pill (`●
    // RUNNING`) next to the wordmark; moved here on 2026-04-29 to keep
    // the header pure-branding and consolidate runtime signals in one
    // panel.
    lines.push(kv("Status", status_span(app)));
    lines.push(kv(
        "Listen",
        Span::styled(status.listen.clone(), Style::default().fg(T.text_primary)),
    ));
    lines.push(kv(
        "Upstream",
        Span::styled(
            format!("{} ({})", status.upstream_mode, status.upstream_count),
            Style::default().fg(T.success),
        ),
    ));

    // Cache occupancy. §4.19: prefer the daemon-reported cap when
    // available (`cache_cap > 0`); fall back to the `cache_capacity`
    // heuristic when polling a pre-§4.19 daemon (serde-default 0).
    let cache_used = format_count(status.cache_entries);
    let cache_cap = if status.cache_cap > 0 {
        format_count(status.cache_cap)
    } else {
        format_count(cache_capacity(status.cache_entries))
    };
    lines.push(kv(
        "Cache",
        Span::styled(
            format!("{cache_used} / {cache_cap}"),
            Style::default().fg(T.text_primary),
        ),
    ));

    // Uptime — wide only (compact drops it to make room for RAM/CPU).
    if !compact {
        lines.push(kv(
            "Uptime",
            Span::styled(
                format_uptime(status.uptime_secs),
                Style::default().fg(T.text_primary),
            ),
        ));
    }

    // RAM / CPU — the daemon's own process health, relocated here from
    // Global Pulse on 2026-05-22 so the System card owns host vitals.
    // Each renders a muted `—` until the first resource sample arrives
    // (cold start / pre-§4.13 daemon / non-Linux daemon).
    let snap = status.resource_budget.as_ref();
    lines.push(kv("RAM", system_ram_span(snap)));
    lines.push(kv("CPU", system_cpu_span(snap)));

    // §4.11-4b (CS9) — cluster health dot, shown only when `[cluster].enabled`.
    // Poll moved to the Global Pulse card (2026-06-06), freeing the row the dot
    // occupies — so the System card fits the dot at its normal height (no grow).
    #[cfg(feature = "cluster")]
    if app.cluster_visible() {
        lines.push(kv("Cluster", cluster_health_span(app)));
    }

    f.render_widget(Paragraph::new(lines), inner);
}

fn status_span(app: &App) -> Span<'static> {
    if !app.connected {
        // Reached only when daemon_status is already populated (the None
        // case returns the STARTING badge earlier), so a dropped link means
        // we are still showing the last good snapshot → stale, not "no data".
        Span::styled(
            "\u{25cc} stale",
            Style::default().fg(T.warning).add_modifier(Modifier::BOLD),
        )
    } else if app.paused {
        Span::styled(
            "|| paused",
            Style::default().fg(T.warning).add_modifier(Modifier::BOLD),
        )
    } else {
        Span::styled(
            "\u{25cf} running",
            Style::default().fg(T.success).add_modifier(Modifier::BOLD),
        )
    }
}

/// §4.11-4b (CS9) — System-card cluster dot. Same glyph convention as
/// `status_span`: solid `●` for stable states (healthy/error), hollow `◌` for
/// transient/degraded. Health (decision 5): green = converged / all peers
/// online; amber = any peer STALE or local not yet converged; red = the local
/// daemon link is down, or (secondary) the primary is unreachable.
#[cfg(feature = "cluster")]
fn cluster_health_span(app: &App) -> Span<'static> {
    // Local daemon ↔ TUI link down → the cluster view is stale; red.
    if !app.connected {
        return cluster_dot("\u{25cf}", "unreachable".to_string(), T.error);
    }
    let Some(status) = app.cluster_status.as_ref() else {
        // Enabled, connected, but the first cluster poll hasn't landed.
        return cluster_dot("\u{25cc}", "syncing\u{2026}".to_string(), T.warning);
    };

    // Tolerate an unrecognised role string the same way the Cluster tab does
    // (clu-02) rather than treating "not secondary" as primary.
    match super::cluster::ClusterRoleView::parse(&status.role) {
        super::cluster::ClusterRoleView::Secondary => {
            if !status.last_poll_ok {
                // N consecutive heartbeats to the primary failed.
                cluster_dot(
                    "\u{25cf}",
                    "secondary \u{00b7} unreachable".to_string(),
                    T.error,
                )
            } else if status.converged {
                let age = match status.last_sync_secs {
                    Some(s) => format!("synced {s}s ago"),
                    None => "never".to_string(),
                };
                cluster_dot("\u{25cf}", format!("secondary \u{00b7} {age}"), T.success)
            } else {
                cluster_dot(
                    "\u{25cc}",
                    "secondary \u{00b7} syncing\u{2026}".to_string(),
                    T.warning,
                )
            }
        }
        super::cluster::ClusterRoleView::Primary => {
            // Primary: weigh the connected-secondary roster (self-row excluded).
            let stale = status
                .roster
                .iter()
                .filter(|r| !r.is_self && !r.online)
                .count();
            let up = status
                .roster
                .iter()
                .filter(|r| !r.is_self && r.online)
                .count();
            if stale > 0 {
                cluster_dot(
                    "\u{25cc}",
                    format!("primary \u{00b7} {stale} stale"),
                    T.warning,
                )
            } else if up == 0 {
                // Primary serving, no secondaries connected yet — healthy, alone.
                cluster_dot(
                    "\u{25cf}",
                    "primary \u{00b7} no peers".to_string(),
                    T.success,
                )
            } else {
                let noun = if up == 1 { "peer" } else { "peers" };
                cluster_dot(
                    "\u{25cf}",
                    format!("primary \u{00b7} {up} {noun} up"),
                    T.success,
                )
            }
        }
        super::cluster::ClusterRoleView::Unknown => {
            cluster_dot("\u{25cc}", "unknown role".to_string(), T.warning)
        }
    }
}

/// Glyph + text in one bold span, the dashboard dot idiom.
#[cfg(feature = "cluster")]
fn cluster_dot(glyph: &str, text: String, color: Color) -> Span<'static> {
    Span::styled(
        format!("{glyph} {text}"),
        Style::default().fg(color).add_modifier(Modifier::BOLD),
    )
}

fn poll_status_span(app: &App) -> Span<'static> {
    if app.paused {
        Span::styled(
            "|| paused",
            Style::default().fg(T.warning).add_modifier(Modifier::BOLD),
        )
    } else if app.connected {
        Span::styled(
            "\u{25cf} healthy  \u{00b7} every 2s",
            Style::default().fg(T.success),
        )
    } else {
        Span::styled(
            "\u{25cf} unreachable",
            Style::default().fg(T.error).add_modifier(Modifier::BOLD),
        )
    }
}

/// Value span for the System card's RAM row: `<rss> MB · <fds> FDs`,
/// coloured against the daemon's `rss_warn_mb` budget via [`rss_colour`]
/// (green < 80 % · amber ≥ 80 % · red over budget). Muted `—` until the
/// first resource sample lands. Carries the RSS + FD halves of the old
/// Pulse Resources row, split out so RAM and CPU read as their own
/// labelled System rows (2026-05-22 rework).
fn system_ram_span(snap: Option<&crate::resource_budget::ResourceBudgetSnapshot>) -> Span<'static> {
    match snap {
        None => Span::styled("\u{2014}", Style::default().fg(T.text_muted)),
        Some(s) => Span::styled(
            format!("{} MB \u{00b7} {} FDs", s.rss_mb, s.fd_count),
            Style::default()
                .fg(rss_colour(s.rss_mb, s.rss_warn_mb))
                .add_modifier(Modifier::BOLD),
        ),
    }
}

/// Value span for the System card's CPU row: user-mode CPU% from the
/// latest resource sample. `text_primary` (CPU has no warn threshold).
/// Muted `—` until the first sample lands.
fn system_cpu_span(snap: Option<&crate::resource_budget::ResourceBudgetSnapshot>) -> Span<'static> {
    match snap {
        None => Span::styled("\u{2014}", Style::default().fg(T.text_muted)),
        Some(s) => Span::styled(
            format!("{}%", s.cpu_user_pct),
            Style::default()
                .fg(T.text_primary)
                .add_modifier(Modifier::BOLD),
        ),
    }
}

/// Ellipsise a KV row's value span to `budget` cells, preserving its style
/// — `render_system_panel`'s answer to `s-4.13-row-narrow-mode-suppress`.
///
/// `Paragraph` clips silently at the cell boundary with no marker, so an
/// overlong value doesn't just get short, it gets wrong (`512 FDs` → `512
/// F`, which reads as a different, smaller number). Characters, not
/// display cells — matches every other truncation helper in this
/// ecosystem (`fit` in `modal_form.rs`, the label truncation a few
/// hundred lines below in `render_bottom_row`).
fn fit_span(span: Span<'static>, budget: usize) -> Span<'static> {
    let text = span.content.as_ref();
    if text.chars().count() <= budget {
        return span;
    }
    if budget == 0 {
        return Span::styled(String::new(), span.style);
    }
    let head: String = text.chars().take(budget - 1).collect();
    Span::styled(format!("{head}\u{2026}"), span.style)
}

// ─── 2. KPI gauges + trend chart row ───────────────────────────────────────

fn render_kpi_row(f: &mut Frame, area: Rect, app: &App, wide: bool) {
    // Three columns: System | Block | Cache. Reading order matches
    // operator priority: first "what is it" (System), then the two
    // operational rates (Block, Cache). Tabular panels — no blank
    // between title and first data row. The trend chart lives below
    // as its own row (split out of this function in v2 so the heatmap
    // / pulse row 3 can sit between them).
    let compact = !wide;
    let kpi_top = Layout::horizontal([
        Constraint::Percentage(34),
        Constraint::Percentage(33),
        Constraint::Percentage(33),
    ])
    .split(area);
    render_system_panel(f, kpi_top[0], app, compact);
    render_block_rate_gauge(f, kpi_top[1], app, compact);
    render_cache_hit_gauge(f, kpi_top[2], app, compact);
}

/// One time window of a fill-good metric. The `value/total` pair is the
/// raw counts for that window; `pct` is just `value/total*100` precomputed
/// so the renderer doesn't divide twice.
struct WindowMetric {
    label: &'static str,
    value: u64,
    total: u64,
    pct: f64,
}

fn pct_of(num: u64, den: u64) -> f64 {
    if den == 0 {
        0.0
    } else {
        (num as f64 / den as f64) * 100.0
    }
}

/// Aggregate (numerator, denominator) over a rolling window of
/// `window_secs` seconds ending at `now`, drawing from a stream of
/// fixed-boundary buckets each `bucket_secs` wide. Buckets fully
/// inside the window contribute at weight 1.0; the single bucket
/// straddling the start edge is pro-rated by the fraction of its span
/// that falls inside `[now - window_secs, now]`.
///
/// The underlying buckets are wall-clock aligned (see
/// `time_series::truncate_hour` / `truncate_day`) — the right shape
/// for the heatmap and trend chart, but a poor fit for "last 1h" KPI
/// gauges, which want a smooth rolling readout. Without pro-rating,
/// the 1h gauge dropped 100 % at every top-of-hour rollover. This
/// helper assumes uniform event distribution within a partial bucket;
/// fine for KPI display, far closer to truth than the old cliff.
fn rolling_sum<NumF, DenF>(
    buckets: &[crate::ipc::protocol::TimeBucketDto],
    now: u64,
    window_secs: u64,
    bucket_secs: u64,
    num: NumF,
    den: DenF,
) -> (u64, u64)
where
    NumF: Fn(&crate::ipc::protocol::TimeBucketDto) -> u64,
    DenF: Fn(&crate::ipc::protocol::TimeBucketDto) -> u64,
{
    let window_start = now.saturating_sub(window_secs);
    let bucket_size = bucket_secs as f64;
    let mut num_acc: f64 = 0.0;
    let mut den_acc: f64 = 0.0;
    for b in buckets.iter().rev() {
        let bucket_end = b.timestamp.saturating_add(bucket_secs);
        if bucket_end <= window_start {
            break;
        }
        let weight = if b.timestamp >= window_start {
            1.0
        } else {
            (bucket_end - window_start) as f64 / bucket_size
        };
        num_acc += num(b) as f64 * weight;
        den_acc += den(b) as f64 * weight;
    }
    (num_acc.round() as u64, den_acc.round() as u64)
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Format a unix timestamp as `HH:MM` in UTC. Matches the Query Log's
/// timestamp convention — the daemon emits UTC and the TUI renders UTC so
/// the two views agree (deriving local time in the multi-threaded TUI would
/// need `time`'s `local-offset` feature, which is unsound under threads).
/// `--:--` on the unreachable out-of-range case.
fn fmt_hhmm(unix_secs: u64) -> String {
    match time::OffsetDateTime::from_unix_timestamp(unix_secs as i64) {
        Ok(dt) => format!("{:02}:{:02}", dt.hour(), dt.minute()),
        Err(_) => "--:--".to_string(),
    }
}

/// Format a unix timestamp as `MM-DD` in UTC, for the daily (7d) trend view
/// where an `HH:MM` clock on a day-aligned bucket would be meaningless.
fn fmt_monthday(unix_secs: u64) -> String {
    match time::OffsetDateTime::from_unix_timestamp(unix_secs as i64) {
        Ok(dt) => format!("{:02}-{:02}", u8::from(dt.month()), dt.day()),
        Err(_) => "--".to_string(),
    }
}

fn rolling_hourly_cache(app: &App, now: u64, window_secs: u64) -> (u64, u64) {
    rolling_sum(
        &app.tracking.hourly,
        now,
        window_secs,
        3600,
        |b| b.cache_hits,
        |b| b.queries,
    )
}

fn rolling_daily_cache(app: &App, now: u64, window_secs: u64) -> (u64, u64) {
    rolling_sum(
        &app.tracking.daily,
        now,
        window_secs,
        86_400,
        |b| b.cache_hits,
        |b| b.queries,
    )
}

fn rolling_hourly_blocked(app: &App, now: u64, window_secs: u64) -> (u64, u64) {
    rolling_sum(
        &app.tracking.hourly,
        now,
        window_secs,
        3600,
        |b| b.blocked,
        |b| b.queries,
    )
}

fn rolling_daily_blocked(app: &App, now: u64, window_secs: u64) -> (u64, u64) {
    rolling_sum(
        &app.tracking.daily,
        now,
        window_secs,
        86_400,
        |b| b.blocked,
        |b| b.queries,
    )
}

fn cache_windows(app: &App, compact: bool) -> Vec<WindowMetric> {
    let mk = |label: &'static str, (v, t): (u64, u64)| WindowMetric {
        label,
        value: v,
        total: t,
        pct: pct_of(v, t),
    };
    let now = now_secs();
    if compact {
        vec![
            mk("1h", rolling_hourly_cache(app, now, 3600)),
            mk("24h", rolling_hourly_cache(app, now, 86_400)),
        ]
    } else {
        vec![
            mk("1h", rolling_hourly_cache(app, now, 3600)),
            mk("8h", rolling_hourly_cache(app, now, 28_800)),
            mk("24h", rolling_hourly_cache(app, now, 86_400)),
            mk("7d", rolling_daily_cache(app, now, 604_800)),
        ]
    }
}

fn block_windows(app: &App, compact: bool) -> Vec<WindowMetric> {
    let mk = |label: &'static str, (v, t): (u64, u64)| WindowMetric {
        label,
        value: v,
        total: t,
        pct: pct_of(v, t),
    };
    let now = now_secs();
    if compact {
        vec![
            mk("1h", rolling_hourly_blocked(app, now, 3600)),
            mk("24h", rolling_hourly_blocked(app, now, 86_400)),
        ]
    } else {
        vec![
            mk("1h", rolling_hourly_blocked(app, now, 3600)),
            mk("8h", rolling_hourly_blocked(app, now, 28_800)),
            mk("24h", rolling_hourly_blocked(app, now, 86_400)),
            mk("7d", rolling_daily_blocked(app, now, 604_800)),
        ]
    }
}

/// Header line for one window: `1h    42.7%  1.2k/2.9k`.
/// Order is verdict-first: label → percentage (the decision-grade
/// metric) → counts (the statistical evidence behind the %). Label is
/// left-padded to 4 chars and percentage right-padded to 6 so the four
/// windows align vertically when stacked. Counts use a slash-attached
/// `value/total` form (no spaces around `/`) since the pair reads as a
/// single ratio measurement, not two independent numbers.
fn window_header_line(w: &WindowMetric) -> Line<'static> {
    let (pct_str, counts_str) = if w.total == 0 {
        ("  —  ".to_string(), "—".to_string())
    } else {
        (
            format!("{:>5.1}%", w.pct),
            format!("{}/{}", format_count(w.value), format_count(w.total)),
        )
    };
    Line::from(vec![
        Span::raw(" "),
        Span::styled(format!("{:<4}", w.label), Style::default().fg(T.text_muted)),
        Span::raw(" "),
        Span::styled(
            pct_str,
            Style::default()
                .fg(T.text_primary)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("  "),
        Span::styled(counts_str, Style::default().fg(T.text_secondary)),
    ])
}

/// Position-based gradient bar. Each filled cell is coloured by its
/// position along the *full* bar width, not by the value — mirrors
/// codeburn's HBar pattern. Empty cells render as `▒` (medium shade)
/// in `border_default` so the track is clearly visible against the
/// dark background — without a visible track, the eye reads only the
/// fill length and loses the "% of full" reference. See _docs/rules/TUI_DESIGN.md
/// §"Bar Gradient" for the policy.
fn gradient_bar_line(pct: f64, width: usize) -> Line<'static> {
    let r = (pct / 100.0).clamp(0.0, 1.0);
    let filled = ((r * width as f64).round() as usize).min(width);
    let mut spans: Vec<Span<'static>> = Vec::with_capacity(width + 2);
    spans.push(Span::raw(" "));
    let denom = width.max(1) as f64;
    for i in 0..filled {
        let pos = i as f64 / denom;
        let c = T.bar_gradient(pos);
        spans.push(Span::styled("\u{2588}", Style::default().fg(c)));
    }
    if filled < width {
        spans.push(Span::styled(
            "\u{2592}".repeat(width - filled),
            Style::default().fg(T.border_default),
        ));
    }
    Line::from(spans)
}

/// Build the panel body for a 4-window fill-good gauge:
/// title, blank, then for each window `[header, bar, blank]` (the
/// trailing blank below the 7d row is intentional — bottom breathing
/// room mirrors the top blank, so the panel reads symmetrically).
/// Body for a 4-window fill-good gauge. Title is the first interior
/// row (bold, category-coloured); data rows follow IMMEDIATELY (no
/// blank). Tabular panels are dense — the breathing blank that
/// chart panels use would just be wasted space here. See
/// _docs/rules/TUI_DESIGN.md §"Gauge Anatomy" for the split rule.
fn build_window_gauge_lines(
    title: &'static str,
    title_color: ratatui::style::Color,
    windows: &[WindowMetric],
    bar_width: usize,
) -> Vec<Line<'static>> {
    let mut lines = Vec::with_capacity(1 + windows.len() * 2);
    lines.push(gauge_title_line(title, title_color, bar_width));
    for w in windows {
        lines.push(window_header_line(w));
        lines.push(gradient_bar_line(w.pct, bar_width));
    }
    lines
}

/// Gauge title row: bold category-coloured title on the left, a gradient
/// key (`●low ●mid ●high`) right-aligned to the bar's right edge — when the
/// panel is wide enough to hold both without crowding. The key's dots
/// sample `T.bar_gradient` at the same low/mid/high positions the fill bars
/// use, so it stays truthful if the gradient stops are retuned. Lives in
/// the title row (not its own row) so the gauge body height is unchanged —
/// the gauge panel is an exact fit (title + N×2 rows = interior) and a
/// dedicated legend row would clip the bottom window. Narrow gauges drop
/// the key entirely rather than overlap the title (graceful degradation).
/// Mirrors the trend chart's title-row legend idiom.
fn gauge_title_line(
    title: &'static str,
    title_color: ratatui::style::Color,
    bar_width: usize,
) -> Line<'static> {
    // (label, gradient sample position). Compact labels keep the key inside
    // the 33%-width KPI gauges at 120 cols.
    const KEY: [(&str, f64); 3] = [("low ", 0.10), ("mid ", 0.55), ("high", 0.95)];
    // Each entry renders as `●<label>`: 1 dot glyph + label chars.
    let key_len: usize = KEY.iter().map(|(l, _)| 1 + l.chars().count()).sum();
    let title_chars = title.chars().count();

    let mut spans = vec![
        Span::raw(" "),
        Span::styled(
            title,
            Style::default()
                .fg(title_color)
                .add_modifier(Modifier::BOLD),
        ),
    ];
    // Strict `>` guarantees at least one spacer cell between title and key.
    if bar_width > title_chars + key_len {
        let spacer = bar_width - title_chars - key_len;
        spans.push(Span::raw(" ".repeat(spacer)));
        for (label, pos) in KEY {
            spans.push(Span::styled(
                "\u{25cf}",
                Style::default().fg(T.bar_gradient(pos)),
            ));
            spans.push(Span::styled(label, Style::default().fg(T.text_muted)));
        }
    }
    Line::from(spans)
}

fn render_cache_hit_gauge(f: &mut Frame, area: Rect, app: &App, compact: bool) {
    // Border in text_primary (the palette's "white"); title stays in
    // category colour. Border defines structure (neutral), title
    // defines category (coloured) — separates structural from
    // semantic signal.
    let block = theme::framed_block_colored(T.text_primary);
    let inner = block.inner(area);
    f.render_widget(block, area);

    // Bar spans the full inner width minus 1 cell of padding on each
    // side (left and right), matching the panel's interior padX=1.
    let bar_width = inner.width.saturating_sub(2) as usize;
    let windows = cache_windows(app, compact);
    let lines = build_window_gauge_lines(
        "Cache Hit Rate \u{2014} 1h",
        T.scope_security,
        &windows,
        bar_width,
    );
    f.render_widget(Paragraph::new(lines), inner);
}

fn render_block_rate_gauge(f: &mut Frame, area: Rect, app: &App, compact: bool) {
    let block = theme::framed_block_colored(T.text_primary);
    let inner = block.inner(area);
    f.render_widget(block, area);

    let bar_width = inner.width.saturating_sub(2) as usize;
    let windows = block_windows(app, compact);
    let lines =
        build_window_gauge_lines("Block Rate \u{2014} 1h", T.brand_red, &windows, bar_width);
    f.render_widget(Paragraph::new(lines), inner);
}

fn render_trend_chart(f: &mut Frame, area: Rect, app: &App) {
    // Gauge Anatomy framing: white border + title inside as first
    // interior row in category colour. Queries series is chart_2
    // (blue) so the title takes T.info — same blue — to signal
    // "this panel is about queries" at a glance.
    let block = theme::framed_block_colored(T.text_primary);
    let inner = block.inner(area);
    f.render_widget(block, area);

    // Interior horizontal padding: 1 cell per side, matching the
    // Cache Hit Rate / Block Rate gauges (`inner.width.saturating_sub(2)`).
    // Without this, the chart's leftmost braille column hugs the
    // border on the left and the y-axis max label brushes the right
    // border, breaking the consistency with the two sibling cards.
    let padded_x = inner.x.saturating_add(1);
    let padded_w = inner.width.saturating_sub(2);

    // Hourly buffer holds 168 entries (7d × 24h) since 2026-04-29 to
    // feed the blocks heatmap; the trend chart only plots the most
    // recent 24 so its "Last 24h" label stays accurate. Sprint G —
    // honest wall-clock slice via `slice_recent_24h` (filter by
    // `timestamp >= now_hour - 23*3600`) instead of "last 24 entries"
    // tail slice, which diverged from real wall-clock time once the
    // ring carried restart-fragments.
    let hourly_24: Vec<crate::ipc::protocol::TimeBucketDto> =
        slice_recent_24h(&app.tracking.hourly);
    // rev-2607 (#4) — window the daily ring to 7 the same way the hourly
    // branch windows to 24, so `x_max` (derived from `buckets.len()`
    // below) never outruns the 8-tick "-7d … now" label set.
    let daily_7: Vec<crate::ipc::protocol::TimeBucketDto> = slice_recent_7d(&app.tracking.daily);
    let (title_text, toggle_hint, buckets): (&'static str, &'static str, &Vec<_>) =
        if app.dashboard.show_daily {
            ("Queries \u{2014} Last 7d", "[h] hourly", &daily_7)
        } else {
            ("Queries \u{2014} Last 24h", "[d] daily", &hourly_24)
        };

    // Title row: bold info-blue heading on the left, legend + muted
    // toggle hint pushed to the right edge. The legend uses heavy
    // black-rectangle (▬) markers in chart_2 (blue) and chart_1
    // (red) to identify the two series. Sequence (left → right):
    //   title, spacer, ▬ Total, ▬ Blocked, hint. The leading space is
    //   provided by the padded sub-rect, not by an extra Span.
    let legend_total = " Total  ";
    let legend_blocked = " Blocked   ";

    // Peak caption: the max-queries bucket in the currently-shown window,
    // tagged with its wall-clock time (UTC — see fmt_hhmm). Sits just after
    // the title, left of the right-aligned legend. Empty while collecting or
    // when every bucket is zero, so a fresh install shows no stray "peak 0".
    let peak_caption: String = buckets
        .iter()
        .max_by_key(|b| b.queries)
        .filter(|b| b.queries > 0)
        .map(|b| {
            let when = if app.dashboard.show_daily {
                fmt_monthday(b.timestamp)
            } else {
                fmt_hhmm(b.timestamp)
            };
            format!(" \u{00b7} peak {} @ {}", format_count(b.queries), when)
        })
        .unwrap_or_default();

    let non_spacer_len = title_text.chars().count()
        + peak_caption.chars().count()
        + 1 // ▬ blue
        + legend_total.chars().count()
        + 1 // ▬ red
        + legend_blocked.chars().count()
        + toggle_hint.chars().count();
    let spacer_len = (padded_w as usize).saturating_sub(non_spacer_len);

    let title_line = Line::from(vec![
        Span::styled(
            title_text,
            Style::default().fg(T.info).add_modifier(Modifier::BOLD),
        ),
        Span::styled(peak_caption, Style::default().fg(T.text_muted)),
        Span::raw(" ".repeat(spacer_len)),
        Span::styled("\u{25ac}", Style::default().fg(T.chart_2)),
        Span::styled(legend_total, Style::default().fg(T.text_secondary)),
        Span::styled("\u{25ac}", Style::default().fg(T.chart_1)),
        Span::styled(legend_blocked, Style::default().fg(T.text_secondary)),
        Span::styled(toggle_hint, Style::default().fg(T.text_muted)),
    ]);
    let title_area = Rect {
        x: padded_x,
        y: inner.y,
        width: padded_w,
        height: 1,
    };
    f.render_widget(Paragraph::new(title_line), title_area);

    // Chart area starts 2 rows below the inner top: row 0 holds the
    // title, row 1 is intentionally blank so the title doesn't crowd
    // the graphic. Chart-type panels diverge from the gauge anatomy
    // rule "0 blank after title" — graphical content benefits from
    // a breathing row that tabular gauges don't need. Horizontal
    // padding (1 cell per side) mirrors the sibling gauges so the
    // three KPI cards visually align at the inner padding line.
    let chart_area = Rect {
        x: padded_x,
        y: inner.y.saturating_add(2),
        width: padded_w,
        height: inner.height.saturating_sub(2),
    };

    if buckets.is_empty() {
        f.render_widget(
            Paragraph::new(Span::styled(
                "  collecting data \u{2026}",
                Style::default().fg(T.text_muted),
            )),
            chart_area,
        );
        return;
    }

    let query_data: Vec<(f64, f64)> = buckets
        .iter()
        .enumerate()
        .map(|(i, b)| (i as f64, b.queries as f64))
        .collect();
    let blocked_data: Vec<(f64, f64)> = buckets
        .iter()
        .enumerate()
        .map(|(i, b)| (i as f64, b.blocked as f64))
        .collect();

    let max_y = buckets
        .iter()
        .map(|b| b.queries.max(b.blocked))
        .max()
        .unwrap_or(1) as f64;
    let x_max = (buckets.len().max(1) - 1) as f64;

    let datasets = vec![
        Dataset::default()
            .name("total")
            .marker(Marker::Braille)
            .graph_type(GraphType::Line)
            .style(Style::default().fg(T.chart_2))
            .data(&query_data),
        Dataset::default()
            .name("blocked")
            .marker(Marker::Braille)
            .graph_type(GraphType::Line)
            .style(Style::default().fg(T.chart_1))
            .data(&blocked_data),
    ];

    // X-axis labels are relative to "now", matching the data's frame
    // of reference (rolling window indexed 0..N with N = current
    // bucket). Major + minor tick pattern: text labels at multiples
    // of 3h (hourly) / 1d (daily); middle-dot `·` ticks at every
    // hour / day in between. Provides hour-grain reference without
    // overwhelming the strip with text.
    let x_labels: Vec<Span> = if app.dashboard.show_daily {
        // 8 labels for 7 daily buckets — one tick per day.
        vec![
            "-7d".into(),
            "-6d".into(),
            "-5d".into(),
            "-4d".into(),
            "-3d".into(),
            "-2d".into(),
            "-1d".into(),
            "now".into(),
        ]
    } else {
        // 25 labels for 24 hourly buckets — text every 3h, dot
        // ticks (·) on the in-between hours.
        vec![
            "-24h".into(),
            "\u{00b7}".into(),
            "\u{00b7}".into(),
            "-21h".into(),
            "\u{00b7}".into(),
            "\u{00b7}".into(),
            "-18h".into(),
            "\u{00b7}".into(),
            "\u{00b7}".into(),
            "-15h".into(),
            "\u{00b7}".into(),
            "\u{00b7}".into(),
            "-12h".into(),
            "\u{00b7}".into(),
            "\u{00b7}".into(),
            "-9h".into(),
            "\u{00b7}".into(),
            "\u{00b7}".into(),
            "-6h".into(),
            "\u{00b7}".into(),
            "\u{00b7}".into(),
            "-3h".into(),
            "\u{00b7}".into(),
            "\u{00b7}".into(),
            "now".into(),
        ]
    };

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
                .bounds([0.0, max_y * 1.1])
                .labels::<Vec<Span>>(vec!["0".into(), format_count(max_y as u64).into()]),
        );

    // Carve out one extra empty cell on each side of the actual chart
    // sub-rect. The earlier `padded_x`/`padded_w` shrink already drops
    // 1 cell per side at the panel-border level; this second 1-cell
    // gutter keeps the chart canvas itself from painting on the column
    // immediately next to the border. Without this gutter the leftmost
    // braille column of the line lands on the column just inside the
    // border — visually "glued" to the frame — because ratatui's Chart
    // maps `bounds[0]` to the leftmost cell of its render area
    // regardless of how much padding lives outside. Mirrors the
    // `inner.width.saturating_sub(2)` interior padding used by Cache
    // Hit Rate / Block Rate, plus an extra cell because Chart paints
    // edge-to-edge whereas the gauges paint from cell 1 of their own
    // inner rect.
    let chart_cols = Layout::horizontal([
        Constraint::Length(1), // left gutter
        Constraint::Min(1),    // chart canvas
        Constraint::Length(1), // right gutter
    ])
    .split(chart_area);
    f.render_widget(chart, chart_cols[1]);
}

// ─── 2bis. QType chart card — wide-mode row 2 right column ────────────────

/// Vertical-bar QType chart card. Wide-mode row 2's right slot
/// (`Constraint::Percentage(33)`) sits directly under the row-1 Cache
/// Hit Rate gauge, extending the column-grid alignment introduced in
/// Sprint D fixup #3.
///
/// The QTYPE distribution used to live as a single 2-line stacked
/// bar inside the Global Pulse card (`pulse_row_types`). Sprint D
/// fixup #4 promoted it to its own 14-row panel so composition data
/// (which buckets the daemon serves, in what proportions) reads at a
/// glance instead of fighting for space with operational counters.
///
/// Layout (12 inner rows: outer 14 − 2 borders):
///   row 0       title `"Query Types"` bold info-blue
///   row 1       blank (chart-panel breathing rule)
///   rows 2..=9  8 bar rows, top-down, half-block stack giving 16
///               distinct heights per column (`██`/`▄▄`/blank)
///   row 10      bucket labels (A / AAAA / HTTPS / TXT / oth) in
///               their bucket colour
///   row 11      percent labels (`70%` / `20%` / `5%` / `3%` / `2%`)
///
/// Buckets: D5 named set + Other rollup, matching `pulse_row_types`
/// semantics. Bars are scaled to the largest bucket's count so the
/// dominant bucket always reaches full height; the visual is
/// "relative composition," not "absolute traffic."
///
/// Cold start (`total == 0`): every bar row blanks out, with a muted
/// `collecting…` placeholder centered in the chart area.
fn render_qtype_chart_card(f: &mut Frame, area: Rect, app: &App) {
    use crate::tracking::query_type::TypeBucket;

    let block = theme::framed_block_colored(T.text_primary);
    let inner = block.inner(area);
    f.render_widget(block, area);

    const BAR_ROWS: usize = 8;
    const MAX_LEVEL: u32 = (BAR_ROWS as u32) * 2;
    // Sprint E: 2-char glyph per bar; Total + Blocked sit side-by-side
    // with a 1-col intra-pair gap, so each bucket group spans
    // 2 + 1 + 2 = 5 cols of glyph block. Inter-group spacing comes
    // from the centring padding inside `col_w`.
    const BAR_WIDTH: usize = 2;
    const PAIR_BLOCK: usize = BAR_WIDTH * 2 + 1;

    let mut lines: Vec<Line<'static>> = Vec::with_capacity(12);

    // Row 0 — title.
    lines.push(Line::from(vec![
        Span::raw(" "),
        Span::styled(
            "Query Types \u{2014} Last 24h (%)",
            Style::default().fg(T.info).add_modifier(Modifier::BOLD),
        ),
    ]));

    // Row 1 — blank.
    lines.push(Line::from(""));

    // Sprint F — read the 24h rolling window variants. Cumulative
    // `qtype_distribution` / `qtype_blocked_distribution` stay on
    // TrackingData for future surfacing but the chart no longer reads
    // them: with multi-day uptime, blocks lag queries by 3 orders of
    // magnitude and the Blocked bar collapses to a 1-row baseline.
    let dist = &app.tracking.qtype_distribution_24h;
    let blocked_dist = &app.tracking.qtype_blocked_distribution_24h;
    let total: u64 = dist.iter().sum();
    let total_blocked: u64 = blocked_dist.iter().sum();

    // Per-bucket displayed entries: A / AAAA / HTTPS / TXT / Other.
    // Buckets outside the D5 named set fold into Other, matching the
    // `pulse_row_types` colour-stability decision (operator 2026-05-10).
    let entries: [(&'static str, ratatui::style::Color); 5] = [
        ("A", T.chart_2),
        ("AAAA", T.chart_3),
        ("HTTPS", T.chart_4),
        ("TXT", T.chart_5),
        ("oth", T.text_muted),
    ];
    let mut counts = [0u64; 5];
    let mut blocked_counts = [0u64; 5];
    for (idx, (&count, &bcount)) in dist.iter().zip(blocked_dist.iter()).enumerate() {
        let bucket = TypeBucket::ALL[idx];
        let slot = match bucket {
            TypeBucket::A => 0,
            TypeBucket::Aaaa => 1,
            TypeBucket::Https => 2,
            TypeBucket::Txt => 3,
            _ => 4,
        };
        counts[slot] = counts[slot].saturating_add(count);
        blocked_counts[slot] = blocked_counts[slot].saturating_add(bcount);
    }

    let inner_w = inner.width as usize;
    // Each bucket group spans `col_w`; the 5-char paired glyph block
    // centres within. Min `col_w` keeps the pair from clipping when
    // the card is unusually narrow.
    let col_w = (inner_w / entries.len()).max(PAIR_BLOCK + 1);

    if total == 0 {
        // Cold start: blank bar rows, muted `collecting…` centred
        // halfway down the chart area, blank label + percent rows.
        for row in 0..BAR_ROWS {
            if row == BAR_ROWS / 2 {
                let placeholder = "collecting\u{2026}";
                let lpad = inner_w.saturating_sub(placeholder.chars().count()) / 2;
                lines.push(Line::from(vec![
                    Span::raw(" ".repeat(lpad)),
                    Span::styled(placeholder, Style::default().fg(T.text_muted)),
                ]));
            } else {
                lines.push(Line::from(""));
            }
        }
        lines.push(Line::from(""));
        lines.push(Line::from(""));
        f.render_widget(Paragraph::new(lines), inner);
        return;
    }

    // Anchor both bars to the GLOBAL max across both metrics so the
    // dominant signal in the chart pegs the top row. A bar reaches
    // half height iff its count is ~half of the loudest signal in
    // either dimension.
    let max_count = counts
        .iter()
        .copied()
        .chain(blocked_counts.iter().copied())
        .max()
        .unwrap_or(0)
        .max(1);
    let mut levels = [0u32; 5];
    let mut blocked_levels = [0u32; 5];
    for i in 0..entries.len() {
        let lvl_q = ((counts[i] as f64 / max_count as f64) * MAX_LEVEL as f64).round() as u32;
        let lvl_b =
            ((blocked_counts[i] as f64 / max_count as f64) * MAX_LEVEL as f64).round() as u32;
        levels[i] = lvl_q.min(MAX_LEVEL);
        blocked_levels[i] = lvl_b.min(MAX_LEVEL);
    }

    // 8 bar rows, top-down. Each group renders Total + Blocked side
    // by side. DM5: a bucket with `blocked == 0` renders the blocked
    // bar as a 1-row muted baseline (level=1) so the slot is visible
    // even when no blocks landed in that bucket — mirrors Sprint D's
    // missing-day baseline pattern.
    for row_from_top in 0..BAR_ROWS {
        let row_from_bottom = (BAR_ROWS - 1 - row_from_top) as u32;
        let full_threshold = (row_from_bottom + 1) * 2;
        let half_threshold = full_threshold - 1;

        let mut spans: Vec<Span<'static>> = Vec::with_capacity(entries.len() * 6);
        for (i, (_, color)) in entries.iter().enumerate() {
            let glyph_q = qtype_bar_glyph(levels[i], full_threshold, half_threshold);
            let (glyph_b, color_b) = if blocked_counts[i] == 0 {
                (
                    qtype_bar_glyph(1, full_threshold, half_threshold),
                    T.text_muted,
                )
            } else {
                (
                    qtype_bar_glyph(blocked_levels[i], full_threshold, half_threshold),
                    T.brand_red,
                )
            };

            let lpad = col_w.saturating_sub(PAIR_BLOCK) / 2;
            let rpad = col_w.saturating_sub(lpad).saturating_sub(PAIR_BLOCK);
            spans.push(Span::raw(" ".repeat(lpad)));
            spans.push(Span::styled(glyph_q, Style::default().fg(*color)));
            spans.push(Span::raw(" "));
            spans.push(Span::styled(glyph_b, Style::default().fg(color_b)));
            if i + 1 < entries.len() {
                spans.push(Span::raw(" ".repeat(rpad)));
            }
        }
        lines.push(Line::from(spans));
    }

    // Bucket label row — name centred in each column, in bucket color.
    let mut label_spans: Vec<Span<'static>> = Vec::with_capacity(entries.len() * 3);
    for (i, (name, color)) in entries.iter().enumerate() {
        let name_w = name.chars().count();
        let lpad = (col_w.saturating_sub(name_w)) / 2;
        let rpad = col_w.saturating_sub(lpad).saturating_sub(name_w);
        label_spans.push(Span::raw(" ".repeat(lpad)));
        label_spans.push(Span::styled(*name, Style::default().fg(*color)));
        if i + 1 < entries.len() {
            label_spans.push(Span::raw(" ".repeat(rpad)));
        }
    }
    lines.push(Line::from(label_spans));

    // Percent row — `Q/B` per bucket, both ends capped at 99 so the
    // label fits the 5-col group budget. Q% = bucket / total_queries
    // (its share of all traffic). B% = bucket / total_blocked (its
    // share of the blocked-traffic pie). Q renders in the bucket
    // colour, slash in muted, B in brand-red so the operator can read
    // the two halves at a glance and the colour cue mirrors the bar
    // pair above.
    let mut pct_spans: Vec<Span<'static>> = Vec::with_capacity(entries.len() * 6);
    for (i, (_, color)) in entries.iter().enumerate() {
        let q_pct = ((counts[i] as f64 / total as f64) * 100.0).round() as u64;
        let b_pct = if total_blocked == 0 {
            0
        } else {
            ((blocked_counts[i] as f64 / total_blocked as f64) * 100.0).round() as u64
        };
        let q_pct = q_pct.min(99);
        let b_pct = b_pct.min(99);
        let q_str = format!("{q_pct}");
        let b_str = format!("{b_pct}");
        let str_w = q_str.chars().count() + 1 + b_str.chars().count();
        let lpad = (col_w.saturating_sub(str_w)) / 2;
        let rpad = col_w.saturating_sub(lpad).saturating_sub(str_w);
        pct_spans.push(Span::raw(" ".repeat(lpad)));
        pct_spans.push(Span::styled(q_str, Style::default().fg(*color)));
        pct_spans.push(Span::styled("/", Style::default().fg(T.text_muted)));
        pct_spans.push(Span::styled(b_str, Style::default().fg(T.brand_red)));
        if i + 1 < entries.len() {
            pct_spans.push(Span::raw(" ".repeat(rpad)));
        }
    }
    lines.push(Line::from(pct_spans));

    f.render_widget(Paragraph::new(lines), inner);
}

/// Pick the bar glyph for a single 2-col bar slot at one row of the
/// 8-row vertical scale. `lvl` is the bar's height on the
/// `0..=MAX_LEVEL` scale; `full_threshold` / `half_threshold` are the
/// row's cutoffs (full-block, half-block, or blank).
fn qtype_bar_glyph(lvl: u32, full_threshold: u32, half_threshold: u32) -> &'static str {
    if lvl >= full_threshold {
        "\u{2588}\u{2588}"
    } else if lvl >= half_threshold {
        "\u{2584}\u{2584}"
    } else {
        "  "
    }
}

// ─── 3. Row 3 — Daily totals barcharts + Global Pulse ─────────────────────

/// Wide-mode row 3 split (34 / 33 / 33 %): `Daily Queries` left,
/// `Daily Blocked` middle, Global Pulse right. The percentages mirror
/// the row-1 KPI strip (System 34 / Block Rate 33 / Cache Hit Rate 33)
/// so the two rows form a single visual column grid: each row-3 card
/// sits exactly under its row-1 sibling. Row 3 lives only in wide
/// mode (≥ 120 cols); the narrow path skips it.
///
/// Sprint D of `_docs/features/dashboard_v2.md` (2026-05-10) retired the
/// 7×24 blocks heatmap that used to occupy this slot — operator note
/// "rework + reasoning": visual signal but not actionable. The two
/// daily-totals barcharts replace it with a directly-actionable
/// "what does my week look like?" answer.
fn render_row3(f: &mut Frame, area: Rect, app: &App) {
    let cols = Layout::horizontal([
        Constraint::Percentage(34),
        Constraint::Percentage(33),
        Constraint::Percentage(33),
    ])
    .split(area);
    render_daily_queries_card(f, cols[0], app);
    render_daily_blocked_card(f, cols[1], app);
    render_global_pulse_card(f, cols[2], app, true);
}

/// Daily total queries managed over the last 10 calendar days (UTC).
/// Blue (`T.chart_2`) accent; today on the right.
fn render_daily_queries_card(f: &mut Frame, area: Rect, app: &App) {
    render_daily_bar_card(
        f,
        area,
        app,
        "Daily Queries \u{2014} 10 UTC days",
        T.chart_2,
        |b| b.queries,
    );
}

/// Daily total blocked queries over the last 10 calendar days (UTC).
/// Red (`T.brand_red`) accent; today on the right.
fn render_daily_blocked_card(f: &mut Frame, area: Rect, app: &App) {
    render_daily_bar_card(
        f,
        area,
        app,
        "Daily Blocked \u{2014} 10 UTC days",
        T.brand_red,
        |b| b.blocked,
    );
}

/// Shared layout for the two daily-totals barcharts on row 3. Renders
/// a 10-day calendar grid anchored on today (UTC, matching
/// `tracking::time_series::truncate_day`). Days with no bucket render
/// as a muted (`T.text_muted`) baseline marker so the column position
/// is visible on cold start, before 10 days of history have
/// accumulated.
///
/// Bars: hand-built half-block stack, 6 vertical rows × 2 sub-levels
/// per row = 12 distinct heights per column (0..=12). Glyphs: `██`
/// for a full-cell row, `▄▄` for a half-cell row (lower half), space
/// for an empty row. Bar cells are flat-coloured in the card accent
/// — no gradient, no `T.heat_color()`, no `ratatui::widgets::BarChart`
/// (Sprint C §11.3 delta 4 lesson: gradients on arbitrary-magnitude
/// charts misread; flat colour scales cleanly).
///
/// Inner layout (9 rows): title + blank + 6 bar rows + weekday labels.
fn render_daily_bar_card<F>(
    f: &mut Frame,
    area: Rect,
    app: &App,
    title: &'static str,
    color: Color,
    extract: F,
) where
    F: Fn(&crate::ipc::protocol::TimeBucketDto) -> u64,
{
    use time::OffsetDateTime;

    let block = theme::framed_block_colored(T.text_primary);
    let inner = block.inner(area);
    f.render_widget(block, area);

    const WINDOW: usize = DAILY_WINDOW;
    const BAR_ROWS: usize = 6;
    const SECS_PER_DAY: u64 = DAILY_SECS_PER_DAY;
    const MAX_LEVEL: u32 = (BAR_ROWS as u32) * 2; // 6 rows × 2 sub-levels

    let now = OffsetDateTime::now_utc();
    let today_anchor = (now.unix_timestamp() as u64) / SECS_PER_DAY * SECS_PER_DAY;

    // Sprint G — aggregation extracted to `aggregate_daily_values` for
    // unit-testability + defensive sum on identical UTC day anchors
    // (belt-and-braces vs `time_series::load()` regressions).
    // `present` flags are computed but unused in the current render
    // path — the cold-start fallback is driven by `is_cold` against
    // `values`. Kept on the helper signature for future callers that
    // may distinguish "no bucket" from "zero-value bucket".
    let (values, _present) = aggregate_daily_values(&app.tracking.daily, today_anchor, &extract);

    let max_val = values.iter().copied().max().unwrap_or(0).max(1);
    let mut levels = [0u32; WINDOW];
    for (i, &v) in values.iter().enumerate() {
        let lvl = ((v as f64 / max_val as f64) * MAX_LEVEL as f64).round() as u32;
        levels[i] = lvl.min(MAX_LEVEL);
    }

    // Y-axis labels render only on populated cards. Cold start hides
    // them (max_val is clamped to 1; "1 / 0 / 0" reads as misleading
    // signal when there is no data).
    let is_cold = values.iter().all(|&v| v == 0);

    // Y-axis labels are sparse: top bar row = max, middle bar row =
    // max/2, bottom bar row = 0. Three reference points give
    // operators a magnitude anchor without crowding the 4-col gutter.
    // All labels are right-aligned to 4 characters; longer values
    // (e.g. `100K`, `10.0M`) overflow gracefully into the leading pad.
    let yaxis_label = |row_from_top: usize| -> String {
        if is_cold {
            return "    ".to_string();
        }
        match row_from_top {
            0 => format!("{:>4}", format_count(max_val)),
            3 => format!("{:>4}", format_count(max_val / 2)),
            r if r == BAR_ROWS - 1 => "   0".to_string(),
            _ => "    ".to_string(),
        }
    };

    let mut lines: Vec<Line<'static>> = Vec::with_capacity(9);

    // Row 0 — bold colored title.
    lines.push(Line::from(vec![
        Span::raw(" "),
        Span::styled(
            title,
            Style::default().fg(color).add_modifier(Modifier::BOLD),
        ),
    ]));

    // Row 1 — blank (chart-panel breathing rule, _docs/rules/TUI_DESIGN.md §"Card
    // Anatomy / Chart panel").
    lines.push(Line::from(""));

    // Rows 2..=7 — 6 bar rows, top-down. Per-cell glyph chosen by
    // comparing the column's level (0..=12) against the row's
    // thresholds. Cells in populated days use the card accent; cells
    // in missing / zero-traffic days fall back to `T.text_muted`,
    // and the bottom row always shows a muted ▄▄ baseline so the
    // column position is visible on cold start. Each row carries a
    // 4-char y-axis label gutter at the left edge (max / mid / 0
    // anchors) and a 1-char separator before the bar grid.
    for row_from_top in 0..BAR_ROWS {
        let row_from_bottom = (BAR_ROWS - 1 - row_from_top) as u32;
        let full_threshold = (row_from_bottom + 1) * 2; // 2,4,6,8,10,12
        let half_threshold = full_threshold - 1; // 1,3,5,7,9,11

        let mut spans: Vec<Span<'static>> = Vec::with_capacity(WINDOW * 2 + 2);
        spans.push(Span::styled(
            yaxis_label(row_from_top),
            Style::default().fg(T.text_muted),
        ));
        spans.push(Span::raw(" "));
        for (i, &lvl) in levels.iter().enumerate() {
            let (glyph, cell_color) = if lvl >= full_threshold {
                ("\u{2588}\u{2588}", color)
            } else if lvl >= half_threshold {
                ("\u{2584}\u{2584}", color)
            } else if row_from_bottom == 0 {
                ("\u{2584}\u{2584}", T.text_muted)
            } else {
                ("  ", T.text_muted)
            };
            spans.push(Span::styled(glyph, Style::default().fg(cell_color)));
            if i + 1 < WINDOW {
                spans.push(Span::raw(" "));
            }
        }
        lines.push(Line::from(spans));
    }

    // Row 8 — x-axis labels: 2-letter English weekday abbreviations
    // (`Mo Tu We Th Fr Sa Su`) for each UTC day in the 10-column
    // window. Today is the rightmost column and renders bold +
    // `T.text_primary` so the right-edge anchor stays obvious; the
    // other 9 columns render `T.text_muted` like the y-axis gutter.
    // The 4-char y-axis gutter + 1-char separator on the left mirror
    // the bar rows' prefix so the labels line up with their bars.
    let mut label_spans: Vec<Span<'static>> = Vec::with_capacity(WINDOW * 2 + 2);
    label_spans.push(Span::raw("    ")); // gutter under y-axis labels
    label_spans.push(Span::raw(" "));
    for i in 0..WINDOW {
        // i=0 (leftmost) → 9 days ago; i=WINDOW-1 (rightmost) → today.
        let days_back = (WINDOW - 1 - i) as u64;
        let column_anchor = today_anchor - days_back * SECS_PER_DAY;
        let label = OffsetDateTime::from_unix_timestamp(column_anchor as i64)
            .map(|dt| weekday_abbrev(dt.weekday()))
            .unwrap_or("  ");
        let style = if i == WINDOW - 1 {
            Style::default()
                .fg(T.text_primary)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(T.text_muted)
        };
        label_spans.push(Span::styled(label, style));
        if i + 1 < WINDOW {
            label_spans.push(Span::raw(" "));
        }
    }
    lines.push(Line::from(label_spans));

    f.render_widget(Paragraph::new(lines), inner);
}

/// Sprint G — trend chart wall-clock slice extracted from
/// `render_trend_chart` for unit-testability. Returns the trailing-24
/// hourly buckets defined by *wall-clock* (`timestamp >= now_hour -
/// 23 × 3600`), not "last 24 entries". Independent of whether the
/// hourly ring carries restart-fragments. Output is timestamp-
/// ascending (preserves input order; the ring is naturally ascending).
pub(crate) fn slice_recent_24h(
    h: &[crate::ipc::protocol::TimeBucketDto],
) -> Vec<crate::ipc::protocol::TimeBucketDto> {
    const SECS_PER_HOUR: u64 = 3600;
    let now = now_secs();
    let now_hour = now - (now % SECS_PER_HOUR);
    let cutoff = now_hour.saturating_sub(23 * SECS_PER_HOUR);
    h.iter()
        .filter(|b| b.timestamp >= cutoff)
        .cloned()
        .collect()
}

/// rev-2607 (#4) — same wall-clock windowing as `slice_recent_24h`,
/// mirrored onto the daily ring. `app.tracking.daily` can carry up to
/// `MAX_DAILY = 10` entries (`tracking/time_series.rs`), but the trend
/// chart's title ("Last 7d") and its 8-tick `-7d … now` label set both
/// assume 7. Without this window, a daemon up 8+ days feeds 8-10 raw
/// buckets straight into an axis sized for 7, so `x_max` outruns the
/// labels and the oldest days plot off the labelled range. Returns the
/// trailing-7 daily buckets defined by wall-clock (`timestamp >=
/// now_day - 6 × 86_400`), not "last 7 entries".
pub(crate) fn slice_recent_7d(
    d: &[crate::ipc::protocol::TimeBucketDto],
) -> Vec<crate::ipc::protocol::TimeBucketDto> {
    const SECS_PER_DAY: u64 = 86_400;
    let now = now_secs();
    let now_day = now - (now % SECS_PER_DAY);
    let cutoff = now_day.saturating_sub(6 * SECS_PER_DAY);
    d.iter()
        .filter(|b| b.timestamp >= cutoff)
        .cloned()
        .collect()
}

/// 2-letter English weekday abbreviation for the daily-bar x-axis
/// labels. Static-str return avoids the per-render allocation that
/// the prior `format!("{:>2}", -offset)` path incurred.
fn weekday_abbrev(wd: time::Weekday) -> &'static str {
    use time::Weekday::*;
    match wd {
        Monday => "Mo",
        Tuesday => "Tu",
        Wednesday => "We",
        Thursday => "Th",
        Friday => "Fr",
        Saturday => "Sa",
        Sunday => "Su",
    }
}

/// Sprint G — daily-bar aggregation helper extracted from
/// `render_daily_bar_card` for unit-testability. Indexes each bucket
/// onto a 10-day UTC grid anchored on `today_anchor`. Buckets older
/// than the window or newer than today are dropped. Multiple buckets
/// sharing the same UTC day anchor are summed via `saturating_add`
/// (defensive vs `time_series::load()` regressions).
pub(crate) const DAILY_WINDOW: usize = 10;
pub(crate) const DAILY_SECS_PER_DAY: u64 = 86_400;

pub(crate) fn aggregate_daily_values<F>(
    buckets: &[crate::ipc::protocol::TimeBucketDto],
    today_anchor: u64,
    extract: F,
) -> ([u64; DAILY_WINDOW], [bool; DAILY_WINDOW])
where
    F: Fn(&crate::ipc::protocol::TimeBucketDto) -> u64,
{
    let oldest_anchor = today_anchor - (DAILY_WINDOW as u64 - 1) * DAILY_SECS_PER_DAY;
    let mut values = [0u64; DAILY_WINDOW];
    let mut present = [false; DAILY_WINDOW];
    for bucket in buckets {
        let day_anchor = bucket.timestamp / DAILY_SECS_PER_DAY * DAILY_SECS_PER_DAY;
        if day_anchor < oldest_anchor || day_anchor > today_anchor {
            continue;
        }
        let idx = ((day_anchor - oldest_anchor) / DAILY_SECS_PER_DAY) as usize;
        values[idx] = values[idx].saturating_add(extract(bucket));
        present[idx] = true;
    }
    (values, present)
}

// ─── 4. Bottom row ────────────────────────────────────────────────────────
//
// History:
//   * Pre-2026-04-29 — two cards (top-blocked + active devices).
//   * 2026-04-29     — redesigned to three ranked cards.
//   * 2026-04-30     — Pulse card (40 %) replaces Top Devices.
//   * 2026-05-10     — Sprint A of dashboard_v2: wide layout drops
//                      Top Domains, splits 50/50 (Top Devices new + Top
//                      Blocked); Pulse moves to row 3 right. Narrow
//                      keeps the pre-v2 40/30/30 (Pulse + Top Domains
//                      + Top Blocked) shape — heatmap row 3 collapses
//                      at < 120 cols and Pulse needs a home there.
//   * 2026-05-10     — Sprint C of dashboard_v2: wide branch re-split
//                      to 33/33/34 (Top Lists left + Top Devices middle
//                      + Top Blocked Domains right). Workstream-closing
//                      layout. Narrow path unchanged.
//   * 2026-05-11     — wide branch shifted to 34/33/33 so the wider
//                      column lands on Top Lists, matching row 3
//                      (`render_row3`: Daily Queries 34 + Daily Blocked
//                      33 + Pulse 33). Column dividers now line up
//                      across rows 3 and 4. Narrow path unchanged.

fn render_bottom_row(f: &mut Frame, area: Rect, app: &App, wide: bool) {
    if wide {
        // 34/33/33 split — Top Lists (Sprint C, daemon-resolved scope/
        // topic labels) | Top Devices (Sprint A) | Top Blocked Domains.
        // Same shape as row 3 (`render_row3`) so column dividers align
        // across rows 3 and 4. Total stays at 100 % so the leftover-
        // cell distribution is deterministic — pure 33/33/33 sums to 99
        // and lets ratatui pick the residual column non-deterministically.
        let cols = Layout::horizontal([
            Constraint::Percentage(34),
            Constraint::Percentage(33),
            Constraint::Percentage(33),
        ])
        .split(area);
        render_top_lists_card(f, cols[0], app);
        render_top_devices_card(f, cols[1], app);
        render_top_domains_card(
            f,
            cols[2],
            "Top Blocked Domains (24h)",
            T.brand_red,
            &app.tracking.top_blocked_24h,
        );
    } else {
        // Narrow fallback: pre-v2 40/30/30 — Pulse, Top Domains, Top
        // Blocked. Heatmap row 3 doesn't render below 120 cols; Pulse
        // needs a home so it stays on the bottom row in narrow mode.
        let cols = Layout::horizontal([
            Constraint::Percentage(40),
            Constraint::Percentage(30),
            Constraint::Percentage(30),
        ])
        .split(area);
        render_global_pulse_card(f, cols[0], app, false);
        render_top_domains_card(
            f,
            cols[1],
            "Top Domains (24h)",
            T.info,
            &app.tracking.top_queried_24h,
        );
        render_top_domains_card(
            f,
            cols[2],
            "Top Blocked Domains (24h)",
            T.brand_red,
            &app.tracking.top_blocked_24h,
        );
    }
}

/// Top-5 devices ranked by `blocked` desc. Reuses `render_ranked_card`.
/// Label is the device's friendly `name` falling back to `ip` for
/// mapped devices (matches `devices.rs:216-219`); unmapped devices
/// have no name field and always render as `ip`.
///
/// Title accent is `T.warning` (amber) per `_docs/features/dashboard_v2.md`
/// D10 — green Top Lists (Sprint C) + amber Top Devices + red Top
/// Blocked rounds out the row 4 trio.
fn render_top_devices_card(f: &mut Frame, area: Rect, app: &App) {
    // Sprint N: rank by `blocked_24h` (sum of the per-device 24h
    // hourly_blocked ring) so the title (24h) and the value agree.
    // Devices with no blocks in the last 24h fall off the list; if
    // every device sums to 0 the card renders the `collecting…`
    // placeholder via `render_ranked_card`'s empty branch.
    let mut rows: Vec<(String, u64)> = Vec::new();
    if let Some(view) = app.device_view.as_ref() {
        for d in &view.mapped {
            let label = if d.name.is_empty() {
                d.ip.clone()
            } else {
                d.name.clone()
            };
            rows.push((label, d.blocked_24h));
        }
        for d in &view.unmapped {
            rows.push((d.ip.clone(), d.blocked_24h));
        }
    }
    rows.retain(|(_, c)| *c > 0);
    rows.sort_by_key(|b| std::cmp::Reverse(b.1));
    rows.truncate(5);
    render_ranked_card(
        f,
        area,
        "Top Devices (24h)",
        T.warning,
        &rows,
        "collecting\u{2026}",
        5,
    );
}

/// Top-5 blocklists ranked by `count` desc. Reuses `render_ranked_card`.
/// Labels arrive ready-to-render from the daemon as `scope/topic`
/// strings (`privacy/tracking`, `security/malicious`, …) — daemon-side
/// bit→label resolution happens in `socket_server::handle_tracking_stats`
/// against the start.rs label snapshot built from `source_bits.iter_urls()`
/// × `Catalog::entries()` (Sprint B plumbing).
///
/// Title accent is `T.scope_security` (green) per `_docs/features/dashboard_v2.md`
/// D10 — green Top Lists + amber Top Devices + red Top Blocked rounds
/// out the row 4 trio. Empty-state copy is `"collecting…"` (D9) to
/// match the sibling Pulse rows' cold-start vocabulary.
fn render_top_lists_card(f: &mut Frame, area: Rect, app: &App) {
    // Sprint N: read the 24h-rolling sibling vec. Pre-Sprint-N daemons
    // emit empty here, so the card renders `collecting…` until both
    // ends of the wire are upgraded. `count_24h` is the per-list
    // ring's 24h sum from `extract_top_n_u8_hourly`.
    let rows: Vec<(String, u64)> = app
        .tracking
        .top_blocked_lists_24h
        .iter()
        .map(|e| (e.label.clone(), e.count_24h))
        .collect();
    render_ranked_card(
        f,
        area,
        "Top Lists (24h)",
        T.scope_security,
        &rows,
        "collecting\u{2026}",
        5,
    );
}

/// Ranked-list card matching the KPI-row Gauge Anatomy: white frame,
/// bold colored title as first interior row, then up to `max_rows`
/// entries laid out as `rank · label · right-aligned count`. The
/// per-row Unicode gradient bar that lived here through 2026-04-29 was
/// retired together with the bottom-row redesign — global signals now
/// live in `render_global_pulse_card`, and these ranking cards stay
/// slim so the eye reads the *order* without competing with bar
/// lengths that didn't carry information beyond the count itself.
fn render_ranked_card(
    f: &mut Frame,
    area: Rect,
    title: &'static str,
    title_color: Color,
    rows: &[(String, u64)],
    empty_msg: &'static str,
    max_rows: usize,
) {
    let block = theme::framed_block_colored(T.text_primary);
    let inner = block.inner(area);
    f.render_widget(block, area);

    let title_line = Line::from(vec![
        Span::raw(" "),
        Span::styled(
            title,
            Style::default()
                .fg(title_color)
                .add_modifier(Modifier::BOLD),
        ),
    ]);

    if rows.is_empty() {
        let lines = vec![
            title_line,
            Line::from(Span::styled(
                format!("  {empty_msg}"),
                Style::default().fg(T.text_muted),
            )),
        ];
        f.render_widget(Paragraph::new(lines), inner);
        return;
    }

    // Body geometry: 1 cell of padding on each side. Columns are
    // rank (right-aligned, 2 chars) → 2-cell gap → label (left-aligned,
    // gets the leftover) → 2-cell gap → count (right-aligned, 7 chars).
    let padded_w = inner.width.saturating_sub(2) as usize;
    const RANK_W: usize = 2;
    const COUNT_W: usize = 7;
    const GAP: usize = 2;
    let label_max = padded_w.saturating_sub(RANK_W + COUNT_W + 2 * GAP).max(6);

    let visible_rows = (inner.height as usize)
        .saturating_sub(1)
        .min(rows.len())
        .min(max_rows);

    let mut lines: Vec<Line<'static>> = Vec::with_capacity(1 + visible_rows);
    lines.push(title_line);

    for (idx, (label, count)) in rows.iter().take(visible_rows).enumerate() {
        let truncated = if label.chars().count() > label_max {
            let head: String = label.chars().take(label_max.saturating_sub(1)).collect();
            format!("{head}\u{2026}")
        } else {
            label.clone()
        };
        let rank_str = format!("{}", idx + 1);

        lines.push(Line::from(vec![
            Span::raw(" "),
            Span::styled(
                format!("{rank_str:>RANK_W$}"),
                Style::default().fg(T.text_muted),
            ),
            Span::raw("  "),
            Span::styled(
                format!("{truncated:<label_max$}"),
                Style::default().fg(T.text_secondary),
            ),
            Span::raw("  "),
            Span::styled(
                format!("{:>COUNT_W$}", format_count(*count)),
                Style::default()
                    .fg(T.text_primary)
                    .add_modifier(Modifier::BOLD),
            ),
        ]));
    }

    f.render_widget(Paragraph::new(lines), inner);
}

/// Polarity of a percentage-point delta. Drives the colour of the
/// `▲`/`▼` glyph next to the 24h value:
///
/// * `HigherIsBetter` — cache hit rate. ↑ = green, ↓ = red.
/// * `Neutral` — block rate. A change up or down isn't intrinsically
///   "good" or "bad" (depends on what the network is doing); rendered
///   in `T.info` so the eye registers the movement without an alarm
///   semantic.
#[derive(Copy, Clone)]
enum DeltaPolarity {
    HigherIsBetter,
    Neutral,
}

/// Synthesis card on the bottom-row left (40 %). Shows five
/// derivative signals — block / cache 24h with 1h delta arrows,
/// peak-hour traffic, active-device count, list freshness — that the
/// daemon already computes but no other surface displays. All rows
/// degrade gracefully to a muted placeholder when the underlying
/// data isn't available yet (cold start, first poll pending, etc.).
/// Title in `T.warning` (amber) to give Pulse its own categorical
/// identity in the bottom-row palette (amber / blue / red across the
/// three cards).
fn render_global_pulse_card(f: &mut Frame, area: Rect, app: &App, wide: bool) {
    let block = theme::framed_block_colored(T.text_primary);
    let inner = block.inner(area);
    f.render_widget(block, area);

    // Bar width budget for the QTYPE stacked-bar row in narrow mode:
    // inner width minus 1-cell leading padding minus the 11-char
    // `Types` label minus 1-cell trailing pad. Clamp at 8 cells so
    // even a narrow Pulse still renders a legible bar.
    let bar_width = (inner.width as usize).saturating_sub(13).max(8);

    let mut lines: Vec<Line<'static>> = Vec::with_capacity(10);
    lines.push(Line::from(vec![
        Span::raw(" "),
        Span::styled(
            "Global Pulse",
            Style::default().fg(T.warning).add_modifier(Modifier::BOLD),
        ),
    ]));
    lines.push(pulse_row_pct(
        "Block 24h",
        app.tracking.blocked_pct_24h,
        app.tracking.blocked_pct_delta_1h,
        DeltaPolarity::Neutral,
    ));
    lines.push(pulse_row_pct(
        "Cache 24h",
        app.tracking.cache_hit_rate_24h,
        app.tracking.cache_hit_rate_delta_1h,
        DeltaPolarity::HigherIsBetter,
    ));
    lines.push(pulse_row_peak(&app.tracking.hourly));
    lines.push(pulse_row_active(app));
    // Filter corpus size — list + domain counts, relocated here from the
    // System card on 2026-05-22. Sits directly above the freshness row so
    // the two list-related signals (how many / how fresh) read together.
    lines.push(pulse_row_filter_counts(app));
    lines.push(pulse_row_lists(app));
    // QTYPE row stays in narrow Pulse only. In wide mode the QTYPE
    // distribution renders as its own row-2 chart card
    // (`render_qtype_chart_card`) — promoting it out of Pulse gives
    // composition data a dedicated panel with at-a-glance comparison
    // across buckets, while leaving Pulse with operational counters.
    if !wide {
        lines.extend(pulse_row_types(&app.tracking.qtype_distribution, bar_width));
    }
    lines.push(pulse_row_prefetch(
        app.tracking.prefetch_pool_size,
        app.tracking.prefetch_promotions_total,
        app.tracking.prefetch_promotions_per_min,
    ));
    // Poll — daemon poll-loop health + cadence, relocated here from the System
    // card (2026-06-06) so System fits the cluster dot without growing. Built
    // with `pulse_label` to match the sibling rows' label width.
    lines.push(Line::from(vec![
        pulse_label("Poll"),
        Span::raw(" "),
        poll_status_span(app),
    ]));
    // RAM/CPU/FDs no longer live here — the daemon's own process health
    // moved to the System card (2026-05-22 rework).

    f.render_widget(Paragraph::new(lines), inner);
}

/// §4.6 + Sprint A of `dashboard_v2`: 100 %-stacked QTYPE bar +
/// compact legend.
///
/// Returns 2 lines on warm state (bar + legend) or 1 line on cold
/// start (`total == 0` → muted `collecting…` placeholder). The caller
/// `extends` the returned vec into its line list so the caller's
/// height accounting stays uniform.
///
/// Active branch:
/// - Rank buckets by count desc, take top 4.
/// - Filter top-4 to the D5 named set `{A, AAAA, HTTPS, TXT}`. Buckets
///   outside the named set fold into the `Other` rollup along with
///   everything below top-4 (operator decision 2026-05-10 — keeps the
///   bar's colour palette stable across polls regardless of which rare
///   bucket happens to spike).
/// - Sub-1 % buckets that round to 0 cells fold into Other too.
/// - Bar cells are `█`, coloured per D5 (A=chart_2 / AAAA=chart_3 /
///   HTTPS=chart_4 / TXT=chart_5 / Other=text_muted). Legend below
///   uses the same colour map; separator `·` muted.
fn pulse_row_types(
    distribution: &[u64; crate::tracking::TYPE_BUCKET_COUNT],
    bar_width: usize,
) -> Vec<Line<'static>> {
    use crate::tracking::query_type::TypeBucket;

    let label = pulse_label("Types");
    let total: u64 = distribution.iter().sum();
    if total == 0 {
        return vec![Line::from(vec![
            label,
            Span::raw(" "),
            Span::styled("collecting\u{2026}", Style::default().fg(T.text_muted)),
        ])];
    }

    // Rank by count desc.
    let mut ranked: Vec<(usize, u64)> = distribution
        .iter()
        .enumerate()
        .map(|(i, c)| (i, *c))
        .filter(|(_, c)| *c > 0)
        .collect();
    ranked.sort_by_key(|b| std::cmp::Reverse(b.1));

    // Pick top-4 D5-named buckets; everything else folds into Other.
    let mut named_runs: Vec<(TypeBucket, u64)> = Vec::with_capacity(4);
    let mut other_count: u64 = 0;
    for (idx, count) in &ranked {
        let bucket = TypeBucket::ALL[*idx];
        let is_named = matches!(
            bucket,
            TypeBucket::A | TypeBucket::Aaaa | TypeBucket::Https | TypeBucket::Txt
        );
        if is_named && named_runs.len() < 4 {
            named_runs.push((bucket, *count));
        } else {
            other_count = other_count.saturating_add(*count);
        }
    }

    // Allocate cells. Sub-1 % named runs (round to 0 cells) fold into
    // Other so the bar always reads cleanly.
    let bw = bar_width.max(1);
    let mut bar_spans: Vec<Span<'static>> = Vec::with_capacity(named_runs.len() + 4);
    bar_spans.push(label.clone());
    bar_spans.push(Span::raw(" "));

    let mut cells_used: usize = 0;
    let mut legend_entries: Vec<(TypeBucket, u64, ratatui::style::Color)> =
        Vec::with_capacity(named_runs.len() + 1);
    for (bucket, count) in &named_runs {
        let cells = (((*count as f64) / (total as f64)) * (bw as f64)).round() as usize;
        if cells == 0 {
            other_count = other_count.saturating_add(*count);
            continue;
        }
        let color = qtype_color(*bucket);
        bar_spans.push(Span::styled(
            "\u{2588}".repeat(cells),
            Style::default().fg(color),
        ));
        legend_entries.push((*bucket, *count, color));
        cells_used = cells_used.saturating_add(cells);
    }

    // Other run gets the leftover cells (so the bar always fills the
    // budget exactly — no trailing dark gutter that would look like
    // missing data).
    if other_count > 0 || cells_used < bw {
        let other_cells = bw.saturating_sub(cells_used);
        if other_cells > 0 {
            bar_spans.push(Span::styled(
                "\u{2588}".repeat(other_cells),
                Style::default().fg(T.text_muted),
            ));
        }
        if other_count > 0 {
            legend_entries.push((TypeBucket::Other, other_count, T.text_muted));
        }
    }

    // Legend line: 11-char blank prefix + entries separated by ` · `.
    // Each entry is `<name> <pct>%`, name + pct in the bucket colour.
    let mut legend_spans: Vec<Span<'static>> = vec![Span::styled(
        " ".repeat(12),
        Style::default().fg(T.text_muted),
    )];
    for (i, (bucket, count, color)) in legend_entries.iter().enumerate() {
        if i > 0 {
            legend_spans.push(Span::styled(
                " \u{00b7} ".to_string(),
                Style::default().fg(T.text_muted),
            ));
        }
        let pct = ((*count as f64) / (total as f64)) * 100.0;
        let label = if matches!(bucket, TypeBucket::Other) {
            "oth".to_string()
        } else {
            bucket.name().to_string()
        };
        legend_spans.push(Span::styled(
            format!("{label} {pct:.0}%"),
            Style::default().fg(*color),
        ));
    }

    vec![Line::from(bar_spans), Line::from(legend_spans)]
}

/// D5 colour map for QTYPE buckets. Other buckets fold into the
/// `Other` rollup (see `pulse_row_types`); they never reach this
/// function.
fn qtype_color(b: crate::tracking::query_type::TypeBucket) -> ratatui::style::Color {
    use crate::tracking::query_type::TypeBucket;
    match b {
        TypeBucket::A => T.chart_2,
        TypeBucket::Aaaa => T.chart_3,
        TypeBucket::Https => T.chart_4,
        TypeBucket::Txt => T.chart_5,
        _ => T.text_muted,
    }
}

/// Sprint §4.4 P2 — Prefetch worker activity row. Renders the current
/// pool size and the per-minute promotion rate derived client-side
/// from the inter-poll counter delta (see `IpcPoller`). Falls back to
/// a muted "collecting…" placeholder until the daemon has reported a
/// non-zero pool or counter — same idiom as `pulse_row_types` so all
/// rows behave consistently on cold start.
fn pulse_row_prefetch(
    pool_size: u32,
    promotions_total: u64,
    promotions_per_min: f64,
) -> Line<'static> {
    let label = pulse_label("Prefetch");
    if pool_size == 0 && promotions_total == 0 {
        return Line::from(vec![
            label,
            Span::raw(" "),
            Span::styled("collecting\u{2026}", Style::default().fg(T.text_muted)),
        ]);
    }
    Line::from(vec![
        label,
        Span::raw(" "),
        Span::styled(
            format!("pool {pool_size}"),
            Style::default()
                .fg(T.text_primary)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(" \u{00b7} ", Style::default().fg(T.text_muted)),
        Span::styled(
            format!("promo {promotions_per_min:.1}/min"),
            Style::default().fg(T.text_secondary),
        ),
    ])
}

/// §4.13 — pure threshold mapping for the System card's RAM row. Integer ratio
/// (`rss_mb * 5 > warn_mb * 4` equals `rss/warn > 0.8`) avoids floats
/// on the render path. `warn_mb == 0` falls through to the muted
/// primary colour because the operator has effectively disabled the
/// threshold and we shouldn't pretend everything is red.
fn rss_colour(rss_mb: u64, warn_mb: u64) -> ratatui::style::Color {
    if warn_mb == 0 {
        return T.text_primary;
    }
    if rss_mb > warn_mb {
        return T.error;
    }
    if rss_mb.saturating_mul(5) > warn_mb.saturating_mul(4) {
        return T.warning;
    }
    T.success
}

/// Standard label column for Pulse rows: leading space + 11-char
/// left-aligned label in `text_secondary`. Fixed width keeps the
/// value column aligned vertically across the five rows.
fn pulse_label(label: &'static str) -> Span<'static> {
    Span::styled(
        format!(" {label:<11}"),
        Style::default().fg(T.text_secondary),
    )
}

fn pulse_row_pct(
    label: &'static str,
    value: f64,
    delta_pp: f64,
    polarity: DeltaPolarity,
) -> Line<'static> {
    Line::from(vec![
        pulse_label(label),
        Span::raw(" "),
        Span::styled(
            format!("{value:>5.1}%"),
            Style::default()
                .fg(T.text_primary)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("  "),
        format_delta_pp(delta_pp, polarity),
    ])
}

/// Render a 1h delta in percentage points. Below 0.1pp the change is
/// dominated by sampling noise — we render an em-dash in `text_muted`
/// instead of an arrow so the eye doesn't lock onto trivial wiggles.
fn format_delta_pp(delta: f64, polarity: DeltaPolarity) -> Span<'static> {
    if delta.abs() < 0.1 {
        return Span::styled("  \u{2014}".to_string(), Style::default().fg(T.text_muted));
    }
    let arrow = if delta > 0.0 { "\u{25b2}" } else { "\u{25bc}" };
    let color = match polarity {
        DeltaPolarity::HigherIsBetter => {
            if delta > 0.0 {
                T.success
            } else {
                T.error
            }
        }
        DeltaPolarity::Neutral => T.info,
    };
    Span::styled(format!("{arrow} {delta:+.1}pp"), Style::default().fg(color))
}

/// Peak hourly query rate in the last 24h, plus how many hours back
/// it landed. Shows `collecting…` while the ring is empty and
/// `no traffic` when every bucket is zero (fresh install, paused
/// daemon).
fn pulse_row_peak(hourly: &[crate::ipc::protocol::TimeBucketDto]) -> Line<'static> {
    let label = pulse_label("Peak");
    if hourly.is_empty() {
        return Line::from(vec![
            label,
            Span::raw(" "),
            Span::styled("collecting\u{2026}", Style::default().fg(T.text_muted)),
        ]);
    }
    // dash-12: window by *wall-clock* via the same `slice_recent_24h`
    // the trend chart uses, not "last 24 entries". Once the hourly ring
    // carries restart fragments (daemon downtime), the trailing 24
    // buckets can span far more than 24h — entry-count slicing then
    // reports a stale peak and an understated "Nh ago". The peak's age
    // comes from its bucket timestamp, not its index distance in the
    // slice.
    let recent = slice_recent_24h(hourly);
    let peak_bucket = match recent.iter().max_by_key(|b| b.queries) {
        Some(b) if b.queries > 0 => b,
        _ => {
            return Line::from(vec![
                label,
                Span::raw(" "),
                Span::styled("no traffic", Style::default().fg(T.text_muted)),
            ]);
        }
    };
    let peak = peak_bucket.queries;
    const SECS_PER_HOUR: u64 = 3600;
    let now = now_secs();
    let now_hour = now - (now % SECS_PER_HOUR);
    let hours_ago = now_hour.saturating_sub(peak_bucket.timestamp) / SECS_PER_HOUR;
    let when = if hours_ago == 0 {
        "now".to_string()
    } else {
        format!("{hours_ago}h ago")
    };
    Line::from(vec![
        label,
        Span::raw(" "),
        Span::styled(
            format!("{:>5} q/h", format_count(peak)),
            Style::default()
                .fg(T.text_primary)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("  "),
        Span::styled(when, Style::default().fg(T.text_muted)),
    ])
}

/// `online / total online` summary across the joined device view.
/// `online` is set daemon-side (see `ObservedDevice::is_online`)
/// using a fixed window in `tracking::engine` — the TUI just sums.
fn pulse_row_active(app: &App) -> Line<'static> {
    let label = pulse_label("Active");
    let Some(view) = app.device_view.as_ref() else {
        return Line::from(vec![
            label,
            Span::raw(" "),
            Span::styled("\u{2014}", Style::default().fg(T.text_muted)),
        ]);
    };
    let online = view.mapped.iter().filter(|d| d.online).count()
        + view.unmapped.iter().filter(|d| d.online).count();
    let total = view.mapped.len() + view.unmapped.len();
    Line::from(vec![
        label,
        Span::raw(" "),
        Span::styled(
            format!("{online} / {total}"),
            Style::default()
                .fg(T.text_primary)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(" online", Style::default().fg(T.text_muted)),
    ])
}

/// Filter corpus counts: number of configured lists + total domains in
/// the engine. Reads the daemon `Status` snapshot — the same source the
/// System card used for these rows before the 2026-05-22 rework moved
/// them here. List count renders `active/total` when the daemon reports
/// the §4.19 registry counters (`lists_total > 0`), else the legacy
/// `list_count` scalar. Muted `—` before the first poll lands.
fn pulse_row_filter_counts(app: &App) -> Line<'static> {
    let label = pulse_label("Filter");
    let Some(s) = app.daemon_status.as_ref() else {
        return Line::from(vec![
            label,
            Span::raw(" "),
            Span::styled("\u{2014}", Style::default().fg(T.text_muted)),
        ]);
    };
    let lists_text = if s.lists_total > 0 {
        format!("{}/{}", s.lists_active, s.lists_total)
    } else {
        format!("{}", s.list_count)
    };
    let refused = s.lists_corpus_refusal.is_some();
    let mut spans = vec![
        label,
        Span::raw(" "),
        // Under a refusal the noun changes, not just the colour. "lists"
        // in this row has always meant *lists in the engine*; a refused
        // cycle fetched every one of them and installed none, so the
        // truthful `N/N` becomes a lie the moment that noun is attached
        // to it. `warden status` makes exactly this substitution
        // (`format_lists_lines`) and for exactly this reason.
        Span::styled(
            format!("{lists_text} {}", if refused { "fetched" } else { "lists" }),
            Style::default()
                .fg(if refused { T.warning } else { T.text_primary })
                .add_modifier(Modifier::BOLD),
        ),
    ];
    if refused {
        spans.push(Span::styled(
            " \u{00b7} ",
            Style::default().fg(T.text_muted),
        ));
        spans.push(Span::styled(
            "REFUSED",
            Style::default().fg(T.error).add_modifier(Modifier::BOLD),
        ));
    } else if s.lists_truncated > 0 {
        spans.push(Span::styled(
            " \u{00b7} ",
            Style::default().fg(T.text_muted),
        ));
        spans.push(Span::styled(
            format!("{} TRUNCATED", s.lists_truncated),
            Style::default().fg(T.warning).add_modifier(Modifier::BOLD),
        ));
    }
    spans.push(Span::styled(
        " \u{00b7} ",
        Style::default().fg(T.text_muted),
    ));
    // The domain count needs its own qualifier, because under a refusal
    // it describes a generation the *last* cycle did not produce — and at
    // zero it describes no generation at all. That zero is the daemon's
    // worst state (up, listening, filtering nothing), and printed bare it
    // reads as an ordinary counter.
    let (domains_text, domains_fg) = match (refused, s.domain_count) {
        (true, 0) => ("0 domains UNFILTERED".to_string(), T.error),
        (true, n) => (
            format!("{} domains (previous)", format_count(n as u64)),
            T.warning,
        ),
        (false, n) => (
            format!("{} domains", format_count(n as u64)),
            T.text_primary,
        ),
    };
    spans.push(Span::styled(
        domains_text,
        Style::default().fg(domains_fg).add_modifier(Modifier::BOLD),
    ));
    Line::from(spans)
}

/// Freshness summary across all configured blocklists. Shows the age
/// of the *oldest* successful fetch as the bottleneck signal — the
/// list most overdue for a refresh — paired with a health badge:
/// `OK` when every list is healthy, `N pending` when at least one is
/// `never_fetched`, `N failed` when at least one failed (failed
/// dominates pending in the badge precedence so a single failure
/// surfaces immediately).
fn pulse_row_lists(app: &App) -> Line<'static> {
    use time::format_description::well_known::Rfc3339;
    use time::OffsetDateTime;

    // Labelled "Fresh" (not "Lists") since the 2026-05-22 rework added a
    // separate "Filter" row carrying the list/domain *counts*; this row
    // owns the freshness/health facet.
    let label = pulse_label("Fresh");
    if app.lists.entries.is_empty() {
        return Line::from(vec![
            label,
            Span::raw(" "),
            Span::styled("not configured", Style::default().fg(T.text_muted)),
        ]);
    }
    let now = OffsetDateTime::now_utc();
    let mut oldest_age_secs: Option<i64> = None;
    let mut never_count: usize = 0;
    let mut failed_count: usize = 0;

    for entry in &app.lists.entries {
        if entry.last_outcome == "never_fetched" {
            never_count += 1;
        } else if entry.last_outcome != "ok" {
            // `failed: <reason>` or any future variant — treat as failed.
            failed_count += 1;
        }
        if let Some(ts_str) = &entry.fetched_at {
            if let Ok(ts) = OffsetDateTime::parse(ts_str, &Rfc3339) {
                let age = (now - ts).whole_seconds();
                oldest_age_secs = Some(match oldest_age_secs {
                    None => age,
                    Some(prev) => prev.max(age),
                });
            }
        }
    }

    let age_text = match oldest_age_secs {
        None => "no fetch yet".to_string(),
        Some(secs) => format!("oldest {}", format_age_short(secs)),
    };
    let badge: Span<'static> = if failed_count > 0 {
        Span::styled(
            format!("{failed_count} failed"),
            Style::default().fg(T.error),
        )
    } else if never_count > 0 {
        Span::styled(
            format!("{never_count} pending"),
            Style::default().fg(T.warning),
        )
    } else {
        Span::styled("OK".to_string(), Style::default().fg(T.success))
    };

    Line::from(vec![
        label,
        Span::raw(" "),
        Span::styled(age_text, Style::default().fg(T.text_primary)),
        Span::styled(" \u{2022} ", Style::default().fg(T.text_muted)),
        badge,
    ])
}

/// Compact "X ago" style used by the Pulse Lists row. Caps at days
/// because anything longer is operationally indistinguishable from
/// "stale" — the badge column carries that signal, no need to render
/// "30d ago" precisely.
fn format_age_short(secs: i64) -> String {
    let s = secs.max(0);
    if s < 60 {
        format!("{s}s ago")
    } else if s < 3600 {
        format!("{}m ago", s / 60)
    } else if s < 86400 {
        format!("{}h ago", s / 3600)
    } else {
        format!("{}d ago", s / 86400)
    }
}

/// Generic top-domains card. Used for both queried (blue title) and
/// blocked (red title) lists; the title color carries the categorical
/// identity now that the per-row bar has been retired. Capped at 5
/// rows so the card height matches the Pulse panel sitting alongside.
fn render_top_domains_card(
    f: &mut Frame,
    area: Rect,
    title: &'static str,
    accent: Color,
    domains: &[DomainCount],
) {
    // Row-4 cards now title themselves `(24h)` and read `count_24h`,
    // so the displayed value matches the title's window semantics.
    // Pre-Sprint-N daemons emit the lifetime vec only (with
    // `count_24h = 0`); the empty-state path renders the
    // `collecting…` placeholder, so the operator never sees a
    // misleading "(24h) = 0" populated card.
    let rows: Vec<(String, u64)> = domains
        .iter()
        .map(|d| (d.domain.clone(), d.count_24h))
        .collect();
    render_ranked_card(f, area, title, accent, &rows, "collecting\u{2026}", 5);
}

// ─── Helpers ───────────────────────────────────────────────────────────────

/// Cache capacity guess: the daemon doesn't expose the cap on the
/// status endpoint, so we round the current usage up to the nearest
/// "nice" capacity bucket. 100k covers the default ceiling; operators
/// with larger caches will see the denominator climb to match.
fn cache_capacity(used: u64) -> u64 {
    if used <= 100_000 {
        100_000
    } else if used <= 1_000_000 {
        1_000_000
    } else {
        10_000_000
    }
}

// ── Formatting helpers ──────────────────────────────────────────────────────

use format::count as format_count;

fn format_uptime(secs: u64) -> String {
    let days = secs / 86400;
    let hours = (secs % 86400) / 3600;
    let mins = (secs % 3600) / 60;
    if days > 0 {
        format!("{days}d {hours:02}h {mins:02}m")
    } else if hours > 0 {
        format!("{hours}h {mins}m")
    } else {
        format!("{mins}m")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line_text(line: &Line<'_>) -> String {
        line.spans.iter().map(|s| s.content.as_ref()).collect()
    }

    fn all_text(lines: &[Line<'_>]) -> String {
        lines.iter().map(line_text).collect::<Vec<_>>().join(" | ")
    }

    #[test]
    fn gauge_title_line_shows_gradient_key_when_wide() {
        // Wide enough: title + `●low ●mid ●high` key fits → key rendered,
        // right-aligned, with three dot glyphs.
        let line = gauge_title_line("Cache Hit Rate \u{2014} 1h", T.scope_security, 60);
        let text = line_text(&line);
        assert!(text.contains("low"), "missing low: {text:?}");
        assert!(text.contains("mid"), "missing mid: {text:?}");
        assert!(text.contains("high"), "missing high: {text:?}");
        assert_eq!(
            text.matches('\u{25cf}').count(),
            3,
            "expected 3 gradient dots: {text:?}"
        );
    }

    #[test]
    fn gauge_title_line_drops_key_when_narrow() {
        // Too narrow to hold the key without crowding the title → key dropped
        // entirely (graceful degradation), title still present, no dots.
        let line = gauge_title_line("Cache Hit Rate \u{2014} 1h", T.scope_security, 10);
        let text = line_text(&line);
        assert!(text.contains("Cache Hit Rate"), "title lost: {text:?}");
        assert_eq!(
            text.matches('\u{25cf}').count(),
            0,
            "key not dropped: {text:?}"
        );
    }

    #[test]
    fn build_window_gauge_lines_row_count_unchanged_by_key() {
        // The gradient key lives in the title row, so the body is still
        // exactly `title + 2 rows per window` — no extra row that would
        // clip the bottom window in the fixed-height KPI panel.
        let windows = vec![
            WindowMetric {
                label: "1h",
                value: 5,
                total: 10,
                pct: 50.0,
            },
            WindowMetric {
                label: "24h",
                value: 2,
                total: 10,
                pct: 20.0,
            },
        ];
        let lines = build_window_gauge_lines("Block Rate \u{2014} 1h", T.brand_red, &windows, 60);
        assert_eq!(lines.len(), 1 + windows.len() * 2);
    }

    #[test]
    fn fmt_hhmm_formats_utc_hour_minute() {
        assert_eq!(fmt_hhmm(0), "00:00"); // 1970-01-01 00:00 UTC
        assert_eq!(fmt_hhmm(50_400), "14:00"); // 14 * 3600
        assert_eq!(fmt_hhmm(86_399), "23:59"); // last minute of the day
    }

    #[test]
    fn fmt_monthday_formats_utc_month_day() {
        assert_eq!(fmt_monthday(0), "01-01"); // 1970-01-01 UTC
        assert_eq!(fmt_monthday(2_678_400), "02-01"); // +31 days
    }

    /// Concatenate a rendered `Buffer`'s cell symbols row-by-row so a
    /// `contains` check reads the post-render grid.
    fn dump_buffer(buf: &ratatui::buffer::Buffer) -> String {
        let mut out = String::new();
        for y in 0..buf.area.height {
            for x in 0..buf.area.width {
                out.push_str(buf[(x, y)].symbol());
            }
        }
        out
    }

    fn mk_bucket(ts: u64, queries: u64) -> crate::ipc::protocol::TimeBucketDto {
        crate::ipc::protocol::TimeBucketDto {
            timestamp: ts,
            queries,
            blocked: 0,
            cache_hits: 0,
        }
    }

    #[test]
    fn trend_chart_renders_peak_caption_in_daily_view() {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;

        let mut app = App::new();
        app.dashboard.show_daily = true;
        // rev-2607 (#4) — the daily branch is now windowed through
        // `slice_recent_7d`, which filters by wall-clock `now`,  so
        // fixed epoch-1970 timestamps (as this test used pre-fix) no
        // longer survive the window. Anchor to `now_day` instead.
        let now = now_secs();
        let now_day = now - (now % 86_400);
        let peak_ts = now_day - 86_400; // yesterday
                                        // Peak is the middle bucket (5 queries), NOT the oldest (2)
                                        // bucket — proves the caption tracks the max bucket.
        app.tracking.daily = vec![
            mk_bucket(now_day - 2 * 86_400, 2),
            mk_bucket(peak_ts, 5),
            mk_bucket(now_day, 1),
        ];

        let backend = TestBackend::new(120, 14);
        let mut term = Terminal::new(backend).unwrap();
        term.draw(|f| {
            render_trend_chart(f, ratatui::layout::Rect::new(0, 0, 120, 14), &app);
        })
        .unwrap();

        let dump = dump_buffer(term.backend().buffer());
        assert!(dump.contains("peak 5"), "peak caption missing:\n{dump}");
        let expected_day = fmt_monthday(peak_ts);
        assert!(
            dump.contains(&expected_day),
            "peak day ({expected_day}) of the max bucket missing:\n{dump}"
        );
    }

    #[test]
    fn trend_chart_omits_peak_caption_when_all_zero() {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;

        let mut app = App::new();
        app.dashboard.show_daily = true;
        // rev-2607 (#4) — anchor to `now_day` so these buckets survive
        // the `slice_recent_7d` window and this test keeps exercising
        // the all-zero `peak_caption` filter, not the empty-`buckets`
        // early return (both happen to omit "peak", but only the
        // former is what this test claims to cover).
        let now = now_secs();
        let now_day = now - (now % 86_400);
        // Every bucket zero (fresh install / paused) → no stray "peak 0".
        app.tracking.daily = vec![mk_bucket(now_day - 86_400, 0), mk_bucket(now_day, 0)];

        let backend = TestBackend::new(120, 14);
        let mut term = Terminal::new(backend).unwrap();
        term.draw(|f| {
            render_trend_chart(f, ratatui::layout::Rect::new(0, 0, 120, 14), &app);
        })
        .unwrap();

        let dump = dump_buffer(term.backend().buffer());
        assert!(
            !dump.contains("peak"),
            "peak caption should be absent:\n{dump}"
        );
    }

    /// rev-2607 (#4) — closes the render-level gap, not just the
    /// `slice_recent_7d` helper: a full `MAX_DAILY = 10` ring with its
    /// single largest bucket OUTSIDE the 7-day window. Before the fix,
    /// `render_trend_chart`'s daily branch bound `&app.tracking.daily`
    /// raw and unwindowed, so `peak_caption` (which scans whatever
    /// `buckets` it's handed) would report the out-of-window spike —
    /// exactly the "chart plots 8-10 points across an 8-tick '-7d …
    /// now' axis" defect, made visible through the one number the
    /// operator actually reads. Unit-testing `slice_recent_7d` alone
    /// cannot catch this: that function didn't exist pre-fix, and it
    /// proves the helper works, not that `render_trend_chart` calls it.
    #[test]
    fn trend_chart_daily_render_excludes_out_of_window_peak() {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;

        let mut app = App::new();
        app.dashboard.show_daily = true;
        let now = now_secs();
        let now_day = now - (now % 86_400);

        // Full 10-entry ring. The largest bucket (999) sits at -9d,
        // outside the 7-day window (cutoff is -6d) — a chart still
        // rendering the raw ring would surface it as the peak. A
        // smaller in-window bucket (77) at -2d proves the windowed
        // chart still finds ITS OWN max, not just "no peak at all".
        app.tracking.daily = vec![
            mk_bucket(now_day - 9 * 86_400, 999), // outside window
            mk_bucket(now_day - 8 * 86_400, 500), // outside window
            mk_bucket(now_day - 7 * 86_400, 300), // outside window (cutoff is -6d)
            mk_bucket(now_day - 6 * 86_400, 10),
            mk_bucket(now_day - 5 * 86_400, 10),
            mk_bucket(now_day - 4 * 86_400, 10),
            mk_bucket(now_day - 3 * 86_400, 10),
            mk_bucket(now_day - 2 * 86_400, 77), // in-window peak
            mk_bucket(now_day - 86_400, 10),
            mk_bucket(now_day, 10),
        ];

        let backend = TestBackend::new(120, 14);
        let mut term = Terminal::new(backend).unwrap();
        term.draw(|f| {
            render_trend_chart(f, ratatui::layout::Rect::new(0, 0, 120, 14), &app);
        })
        .unwrap();

        let dump = dump_buffer(term.backend().buffer());
        assert!(
            !dump.contains("peak 999") && !dump.contains("peak 500") && !dump.contains("peak 300"),
            "out-of-window buckets must not be considered for the peak caption:\n{dump}"
        );
        assert!(
            dump.contains("peak 77"),
            "the in-window max (77) must still be found:\n{dump}"
        );
    }

    #[test]
    fn status_span_reports_stale_when_disconnected() {
        // status_span is only reached with a populated daemon_status, so a
        // dropped link is "stale" (holding old data), not "disconnected".
        let mut app = App::new();
        app.connected = false;
        app.paused = false;
        let text = status_span(&app).content.into_owned();
        assert!(text.contains("stale"), "expected stale: {text:?}");
        assert!(text.contains('\u{25cc}'), "expected dotted ◌: {text:?}");
    }

    #[test]
    fn status_span_reports_running_when_connected() {
        let mut app = App::new();
        app.connected = true;
        app.paused = false;
        assert!(status_span(&app).content.contains("running"));
    }

    #[test]
    fn status_span_reports_paused_when_connected_and_paused() {
        let mut app = App::new();
        app.connected = true;
        app.paused = true;
        assert!(status_span(&app).content.contains("paused"));
    }

    #[test]
    fn system_panel_shows_starting_before_first_status() {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;

        let app = App::new(); // daemon_status defaults to None
        assert!(app.daemon_status.is_none());

        let backend = TestBackend::new(40, 11);
        let mut term = Terminal::new(backend).unwrap();
        term.draw(|f| {
            render_system_panel(f, ratatui::layout::Rect::new(0, 0, 40, 11), &app, false);
        })
        .unwrap();

        let dump = dump_buffer(term.backend().buffer());
        assert!(dump.contains("STARTING"), "missing STARTING badge:\n{dump}");
    }

    /// `s-4.13-row-narrow-mode-suppress`, measured at the real floor share
    /// rather than reasoned about: the System card gets 34 % of an 80-col
    /// KPI row, ~25 cells inside its border. A daemon under load
    /// (4-digit RSS, 3-digit FD count) overflowed that silently — the
    /// RAM row's last two characters vanished with no marker (`512 FDs`
    /// rendered as `512 F`, which reads as a smaller, wrong number, not
    /// as "something was cut").
    #[test]
    fn floor_system_panel_ellipsises_an_overlong_ram_row_instead_of_clipping_it() {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;

        let mut app = App::new();
        app.daemon_status = Some(crate::tui::app::DaemonStatus {
            pid: 1,
            listen: "0.0.0.0:53".into(),
            upstream_mode: "DoH".into(),
            upstream_count: 2,
            domain_count: 5_000_000,
            cache_entries: 12345,
            list_count: 8,
            uptime_secs: 100000,
            version: "0.37.0".into(),
            cache_cap: 20000,
            lists_active: 8,
            lists_total: 8,
            lists_truncated: 0,
            resource_budget: Some(crate::resource_budget::ResourceBudgetSnapshot {
                rss_mb: 4096,
                vsz_mb: 8192,
                fd_count: 512,
                cpu_user_pct: 87,
                rss_warn_mb: 3000,
            }),
            lists_corpus_refusal: None,
        });
        app.connected = true;
        // 80-col floor, System gets 34% of the KPI row width — the real
        // narrow-mode share `render_kpi_row` gives it, not a guess.
        let sys_w = (80u16 * 34) / 100;
        let backend = TestBackend::new(sys_w, 11);
        let mut term = Terminal::new(backend).unwrap();
        term.draw(|f| {
            render_system_panel(f, ratatui::layout::Rect::new(0, 0, sys_w, 11), &app, true);
        })
        .unwrap();
        let dump = dump_buffer(term.backend().buffer());

        // The exact truncation, not just "an ellipsis appeared somewhere":
        // `value_budget` is 15 cells at this width, so 14 characters of
        // the real value plus the marker — never the old silent clip
        // (`512 F`, missing "Ds" with nothing saying so).
        assert!(
            dump.contains("4096 MB \u{b7} 512 \u{2026}"),
            "the RAM row must ellipsise at its real budget, not clip \
             mid-unit with no marker:\n{dump}"
        );
        assert!(
            !dump.contains("512 FDs"),
            "the fixture's value must actually exceed the budget for this \
             test to mean anything:\n{dump}"
        );
    }

    #[test]
    fn dim_rect_dims_only_inside_rect() {
        use ratatui::buffer::Buffer;
        use ratatui::layout::Rect as R;

        let mut buf = Buffer::empty(R::new(0, 0, 10, 4));
        dim_rect(&mut buf, R::new(2, 1, 4, 2)); // x∈[2,6) y∈[1,3)
        assert!(
            buf[(3, 1)].modifier.contains(Modifier::DIM),
            "inside not dimmed"
        );
        assert!(
            buf[(5, 2)].modifier.contains(Modifier::DIM),
            "inside not dimmed"
        );
        assert!(
            !buf[(0, 0)].modifier.contains(Modifier::DIM),
            "outside dimmed"
        );
        assert!(
            !buf[(8, 3)].modifier.contains(Modifier::DIM),
            "outside dimmed"
        );
        assert!(
            !buf[(6, 1)].modifier.contains(Modifier::DIM),
            "right edge must be exclusive"
        );
    }

    #[test]
    fn disconnect_dims_data_widgets_but_not_system_panel() {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;

        let mut app = App::new();
        app.connected = false; // link down → stale snapshot

        let backend = TestBackend::new(120, 43);
        let mut term = Terminal::new(backend).unwrap();
        term.draw(|f| {
            render(f, ratatui::layout::Rect::new(0, 0, 120, 43), &app);
        })
        .unwrap();

        let buf = term.backend().buffer();
        // System panel (first KPI column, top-left) stays bright.
        assert!(
            !buf[(3, 1)].modifier.contains(Modifier::DIM),
            "System panel must stay bright"
        );
        // Block Rate gauge (second KPI column) is dimmed.
        assert!(
            buf[(60, 3)].modifier.contains(Modifier::DIM),
            "Block Rate gauge must be dimmed"
        );
        // A data widget below the KPI row is dimmed.
        assert!(
            buf[(3, 12)].modifier.contains(Modifier::DIM),
            "row-2 data widget must be dimmed"
        );
    }

    #[test]
    fn connected_dashboard_applies_no_dim() {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;

        let mut app = App::new();
        app.connected = true;

        let backend = TestBackend::new(120, 43);
        let mut term = Terminal::new(backend).unwrap();
        term.draw(|f| {
            render(f, ratatui::layout::Rect::new(0, 0, 120, 43), &app);
        })
        .unwrap();

        let buf = term.backend().buffer();
        assert!(
            !buf[(3, 12)].modifier.contains(Modifier::DIM),
            "nothing should be dimmed while connected"
        );
    }

    #[test]
    fn pulse_row_types_empty_distribution_shows_collecting() {
        // Cold start returns exactly 1 line with the muted placeholder.
        let dist = [0u64; crate::tracking::TYPE_BUCKET_COUNT];
        let lines = pulse_row_types(&dist, 40);
        assert_eq!(lines.len(), 1);
        assert!(line_text(&lines[0]).contains("collecting"));
    }

    #[test]
    fn pulse_row_types_renders_top_three_in_descending_order() {
        // 700 A + 200 AAAA + 80 HTTPS + 14 Other + 5 TXT + 1 PTR.
        // Top 4 named: A, AAAA, HTTPS (TXT only 5 = sub-1% folds).
        let mut dist = [0u64; crate::tracking::TYPE_BUCKET_COUNT];
        dist[0] = 700; // A
        dist[1] = 200; // AAAA
        dist[8] = 80; // HTTPS
        dist[9] = 14; // Other (literal bucket folds into rollup)
        dist[2] = 5; // TXT (sub-1% — rounds to 0 cells, folds)
        dist[3] = 1; // PTR (not in D5 named set, folds)
        let lines = pulse_row_types(&dist, 40);
        assert_eq!(lines.len(), 2, "warm state returns bar + legend");
        let text = all_text(&lines);

        let pos_a = text.find('A').unwrap_or(usize::MAX);
        let pos_aaaa = text.find("AAAA").unwrap_or(usize::MAX);
        let pos_https = text.find("HTTPS").unwrap_or(usize::MAX);
        assert!(pos_a < pos_aaaa);
        assert!(pos_aaaa < pos_https);
        assert!(!text.contains("TXT"), "sub-1% TXT must fold to oth");
        assert!(!text.contains("PTR"), "non-D5 PTR must fold to oth");
        assert!(text.contains("70%"));
        assert!(text.contains("20%"));
        assert!(text.contains("8%"));
    }

    #[test]
    fn pulse_row_types_omits_zero_buckets_when_fewer_than_three_active() {
        // Only A queries — bar 100% A, no Other run, no AAAA in legend.
        let mut dist = [0u64; crate::tracking::TYPE_BUCKET_COUNT];
        dist[0] = 50;
        let lines = pulse_row_types(&dist, 40);
        let text = all_text(&lines);
        assert!(text.contains("100%"));
        assert!(!text.contains("AAAA"));
        assert!(!text.contains(" oth "));
    }

    // ── Sprint A of dashboard_v2 — Top Devices / Top Lists / row-3 ─

    #[test]
    fn top_devices_sort_truncates_at_five() {
        use crate::ipc::protocol::{DeviceViewDto, MappedDeviceDto, UnmappedDeviceDto};
        use crate::tui::app::App;
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;

        let mk_mapped = |name: &str, ip: &str, blocked: u64| MappedDeviceDto {
            ip: ip.into(),
            name: name.into(),
            mac: None,
            mac_aliases: vec![],
            profile: "default".into(),
            owner: None,
            device_type: None,
            department: None,
            queries: blocked * 10,
            queries_today: 0,
            blocked,
            // Top Devices ranks on blocked_24h post-Sprint-N. Mirror
            // the lifetime fixture value so the existing test intent
            // (top 5 by the closure's `blocked` arg) is preserved
            // without rewriting the assertion table.
            blocked_24h: blocked,
            cache_hits: 0,
            last_seen: 0,
            online: false,
            vendor: None,
            groups: vec![],
            notes: None,
            network_name: None,
            network_name_wildcard: false,
            id: None,
            hourly_queries: vec![],
            unfiltered: false,
        };
        let mk_unmapped = |ip: &str, blocked: u64| UnmappedDeviceDto {
            ip: ip.into(),
            mac: None,
            queries: blocked * 10,
            queries_today: 0,
            blocked,
            blocked_24h: blocked,
            last_seen: 0,
            online: false,
            vendor: None,
            hourly_queries: vec![],
        };

        // 7 mapped + 3 unmapped, mixed blocked counts. Top 5 by
        // blocked desc must be: phone(99) / laptop(80) / 10.0.0.5(70)
        /* / tv(55) / desktop(40). */
        let mut app = App::new();
        app.device_view = Some(DeviceViewDto {
            mapped: vec![
                mk_mapped("laptop", "10.0.0.1", 80),
                mk_mapped("desktop", "10.0.0.2", 40),
                mk_mapped("", "10.0.0.3", 25), // empty name → ip fallback
                mk_mapped("phone", "10.0.0.4", 99),
                mk_mapped("tv", "10.0.0.6", 55),
                mk_mapped("printer", "10.0.0.7", 5),
                mk_mapped("speaker", "10.0.0.8", 1),
            ],
            unmapped: vec![
                mk_unmapped("10.0.0.5", 70),
                mk_unmapped("10.0.0.9", 30),
                mk_unmapped("10.0.0.10", 0),
            ],
        });

        // Build the rows the same way render_top_devices_card does
        // and assert ordering — direct rendering would only compile
        // the function; this asserts the sort + label fallback rule.
        let mut rows: Vec<(String, u64)> = Vec::new();
        if let Some(view) = app.device_view.as_ref() {
            for d in &view.mapped {
                let label = if d.name.is_empty() {
                    d.ip.clone()
                } else {
                    d.name.clone()
                };
                rows.push((label, d.blocked));
            }
            for d in &view.unmapped {
                rows.push((d.ip.clone(), d.blocked));
            }
        }
        rows.sort_by_key(|b| std::cmp::Reverse(b.1));
        rows.truncate(5);

        assert_eq!(rows.len(), 5);
        assert_eq!(rows[0], ("phone".to_string(), 99));
        assert_eq!(rows[1], ("laptop".to_string(), 80));
        assert_eq!(rows[2], ("10.0.0.5".to_string(), 70));
        assert_eq!(rows[3], ("tv".to_string(), 55));
        assert_eq!(rows[4], ("desktop".to_string(), 40));

        // Render must not panic against the same fixture.
        let backend = TestBackend::new(60, 10);
        let mut term = Terminal::new(backend).unwrap();
        term.draw(|f| {
            let area = ratatui::layout::Rect::new(0, 0, 60, 10);
            render_top_devices_card(f, area, &app);
        })
        .unwrap();
    }

    #[test]
    fn qtype_bar_proportions_correct() {
        // [A=70, AAAA=20, HTTPS=5, TXT=3, NS=1, SOA=1] @ width 40.
        // Total = 100. Cells: A=28, AAAA=8, HTTPS=2, TXT=1; NS+SOA
        // (non-D5) fold into Other.
        let mut dist = [0u64; crate::tracking::TYPE_BUCKET_COUNT];
        dist[0] = 70; // A
        dist[1] = 20; // AAAA
        dist[8] = 5; // HTTPS
        dist[2] = 3; // TXT
        dist[4] = 1; // NS
        dist[5] = 1; // SOA
        let lines = pulse_row_types(&dist, 40);
        assert_eq!(lines.len(), 2);
        let bar = &lines[0];
        // Count █ glyphs per coloured run via span colours.
        let block = '\u{2588}';
        let counts: Vec<(usize, ratatui::style::Color)> = bar
            .spans
            .iter()
            .filter_map(|s| {
                let n = s.content.chars().filter(|c| *c == block).count();
                if n > 0 {
                    Some((n, s.style.fg.unwrap_or(T.text_muted)))
                } else {
                    None
                }
            })
            .collect();
        // 4 named runs + 1 Other run = 5 coloured segments total.
        assert_eq!(counts.len(), 5, "got runs: {counts:?}");
        assert_eq!(counts[0].0, 28); // A
        assert_eq!(counts[1].0, 8); // AAAA
        assert_eq!(counts[2].0, 2); // HTTPS
        assert_eq!(counts[3].0, 1); // TXT
                                    // Other gets remaining: 40 - 28 - 8 - 2 - 1 = 1 cell.
        assert_eq!(counts[4].0, 1);
        assert_eq!(counts[4].1, T.text_muted);
    }

    #[test]
    fn qtype_bar_folds_sub_one_pct_into_other() {
        // 6 buckets each 1/600 = ~0.17%. At width 40, each rounds to
        // 0 cells → all fold into Other. Total bar = Other gray run.
        let mut dist = [0u64; crate::tracking::TYPE_BUCKET_COUNT];
        // Heavy bucket so the others are sub-1%.
        dist[0] = 600; // A — dominates
        dist[1] = 1; // AAAA
        dist[2] = 1; // TXT
        dist[8] = 1; // HTTPS
        let lines = pulse_row_types(&dist, 40);
        assert_eq!(lines.len(), 2);
        let text = all_text(&lines);
        // A run dominates → ~99% → 40 cells. Sub-1% AAAA/TXT/HTTPS
        // each round to 0 cells and fold into Other.
        assert!(text.contains("oth") || text.contains("99%"));
        // Sub-1% buckets must NOT appear in the legend (folded to oth).
        // Note: "A 99%" still contains 'A', so we look for the
        // standalone "AAAA " token.
        assert!(!text.contains("AAAA "));
    }

    #[test]
    fn qtype_bar_cold_start_muted_fallback() {
        // total == 0 → single line with collecting placeholder.
        let dist = [0u64; crate::tracking::TYPE_BUCKET_COUNT];
        let lines = pulse_row_types(&dist, 40);
        assert_eq!(lines.len(), 1);
        let text = line_text(&lines[0]);
        assert!(text.contains("collecting"));
        assert!(text.contains("Types"));
    }

    // ── Sprint C of dashboard_v2 — Top Lists card render ────────────

    /// Concatenate `Buffer` cell symbols row-by-row with newlines so
    /// `find` / `contains` checks read the rendered grid rather than
    /// the abstract Line list. Local to the Sprint C tests; the
    /// existing `line_text` / `all_text` helpers operate on `Line`s,
    /// not on the post-render buffer.
    fn buffer_dump(buf: &ratatui::buffer::Buffer) -> String {
        let mut out = String::new();
        for y in 0..buf.area.height {
            for x in 0..buf.area.width {
                out.push_str(buf[(x, y)].symbol());
            }
            out.push('\n');
        }
        out
    }

    #[test]
    fn top_lists_card_renders_from_fixture() {
        use crate::ipc::protocol::ListBlockCount;
        use crate::tui::app::App;
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;

        let mut app = App::new();
        // Top Lists card now reads `top_blocked_lists_24h` and ranks by
        // `count_24h`. Mirror lifetime → 24h so the fixture's
        // assertion table (privacy/tracking is rank 1, etc.) stays
        // valid without rewriting per-row expectations.
        app.tracking.top_blocked_lists_24h = vec![
            ListBlockCount {
                label: "privacy/tracking".into(),
                count: 220,
                count_24h: 220,
            },
            ListBlockCount {
                label: "security/suspicious".into(),
                count: 110,
                count_24h: 110,
            },
            ListBlockCount {
                label: "privacy/ads".into(),
                count: 55,
                count_24h: 55,
            },
            ListBlockCount {
                label: "security/malicious".into(),
                count: 12,
                count_24h: 12,
            },
            ListBlockCount {
                label: "content/social".into(),
                count: 3,
                count_24h: 3,
            },
        ];

        let backend = TestBackend::new(60, 8);
        let mut term = Terminal::new(backend).unwrap();
        term.draw(|f| {
            let area = ratatui::layout::Rect::new(0, 0, 60, 8);
            render_top_lists_card(f, area, &app);
        })
        .unwrap();

        let dump = buffer_dump(term.backend().buffer());
        // Title + ranked labels + a count must reach the buffer.
        assert!(dump.contains("Top Lists"), "title missing in dump:\n{dump}");
        assert!(dump.contains("privacy/tracking"), "rank 1 label missing");
        assert!(dump.contains("security/suspicious"), "rank 2 label missing");
        assert!(dump.contains("220"), "rank 1 count missing");
        // Rank 1 must precede rank 2 in reading order.
        let pos_one = dump.find("privacy/tracking").unwrap();
        let pos_two = dump.find("security/suspicious").unwrap();
        assert!(
            pos_one < pos_two,
            "rank 1 must precede rank 2: {pos_one} vs {pos_two}"
        );
        // Cold-start placeholder must NOT appear when warm.
        assert!(
            !dump.contains("collecting"),
            "warm state must not show cold-start placeholder"
        );
    }

    #[test]
    fn top_lists_card_cold_start_muted_fallback() {
        use crate::tui::app::App;
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;

        // Empty top_blocked_lists by default — pre-Sprint-B daemons
        // and freshly-restarted Sprint-B daemons both land here.
        let app = App::new();

        let backend = TestBackend::new(60, 8);
        let mut term = Terminal::new(backend).unwrap();
        term.draw(|f| {
            let area = ratatui::layout::Rect::new(0, 0, 60, 8);
            render_top_lists_card(f, area, &app);
        })
        .unwrap();

        let dump = buffer_dump(term.backend().buffer());
        assert!(dump.contains("Top Lists"), "title missing in dump:\n{dump}");
        // Per §9 sub-decision: D9 "collecting…" (operator-confirmed).
        assert!(
            dump.contains("collecting"),
            "cold-start placeholder missing in dump:\n{dump}"
        );
    }

    /// Sprint N: title qualifier flipped from `(lifetime)` to `(24h)`
    /// on all three row-4 cards. Pin so a future refactor doesn't
    /// silently revert the operator-facing semantics.
    #[test]
    fn row4_cards_titles_show_24h_qualifier() {
        use crate::ipc::protocol::{DomainCount, ListBlockCount};
        use crate::tui::app::App;
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;

        let mut app = App::new();
        app.tracking.top_blocked_24h = vec![DomainCount {
            domain: "ads.example".into(),
            count: 100,
            count_24h: 50,
            scope: None,
        }];
        app.tracking.top_blocked_lists_24h = vec![ListBlockCount {
            label: "privacy/ads".into(),
            count: 100,
            count_24h: 30,
        }];

        // Top Blocked Domains (24h)
        let backend = TestBackend::new(60, 8);
        let mut term = Terminal::new(backend).unwrap();
        term.draw(|f| {
            render_top_domains_card(
                f,
                ratatui::layout::Rect::new(0, 0, 60, 8),
                "Top Blocked Domains (24h)",
                T.brand_red,
                &app.tracking.top_blocked_24h,
            );
        })
        .unwrap();
        let dump = buffer_dump(term.backend().buffer());
        assert!(
            dump.contains("(24h)"),
            "(24h) qualifier missing on Top Blocked Domains:\n{dump}"
        );
        assert!(
            !dump.contains("(lifetime)"),
            "stale (lifetime) text still present:\n{dump}"
        );

        // Top Lists (24h)
        let backend = TestBackend::new(60, 8);
        let mut term = Terminal::new(backend).unwrap();
        term.draw(|f| {
            render_top_lists_card(f, ratatui::layout::Rect::new(0, 0, 60, 8), &app);
        })
        .unwrap();
        let dump = buffer_dump(term.backend().buffer());
        assert!(
            dump.contains("(24h)"),
            "(24h) qualifier missing on Top Lists:\n{dump}"
        );

        // Top Devices (24h)
        let backend = TestBackend::new(60, 8);
        let mut term = Terminal::new(backend).unwrap();
        term.draw(|f| {
            render_top_devices_card(f, ratatui::layout::Rect::new(0, 0, 60, 8), &app);
        })
        .unwrap();
        let dump = buffer_dump(term.backend().buffer());
        assert!(
            dump.contains("(24h)"),
            "(24h) qualifier missing on Top Devices:\n{dump}"
        );
    }

    /// Sprint N: Top Devices ranks by `blocked_24h`, not lifetime
    /// `blocked`. Set a fixture where the two diverge and assert the
    /// renderer picks the 24h ordering.
    #[test]
    fn top_devices_ranks_by_24h_not_lifetime() {
        use crate::ipc::protocol::{DeviceViewDto, MappedDeviceDto};
        use crate::tui::app::App;
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;

        let mk = |name: &str, ip: &str, lifetime: u64, last_24h: u64| MappedDeviceDto {
            ip: ip.into(),
            name: name.into(),
            mac: None,
            mac_aliases: vec![],
            profile: "default".into(),
            owner: None,
            device_type: None,
            department: None,
            queries: lifetime * 10,
            queries_today: 0,
            blocked: lifetime,
            blocked_24h: last_24h,
            cache_hits: 0,
            last_seen: 0,
            online: false,
            vendor: None,
            groups: vec![],
            notes: None,
            network_name: None,
            network_name_wildcard: false,
            id: None,
            hourly_queries: vec![],
            unfiltered: false,
        };

        let mut app = App::new();
        app.device_view = Some(DeviceViewDto {
            // Heavy-lifetime / no-recent-traffic device should fall off
            // the 24h list. Fresh device with 24h spike should top it.
            mapped: vec![
                mk("dormant", "10.0.0.1", 10_000, 0),
                mk("fresh", "10.0.0.2", 100, 500),
                mk("steady", "10.0.0.3", 1_000, 200),
            ],
            unmapped: vec![],
        });

        let backend = TestBackend::new(60, 8);
        let mut term = Terminal::new(backend).unwrap();
        term.draw(|f| {
            render_top_devices_card(f, ratatui::layout::Rect::new(0, 0, 60, 8), &app);
        })
        .unwrap();
        let dump = buffer_dump(term.backend().buffer());

        assert!(dump.contains("fresh"), "fresh device missing:\n{dump}");
        assert!(dump.contains("steady"), "steady device missing:\n{dump}");
        assert!(
            !dump.contains("dormant"),
            "dormant device has 0 in 24h — must be filtered out:\n{dump}"
        );
        let pos_fresh = dump.find("fresh").unwrap();
        let pos_steady = dump.find("steady").unwrap();
        assert!(
            pos_fresh < pos_steady,
            "fresh (24h=500) must rank above steady (24h=200): fresh@{pos_fresh} steady@{pos_steady}"
        );
    }

    // ── Sprint D of dashboard_v2 — daily-totals barcharts ──────────

    /// Builds a `Vec<TimeBucketDto>` covering the `n` most recent UTC
    /// days ending at today, each populated with the same fixture
    /// `(queries, blocked)` payload. Used to seed the daily-bar tests
    /// against a stable today-anchored grid regardless of when the
    /// suite runs.
    fn seed_daily_window(
        n: usize,
        queries: u64,
        blocked: u64,
    ) -> Vec<crate::ipc::protocol::TimeBucketDto> {
        use crate::ipc::protocol::TimeBucketDto;
        use time::OffsetDateTime;
        const SECS_PER_DAY: u64 = 86_400;
        let now = OffsetDateTime::now_utc().unix_timestamp() as u64;
        let today_anchor = now / SECS_PER_DAY * SECS_PER_DAY;
        (0..n)
            .map(|i| TimeBucketDto {
                timestamp: today_anchor - (n as u64 - 1 - i as u64) * SECS_PER_DAY,
                queries,
                blocked,
                cache_hits: 0,
            })
            .collect()
    }

    #[test]
    fn daily_bar_card_renders_with_full_window() {
        use crate::tui::app::App;
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;

        let mut app = App::new();
        app.tracking.daily = seed_daily_window(10, 1_000, 100);

        let backend = TestBackend::new(48, 11);
        let mut term = Terminal::new(backend).unwrap();
        term.draw(|f| {
            let area = ratatui::layout::Rect::new(0, 0, 48, 11);
            render_daily_queries_card(f, area, &app);
        })
        .unwrap();
        let dump = buffer_dump(term.backend().buffer());
        assert!(
            dump.contains("Daily Queries"),
            "title missing in dump:\n{dump}"
        );
        // Full-block glyph U+2588 must appear at least once when 10
        // populated days render at uniform max value.
        assert!(
            dump.contains('\u{2588}'),
            "expected at least one full-block bar cell in dump:\n{dump}"
        );
    }

    #[test]
    fn daily_bar_card_pads_left_when_below_window() {
        use crate::tui::app::App;
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;

        let mut app = App::new();
        // Only 3 days seeded → leftmost 7 columns must render as
        // muted baseline; rightmost 3 carry the card-accent fill.
        app.tracking.daily = seed_daily_window(3, 500, 50);

        let backend = TestBackend::new(48, 11);
        let mut term = Terminal::new(backend).unwrap();
        term.draw(|f| {
            let area = ratatui::layout::Rect::new(0, 0, 48, 11);
            render_daily_blocked_card(f, area, &app);
        })
        .unwrap();
        let dump = buffer_dump(term.backend().buffer());
        assert!(
            dump.contains("Daily Blocked"),
            "title missing in dump:\n{dump}"
        );
        // The render must execute end-to-end; layout sanity is the
        // stable assertion (per-cell colours depend on theme rgb).
        assert!(
            dump.contains('\u{2588}') || dump.contains('\u{2584}'),
            "expected at least one bar glyph for the populated days in dump:\n{dump}"
        );
    }

    #[test]
    fn daily_bar_card_cold_start_zero_data() {
        use crate::tui::app::App;
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;

        let app = App::new();
        // `app.tracking.daily` is empty by default. Render must not
        // panic and the card title must appear.
        let backend = TestBackend::new(48, 11);
        let mut term = Terminal::new(backend).unwrap();
        term.draw(|f| {
            let area = ratatui::layout::Rect::new(0, 0, 48, 11);
            render_daily_queries_card(f, area, &app);
        })
        .unwrap();
        let dump = buffer_dump(term.backend().buffer());
        assert!(
            dump.contains("Daily Queries"),
            "title missing in dump:\n{dump}"
        );
        // Cold start: every column gets a muted ▄▄ baseline at the
        // bottom row so the 10-day grid is visible. No full-block
        // cells should appear above the baseline.
        assert!(
            dump.contains('\u{2584}'),
            "expected muted baseline ▄▄ marker on cold start in dump:\n{dump}"
        );
        assert!(
            !dump.contains('\u{2588}'),
            "no full-block cells expected when daily ring is empty:\n{dump}"
        );
    }

    #[test]
    fn weekday_abbrev_covers_all_seven_days() {
        use time::Weekday::*;
        assert_eq!(weekday_abbrev(Monday), "Mo");
        assert_eq!(weekday_abbrev(Tuesday), "Tu");
        assert_eq!(weekday_abbrev(Wednesday), "We");
        assert_eq!(weekday_abbrev(Thursday), "Th");
        assert_eq!(weekday_abbrev(Friday), "Fr");
        assert_eq!(weekday_abbrev(Saturday), "Sa");
        assert_eq!(weekday_abbrev(Sunday), "Su");
    }

    #[test]
    fn daily_bar_card_renders_weekday_initials() {
        use crate::tui::app::App;
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;

        let mut app = App::new();
        app.tracking.daily = seed_daily_window(10, 1_000, 100);

        let backend = TestBackend::new(48, 11);
        let mut term = Terminal::new(backend).unwrap();
        term.draw(|f| {
            let area = ratatui::layout::Rect::new(0, 0, 48, 11);
            render_daily_queries_card(f, area, &app);
        })
        .unwrap();
        let dump = buffer_dump(term.backend().buffer());
        // At least one weekday abbrev must appear on the x-axis row.
        let weekdays = ["Mo", "Tu", "We", "Th", "Fr", "Sa", "Su"];
        assert!(
            weekdays.iter().any(|w| dump.contains(w)),
            "expected weekday abbrev on x-axis in dump:\n{dump}"
        );
        // Old days-ago labels (" -1" … " -9") must not appear.
        assert!(
            !dump.contains(" -"),
            "stale `-N` day-offset label still present:\n{dump}"
        );
    }

    // ── Sprint D fixup #4 + Sprint E — QType chart card on row 2 right ─────────

    #[test]
    fn qtype_chart_card_renders_named_buckets() {
        use crate::tui::app::App;
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;

        let mut app = App::new();
        // 4 named buckets with non-uniform counts so bar levels differ.
        // Bucket order matches `TypeBucket::ALL`: A(0) / AAAA(1) / TXT(4)
        // / HTTPS(8). Exact discriminants are pinned by the
        // `qtype_classifier_*` tests in tracking::query_type.
        let mut dist = [0u64; crate::tracking::TYPE_BUCKET_COUNT];
        dist[0] = 700; // A
        dist[1] = 200; // AAAA
        dist[4] = 50; // TXT
        dist[8] = 30; // HTTPS
                      // 20 rolled into Other via PTR (idx 5).
        dist[5] = 20;
        app.tracking.qtype_distribution_24h = dist;
        // Sprint E — non-zero blocked counts in three buckets so the
        // grouped 2-bar layout has a Total + Blocked pair to render
        // per group. Sums to 62, exercising the `b_pct` denominator.
        let mut bdist = [0u64; crate::tracking::TYPE_BUCKET_COUNT];
        bdist[0] = 45; // A blocked
        bdist[1] = 10; // AAAA blocked
        bdist[4] = 5; // TXT blocked
        bdist[5] = 2; // PTR → Other blocked
                      // HTTPS blocked stays at 0 → DM5 muted baseline.
        app.tracking.qtype_blocked_distribution_24h = bdist;

        let backend = TestBackend::new(40, 14);
        let mut term = Terminal::new(backend).unwrap();
        term.draw(|f| {
            let area = ratatui::layout::Rect::new(0, 0, 40, 14);
            render_qtype_chart_card(f, area, &app);
        })
        .unwrap();
        let dump = buffer_dump(term.backend().buffer());
        assert!(
            dump.contains("Query Types"),
            "title missing in dump:\n{dump}"
        );
        assert!(
            dump.contains("AAAA"),
            "AAAA bucket label missing in dump:\n{dump}"
        );
        assert!(
            dump.contains("HTTPS"),
            "HTTPS bucket label missing in dump:\n{dump}"
        );
        assert!(
            dump.contains("oth"),
            "Other rollup label missing in dump:\n{dump}"
        );
        // The dominant bucket renders at full level → at least one
        // full-block cell must appear above the baseline.
        assert!(
            dump.contains('\u{2588}'),
            "expected at least one full-block bar cell in dump:\n{dump}"
        );
        // Sprint E percent row uses `Q/B` not `Q%`; expect ≥ 5 slashes
        // (one per bucket group).
        assert!(
            dump.matches('/').count() >= 5,
            "expected ≥ 5 `/` separators in percent row:\n{dump}"
        );
    }

    #[test]
    fn qtype_chart_card_cold_start_collecting_placeholder() {
        use crate::tui::app::App;
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;

        let app = App::new();
        // Sprint F — `qtype_distribution_24h` + `qtype_blocked_distribution_24h`
        // are both `[0; N]` by default (the chart card now reads the 24h
        // rolling window, not the cumulative counters); total == 0 → cold
        // start placeholder.
        let backend = TestBackend::new(40, 14);
        let mut term = Terminal::new(backend).unwrap();
        term.draw(|f| {
            let area = ratatui::layout::Rect::new(0, 0, 40, 14);
            render_qtype_chart_card(f, area, &app);
        })
        .unwrap();
        let dump = buffer_dump(term.backend().buffer());
        assert!(
            dump.contains("Query Types"),
            "title missing in dump:\n{dump}"
        );
        assert!(
            dump.contains("collecting"),
            "expected `collecting…` placeholder on cold start in dump:\n{dump}"
        );
        // No bar glyphs and no `Q/B` percent row on cold start.
        assert!(
            !dump.contains('\u{2588}'),
            "no full-block cells expected on cold start:\n{dump}"
        );
        assert!(
            !dump.contains('/'),
            "no `Q/B` percent labels expected on cold start:\n{dump}"
        );
    }

    /// Sprint E DM4 — populated blocked counts must render as a second
    /// bar per bucket. Verifies the layout produces a high cell count
    /// (multiple bar columns × multiple rows) which is impossible with
    /// the legacy single-bar shape at this grid size.
    #[test]
    fn qtype_chart_card_renders_blocked_bar_in_brand_red() {
        use crate::tui::app::App;
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;

        let mut app = App::new();
        let mut dist = [0u64; crate::tracking::TYPE_BUCKET_COUNT];
        dist[0] = 100; // A
        dist[1] = 100; // AAAA — equal totals so both bars peg max
        app.tracking.qtype_distribution_24h = dist;
        let mut bdist = [0u64; crate::tracking::TYPE_BUCKET_COUNT];
        bdist[0] = 100; // A all blocked → blocked bar pegs max
        bdist[1] = 100; // AAAA all blocked
        app.tracking.qtype_blocked_distribution_24h = bdist;

        let backend = TestBackend::new(40, 14);
        let mut term = Terminal::new(backend).unwrap();
        term.draw(|f| {
            let area = ratatui::layout::Rect::new(0, 0, 40, 14);
            render_qtype_chart_card(f, area, &app);
        })
        .unwrap();
        let dump = buffer_dump(term.backend().buffer());
        // With 2 buckets at full height + 2-bar grouping, the Total +
        // Blocked bars together produce ≥ 2 × BAR_ROWS = 16 full-block
        // cells. Legacy single-bar layout would produce at most 8.
        let full_block_count = dump.matches('\u{2588}').count();
        assert!(
            full_block_count >= 16,
            "expected ≥ 16 full-block cells (2 bars × 8 rows × 2 buckets), got {full_block_count}:\n{dump}"
        );
    }

    /// Sprint E DM5 — when a bucket has queries but blocked == 0, its
    /// blocked bar must render as a muted 1-row baseline so the slot
    /// remains visible. Verified by the absence of full-block above
    /// the baseline for the all-zero-blocked case.
    #[test]
    fn qtype_chart_card_blocked_zero_for_bucket_renders_muted_baseline() {
        use crate::tui::app::App;
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;

        let mut app = App::new();
        // Single bucket, no blocks at all.
        let mut dist = [0u64; crate::tracking::TYPE_BUCKET_COUNT];
        dist[0] = 1000; // A — dominant Total
        app.tracking.qtype_distribution_24h = dist;
        // qtype_blocked_distribution stays all-zero.

        let backend = TestBackend::new(40, 14);
        let mut term = Terminal::new(backend).unwrap();
        term.draw(|f| {
            let area = ratatui::layout::Rect::new(0, 0, 40, 14);
            render_qtype_chart_card(f, area, &app);
        })
        .unwrap();
        let dump = buffer_dump(term.backend().buffer());
        // The Total bar reaches full height (1 bucket alone) → some
        // full-block cells exist. The blocked bar across all buckets
        // is the muted baseline; the half-block ▄▄ glyph must appear
        // somewhere in the chart even though no bucket has any blocks.
        assert!(
            dump.contains('\u{2584}'),
            "expected muted ▄▄ baseline for blocked-zero bucket:\n{dump}"
        );
    }

    /// Sprint E DM4 — percent row uses `Q/B` format with operator-
    /// confirmed denominators (Q% = bucket / total_queries; B% =
    /// bucket / total_blocked).
    #[test]
    fn qtype_chart_card_percent_row_format_q_slash_b() {
        use crate::tui::app::App;
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;

        let mut app = App::new();
        // Total = 1000 → A is 70 % of queries.
        // Blocked total = 100 → A is 45 % of blocks.
        let mut dist = [0u64; crate::tracking::TYPE_BUCKET_COUNT];
        dist[0] = 700; // A → 70 / total
        dist[1] = 200; // AAAA → 20
        dist[4] = 50; // TXT → 5
        dist[8] = 30; // HTTPS → 3
        dist[5] = 20; // PTR → Other → 2
        app.tracking.qtype_distribution_24h = dist;
        let mut bdist = [0u64; crate::tracking::TYPE_BUCKET_COUNT];
        bdist[0] = 45; // A → 45 / total_blocked
        bdist[1] = 30;
        bdist[4] = 15;
        bdist[8] = 5;
        bdist[5] = 5;
        app.tracking.qtype_blocked_distribution_24h = bdist;

        let backend = TestBackend::new(60, 14);
        let mut term = Terminal::new(backend).unwrap();
        term.draw(|f| {
            let area = ratatui::layout::Rect::new(0, 0, 60, 14);
            render_qtype_chart_card(f, area, &app);
        })
        .unwrap();
        let dump = buffer_dump(term.backend().buffer());
        // A: Q% = 70, B% = 45 → "70/45" must appear verbatim.
        assert!(
            dump.contains("70/45"),
            "expected `70/45` in A bucket percent column:\n{dump}"
        );
    }

    /// Sprint E DM4 — overflow guard: percentages cap at 99 to keep
    /// the label inside the 5-col group budget. A 100 % bucket renders
    /// as `99`, never `100`.
    #[test]
    fn qtype_chart_card_percent_overflow_caps_at_99() {
        use crate::tui::app::App;
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;

        let mut app = App::new();
        // Single bucket carries 100 % of both totals.
        let mut dist = [0u64; crate::tracking::TYPE_BUCKET_COUNT];
        dist[0] = 1; // A only
        app.tracking.qtype_distribution_24h = dist;
        let mut bdist = [0u64; crate::tracking::TYPE_BUCKET_COUNT];
        bdist[0] = 1;
        app.tracking.qtype_blocked_distribution_24h = bdist;

        let backend = TestBackend::new(40, 14);
        let mut term = Terminal::new(backend).unwrap();
        term.draw(|f| {
            let area = ratatui::layout::Rect::new(0, 0, 40, 14);
            render_qtype_chart_card(f, area, &app);
        })
        .unwrap();
        let dump = buffer_dump(term.backend().buffer());
        // The A bucket renders as "99/99" (cap), not "100/100".
        assert!(
            dump.contains("99/99"),
            "expected `99/99` cap in A bucket:\n{dump}"
        );
        assert!(
            !dump.contains("100/"),
            "100 must be capped to 99, never appear as `100/`:\n{dump}"
        );
    }

    /// Sprint F — the QTYPE chart card must read the 24h rolling
    /// fields, NOT the cumulative ones. Seed cumulative with non-zero
    /// counts but leave the 24h fields all-zero: the render fn should
    /// still produce the cold-start `collecting…` placeholder, proving
    /// the active read source is the 24h pair.
    #[test]
    fn qtype_chart_card_reads_24h_not_cumulative() {
        use crate::tui::app::App;
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;

        let mut app = App::new();
        // Cumulative (Sprint E) fields heavily populated.
        let mut dist = [0u64; crate::tracking::TYPE_BUCKET_COUNT];
        dist[0] = 35_000;
        dist[1] = 12_000;
        dist[8] = 4_500;
        app.tracking.qtype_distribution = dist;
        let mut bdist = [0u64; crate::tracking::TYPE_BUCKET_COUNT];
        bdist[0] = 30;
        bdist[1] = 6;
        app.tracking.qtype_blocked_distribution = bdist;
        // 24h rolling window fields stay all-zero (default) → render
        // must short-circuit on the 24h `total == 0` check.

        let backend = TestBackend::new(40, 14);
        let mut term = Terminal::new(backend).unwrap();
        term.draw(|f| {
            let area = ratatui::layout::Rect::new(0, 0, 40, 14);
            render_qtype_chart_card(f, area, &app);
        })
        .unwrap();
        let dump = buffer_dump(term.backend().buffer());
        assert!(
            dump.contains("collecting"),
            "render must use 24h fields (all-zero) → expect `collecting…`, not the cumulative bars:\n{dump}"
        );
        assert!(
            !dump.contains('\u{2588}'),
            "no full-block cells should render when 24h fields are zero, even if cumulative is set:\n{dump}"
        );
    }

    #[test]
    fn dashboard_layout_shrink_no_panic() {
        // Render the full dashboard at 60×24 (well below
        // WIDE_THRESHOLD = 120). Must pick the narrow branch and
        // not panic.
        use crate::tui::app::App;
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;

        let app = App::new();
        let backend = TestBackend::new(60, 24);
        let mut term = Terminal::new(backend).unwrap();
        let result = term.draw(|f| {
            let area = ratatui::layout::Rect::new(0, 0, 60, 24);
            render(f, area, &app);
        });
        assert!(result.is_ok());
    }

    // Sprint §4.4 P2 — Prefetch row coverage.

    #[test]
    fn pulse_row_prefetch_cold_state_shows_collecting() {
        // First poll, no promotions yet → muted placeholder.
        let line = pulse_row_prefetch(0, 0, 0.0);
        let text = line_text(&line);
        assert!(text.contains("Prefetch"));
        assert!(text.contains("collecting"));
        assert!(!text.contains("pool"));
        assert!(!text.contains("promo"));
    }

    #[test]
    fn pulse_row_prefetch_active_state_shows_pool_and_rate() {
        // pool=12, total=42, rate=3.2/min → "pool 12 · promo 3.2/min".
        let line = pulse_row_prefetch(12, 42, 3.2);
        let text = line_text(&line);
        assert!(text.contains("Prefetch"));
        assert!(text.contains("pool 12"));
        assert!(text.contains("promo 3.2/min"));
        assert!(!text.contains("collecting"));
    }

    #[test]
    fn pulse_row_prefetch_zero_rate_with_warm_pool_still_shows_active() {
        // pool>0 OR promotions>0 → active state, even if the per-min
        // rate is currently 0.0 (e.g. first poll after a quiet minute).
        let line = pulse_row_prefetch(5, 1, 0.0);
        let text = line_text(&line);
        assert!(text.contains("pool 5"));
        assert!(text.contains("promo 0.0/min"));
        assert!(!text.contains("collecting"));
    }

    // ── Rolling-window pro-rate tests (rolling_sum) ─────────────────
    //
    // Background: the dashboard's "1h"/"8h"/"24h"/"7d" gauges used to
    // sum the last N fixed-boundary buckets, which produced a 100 %
    // cliff at every top-of-hour rollover for the 1h gauge. The new
    // `rolling_sum` aggregates buckets that intersect a window ending
    // at `now`, pro-rating the single bucket that straddles the
    // start edge by the fraction of its span inside the window.

    use crate::ipc::protocol::TimeBucketDto;

    fn at_hour(h: u64) -> u64 {
        // 2024-01-01 00:00:00 UTC = 1_704_067_200
        1_704_067_200 + h * 3600
    }

    fn bk(ts: u64, queries: u64, blocked: u64, cache_hits: u64) -> TimeBucketDto {
        TimeBucketDto {
            timestamp: ts,
            queries,
            blocked,
            cache_hits,
        }
    }

    #[test]
    fn rolling_inside_single_bucket_full_weight() {
        // Single hourly bucket at 14:00 with 100 queries; now = 14:32.
        // Bucket is fully inside the 1h window [13:32, 14:32], weight 1.0.
        let buckets = vec![bk(at_hour(14), 100, 10, 0)];
        let now = at_hour(14) + 32 * 60;
        let (blocked, total) = rolling_sum(&buckets, now, 3600, 3600, |b| b.blocked, |b| b.queries);
        assert_eq!(total, 100);
        assert_eq!(blocked, 10);
    }

    #[test]
    fn rolling_pro_rates_trailing_edge_bucket() {
        // now = 14:32, window = 1h → window_start = 13:32.
        // Bucket 13:00 (100q, 10 blk) overlaps 28 min of 60 → weight 28/60.
        // Bucket 14:00 (50q,  5 blk) fully inside           → weight 1.0.
        // Expected total: 50 + 100 * 28/60 = 50 + 46.67 ≈ 97.
        // Expected blocked: 5 + 10 * 28/60 ≈ 9.67 → rounds to 10.
        let buckets = vec![bk(at_hour(13), 100, 10, 0), bk(at_hour(14), 50, 5, 0)];
        let now = at_hour(14) + 32 * 60;
        let (blocked, total) = rolling_sum(&buckets, now, 3600, 3600, |b| b.blocked, |b| b.queries);
        assert!((total as i64 - 97).abs() <= 1, "total = {}", total);
        assert!((blocked as i64 - 10).abs() <= 1, "blocked = {}", blocked);
    }

    #[test]
    fn rolling_smooth_across_hour_boundary() {
        // 30 sec before vs 30 sec after a top-of-hour rollover, the
        // rolling 1h sum must not drop by a full bucket. Old code: cliff
        // of ~60 (one full hourly bucket falls off). New code: < 5.
        let pre = vec![bk(at_hour(13), 60, 0, 0), bk(at_hour(14), 60, 0, 0)];
        let now_pre = at_hour(14) + 59 * 60 + 30; // 14:59:30
        let (_, total_pre) = rolling_sum(&pre, now_pre, 3600, 3600, |b| b.blocked, |b| b.queries);

        // After the boundary the daemon adds the new bucket at 15:00
        // with whatever traffic accrued in the first 30 sec — say 1 query.
        let post = vec![
            bk(at_hour(13), 60, 0, 0),
            bk(at_hour(14), 60, 0, 0),
            bk(at_hour(15), 1, 0, 0),
        ];
        let now_post = at_hour(15) + 30; // 15:00:30
        let (_, total_post) =
            rolling_sum(&post, now_post, 3600, 3600, |b| b.blocked, |b| b.queries);

        assert!(
            (total_pre as i64 - total_post as i64).abs() < 5,
            "pre = {}, post = {} (must transition smoothly, no cliff)",
            total_pre,
            total_post
        );
    }

    #[test]
    fn rolling_skips_buckets_fully_outside_window() {
        // Stale bucket far in the past must not contribute even at
        // partial weight — `bucket_end <= window_start` short-circuits.
        let buckets = vec![
            bk(at_hour(0), 999, 999, 999), // ancient
            bk(at_hour(14), 50, 5, 0),
        ];
        let now = at_hour(14) + 30 * 60;
        let (blocked, total) = rolling_sum(&buckets, now, 3600, 3600, |b| b.blocked, |b| b.queries);
        assert_eq!(total, 50);
        assert_eq!(blocked, 5);
    }

    #[test]
    fn rolling_daily_uses_86400_bucket_size() {
        // 7-day window over daily buckets; oldest bucket aligns exactly
        // with `window_start` so its weight is full 1.0 and total = 700.
        let now = 1_704_067_200 + 7 * 86_400; // 2024-01-08 00:00 UTC
        let buckets: Vec<TimeBucketDto> = (0..7)
            .map(|i| bk(now - (7 - i) * 86_400, 100, 10, 0))
            .collect();
        let (blocked, total) = rolling_sum(
            &buckets,
            now,
            7 * 86_400,
            86_400,
            |b| b.blocked,
            |b| b.queries,
        );
        assert_eq!(total, 700);
        assert_eq!(blocked, 70);
    }

    #[test]
    fn rolling_empty_window_returns_zero() {
        let buckets: Vec<TimeBucketDto> = vec![];
        let (blocked, total) = rolling_sum(
            &buckets,
            at_hour(14),
            3600,
            3600,
            |b| b.blocked,
            |b| b.queries,
        );
        assert_eq!(total, 0);
        assert_eq!(blocked, 0);
    }

    // ── Sprint G — daily aggregation + trend slice helpers ──────────

    /// Sprint G — three same-UTC-day fragments at the today anchor
    /// collapse into the today column (sum), while a fragment on the
    /// previous day stays in its own column. Proves
    /// `aggregate_daily_values` is sum-not-assign.
    #[test]
    fn daily_card_sums_buckets_sharing_utc_day() {
        let day = DAILY_SECS_PER_DAY;
        let today_anchor = 1_700_000_000u64 / day * day;
        let buckets = vec![
            TimeBucketDto {
                timestamp: today_anchor,
                queries: 100,
                blocked: 10,
                cache_hits: 1,
            },
            TimeBucketDto {
                timestamp: today_anchor,
                queries: 200,
                blocked: 20,
                cache_hits: 2,
            },
            TimeBucketDto {
                timestamp: today_anchor,
                queries: 50,
                blocked: 5,
                cache_hits: 0,
            },
            TimeBucketDto {
                timestamp: today_anchor - day,
                queries: 75,
                blocked: 7,
                cache_hits: 0,
            },
        ];
        let (values, present) = aggregate_daily_values(&buckets, today_anchor, |b| b.queries);

        // Window: indices 0..=9, index 9 is today (today_anchor),
        // index 8 is yesterday (today_anchor - 86400).
        assert_eq!(values[9], 350, "today sums three fragments 100+200+50");
        assert_eq!(values[8], 75, "yesterday single bucket");
        assert!(present[9]);
        assert!(present[8]);
        assert!(!present[7], "two-days-ago has no bucket");
        assert_eq!(values[7], 0);

        // Same exercise on the blocked extractor — proves the helper
        // is generic over the extract closure, not hard-wired.
        let (vb, _) = aggregate_daily_values(&buckets, today_anchor, |b| b.blocked);
        assert_eq!(vb[9], 35);
        assert_eq!(vb[8], 7);
    }

    /// Sprint G — `slice_recent_24h` filters by wall-clock
    /// `timestamp >= now_hour - 23*3600`, not "last 24 entries". A ring
    /// with restart-fragments older than 23h is dropped even if the
    /// total entry count is under 24.
    #[test]
    fn trend_slice_takes_only_recent_24h() {
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let now_hour = now - (now % 3600);
        let buckets = vec![
            TimeBucketDto {
                timestamp: now_hour - 30 * 3600,
                queries: 5,
                blocked: 0,
                cache_hits: 0,
            }, // dropped — too old
            TimeBucketDto {
                timestamp: now_hour - 25 * 3600,
                queries: 10,
                blocked: 0,
                cache_hits: 0,
            }, // dropped
            TimeBucketDto {
                timestamp: now_hour - 23 * 3600,
                queries: 15,
                blocked: 0,
                cache_hits: 0,
            }, // kept (boundary)
            TimeBucketDto {
                timestamp: now_hour - 3600,
                queries: 20,
                blocked: 0,
                cache_hits: 0,
            }, // kept
            TimeBucketDto {
                timestamp: now_hour,
                queries: 25,
                blocked: 0,
                cache_hits: 0,
            }, // kept (current)
        ];
        let out = slice_recent_24h(&buckets);
        assert_eq!(out.len(), 3);
        assert_eq!(out[0].queries, 15);
        assert_eq!(out[1].queries, 20);
        assert_eq!(out[2].queries, 25);
    }

    /// rev-2607 (#4) — a daemon up 8+ days fills `MAX_DAILY = 10`
    /// entries in the daily ring, but the trend chart's "Last 7d"
    /// title and its 8-tick `-7d … now` label set both assume 7. Feed
    /// `slice_recent_7d` a full 10-entry ring (mirroring what
    /// `app.tracking.daily` actually holds) and confirm the window —
    /// and therefore `x_max = buckets.len() - 1`, which sizes the
    /// chart's x-axis in `render_trend_chart` — never exceeds the
    /// 7-day / 6-index range the labels can represent. Before this
    /// fix, `buckets` was `&app.tracking.daily` raw and unwindowed, so
    /// a 10-entry ring plotted `x_max = 9` against labels that only
    /// span `[0, 6]` — the two oldest days landed off the labelled
    /// range and "now" landed on the wrong column.
    #[test]
    fn trend_daily_slice_windows_full_ring_to_7_days() {
        const SECS_PER_DAY: u64 = 86_400;
        let now = now_secs();
        let now_day = now - (now % SECS_PER_DAY);
        // Full MAX_DAILY = 10 ring, oldest-first (ascending), matching
        // the real ring's natural order: 9 days ago through today.
        let buckets: Vec<TimeBucketDto> = (0u64..10)
            .rev()
            .map(|days_ago| TimeBucketDto {
                timestamp: now_day - days_ago * SECS_PER_DAY,
                queries: 100 - days_ago,
                blocked: 0,
                cache_hits: 0,
            })
            .collect();
        let out = slice_recent_7d(&buckets);

        // Exactly 7 buckets survive: today plus the 6 days before it.
        assert_eq!(out.len(), 7, "expected a 7-day window, got {out:?}");

        // The x-axis this feeds is `bounds([0.0, buckets.len() - 1])`
        // under an 8-label `-7d..now` set sized for a 7-bucket range —
        // so every surviving bucket's implied x-index must fall inside
        // that range.
        let x_max = out.len() - 1;
        assert!(
            x_max <= 6,
            "x_max ({x_max}) must stay inside the 7-day labelled range"
        );

        // Oldest surviving bucket is the boundary (-6d); newest is
        // today (0d) — the two days beyond the window (-8d, -9d) are
        // gone.
        assert_eq!(out.first().unwrap().timestamp, now_day - 6 * SECS_PER_DAY);
        assert_eq!(out.last().unwrap().timestamp, now_day);
        assert!(out
            .iter()
            .all(|b| b.timestamp >= now_day - 6 * SECS_PER_DAY));
    }

    /// dash-12 — the Pulse `Peak` row must window by wall-clock, not
    /// entry count. A big spike 30h ago (outside the 24h window) plus a
    /// smaller real peak 5h ago: entry-count slicing would pick the
    /// stale spike and misreport its age; wall-clock slicing drops it
    /// and ages the in-window peak off its bucket timestamp.
    #[test]
    fn pulse_peak_windows_by_wall_clock_not_entry_count() {
        let now = now_secs();
        let now_hour = now - (now % 3600);
        let mk = |h_ago: u64, q: u64| TimeBucketDto {
            timestamp: now_hour - h_ago * 3600,
            queries: q,
            blocked: 0,
            cache_hits: 0,
        };
        let buckets = vec![mk(30, 100), mk(5, 40), mk(1, 20), mk(0, 10)];
        let line = pulse_row_peak(&buckets);
        let rendered: String = line.spans.iter().map(|s| s.content.as_ref()).collect();
        assert!(
            rendered.contains("5h ago"),
            "peak age should be wall-clock: {rendered}"
        );
        assert!(
            rendered.contains("40"),
            "peak value should be the in-window max: {rendered}"
        );
        assert!(
            !rendered.contains("100"),
            "out-of-window spike must be excluded: {rendered}"
        );
    }

    // ── §4.13 Resources row ────────────────────────────────────

    #[test]
    fn rss_colour_green_under_80pct() {
        assert_eq!(rss_colour(10, 100), T.success);
    }

    #[test]
    fn rss_colour_at_80pct_still_green() {
        // 80 / 100 = 0.80 exactly; integer compare `80 * 5 > 100 * 4`
        // is `400 > 400` = false, so this stays green. Crossing into
        // yellow happens strictly above 80 %.
        assert_eq!(rss_colour(80, 100), T.success);
    }

    #[test]
    fn rss_colour_above_80pct_is_yellow() {
        assert_eq!(rss_colour(85, 100), T.warning);
    }

    #[test]
    fn rss_colour_above_warn_is_red() {
        assert_eq!(rss_colour(110, 100), T.error);
    }

    #[test]
    fn rss_colour_zero_warn_is_primary_not_red() {
        // `warn_mb = 0` would otherwise trigger the `rss > warn`
        // branch and paint every sample red; the early return guards
        // against that by falling through to the muted primary colour.
        assert_eq!(rss_colour(10, 0), T.text_primary);
    }

    // ── tui-blind-to-corpus-refusal ────────────────────────────────────

    fn refusal_status(domain_count: usize) -> crate::tui::app::DaemonStatus {
        crate::tui::app::DaemonStatus {
            domain_count,
            lists_active: 8,
            lists_total: 8,
            lists_corpus_refusal: Some(crate::lists::status::CorpusRefusal {
                unique: 14_200_000,
                ceiling: 14_000_000,
                novel_by_source: vec![("privacy-ads".to_string(), 2_100_000)],
            }),
            ..Default::default()
        }
    }

    /// Render the Pulse row through a real buffer rather than reading the
    /// `Line` back.
    ///
    /// The two are not equivalent here: this row grew by roughly twenty
    /// cells under a refusal, and a `Line` assertion is blind to a card
    /// narrow enough to clip the words that carry the alarm.
    fn pulse_row_cells(app: &App, width: u16) -> String {
        use ratatui::backend::TestBackend;
        use ratatui::widgets::Paragraph;
        use ratatui::Terminal;

        let backend = TestBackend::new(width, 1);
        let mut term = Terminal::new(backend).unwrap();
        term.draw(|f| {
            f.render_widget(Paragraph::new(pulse_row_filter_counts(app)), f.area());
        })
        .unwrap();
        let buf = term.backend().buffer();
        (0..buf.area.width)
            .map(|x| buf[(x, 0)].symbol())
            .collect::<String>()
    }

    #[test]
    fn pulse_row_stops_calling_them_lists_under_a_refusal() {
        // The noun is the fix, not the colour: `8/8 lists` asserts eight
        // lists are in the engine, which under a refusal is false. `8/8
        // fetched` is the true statement about the same number.
        let mut app = App::new();
        app.daemon_status = Some(refusal_status(500_000));
        let cells = pulse_row_cells(&app, 120);

        assert!(
            cells.contains("8/8 fetched"),
            "under a refusal the count describes fetching, not serving: {cells:?}"
        );
        assert!(
            !cells.contains("8/8 lists"),
            "`lists` claims they are installed, and they are not: {cells:?}"
        );
        assert!(
            cells.contains("REFUSED"),
            "the row must carry the alarm itself: {cells:?}"
        );
    }

    #[test]
    fn pulse_row_marks_a_zero_corpus_as_unfiltered() {
        let mut app = App::new();
        app.daemon_status = Some(refusal_status(0));
        let cells = pulse_row_cells(&app, 120);
        assert!(
            cells.contains("UNFILTERED"),
            "zero domains under a refusal is not a small corpus, it is none: {cells:?}"
        );
    }

    /// Control arm: one field differs from the tests above.
    #[test]
    fn pulse_row_keeps_the_healthy_wording_without_a_refusal() {
        let mut app = App::new();
        app.daemon_status = Some(crate::tui::app::DaemonStatus {
            domain_count: 500_000,
            lists_active: 8,
            lists_total: 8,
            lists_corpus_refusal: None,
            ..Default::default()
        });
        let cells = pulse_row_cells(&app, 120);
        assert!(cells.contains("8/8 lists"), "{cells:?}");
        assert!(!cells.contains("REFUSED"), "{cells:?}");
        assert!(!cells.contains("UNFILTERED"), "{cells:?}");
    }

    /// Truncation is the weaker sibling: the corpus installed, just short.
    /// It annotates rather than replacing the noun.
    #[test]
    fn pulse_row_flags_truncated_sources_without_claiming_a_refusal() {
        let mut app = App::new();
        app.daemon_status = Some(crate::tui::app::DaemonStatus {
            domain_count: 480_000,
            lists_active: 8,
            lists_total: 8,
            lists_truncated: 3,
            lists_corpus_refusal: None,
            ..Default::default()
        });
        let cells = pulse_row_cells(&app, 120);
        assert!(cells.contains("3 TRUNCATED"), "{cells:?}");
        assert!(
            cells.contains("8/8 lists"),
            "a truncated corpus IS installed — the noun stays: {cells:?}"
        );
        assert!(!cells.contains("REFUSED"), "{cells:?}");
    }

    #[test]
    fn system_ram_cpu_spans_none_render_em_dash() {
        // 2026-05-22 rework: RAM/CPU moved from the Pulse Resources row
        // to their own System-card rows. No snapshot → muted em-dash.
        assert_eq!(system_ram_span(None).content.as_ref(), "\u{2014}");
        assert_eq!(system_cpu_span(None).content.as_ref(), "\u{2014}");
    }

    #[test]
    fn system_ram_cpu_spans_some_render_values() {
        use crate::resource_budget::ResourceBudgetSnapshot;
        let snap = ResourceBudgetSnapshot {
            rss_mb: 42,
            vsz_mb: 280,
            fd_count: 18,
            cpu_user_pct: 3,
            rss_warn_mb: 256,
        };
        // RAM row carries the RSS + FD halves; CPU row the CPU%.
        assert_eq!(
            system_ram_span(Some(&snap)).content.as_ref(),
            "42 MB \u{00b7} 18 FDs"
        );
        assert_eq!(system_cpu_span(Some(&snap)).content.as_ref(), "3%");
    }

    #[test]
    fn pulse_row_filter_counts_none_renders_em_dash() {
        // No daemon_status yet (pre-first-poll) → muted em-dash, mirroring
        // the other Pulse rows' cold-start placeholder.
        let app = App::new();
        assert!(app.daemon_status.is_none());
        let text = line_text(&pulse_row_filter_counts(&app));
        assert!(text.contains("Filter"), "missing label: {text:?}");
        assert!(text.contains('\u{2014}'), "missing em-dash: {text:?}");
    }
}
