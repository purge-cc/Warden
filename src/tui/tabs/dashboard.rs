//! Dashboard tab — the wide-layout KPI/chart/ranked-list view.
//!
//! Owns the KPI/trend/chart cards and the row-4 ranked lists (Top
//! Lists / Top Devices / Top Blocked Domains). Does not own per-tab
//! navigation or polling (`tui/mod.rs`) or the stats aggregation this
//! file only reads from `app.tracking`.
//!
//! Reading order, wide layout:
//!   row 1  KPI strip (System 34 | Block Rate 33 | Cache Hit Rate 33)
//!   row 2  Trend chart 67% + QType chart 33%
//!   row 3  Daily Queries 34% + Daily Blocked 33% + Global Pulse 33%
//!   row 4  Top Lists 33% + Top Devices 33% + Top Blocked Domains 34%
//!
//! Below `WIDE_THRESHOLD` cols the layout falls back to the narrow
//! shape (no row 3 cards; bottom holds Pulse + Top Domains + Top
//! Blocked at 40/30/30). The 7×24 heatmap this row 3 used to hold is
//! gone; its palette tokens (`heat_*`) stay dormant in `theme.rs` in
//! case the heatmap comes back — nothing in this file uses them today.

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
/// the graceful narrow stacked layout instead.
const WIDE_MIN_HEIGHT: u16 = 43;

pub fn render(f: &mut Frame, area: Rect, app: &App) {
    let wide = area.width >= WIDE_THRESHOLD && area.height >= WIDE_MIN_HEIGHT;

    if wide {
        // 4-row layout:
        //   row 1 KPI         Length(11) — 3 panels (System | Block | Cache)
        //   row 2 Trend+QType Length(14) — Trend chart 67 % | QType chart 33 %
        //   row 3 Daily+Pulse Length(11) — Daily Queries 34 / Daily Blocked 33 / Pulse 33
        //   row 4 Bottom      Min(7)     — Top Lists 33 / Devices 33 / Blocked 34
        // Row 2 split mirrors the row-1 KPI percentages: Trend chart
        // sits under System + Block Rate combined (67 %), QType chart
        // under Cache Hit Rate (33 %).
        // KPI strip height: the System card holds 8 rows even with the
        // cluster dot shown, since Poll lives in the Global Pulse card
        // instead — a constant 11 fits both builds (no cluster-
        // conditional grow).
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
        // Narrow fallback: no row 3, bottom row holds Pulse + Top
        // Domains + Top Blocked directly. Heatmap dropped — the 7×24
        // matrix needs ≥53 cols and the Pulse-40 split doesn't leave
        // enough canvas at narrow widths.
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
/// Rate and Block Rate.
///
/// Wide: 8 fields (Status / Listen / Upstream / Cache / Uptime / RAM /
/// CPU / Poll). Narrow/compact: 7 fields (drops Uptime). Status sits up
/// top in both modes because daemon liveness is the most operator-
/// critical signal. RAM/CPU (the daemon's own RSS·FDs / CPU%) lives
/// here so the System card owns host vitals; the Lists/Domains counts
/// live in Pulse instead; the daemon-version row is dropped since the
/// footer already prints it.
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
    // lead and the 9-char label column:
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
    // sees daemon liveness up top. Lives here rather than as a header
    // pill so the header stays pure-branding and runtime signals stay
    // consolidated in this one panel.
    lines.push(kv("Status", status_span(app)));
    lines.push(kv(
        "Listen",
        Span::styled(status.listen.clone(), Style::default().fg(T.text_primary)),
    ));
    // Upstream: render the literal resolver addresses
    // (kind-led, e.g. `plain · 1.1.1.1, 1.0.0.1`) when the daemon reports
    // them; fall back to the legacy `mode (N)` collapse when polling a
    // older daemon (empty `upstream_servers`). Budget = the panel's
    // inner width minus the 10-col `kv` prefix (1 space + 9-char label).
    let upstream_value = if status.upstream_servers.is_empty() {
        format!("{} ({})", status.upstream_mode, status.upstream_count)
    } else {
        let budget = (inner.width as usize).saturating_sub(10);
        format_upstream_value(&status.upstream_servers, budget)
    };
    lines.push(kv(
        "Upstream",
        Span::styled(upstream_value, Style::default().fg(T.success)),
    ));

    // Cache occupancy: prefer the daemon-reported cap when available
    // (`cache_cap > 0`); fall back to the `cache_capacity` heuristic
    // when polling an older daemon that doesn't report one (serde
    // default 0).
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

    // RAM / CPU — the daemon's own process health. Lives on the System
    // card, not Global Pulse, so host vitals stay with the rest of the
    // System card's state. Each renders a muted `—` until the first
    // resource sample arrives (cold start / an older daemon that
    // doesn't report one / non-Linux daemon).
    let snap = status.resource_budget.as_ref();
    lines.push(kv("RAM", system_ram_span(snap)));
    lines.push(kv("CPU", system_cpu_span(snap)));

    // Cluster health dot, shown only when `[cluster].enabled`. The poll
    // itself runs off the Global Pulse card, which frees the row this
    // dot occupies — so the System card fits it at normal height, no
    // extra growth needed.
    #[cfg(feature = "cluster")]
    if app.cluster_visible() {
        lines.push(kv("Cluster", cluster_health_span(app)));
    }

    f.render_widget(Paragraph::new(lines), inner);
}

/// Format the System card's Upstream value from the per-server
/// list, fitting `budget` characters. Kind leads (matches the `·`-separated
/// example `plain · 1.1.1.1, 1.0.0.1`):
///
/// - **single kind** → `"{kind} · addr1, addr2"`; on overflow
///   `"{kind} · addr1 +N"` (N = hidden servers), then char-ellipsis if even
///   one address can't fit.
/// - **mixed kinds** (a fallback with a different mode is the only source) →
///   `"{k1} ×{n1} · {k2} ×{n2}"` so every kind stays visible in the narrow
///   column rather than the 2nd kind clipping off-screen.
///
/// Caller guarantees `servers` is non-empty (empty → legacy rendering).
fn format_upstream_value(
    servers: &[crate::ipc::protocol::UpstreamServerInfo],
    budget: usize,
) -> String {
    // Distinct kinds in first-seen order.
    let mut kinds: Vec<&str> = Vec::new();
    for s in servers {
        if !kinds.contains(&s.kind.as_str()) {
            kinds.push(s.kind.as_str());
        }
    }

    if kinds.len() <= 1 {
        // Single kind → lead with the kind, then the addresses.
        let kind = servers.first().map(|s| s.kind.as_str()).unwrap_or("");
        let prefix = format!("{kind} \u{b7} ");
        let addrs: Vec<&str> = servers.iter().map(|s| s.address.as_str()).collect();
        let full = format!("{prefix}{}", addrs.join(", "));
        if full.chars().count() <= budget {
            return full;
        }
        // Overflow: first address + "+N" (only when there's a remainder to
        // hide — a lone over-long address falls straight through to ellipsis).
        let hidden = addrs.len().saturating_sub(1);
        if hidden > 0 {
            let candidate = format!("{prefix}{} +{hidden}", addrs[0]);
            if candidate.chars().count() <= budget {
                return candidate;
            }
        }
        return truncate_chars(&full, budget);
    }

    // Mixed kinds → per-kind counts so every kind stays visible.
    let segments: Vec<String> = kinds
        .iter()
        .map(|k| {
            let count = servers.iter().filter(|s| s.kind.as_str() == *k).count();
            format!("{k} \u{d7}{count}")
        })
        .collect();
    let full = segments.join(" \u{b7} ");
    if full.chars().count() <= budget {
        full
    } else {
        truncate_chars(&full, budget)
    }
}

/// Char-count truncation with a trailing ellipsis, fitting `max` columns.
/// Mirrors the inline idiom in `render_ranked_card`.
fn truncate_chars(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    if max == 0 {
        return String::new();
    }
    let head: String = s.chars().take(max.saturating_sub(1)).collect();
    format!("{head}\u{2026}")
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

/// System-card cluster dot. Same glyph convention as `status_span`: solid
/// `●` for stable states (healthy/error), hollow `◌` for
/// transient/degraded. Colour: green = converged / all peers online;
/// amber = any peer STALE or local not yet converged; red = the local
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
/// first resource sample lands. Carries the RSS + FD halves; RAM and
/// CPU each read as their own labelled System row rather than sharing
/// one combined line.
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
    // between title and first data row. The trend chart lives below as
    // its own row, leaving room for row 3 (Daily Queries / Daily
    // Blocked / Global Pulse) to sit between them.
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
/// for the trend chart, but a poor fit for "last 1h" KPI gauges, which
/// want a smooth rolling readout. Without pro-rating,
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
/// fill length and loses the "% of full" reference.
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

/// Body for a 4-window fill-good gauge. Title is the first interior
/// row (bold, category-coloured); data rows follow IMMEDIATELY (no
/// blank). Tabular panels are dense — the breathing blank that
/// chart panels use would just be wasted space here.
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

    // Hourly ring holds 168 entries (7d × 24h); the trend chart only
    // plots the most recent 24, via `slice_recent_24h`, so its "Last
    // 24h" label stays accurate. That is an honest wall-clock slice
    // (filter by `timestamp >= now_hour - 23*3600`), not a "last 24
    // entries" tail slice — a tail slice diverges from real wall-clock
    // time once the ring carries restart-fragments.
    let hourly_24: Vec<crate::ipc::protocol::TimeBucketDto> =
        slice_recent_24h(&app.tracking.hourly);
    // Window the daily ring to 7, the same way the hourly branch windows
    // to 24, so `x_max` (derived from `buckets.len()` below) never
    // outruns the 8-tick "-7d … now" label set.
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
/// Hit Rate gauge, continuing that column's grid alignment.
///
/// The QTYPE distribution also renders as a compact 2-line stacked bar
/// inside the Global Pulse card (`pulse_row_types`) in narrow mode;
/// this wide-mode panel exists so composition data (which buckets the
/// daemon serves, in what proportions) reads at a glance instead of
/// fighting for space with operational counters.
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
/// Buckets: the four named QTYPE buckets plus an Other rollup,
/// matching `pulse_row_types` semantics. Bars are scaled to the
/// largest bucket's count so the dominant bucket always reaches full
/// height; the visual is "relative composition," not "absolute
/// traffic."
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
    // 2-char glyph per bar; Total + Blocked sit side-by-side with a
    // 1-col intra-pair gap, so each bucket group spans 2 + 1 + 2 = 5
    // cols of glyph block. Inter-group spacing comes from the centring
    // padding inside `col_w`.
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

    // Reads the 24h rolling window variants, not the cumulative
    // `qtype_distribution` (that one feeds `pulse_row_types` instead):
    // with multi-day uptime, blocks lag queries by 3 orders of
    // magnitude and the Blocked bar would collapse to a 1-row baseline
    // against the lifetime totals.
    let dist = &app.tracking.qtype_distribution_24h;
    let blocked_dist = &app.tracking.qtype_blocked_distribution_24h;
    let total: u64 = dist.iter().sum();
    let total_blocked: u64 = blocked_dist.iter().sum();

    // Per-bucket displayed entries: A / AAAA / HTTPS / TXT / Other.
    // Buckets outside this fixed set fold into Other, matching
    // `pulse_row_types`'s colour-stability.
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
    // by side. A bucket with `blocked == 0` renders the blocked bar as
    // a 1-row muted baseline (level=1) so the slot stays visible even
    // when no blocks landed in it — the same zero-still-gets-a-mark
    // treatment as the daily bar charts' missing-day baseline.
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
/// The 7×24 blocks heatmap that used to occupy this slot is retired:
/// visual signal, but not actionable. The two daily-totals barcharts
/// replace it with a directly-actionable "what does my week look
/// like?" answer.
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
/// (gradients on arbitrary-magnitude charts misread; flat colour
/// scales cleanly).
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

    // Aggregation lives in `aggregate_daily_values` for unit-testability
    // + defensive sum on identical UTC day anchors (belt-and-braces vs
    // `time_series::load()` regressions).
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

    // Row 1 — blank (chart-panel breathing rule).
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

/// Trend chart wall-clock slice, kept as its own function (out of
/// `render_trend_chart`) for unit-testability. Returns the trailing-24
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

/// Same wall-clock windowing as `slice_recent_24h`, mirrored onto the
/// daily ring. `app.tracking.daily` can carry up to
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

/// Daily-bar aggregation helper, kept as its own function (out of
/// `render_daily_bar_card`) for unit-testability. Indexes each bucket
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

fn render_bottom_row(f: &mut Frame, area: Rect, app: &App, wide: bool) {
    if wide {
        // 34/33/33 split — Top Lists (daemon-resolved scope/topic
        // labels) | Top Devices | Top Blocked Domains.
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
        // Narrow fallback: 40/30/30 — Pulse, Top Domains, Top Blocked.
        // Row 3 doesn't render below 120 cols; Pulse needs a home, so
        // it stays on the bottom row in narrow mode.
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
/// Title accent is `T.warning` (amber) — green Top Lists, amber Top
/// Devices, red Top Blocked, a consistent categorical palette across
/// the row 4 trio.
fn render_top_devices_card(f: &mut Frame, area: Rect, app: &App) {
    // Ranks by `blocked_24h` (sum of the per-device 24h hourly_blocked
    // ring) so the title (24h) and the value agree. Devices with no
    // blocks in the last 24h fall off the list; if every device sums
    // to 0 the card renders the `collecting…` placeholder via
    // `render_ranked_card`'s empty branch.
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
/// × `Catalog::entries()`.
///
/// Title accent is `T.scope_security` (green) — green Top Lists, amber
/// Top Devices, red Top Blocked round out the row 4 trio. Empty-state
/// copy is `"collecting…"` to match the sibling Pulse rows' cold-start
/// vocabulary.
fn render_top_lists_card(f: &mut Frame, area: Rect, app: &App) {
    // Reads the 24h-rolling sibling vec; a daemon older than this field
    // emits it empty, so the card falls back to the `collecting…`
    // placeholder until both ends of the wire are upgraded. `count_24h`
    // is the per-list ring's 24h sum from `extract_top_n_u8_hourly`.
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
/// per-row Unicode gradient bar this card once had was retired
/// together with the bottom-row redesign — global signals now
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
    // No `.max(N)` floor here: rank + gaps + count already cost
    // `RANK_W + COUNT_W + 2 * GAP` cells, and a floor under `label_max`
    // that ignores how much is actually left pushes the assembled line
    // past `inner.width` on any card narrower than the floor plus that
    // fixed cost — below ~21 inner columns with the constants as written.
    let label_max = padded_w.saturating_sub(RANK_W + COUNT_W + 2 * GAP);

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
    // Filter corpus size — list + domain counts, lives here rather than
    // the System card, directly above the freshness row so the two
    // list-related signals (how many / how fresh) read together.
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
    // Poll — daemon poll-loop health + cadence, lives here rather than
    // the System card so System fits the cluster dot without growing.
    // Built with `pulse_label` to match the sibling rows' label width.
    lines.push(Line::from(vec![
        pulse_label("Poll"),
        Span::raw(" "),
        poll_status_span(app),
    ]));
    // RAM/CPU/FDs live on the System card, not here — that card owns
    // the daemon's own process health.

    f.render_widget(Paragraph::new(lines), inner);
}

/// 100 %-stacked QTYPE bar + compact legend.
///
/// Returns 2 lines on warm state (bar + legend) or 1 line on cold
/// start (`total == 0` → muted `collecting…` placeholder). The caller
/// `extends` the returned vec into its line list so the caller's
/// height accounting stays uniform.
///
/// Active branch:
/// - Rank buckets by count desc, take top 4.
/// - Filter top-4 to the named set `{A, AAAA, HTTPS, TXT}`. Buckets
///   outside the named set fold into the `Other` rollup along with
///   everything below top-4 — keeps the bar's colour palette stable
///   across polls regardless of which rare bucket happens to spike.
/// - Sub-1 % buckets that round to 0 cells fold into Other too.
/// - Bar cells are `█`, coloured by bucket (A=chart_2 / AAAA=chart_3 /
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

    // Pick the top-4 named buckets; everything else folds into Other.
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

/// Colour map for QTYPE buckets. Other buckets fold into the `Other`
/// rollup (see `pulse_row_types`); they never reach this function.
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

/// Prefetch worker activity row. Renders the current
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

/// Pure threshold mapping for the System card's RAM row. Integer ratio
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
    // Windows by *wall-clock* via the same `slice_recent_24h` the
    // trend chart uses, not "last 24 entries". Once the hourly ring
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
/// the engine. Reads the daemon `Status` snapshot. List count renders
/// `active/total` when the daemon reports the registry counters
/// (`lists_total > 0`), else falls back to the legacy `list_count`
/// scalar for an older daemon that doesn't report them. Muted `—`
/// before the first poll lands.
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

    // Labelled "Fresh" (not "Lists") — the separate "Filter" row above
    // carries the list/domain *counts*; this row owns the
    // freshness/health facet.
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
        // Success-only, matching what `is_stale_for_dto` reads for the
        // Lists tab's own Stale badge: `fetched_at` also advances on a
        // failed retry, which would let a list that keeps failing
        // masquerade here as freshly updated.
        if let Some(ts_str) = &entry.last_refresh_at {
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
#[path = "../tests/dashboard.rs"]
mod tests;
