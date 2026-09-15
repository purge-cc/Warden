//! Timestamp-aware charts used by the Dashboard.
//!
//! The renderers deliberately build fixed calendar grids before drawing.  A
//! resize can therefore change label density and plot height, but never which
//! hours/days are represented.  Presence is tracked separately from value so
//! an absent bucket is not silently turned into a zero.

use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::symbols::Marker;
use ratatui::text::{Line, Span};
use ratatui::widgets::canvas::{Canvas, Line as CanvasLine, Points};
use ratatui::widgets::{Gauge, Paragraph, Widget};

use crate::ipc::protocol::TimeBucketDto;
use crate::tracking::query_type::TypeBucket;
use crate::tracking::time_series::hour_in_24h_window;
use crate::tui::app::App;
use crate::tui::format;
use crate::tui::text::{fit, fit_tail, pad, width};
use crate::tui::theme::{self, T};

const HOURS: usize = 24;
const DAYS: usize = 10;
const HOUR_SECS: u64 = 3_600;
const DAY_SECS: u64 = 86_400;
const BLOCK_WINDOWS: [(&str, usize); 4] = [("1h", 1), ("3h", 3), ("12h", 12), ("24h", 24)];

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct TrafficBucket {
    queries: u64,
    blocked: u64,
    present: bool,
}

/// Render total and blocked query volumes for the current UTC hour and the
/// preceding 23 hourly buckets. `anchor` is the shared Dashboard snapshot
/// reference; it is intentionally not read from the wall clock here.
pub(super) fn render_traffic(
    buf: &mut Buffer,
    area: Rect,
    app: &App,
    anchor: u64,
    _selected: Option<u64>,
) {
    let buckets = aggregate_hours(&app.tracking.hourly, anchor);
    let total_queries = buckets
        .iter()
        .filter(|bucket| bucket.present)
        .fold(0u64, |total, bucket| total.saturating_add(bucket.queries));
    let total_blocked = buckets
        .iter()
        .filter(|bucket| bucket.present)
        .fold(0u64, |total, bucket| total.saturating_add(bucket.blocked));
    let inner = theme::filled_card_with_subtitle(
        buf,
        area,
        "DNS TRAFFIC",
        traffic_subtitle(area, total_queries, total_blocked),
        theme::CardRole::Analytics,
    );
    if inner.is_empty() {
        return;
    }
    let body = inset_x(inner, 1);
    if body.is_empty() {
        return;
    }

    let anchor_hour = truncate(anchor, HOUR_SECS);
    if body.height < 4 {
        return;
    }

    let label_y = body.bottom() - 1;
    let plot_top = body.y;
    let plot_height = label_y.saturating_sub(plot_top);
    if plot_height == 0 {
        return;
    }

    let max_value = buckets
        .iter()
        .filter(|bucket| bucket.present)
        .map(|bucket| bucket.queries.max(bucket.blocked))
        .max()
        .unwrap_or(0);
    let scale = nice_ceiling(max_value.max(1));
    let axis_samples = [scale, scale / 2, 0];
    let axis_width = axis_samples
        .iter()
        .map(|value| width(&format::count(*value)))
        .max()
        .unwrap_or(1)
        .min(7);
    let plot_x = body.x.saturating_add(axis_width as u16 + 1);
    let plot_width = body.right().saturating_sub(plot_x);
    if plot_width == 0 {
        return;
    }
    let plot = Rect::new(plot_x, plot_top, plot_width, plot_height);

    draw_numeric_axis(buf, body.x, axis_width, plot, scale, max_value > 0);

    if !buckets.iter().any(|bucket| bucket.present) {
        let message = fit("No hourly data yet · × = missing", plot.width as usize);
        let y = plot.y + plot.height / 2;
        render_at(
            buf,
            Rect::new(plot.x, y, plot.width, 1),
            &message,
            T.text_muted,
        );
    }

    draw_traffic_series(buf, plot, &buckets, scale);

    // Missing hours get an explicit baseline mark. Present zeroes instead get
    // the coloured series point at y=0, so the two states remain distinct.
    for (index, bucket) in buckets.iter().enumerate() {
        if !bucket.present {
            put_cell(
                buf,
                hour_x(plot, index),
                plot.bottom() - 1,
                '×',
                T.text_disabled,
                false,
            );
        }
    }

    let selected_index = None;
    draw_hour_labels(
        buf,
        Rect::new(plot.x, label_y, plot.width, 1),
        anchor_hour,
        selected_index,
    );
}

fn traffic_subtitle(area: Rect, queries: u64, blocked: u64) -> Line<'static> {
    theme::card_subtitle_with_legend(
        area,
        &format!(
            "24H Queries · Total {} · Blocked {}",
            format::count(queries),
            format::count(blocked)
        ),
        Line::from(vec![
            Span::styled("⠿ Total", Style::default().fg(T.chart_2)),
            Span::raw("  "),
            Span::styled("⠿ Blocked", Style::default().fg(T.brand_red)),
        ]),
    )
}

/// Render the honest 24-hour query-type composition. Every percentage and
/// every bar uses total queries as its denominator; blocked-per-type data is
/// intentionally absent from this panel because it is a different metric.
pub(super) fn render_qtypes(buf: &mut Buffer, area: Rect, app: &App) {
    let inner = theme::filled_card(
        buf,
        area,
        "QUERY TYPES",
        "% of 24H Queries",
        theme::CardRole::Analytics,
    );
    if inner.is_empty() {
        return;
    }
    let body = inset_x(inner, 1);
    if body.is_empty() {
        return;
    }

    if body.height < 1 {
        return;
    }

    let counts = app.tracking.qtype_distribution_24h;
    let total: u128 = counts.iter().map(|value| u128::from(*value)).sum();
    if total == 0 && app.tracking.hourly.is_empty() {
        render_at(
            buf,
            Rect::new(body.x, body.y, body.width, body.height),
            &fit("Query-type data not available yet", body.width as usize),
            T.text_muted,
        );
        return;
    }
    if total == 0 && app.tracking.hourly.iter().any(|bucket| bucket.queries > 0) {
        render_at(
            buf,
            Rect::new(body.x, body.y, body.width, body.height),
            &fit(
                "Query-type data unavailable for this traffic",
                body.width as usize,
            ),
            T.text_muted,
        );
        return;
    }

    let entries = qtype_entries(&counts);
    let layout = qtype_layout(body.width as usize, &entries);
    let available_entries = (body.height / 2) as usize;
    for (row, entry) in entries.iter().enumerate().take(available_entries) {
        render_qtype_row(
            buf,
            Rect::new(body.x, body.y + row as u16 * 2, body.width, 2),
            *entry,
            total,
            layout,
        );
    }
}

/// Render rolling block rates estimated from fixed UTC hourly buckets. The
/// oldest overlapping bucket is weighted by its overlap with the window;
/// the current bucket contributes the observations collected so far.
pub(super) fn render_block_rate(buf: &mut Buffer, area: Rect, app: &App, anchor: u64) {
    let inner = theme::filled_card(
        buf,
        area,
        "BLOCK RATE",
        "Hourly Estimates",
        theme::CardRole::Summary,
    );
    if inner.is_empty() {
        return;
    }
    let body = inset_x(inner, 1);
    if body.is_empty() {
        return;
    }

    if body.height < 1 {
        return;
    }
    let windows = block_windows(&app.tracking.hourly, anchor);
    let ratio_width = windows
        .iter()
        .map(block_ratio_text)
        .map(|value| width(&value))
        .max()
        .unwrap_or(3);
    for (index, window) in windows.iter().enumerate() {
        let header_row = index as u16 * 2;
        if header_row >= body.height {
            break;
        }
        render_line(
            buf,
            body,
            header_row,
            block_window_header(window, ratio_width, body.width as usize),
        );
        if header_row + 1 < body.height {
            let bar = Rect::new(body.x, body.y + header_row + 1, body.width, 1);
            if window.present_buckets == 0 {
                render_line(
                    buf,
                    bar,
                    0,
                    Line::styled(
                        "·".repeat(bar.width as usize),
                        Style::default().fg(T.text_disabled),
                    ),
                );
            } else {
                let ratio = if window.queries == 0 {
                    0.0
                } else {
                    window.blocked as f64 / window.queries as f64
                };
                percentage_bar(buf, bar, ratio, T.brand_red);
            }
        }
    }
    if body.height > 9 {
        render_at(
            buf,
            Rect::new(body.x, body.y + 9, body.width, 1),
            &fit("Blocked / total · partial = gaps", body.width as usize),
            T.text_disabled,
        );
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct BlockWindow {
    label: &'static str,
    blocked: u64,
    queries: u64,
    present_buckets: usize,
    expected_buckets: usize,
}

fn block_windows(buckets: &[TimeBucketDto], anchor: u64) -> [BlockWindow; 4] {
    std::array::from_fn(|index| {
        let (label, hours) = BLOCK_WINDOWS[index];
        rolling_block_window(buckets, anchor, label, hours)
    })
}

fn rolling_block_window(
    buckets: &[TimeBucketDto],
    anchor: u64,
    label: &'static str,
    hours: usize,
) -> BlockWindow {
    const MAX_ROLLING_BUCKETS: usize = HOURS + 1;
    let window_secs = hours as u64 * HOUR_SECS;
    let window_start = anchor.saturating_sub(window_secs);
    let oldest_hour = truncate(window_start, HOUR_SECS);
    let anchor_hour = truncate(anchor, HOUR_SECS);
    let mut slots = [TrafficBucket::default(); MAX_ROLLING_BUCKETS];

    for bucket in buckets {
        let timestamp = truncate(bucket.timestamp, HOUR_SECS);
        if timestamp < oldest_hour || timestamp > anchor_hour {
            continue;
        }
        let index = ((timestamp - oldest_hour) / HOUR_SECS) as usize;
        if let Some(slot) = slots.get_mut(index) {
            slot.queries = slot.queries.saturating_add(bucket.queries);
            slot.blocked = slot.blocked.saturating_add(bucket.blocked);
            slot.present = true;
        }
    }

    let mut blocked = 0.0f64;
    let mut queries = 0.0f64;
    let mut present_buckets = 0usize;
    let mut expected_buckets = 0usize;
    for (index, bucket) in slots.iter().enumerate() {
        let bucket_start = oldest_hour.saturating_add(index as u64 * HOUR_SECS);
        if bucket_start > anchor_hour {
            break;
        }
        let bucket_end = bucket_start.saturating_add(HOUR_SECS);
        let overlap_start = bucket_start.max(window_start);
        let overlap_end = bucket_end.min(anchor);
        if overlap_end <= overlap_start {
            continue;
        }
        expected_buckets += 1;
        if !bucket.present {
            continue;
        }
        present_buckets += 1;
        let weight = if bucket_start < window_start {
            (bucket_end.saturating_sub(window_start)) as f64 / HOUR_SECS as f64
        } else {
            1.0
        };
        blocked += bucket.blocked as f64 * weight;
        queries += bucket.queries as f64 * weight;
    }

    BlockWindow {
        label,
        blocked: blocked.round() as u64,
        queries: queries.round() as u64,
        present_buckets,
        expected_buckets,
    }
}

fn block_ratio_text(window: &BlockWindow) -> String {
    if window.present_buckets == 0 {
        "—/—".to_owned()
    } else {
        format!(
            "{}/{}",
            format::count(window.blocked),
            format::count(window.queries)
        )
    }
}

fn block_window_header(window: &BlockWindow, ratio_width: usize, cells: usize) -> Line<'static> {
    let percentage = if window.present_buckets == 0 || window.queries == 0 {
        "     —".to_owned()
    } else {
        format!(
            "{:>5.1}%",
            window.blocked as f64 * 100.0 / window.queries as f64
        )
    };
    let ratio = pad(&block_ratio_text(window), ratio_width);
    let coverage = if window.present_buckets == 0 {
        "no data"
    } else if window.present_buckets < window.expected_buckets {
        "partial"
    } else {
        ""
    };
    let fixed_width = 3 + 1 + 6 + 2 + ratio_width + width(coverage);
    let spacer = " ".repeat(cells.saturating_sub(fixed_width).max(1));
    Line::from(vec![
        Span::styled(pad(window.label, 3), Style::default().fg(T.text_secondary)),
        Span::raw(" "),
        Span::styled(
            percentage,
            Style::default()
                .fg(if window.present_buckets == 0 {
                    T.text_disabled
                } else {
                    T.text_primary
                })
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("  "),
        Span::styled(
            ratio,
            Style::default().fg(if window.present_buckets == 0 {
                T.text_disabled
            } else {
                T.text_secondary
            }),
        ),
        Span::raw(spacer),
        Span::styled(coverage, Style::default().fg(T.warning)),
    ])
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

/// Render one of the two distinct ten-calendar-day panels. Both panels use
/// the same timestamp aggregation, while retaining their
/// own explicitly labelled numeric scale.
pub(super) fn render_daily(
    buf: &mut Buffer,
    area: Rect,
    app: &App,
    anchor: u64,
    _selected: Option<u64>,
    blocked: bool,
) {
    let color = if blocked { T.brand_red } else { T.chart_2 };
    let anchor_day = truncate(anchor, DAY_SECS);
    let days = aggregate_days(&app.tracking.daily, anchor_day);
    let total = days
        .iter()
        .filter(|day| day.present)
        .fold(0u64, |sum, day| {
            sum.saturating_add(if blocked { day.blocked } else { day.queries })
        });
    let inner = theme::filled_card_with_subtitle(
        buf,
        area,
        if blocked {
            "DAILY BLOCKED"
        } else {
            "DAILY QUERIES"
        },
        daily_subtitle(area, total, blocked),
        theme::CardRole::History,
    );
    if inner.is_empty() {
        return;
    }
    let body = inset_x(inner, 1);
    if body.is_empty() {
        return;
    }
    if body.height < 4 {
        return;
    }

    let two_label_rows = body.height >= 8;
    let label_rows = if two_label_rows { 2 } else { 1 };
    let chart_top = body.y;
    let chart_bottom = body.bottom().saturating_sub(label_rows);
    let chart_height = chart_bottom.saturating_sub(chart_top);
    if chart_height == 0 {
        return;
    }

    let values: [u64; DAYS] = std::array::from_fn(|index| {
        if blocked {
            days[index].blocked
        } else {
            days[index].queries
        }
    });
    let max_value = days
        .iter()
        .zip(values)
        .filter(|(day, _)| day.present)
        .map(|(_, value)| value)
        .max()
        .unwrap_or(0);
    let scale = nice_ceiling(max_value.max(1));
    let axis_width = width(&format::count(scale)).clamp(1, 7);
    let bars_x = body.x.saturating_add(axis_width as u16 + 1);
    let bars_width = body.right().saturating_sub(bars_x);
    if bars_width == 0 {
        return;
    }
    let chart = Rect::new(bars_x, chart_top, bars_width, chart_height);
    draw_numeric_axis(buf, body.x, axis_width, chart, scale, max_value > 0);

    let selected_index = None;
    let points: Vec<(f64, f64)> = days
        .iter()
        .enumerate()
        .filter(|(_, day)| day.present)
        .map(|(i, _)| (i as f64, values[i] as f64))
        .collect();
    Canvas::default()
        .background_color(T.bg_elevated)
        .marker(Marker::Braille)
        .x_bounds([0.0, (DAYS - 1) as f64])
        .y_bounds([0.0, scale.max(1) as f64])
        .paint(|context| {
            for (i, pair) in days.windows(2).enumerate() {
                if pair[0].present && pair[1].present {
                    context.draw(&CanvasLine::new(
                        i as f64,
                        values[i] as f64,
                        (i + 1) as f64,
                        values[i + 1] as f64,
                        color,
                    ));
                }
            }
            context.draw(&Points {
                coords: &points,
                color,
            });
        })
        .render(chart, buf);
    for (i, day) in days.iter().enumerate() {
        let x =
            chart.x + (i as u32 * chart.width.saturating_sub(1) as u32 / (DAYS - 1) as u32) as u16;
        if !day.present {
            put_cell(buf, x, chart.bottom() - 1, '·', T.text_disabled, false);
        } else if values[i] == 0 {
            put_cell(buf, x, chart.bottom() - 1, '▁', color, false);
        }
    }
    draw_day_labels(
        buf,
        Rect::new(bars_x, chart_bottom, bars_width, label_rows),
        anchor_day,
        selected_index,
    );
}

fn daily_subtitle(area: Rect, total: u64, blocked: bool) -> Line<'static> {
    let cells = theme::card_subtitle_area(area).width as usize;
    let metric = if blocked { "Blocked" } else { "Queries" };
    let full = format!(
        "{} Total Rolling {metric} (Daily History)",
        format::count(total)
    );
    let compact = format!("{} Rolling {metric}", format::count(total));
    Line::raw(if width(&full) <= cells {
        full
    } else {
        fit(&compact, cells)
    })
}

fn inset_x(area: Rect, amount: u16) -> Rect {
    Rect::new(
        area.x.saturating_add(amount),
        area.y,
        area.width.saturating_sub(amount.saturating_mul(2)),
        area.height,
    )
}

fn render_line(buf: &mut Buffer, area: Rect, row: u16, line: Line<'static>) {
    if row < area.height {
        Paragraph::new(line).render(Rect::new(area.x, area.y + row, area.width, 1), buf);
    }
}

fn render_at(buf: &mut Buffer, area: Rect, value: &str, color: Color) {
    Paragraph::new(Line::styled(value.to_owned(), Style::default().fg(color))).render(area, buf);
}

fn put_cell(buf: &mut Buffer, x: u16, y: u16, symbol: char, color: Color, bold: bool) {
    if let Some(cell) = buf.cell_mut((x, y)) {
        cell.set_char(symbol).set_fg(color);
        if bold {
            cell.set_style(Style::default().add_modifier(Modifier::BOLD));
        }
    }
}

fn truncate(timestamp: u64, period: u64) -> u64 {
    timestamp / period * period
}

fn aggregate_hours(buckets: &[TimeBucketDto], anchor: u64) -> [TrafficBucket; HOURS] {
    let newest = truncate(anchor, HOUR_SECS);
    let mut result = [TrafficBucket::default(); HOURS];
    for bucket in buckets {
        let timestamp = truncate(bucket.timestamp, HOUR_SECS);
        // Keep the renderer on the exact same bucket-boundary contract as
        // daemon-side rates and query-type aggregation.
        if !hour_in_24h_window(timestamp, anchor) {
            continue;
        }
        let hours_ago = ((newest - timestamp) / HOUR_SECS) as usize;
        let index = HOURS - 1 - hours_ago;
        result[index].queries = result[index].queries.saturating_add(bucket.queries);
        result[index].blocked = result[index].blocked.saturating_add(bucket.blocked);
        result[index].present = true;
    }
    result
}

fn aggregate_days(buckets: &[TimeBucketDto], anchor_day: u64) -> [TrafficBucket; DAYS] {
    let newest = truncate(anchor_day, DAY_SECS);
    let mut result = [TrafficBucket::default(); DAYS];
    for bucket in buckets {
        let timestamp = truncate(bucket.timestamp, DAY_SECS);
        let Some(elapsed) = newest.checked_sub(timestamp) else {
            continue;
        };
        let days_ago = (elapsed / DAY_SECS) as usize;
        if days_ago >= DAYS {
            continue;
        }
        let index = DAYS - 1 - days_ago;
        result[index].queries = result[index].queries.saturating_add(bucket.queries);
        result[index].blocked = result[index].blocked.saturating_add(bucket.blocked);
        result[index].present = true;
    }
    result
}

fn nice_ceiling(value: u64) -> u64 {
    if value <= 1 {
        return value.max(1);
    }
    let mut magnitude = 1u64;
    while value / magnitude >= 10 {
        let next = magnitude.saturating_mul(10);
        if next == magnitude {
            break;
        }
        magnitude = next;
    }
    let leading = value.saturating_add(magnitude - 1) / magnitude;
    let nice_leading: u64 = match leading {
        0 | 1 => 1,
        2 => 2,
        3..=5 => 5,
        _ => 10,
    };
    nice_leading.saturating_mul(magnitude).max(value)
}

fn draw_numeric_axis(
    buf: &mut Buffer,
    axis_x: u16,
    axis_width: usize,
    plot: Rect,
    scale: u64,
    populated: bool,
) {
    if plot.height == 0 {
        return;
    }
    let samples = if populated {
        [
            (0, scale),
            (plot.height / 2, scale / 2),
            (plot.height - 1, 0),
        ]
    } else {
        [(0, 0), (plot.height / 2, 0), (plot.height - 1, 0)]
    };
    for (offset, value) in samples {
        if (!populated || scale < 2) && offset == plot.height / 2 && offset != plot.height - 1 {
            continue;
        }
        if !populated && offset != plot.height - 1 {
            continue;
        }
        let raw = format::count(value);
        let label = pad(&fit_tail(&raw, axis_width), axis_width);
        render_at(
            buf,
            Rect::new(axis_x, plot.y + offset, axis_width as u16, 1),
            &label,
            T.axis_label,
        );
        for x in plot.x..plot.right() {
            if buf
                .cell((x, plot.y + offset))
                .is_some_and(|cell| cell.symbol() == " ")
            {
                put_cell(buf, x, plot.y + offset, '·', T.grid_line, false);
            }
        }
    }
}

fn draw_traffic_series(buf: &mut Buffer, plot: Rect, buckets: &[TrafficBucket; HOURS], scale: u64) {
    let queries: Vec<(f64, f64)> = buckets
        .iter()
        .enumerate()
        .filter(|(_, bucket)| bucket.present)
        .map(|(index, bucket)| (index as f64, bucket.queries as f64))
        .collect();
    let blocked: Vec<(f64, f64)> = buckets
        .iter()
        .enumerate()
        .filter(|(_, bucket)| bucket.present)
        .map(|(index, bucket)| (index as f64, bucket.blocked as f64))
        .collect();
    let query_segments: Vec<CanvasLine> = buckets
        .windows(2)
        .enumerate()
        .filter(|(_, pair)| pair[0].present && pair[1].present)
        .map(|(index, pair)| {
            CanvasLine::new(
                index as f64,
                pair[0].queries as f64,
                (index + 1) as f64,
                pair[1].queries as f64,
                T.chart_2,
            )
        })
        .collect();
    let blocked_segments: Vec<CanvasLine> = buckets
        .windows(2)
        .enumerate()
        .filter(|(_, pair)| pair[0].present && pair[1].present)
        .map(|(index, pair)| {
            CanvasLine::new(
                index as f64,
                pair[0].blocked as f64,
                (index + 1) as f64,
                pair[1].blocked as f64,
                T.brand_red,
            )
        })
        .collect();

    Canvas::default()
        .background_color(T.bg_elevated)
        .marker(Marker::Braille)
        .x_bounds([0.0, (HOURS - 1) as f64])
        .y_bounds([0.0, scale.max(1) as f64])
        .paint(|context| {
            for segment in &query_segments {
                context.draw(segment);
            }
            context.draw(&Points {
                coords: &queries,
                color: T.chart_2,
            });
            for segment in &blocked_segments {
                context.draw(segment);
            }
            context.draw(&Points {
                coords: &blocked,
                color: T.brand_red,
            });
        })
        .render(plot, buf);
}

fn hour_x(plot: Rect, index: usize) -> u16 {
    if plot.width <= 1 {
        return plot.x;
    }
    plot.x + ((index as u32 * (plot.width - 1) as u32 + 11) / 23) as u16
}

fn draw_hour_labels(buf: &mut Buffer, area: Rect, anchor_hour: u64, selected: Option<usize>) {
    let indices: &[usize] = if area.width >= 48 {
        &[0, 6, 12, 18, 23]
    } else if area.width >= 28 {
        &[0, 8, 16, 23]
    } else {
        &[0, 12, 23]
    };
    let oldest = anchor_hour.saturating_sub(23 * HOUR_SECS);
    for &index in indices {
        let label = fmt_hour(oldest.saturating_add(index as u64 * HOUR_SECS));
        let center = hour_x(area, index);
        let x = center
            .saturating_sub((width(&label) / 2) as u16)
            .min(area.right().saturating_sub(width(&label) as u16))
            .max(area.x);
        let max_width = area.right().saturating_sub(x);
        render_at(
            buf,
            Rect::new(x, area.y, max_width, 1),
            &fit(&label, max_width as usize),
            if selected == Some(index) {
                T.emerald_ping
            } else {
                T.axis_label
            },
        );
    }
}

#[derive(Clone, Copy)]
struct QtypeEntry {
    label: &'static str,
    count: u128,
    color: Color,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct QtypeLayout {
    label_width: usize,
    percent_width: usize,
}

fn qtype_entries(counts: &[u64; crate::tracking::TYPE_BUCKET_COUNT]) -> [QtypeEntry; 5] {
    let mut indices: Vec<usize> = (0..TypeBucket::ALL.len() - 1).collect();
    indices.sort_by(|a, b| counts[*b].cmp(&counts[*a]).then(a.cmp(b)));
    let total: u128 = counts.iter().map(|count| u128::from(*count)).sum();
    let first: u128 = indices[..4].iter().map(|i| u128::from(counts[*i])).sum();
    std::array::from_fn(|index| QtypeEntry {
        label: if index == 4 {
            "Other"
        } else {
            TypeBucket::ALL[indices[index]].name()
        },
        count: if index == 4 {
            total - first
        } else {
            u128::from(counts[indices[index]])
        },
        color: T.info,
    })
}

fn qtype_layout(cells: usize, _entries: &[QtypeEntry]) -> QtypeLayout {
    QtypeLayout {
        label_width: 6.min(cells.saturating_sub(7)),
        percent_width: 6,
    }
}

fn render_qtype_row(
    buf: &mut Buffer,
    area: Rect,
    entry: QtypeEntry,
    total: u128,
    layout: QtypeLayout,
) {
    if area.width == 0 || area.height == 0 {
        return;
    }
    let percentage = if total == 0 {
        0.0
    } else {
        entry.count as f64 * 100.0 / total as f64
    };
    let percent = pad(&format!("{percentage:>5.1}%"), layout.percent_width);
    let mut spans = vec![
        Span::styled(
            pad(entry.label, layout.label_width),
            Style::default().fg(T.text_secondary),
        ),
        Span::raw(" "),
    ];
    spans.push(Span::styled(percent, Style::default().fg(entry.color)));
    render_line(buf, area, 0, Line::from(spans));
    if area.height > 1 {
        percentage_bar(
            buf,
            Rect::new(area.x, area.y + 1, area.width, 1),
            percentage / 100.0,
            entry.color,
        );
    }
}

fn day_slot(area: Rect, index: usize) -> (u16, u16) {
    let start = area.x + (index as u32 * area.width as u32 / DAYS as u32) as u16;
    let end = area.x + ((index as u32 + 1) * area.width as u32 / DAYS as u32) as u16;
    (start, end.saturating_sub(start))
}

fn draw_day_labels(buf: &mut Buffer, area: Rect, anchor_day: u64, selected: Option<usize>) {
    let oldest = anchor_day.saturating_sub((DAYS as u64 - 1) * DAY_SECS);
    for index in 0..DAYS {
        let (start, slot_width) = day_slot(area, index);
        if slot_width == 0 {
            continue;
        }
        let timestamp = oldest.saturating_add(index as u64 * DAY_SECS);
        let (weekday, day) = date_labels(timestamp);
        let active = selected == Some(index);
        let color = if active {
            T.emerald_ping
        } else if index + 1 == DAYS {
            T.text_primary
        } else {
            T.axis_label
        };
        let weekday = if slot_width >= 2 {
            weekday.to_owned()
        } else {
            weekday.chars().next().unwrap_or(' ').to_string()
        };
        let weekday = fit(&weekday, slot_width as usize);
        let weekday_x = start + slot_width.saturating_sub(width(&weekday) as u16) / 2;
        render_at(
            buf,
            Rect::new(
                weekday_x,
                area.y,
                start.saturating_add(slot_width).saturating_sub(weekday_x),
                1,
            ),
            &weekday,
            color,
        );
        if area.height >= 2 {
            let day = fit(&day, slot_width as usize);
            let day_x = start + slot_width.saturating_sub(width(&day) as u16) / 2;
            render_at(
                buf,
                Rect::new(
                    day_x,
                    area.y + 1,
                    start.saturating_add(slot_width).saturating_sub(day_x),
                    1,
                ),
                &day,
                color,
            );
        }
    }
}

fn fmt_hour(timestamp: u64) -> String {
    time::OffsetDateTime::from_unix_timestamp(timestamp as i64)
        .map(|date| format!("{:02}:00", date.hour()))
        .unwrap_or_else(|_| "--:--".to_owned())
}

fn date_labels(timestamp: u64) -> (&'static str, String) {
    time::OffsetDateTime::from_unix_timestamp(timestamp as i64)
        .map(|date| (weekday_abbrev(date.weekday()), format!("{:02}", date.day())))
        .unwrap_or(("--", "--".to_owned()))
}

fn weekday_abbrev(weekday: time::Weekday) -> &'static str {
    use time::Weekday::*;
    match weekday {
        Monday => "Mo",
        Tuesday => "Tu",
        Wednesday => "We",
        Thursday => "Th",
        Friday => "Fr",
        Saturday => "Sa",
        Sunday => "Su",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bucket(timestamp: u64, queries: u64, blocked: u64) -> TimeBucketDto {
        TimeBucketDto {
            timestamp,
            queries,
            blocked,
            cache_hits: 0,
        }
    }

    fn dump(buf: &Buffer) -> String {
        let mut result = String::new();
        for y in buf.area.y..buf.area.bottom() {
            for x in buf.area.x..buf.area.right() {
                result.push_str(buf[(x, y)].symbol());
            }
            result.push('\n');
        }
        result
    }

    #[test]
    fn hourly_grid_sums_duplicates_and_preserves_missing_and_zero() {
        let anchor = 30 * HOUR_SECS + 1_234;
        let oldest = 7 * HOUR_SECS;
        let buckets = [
            bucket(oldest + 17, 4, 1),
            bucket(oldest + 3_599, 6, 2),
            bucket(oldest + HOUR_SECS, 0, 0),
            bucket(oldest - 1, 99, 99),
            bucket(31 * HOUR_SECS, 99, 99),
        ];

        let result = aggregate_hours(&buckets, anchor);
        assert_eq!(
            result[0],
            TrafficBucket {
                queries: 10,
                blocked: 3,
                present: true
            }
        );
        assert_eq!(
            result[1],
            TrafficBucket {
                queries: 0,
                blocked: 0,
                present: true
            }
        );
        assert!(!result[2].present);
        assert_eq!(result.iter().filter(|item| item.present).count(), 2);
    }

    #[test]
    fn daily_grid_is_ten_utc_dates_and_saturates_duplicate_sums() {
        let today = 20 * DAY_SECS;
        let oldest = 11 * DAY_SECS;
        let buckets = [
            bucket(oldest + 1, u64::MAX, 2),
            bucket(oldest + 4_000, 5, 3),
            bucket(today, 0, 0),
            bucket(oldest - 1, 10, 10),
        ];
        let result = aggregate_days(&buckets, today + 42);

        assert_eq!(result[0].queries, u64::MAX);
        assert_eq!(result[0].blocked, 5);
        assert!(result[0].present);
        assert!(result[9].present, "a real zero bucket remains present");
        assert!(!result[8].present, "an absent day remains missing");
    }

    #[test]
    fn qtype_percentages_reach_a_real_hundred_percent() {
        let mut buf = Buffer::empty(Rect::new(0, 0, 34, 1));
        let area = buf.area;
        render_qtype_row(
            &mut buf,
            area,
            QtypeEntry {
                label: "HTTPS",
                count: 7,
                color: T.chart_4,
            },
            7,
            qtype_layout(
                34,
                &[QtypeEntry {
                    label: "HTTPS",
                    count: 7,
                    color: T.chart_4,
                }],
            ),
        );
        let rendered = dump(&buf);
        assert!(
            rendered.contains("100.0%"),
            "percentage was capped: {rendered}"
        );
        assert!(
            !rendered.contains('/'),
            "query and blocked denominators were mixed"
        );
    }

    #[test]
    fn traffic_render_marks_a_gap_instead_of_connecting_it() {
        let anchor = 100 * HOUR_SECS;
        let mut app = App::new();
        app.tracking.hourly = vec![bucket(anchor - 2 * HOUR_SECS, 10, 1), bucket(anchor, 20, 2)];
        let area = Rect::new(0, 0, 90, 12);
        let mut buf = Buffer::empty(area);
        render_traffic(&mut buf, area, &app, anchor, Some(anchor));
        let rendered = dump(&buf);

        assert!(rendered.contains("DNS TRAFFIC"));
        assert!(
            rendered.contains('×'),
            "missing hour has no explicit marker: {rendered}"
        );
        assert!(!rendered.contains("partial"));
    }

    #[test]
    fn narrow_traffic_keeps_both_legend_labels_and_four_plot_rows() {
        let anchor = 100 * HOUR_SECS;
        let mut app = App::new();
        app.tracking.hourly = vec![bucket(anchor, 20, 2)];
        let area = Rect::new(0, 0, 40, 14);
        let mut buf = Buffer::empty(area);
        render_traffic(&mut buf, area, &app, anchor, None);
        let rendered = dump(&buf);
        assert!(
            rendered.contains("Total"),
            "total legend disappeared: {rendered}"
        );
        assert!(
            rendered.contains("Blocked"),
            "blocked legend disappeared: {rendered}"
        );
        let subtitle = (buf.area.x..buf.area.right())
            .map(|x| buf[(x, 2)].symbol())
            .collect::<String>();
        assert!(
            subtitle.trim_end().ends_with("⠿ Total  ⠿ Blocked"),
            "legend must stay right-aligned in the subtitle band: {subtitle}"
        );

        assert!(!rendered.contains("partial"));
    }

    #[test]
    fn daily_render_distinguishes_missing_from_recorded_zero_at_small_height() {
        let anchor = 20 * DAY_SECS;
        let mut app = App::new();
        app.tracking.daily = vec![bucket(anchor - DAY_SECS, 0, 0), bucket(anchor, 8, 3)];
        let area = Rect::new(0, 0, 76, 8);
        let mut buf = Buffer::empty(area);
        render_daily(&mut buf, area, &app, anchor, Some(anchor - DAY_SECS), false);
        let rendered = dump(&buf);

        assert!(rendered.contains("DAILY QUERIES"));
        assert!(
            rendered.contains('·'),
            "missing dates need a dot marker: {rendered}"
        );
        assert!(
            rendered.contains('▁'),
            "a recorded zero needs its own marker: {rendered}"
        );
        assert!(!rendered.contains("Queries 0 · Blocked 0"));
        assert!(rendered.contains("8 Total Rolling Queries (Daily History)"));
    }

    #[test]
    fn nice_scale_is_numeric_stable_and_never_below_the_peak() {
        for (value, expected) in [(1, 1), (2, 2), (3, 5), (11, 20), (501, 1_000)] {
            assert_eq!(nice_ceiling(value), expected);
            assert!(nice_ceiling(value) >= value);
        }
    }
}

#[cfg(test)]
#[path = "../../tests/dashboard_charts.rs"]
mod regression_tests;
