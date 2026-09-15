use super::*;

fn bucket(timestamp: u64, queries: u64, blocked: u64) -> TimeBucketDto {
    TimeBucketDto {
        timestamp,
        queries,
        blocked,
        cache_hits: 0,
    }
}

fn line_text(buf: &Buffer, y: u16) -> String {
    (buf.area.x..buf.area.right())
        .map(|x| buf[(x, y)].symbol())
        .collect()
}

fn assert_chart_title(buf: &Buffer, title: &str) {
    assert!(line_text(buf, 1).contains(title));
    let first = &buf[(1, 1)];
    assert_eq!(first.fg, T.text_inverse);
    assert!(first.modifier.contains(Modifier::BOLD));
}

#[test]
fn rolling_block_rate_is_stable_at_rollover_and_ignores_future_buckets() {
    let before = rolling_block_window(
        &[bucket(10 * HOUR_SECS, 100, 20)],
        11 * HOUR_SECS - 1,
        "1h",
        1,
    );
    let after = rolling_block_window(
        &[
            bucket(10 * HOUR_SECS, 100, 20),
            bucket(11 * HOUR_SECS, 0, 0),
            bucket(12 * HOUR_SECS, 9_999, 9_999),
        ],
        11 * HOUR_SECS + 1,
        "1h",
        1,
    );

    assert_eq!((before.blocked, before.queries), (20, 100));
    assert_eq!((after.blocked, after.queries), (20, 100));
    assert_eq!((after.present_buckets, after.expected_buckets), (2, 2));
}

#[test]
fn block_rate_keeps_unavailable_no_queries_and_real_zero_percent_distinct() {
    let unavailable = rolling_block_window(&[], 20 * HOUR_SECS + 60, "1h", 1);
    let no_queries = rolling_block_window(
        &[bucket(20 * HOUR_SECS, 0, 0)],
        20 * HOUR_SECS + 60,
        "1h",
        1,
    );
    let zero_percent = rolling_block_window(
        &[bucket(20 * HOUR_SECS, 10, 0)],
        20 * HOUR_SECS + 60,
        "1h",
        1,
    );
    let text = |window: &BlockWindow| {
        block_window_header(window, 3, 36)
            .spans
            .iter()
            .map(|span| span.content.as_ref())
            .collect::<String>()
    };

    assert!(text(&unavailable).contains("—/—"));
    assert!(text(&no_queries).contains("—"));
    assert!(text(&no_queries).contains("0/0"));
    assert!(!text(&no_queries).contains("0.0%"));
    assert!(text(&zero_percent).contains("0.0%"));
}

#[test]
fn traffic_series_are_braille_dot_lines_at_contract_and_tall_heights() {
    let anchor = 100 * HOUR_SECS;
    let mut app = App::new();
    app.tracking.hourly = (0..HOURS)
        .map(|index| {
            bucket(
                anchor - (HOURS - 1 - index) as u64 * HOUR_SECS,
                (index as u64 % 7 + 1) * 10,
                (index as u64 % 4) * 3,
            )
        })
        .collect();

    for height in [14, 30] {
        let area = Rect::new(0, 0, 90, height);
        let mut buf = Buffer::empty(area);
        render_traffic(&mut buf, area, &app, anchor, None);
        assert!(line_text(&buf, height - 2).contains(&fmt_hour(anchor)));
        let mut interior = String::new();
        for y in 1..height - 1 {
            for x in 1..89 {
                interior.push_str(buf[(x, y)].symbol());
            }
        }
        assert!(
            interior
                .chars()
                .any(|ch| ('\u{2801}'..='\u{28ff}').contains(&ch)),
            "no Braille chart cells at height {height}"
        );
        for stroke in ['─', '╱', '╲'] {
            assert!(
                !interior.contains(stroke),
                "non-Braille connecting stroke {stroke:?} at height {height}"
            );
        }
    }
}

#[test]
fn query_types_show_top_four_and_aggregate_every_other_bucket() {
    let mut app = App::new();
    let counts = [1, 20, 300, 4_000, 50_000, 6, 70, 800, 9_000, 10];
    app.tracking.qtype_distribution_24h = counts;
    let entries = qtype_entries(&counts);
    assert_eq!(
        entries.map(|e| e.label),
        ["NS", "HTTPS", "PTR", "SVCB", "Other"]
    );
    assert_eq!(entries[4].count, 407);
    assert_eq!(
        entries.iter().map(|e| e.count).sum::<u128>(),
        counts.iter().map(|v| u128::from(*v)).sum::<u128>()
    );
    let area = Rect::new(0, 0, 40, 14);
    let mut buf = Buffer::empty(area);
    render_qtypes(&mut buf, area, &app);
    for (index, entry) in entries.iter().enumerate() {
        let y = 3 + index as u16 * 2;
        assert!(line_text(&buf, y).contains(entry.label));
        assert!(line_text(&buf, y).contains('%'));
        let bar = line_text(&buf, y + 1);
        assert!(bar.chars().skip(3).all(|ch| matches!(
            ch,
            '░' | '▏' | '▎' | '▍' | '▌' | '▋' | '▊' | '▉' | '█' | ' '
        )));
    }
}

#[test]
fn query_type_aggregation_handles_empty_ties_and_full_width_counts() {
    let zero = qtype_entries(&[0; crate::tracking::TYPE_BUCKET_COUNT]);
    assert_eq!(zero.map(|e| e.label), ["A", "AAAA", "TXT", "PTR", "Other"]);
    assert!(zero.iter().all(|e| e.count == 0));
    let max = qtype_entries(&[u64::MAX; crate::tracking::TYPE_BUCKET_COUNT]);
    assert_eq!(
        max.iter().map(|e| e.count).sum::<u128>(),
        u128::from(u64::MAX) * 10
    );
    assert_eq!(max[4].count, u128::from(u64::MAX) * 6);
}

#[test]
fn every_chart_title_uses_the_same_inner_position_and_style() {
    let app = App::new();

    let traffic_area = Rect::new(0, 0, 76, 14);
    let mut traffic = Buffer::empty(traffic_area);
    render_traffic(&mut traffic, traffic_area, &app, 100 * HOUR_SECS, None);
    assert_chart_title(&traffic, "DNS TRAFFIC");

    let qtypes_area = Rect::new(0, 0, 40, 14);
    let mut qtypes = Buffer::empty(qtypes_area);
    render_qtypes(&mut qtypes, qtypes_area, &app);
    assert_chart_title(&qtypes, "QUERY TYPES");

    let block_rate_area = Rect::new(0, 0, 40, 13);
    let mut block_rate = Buffer::empty(block_rate_area);
    render_block_rate(&mut block_rate, block_rate_area, &app, 100 * HOUR_SECS);
    assert_chart_title(&block_rate, "BLOCK RATE");

    let daily_area = Rect::new(0, 0, 76, 20);
    let mut daily = Buffer::empty(daily_area);
    render_daily(&mut daily, daily_area, &app, 100 * DAY_SECS, None, true);
    assert_chart_title(&daily, "DAILY BLOCKED");
}

#[test]
fn chart_canvases_keep_the_neutral_card_surface() {
    let anchor = 100 * HOUR_SECS;
    let mut app = App::new();
    app.tracking.hourly = vec![bucket(anchor, 10, 2)];
    app.tracking.daily = vec![bucket(100 * DAY_SECS, 10, 2)];
    let area = Rect::new(0, 0, 90, 20);
    for daily in [false, true] {
        let mut buffer = Buffer::empty(area);
        if daily {
            render_daily(&mut buffer, area, &app, 100 * DAY_SECS, None, false);
        } else {
            render_traffic(&mut buffer, area, &app, anchor, None);
        }
        for y in 5..15 {
            for x in 12..80 {
                assert_eq!(
                    buffer[(x, y)].bg,
                    T.bg_elevated,
                    "canvas cleared its card at {x},{y}"
                );
            }
        }
    }
}

#[test]
fn percentage_bars_keep_a_track_and_fractional_endpoint() {
    let area = Rect::new(0, 0, 10, 1);
    let mut buffer = Buffer::empty(area);
    percentage_bar(&mut buffer, area, 0.25, T.info);
    assert_eq!(buffer[(0, 0)].symbol(), "░");
    assert_eq!(buffer[(1, 0)].symbol(), "░");
    assert_eq!(buffer[(2, 0)].symbol(), "▌");
    for x in 0..10 {
        assert_eq!(buffer[(x, 0)].bg, T.border_default);
    }
}
