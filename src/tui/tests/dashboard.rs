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
    // The daily branch is windowed through `slice_recent_7d`, which
    // filters by wall-clock `now`, so a fixed epoch-1970 timestamp
    // would not survive the window. Anchor to `now_day` instead.
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
    // Anchor to `now_day` so these buckets survive the
    // `slice_recent_7d` window and this test keeps exercising the
    // all-zero `peak_caption` filter, not the empty-`buckets` early
    // return (both happen to omit "peak", but only the former is
    // what this test claims to cover).
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

/// Closes the render-level gap, not just the `slice_recent_7d`
/// helper: a full `MAX_DAILY = 10` ring with its
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
        upstream_servers: Vec::new(),
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
        lists_corpus_freeze: None,
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
    dist[3] = 1; // PTR (not in the named set, folds)
    let lines = pulse_row_types(&dist, 40);
    assert_eq!(lines.len(), 2, "warm state returns bar + legend");
    let text = all_text(&lines);

    let pos_a = text.find('A').unwrap_or(usize::MAX);
    let pos_aaaa = text.find("AAAA").unwrap_or(usize::MAX);
    let pos_https = text.find("HTTPS").unwrap_or(usize::MAX);
    assert!(pos_a < pos_aaaa);
    assert!(pos_aaaa < pos_https);
    assert!(!text.contains("TXT"), "sub-1% TXT must fold to oth");
    assert!(!text.contains("PTR"), "non-named PTR must fold to oth");
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

// ── Top Devices / Top Lists / row-3 ──────────────────────────────

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
        // Top Devices ranks on blocked_24h. Mirror the lifetime
        // fixture value so the existing test intent (top 5 by the
        // closure's `blocked` arg) is preserved without rewriting
        // the assertion table.
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
    // (not in the named set) fold into Other.
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

// ── Top Lists card render ─────────────────────────────────────

/// Concatenate `Buffer` cell symbols row-by-row with newlines so
/// `find` / `contains` checks read the rendered grid rather than
/// the abstract Line list. Local to the tests below; the existing
/// `line_text` / `all_text` helpers operate on `Line`s, not on the
/// post-render buffer.
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
    // Cold-start placeholder matches the sibling Pulse rows'
    // "collecting…" vocabulary.
    assert!(
        dump.contains("collecting"),
        "cold-start placeholder missing in dump:\n{dump}"
    );
}

/// `render_ranked_card` used to floor `label_max` at 6 regardless of
/// how little width was actually left after the fixed rank/gap/count
/// columns, so any card narrower than ~21 inner columns assembled a
/// line longer than `inner.width` — `Paragraph` silently clips the
/// overrun from the line's tail, corrupting the right-aligned count.
/// A pass-through here (no panic) proves nothing; the count digits
/// staying intact does.
#[test]
fn top_lists_card_does_not_clip_the_count_below_21_inner_columns() {
    use crate::ipc::protocol::ListBlockCount;
    use crate::tui::app::App;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    let mut app = App::new();
    app.tracking.top_blocked_lists_24h = vec![ListBlockCount {
        label: "a-very-long-blocklist-label.example".into(),
        count: 220,
        count_24h: 220,
    }];

    // area.width 21 - 2 border cells = 19 inner columns, inside the
    // "below ~21" overflow window the fix addresses.
    let backend = TestBackend::new(21, 6);
    let mut term = Terminal::new(backend).unwrap();
    term.draw(|f| {
        let area = ratatui::layout::Rect::new(0, 0, 21, 6);
        render_top_lists_card(f, area, &app);
    })
    .unwrap();

    let dump = buffer_dump(term.backend().buffer());
    assert!(
        dump.contains("220"),
        "count must survive intact at a narrow width, not lose its \
         tail to an overrun line:\n{dump}"
    );
}

/// Title qualifier flipped from `(lifetime)` to `(24h)` on all
/// three row-4 cards. Pinned so a future refactor doesn't silently
/// revert the operator-facing semantics.
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

/// Top Devices ranks by `blocked_24h`, not lifetime `blocked`. Set
/// a fixture where the two diverge and assert the renderer picks
/// the 24h ordering.
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

// ── Daily-totals barcharts ───────────────────────────────────

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

// ── QType chart card on row 2 right ──────────────────────────────

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
    // Non-zero blocked counts in three buckets so the grouped
    // 2-bar layout has a Total + Blocked pair to render per group.
    // Sums to 62, exercising the `b_pct` denominator.
    let mut bdist = [0u64; crate::tracking::TYPE_BUCKET_COUNT];
    bdist[0] = 45; // A blocked
    bdist[1] = 10; // AAAA blocked
    bdist[4] = 5; // TXT blocked
    bdist[5] = 2; // PTR → Other blocked
                  // HTTPS blocked stays at 0 → renders the muted baseline.
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
    // Percent row uses `Q/B` not `Q%`; expect ≥ 5 slashes (one per
    // bucket group).
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
    // `qtype_distribution_24h` + `qtype_blocked_distribution_24h`
    // are both `[0; N]` by default (the chart card reads the 24h
    // rolling window, not the cumulative counters); total == 0 →
    // cold start placeholder.
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

/// Populated blocked counts must render as a second bar per
/// bucket. Verifies the layout produces a high cell count
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

/// When a bucket has queries but blocked == 0, its blocked bar
/// must render as a muted 1-row baseline so the slot remains
/// visible. Verified by the absence of full-block above the
/// baseline for the all-zero-blocked case.
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

/// Percent row uses `Q/B` format (Q% = bucket / total_queries; B%
/// = bucket / total_blocked).
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

/// Overflow guard: percentages cap at 99 to keep the label inside
/// the 5-col group budget. A 100 % bucket renders as `99`, never
/// `100`.
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

/// The QTYPE chart card must read the 24h rolling fields, NOT the
/// cumulative ones. Seed cumulative with non-zero
/// counts but leave the 24h fields all-zero: the render fn should
/// still produce the cold-start `collecting…` placeholder, proving
/// the active read source is the 24h pair.
#[test]
fn qtype_chart_card_reads_24h_not_cumulative() {
    use crate::tui::app::App;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    let mut app = App::new();
    // Cumulative fields heavily populated.
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

// Prefetch row coverage.

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
    let (_, total_post) = rolling_sum(&post, now_post, 3600, 3600, |b| b.blocked, |b| b.queries);

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

// ── Daily aggregation + trend slice helpers ──────────────────────

/// Three same-UTC-day fragments at the today anchor collapse into
/// the today column (sum), while a fragment on the previous day
/// stays in its own column. Proves `aggregate_daily_values` is
/// sum-not-assign.
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

/// `slice_recent_24h` filters by wall-clock
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

/// A daemon up 8+ days fills `MAX_DAILY = 10`
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

/// The Pulse `Peak` row must window by wall-clock, not entry
/// count. A big spike 30h ago (outside the 24h window) plus a
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

// ── Resources row ─────────────────────────────────────────────

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
    // RAM/CPU live on their own System-card rows, not the Pulse
    // Resources row. No snapshot → muted em-dash.
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

/// Dashboard counterpart of `lists.rs`'s
/// `last_update_and_stale_badge_agree_when_never_succeeded`: a list
/// attempted 5 minutes ago and failed, never once successfully
/// refreshed. Before this fix `oldest_age_secs` read `fetched_at` (the
/// attempt), so this row would have said "oldest 5m ago" — reading as
/// nearly fresh — right next to a badge saying the opposite.
#[test]
fn pulse_lists_age_does_not_read_fresh_off_a_failed_attempt() {
    use crate::lists::status::BlocklistStatusDto;
    use time::format_description::well_known::Rfc3339;
    use time::OffsetDateTime;

    let now = OffsetDateTime::now_utc();
    let five_minutes_ago = now - time::Duration::minutes(5);
    let mut app = App::new();
    app.lists.entries = vec![BlocklistStatusDto {
        source: "privacy/ads".into(),
        id: Some("privacy-ads".into()),
        last_outcome: "failed: HTTP 502".into(),
        fetched_at: Some(five_minutes_ago.format(&Rfc3339).unwrap()),
        last_refresh_at: None,
        ..Default::default()
    }];
    let text = line_text(&pulse_row_lists(&app));
    assert!(
        !text.contains("oldest"),
        "no list has ever succeeded — there is no successful age to report: {text:?}"
    );
    assert!(
        text.contains("1 failed"),
        "the failure must still be visible: {text:?}"
    );
}

/// Discipline pin for the extract-test-blocks move: `dashboard.rs`'s
/// `#[cfg(test)] mod tests { ... }` now lives here via `#[path]`.
/// Scans the raw production source for a marker that still opens a
/// brace-delimited `mod` block — distinct from a standalone
/// `#[cfg(test)] fn` helper, which also opens a brace but is not this
/// shape — so a future rebase or merge that pastes a test module back
/// into `dashboard.rs` fails here instead of silently regrowing the
/// file this move just shrank.
#[test]
fn no_test_module_remains_inline_in_dashboard_rs() {
    crate::tui::cfg_scan::assert_no_inline_test_module(
        "dashboard.rs",
        include_str!("../tabs/dashboard.rs"),
    );
}
