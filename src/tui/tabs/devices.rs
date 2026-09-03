//! Devices tab — unified mapped + unmapped list with side detail card.
//!
//! Single ratatui `Table` mixes configured (mapped) and observed
//! (unmapped) devices into one scrollable list, dimmed for unmapped
//! rows. Group-by `G` cycles owner / department / profile and inserts
//! non-selectable header rows. A side card on the right always renders
//! the full field set for the highlighted row (vendor, MAC aliases,
//! cumulative counters, etc.).
//!
//! Data source: `app.device_view` populated by the IPC `GetAllDevices`
//! poll. The unified row builder runs on every render —
//! cheap because `mapped` is bounded by config size (~50) and
//! `unmapped` by observed traffic (~200 typical).
//!
//! Keybindings (handled in `tui/mod.rs`):
//!   j/k    move cursor in the unified list (skips group headers)
//!   G      cycle group-by (none → owner → department → profile)
//!   Enter  edit modal on mapped row, promote modal on unmapped
//!   a      add new mapped device
//!   e      edit (mapped only)
//!   d      delete (mapped only, opens confirmation)
//!
//! Promote has no dedicated shortcut on this tab — Enter on an
//! unmapped row dispatches to the Promote flow contextually. The
//! previous `p` binding collided with the global `[p] pause`.

use std::net::IpAddr;
use std::str::FromStr;

use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Cell, Paragraph, Row, Table, TableState, Wrap};
use ratatui::Frame;

use crate::config::cidr::Cidr;
use crate::ipc::protocol::{DeviceViewDto, MappedDeviceDto, UnmappedDeviceDto};
use crate::tui::app::{
    App, DeviceFormField, DeviceFormFocus, DeviceFormMode, DeviceFormState, DeviceGroupBy,
    DeviceModal, FieldPicker,
};
use crate::tui::format::count as format_count;
use crate::tui::modal_form::{self, Action, ActionKind, ProseRow, ValueKind};
use crate::tui::theme::{self, T};
use crate::tui::ui::render_section_chrome;

/// One row in the unified Devices list. `GroupHeader` is rendered
/// styled but is never the selection target — `next_selectable_index`
/// skips over it.
///
/// `Mapped` is the largest variant (~336 bytes after the S44 vendor /
/// groups / notes additions) but the row vector is rebuilt every
/// render anyway and only ever holds ~50 entries — Boxing the variant
/// would add a heap allocation per row for no measurable gain. The
/// pattern matches downstream are stable enough that the size
/// difference is just an honest reflection of the schema, not a sign
/// of structural drift.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq)]
pub enum DeviceRow {
    GroupHeader(String),
    Mapped(MappedDeviceDto),
    Unmapped(UnmappedDeviceDto),
}

impl DeviceRow {
    pub fn is_selectable(&self) -> bool {
        !matches!(self, DeviceRow::GroupHeader(_))
    }
}

pub fn render(f: &mut Frame, area: Rect, app: &mut App) {
    let view = match &app.device_view {
        Some(v) => v,
        None => {
            render_empty(f, area);
            // Modal still renders on top of the empty state so a form
            // opened before the first IPC poll lands isn't invisible.
            render_modal_overlay(f, area, app);
            return;
        }
    };

    let now_secs = unix_now();
    let (rows, filter_status) = build_filtered_rows(
        view,
        app.devices.group_by,
        app.devices.filter_subnet.as_deref(),
    );
    // dev-03: resolve the operator's stable selection key to an index
    // every frame so a background poll reshuffle keeps the highlight on
    // the same device. Fall back to the positional cursor before the key
    // is seeded (first render) or if the device vanished.
    let selected =
        crate::tui::app::resolve_row_index(&rows, app.devices.selected_id.as_ref(), row_key)
            .or_else(|| current_selection(&app.devices.table_state, &rows));

    // Two completely independent panels: the list on the left, the
    // detail card on the right, separated by a 1-cell gutter so neither
    // panel's frame touches the other. Width-wise the card is fixed at
    // 38 cells (enough for the longest KV row) and the list takes the
    // rest. On terminals narrower than ~95 cells the card collapses but
    // the list still renders — the redesign target is ≥100 cols.
    let cols = Layout::horizontal([
        Constraint::Min(60),
        Constraint::Length(1),
        Constraint::Length(38),
    ])
    .split(area);

    // The shared filter-card frame sits above the list, inside the list
    // column only — the detail card on the right stays uncovered, same
    // reasoning `render_modal_overlay` below already documents for the
    // form modal.
    let list_rows = Layout::vertical([Constraint::Length(3), Constraint::Min(5)]).split(cols[0]);
    let group_by = app.devices.group_by;
    render_subnet_filter_card(f, list_rows[0], app, filter_status);
    render_list_panel(
        f,
        list_rows[1],
        group_by,
        view,
        &rows,
        now_secs,
        (selected, &mut app.devices.table_state),
    );
    render_card_panel(f, cols[2], &rows, selected, now_secs);

    // Anchor the modal over the LIST column only. The detail card on
    // the right stays uncovered, so the operator filling out the form
    // still sees the live status / vendor / counters of the device
    // they are mapping (they're looking at row N's fields in the
    // form AND row N's read-only context in the card simultaneously).
    // Card refreshes on every poll tick even while the modal is open.
    render_modal_overlay(f, cols[0], app);
}

// ── Empty state ─────────────────────────────────────────────────────

fn render_empty(f: &mut Frame, area: Rect) {
    let content = render_section_chrome(f, area, "Devices", T.text_secondary);
    f.render_widget(
        Paragraph::new(Span::styled(
            " waiting for daemon\u{2026}",
            Style::default().fg(T.text_muted),
        )),
        content,
    );
}

// ── Subnet filter card ──────────────────────────────────────────────

/// Shared filter-card frame (`theme::render_filter_card`), same
/// chrome as Query Log / Lists / Rules / Tags: rounded
/// `T.text_primary` frame, height 3, no interior title — the field is
/// the label. Devices has one field, not a search + chip pair, because
/// there is exactly one dimension to narrow on: the operator filters
/// one subnet at a time.
///
/// `SubnetFilterStatus::Invalid` renders the CIDR in `T.error` with an
/// inline note instead of blanking the card — the on-screen row set is
/// the full, unfiltered list in that state (see `build_filtered_rows`),
/// and the card must say so or the operator reads "no rows changed" as
/// "my filter matched everything" rather than "my filter didn't parse".
fn render_subnet_filter_card(f: &mut Frame, area: Rect, app: &App, status: SubnetFilterStatus) {
    let content_area = theme::render_filter_card(f, area);

    // While `/` is focused the card shows the LIVE buffer with a cursor,
    // not the committed value — same shape as the Lists card. Without
    // this the operator types into a field that shows nothing back.
    let live = match &app.input_mode {
        crate::tui::app::InputMode::FilterDevicesSubnet(buf) => Some(buf.clone()),
        _ => None,
    };
    let value: &str = match live.as_deref() {
        Some(b) => b,
        None => app.devices.filter_subnet.as_deref().unwrap_or(""),
    };
    let (value_style, note) = match status {
        SubnetFilterStatus::Inactive => (Style::default().fg(T.text_secondary), ""),
        SubnetFilterStatus::Active => (Style::default().fg(T.text_primary), ""),
        SubnetFilterStatus::Invalid => (
            Style::default().fg(T.error),
            "  invalid CIDR \u{2014} showing all devices",
        ),
    };
    let shown = if live.is_some() {
        format!("{value}_")
    } else if value.is_empty() {
        "___________".to_string()
    } else {
        value.to_string()
    };

    // Budget the value against the fixed spans so the invalid-CIDR note
    // and the clear hint cannot be pushed off the edge — the note is the
    // whole reason the Invalid state renders at all. Tail-truncated, so a
    // live edit's trailing `_` cursor stays visible.
    let lead = Span::styled("Subnet [/]: ", Style::default().fg(T.text_muted));
    let trailing = vec![
        Span::styled(note, Style::default().fg(T.error)),
        Span::styled("   [R] clear", Style::default().fg(T.text_muted)),
    ];
    let fixed: usize = lead.width() + trailing.iter().map(Span::width).sum::<usize>();
    let budget = (content_area.width as usize).saturating_sub(fixed).max(11);
    let shown = crate::tui::tabs::query_log::truncate_tail(&shown, budget);

    let mut spans = Vec::with_capacity(trailing.len() + 2);
    spans.push(lead);
    spans.push(Span::styled(shown, value_style));
    spans.extend(trailing);
    f.render_widget(Paragraph::new(Line::from(spans)), content_area);
}

// ── Unified list panel ──────────────────────────────────────────────

fn render_list_panel(
    f: &mut Frame,
    area: Rect,
    group_by: DeviceGroupBy,
    view: &DeviceViewDto,
    rows: &[DeviceRow],
    now_secs: u64,
    cursor: (Option<usize>, &mut TableState),
) {
    let (selected, table_state) = cursor;
    let title = format!(
        "Devices ({} mapped \u{00b7} {} unmapped) \u{00b7} group: {}",
        view.mapped.len(),
        view.unmapped.len(),
        group_by.label(),
    );
    let content_area = render_section_chrome(f, area, &title, T.brand_red);

    let header = Row::new(vec![
        Cell::from("IDENTITY"),
        Cell::from("IP"),
        Cell::from("PROFILE"),
        Cell::from("Q.TODAY"),
        // Lifetime blocked ÷ lifetime queries, NOT today's — the column
        // beside it (Q.TODAY) is today-scoped, and an unqualified "BLOCK%"
        // reads as if it belonged to that neighbour.
        Cell::from("BLK% ALL"),
        Cell::from("LAST"),
    ])
    .style(
        Style::default()
            .fg(T.brand_red)
            .add_modifier(Modifier::BOLD),
    );

    const COLUMN_SPACING: u16 = 3;
    const IP_W: u16 = 15; // fits IPv4 xxx.xxx.xxx.xxx
    const PROFILE_W: u16 = 10;
    const Q_TODAY_W: u16 = 8;
    const BLOCK_W: u16 = 8; // fits "BLK% ALL"
    const LAST_W: u16 = 9;
    let constraints = [
        Constraint::Min(15), // identity (flex)
        Constraint::Length(IP_W),
        Constraint::Length(PROFILE_W),
        Constraint::Length(Q_TODAY_W),
        Constraint::Length(BLOCK_W),
        Constraint::Length(LAST_W),
    ];

    let table_rows: Vec<Row> = rows
        .iter()
        .map(|row| match row {
            DeviceRow::GroupHeader(label) => render_group_header_row(label, content_area.width),
            DeviceRow::Mapped(c) => render_mapped_row(c, now_secs),
            DeviceRow::Unmapped(c) => render_unmapped_row(c, now_secs),
        })
        .collect();

    let table = Table::new(table_rows, constraints)
        .header(header)
        .column_spacing(COLUMN_SPACING)
        .row_highlight_style(theme::highlight_style());

    // `selected` already snapped a possibly-stale cursor (left over from
    // a previous group_by snapshot) to a valid selectable row.
    super::render_table(f, content_area, table, table_state, selected);

    // qlog-05: paint the inter-column separators by re-running ratatui's
    // own column layout (`draw_table_column_separators`) on the same
    // constraints the Table used, instead of hand-deriving x-positions
    // from the fixed widths. The manual pass assumed the single flex
    // column absorbs all leftover width, but the solver squeezes the
    // trailing Length columns when the list panel is narrow (terminal
    // widths ~108..121), so the separators drifted through the
    // PROFILE/Q.TODAY/BLOCK%/LAST text.
    crate::tui::ui::draw_table_column_separators(f, content_area, &constraints, COLUMN_SPACING);
}

fn render_mapped_row<'a>(c: &'a MappedDeviceDto, now_secs: u64) -> Row<'a> {
    let dot_style = if c.online {
        Style::default().fg(T.success)
    } else {
        Style::default().fg(T.text_muted)
    };
    let dot = "\u{25cf}"; // filled circle

    // Identity now carries only the friendly name — IP gets its own
    // column to the right, so the operator can scan IPs vertically
    // instead of hunting them inside a compound `name · ip` blob.
    // When the device has no name (rare but possible for partial
    // configs), fall back to the IP so the row isn't empty.
    let label = if c.name.is_empty() {
        c.ip.clone()
    } else {
        c.name.clone()
    };
    // The `[⚠ UNFILTERED]` badge surfaces opt-out devices in the row
    // identity so the operator spots them without opening the card,
    // styled in the shared warning palette.
    let mut identity_spans: Vec<Span<'a>> = vec![
        Span::styled(format!("{dot} "), dot_style),
        Span::styled(label, Style::default().fg(T.text_primary)),
    ];
    if c.unfiltered {
        identity_spans.push(Span::raw(" "));
        identity_spans.push(Span::styled(
            "[\u{26a0} UNFILTERED]",
            Style::default().fg(T.warning).add_modifier(Modifier::BOLD),
        ));
    }
    let identity = Line::from(identity_spans);

    let block_pct = if c.queries > 0 {
        (c.blocked as f64 / c.queries as f64) * 100.0
    } else {
        0.0
    };
    let pct_color = theme::blocked_pct_color(block_pct);
    let secs_ago = now_secs.saturating_sub(c.last_seen);
    let seen_color = theme::last_seen_color(secs_ago);

    Row::new(vec![
        Cell::from(identity),
        Cell::from(Span::styled(
            c.ip.clone(),
            Style::default().fg(T.text_primary),
        )),
        Cell::from(Span::styled(
            c.profile.clone(),
            Style::default().fg(T.text_primary),
        )),
        Cell::from(format_count(c.queries_today)),
        Cell::from(Span::styled(
            format!("{block_pct:.1}%"),
            Style::default().fg(pct_color),
        )),
        Cell::from(Span::styled(
            format_last_seen(secs_ago, c.last_seen),
            Style::default().fg(seen_color),
        )),
    ])
}

fn render_unmapped_row<'a>(c: &'a UnmappedDeviceDto, now_secs: u64) -> Row<'a> {
    // Unmapped rows are dimmed across the entire row — text_secondary
    // for the "real" content, text_muted for the "(unmapped)" label
    // so the row visually says "this device is unrecognised" at a
    // glance without an explicit badge. The Identity column now
    // carries the `(unmapped)` literal alone; the IP lives in its
    // own column to the right.
    let dot_style = if c.online {
        Style::default().fg(T.text_secondary)
    } else {
        Style::default().fg(T.text_muted)
    };
    let dot = "\u{25cb}"; // hollow circle — distinct from mapped (filled)
    let identity = Line::from(vec![
        Span::styled(format!("{dot} "), dot_style),
        Span::styled("(unmapped)", Style::default().fg(T.text_muted)),
    ]);

    let block_pct = if c.queries > 0 {
        (c.blocked as f64 / c.queries as f64) * 100.0
    } else {
        0.0
    };
    let secs_ago = now_secs.saturating_sub(c.last_seen);

    Row::new(vec![
        Cell::from(identity),
        Cell::from(Span::styled(
            c.ip.clone(),
            Style::default().fg(T.text_secondary),
        )),
        Cell::from(Span::styled("\u{2014}", Style::default().fg(T.text_muted))),
        Cell::from(Span::styled(
            format_count(c.queries_today),
            Style::default().fg(T.text_secondary),
        )),
        Cell::from(Span::styled(
            format!("{block_pct:.1}%"),
            Style::default().fg(T.text_muted),
        )),
        Cell::from(Span::styled(
            format_last_seen(secs_ago, c.last_seen),
            Style::default().fg(T.text_muted),
        )),
    ])
}

/// Divider fill width for [`render_group_header_row`]: total row width
/// minus the fixed `"── {label} "` prefix, capped so a very wide table
/// doesn't grow an absurdly long dash run.
///
/// Uses `label.chars().count()`, not `label.len()`.
/// `label` is built from operator-supplied owner / department / profile
/// strings, so it isn't necessarily ASCII — `len()` counts UTF-8
/// *bytes*, which over-subtracts for any multi-byte name ("François" is
/// 8 chars but 9 bytes; a CJK name is 3 bytes per char) and leaves the
/// divider short of the table's actual width.
fn group_header_dash_count(label: &str, width: u16) -> usize {
    (width as usize)
        .saturating_sub(label.chars().count() + 4)
        .min(80)
}

fn render_group_header_row<'a>(label: &str, width: u16) -> Row<'a> {
    // One-cell-wide cells for the four trailing columns are sufficient
    // — the header lives in the flex Identity column. We pad with em
    // dashes so the section divider visually spans the full table.
    let dash_count = group_header_dash_count(label, width);
    let dashes = "\u{2500}".repeat(dash_count);
    let body = format!("\u{2500}\u{2500} {label} {dashes}");
    Row::new(vec![Cell::from(Span::styled(
        body,
        Style::default()
            .fg(T.text_muted)
            .add_modifier(Modifier::ITALIC),
    ))])
    .style(
        Style::default()
            .fg(T.text_muted)
            .add_modifier(Modifier::ITALIC),
    )
}

// ── Side detail card ────────────────────────────────────────────────

fn render_card_panel(
    f: &mut Frame,
    area: Rect,
    rows: &[DeviceRow],
    selected: Option<usize>,
    now_secs: u64,
) {
    let title = match selected.and_then(|i| rows.get(i)) {
        Some(DeviceRow::Mapped(c)) => {
            let head = if c.name.is_empty() { &c.ip } else { &c.name };
            format!("Device \u{00b7} {head}")
        }
        Some(DeviceRow::Unmapped(c)) => format!("Device \u{00b7} {}", c.ip),
        _ => "Device".to_string(),
    };
    let content = render_section_chrome(f, area, &title, T.brand_red);

    let lines: Vec<Line<'static>> = match selected.and_then(|i| rows.get(i)) {
        Some(DeviceRow::Mapped(c)) => mapped_card_lines(c, now_secs),
        Some(DeviceRow::Unmapped(c)) => unmapped_card_lines(c, now_secs),
        _ => vec![Line::from(Span::styled(
            " select a device",
            Style::default().fg(T.text_muted),
        ))],
    };

    f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), content);
}

fn mapped_card_lines(c: &MappedDeviceDto, now_secs: u64) -> Vec<Line<'static>> {
    let secs_ago = now_secs.saturating_sub(c.last_seen);
    let mut out: Vec<Line<'static>> = Vec::with_capacity(20);

    out.push(kv("Status", status_span(c.online, secs_ago, c.last_seen)));
    out.push(kv_str("Name", &c.name, T.text_primary));
    out.push(kv_str("IP", &c.ip, T.text_primary));
    out.push(mac_line(c.mac.as_deref(), &c.mac_aliases));
    if let Some(v) = c.vendor.as_deref() {
        out.push(kv_str("Vendor", v, T.text_secondary));
    }
    out.push(kv_str("Profile", &c.profile, T.text_primary));
    out.push(group_line(&c.groups));
    out.push(kv_opt("Owner", c.owner.as_deref(), T.text_primary));
    // "Type" matches the form label (renamed from the legacy "Device"
    // wording — the schema field is `device_type`, the operator-facing
    // label everywhere is `type`).
    out.push(kv_opt("Type", c.device_type.as_deref(), T.text_primary));
    out.push(kv_opt("Dept", c.department.as_deref(), T.text_primary));
    // No "Tag propri" / "Tag ereditati" pair here: both were projections
    // of `tags` arrays the schema no longer has, so they could only ever
    // read "—" — a card teaching an inheritance relation that does not
    // exist. The `[⚠ UNFILTERED]` badge, which is what their `unfiltered`
    // branch was really about, renders independently below.
    out.push(notes_line(c.notes.as_deref()));

    out.push(divider_line());

    let block_pct = if c.queries > 0 {
        (c.blocked as f64 / c.queries as f64) * 100.0
    } else {
        0.0
    };
    // mem2608-s3 / F-P, FIFTH site — found by smoke-testing the fix, not by
    // the sweep that produced it. `socket_server.rs` (see the comment at the
    // `cacheable` binding there) excludes blocked queries from the cache-rate
    // denominator because the block check runs before the cache is consulted,
    // so a blocked query is a *structural* non-hit. That argument is about the
    // query path, not about the scope, so it holds per device exactly as it
    // holds globally — and this row already had `blocked` in hand and divided
    // by the full count anyway.
    //
    // The effect was perverse rather than merely imprecise: the more
    // effectively a device was filtered, the WORSE its cache looked, because
    // every newly-blocked query landed in the denominator and could never
    // land in the numerator. `block_pct` above stays over ALL queries and is
    // deliberately untouched — "what fraction of this device's traffic did I
    // block" is correctly a statement about all of it.
    let cacheable = c.queries.saturating_sub(c.blocked);
    let cache_pct = if cacheable > 0 {
        (c.cache_hits as f64 / cacheable as f64) * 100.0
    } else {
        0.0
    };

    out.push(kv(
        "Queries",
        Span::styled(
            format!(
                "{}  (today {})",
                format_count(c.queries),
                format_count(c.queries_today),
            ),
            Style::default().fg(T.text_primary),
        ),
    ));
    out.push(kv(
        "Blocked",
        Span::styled(
            format!("{}  ({block_pct:.1}%)", format_count(c.blocked)),
            Style::default().fg(theme::blocked_pct_color(block_pct)),
        ),
    ));
    out.push(kv(
        "Cache hits",
        Span::styled(
            format!("{}  ({cache_pct:.1}%)", format_count(c.cache_hits)),
            Style::default().fg(T.text_secondary),
        ),
    ));
    out.push(kv(
        "Last seen",
        Span::styled(
            format_last_seen(secs_ago, c.last_seen),
            Style::default().fg(theme::last_seen_color(secs_ago)),
        ),
    ));

    out
}

fn unmapped_card_lines(c: &UnmappedDeviceDto, now_secs: u64) -> Vec<Line<'static>> {
    let secs_ago = now_secs.saturating_sub(c.last_seen);
    let mut out: Vec<Line<'static>> = Vec::with_capacity(12);

    out.push(kv("Status", status_span(c.online, secs_ago, c.last_seen)));
    out.push(kv_str("IP", &c.ip, T.text_primary));
    out.push(mac_line(c.mac.as_deref(), &[]));
    if let Some(v) = c.vendor.as_deref() {
        out.push(kv_str("Vendor", v, T.text_secondary));
    }

    out.push(divider_line());

    let block_pct = if c.queries > 0 {
        (c.blocked as f64 / c.queries as f64) * 100.0
    } else {
        0.0
    };

    out.push(kv(
        "Queries",
        Span::styled(
            format!(
                "{}  (today {})",
                format_count(c.queries),
                format_count(c.queries_today),
            ),
            Style::default().fg(T.text_primary),
        ),
    ));
    out.push(kv(
        "Blocked",
        Span::styled(
            format!("{}  ({block_pct:.1}%)", format_count(c.blocked)),
            Style::default().fg(theme::blocked_pct_color(block_pct)),
        ),
    ));
    out.push(kv(
        "Last seen",
        Span::styled(
            format_last_seen(secs_ago, c.last_seen),
            Style::default().fg(theme::last_seen_color(secs_ago)),
        ),
    ));

    out.push(Line::from(""));
    out.push(Line::from(Span::styled(
        " press Enter to add as mapped device",
        Style::default()
            .fg(T.text_muted)
            .add_modifier(Modifier::ITALIC),
    )));

    out
}

fn kv(label: &'static str, value: Span<'static>) -> Line<'static> {
    Line::from(vec![
        Span::raw(" "),
        Span::styled(format!("{label:<11}"), Style::default().fg(T.text_muted)),
        value,
    ])
}

fn kv_str(label: &'static str, value: &str, color: Color) -> Line<'static> {
    kv(
        label,
        Span::styled(value.to_string(), Style::default().fg(color)),
    )
}

fn kv_opt(label: &'static str, value: Option<&str>, color: Color) -> Line<'static> {
    match value.filter(|s| !s.is_empty()) {
        Some(v) => kv_str(label, v, color),
        None => kv(
            label,
            Span::styled("\u{2014}", Style::default().fg(T.text_muted)),
        ),
    }
}

fn mac_line(mac: Option<&str>, aliases: &[String]) -> Line<'static> {
    let value = match mac {
        Some(m) if !aliases.is_empty() => Span::styled(
            format!("{m}  +{}", aliases.len()),
            Style::default().fg(T.text_primary),
        ),
        Some(m) => Span::styled(m.to_string(), Style::default().fg(T.text_primary)),
        None => Span::styled("(no arp)".to_string(), Style::default().fg(T.text_muted)),
    };
    kv("MAC", value)
}

/// Group line on the side card — every membership, in file order,
/// comma-joined. The card paragraph wraps (`Wrap { trim: false }`), so a
/// long list costs a second row rather than being cut.
///
/// It used to show the first name and a muted `+N more (CLI)`, which was
/// two claims: that the rest existed, and that only the CLI could touch
/// them. The second claim is now false — the Edit modal holds the whole
/// list — and a hint that mis-states where an operator must go is worse
/// than no hint, because it sends them somewhere else.
fn group_line(groups: &[String]) -> Line<'static> {
    if groups.is_empty() {
        return kv(
            "Group",
            Span::styled("\u{2014}", Style::default().fg(T.text_muted)),
        );
    }
    kv(
        "Group",
        Span::styled(groups.join(", "), Style::default().fg(T.text_primary)),
    )
}

/// Notes line on the side card. Long notes are truncated at 60 **chars**
/// (not bytes — notes are operator-supplied and need not be ASCII) with
/// an ellipsis so the line stays single-row; the operator can see
/// the full text by editing the device.
fn notes_line(notes: Option<&str>) -> Line<'static> {
    match notes.filter(|s| !s.is_empty()) {
        None => kv(
            "Notes",
            Span::styled("\u{2014}", Style::default().fg(T.text_muted)),
        ),
        Some(s) => {
            let display = if s.chars().count() > 60 {
                let mut head: String = s.chars().take(59).collect();
                head.push('\u{2026}');
                head
            } else {
                s.to_string()
            };
            kv(
                "Notes",
                Span::styled(
                    display,
                    Style::default()
                        .fg(T.text_secondary)
                        .add_modifier(Modifier::ITALIC),
                ),
            )
        }
    }
}

fn divider_line() -> Line<'static> {
    Line::from(Span::styled(
        " \u{2500}".repeat(18),
        Style::default().fg(T.border_default),
    ))
}

fn status_span(online: bool, secs_ago: u64, last_seen: u64) -> Span<'static> {
    if online {
        Span::styled(
            "\u{25cf} online",
            Style::default().fg(T.success).add_modifier(Modifier::BOLD),
        )
    } else if last_seen == 0 {
        Span::styled("\u{25cb} never seen", Style::default().fg(T.text_muted))
    } else {
        Span::styled(
            format!(
                "\u{25cb} offline ({})",
                format_last_seen(secs_ago, last_seen)
            ),
            Style::default().fg(T.text_muted),
        )
    }
}

// ── Row builder + selection helpers ────────────────────────────────

/// Build the merged row sequence from the current device view + group
/// preference. Mapped rows come first, grouped if `group_by != None`.
/// Unmapped rows always appear at the bottom under their own
/// `── Unmapped ──` header (or no header when `group_by == None` and
/// there are no group dividers above).
pub fn build_rows(view: &DeviceViewDto, group_by: DeviceGroupBy) -> Vec<DeviceRow> {
    let mut out = Vec::with_capacity(view.mapped.len() + view.unmapped.len() + 8);

    let mut mapped: Vec<&MappedDeviceDto> = view.mapped.iter().collect();
    sort_mapped(&mut mapped, group_by);

    if matches!(group_by, DeviceGroupBy::None) {
        for m in mapped {
            out.push(DeviceRow::Mapped(m.clone()));
        }
    } else {
        let mut last_key: Option<String> = None;
        for m in mapped {
            let key = group_key(m, group_by);
            if last_key.as_deref() != Some(key.as_str()) {
                out.push(DeviceRow::GroupHeader(format!(
                    "{}: {}",
                    group_label(group_by),
                    if key.is_empty() {
                        "(unset)".to_string()
                    } else {
                        key.clone()
                    }
                )));
                last_key = Some(key);
            }
            out.push(DeviceRow::Mapped(m.clone()));
        }
    }

    if !view.unmapped.is_empty() {
        out.push(DeviceRow::GroupHeader("Unmapped".to_string()));
        let mut unmapped: Vec<&UnmappedDeviceDto> = view.unmapped.iter().collect();
        unmapped.sort_by(|a, b| a.ip.cmp(&b.ip));
        for u in unmapped {
            out.push(DeviceRow::Unmapped(u.clone()));
        }
    }

    out
}

/// Status of the operator's subnet filter for one render — drives both
/// the filter-card wording and whether [`build_filtered_rows`] actually
/// narrowed the row set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubnetFilterStatus {
    /// `app.devices.filter_subnet` is `None` — no filter applied.
    Inactive,
    /// Filter set and parsed as a CIDR — rows narrowed to members.
    Active,
    /// Filter set but did not parse as a CIDR. Rows are left
    /// **unfiltered** rather than collapsing to zero: a typo in the
    /// CIDR must never read as "no devices on this subnet" — that is
    /// exactly the data-loss reading a filter that hides rows silently
    /// would produce.
    Invalid,
}

/// Narrow `view` to the mapped + unmapped devices whose IP falls inside
/// `cidr`. Returns `None` when `cidr` fails to parse.
///
/// Deliberately calls `config::cidr::Cidr` directly rather than
/// `tabs::subnets::filter_clients_in_subnet`: that helper returns an
/// empty `Vec` both when the CIDR fails to parse and when it parses but
/// matches nothing, so a caller can't tell "typo" from "zero devices
/// here" — exactly the ambiguity `SubnetFilterStatus` exists to keep
/// apart. `Cidr::parse` / `Cidr::contains` are the primitive that
/// helper itself calls, so this is not a second CIDR parser.
fn subnet_filtered_view(view: &DeviceViewDto, cidr: &str) -> Option<DeviceViewDto> {
    let parsed = Cidr::parse(cidr).ok()?;
    let ip_in = |ip: &str| {
        IpAddr::from_str(ip)
            .map(|ip| parsed.contains(ip))
            .unwrap_or(false)
    };
    Some(DeviceViewDto {
        mapped: view
            .mapped
            .iter()
            .filter(|m| ip_in(&m.ip))
            .cloned()
            .collect(),
        unmapped: view
            .unmapped
            .iter()
            .filter(|u| ip_in(&u.ip))
            .cloned()
            .collect(),
    })
}

/// Build the row set for render, applying the operator's subnet filter
/// on top of the existing group-by (`build_rows`).
///
/// The row set every consumer must use: it is what `render` paints, so
/// it is what a cursor index means. `build_rows` is the unfiltered
/// builder underneath and is not a substitute for a live cursor — indexing
/// it with a cursor taken against this one silently addresses a device
/// that is not on screen.
pub fn build_filtered_rows(
    view: &DeviceViewDto,
    group_by: DeviceGroupBy,
    filter_subnet: Option<&str>,
) -> (Vec<DeviceRow>, SubnetFilterStatus) {
    match filter_subnet {
        None => (build_rows(view, group_by), SubnetFilterStatus::Inactive),
        Some(cidr) => match subnet_filtered_view(view, cidr) {
            Some(filtered) => (build_rows(&filtered, group_by), SubnetFilterStatus::Active),
            None => (build_rows(view, group_by), SubnetFilterStatus::Invalid),
        },
    }
}

fn group_key(m: &MappedDeviceDto, group_by: DeviceGroupBy) -> String {
    match group_by {
        DeviceGroupBy::None => String::new(),
        DeviceGroupBy::Owner => m.owner.clone().unwrap_or_default(),
        DeviceGroupBy::Department => m.department.clone().unwrap_or_default(),
        DeviceGroupBy::Profile => m.profile.clone(),
    }
}

fn group_label(group_by: DeviceGroupBy) -> &'static str {
    match group_by {
        DeviceGroupBy::None => "",
        DeviceGroupBy::Owner => "Owner",
        DeviceGroupBy::Department => "Dept",
        DeviceGroupBy::Profile => "Profile",
    }
}

fn sort_mapped(rows: &mut [&MappedDeviceDto], group: DeviceGroupBy) {
    match group {
        DeviceGroupBy::None => rows.sort_by(|a, b| a.name.cmp(&b.name)),
        DeviceGroupBy::Owner => rows.sort_by(|a, b| {
            a.owner
                .as_deref()
                .unwrap_or("")
                .cmp(b.owner.as_deref().unwrap_or(""))
                .then_with(|| a.name.cmp(&b.name))
        }),
        DeviceGroupBy::Department => rows.sort_by(|a, b| {
            a.department
                .as_deref()
                .unwrap_or("")
                .cmp(b.department.as_deref().unwrap_or(""))
                .then_with(|| a.name.cmp(&b.name))
        }),
        DeviceGroupBy::Profile => {
            rows.sort_by(|a, b| a.profile.cmp(&b.profile).then_with(|| a.name.cmp(&b.name)));
        }
    }
}

/// dev-03: the stable selection key for a row — the mapped device's id
/// (falling back to the slug of its name, then the raw name, for a
/// pre-S44 id-less DTO) or the unmapped device's IP. Group-header rows
/// are not selectable and have no key. Mirrors the IPC key the modal
/// openers resolve, so the highlight and the mutation target agree.
pub fn row_key(row: &DeviceRow) -> Option<String> {
    match row {
        DeviceRow::Mapped(m) => Some(
            m.id.clone()
                .filter(|s| !s.is_empty())
                .or_else(|| crate::cli::commands::target::slug_id(&m.name).ok())
                .unwrap_or_else(|| m.name.clone()),
        ),
        DeviceRow::Unmapped(u) => Some(u.ip.clone()),
        DeviceRow::GroupHeader(_) => None,
    }
}

/// Snap a possibly-stale `TableState` selection to a valid selectable
/// row. Returns `None` when the list is empty or contains only headers.
/// Public so the key handler can drive the same logic when applying
/// j/k movement.
pub fn current_selection(
    state: &ratatui::widgets::TableState,
    rows: &[DeviceRow],
) -> Option<usize> {
    let cursor = state.selected();
    // Try the existing cursor first.
    if let Some(i) = cursor {
        if i < rows.len() && rows[i].is_selectable() {
            return Some(i);
        }
    }
    // Otherwise scan forward from the current position (or 0) until
    // we find a selectable row.
    let start = cursor.unwrap_or(0);
    for offset in 0..rows.len() {
        let i = (start + offset) % rows.len();
        if rows[i].is_selectable() {
            return Some(i);
        }
    }
    None
}

/// Move the cursor to the next selectable row in the given direction
/// (`+1` for j/down, `-1` for k/up). N4: **clamps** at both ends —
/// walking off the last/first selectable row is a no-op, never a
/// teleport to the other end. Returns `None` when no further selectable
/// row exists in that direction without leaving `[0, len)` (including
/// when the list has none at all); both call sites in `mod.rs` are
/// `if let Some(idx) = ... { select(idx) }`, so `None` already means
/// "leave the cursor where it is."
pub fn next_selectable_index(
    rows: &[DeviceRow],
    current: Option<usize>,
    dir: i32,
) -> Option<usize> {
    if rows.is_empty() {
        return None;
    }
    let len = rows.len() as i32;
    // Treat `None` as "before the start" so a fresh j moves to row 0.
    let start = current.map(|i| i as i32).unwrap_or(-dir.signum());
    for step in 1..=len {
        let raw = start + dir * step;
        if raw < 0 || raw >= len {
            return None;
        }
        let i = raw as usize;
        if rows[i].is_selectable() {
            return Some(i);
        }
    }
    None
}

// ── Helpers ─────────────────────────────────────────────────────────

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn format_last_seen(secs_ago: u64, last_seen: u64) -> String {
    if last_seen == 0 {
        return "never".to_string();
    }
    if secs_ago < 60 {
        "now".to_string()
    } else if secs_ago < 3600 {
        format!("{}m ago", secs_ago / 60)
    } else if secs_ago < 86400 {
        format!("{}h ago", secs_ago / 3600)
    } else {
        format!("{}d ago", secs_ago / 86400)
    }
}

// ── Modal overlay ────────────────────────────────────────────────

/// Render the active modal (if any) on top of the Devices tab. The
/// modal is centered horizontally and occupies a fixed-height region
/// inset from the parent area. `Clear` is rendered first so the popup
/// opaquely covers the underlying content — operators see ONLY the
/// form when they're filling it out, not a confusing mix of tables
/// bleeding through.
pub(super) fn render_modal_overlay(f: &mut Frame, area: Rect, app: &App) {
    let Some(modal) = &app.devices.modal else {
        return;
    };
    match modal {
        DeviceModal::Form(form) => {
            render_form_modal(f, area, form);
            // Popup radio picker (Profile / Group) drawn on top of the form
            // while the operator is choosing a value.
            if let Some(picker) = form.picker.as_ref() {
                render_field_picker(f, area, picker);
            }
        }
        DeviceModal::DeleteConfirm { display_name, .. } => {
            render_delete_confirm(f, area, display_name)
        }
    }
}

/// Outer modal width. The interior is two columns narrower, and one
/// narrower again while the field region scrolls —
/// [`modal_form::render_modal`] resolves that, so nothing here measures
/// against it by hand.
const MODAL_W: u16 = 60;

/// Nav-key legend. Byte-identical to the copy this form carried before the
/// migration (D7′: chrome, layout and colour change, keying does not).
///
/// Deliberately **not** the `←/→ change` legend the retired grid
/// advertised for every surface: this form's select-only fields open a
/// popup on `Enter` rather than cycling inline, and telling the operator
/// about a key that does nothing is worse than silence.
const FORM_KEYS: &str = "\u{2191}\u{2193}/\u{21b9} move \u{b7} Enter open/save \u{b7} Esc cancel";

/// Placeholder for the two select-only rows. Carries the affordance the
/// retired grid drew as a right-aligned muted `[Enter]`: the ecosystem row
/// vocabulary has no picker variant, and a suffix span appended after
/// [`modal_form::value_row`] would land past the focus bar's `◀` marker
/// and overflow the row. The focused hint states it a second time.
const PICK_PLACEHOLDER: &str = "Enter to pick";

/// The two sections' field order AND labels — the single source both the
/// rendered rows and the cursor's row lookup read. Keeping them as one
/// list is the point: when they were two (an array of `field_row` calls
/// plus a separate order constant), adding a field to one and not the
/// other silently put the hardware cursor on the wrong row, and no test
/// could see it.
const IDENTITY_FIELDS: [(DeviceFormField, &str); 3] = [
    (DeviceFormField::Ip, "ip"),
    (DeviceFormField::Mac, "mac"),
    (DeviceFormField::MacAliases, "aliases"),
];
const ASSIGNMENT_FIELDS: [(DeviceFormField, &str); 9] = [
    (DeviceFormField::Name, "name"),
    (DeviceFormField::Profile, "profile"),
    (DeviceFormField::Group, "group"),
    (DeviceFormField::Owner, "owner"),
    (DeviceFormField::Device, "type"),
    (DeviceFormField::Department, "department"),
    (DeviceFormField::Notes, "notes"),
    (DeviceFormField::NetworkName, "net name"),
    (DeviceFormField::NetworkNameWildcard, "wildcard"),
];

/// Per-mode title and description band strings. The description replaces
/// the two italic caption lines the pre-band form carried above the
/// identity block.
fn band_text(mode: DeviceFormMode) -> (&'static str, &'static str) {
    match mode {
        DeviceFormMode::Add => (
            "ADD CLIENT",
            "MAC pins the device through DHCP changes. IP optional.",
        ),
        DeviceFormMode::Edit => (
            "EDIT CLIENT",
            "Change the profile, group and metadata for this device.",
        ),
        DeviceFormMode::Promote => (
            "PROMOTE UNMAPPED CLIENT",
            "Seen on the network \u{2014} give it a name and a profile.",
        ),
    }
}

/// One-line hint for the focused stop, shown on the validation row when
/// there is no pending error.
fn focus_hint(mode: DeviceFormMode, focus: DeviceFormFocus) -> &'static str {
    match focus {
        DeviceFormFocus::Field(DeviceFormField::Mac) => {
            "The MAC the device identifies with \u{2014} survives DHCP changes."
        }
        DeviceFormFocus::Field(DeviceFormField::MacAliases) => {
            "Extra MACs, comma-separated \u{2014} for devices that rotate theirs."
        }
        DeviceFormFocus::Field(DeviceFormField::Profile) => "Enter opens the profile list.",
        // The two Group hints differ because the two wires differ, and the
        // operator should learn that from the form rather than from a
        // refusal on Save: Add carries one id, Edit carries the whole list.
        DeviceFormFocus::Field(DeviceFormField::Group) if mode == DeviceFormMode::Edit => {
            "Enter opens the group list \u{2014} Space toggles, a device can be in several."
        }
        DeviceFormFocus::Field(DeviceFormField::Group) => {
            "Enter opens the group list \u{2014} one here; add the others after saving."
        }
        // Mode-split for the same reason the two Group hints are, and
        // stated by the same rule: the Add and Promote wires carry no
        // network name, so `parse_form` refuses one there. The operator
        // should learn that from the form, not from a refusal on Save —
        // an unconditional hint would invite exactly the input the guard
        // then rejects.
        //
        // Both hints run past one row and hard-wrap across `HINT_ROWS`,
        // which is fine — the budget is 2 rows whatever the text.
        DeviceFormFocus::Field(DeviceFormField::NetworkName) if mode == DeviceFormMode::Edit => {
            "Bare name, no suffix \u{2014} e.g. \"desktop-1\". Empty = not resolvable."
        }
        DeviceFormFocus::Field(DeviceFormField::NetworkNameWildcard)
            if mode == DeviceFormMode::Edit =>
        {
            "true / false \u{2014} also answer for every subdomain of the name above."
        }
        DeviceFormFocus::Field(
            DeviceFormField::NetworkName | DeviceFormField::NetworkNameWildcard,
        ) => "Set after saving \u{2014} save this device, then edit it to name it.",
        DeviceFormFocus::Cancel => "Discard changes and close.",
        DeviceFormFocus::Save => "Write the changes and close.",
        _ => "",
    }
}

/// The raw buffer behind a field — the value the cursor arithmetic and the
/// row renderer both measure.
fn field_value(form: &DeviceFormState, field: DeviceFormField) -> &str {
    match field {
        DeviceFormField::Name => &form.name,
        DeviceFormField::Ip => &form.ip,
        DeviceFormField::Mac => &form.mac,
        DeviceFormField::MacAliases => &form.mac_aliases,
        DeviceFormField::Profile => &form.profile,
        DeviceFormField::Group => &form.groups,
        DeviceFormField::Owner => &form.owner,
        DeviceFormField::Device => &form.device_type,
        DeviceFormField::Department => &form.department,
        DeviceFormField::Notes => &form.notes,
        DeviceFormField::NetworkName => &form.network_name,
        DeviceFormField::NetworkNameWildcard => &form.network_name_wildcard,
    }
}

/// Push one field's row, with its shape resolved from the form's mode and
/// lock flags: locked (Promote's ip / mac) renders inert, the two
/// select-only fields take focus but no caret, everything else is an
/// editable text row that does take one.
///
/// One call per field instead of the four parallel `if focused { … }`
/// blocks the flat body needed — [`modal_form::FormRows`] cannot be handed
/// a focused row without its hint, so the second `match focus { … }` table
/// that used to drift out of step with the field list is gone.
fn push_field(
    rows: &mut modal_form::FormRows,
    form: &DeviceFormState,
    field: DeviceFormField,
    label: &str,
) {
    let width = rows.width();
    let value = field_value(form, field);
    let focused = form.focused == DeviceFormFocus::Field(field);
    let hint = focus_hint(form.mode, DeviceFormFocus::Field(field));

    if form.is_locked(field) {
        // Pinned from the ARP snapshot. `focus_ring` filters `is_locked`,
        // so it can never hold focus — no hint, no caret, and `line`
        // rather than `field` keeps it out of the viewport's anchor set.
        //
        // The ARP-pinned rows always carry a value, so they need no
        // placeholder. Group on a Promote form is locked for a different
        // reason — the wire has no field for it — and is empty, so it
        // states when it becomes available instead of rendering blank.
        let placeholder = (field == DeviceFormField::Group).then_some("after saving, via Edit");
        rows.line(modal_form::value_row(
            label,
            value,
            false,
            ValueKind::Identity,
            placeholder,
            width,
        ));
        return;
    }

    match field {
        // Select-only: `Enter` opens a popup rather than accepting
        // keystrokes, so the row takes focus but NOT the hardware cursor
        // — there is no insertion point to put it on.
        DeviceFormField::Profile | DeviceFormField::Group => rows.field(
            modal_form::value_row(
                label,
                value,
                focused,
                ValueKind::Identity,
                Some(PICK_PLACEHOLDER),
                width,
            ),
            focused,
            hint,
        ),
        _ => rows.text_field(
            modal_form::value_row(
                label,
                value,
                focused,
                ValueKind::Editable,
                Some("\u{2014}"),
                width,
            ),
            focused,
            hint,
            value.chars().count() as u16,
        ),
    }
}

/// The frozen id row. On Edit it is the `original_id` pinned at modal-open
/// — the id the submit will patch, which does NOT follow the name. On Add
/// and Promote no entity exists yet, so it is the live slug preview of the
/// name. Never focusable in either case: it is derived, never typed.
fn push_id_row(rows: &mut modal_form::FormRows, form: &DeviceFormState) {
    let (value, note) = match form.mode {
        DeviceFormMode::Edit => (form.original_id.clone().unwrap_or_default(), "  (fixed)"),
        _ => (form.id_preview(), "  (auto from name)"),
    };
    let shown = if value.is_empty() {
        "(set name to derive)".to_string()
    } else {
        format!("{value}{note}")
    };
    let width = rows.width();
    rows.line(modal_form::value_row(
        "id",
        &shown,
        false,
        ValueKind::Identity,
        None,
        width,
    ));
}

/// Build the Archetype-F body: banded head, two labelled sections, one row
/// per field, pinned tail. Returns the [`modal_form::ScrollBody`] plus the
/// real terminal cursor's target, exactly as `tabs/lists.rs::edit_form_body`
/// and `profile_modal::form_body` do.
///
/// `width` is handed down by [`modal_form::render_modal`] and is already net
/// of the scrollbar column when the field region scrolls — no row here
/// measures the modal for itself. The **row count must not vary with it**:
/// every builder called below returns a fixed number of
/// lines, and `form_tail_with_status` pads its note region to exactly
/// `HINT_ROWS`, so the two build passes agree.
fn form_body(form: &DeviceFormState, width: u16) -> (modal_form::ScrollBody, Option<(usize, u16)>) {
    let (title, desc) = band_text(form.mode);
    let mut rows = modal_form::FormRows::new(title, desc, width);

    rows.section("Identity \u{b7} Network");
    // `id` is derived, never typed, so it is not in IDENTITY_FIELDS and is
    // pushed as an inert row rather than a focusable one.
    push_id_row(&mut rows, form);
    for (field, label) in IDENTITY_FIELDS {
        push_field(&mut rows, form, field, label);
    }

    rows.spacer();
    rows.section("Assignments & Metadata");
    for (field, label) in ASSIGNMENT_FIELDS {
        push_field(&mut rows, form, field, label);
    }

    let tail = form_tail_for(&rows, form);
    rows.finish(tail)
}

/// The pinned tail: transient status / hint / error, the key legend, then
/// `Cancel` · `Save`.
///
/// Two colour-rule corrections land here. `Cancel` used to take a
/// `brand_red` fill on focus — a filled red beside a filled `Save` is how
/// an operator discards work they meant to keep — and is now
/// `ActionKind::Neutral`. `Save` becomes the modal's one
/// `ActionKind::Primary`, so the single teal fill is the only fill.
///
/// `submitting` moves from the hint slot to the **status** slot: it used to
/// be handed to every row in place of that row's own guidance, so it wore
/// the hint's muted italic and the focused field's help vanished for the
/// duration of the submit.
fn form_tail_for(rows: &modal_form::FormRows, form: &DeviceFormState) -> Vec<Line<'static>> {
    let actions = [
        Action::new(
            "  Cancel  ",
            form.focused == DeviceFormFocus::Cancel,
            ActionKind::Neutral,
            focus_hint(form.mode, DeviceFormFocus::Cancel),
        ),
        Action::new(
            "  Save  ",
            form.focused == DeviceFormFocus::Save,
            ActionKind::Primary,
            focus_hint(form.mode, DeviceFormFocus::Save),
        ),
    ];
    modal_form::form_tail_with_status(
        rows,
        form.submitting.then_some("submitting\u{2026}"),
        form.error_message.as_deref(),
        // Belt and braces: a locked row renders no focusable line, so its
        // guidance would otherwise come from nowhere.
        focus_hint(form.mode, form.focused),
        FORM_KEYS,
        &actions,
    )
}

/// Draw the form. Anchored on `area` — the **list column**, not the whole
/// frame — so the detail card on the right stays readable while the form is
/// open.
///
/// Everything geometric belongs to [`modal_form::render_modal`]: the
/// elevated rounded chrome, the height request, the anchor clamp, the
/// two-pass width resolution that keeps rows clear of the scrollbar column,
/// and the focus-following viewport. What is left here is the width and
/// where the real terminal cursor goes.
fn render_form_modal(f: &mut Frame, area: Rect, form: &DeviceFormState) {
    let render = modal_form::render_modal(f, area, MODAL_W, |w| form_body(form, w));
    if let Some((row, caret)) = render.cursor {
        render.place_cursor(f, row, modal_form::VALUE_COL as u16 + caret);
    }
}

/// Outer width of the nested field picker. Deliberately narrower than
/// [`MODAL_W`] so the nesting is legible: `render_chrome_in` centres on the
/// anchor, and both modals are handed the **same** anchor, so a narrower
/// popup sits concentrically inside the form it was opened from.
const PICKER_W: u16 = 46;

/// The nested "Select profile" / "Select group" popup as an Archetype-C
/// option list — opened by `Enter` on a select-only row **inside** the
/// Archetype-F form, and drawn after it.
///
/// ## Why Archetype C is right even though it nests
///
/// It is a picker, which is C's remit, and nesting turns out not to be a
/// third case:
///
/// - **Anchor.** It takes the same anchor as its parent form (the list
///   column). `overlay::centered_rect` centres within that rect, so a
///   narrower, shorter popup nests concentrically rather than needing the
///   form's own rect threaded down to it.
/// - **Z-order.** By draw order alone: `render_modal_overlay` renders the
///   form first, then this, and `render_chrome_in` renders `Clear` before
///   its block — so the form underneath is wiped, not blended.
/// - **Scrolling.** The hand-rolled `offset` arithmetic this replaced kept
///   the cursor visible by subtracting a window height it computed itself.
///   `notice_body` gives the focused `ChoiceRow` to `ScrollBody::focus_row`
///   and `render_scroll_body` tracks it — the same focus-following viewport
///   the form uses, and no keybinding changes because `picker.cursor`
///   already moves in state and every keystroke re-renders.
///
/// The one thing lost is the `●`/`○` radio glyph pair: the ecosystem focus
/// grammar is an emerald `▌` rule, a `bg_highlight` bar and a `◀` marker,
/// which is three signals to the radio pair's one, and only one of them is
/// colour. `brand_red` also leaves the border and the cursor row.
fn render_field_picker(f: &mut Frame, area: Rect, picker: &FieldPicker) {
    let spec = picker_notice(picker);
    modal_form::render_modal(f, area, PICKER_W, |w| {
        (modal_form::notice_body(&spec, w), ())
    });
}

/// The picker's Archetype-C spec.
///
/// With no options the list is empty, so the body is pure prose — which
/// `notice_body` marks `scrollable: false`, correctly suppressing a
/// scrollbar nothing could move. One prose row against a 6-row ceiling.
fn picker_notice(picker: &FieldPicker) -> modal_form::NoticeSpec {
    let (title, desc) = match picker.target {
        DeviceFormField::Profile => ("Select profile", "the policy bundle this device points at"),
        DeviceFormField::Group if picker.multi => (
            "Select groups",
            "every group this device belongs to \u{2014} Space toggles",
        ),
        DeviceFormField::Group => ("Select group", "the group this device belongs to"),
        _ => ("Select", ""),
    };

    let choices = picker
        .options
        .iter()
        .enumerate()
        .map(|(i, opt)| modal_form::ChoiceRow {
            // The empty string is the explicit clear option on the three
            // metadata pickers. It renders as a word rather than as a
            // blank row, which would read as a rendering bug.
            //
            // A multi-select picker must show membership on EVERY row,
            // not only on the one under the cursor — the focus grammar
            // (`\u{25c0}` + highlight bar) says "here", and the operator
            // also needs "chosen". A `[x]` / `[ ]` box carries that
            // without colour, which the ecosystem reserves for focus.
            label: if opt.is_empty() {
                "(none)".to_string()
            } else if picker.multi {
                let mark = if picker.selected.iter().any(|s| s == opt) {
                    '\u{00d7}'
                } else {
                    ' '
                };
                format!("[{mark}] {opt}")
            } else {
                opt.clone()
            },
            // Nothing to say about a bare id, and every option here is
            // choosable — the daemon's snapshot only ever holds live ones.
            detail: None,
            note: None,
            kind: ValueKind::Identity,
            focused: i == picker.cursor,
        })
        .collect();

    modal_form::NoticeSpec {
        title: title.to_string(),
        desc: desc.to_string(),
        prose: if picker.options.is_empty() {
            vec![ProseRow::plain("(none configured)")]
        } else {
            Vec::new()
        },
        choices,
        error: None,
        hint: String::new(),
        hint_rows: None,
        keys: if picker.multi {
            "[j/k] move \u{b7} [Space] toggle \u{b7} [Enter] confirm \u{b7} [Esc] cancel"
                .to_string()
        } else {
            "[j/k] move \u{b7} [Enter] select \u{b7} [Esc] cancel".to_string()
        },
        actions: Vec::new(),
    }
}

/// Destructive confirm, as an Archetype-C notice. Same frame as the form
/// (neutral, rounded, elevated) so the two read as one family.
///
/// Red is carried by the `y Delete` action alone — `ActionKind::Destructive`
/// paints it `red_glow` and **never fills it**: a filled red beside
/// a filled primary is how an operator deletes the thing they meant to keep.
/// The banded title stays neutral like every other band.
///
/// Both actions render unfocused because this modal genuinely has no focus
/// ring — `y`/`Enter` confirm, `n`/`Esc` cancel, handled in `tui::mod`
/// (unchanged, D7′). Marking one `focused` would put the emerald "you are
/// here" rule on a target no key can move off, so the keys ride in the
/// labels instead, and the legend states them a second time.
fn render_delete_confirm(f: &mut Frame, area: Rect, name: &str) {
    let spec = delete_notice(name);
    modal_form::render_modal(f, area, MODAL_W, |w| {
        (modal_form::notice_body(&spec, w), ())
    });
}

fn delete_notice(name: &str) -> modal_form::NoticeSpec {
    modal_form::NoticeSpec {
        title: "DELETE CLIENT".to_string(),
        desc: "The device loses its mapping and its stats.".to_string(),
        // The target names itself in the one row that cannot be mistaken
        // for chrome: `Blocking` is the destructive kind.
        prose: vec![ProseRow::emphasis(name.to_string(), ValueKind::Blocking)],
        choices: Vec::new(),
        error: None,
        hint: String::new(),
        hint_rows: None,
        // Deliberately a one-key confirm, unlike the Rules typed-id gate: a
        // device mapping is re-derivable from the unmapped list, so the
        // cost of a mistaken delete is its stats, not authored policy.
        keys: "[y / Enter] delete \u{b7} [n / Esc] cancel".to_string(),
        actions: vec![
            Action::new("  n  Cancel  ", false, ActionKind::Neutral, ""),
            Action::new("  y  Delete  ", false, ActionKind::Destructive, ""),
        ],
    }
}

#[cfg(test)]
#[path = "../tests/devices_tests.rs"]
mod tests;
