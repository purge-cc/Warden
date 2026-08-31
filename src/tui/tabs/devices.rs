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
//! poll (Sprint 22). The unified row builder runs on every render —
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
use ratatui::widgets::{Cell, Paragraph, Row, Table, Wrap};
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

pub fn render(f: &mut Frame, area: Rect, app: &App) {
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

    // N13 shared filter-card frame sits above the list, inside the list
    // column only — the detail card on the right stays uncovered, same
    // reasoning `render_modal_overlay` below already documents for the
    // form modal.
    let list_rows = Layout::vertical([Constraint::Length(3), Constraint::Min(5)]).split(cols[0]);
    render_subnet_filter_card(f, list_rows[0], app, filter_status);
    render_list_panel(f, list_rows[1], app, view, &rows, selected, now_secs);
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

/// N13 shared filter-card frame (`theme::render_filter_card`), same
/// chrome as Query Log / Lists / Rules / Tags: rounded
/// `T.text_primary` frame, height 3, no interior title — the field is
/// the label. Devices has one field, not a search + chip pair, because
/// there is exactly one dimension to narrow on (§ the operator's
/// request was "one subnet at a time").
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

    let line = Line::from(vec![
        Span::styled("Subnet [/]: ", Style::default().fg(T.text_muted)),
        Span::styled(shown, value_style),
        Span::styled(note, Style::default().fg(T.error)),
        Span::styled("   [R] clear", Style::default().fg(T.text_muted)),
    ]);
    f.render_widget(Paragraph::new(line), content_area);
}

// ── Unified list panel ──────────────────────────────────────────────

fn render_list_panel(
    f: &mut Frame,
    area: Rect,
    app: &App,
    view: &DeviceViewDto,
    rows: &[DeviceRow],
    selected: Option<usize>,
    now_secs: u64,
) {
    let title = format!(
        "Devices ({} mapped \u{00b7} {} unmapped) \u{00b7} group: {}",
        view.mapped.len(),
        view.unmapped.len(),
        app.devices.group_by.label(),
    );
    let content_area = render_section_chrome(f, area, &title, T.brand_red);

    let header = Row::new(vec![
        Cell::from("IDENTITY"),
        Cell::from("IP"),
        Cell::from("PROFILE"),
        Cell::from("Q.TODAY"),
        Cell::from("BLOCK%"),
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
    const BLOCK_W: u16 = 7;
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

    // Snap a possibly-stale selection (left over from a previous
    // group_by snapshot) to a valid selectable row before rendering.
    let mut table_state = app.devices.table_state.clone();
    table_state.select(selected);

    let table = Table::new(table_rows, constraints)
        .header(header)
        .column_spacing(COLUMN_SPACING)
        .row_highlight_style(theme::highlight_style());

    f.render_stateful_widget(table, content_area, &mut table_state);

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
    // Sprint C T4 of `lists_categories_v2` (D14, §8.1): the
    // `[⚠ UNFILTERED]` badge surfaces D14 opt-out devices in the row
    // identity so the operator spots them without opening the card.
    // Warning palette per _docs/rules/TUI_DESIGN.md §Semantic.
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
/// rev-2607 (#14): uses `label.chars().count()`, not `label.len()`.
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
    // The "Tag propri" / "Tag ereditati" pair stood here until `plp-s5a`.
    // Both were projections of `tags` arrays the schema no longer has, so
    // keeping them would have meant two rows that can only ever read "—" —
    // a card teaching an inheritance relation that does not exist. The
    // `[⚠ UNFILTERED]` badge, which is what their `unfiltered` branch was
    // really about, is rendered independently below.
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
/// them. §4.64 G4 made the second one false — the Edit modal now holds
/// the whole list — and a hint that mis-states where an operator must go
/// is worse than no hint, because it sends them somewhere else.
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

/// Notes line on the side card. Long notes are truncated at ~60 bytes
/// with an ellipsis so the line stays single-row; the operator can see
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
/// Kept as a sibling of `build_rows` rather than a parameter added to
/// it: `mod.rs::handle_devices_key` calls `build_rows(view,
/// group_by)` directly to resolve the selection/mutation target for
/// `↑`/`↓`/`Enter`/`e`/`d`, and that call site is outside this lane's
/// ownership (CONTRACT.md — Lane C owns only this file). Changing
/// `build_rows`'s signature would break a file this lane cannot edit.
///
/// **Integrator note — read before wiring a key to `filter_subnet`:**
/// the keybinding must land in the same commit as switching
/// `mod.rs::handle_devices_key`'s `build_rows(view, app.devices.group_by)`
/// call to `build_filtered_rows(view, app.devices.group_by,
/// app.devices.filter_subnet.as_deref()).0`. Landing the keybinding
/// alone makes the on-screen row set and the row set `Enter`/`e`/`d`
/// mutate diverge — a stale index can open the edit/delete modal for a
/// device that isn't even on screen. See this lane's final report.
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

// ── Modal overlay (Sprint 23 s23-tui-clients-modal-form) ──────────

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
/// measures the modal for itself. The **row count must not vary with it**
/// (contract §2.1): every builder called below returns a fixed number of
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
/// Two colour-rule corrections land here, both §4.1's original ask for this
/// file. `Cancel` used to take a `brand_red` fill on focus — a filled red
/// beside a filled `Save` is how an operator discards work they meant to
/// keep — and is now `ActionKind::Neutral`. `Save` becomes the modal's one
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
/// open (chrome-v2 D6, a documented sub-case of D18).
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
/// colour. `brand_red` also leaves the border and the cursor row (D15).
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
            // §4.66 L3: the empty string is the explicit clear option on the
            // three metadata pickers. It renders as a word rather than as a
            // blank row, which would read as a rendering bug.
            //
            // §4.64 G4: a multi-select picker must show membership on EVERY
            // row, not only on the one under the cursor — the focus grammar
            // (`\u{25c0}` + highlight bar) says "here", and the operator also
            // needs "chosen". A `[x]` / `[ ]` box carries that without
            // colour, which the ecosystem reserves for focus.
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
/// paints it `red_glow` and, per §5, **never fills it**: a filled red beside
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
        keys: "[y / Enter] delete \u{b7} [n / Esc] cancel".to_string(),
        actions: vec![
            Action::new("  n  Cancel  ", false, ActionKind::Neutral, ""),
            Action::new("  y  Delete  ", false, ActionKind::Destructive, ""),
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk_mapped(name: &str, ip: &str, owner: Option<&str>) -> MappedDeviceDto {
        MappedDeviceDto {
            ip: ip.into(),
            name: name.into(),
            mac: Some("AA:BB:CC:DD:EE:FF".into()),
            mac_aliases: vec![],
            profile: "default".into(),
            owner: owner.map(|s| s.into()),
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
            hourly_queries: Vec::new(),
            unfiltered: false,
        }
    }

    fn mk_unmapped(ip: &str) -> UnmappedDeviceDto {
        UnmappedDeviceDto {
            ip: ip.into(),
            mac: None,
            queries: 0,
            queries_today: 0,
            blocked: 0,
            blocked_24h: 0,
            last_seen: 0,
            online: false,
            vendor: None,
            hourly_queries: Vec::new(),
        }
    }

    // mem2608-s3 / F-P, fifth site. queries=100, blocked=60, cache_hits=20.
    //
    // Pre-fix the denominator was `queries`: 20/100 = 20.0%. The cacheable
    // denominator is queries-blocked = 40: 20/40 = 50.0%. The two are far
    // apart on purpose — a fixture where they differ only in the last decimal
    // would pass against either form and pin nothing.
    //
    // The `Blocked` assertion is the CONTROL ARM, and it is why this test is
    // worth more than an equality check on one number. `block_pct` is
    // correctly computed over ALL queries and must stay that way, so a change
    // that "fixed" both ratios would be an overreach — and would still satisfy
    // the cache assertion on its own. Pinning 60.0% is what makes that
    // overreach fail instead of passing quietly.
    #[test]
    fn cache_rate_excludes_blocked_queries_but_block_rate_does_not() {
        let mut d = mk_mapped("dev", "192.0.2.10", None);
        d.queries = 100;
        d.blocked = 60;
        d.cache_hits = 20;

        let text: String = mapped_card_lines(&d, 0)
            .iter()
            .map(|l| {
                l.spans
                    .iter()
                    .map(|s| s.content.as_ref())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n");

        assert!(
            text.contains("20  (50.0%)"),
            "cache rate must divide by cacheable (queries - blocked = 40), not by all 100 \
             queries: otherwise a device shows its WORST cache rate precisely when filtering \
             works best. got:\n{text}"
        );
        assert!(
            !text.contains("20  (20.0%)"),
            "cache rate still divides by total queries — the pre-fix form. got:\n{text}"
        );
        assert!(
            text.contains("60  (60.0%)"),
            "block rate must stay over ALL queries — it is not part of the cache-rate family, \
             and widening this fix to cover it would be an overreach. got:\n{text}"
        );
    }

    // dev-03: build_rows is name-sorted and rebuilt every poll. A device
    // inserted ahead of the selected one shifts its index, but the stable
    // key must still resolve to the SAME device — not whatever now sits
    // at the old index. This is the selection-drift the bare TableState
    // index suffered.
    #[test]
    fn selection_anchors_to_device_key_across_poll_reshuffle() {
        let view = DeviceViewDto {
            mapped: vec![
                mk_mapped("bravo", "10.0.0.2", None),
                mk_mapped("charlie", "10.0.0.3", None),
            ],
            unmapped: vec![],
        };
        let rows = build_rows(&view, DeviceGroupBy::None);
        let charlie_idx = rows
            .iter()
            .position(|r| matches!(r, DeviceRow::Mapped(m) if m.name == "charlie"))
            .unwrap();
        let key = row_key(&rows[charlie_idx]);

        // A poll inserts "alpha", which name-sorts first and pushes
        // charlie down a row.
        let view2 = DeviceViewDto {
            mapped: vec![
                mk_mapped("alpha", "10.0.0.1", None),
                mk_mapped("bravo", "10.0.0.2", None),
                mk_mapped("charlie", "10.0.0.3", None),
            ],
            unmapped: vec![],
        };
        let rows2 = build_rows(&view2, DeviceGroupBy::None);
        let resolved = crate::tui::app::resolve_row_index(&rows2, key.as_ref(), row_key).unwrap();
        assert_ne!(
            resolved, charlie_idx,
            "the insertion should have shifted charlie's index"
        );
        match &rows2[resolved] {
            DeviceRow::Mapped(m) => assert_eq!(m.name, "charlie"),
            other => panic!("stable key resolved to the wrong row: {other:?}"),
        }
        // A bare positional index would now point at the wrong device.
        if let DeviceRow::Mapped(m) = &rows2[charlie_idx] {
            assert_ne!(m.name, "charlie");
        }
    }

    fn subnet_filter_fixture() -> DeviceViewDto {
        DeviceViewDto {
            mapped: vec![
                mk_mapped("alpha", "192.0.2.5", None),
                mk_mapped("bravo", "192.0.2.9", None),
                mk_mapped("charlie", "10.10.2.5", None),
            ],
            unmapped: vec![mk_unmapped("192.0.2.20"), mk_unmapped("10.10.3.1")],
        }
    }

    fn mapped_names(rows: &[DeviceRow]) -> Vec<&str> {
        rows.iter()
            .filter_map(|r| match r {
                DeviceRow::Mapped(m) => Some(m.name.as_str()),
                _ => None,
            })
            .collect()
    }

    fn unmapped_ips(rows: &[DeviceRow]) -> Vec<&str> {
        rows.iter()
            .filter_map(|r| match r {
                DeviceRow::Unmapped(u) => Some(u.ip.as_str()),
                _ => None,
            })
            .collect()
    }

    // Before `build_filtered_rows` existed, the only row builder was
    // `build_rows`, which has no filter parameter — it always returns
    // every device, so a caller had no way to narrow the list to one
    // CIDR at all. This pins the narrowing itself: with the filter set,
    // only alpha/bravo (192.0.2.0/24) and their unmapped sibling survive
    // — charlie (10.10.2.5) and the unmapped 10.10.3.1 must not.
    #[test]
    fn subnet_filter_narrows_to_matching_cidr() {
        let view = subnet_filter_fixture();
        let (rows, status) = build_filtered_rows(&view, DeviceGroupBy::None, Some("192.0.2.0/24"));

        assert_eq!(status, SubnetFilterStatus::Active);
        assert_eq!(mapped_names(&rows), vec!["alpha", "bravo"]);
        assert_eq!(unmapped_ips(&rows), vec!["192.0.2.20"]);
    }

    // Clearing the filter (`None`) must restore every row — the DoD's
    // "clearing it restores every row" bullet. Also pins that `None`
    // produces exactly what `build_rows` alone would.
    #[test]
    fn subnet_filter_none_restores_every_row() {
        let view = subnet_filter_fixture();
        let (filtered_rows, status) = build_filtered_rows(&view, DeviceGroupBy::None, None);
        let (baseline_rows, _) =
            build_filtered_rows(&view, DeviceGroupBy::None, Some("192.0.2.0/24"));
        assert_ne!(
            filtered_rows.len(),
            baseline_rows.len(),
            "sanity: the filtered fixture must actually drop rows, or this test proves nothing"
        );

        assert_eq!(status, SubnetFilterStatus::Inactive);
        assert_eq!(filtered_rows, build_rows(&view, DeviceGroupBy::None));
        assert_eq!(
            mapped_names(&filtered_rows),
            vec!["alpha", "bravo", "charlie"]
        );
        assert_eq!(
            unmapped_ips(&filtered_rows),
            vec!["10.10.3.1", "192.0.2.20"]
        );
    }

    // An unparseable CIDR must not read as "zero devices in this
    // subnet" — that is silent data loss. The full list stays visible
    // and the status flags the failure so the card can say so.
    #[test]
    fn subnet_filter_invalid_cidr_keeps_every_row_visible() {
        let view = subnet_filter_fixture();
        let (rows, status) = build_filtered_rows(&view, DeviceGroupBy::None, Some("not-a-cidr"));

        assert_eq!(status, SubnetFilterStatus::Invalid);
        assert_eq!(rows, build_rows(&view, DeviceGroupBy::None));
    }

    fn dump(buf: &ratatui::buffer::Buffer) -> String {
        let mut out = String::new();
        for y in 0..buf.area.height {
            for x in 0..buf.area.width {
                out.push_str(buf[(x, y)].symbol());
            }
            out.push('\n');
        }
        out
    }

    // ── F7 · the row budget at the declared floor ────────────────────
    //
    // Three anchors exist for this modal and only one of them is
    // production's, so a test that picks the wrong one measures nothing:
    //
    //   f.area()            the whole frame — what the audit's repro used
    //   the D18 content rect  what `ui.rs:498` hands `devices::render`
    //   `cols[0]`           the LIST column — what `render` actually
    //                       anchors the modal on (chrome-v2 D6), a
    //                       sub-rect of the content rect
    //
    // These helpers go through `render`, so the anchor is `cols[0]`
    // derived by the same `Layout` the operator's terminal derives it
    // with. A backend of 80×14 therefore reproduces the Network/Filtering
    // content rect at `MIN_WIDTH 80` × `MIN_HEIGHT 24` exactly:
    // 24 − 4 header − 5 menu card − 1 footer = 14.

    /// Render the whole tab — list, side card, modal — at `w`×`h` with
    /// `modal` open, exactly as `ui.rs` drives it.
    fn render_tab_at(w: u16, h: u16, modal: DeviceModal) -> String {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;
        let mut app = App::new();
        app.device_view = Some(DeviceViewDto {
            mapped: vec![mk_mapped("kitchen-tv", "192.0.2.50", Some("alex"))],
            unmapped: vec![mk_unmapped("192.0.2.77")],
        });
        app.devices.modal = Some(modal);
        let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
        term.draw(|f| render(f, f.area(), &app)).unwrap();
        dump(term.backend().buffer())
    }

    /// A form of `mode` whose focus sits on the LAST field in the ring,
    /// carrying a needle no other row can produce.
    ///
    /// `notes` is deliberate: it is the bottom of the second section, so
    /// it is the first thing a bottom-cut takes and the last thing a
    /// focus-tracking viewport has to fetch. The value is the needle
    /// rather than the label, per the `"tags"`-matched-the-band trap —
    /// a label needle can match a section band or a hint.
    fn form_focused_on_last_field(mode: DeviceFormMode) -> DeviceFormState {
        let mut form = match mode {
            DeviceFormMode::Add => DeviceFormState::new_add(),
            DeviceFormMode::Edit => edit_form("Kitchen TV", Some("kitchen-tv")),
            DeviceFormMode::Promote => {
                DeviceFormState::new_promote("192.0.2.77".into(), "aa:bb:cc:dd:ee:ff".into())
            }
        };
        form.notes = "ZZQQ".to_string();
        form.focused = DeviceFormFocus::Field(DeviceFormField::Notes);
        form
    }

    /// The two things a clip can silently take, asserted **together**.
    ///
    /// Needles chosen to discriminate, not merely to match:
    ///
    /// - `"  Save  "` with its padding, never bare `Save` — the nav
    ///   legend already says `Enter open/save`, so a substring match on
    ///   the word would pass with the action row cut clean off.
    /// - `"ZZQQ"`, the operator's own buffer in the focused field, never
    ///   the label `notes` — `assert!(contains("notes"))` would also
    ///   match a hint or a band.
    /// - the legend itself, so a failure says *which* row was missing
    ///   instead of leaving both candidates open.
    fn assert_action_row_and_focus_on_screen(out: &str, mode: DeviceFormMode) {
        assert!(
            out.contains("  Save  "),
            "{mode:?}: the action row's Save is off screen \
             (bare \"Save\" would have matched the nav legend):\n{out}"
        );
        assert!(
            out.contains("  Cancel  "),
            "{mode:?}: the action row's Cancel is off screen:\n{out}"
        );
        assert!(
            out.contains("ZZQQ"),
            "{mode:?}: the FOCUSED field's value is off screen while Tab \
             still reaches it \u{2014} the operator types blind:\n{out}"
        );
    }

    /// **F7.** At the declared floor the form must still show the action
    /// row and the focused field simultaneously, in all three stages.
    ///
    /// Fails before the Archetype-F migration: `render_chrome_in(…, 28, …)`
    /// asks for 28 rows, `centered_rect` clamps to 14, and
    /// `render_body_fixed` has no viewport — so the body is cut after 12
    /// rows while `DeviceFormFocus::Save` stays in the ring. The operator
    /// commits or discards blind.
    #[test]
    fn floor_form_keeps_its_action_row_and_focused_field_in_every_mode() {
        for mode in [
            DeviceFormMode::Add,
            DeviceFormMode::Edit,
            DeviceFormMode::Promote,
        ] {
            let out = render_tab_at(80, 14, DeviceModal::Form(form_focused_on_last_field(mode)));
            assert_action_row_and_focus_on_screen(&out, mode);
        }
    }

    /// This file owns the **tab**, not only the modal. The migration
    /// rewrote its imports and its shared row vocabulary, so pin the three
    /// tab-level affordances the modal work could plausibly have broken:
    /// the side detail card, the group-by header rows (`G`), and the
    /// promote-unmapped path's read-only pins.
    #[test]
    fn the_tab_itself_still_renders_card_grouping_and_the_promote_path() {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;

        // Side card + group-by headers, no modal open.
        let mut app = App::new();
        app.device_view = Some(DeviceViewDto {
            mapped: vec![
                mk_mapped("kitchen-tv", "192.0.2.50", Some("alex")),
                mk_mapped("study-pi", "192.0.2.51", Some("ada")),
            ],
            unmapped: vec![mk_unmapped("192.0.2.77")],
        });
        app.devices.group_by = DeviceGroupBy::Owner;
        // 160 wide, not 100: the identity column is `Constraint::Min(15)` and
        // flexes, so at 100 cols the header row truncates to
        // `── Owner: edoar` and an assertion on the owner's name would fail
        // for a reason that has nothing to do with grouping.
        let mut term = Terminal::new(TestBackend::new(160, 30)).unwrap();
        term.draw(|f| render(f, f.area(), &app)).unwrap();
        let out = dump(term.backend().buffer());
        assert!(
            out.contains("group: owner"),
            "group-by in the title:\n{out}"
        );
        assert!(
            out.contains("Owner: ada") && out.contains("Owner: alex"),
            "grouping must insert one header row per owner:\n{out}"
        );
        // The card renders the highlighted row's full field set; `Status` is
        // a card-only label, so it discriminates the card from the table.
        assert!(out.contains("Status"), "side detail card:\n{out}");

        // Promote pins ip + mac from the ARP snapshot — both inert.
        let promote = DeviceFormState::new_promote("192.0.2.77".into(), "aa:bb:cc:dd:ee:ff".into());
        let out = render_tab_at(80, 30, DeviceModal::Form(promote));
        assert!(
            out.contains("PROMOTE UNMAPPED CLIENT"),
            "promote title band:\n{out}"
        );
        assert!(
            out.contains("192.0.2.77") && out.contains("aa:bb:cc:dd:ee:ff"),
            "the pinned ip and mac render:\n{out}"
        );
    }

    /// Write `v` into `field`'s buffer. Test-only: production never needs a
    /// setter, because `tui::mod`'s key handler owns the buffers directly.
    fn set_field(form: &mut DeviceFormState, field: DeviceFormField, v: &str) {
        let slot = match field {
            DeviceFormField::Name => &mut form.name,
            DeviceFormField::Ip => &mut form.ip,
            DeviceFormField::Mac => &mut form.mac,
            DeviceFormField::MacAliases => &mut form.mac_aliases,
            DeviceFormField::Profile => &mut form.profile,
            DeviceFormField::Group => &mut form.groups,
            DeviceFormField::Owner => &mut form.owner,
            DeviceFormField::Device => &mut form.device_type,
            DeviceFormField::Department => &mut form.department,
            DeviceFormField::Notes => &mut form.notes,
            DeviceFormField::NetworkName => &mut form.network_name,
            DeviceFormField::NetworkNameWildcard => &mut form.network_name_wildcard,
        };
        *slot = v.to_string();
    }

    /// The ecosystem colour rule, asserted against the rendered buffer.
    ///
    /// The sibling surfaces pin this with a file-wide source scan
    /// (`subnet_modal::no_hand_rolled_colour_in_this_module`), which cannot
    /// work here: this file owns the **tab** as well as the modal, and the
    /// list rows and the detail card hand-roll colour legitimately — §1.1 of
    /// the design doc rules those out of scope explicitly. So this asserts
    /// the same rule one level down, on the pixels, which is the stronger
    /// form anyway: whatever the source does, the modal must *render*
    /// teal for static structure, emerald for the one live focus, and a
    /// neutral frame.
    #[test]
    fn the_form_renders_the_teal_emerald_colour_rule() {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;

        let mut form = edit_form("Kitchen TV", Some("kitchen-tv"));
        form.notes = "ZZQQ".to_string();
        form.focused = DeviceFormFocus::Field(DeviceFormField::Notes);
        let mut app = App::new();
        app.devices.modal = Some(DeviceModal::Form(form));
        let mut term = Terminal::new(TestBackend::new(80, 30)).unwrap();
        term.draw(|f| {
            render_modal_overlay(f, ratatui::layout::Rect::new(0, 0, 80, 30), &app);
        })
        .unwrap();
        let buf = term.backend().buffer();
        let out = dump(buf);

        // Column lookups by CHARACTER, never `str::find` — the frame's `│`
        // is 3 UTF-8 bytes and a byte offset lands 2 cells right.
        let col_in = |row: u16, glyph: char| {
            out.lines()
                .nth(row as usize)
                .unwrap()
                .chars()
                .position(|c| c == glyph)
                .map(|c| c as u16)
        };
        let row_with = |needle: &str| {
            out.lines()
                .position(|l| l.contains(needle))
                .map(|r| r as u16)
                .unwrap_or_else(|| panic!("{needle:?} not on screen:\n{out}"))
        };

        // warden_teal — static structure. Both section headers.
        for band in ["IDENTITY \u{b7} NETWORK", "ASSIGNMENTS & METADATA"] {
            let row = row_with(band);
            let x = col_in(row, band.chars().next().unwrap()).unwrap();
            assert_eq!(
                buf[(x, row)].fg,
                T.warden_teal,
                "section band {band:?} must be warden_teal:\n{out}"
            );
        }

        // emerald_ping — the ONE live focus, on the focused row's rule.
        let focus_row = row_with("ZZQQ");
        let rule_x = col_in(focus_row, '\u{258c}')
            .unwrap_or_else(|| panic!("the focused row draws no \u{258c} rule:\n{out}"));
        assert_eq!(
            buf[(rule_x, focus_row)].fg,
            T.emerald_ping,
            "the focused row's rule must be emerald_ping:\n{out}"
        );
        // ...and it is the ONLY emerald rule in the field region: "the one
        // live focus" is a cardinality claim, not just a colour one.
        let emerald_rules = (0..buf.area.height)
            .flat_map(|y| (0..buf.area.width).map(move |x| (x, y)))
            .filter(|&(x, y)| {
                buf[(x, y)].symbol() == "\u{258c}" && buf[(x, y)].fg == T.emerald_ping
            })
            .count();
        assert_eq!(
            emerald_rules, 1,
            "exactly one emerald focus rule may be on screen:\n{out}"
        );

        // Save is the modal's one filled action: warden_teal fill, inverse
        // label. Cancel is colour-only, so nothing else carries that fill.
        let action_row = row_with("  Save  ");
        let save_x = out
            .lines()
            .nth(action_row as usize)
            .unwrap()
            .chars()
            .collect::<String>()
            .find("  Save  ")
            .map(|b| {
                // ASCII-only prefix here, so byte == char, but derive it the
                // safe way regardless.
                out.lines().nth(action_row as usize).unwrap()[..b]
                    .chars()
                    .count() as u16
            })
            .unwrap();
        let fill = &buf[(save_x + 2, action_row)];
        assert_eq!(
            (fill.bg, fill.fg),
            (T.warden_teal, T.text_inverse),
            "Save is the one ActionKind::Primary — teal fill, inverse label:\n{out}"
        );

        // The frame stays neutral grey (D15).
        let top = row_with("\u{256d}");
        let left = col_in(top, '\u{256d}').unwrap();
        let right = col_in(top, '\u{256e}').unwrap();
        for x in left..=right {
            assert_eq!(
                buf[(x, top)].fg,
                T.text_primary,
                "border cell ({x},{top}) is not the neutral frame:\n{out}"
            );
        }
    }

    /// **The invariant, not a sample of it.** `floor_form_keeps_…` above
    /// pins the *last* field, which is the worst case for a bottom-cut — but
    /// the guarantee `ScrollBody` exists to provide is that **no** focusable
    /// target is ever off screen, so walk every stop in every stage.
    ///
    /// A per-stop unique needle is what makes this buffer-level rather than
    /// a re-derivation of `scroll_layout` in the test. Recomputing the
    /// renderer's own arithmetic and comparing it to itself would pass
    /// whether or not the widget honoured it — the failure mode that let a
    /// wrapping bug ship here with every unit test green.
    #[test]
    fn no_focusable_target_is_ever_off_screen_at_the_floor() {
        for mode in [
            DeviceFormMode::Add,
            DeviceFormMode::Edit,
            DeviceFormMode::Promote,
        ] {
            let base = form_focused_on_last_field(mode);

            for field in DeviceFormState::FIELDS {
                // A locked row is not in the ring (`focus_ring` filters it),
                // so it is not a focusable target and cannot be a defect.
                if base.is_locked(field) {
                    continue;
                }
                let mut form = base.clone();
                set_field(&mut form, field, "ZQ7X");
                form.focused = DeviceFormFocus::Field(field);

                let out = render_tab_at(80, 14, DeviceModal::Form(form));
                assert!(
                    out.contains("ZQ7X"),
                    "{mode:?}/{field:?}: the focused field is off screen at the \
                     floor while Tab still reaches it:\n{out}"
                );
                assert!(
                    out.contains("  Save  "),
                    "{mode:?}/{field:?}: the action row is off screen at the \
                     floor:\n{out}"
                );
            }

            // The two action stops. Their own row is pinned by
            // `scroll_layout`, so what matters is that focus on an action
            // does not cost the field region its viewport.
            for stop in [DeviceFormFocus::Cancel, DeviceFormFocus::Save] {
                let mut form = base.clone();
                form.focused = stop;
                let out = render_tab_at(80, 14, DeviceModal::Form(form));
                assert!(
                    out.contains("  Save  ") && out.contains("  Cancel  "),
                    "{mode:?}/{stop:?}: the action row is off screen at the floor:\n{out}"
                );
            }
        }
    }

    /// The control arm. Passes before *and* after the migration — which is
    /// what makes the 80×14 arm above evidence rather than decoration: it
    /// proves the defect is the row budget and not the fixture.
    #[test]
    fn control_arm_form_is_complete_when_the_terminal_has_room() {
        for mode in [
            DeviceFormMode::Add,
            DeviceFormMode::Edit,
            DeviceFormMode::Promote,
        ] {
            let out = render_tab_at(80, 30, DeviceModal::Form(form_focused_on_last_field(mode)));
            assert_action_row_and_focus_on_screen(&out, mode);
        }
    }

    fn render_picker_at(w: u16, h: u16, picker: &FieldPicker) -> String {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;
        let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
        term.draw(|f| {
            render_field_picker(f, ratatui::layout::Rect::new(0, 0, w, h), picker);
        })
        .unwrap();
        dump(term.backend().buffer())
    }

    /// The picker's cursor row must be marked with the **ecosystem** focus
    /// grammar, not the retired `●`/`○` radio pair: an emerald `▌` rule
    /// replacing the lead indent, and a `◀` marker closing the row.
    #[test]
    fn field_picker_renders_options_with_cursor_marker() {
        let picker = FieldPicker {
            target: DeviceFormField::Profile,
            options: vec!["default".into(), "kids".into(), "guest".into()],
            cursor: 1,
            multi: false,
            selected: Vec::new(),
        };
        let out = render_picker_at(60, 20, &picker);
        assert!(out.contains("Select profile"), "title missing:\n{out}");
        assert!(
            out.contains("default") && out.contains("kids") && out.contains("guest"),
            "options missing:\n{out}"
        );
        assert!(
            out.contains('\u{258c}'),
            "focus rule \u{258c} missing:\n{out}"
        );
        assert!(
            out.contains('\u{25c0}'),
            "focus marker \u{25c0} missing:\n{out}"
        );
        // The marker must be on the CURSOR's row, not merely somewhere on
        // screen — the whole point of a cursor.
        let cursor_row = out
            .lines()
            .find(|l| l.contains("kids"))
            .expect("the cursor's option renders");
        assert!(
            cursor_row.contains('\u{258c}') && cursor_row.contains('\u{25c0}'),
            "focus grammar landed on a row other than the cursor's:\n{out}"
        );
    }

    /// §4.64 G4: the multi-select picker must show membership on EVERY
    /// row and advertise the key that changes it. The focus grammar says
    /// "here"; it cannot also say "chosen", and a picker where the
    /// operator cannot see what is selected is how a Save silently drops
    /// a group — which is the defect G4 closed.
    #[test]
    fn multi_picker_boxes_every_row_and_names_the_toggle_key() {
        let picker = FieldPicker {
            target: DeviceFormField::Group,
            options: vec!["phones".into(), "kids".into(), "iot".into()],
            cursor: 0,
            multi: true,
            selected: vec!["phones".into(), "iot".into()],
        };
        let out = render_picker_at(60, 20, &picker);
        assert!(out.contains("Select groups"), "plural title:\n{out}");
        for (name, want) in [
            ("phones", "[\u{00d7}]"),
            ("kids", "[ ]"),
            ("iot", "[\u{00d7}]"),
        ] {
            let row = out
                .lines()
                .find(|l| l.contains(name))
                .unwrap_or_else(|| panic!("option {name} missing:\n{out}"));
            assert!(
                row.contains(want),
                "row for {name} must carry {want}:\n{out}"
            );
        }
        assert!(
            out.contains("[Space] toggle"),
            "the toggle key must be named — nothing else reveals it:\n{out}"
        );
    }

    /// The single-select picker keeps its bare labels: a checkbox there
    /// would promise a multiple choice the field cannot hold.
    #[test]
    fn single_picker_draws_no_checkboxes() {
        let picker = FieldPicker {
            target: DeviceFormField::Group,
            options: vec!["phones".into(), "kids".into()],
            cursor: 0,
            multi: false,
            selected: Vec::new(),
        };
        let out = render_picker_at(60, 20, &picker);
        assert!(!out.contains("[\u{00d7}]") && !out.contains("[ ]"), "{out}");
        assert!(out.contains("[Enter] select"), "{out}");
    }

    /// The side card names every membership. It used to name the first
    /// and add `+N more (CLI)` — a hint that now points the operator at
    /// the wrong tool, since the Edit modal holds the whole list.
    #[test]
    fn side_card_group_line_lists_every_membership() {
        let line = group_line(&["phones".to_string(), "kids".to_string()]);
        let text: String = line.spans.iter().map(|s| s.content.as_ref()).collect();
        assert!(text.contains("phones") && text.contains("kids"), "{text}");
        assert!(
            !text.contains("(CLI)"),
            "the CLI-only claim is false since G4:\n{text}"
        );
    }

    /// An empty option list is pure prose, so `notice_body` marks it
    /// unscrollable and draws no bar — a scrollbar there would advertise a
    /// control no keystroke can operate.
    #[test]
    fn field_picker_with_no_options_says_so_and_draws_no_scrollbar() {
        let picker = FieldPicker {
            target: DeviceFormField::Group,
            options: Vec::new(),
            cursor: 0,
            multi: false,
            selected: Vec::new(),
        };
        let out = render_picker_at(60, 20, &picker);
        assert!(out.contains("Select group"), "title missing:\n{out}");
        assert!(out.contains("(none configured)"), "empty copy:\n{out}");
        assert!(
            !out.contains('\u{2588}'),
            "a prose-only body must draw no scrollbar thumb:\n{out}"
        );
    }

    /// The picker is nested inside an Archetype-F form and takes the SAME
    /// anchor, so it must land concentrically inside it rather than
    /// covering it edge to edge — and it must still show its option list
    /// and its key legend at the declared floor.
    #[test]
    fn floor_nested_picker_stays_inside_its_parent_form() {
        let mut form =
            DeviceFormState::new_add().with_options(vec!["default".into(), "kids".into()], vec![]);
        form.focused = DeviceFormFocus::Field(DeviceFormField::Profile);
        form.picker = Some(FieldPicker {
            target: DeviceFormField::Profile,
            options: form.profiles_snapshot.clone(),
            cursor: 1,
            multi: false,
            selected: Vec::new(),
        });
        let out = render_tab_at(80, 14, DeviceModal::Form(form));

        assert!(
            out.contains("Select profile"),
            "the picker is off screen at the floor:\n{out}"
        );
        assert!(
            out.contains("kids"),
            "the cursor's option is off screen at the floor:\n{out}"
        );
        assert!(
            out.contains("[Enter] select"),
            "the key legend is off screen at the floor:\n{out}"
        );
        // PICKER_W 46 < MODAL_W 60 on a shared anchor, so the form's own
        // frame must survive on both sides of the popup. Its title band is
        // the discriminating needle: the picker cannot produce it.
        assert!(
            out.contains("ADD CLIENT"),
            "the parent form's frame was covered edge to edge:\n{out}"
        );
    }

    // rev-2607 (#14): the group-header divider must size its dash fill
    // by display *characters*, not UTF-8 *bytes* — the label comes from
    // operator-supplied owner/department/profile strings.
    #[test]
    fn group_header_dash_count_uses_chars_not_bytes() {
        // "日本" is 2 chars but 6 UTF-8 bytes. A byte-length bug would
        // subtract 4 extra columns it shouldn't, coming out short
        // relative to a same-char-count ASCII label ("ab").
        assert_eq!(
            group_header_dash_count("\u{65e5}\u{672c}", 40),
            group_header_dash_count("ab", 40),
            "a 2-char multi-byte label must yield the same dash_count as a 2-char ASCII label"
        );
        // Pin the actual number too: width 40, 2-char label, fixed
        // "── {label} " overhead of 4 columns → 40 - (2 + 4) = 34.
        assert_eq!(group_header_dash_count("\u{65e5}\u{672c}", 40), 34);
    }

    /// `picker_popup_size` and its two floor/clamp tests are gone with the
    /// Archetype-C migration: the popup no longer sizes itself from its
    /// content, `render_modal` derives its height from the spec's row count
    /// and `centered_rect` does the clamping. What those tests protected —
    /// "a one-option list must not collapse to a sliver" — is now
    /// structural: head 2 + tail 1 is the floor whatever the option count.
    #[test]
    fn one_option_picker_is_still_a_readable_dialog() {
        let picker = FieldPicker {
            target: DeviceFormField::Profile,
            options: vec!["default".into()],
            cursor: 0,
            multi: false,
            selected: Vec::new(),
        };
        let out = render_picker_at(80, 30, &picker);
        assert!(out.contains("Select profile"), "title band:\n{out}");
        assert!(out.contains("default"), "the single option:\n{out}");
        assert!(out.contains("[Enter] select"), "the key legend:\n{out}");
    }

    /// Build an Edit form with every field named, so a render assertion
    /// can tell one column from another.
    fn edit_form(name: &str, original_id: Option<&str>) -> DeviceFormState {
        DeviceFormState::new_edit(
            name.to_string(),
            "192.0.2.50".to_string(),
            "a4:5e:60:11:22:33".to_string(),
            String::new(),
            "kids".to_string(),
            "living-room".to_string(),
            "alex".to_string(),
            "tv".to_string(),
            String::new(),
            String::new(),
            // Deliberately NOT the `original_id` the callers pass
            // ("kitchen-tv"): Edit does not render the id, so a fixture
            // that echoed it here would make `out.contains("kitchen-tv")`
            // succeed off the net-name row and quietly prove the opposite
            // of what an id-preview assertion means to check.
            "kitchentv-net".to_string(),
            "false".to_string(),
        )
        .with_original_id(original_id.map(|s| s.to_string()))
    }

    /// Render a form modal into an 80x30 backend and flatten the buffer.
    /// `dump` drops styling, which is what we want — ratatui splits styled
    /// text across spans, so asserting on raw cells is unreliable.
    fn render_form_to_string(form: DeviceFormState) -> String {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;
        let mut app = App::new();
        app.devices.modal = Some(DeviceModal::Form(form));
        let mut term = Terminal::new(TestBackend::new(80, 30)).unwrap();
        term.draw(|f| {
            render_modal_overlay(f, ratatui::layout::Rect::new(0, 0, 80, 30), &app);
        })
        .unwrap();
        dump(term.backend().buffer())
    }

    /// The destructive confirm shares the form's frame — white, rounded,
    /// banded — so the two read as one family. Red stays on the `y Delete`
    /// button, the actionable destructive element; the banded title is
    /// neutral like every other band.
    #[test]
    fn delete_confirm_uses_the_shared_frame_with_red_only_on_the_button() {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;
        let mut app = App::new();
        app.devices.modal = Some(DeviceModal::DeleteConfirm {
            id: "kitchen-tv".to_string(),
            display_name: "Kitchen TV".to_string(),
        });
        let mut term = Terminal::new(TestBackend::new(80, 30)).unwrap();
        term.draw(|f| {
            render_modal_overlay(f, ratatui::layout::Rect::new(0, 0, 80, 30), &app);
        })
        .unwrap();
        let buf = term.backend().buffer();
        let out = dump(buf);
        assert!(out.contains("DELETE CLIENT"), "banded title:\n{out}");
        assert!(out.contains("Kitchen TV"), "names the target:\n{out}");
        assert!(out.contains('\u{256d}'), "rounded frame:\n{out}");
        assert!(
            out.contains("  y  Delete  ") && out.contains("  n  Cancel  "),
            "both actions offered, with their keys:\n{out}"
        );

        // The claim in this test's name, actually asserted — but NOT as a
        // colour-equality check, because it cannot be one: `theme.rs` pins
        // `brand_red` and `red_glow` to the SAME `Color::Rgb(220, 38, 38)`
        // (`:140` / `:143`, asserted at `:431-432`). So "is this red cell
        // the brand tick or destructive data?" is unanswerable from a
        // rendered buffer, and an assertion phrased that way is a false
        // result waiting to happen.
        //
        // What IS answerable, and is what D15 actually forbids: no cell of
        // the modal's BORDER RING may be red. That is also the DoD's own
        // wording — "brand_red appears on no border".
        //
        // `chars().position`, NOT `str::find` — `find` returns a BYTE offset
        // and the frame's `│` is 3 bytes, so it would report every column
        // two cells right of where it is. Same trap as
        // `group_header_dash_count_uses_chars_not_bytes`.
        let row_at = |y: u16| out.lines().nth(y as usize).unwrap();
        let col_of =
            |y: u16, glyph: char| row_at(y).chars().position(|c| c == glyph).unwrap() as u16;
        let top = out
            .lines()
            .position(|l| l.contains('\u{256d}'))
            .expect("the top frame renders") as u16;
        let bottom = out
            .lines()
            .position(|l| l.contains('\u{2570}'))
            .expect("the bottom frame renders") as u16;
        let left = col_of(top, '\u{256d}');
        let right = col_of(top, '\u{256e}');

        for y in top..=bottom {
            for x in [left, right] {
                assert_eq!(
                    buf[(x, y)].fg,
                    T.text_primary,
                    "border cell ({x},{y}) is not the neutral frame \u{2014} D15:\n{out}"
                );
            }
        }
        for x in left..=right {
            for y in [top, bottom] {
                assert_eq!(
                    buf[(x, y)].fg,
                    T.text_primary,
                    "border cell ({x},{y}) is not the neutral frame \u{2014} D15:\n{out}"
                );
            }
        }

        // Red belongs to exactly two things here: the row that names the
        // target, and the action that destroys it.
        let name_row = out
            .lines()
            .position(|l| l.contains("Kitchen TV"))
            .expect("the target names itself") as u16;
        assert_eq!(
            buf[(left + 3, name_row)].fg,
            T.red_glow,
            "the target's name must render in the destructive kind:\n{out}"
        );
        // And it must be an outline, never a fill — a filled red beside a
        // filled primary is how an operator deletes what they meant to keep.
        let delete_row = out
            .lines()
            .position(|l| l.contains("  y  Delete  "))
            .expect("the action row renders") as u16;
        let delete_col = out.lines().nth(delete_row as usize).unwrap();
        let start = delete_col.find("  y  Delete  ").unwrap() as u16;
        assert_eq!(
            buf[(start + 2, delete_row)].bg,
            T.bg_elevated,
            "the destructive action is outlined by colour, never filled:\n{out}"
        );
    }

    #[test]
    fn edit_modal_id_row_shows_original_id_not_slug_of_name() {
        let mut form = edit_form("Kitchen TV", Some("kitchen-tv"));
        form.name = "Living Room Pi".to_string();
        let out = render_form_to_string(form);
        assert!(out.contains("kitchen-tv"), "frozen id must render:\n{out}");
        assert!(
            !out.contains("living-room-pi"),
            "slug(name) must NOT be shown as the id on Edit:\n{out}"
        );
    }

    /// Add has no entity yet, so the id row previews what the submit will
    /// derive from the name.
    #[test]
    fn add_modal_id_row_previews_slug_of_name() {
        let mut form = DeviceFormState::new_add();
        form.name = "Living Room Pi".to_string();
        let out = render_form_to_string(form);
        assert!(
            out.contains("living-room-pi"),
            "Add previews the derived id:\n{out}"
        );
    }

    /// The action row must actually reach the screen. Caught by CT pty
    /// smoke: the body is laid out to exactly fill the modal, so a single
    /// wrapped line pushes the last row off the bottom.
    /// Every focusable field must be rendered exactly once. Catches the
    /// drift the old two-list layout allowed: adding a field to
    /// `DeviceFormState::FIELDS` without giving it a row leaves it
    /// reachable by Tab but invisible, and the cursor lands nowhere.
    #[test]
    fn every_focusable_field_is_rendered_exactly_once() {
        for field in DeviceFormState::FIELDS {
            let hits = IDENTITY_FIELDS.iter().filter(|(f, _)| *f == field).count()
                + ASSIGNMENT_FIELDS
                    .iter()
                    .filter(|(f, _)| *f == field)
                    .count();
            assert_eq!(
                hits, 1,
                "{field:?} appears {hits} times across the two sections, expected exactly 1"
            );
        }
    }

    #[test]
    fn modal_renders_the_action_buttons() {
        let out = render_form_to_string(edit_form("Kitchen TV", Some("kitchen-tv")));
        assert!(out.contains("Save"), "Save button missing:\n{out}");
        assert!(out.contains("Cancel"), "Cancel button missing:\n{out}");
    }

    /// Every region's row count must be **fixed** — independent of which
    /// stop holds focus, and independent of the width.
    ///
    /// Two distinct properties, both load-bearing:
    ///
    /// - *Focus-independence.* Each stop carries a different hint, and a
    ///   hint wider than the body used to wrap, shifting everything below
    ///   it. Testing only the default focus once missed two hints that were
    ///   61 and 63 cells wide.
    /// - *Width-independence* (contract §2.1). `render_modal` calls the
    ///   builder twice — at `width - 2`, then again at `width - 3` if the
    ///   body scrolls, because the scrollbar claims the last column. A row
    ///   count that flips between the two silently mis-sizes the modal, and
    ///   no assertion on the line vector alone can see it.
    #[test]
    fn form_body_holds_its_row_and_width_budget_at_every_focus_stop() {
        // head  = title band, desc band, spacer
        // fields= 2 section band + 1 id + 3 identity
        //       + 1 spacer + 2 section band + 9 assignments
        // tail  = spacer, HINT_ROWS (2), key legend, action row
        //
        // 19 -> 18 on `plp-s5d`: the Tags row left ASSIGNMENT_FIELDS, so
        // the assignment block is 9 rows, not 10. That one row also moves
        // two other assertions in this file — see the centring note on
        // `modal_border_is_rounded_and_not_brand_red`.
        const HEAD: usize = 3;
        const FIELDS: usize = 18;
        const TAIL: usize = 5;

        let mut form = edit_form("Kitchen TV", Some("kitchen-tv"));
        let mut stops = vec![DeviceFormFocus::Cancel, DeviceFormFocus::Save];
        stops.extend(DeviceFormState::FIELDS.map(DeviceFormFocus::Field));

        for stop in stops {
            form.focused = stop;
            // Both widths `render_modal` can pass, for the same spec.
            for width in [58u16, 57] {
                let (body, _) = form_body(&form, width);
                assert_eq!(
                    (body.head.len(), body.fields.len(), body.tail.len()),
                    (HEAD, FIELDS, TAIL),
                    "row budget changed with focus on {stop:?} at width {width}"
                );
                for (i, line) in body
                    .head
                    .iter()
                    .chain(body.fields.iter())
                    .chain(body.tail.iter())
                    .enumerate()
                {
                    let w: usize = line.spans.iter().map(|s| s.content.chars().count()).sum();
                    assert!(
                        w <= width as usize,
                        "focus {stop:?}: line {i} is {w} cells, over the {width}-cell inner width"
                    );
                }
            }
        }
    }

    /// A long validation error must stay readable — wrapped across the
    /// reserved rows, and ellipsised if it still does not fit, so a cut
    /// message always looks cut. It used to be hard-truncated mid-word.
    #[test]
    fn a_long_validation_error_wraps_instead_of_being_silently_cut() {
        let mut form = edit_form("Kitchen TV", Some("kitchen-tv"));
        form.error_message = Some(
            "mac alias \"aa:bb\" doesn't look like a MAC \u{2014} expected XX:XX:XX:XX:XX:XX"
                .to_string(),
        );
        let out = render_form_to_string(form);
        assert!(out.contains("mac alias"), "error head shown:\n{out}");
        assert!(
            out.contains("XX:XX:XX:XX:XX:XX"),
            "the actionable half of the message survives:\n{out}"
        );
    }

    /// The cursor's row must actually be the focused field's row. Pins the
    /// mapping end-to-end, so reordering or inserting a field cannot move
    /// the caret onto a neighbour without a test noticing.
    #[test]
    fn cursor_row_always_belongs_to_the_focused_field() {
        let mut form = edit_form("Kitchen TV", Some("kitchen-tv"));
        for (field, label) in IDENTITY_FIELDS.iter().chain(ASSIGNMENT_FIELDS.iter()) {
            form.focused = DeviceFormFocus::Field(*field);
            let (body, cursor) = form_body(&form, 58);
            let Some((row, _)) = cursor else {
                // Pickers and locked rows legitimately take no cursor.
                continue;
            };
            // The row is an index into the FIELD REGION, not the whole
            // body — `render_scroll_body` scrolls that region under a
            // pinned head, and `place_cursor` adds `head_h` back.
            let text: String = body.fields[row]
                .spans
                .iter()
                .map(|s| s.content.as_ref())
                .collect();
            assert!(
                text.contains(label),
                "cursor row {row} does not hold {label:?}, it holds {text:?}"
            );
        }
    }

    #[test]
    fn modal_renders_both_section_headers() {
        let out = render_form_to_string(edit_form("Kitchen TV", Some("kitchen-tv")));
        assert!(out.contains("IDENTITY"), "identity section header:\n{out}");
        assert!(
            out.contains("ASSIGNMENTS"),
            "assignments section header:\n{out}"
        );
    }

    /// Red is an accent, never the frame. The old form drew a square
    /// brand_red border; the shared chrome is a rounded text_primary one.
    #[test]
    fn modal_border_is_rounded_and_not_brand_red() {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;
        let mut app = App::new();
        app.devices.modal = Some(DeviceModal::Form(edit_form("Kitchen TV", Some("kt"))));
        let mut term = Terminal::new(TestBackend::new(80, 30)).unwrap();
        term.draw(|f| {
            render_modal_overlay(f, ratatui::layout::Rect::new(0, 0, 80, 30), &app);
        })
        .unwrap();
        let buf = term.backend().buffer();
        // `plp-s5d`: the body lost the Tags row, so it is 3+18+5 = 26
        // rows → 28 with the frame. Centred in 80x30 that puts the box at
        // y = (30-28)/2 = 1, one row LOWER than the 29-row box it replaced
        // (which floored to 0). Probing the old (10, 0) now finds blank
        // space above the frame, which is what the first run reported.
        let corner = &buf[(10, 1)];
        assert_eq!(corner.symbol(), "\u{256d}", "rounded corner, not square");
        assert_eq!(
            corner.fg, T.text_primary,
            "white frame — red is an accent only"
        );
    }

    /// Promote pins ip + mac from the ARP snapshot; both must render
    /// read-only, which in this grid means no caret can appear on them.
    #[test]
    fn promote_mode_renders_ip_and_mac_read_only() {
        let form = DeviceFormState::new_promote("192.0.2.77".into(), "aa:bb:cc:dd:ee:ff".into());
        let out = render_form_to_string(form);
        assert!(out.contains("192.0.2.77") && out.contains("aa:bb:cc:dd:ee:ff"));
        assert!(
            !out.contains("192.0.2.77_"),
            "a locked field takes no caret:\n{out}"
        );
    }

    /// The real terminal cursor must land on the caret cell. Uses a field
    /// in the SECOND section on purpose — a first-section-only test would
    /// pass even with the body-origin offset wrong.
    #[test]
    fn cursor_lands_on_the_focused_value_tail_in_the_second_section() {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;
        let mut form = edit_form("Kitchen TV", Some("kitchen-tv"));
        form.focused = DeviceFormFocus::Field(DeviceFormField::Owner);
        form.owner = "alex".to_string();
        let mut app = App::new();
        app.devices.modal = Some(DeviceModal::Form(form));
        let mut term = Terminal::new(TestBackend::new(80, 30)).unwrap();
        term.draw(|f| {
            render_modal_overlay(f, ratatui::layout::Rect::new(0, 0, 80, 30), &app);
        })
        .unwrap();
        let pos = term.get_cursor_position().unwrap();
        // Modal is MODAL_W=60 wide, body 3+18+5=26 rows → 28 with the
        // frame, centred in 80×30 → box at (10, 1), so inner is (11, 2).
        // (`plp-s5d`: was 27/29 and box at (10, 0) while the Tags row was
        // in the assignment block. `x` is unaffected — the width did not
        // change.)
        //
        // x: the ecosystem rows carry no `│` rule, so the value column is
        // VALUE_COL = 2 lead + GRID_LABEL_W 18 + 2 gap = 22 — one cell left
        // of the retired grid's GRID_RULE_COL + 2 = 23. "alex" is 4
        // chars → 11 + 22 + 4 = 37.
        assert_eq!(pos.x, 37, "cursor sits at the value tail");
        // y: `place_cursor` works in FIELD-REGION coordinates and adds the
        // pinned head back. `owner` is field index 12 (2 section band + id
        // + 3 identity + spacer + 2 section band + name/profile/group) —
        // unchanged by `plp-s5d`, because Tags sat AFTER owner in the
        // block. What moved is the box: the inner origin is now y=2, so
        // 2 + 3 + 12 = 17.
        assert_eq!(pos.y, 17, "cursor row follows the second section's offset");
    }

    /// A picker-backed field opens a popup instead of accepting keystrokes,
    /// so it must NOT claim the hardware cursor.
    #[test]
    fn picker_field_does_not_take_the_cursor() {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;
        let mut form = edit_form("Kitchen TV", Some("kitchen-tv"));
        form.focused = DeviceFormFocus::Field(DeviceFormField::Profile);
        let mut app = App::new();
        app.devices.modal = Some(DeviceModal::Form(form));
        let mut term = Terminal::new(TestBackend::new(80, 30)).unwrap();
        term.draw(|f| {
            render_modal_overlay(f, ratatui::layout::Rect::new(0, 0, 80, 30), &app);
        })
        .unwrap();
        // Assert on the model, not the backend: TestBackend's cursor
        // defaults to (0,0), so a buffer-level check here passes even when
        // the cursor was never suppressed.
        let mut f2 = edit_form("Kitchen TV", Some("kitchen-tv"));
        f2.focused = DeviceFormFocus::Field(DeviceFormField::Profile);
        assert!(
            form_body(&f2, 58).1.is_none(),
            "a picker field opens a popup and has no insertion point"
        );
    }

    #[test]
    fn form_with_open_picker_renders_overlay_without_panic() {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;

        let mut app = App::new();
        let mut form =
            DeviceFormState::new_add().with_options(vec!["default".into(), "kids".into()], vec![]);
        form.picker = Some(FieldPicker {
            target: DeviceFormField::Profile,
            options: form.profiles_snapshot.clone(),
            cursor: 0,
            multi: false,
            selected: Vec::new(),
        });
        app.devices.modal = Some(DeviceModal::Form(form));

        let backend = TestBackend::new(80, 30);
        let mut term = Terminal::new(backend).unwrap();
        term.draw(|f| {
            render_modal_overlay(f, ratatui::layout::Rect::new(0, 0, 80, 30), &app);
        })
        .unwrap();
        let out = dump(term.backend().buffer());
        assert!(
            out.contains("Select profile"),
            "picker overlay missing over form:\n{out}"
        );
    }

    #[test]
    fn build_rows_no_grouping_emits_mapped_then_unmapped_with_one_header() {
        let view = DeviceViewDto {
            mapped: vec![
                mk_mapped("b", "10.0.0.1", None),
                mk_mapped("a", "10.0.0.2", None),
            ],
            unmapped: vec![mk_unmapped("10.0.0.99")],
        };
        let rows = build_rows(&view, DeviceGroupBy::None);
        // Sort by name with no grouping → "a", "b", header, unmapped row.
        assert_eq!(rows.len(), 4);
        assert!(matches!(&rows[0], DeviceRow::Mapped(m) if m.name == "a"));
        assert!(matches!(&rows[1], DeviceRow::Mapped(m) if m.name == "b"));
        assert!(matches!(&rows[2], DeviceRow::GroupHeader(h) if h == "Unmapped"));
        assert!(matches!(&rows[3], DeviceRow::Unmapped(u) if u.ip == "10.0.0.99"));
    }

    #[test]
    fn build_rows_owner_grouping_inserts_owner_headers() {
        let view = DeviceViewDto {
            mapped: vec![
                mk_mapped("phone", "10.0.0.2", Some("Family")),
                mk_mapped("laptop", "10.0.0.1", Some("Alex")),
            ],
            unmapped: vec![],
        };
        let rows = build_rows(&view, DeviceGroupBy::Owner);
        assert_eq!(rows.len(), 4);
        assert!(matches!(&rows[0], DeviceRow::GroupHeader(h) if h == "Owner: Alex"));
        assert!(matches!(&rows[1], DeviceRow::Mapped(m) if m.name == "laptop"));
        assert!(matches!(&rows[2], DeviceRow::GroupHeader(h) if h == "Owner: Family"));
        assert!(matches!(&rows[3], DeviceRow::Mapped(m) if m.name == "phone"));
    }

    #[test]
    fn next_selectable_index_skips_headers_forward() {
        let rows = vec![
            DeviceRow::GroupHeader("a".into()),
            DeviceRow::Mapped(mk_mapped("x", "10.0.0.1", None)),
            DeviceRow::GroupHeader("b".into()),
            DeviceRow::Mapped(mk_mapped("y", "10.0.0.2", None)),
        ];
        // Fresh start → first selectable.
        assert_eq!(next_selectable_index(&rows, None, 1), Some(1));
        // From row 1, next forward → row 3 (skipping header at idx 2).
        assert_eq!(next_selectable_index(&rows, Some(1), 1), Some(3));
        // N4: from row 3 (last selectable), forward clamps — no wrap
        // back to row 1.
        assert_eq!(next_selectable_index(&rows, Some(3), 1), None);
    }

    #[test]
    fn next_selectable_index_skips_headers_backward() {
        let rows = vec![
            DeviceRow::GroupHeader("a".into()),
            DeviceRow::Mapped(mk_mapped("x", "10.0.0.1", None)),
            DeviceRow::GroupHeader("b".into()),
            DeviceRow::Mapped(mk_mapped("y", "10.0.0.2", None)),
        ];
        // From row 3 backward → row 1.
        assert_eq!(next_selectable_index(&rows, Some(3), -1), Some(1));
        // N4: from row 1 (first selectable), backward clamps — no wrap
        // to row 3. Row 0 is a header, so there is nothing left to land
        // on without leaving `[0, len)`.
        assert_eq!(next_selectable_index(&rows, Some(1), -1), None);
    }

    // §4.19 drain of `backlog-tui-clients-focus-refactor`: the original
    // concern (focus_unmapped split-panel boolean + missing view_len guard
    // on `k`) was eliminated by the S45/S46 unified-list refactor. These
    // two tests pin the post-refactor shape so a future split-panel revival
    // would surface immediately.
    #[test]
    fn unified_list_walk_visits_all_selectable_rows_no_headers() {
        let view = DeviceViewDto {
            mapped: vec![
                mk_mapped("phone", "10.0.0.1", Some("Family")),
                mk_mapped("laptop", "10.0.0.2", Some("Alex")),
            ],
            unmapped: vec![mk_unmapped("10.0.0.99")],
        };
        let rows = build_rows(&view, DeviceGroupBy::Owner);
        let selectable_count = rows.iter().filter(|r| r.is_selectable()).count();
        assert!(
            selectable_count >= 3,
            "expected ≥3 selectable rows, got {selectable_count}"
        );

        let mut visited = Vec::new();
        let mut cursor = next_selectable_index(&rows, None, 1).unwrap();
        visited.push(cursor);
        while visited.len() < selectable_count {
            cursor = next_selectable_index(&rows, Some(cursor), 1).unwrap();
            visited.push(cursor);
        }
        for &idx in &visited {
            assert!(
                rows[idx].is_selectable(),
                "cursor landed on non-selectable row at idx {idx}"
            );
        }
        let mut sorted = visited.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(
            sorted.len(),
            visited.len(),
            "unified walk visited the same row twice before reaching the end"
        );
        // N4: the walk clamps at the last selectable row instead of
        // wrapping back to the first.
        assert_eq!(
            next_selectable_index(&rows, Some(*visited.last().unwrap()), 1),
            None,
            "expected a clamp at the last selectable row, not a wrap-around"
        );
    }

    #[test]
    fn unified_list_navigation_safe_on_empty_view() {
        // Empty rows must yield None (no panic) — protects the
        // `if let Some(idx) = ...` guard in handle_devices_key.
        let rows: Vec<DeviceRow> = Vec::new();
        assert_eq!(next_selectable_index(&rows, None, 1), None);
        assert_eq!(next_selectable_index(&rows, None, -1), None);
    }

    #[test]
    fn current_selection_snaps_off_a_header() {
        let rows = vec![
            DeviceRow::GroupHeader("a".into()),
            DeviceRow::Mapped(mk_mapped("x", "10.0.0.1", None)),
        ];
        let mut state = ratatui::widgets::TableState::default();
        state.select(Some(0)); // pointing at the header
        assert_eq!(current_selection(&state, &rows), Some(1));
    }

    #[test]
    fn modal_form_variant_constructs_via_state_helper() {
        // Pinned so dead-code analysis sees DeviceModal::Form being
        // constructed, not just matched on. The keybindings task wires
        // the live constructors at the key handler layer.
        let modal = DeviceModal::Form(DeviceFormState::new_add());
        match modal {
            DeviceModal::Form(form) => assert_eq!(form.mode, DeviceFormMode::Add),
            _ => panic!("wrong variant"),
        }
    }

    /// Sprint C T4 (§8.1 list row badge): the row renderer appends
    /// `[⚠ UNFILTERED]` to the identity span chain when the device
    /// opted out via D14, so the operator spots it from the list
    /// without having to open the card.
    #[test]
    fn render_mapped_row_unfiltered_device_adds_warning_badge() {
        let mut dto = mk_mapped("guest-laptop", "10.0.0.50", None);
        dto.unfiltered = true;
        let row = render_mapped_row(&dto, 0);
        let cells = row_cells_text(&row);
        assert!(
            cells[0].contains("[\u{26a0} UNFILTERED]"),
            "identity column must carry the warning badge — got {:?}",
            cells[0],
        );
    }

    /// Sprint C T4 regression pin: filtered devices keep the legacy
    /// row shape — no badge, just dot + name. A future regression
    /// that always emits the badge would surface here.
    #[test]
    fn render_mapped_row_filtered_device_no_badge() {
        let dto = mk_mapped("worker", "10.0.0.42", None);
        let row = render_mapped_row(&dto, 0);
        let cells = row_cells_text(&row);
        assert!(
            !cells[0].contains("UNFILTERED"),
            "filtered device must NOT show the badge — got {:?}",
            cells[0],
        );
    }

    /// Helper: render every cell of a Row to a flat string by
    /// concatenating its spans' content. Test-local — production
    /// code uses ratatui's renderer directly.
    fn row_cells_text(row: &ratatui::widgets::Row<'_>) -> Vec<String> {
        // ratatui doesn't expose Row's internal cells publicly, so
        // we re-render via Debug. The Debug impl of Row prints the
        // span content verbatim, which is enough for shape pins.
        let dbg = format!("{row:?}");
        // Single-element vec — the Debug string carries every cell.
        vec![dbg]
    }
}
