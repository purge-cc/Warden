//! Groups tab — read-only view of `[[groups]]`.
//!
//! `[[groups]]` is a first-class config entity with a full CLI surface;
//! this leaf is its TUI surface. The only other contact point is
//! `DeviceFormField::Group`, a picker seeded from the loaded config —
//! and `open_field_picker` no-ops on an empty option list, so on a
//! config with no groups that field is dead by construction and no
//! TUI path could create the first group without this leaf.
//!
//! *This module* still holds no write path and issues no IPC — it
//! renders. The `a`/`e`/`d` modal, its submit path and the two writers
//! behind it all live in `tui/mod.rs` and `tui/group_modal.rs`. The
//! source here is `app.loaded_config`, read from disk: the same
//! offline cohort the Subnets/Profiles/Rules leaves belong to. A
//! successful write re-reads that field rather than adding a poller.
//!
//! ## The distinction this view exists to make legible
//!
//! A group carries exactly one `profile`, and `priority` is the tiebreak
//! when a device is in several. Nothing about a group is merged across
//! memberships — the highest-priority group wins outright, and a tie
//! between different profiles is a validator error, not a coin flip.
//!
//! ## Membership is bidirectional — and this view used to read one side
//!
//! A device is in a group if **either** `[[groups]].devices` names the
//! device **or** `[[devices]].groups` names the group. Neither side is
//! canonical and symmetry is not required: the resolver unions both
//! ([`groups_for_device`](crate::profiles::profile::groups_for_device))
//! and so does the validator's conflict check
//! (`check_group_priority_conflicts`).
//!
//! This view must not read `g.devices` alone: that is the side the TUI
//! does **not** write, since the Devices form writes
//! `[[devices]].groups`. Reading only `g.devices` makes every
//! membership an operator creates from the Devices form read back as
//! `Members 0 device(s)` — a device in several groups, all reporting
//! zero. No unit test can catch that by accident: a fixture that
//! builds a `Group` by hand never crosses the device side and so
//! cannot express the relation, let alone fail on it — hence the union
//! read above, and a live pty-smoke test rather than a unit fixture.
//!
//! The two sides are **not** interchangeable to the operator, because they
//! are edited in different places — so the member list marks each one.
//! Removing a `(device-side)` member from the group modal changes nothing;
//! without the marker that reads as a broken delete.
//!
//! ```text
//! Groups (2)
//!   ID          DISPLAY NAME        PROFILE     PRI  DEVICES │ iot-strict
//!   iot-strict  IoT devices         iot-strict   10    7     │ Profile   iot-strict  (priority 10)
//!   kids        Kids' phones        kids-safe     0    3     │ Members   7 device(s)
//!                                                            │
//!                                                            │ Members
//!                                                            │   hue-bulb-1  (group-side)
//!                                                            │   edo-laptop  (device-side)
//!                                                            │   living-tv   (both sides)
//! ```
//!
//! ## Not here
//! - Keys:  `mod.rs::handle_groups_key` (the `a`/`e`/`d` modal named above)
//! - Form:  `tui::group_modal` (named above)
//! - State: `app::GroupsState` (cursor, the modal, table viewport)
//! - Tests: render + pure fns here; key handling in `tui/tests/`, declared from `mod.rs`

use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Cell, Paragraph, Row, Table, TableState, Wrap};
use ratatui::Frame;

use crate::config::schema::{Device, Group};
use crate::tui::app::App;
use crate::tui::theme::{self, T};
use crate::tui::ui::render_section_chrome;

/// Below this width the master/detail split collapses to master-only.
/// Mirrors Profiles and Subnets — the side card needs ≥40 cells for its
/// KV rows to stay legible.
const NARROW_THRESHOLD: u16 = 100;

/// Shown when the config parsed but declares no groups.
///
/// `handle_groups_key` runs `a` **above** its empty-list guard precisely
/// so it works here — so the hint names the key rather than pointing at
/// `warden group add`. The CLI still works, but copy that sends an
/// operator to a terminal they already left is copy that has gone
/// stale.
pub const EMPTY_HINT: &str = "  press a to add the first group";

pub fn render(f: &mut Frame, area: Rect, app: &mut App) {
    let Some(loaded) = app.loaded_config.as_ref() else {
        render_no_config(f, area);
        return;
    };

    let groups = &loaded.config.groups;
    // Both panes need the device side to resolve membership; it comes
    // from the SAME `LoadedConfig` as `groups` on purpose — one file,
    // one read, no skew, and no dependency on the daemon being up.
    let devices = &loaded.config.devices;
    let title = format!("Groups ({})", groups.len());
    let outer = render_section_chrome(f, area, &title, T.text_secondary);

    if groups.is_empty() {
        render_empty(f, outer);
        return;
    }

    if outer.width < NARROW_THRESHOLD {
        // Single-column fallback: the operator still sees every group;
        // the detail card returns when they widen the terminal.
        render_master(
            f,
            outer,
            groups,
            devices,
            app.groups.selected_id.as_deref(),
            &mut app.groups.table_state,
        );
        return;
    }

    let cols = Layout::horizontal([
        Constraint::Percentage(38),
        Constraint::Length(1),
        Constraint::Percentage(62),
    ])
    .split(outer);

    render_master(
        f,
        cols[0],
        groups,
        devices,
        app.groups.selected_id.as_deref(),
        &mut app.groups.table_state,
    );
    render_detail(f, cols[2], app, groups, devices);
    draw_v_divider(f, cols[1]);
}

// ── Membership ───────────────────────────────────────────────────────

/// Which side of the bidirectional membership declares a device to be in
/// a group — and therefore **where the operator edits it**.
///
/// That last clause is the whole reason this enum exists rather than a
/// bare `bool`. `Group` is editable from the group modal on this tab;
/// `Device` is not, and deleting it here is a no-op the operator will
/// read as a broken delete.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Side {
    /// Only `[[groups]].devices` names the device. Editable here.
    Group,
    /// Only `[[devices]].groups` names the group. Editable on Devices.
    Device,
    /// Both arrays name each other. Removing one side leaves the other.
    Both,
}

impl Side {
    fn label(self) -> &'static str {
        match self {
            Side::Group => "(group-side)",
            Side::Device => "(device-side)",
            Side::Both => "(both sides)",
        }
    }
}

/// `None` when `d` is not a member of `g` by either declaration.
///
/// **This is a second expression of the union in
/// [`groups_for_device`](crate::profiles::profile::groups_for_device)**,
/// and a second copy of that predicate is precisely what produced the
/// defect this function fixes. It is written out rather than delegated
/// because the render needs to know *which* side matched, which the
/// resolver's helper does not report — delegating and then re-testing the
/// two `contains` calls at the call site would be the same duplication
/// with a wrapper on top.
///
/// The divergence guard is therefore a test, not a call:
/// `membership_side_agrees_with_the_resolver_predicate` drives all four
/// `(group-side, device-side)` combinations through both definitions and
/// asserts they agree on membership. Either one drifting turns it red.
fn membership_side(g: &Group, d: &Device) -> Option<Side> {
    match (g.devices.contains(&d.id), d.groups.contains(&g.id)) {
        (true, true) => Some(Side::Both),
        (true, false) => Some(Side::Group),
        (false, true) => Some(Side::Device),
        (false, false) => None,
    }
}

/// Every member of `g`, in `[[devices]]` file order, with the side that
/// declares it.
///
/// Iterating `devices` rather than `g.devices` is safe for the count: a
/// `g.devices` entry with no `[[devices]]` row is a hard `CrossRefMiss`
/// in `check_groups`, so a *validated* config — which is the only kind
/// `app.loaded_config` holds — cannot contain one.
fn members_of<'a>(g: &Group, devices: &'a [Device]) -> Vec<(&'a Device, Side)> {
    devices
        .iter()
        .filter_map(|d| membership_side(g, d).map(|s| (d, s)))
        .collect()
}

/// Union member count — what both the `DEVICES` column and the `Members`
/// row show. Never `g.devices.len()`.
fn member_count(g: &Group, devices: &[Device]) -> usize {
    members_of(g, devices).len()
}

// ── Master pane ──────────────────────────────────────────────────────

fn render_master(
    f: &mut Frame,
    area: Rect,
    groups: &[Group],
    devices: &[Device],
    selected_id: Option<&str>,
    table_state: &mut TableState,
) {
    let header = Row::new(vec![
        Cell::from("ID"),
        Cell::from("DISPLAY NAME"),
        Cell::from("PROFILE"),
        Cell::from("PRI"),
        Cell::from("DEVICES"),
    ])
    .style(
        Style::default()
            .fg(T.brand_red)
            .add_modifier(Modifier::BOLD),
    );

    let rows: Vec<Row> = groups
        .iter()
        .map(|g| {
            Row::new(vec![
                Cell::from(g.id.as_str().to_string()),
                Cell::from(g.display_name.clone()),
                Cell::from(g.profile.as_str().to_string()),
                Cell::from(g.priority.to_string()),
                Cell::from(member_count(g, devices).to_string()),
            ])
        })
        .collect();

    // Resolve the selection back to an index every frame rather than
    // trusting one carried over: a config reload can reorder or remove
    // rows, and a stale index then points at the wrong group. The scroll
    // offset persists regardless (see `tabs::subnets::render_master` for
    // why that is safe across a row-count change).
    let selected =
        resolve_selected_index(groups, selected_id).or_else(|| (!rows.is_empty()).then_some(0));

    let table = Table::new(
        rows,
        [
            Constraint::Min(12),
            Constraint::Min(14),
            Constraint::Min(12),
            Constraint::Length(4),
            Constraint::Length(8),
        ],
    )
    .header(header)
    .row_highlight_style(theme::highlight_style());

    super::render_table(f, area, table, table_state, selected);
}

/// Index of `selected_id` in the current group list, or `None` when the
/// anchor no longer resolves (removed, renamed, or never set).
pub fn resolve_selected_index(groups: &[Group], selected_id: Option<&str>) -> Option<usize> {
    let want = selected_id?;
    groups.iter().position(|g| g.id.as_str() == want)
}

/// The group the detail pane describes: the anchored selection, else the
/// first row — matching what `render_master` highlights.
fn selected_group<'a>(groups: &'a [Group], app: &App) -> Option<&'a Group> {
    resolve_selected_index(groups, app.groups.selected_id.as_deref())
        .and_then(|i| groups.get(i))
        .or_else(|| groups.first())
}

// ── Detail pane ──────────────────────────────────────────────────────

fn render_detail(f: &mut Frame, area: Rect, app: &App, groups: &[Group], devices: &[Device]) {
    let Some(g) = selected_group(groups, app) else {
        return;
    };
    let members = members_of(g, devices);

    let mut lines: Vec<Line> = Vec::new();
    lines.push(Line::from(Span::styled(
        format!("  {}", g.id.as_str()),
        Style::default()
            .fg(T.text_primary)
            .add_modifier(Modifier::BOLD),
    )));
    lines.push(Line::from(Span::styled(
        format!("  {}", g.display_name),
        Style::default().fg(T.text_secondary),
    )));
    lines.push(Line::from(""));

    // `profile` + `priority` read as one fact because they are one:
    // which single profile a member resolves, and what breaks the tie.
    lines.push(kv(
        "Profile",
        format!("{}  (priority {})", g.profile.as_str(), g.priority),
    ));
    lines.push(kv("Members", format!("{} device(s)", members.len())));

    lines.push(Line::from(""));

    // The semantics an operator gets wrong. Stated on the surface that
    // shows both fields, not only in the design doc.
    //
    // This said "tags are UNIONED across every group a device belongs
    // to" until `plp-s5a` removed `Group.tags`. There is no union left:
    // a group carries exactly one `profile: Id`, and `resolver.rs:560`
    // takes the FIRST entry of the priority-sorted list. Explaining a
    // filtering mechanism that no longer exists is worse than explaining
    // none — the operator acts on it.
    lines.push(Line::from(Span::styled(
        "  priority picks ONE profile — the highest-priority group's;",
        Style::default().fg(T.text_muted),
    )));
    lines.push(Line::from(Span::styled(
        "  memberships are never merged.",
        Style::default().fg(T.text_muted),
    )));

    if !members.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "  Members",
            Style::default()
                .fg(T.brand_red)
                .add_modifier(Modifier::BOLD),
        )));
        // Pad to the longest id so the side markers form a column. Capped
        // so one pathological id cannot push every marker off a 60-cell
        // detail pane — `Wrap` would fold it onto the next line, which
        // reads as a phantom member.
        let pad = members
            .iter()
            .map(|(d, _)| d.id.as_str().chars().count())
            .max()
            .unwrap_or(0)
            .min(24);
        for (d, side) in &members {
            lines.push(Line::from(vec![
                Span::styled(
                    format!("    {:<pad$}  ", d.id.as_str()),
                    Style::default().fg(T.text_secondary),
                ),
                Span::styled(side.label(), Style::default().fg(T.text_muted)),
            ]));
        }

        // Only when it is actionable. A device-side member cannot be
        // removed from this tab, and an unexplained no-op delete reads as
        // a bug in the delete rather than as a membership declared
        // elsewhere. Suppressed on an all-group-side group because
        // standing advice about a state the operator is not in is the
        // noise that makes the useful case invisible.
        if members.iter().any(|(_, s)| *s != Side::Group) {
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "  a member not marked (group-side) is also declared in",
                Style::default().fg(T.text_muted),
            )));
            lines.push(Line::from(Span::styled(
                "  [[devices]].groups — edit it on the Devices tab;",
                Style::default().fg(T.text_muted),
            )));
            lines.push(Line::from(Span::styled(
                "  removing it here leaves it in place.",
                Style::default().fg(T.text_muted),
            )));
        }
    }

    f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), area);
}

fn kv(key: &str, value: String) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("  {key:<9}"), Style::default().fg(T.text_muted)),
        Span::styled(value, Style::default().fg(T.text_primary)),
    ])
}

// ── Chrome ───────────────────────────────────────────────────────────

/// Paint a 1-cell-wide vertical separator for every row of `area`.
/// Mirrors the Profiles/Subnets master-detail gutter.
fn draw_v_divider(f: &mut Frame, area: Rect) {
    let style = Style::default().fg(T.text_muted);
    let buf = f.buffer_mut();
    for y in area.y..area.y.saturating_add(area.height) {
        if area.x < buf.area.right() && y < buf.area.bottom() {
            buf.set_string(area.x, y, "\u{2502}", style);
        }
    }
}

fn render_no_config(f: &mut Frame, area: Rect) {
    let content = render_section_chrome(f, area, "Groups", T.text_secondary);
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
            "  no groups configured.",
            Style::default().fg(T.text_muted),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "  a group binds a set of devices to one profile.",
            Style::default().fg(T.text_muted),
        )),
        Line::from(""),
        Line::from(Span::styled(
            EMPTY_HINT,
            Style::default().fg(T.text_secondary),
        )),
    ];
    f.render_widget(Paragraph::new(lines), area);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::schema::{Group, Id};

    /// `Device` has no `Default` and a dozen fields; deserialising the
    /// minimum TOML is shorter than a struct literal and stays correct
    /// when the schema grows a field.
    fn device(id: &str, groups: &[&str]) -> Device {
        let list = groups
            .iter()
            .map(|g| format!("\"{g}\""))
            .collect::<Vec<_>>()
            .join(", ");
        toml::from_str(&format!(
            "id = \"{id}\"\ndisplay_name = \"{id}\"\nmac = \"00:11:22:33:44:55\"\ngroups = [{list}]\n"
        ))
        .expect("device fixture must deserialise")
    }

    fn group(id: &str, profile: &str, priority: i32, devices: &[&str]) -> Group {
        Group {
            id: Id::new(id).unwrap(),
            display_name: format!("{id} display"),
            profile: Id::new(profile).unwrap(),
            priority,
            devices: devices.iter().map(|d| Id::new(*d).unwrap()).collect(),
        }
    }

    #[test]
    fn selection_resolves_by_id_not_by_index() {
        let groups = vec![group("a", "p", 0, &[]), group("b", "p", 0, &[])];
        assert_eq!(resolve_selected_index(&groups, Some("b")), Some(1));
    }

    #[test]
    fn a_selection_that_no_longer_exists_resolves_to_none() {
        let groups = vec![group("a", "p", 0, &[])];
        assert_eq!(
            resolve_selected_index(&groups, Some("gone")),
            None,
            "a stale anchor must not silently point at another group"
        );
    }

    #[test]
    fn detail_falls_back_to_the_first_row_when_nothing_is_anchored() {
        let groups = vec![group("a", "p", 0, &[]), group("b", "p", 0, &[])];
        let app = App::default();
        assert_eq!(
            selected_group(&groups, &app).map(|g| g.id.as_str()),
            Some("a"),
            "detail must describe what master highlights"
        );
    }

    /// Rendered-buffer test at the layout floor: a line-vector assertion
    /// passes even when the text is clipped off screen, which is exactly
    /// the failure an empty-state is supposed to prevent.
    ///
    /// The hint names the `a` key, not the CLI verb, and the assertion
    /// below checks that claim directly. The pairing matters:
    /// `handle_groups_key` runs `a` above its empty-list guard so the key genuinely works from
    /// this exact state. If that guard is ever reordered, this copy
    /// becomes a lie that no compiler catches — see
    /// `groups_add_opens_on_an_empty_config` in `tui/mod.rs`, which pins
    /// the behaviour this sentence promises.
    #[test]
    fn the_empty_state_names_the_add_key_at_the_narrow_floor() {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;

        let mut term = Terminal::new(TestBackend::new(60, 10)).unwrap();
        term.draw(|f| render_empty(f, f.area())).unwrap();
        let dump = term.backend().to_string();
        assert!(
            dump.contains("press a to add"),
            "an empty Groups tab must say how to make one; got:\n{dump}"
        );
    }

    /// The two semantics an operator conflates must both be on screen,
    /// not only in the design doc.
    #[test]
    fn the_detail_card_states_selection_versus_union() {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;

        let groups = vec![group("iot", "strict", 10, &["a", "b"])];
        let devices = vec![device("a", &[]), device("b", &[])];
        let app = App::default();
        let mut term = Terminal::new(TestBackend::new(80, 20)).unwrap();
        term.draw(|f| render_detail(f, f.area(), &app, &groups, &devices))
            .unwrap();
        let dump = term.backend().to_string();
        assert!(
            dump.contains("priority 10"),
            "priority belongs beside the profile it selects; got:\n{dump}"
        );
        // `plp-s5a` deleted `Group.tags`, and this asserted "UNION" —
        // pinning a sentence about a mechanism that no longer exists.
        // The needle stays on the FIRST hint line, the row the old one
        // was on: an 80x20 backend that could not reach the second line
        // would make this negative-by-omission rather than a real read.
        assert!(
            dump.contains("highest-priority"),
            "the tie-break semantic must be stated — a device in several \
             groups gets ONE profile, not a merge; got:\n{dump}"
        );
    }

    // ── The bidirectional membership union ────────────────────────────
    //
    // Every fixture below declares the membership on the DEVICE side and
    // leaves `Group::devices` EMPTY. That asymmetry is the test: a
    // fixture that names the device on both sides passes on the pre-fix
    // `g.devices.len()` and proves only the direction that already
    // worked.

    #[test]
    fn a_device_side_only_membership_is_counted() {
        let g = group("phones", "p", 0, &[]);
        let devices = vec![device("edo-laptop", &["phones"])];
        assert_eq!(
            member_count(&g, &devices),
            1,
            "the group names nobody; the device names the group. \
             Membership is bidirectional, so the count is 1 — reading \
             g.devices.len() here yields 0, which is the defect."
        );
    }

    #[test]
    fn a_symmetric_membership_is_counted_once() {
        let g = group("phones", "p", 0, &["edo-laptop"]);
        let devices = vec![device("edo-laptop", &["phones"])];
        assert_eq!(
            member_count(&g, &devices),
            1,
            "a union must not double-count the device both sides name"
        );
    }

    #[test]
    fn a_non_member_device_is_not_counted() {
        let g = group("phones", "p", 0, &[]);
        let devices = vec![device("printer", &["office"])];
        assert_eq!(
            member_count(&g, &devices),
            0,
            "membership in another group must not leak into this one"
        );
    }

    #[test]
    fn the_side_reports_where_the_membership_is_declared() {
        let g = group("phones", "p", 0, &["from-group", "both"]);
        assert_eq!(
            membership_side(&g, &device("from-group", &[])),
            Some(Side::Group)
        );
        assert_eq!(
            membership_side(&g, &device("from-device", &["phones"])),
            Some(Side::Device)
        );
        assert_eq!(
            membership_side(&g, &device("both", &["phones"])),
            Some(Side::Both)
        );
        assert_eq!(membership_side(&g, &device("stranger", &[])), None);
    }

    /// The divergence guard. [`membership_side`] restates the union that
    /// `profiles::profile::groups_for_device` already owns — a second
    /// copy of that predicate is what produced this defect in the first
    /// place — so the two are driven through all four
    /// `(group-side, device-side)` combinations and must agree.
    #[test]
    fn membership_side_agrees_with_the_resolver_predicate() {
        use crate::profiles::profile::groups_for_device;

        for (on_group_side, on_device_side) in
            [(false, false), (false, true), (true, false), (true, true)]
        {
            let g = group("phones", "p", 0, if on_group_side { &["dev"] } else { &[] });
            let d = device("dev", if on_device_side { &["phones"] } else { &[] });

            let ours = membership_side(&g, &d).is_some();
            let resolvers = !groups_for_device(&d, std::slice::from_ref(&g)).is_empty();
            assert_eq!(
                ours, resolvers,
                "the TUI and the resolver disagree on membership for \
                 (group-side={on_group_side}, device-side={on_device_side}); \
                 one of the two definitions has drifted"
            );
        }
    }

    /// The `DEVICES` column is the only membership figure the narrow
    /// (<100 cell) layout shows, so it gets its own rendered-buffer
    /// assertion rather than riding on `member_count`.
    #[test]
    fn the_devices_column_shows_the_union_not_the_group_side_array() {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;

        let groups = vec![group("phones", "p", 0, &[])];
        let devices = vec![device("edo-laptop", &["phones"]), device("tv", &["phones"])];
        let mut app = App::default();
        let mut term = Terminal::new(TestBackend::new(60, 6)).unwrap();
        term.draw(|f| {
            render_master(
                f,
                f.area(),
                &groups,
                &devices,
                app.groups.selected_id.as_deref(),
                &mut app.groups.table_state,
            )
        })
        .unwrap();
        let dump = term.backend().to_string();
        // Read the cell by the header's column offset. A substring probe
        // is not usable here: `PRI` is 0 in this fixture, so `" 0 "`
        // matches whether or not the DEVICES cell is wrong.
        // `TestBackend::to_string` wraps every row in literal quotes;
        // strip them or the column offsets are off by one and the cell
        // carries a trailing `"`.
        let rows: Vec<&str> = dump.lines().map(|l| l.trim_matches('"')).collect();
        let col = rows[0]
            .find("DEVICES")
            .expect("the header must name the column this test reads");
        // Find the row by its id, not by index: a spacer row or a chrome
        // shift would silently move index 1 onto whitespace, and an
        // assertion against whitespace passes or fails for reasons that
        // have nothing to do with the union.
        let row = rows
            .iter()
            .find(|l| l.contains("phones"))
            .expect("the group row must be on screen at all");
        let cell = row[col..].trim();
        assert_eq!(
            cell, "2",
            "two devices name this group from their own [[devices]].groups \
             and the group names neither; the DEVICES column must show 2. \
             A 0 here is the one-sided g.devices.len() read. Got:\n{dump}"
        );
    }

    /// A membership the operator created from the Devices form must show
    /// up on the card — counted, listed, and marked as un-deletable from
    /// here.
    #[test]
    fn the_card_lists_a_device_side_member_and_says_where_to_edit_it() {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;

        let groups = vec![group("phones", "p", 0, &[])];
        let devices = vec![device("edo-laptop", &["phones"])];
        let app = App::default();
        let mut term = Terminal::new(TestBackend::new(80, 24)).unwrap();
        term.draw(|f| render_detail(f, f.area(), &app, &groups, &devices))
            .unwrap();
        let dump = term.backend().to_string();
        assert!(
            dump.contains("1 device(s)"),
            "the Members row must count the device side; got:\n{dump}"
        );
        assert!(
            dump.contains("edo-laptop"),
            "a counted member missing from the list is worse than a \
             wrong count; got:\n{dump}"
        );
        assert!(
            dump.contains("(device-side)"),
            "the member must be marked as declared elsewhere; got:\n{dump}"
        );
        assert!(
            dump.contains("Devices tab"),
            "the card must name where the membership is editable, or a \
             no-op delete reads as a broken delete; got:\n{dump}"
        );
    }

    /// A symmetric member is *also* declared on the device side, so
    /// deleting the group-side row leaves it in place — the same surprise
    /// the note exists to pre-empt. Pins the condition as
    /// `!= Side::Group` rather than the narrower `== Side::Device`.
    #[test]
    fn a_both_sides_member_still_earns_the_edit_elsewhere_note() {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;

        let groups = vec![group("phones", "p", 0, &["edo-laptop"])];
        let devices = vec![device("edo-laptop", &["phones"])];
        let app = App::default();
        let mut term = Terminal::new(TestBackend::new(80, 24)).unwrap();
        term.draw(|f| render_detail(f, f.area(), &app, &groups, &devices))
            .unwrap();
        let dump = term.backend().to_string();
        assert!(
            dump.contains("(both sides)"),
            "a symmetric membership must read as such; got:\n{dump}"
        );
        assert!(
            dump.contains("Devices tab"),
            "the group-side delete will not remove this member either; \
             got:\n{dump}"
        );
    }

    /// The converse: a group whose members are all its own must not carry
    /// advice about a state the operator is not in.
    #[test]
    fn an_all_group_side_card_omits_the_edit_elsewhere_note() {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;

        let groups = vec![group("phones", "p", 0, &["edo-laptop"])];
        let devices = vec![device("edo-laptop", &[])];
        let app = App::default();
        let mut term = Terminal::new(TestBackend::new(80, 24)).unwrap();
        term.draw(|f| render_detail(f, f.area(), &app, &groups, &devices))
            .unwrap();
        let dump = term.backend().to_string();
        assert!(
            dump.contains("(group-side)"),
            "the marker column is unconditional; got:\n{dump}"
        );
        assert!(
            !dump.contains("Devices tab"),
            "no member is editable elsewhere, so the note is noise; \
             got:\n{dump}"
        );
    }
}
