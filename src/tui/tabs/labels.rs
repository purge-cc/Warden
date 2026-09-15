//! Declared label vocabulary with category, list and detail columns.
//! Add and Edit replace the detail card with an inline form; narrow terminals
//! show that form in the list column. The information view preserves full values.
//!
//! Usage matches a device's free-text metadata against either the label ID or
//! display name through [`Label::matches_value`]. Zero usage is valid because
//! devices may carry undeclared metadata values.

use std::cmp::Ordering;

use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Cell, List, ListItem, Paragraph, Row, Table, TableState};
use ratatui::Frame;

use crate::config::schema::{Label, LabelKind};
use crate::tui::app::{App, LabelsFocus, Leaf};
use crate::tui::mouse::{self, MouseAction, SortOrder};
use crate::tui::theme::{self, T};

const CATEGORY_RAIL_WIDTH: u16 = 16;

/// Labels-specific responsive columns.
///
/// The entry table keeps the shared master/detail helper's 42% width at the
/// wide breakpoint. The category rail is inserted before it, so the detail
/// card yields the additional space. Below the breakpoint only details
/// collapse; category selection remains available beside the entries.
pub fn columns(area: Rect) -> (Rect, Rect, Option<Rect>) {
    let category_width = area.width.min(CATEGORY_RAIL_WIDTH);
    let categories = Rect::new(area.x, area.y, category_width, area.height);
    let list_x = area.x.saturating_add(category_width.saturating_sub(1));

    if let Some(shared) = crate::tui::detail_panel::columns(area) {
        let list = Rect::new(list_x, area.y, shared[0].width, area.height);
        let detail_x = list.x.saturating_add(list.width.saturating_sub(1));
        let details = Rect::new(
            detail_x,
            area.y,
            area.right().saturating_sub(detail_x),
            area.height,
        );
        (categories, list, Some(details))
    } else {
        let list = Rect::new(
            list_x,
            area.y,
            area.right().saturating_sub(list_x),
            area.height,
        );
        (categories, list, None)
    }
}

/// Whether the viewport leaves room for the detail card.
pub fn menu_is_painted(viewport_width: u16) -> bool {
    columns(Rect::new(0, 0, viewport_width, 1)).2.is_some()
}

/// The kinds this leaf offers, and the **only** list any part of it may
/// enumerate — the menu, the empty-state hint, and the key handler all
/// read this one function.
///
/// Every declared kind, in `LabelKind::ALL` order — the same order
/// `warden label list` groups by, so the category rail and CLI read alike.
pub fn menu_kinds() -> Vec<LabelKind> {
    LabelKind::ALL.to_vec()
}

/// Named so the empty state can point at the verb that makes the first one.
/// This leaf is read-plus-declare; there is no other way to seed a
/// vocabulary.
///
/// Built from [`menu_kinds`] — the same list the menu draws — so the tab
/// can never tell an operator to declare a kind it refuses to show them.
/// `empty_hint_names_every_menu_kind` and `empty_hint_and_menu_agree` pin
/// both halves of that.
pub fn empty_hint() -> String {
    let kinds: Vec<&str> = menu_kinds().iter().map(|k| k.as_str()).collect();
    format!("  warden label add <id> --kind <{}>", kinds.join("|"))
}

/// Human label for a kind in the left menu. Plural, because the row is a
/// bucket rather than a single value.
///
pub fn kind_menu_label(kind: LabelKind) -> &'static str {
    match kind {
        LabelKind::Owner => "Owners",
        LabelKind::DeviceType => "Device types",
        LabelKind::Department => "Departments",
    }
}

pub fn render(f: &mut Frame, area: Rect, app: &mut App) {
    let (categories, list, details) = columns(area);
    mouse::register(
        app,
        categories,
        MouseAction::LabelsPanel(LabelsFocus::Categories),
    );
    mouse::register(app, list, MouseAction::LabelsPanel(LabelsFocus::Entries));
    render_categories(f, categories, app);
    if app.loaded_config.is_none() {
        let unavailable = Rect::new(
            list.x,
            list.y,
            area.right().saturating_sub(list.x),
            list.height,
        );
        render_no_config(f, unavailable);
        return;
    }
    let editing = app
        .labels
        .modal
        .as_ref()
        .is_some_and(|modal| modal.form().is_some());
    if !editing || details.is_some() {
        let rows = build_display_rows(app);
        render_entries(
            f,
            list,
            &rows,
            app.labels.selected_kind,
            app.mouse.sort(Leaf::Labels),
            (
                app.labels.selected_id.as_deref(),
                &mut app.labels.table_state,
            ),
            app.loaded_config.as_ref().unwrap().config.labels.is_empty(),
        );
        register_label_mouse(app, list, rows.len());
    }
    if editing {
        crate::tui::label_modal::render_inline_editor(
            f,
            details.unwrap_or(list),
            app.labels.modal.as_ref().unwrap(),
        );
    } else if let Some(details) = details {
        let info = information_with_width(app, body_width_for(details));
        let body = theme::filled_card(
            f.buffer_mut(),
            details,
            &info.title,
            &info.subtitle,
            theme::CardRole::History,
        );
        crate::tui::detail_panel::render(
            f,
            Rect::new(body.x, body.y, body.width, body.height.saturating_sub(2)),
            app,
            Leaf::Labels,
            app.labels.selected_id.as_deref().unwrap_or(""),
            info.lines,
        );
        if body.height > 1 && app.labels.selected_id.is_some() {
            use crate::tui::modal_form::{self, Action, ActionKind};
            let row = Rect::new(body.x, body.bottom() - 1, body.width, 1);
            let actions = [
                Action::new("Edit", false, ActionKind::Primary, "Edit label")
                    .on_key(crossterm::event::KeyCode::Char('e')),
            ];
            f.render_widget(
                Paragraph::new(modal_form::action_row(&actions, row.width)),
                row,
            );
            for (rect, key) in modal_form::action_regions(&actions, row) {
                mouse::register(app, rect, MouseAction::Key(key.code));
            }
        }
    }
}

fn render_categories(f: &mut Frame, area: Rect, app: &mut App) {
    let body = theme::filled_card(
        f.buffer_mut(),
        area,
        "Categories",
        "Label Type",
        theme::CardRole::Summary,
    );
    // A complete card has no list body at four terminal rows or fewer. Keep the
    // selected category reachable by reusing its visible card surface there.
    let body = if body.is_empty() {
        Rect::new(
            area.x.saturating_add(1),
            area.y.saturating_add(1),
            area.width.saturating_sub(2),
            area.height.saturating_sub(2),
        )
    } else {
        body
    };
    let kinds = menu_kinds();
    let selected = kinds
        .iter()
        .position(|kind| *kind == app.labels.selected_kind)
        .unwrap_or(0);
    app.labels.category_state.select(Some(selected));

    let selected_style = if app.labels.focus == LabelsFocus::Categories {
        theme::highlight_style().add_modifier(Modifier::BOLD)
    } else {
        Style::default()
            .fg(T.emerald_ping)
            .add_modifier(Modifier::BOLD)
    };
    let items = kinds
        .iter()
        .map(|kind| ListItem::new(category_label(*kind)))
        .collect::<Vec<_>>();
    f.render_stateful_widget(
        List::new(items)
            .style(Style::default().fg(T.text_primary).bg(T.bg_elevated))
            .highlight_style(selected_style),
        body,
        &mut app.labels.category_state,
    );

    let offset = app.labels.category_state.offset();
    for visible in 0..body.height as usize {
        let index = offset + visible;
        if index >= kinds.len() {
            break;
        }
        mouse::register(
            app,
            Rect::new(body.x, body.y + visible as u16, body.width, 1),
            MouseAction::LabelKind(index),
        );
    }
}

fn category_label(kind: LabelKind) -> &'static str {
    match kind {
        LabelKind::Owner => "Owner",
        LabelKind::DeviceType => "Device Types",
        LabelKind::Department => "Department",
    }
}

pub fn information(app: &App) -> crate::tui::detail_panel::Information {
    information_with_width(app, 74)
}

fn information_with_width(app: &App, width: u16) -> crate::tui::detail_panel::Information {
    let rows = build_display_rows(app);
    let row = rows
        .iter()
        .find(|row| Some(&row.key) == app.labels.selected_id.as_ref())
        .or(rows.first());
    let mut lines = vec![crate::tui::modal_form::section_rule(
        "Identity",
        width,
        theme::CardRole::Summary,
    )];
    if let Some(row) = row {
        lines.extend([
            detail_value("Kind", app.labels.selected_kind.as_str()),
            detail_value("ID", &row.id),
            detail_value("Name", &row.name),
            detail_value("Description", &row.description),
            Line::default(),
            crate::tui::modal_form::section_rule(
                "Device References",
                width,
                theme::CardRole::History,
            ),
            detail_value("Used By", format!("{} Devices", row.used)),
        ]);
        if let Some(loaded) = app.loaded_config.as_ref() {
            if let Some(label) =
                loaded.config.labels.iter().find(|label| {
                    label.kind == app.labels.selected_kind && label.id.as_str() == row.id
                })
            {
                for (index, device) in loaded.config.devices.iter().enumerate() {
                    let value = match label.kind {
                        LabelKind::Owner => device.owner.as_deref(),
                        LabelKind::DeviceType => device.device_type.as_deref(),
                        LabelKind::Department => device.department.as_deref(),
                    };
                    if value.is_some_and(|value| label.matches_value(value)) {
                        lines.push(detail_value(
                            &format!("device{:02}", index + 1),
                            device.id.to_string(),
                        ));
                    }
                }
            }
        }
    } else {
        lines.push(Line::from("No label selected"));
    }
    crate::tui::detail_panel::Information::new(
        "Label Details",
        format!(
            "{} · Identity & Device References",
            detail_kind_label(app.labels.selected_kind)
        ),
        lines,
    )
}

fn detail_kind_label(kind: LabelKind) -> &'static str {
    match kind {
        LabelKind::Owner => "Owners",
        LabelKind::DeviceType => "Device Types",
        LabelKind::Department => "Departments",
    }
}

fn detail_value(label: &str, value: impl Into<String>) -> Line<'static> {
    let value = value.into();
    Line::from(vec![
        Span::styled(format!("{label:<14} "), Style::default().fg(T.text_muted)),
        Span::styled(
            if value.is_empty() {
                "—".into()
            } else {
                value
            },
            Style::default().fg(T.text_primary),
        ),
    ])
}

fn body_width_for(area: Rect) -> u16 {
    area.width.saturating_sub(4)
}

// ── Centre card: entries of the selected category ────────────────────

fn render_entries(
    f: &mut Frame,
    area: Rect,
    rows_data: &[LabelDisplayRow],
    kind: crate::config::schema::LabelKind,
    sort: Option<SortOrder>,
    cursor: (Option<&str>, &mut TableState),
    whole_vocab_empty: bool,
) {
    let (selected_id, table_state) = cursor;

    if rows_data.is_empty() {
        let body = theme::filled_card(
            f.buffer_mut(),
            area,
            "LABELS",
            &format!("{} · {} Entries", kind_menu_label(kind), 0),
            theme::CardRole::Analytics,
        );
        render_empty_for_kind(f, body, kind, whole_vocab_empty);
        return;
    }

    let header = Row::new(
        ["ID", "NAME", "DESCRIPTION", "USED"]
            .into_iter()
            .enumerate()
            .map(|(column, label)| {
                Cell::from(mouse::sort_label(label, column, sort)).style(
                    theme::table_heading_style(sort.is_some_and(|order| order.column == column)),
                )
            }),
    )
    .style(theme::table_heading_style(false));

    let row_count = rows_data.len();
    let rows: Vec<Row> = rows_data
        .iter()
        .map(|row| {
            Row::new(vec![
                Cell::from(row.id.clone()),
                Cell::from(row.name.clone()),
                Cell::from(row.description.clone()),
                Cell::from(row.used.to_string()),
            ])
        })
        .collect();

    // Re-resolve the anchor every frame rather than carrying an index: a
    // config reload can add, remove or reorder entries, and an index from
    // the previous frame then points at a different label. The scroll
    // offset persists regardless (see `tabs::subnets::render_master` for
    // why that is safe across a row-count change).
    let selected =
        resolve_selected_index(rows_data, selected_id).or_else(|| (!rows.is_empty()).then_some(0));

    let table = Table::new(rows, label_columns(area.width.saturating_sub(4)))
        .header(header)
        .row_highlight_style(theme::highlight_style());

    let body = theme::filled_card(
        f.buffer_mut(),
        area,
        "LABELS",
        &format!("{} · {} Entries", kind_menu_label(kind), row_count),
        theme::CardRole::Analytics,
    );
    super::render_table(f, body, table, table_state, selected);
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LabelDisplayRow {
    pub key: String,
    pub id: String,
    pub name: String,
    pub description: String,
    pub used: usize,
}

pub fn build_display_rows(app: &App) -> Vec<LabelDisplayRow> {
    build_display_rows_for_kind(app, app.labels.selected_kind)
}

/// Build the exact sorted projection for an explicitly selected kind. Root
/// selection/edit wiring can use this without temporarily mutating the tab's
/// visible kind.
pub fn build_display_rows_for_kind(app: &App, kind: LabelKind) -> Vec<LabelDisplayRow> {
    let Some(loaded) = app.loaded_config.as_ref() else {
        return Vec::new();
    };
    let mut rows: Vec<LabelDisplayRow> = rows_for_kind(&loaded.config.labels, kind)
        .into_iter()
        .map(|label| LabelDisplayRow {
            key: label.id.as_str().to_string(),
            id: label.id.as_str().to_string(),
            name: label.display_name.clone(),
            description: label.description.clone().unwrap_or_else(|| "—".into()),
            used: usage_count(loaded, label),
        })
        .collect();
    if let Some(sort) = app.mouse.sort(Leaf::Labels) {
        rows.sort_by(|a, b| compare_display_rows(a, b, sort));
    }
    rows
}

/// Stable identity for root-level edit/delete selection wiring. Sorting and
/// scrolling must never turn a visual index into a different label.
pub fn stable_row_key(row: &LabelDisplayRow) -> &str {
    &row.key
}

fn compare_display_rows(a: &LabelDisplayRow, b: &LabelDisplayRow, sort: SortOrder) -> Ordering {
    let primary = match sort.column {
        0 => a.id.to_lowercase().cmp(&b.id.to_lowercase()),
        1 => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
        2 => a
            .description
            .to_lowercase()
            .cmp(&b.description.to_lowercase()),
        3 => a.used.cmp(&b.used),
        _ => Ordering::Equal,
    };
    let primary = if sort.descending {
        primary.reverse()
    } else {
        primary
    };
    primary.then_with(|| a.key.cmp(&b.key))
}

fn label_columns(width: u16) -> [Constraint; 4] {
    [
        Constraint::Length((width / 5).max(8)),
        Constraint::Length((width / 4).max(10)),
        Constraint::Min(0),
        Constraint::Length(4),
    ]
}

fn register_label_mouse(app: &App, area: Rect, row_count: usize) {
    if row_count == 0 {
        return;
    }
    let body = card_body_area(area);
    let constraints = label_columns(body.width);
    let columns = crate::tui::ui::table_column_rects(
        Rect::new(body.x, body.y, body.width, 1),
        &constraints,
        1,
        0,
    );
    for (column, column_area) in columns.into_iter().enumerate() {
        mouse::register(app, column_area, MouseAction::Sort(Leaf::Labels, column));
    }
    let visible = body.height.saturating_sub(1) as usize;
    let offset = app.labels.table_state.offset();
    for index in 0..visible.min(row_count.saturating_sub(offset)) {
        mouse::register(
            app,
            Rect::new(body.x, body.y + 1 + index as u16, body.width, 1),
            MouseAction::Row(Leaf::Labels, offset + index),
        );
    }
}

fn card_body_area(area: Rect) -> Rect {
    Rect::new(
        area.x.saturating_add(2),
        area.y.saturating_add(3),
        area.width.saturating_sub(4),
        area.height.saturating_sub(4),
    )
}

/// How many entities use this label's value.
///
/// Devices matched via [`Label::matches_value`] against whichever field
/// `label.kind` names (`owner`, `device_type` or `department`) — id **or**
/// display_name, because the two sets never intersect on their own.
///
/// A `[[labels]]` row declaring `kind = "tag"` cannot reach this function:
/// `LabelKind` has no such variant (see the module doc's "Why a registry
/// existed here for tags"), and `Vec<Label>` deserialisation is
/// all-or-nothing, so a config still carrying one fails to load entirely.
/// The operator sees the ordinary "could not load config" state on every
/// tab that reads `app.loaded_config`, not a gap local to this one.
pub fn usage_count(loaded: &crate::config::loader::LoadedConfig, label: &Label) -> usize {
    loaded
        .config
        .devices
        .iter()
        .filter(|d| {
            let field = match label.kind {
                LabelKind::Owner => d.owner.as_deref(),
                LabelKind::DeviceType => d.device_type.as_deref(),
                LabelKind::Department => d.department.as_deref(),
            };
            field.is_some_and(|v| label.matches_value(v))
        })
        .count()
}

/// The rows of one vocabulary, in the order the table paints them.
///
/// **One implementation, two consumers, on purpose.** [`render_entries`]
/// draws these rows and highlights one of them; `mod.rs::focused_label`
/// resolves which row `e` and `d` act on. If those two derived their row
/// set separately — a different filter, a different order — the operator
/// would edit or delete a row other than the one under the highlight, and
/// nothing on screen would say so — harmless while read-only, load-bearing
/// the moment CRUD arrives.
pub fn rows_for_kind(labels: &[Label], kind: LabelKind) -> Vec<&Label> {
    labels.iter().filter(|l| l.kind == kind).collect()
}

/// Index of `selected_id` among the currently shown entries, or `None`
/// when the anchor no longer resolves.
pub fn resolve_selected_index(
    rows: &[LabelDisplayRow],
    selected_id: Option<&str>,
) -> Option<usize> {
    let want = selected_id?;
    rows.iter().position(|row| stable_row_key(row) == want)
}

// ── Empty / error states ─────────────────────────────────────────────

fn render_empty_for_kind(f: &mut Frame, area: Rect, kind: LabelKind, whole_vocab_empty: bool) {
    let mut lines = vec![Line::from(Span::styled(
        format!("  no {} declared.", kind_menu_label(kind).to_lowercase()),
        Style::default().fg(T.text_muted),
    ))];

    if whole_vocab_empty {
        // Worth saying once, on a config that has never had a vocabulary:
        // declaring one is optional, and nothing breaks without it.
        //
        // It used to branch on the kind: telling a Tags-row operator that
        // "these device fields stay free text" would have been false, since
        // a tag was neither a device field nor free text. With that kind
        // removed, every kind reaching here governs a device field and
        // one sentence is true for all of them.
        let (why_a, why_b) = (
            "  a vocabulary is optional — without one these device fields",
            "  stay free text, exactly as they are today.",
        );
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            why_a,
            Style::default().fg(T.text_muted),
        )));
        lines.push(Line::from(Span::styled(
            why_b,
            Style::default().fg(T.text_muted),
        )));
    }

    lines.push(Line::from(""));
    // The dashboard can declare now, so the empty state leads
    // with the key. The CLI line stays underneath, unchanged and pinned —
    // it is what an operator scripting the box needs.
    //
    // Unconditional: every kind the menu can select is one `a` can
    // declare, so this no longer needs to be gated on the same
    // discriminator `menu_kinds` uses.
    lines.push(Line::from(Span::styled(
        "  press [a] to declare one.",
        Style::default().fg(T.text_secondary),
    )));
    lines.push(Line::from(Span::styled(
        empty_hint(),
        Style::default().fg(T.text_secondary),
    )));
    f.render_widget(Paragraph::new(lines), area);
}

fn render_no_config(f: &mut Frame, area: Rect) {
    let content = theme::filled_card(
        f.buffer_mut(),
        area,
        "LABELS",
        "Device Metadata & Vocabulary",
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::loader::LoadedConfig;
    use crate::config::schema::{ConfigV1, Device, Id};
    use crate::tui::cfg_scan::{
        classify_tail, is_test_cfg_marker, split_leading_attr, without_line_comment, StripState,
    };

    fn label(id: &str, kind: LabelKind, display: &str) -> Label {
        Label {
            id: Id::new(id).unwrap(),
            kind,
            display_name: display.to_string(),
            description: None,
        }
    }

    fn loaded(labels: Vec<Label>, devices: Vec<Device>) -> LoadedConfig {
        LoadedConfig {
            config: ConfigV1 {
                labels,
                devices,
                ..Default::default()
            },
            master_path: std::path::PathBuf::from("/tmp/dummy.toml"),
            files_loaded: Vec::new(),
            total_bytes: 0,
            provenance: Default::default(),
            custom_lists: Default::default(),
        }
    }

    fn device(id: &str, field: Option<&str>, kind: LabelKind) -> Device {
        let v = field.map(|s| s.to_string());
        Device {
            id: Id::new(id).unwrap(),
            display_name: id.to_string(),
            ip: None,
            mac: None,
            mac_aliases: Vec::new(),
            profile: None,
            groups: Vec::new(),
            owner: if kind == LabelKind::Owner {
                v.clone()
            } else {
                None
            },
            device_type: if kind == LabelKind::DeviceType {
                v.clone()
            } else {
                None
            },
            department: if kind == LabelKind::Department {
                v
            } else {
                None
            },
            notes: None,
            allow_rules: Vec::new(),
            deny_rules: Vec::new(),
            override_profile_deny: false,
            unfiltered: false,
            network_name: None,
            network_name_wildcard: false,
        }
    }

    /// The constraint that makes this column non-obvious: the device value
    /// and the label id can never be equal, so a naive `id == value` count
    /// would report 0 for a label that is in use everywhere.
    #[test]
    fn usage_counts_by_display_name_not_only_by_id() {
        let l = label("dweller", LabelKind::Owner, "Dweller");
        let lc = loaded(
            vec![l.clone()],
            vec![
                device("a", Some("Dweller"), LabelKind::Owner),
                device("b", Some("Dweller"), LabelKind::Owner),
            ],
        );
        assert_eq!(
            usage_count(&lc, &l),
            2,
            "devices carry the display name; counting ids alone would say 0"
        );
    }

    #[test]
    fn usage_counts_the_id_form_too() {
        let l = label("dweller", LabelKind::Owner, "Dweller");
        let lc = loaded(
            vec![l.clone()],
            vec![device("a", Some("dweller"), LabelKind::Owner)],
        );
        assert_eq!(usage_count(&lc, &l), 1);
    }

    #[test]
    fn a_value_no_label_declares_counts_for_nobody() {
        // `Persona` vs `Personal` is the real drift on the live boxes. An
        // undeclared value is legal and must not be attributed to a
        // near-neighbour.
        let l = label("personal", LabelKind::Department, "Personal");
        let lc = loaded(
            vec![l.clone()],
            vec![device("a", Some("Persona"), LabelKind::Department)],
        );
        assert_eq!(
            usage_count(&lc, &l),
            0,
            "no fuzzy matching — a typo is a different value, not this one"
        );
    }

    #[test]
    fn selection_resolves_by_id_not_by_index() {
        let a = label("a", LabelKind::Owner, "A");
        let b = label("b", LabelKind::Owner, "B");
        let mut app = App::new();
        app.loaded_config = Some(loaded(vec![a, b], Vec::new()));
        let rows = build_display_rows(&app);
        assert_eq!(resolve_selected_index(&rows, Some("b")), Some(1));
        assert_eq!(resolve_selected_index(&rows, Some("gone")), None);
    }

    #[test]
    fn display_rows_follow_real_column_sort_and_keep_stable_keys() {
        let mut app = App::new();
        app.loaded_config = Some(loaded(
            vec![
                label("zeta", LabelKind::Owner, "Same"),
                label("alpha", LabelKind::Owner, "Same"),
            ],
            Vec::new(),
        ));
        app.mouse.toggle_sort(Leaf::Labels, 1);
        let rows = build_display_rows(&app);
        assert_eq!(
            rows.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(),
            ["alpha", "zeta"]
        );
        assert_eq!(stable_row_key(&rows[0]), "alpha");

        app.mouse.toggle_sort(Leaf::Labels, 1);
        let descending_tie = build_display_rows(&app);
        assert_eq!(
            descending_tie
                .iter()
                .map(|r| r.id.as_str())
                .collect::<Vec<_>>(),
            ["alpha", "zeta"],
            "descending reverses only the selected value, not its immutable-id tie"
        );

        app.mouse.toggle_sort(Leaf::Labels, 0);
        let rows = build_display_rows(&app);
        assert_eq!(
            rows.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(),
            ["alpha", "zeta"]
        );
        assert_eq!(
            build_display_rows_for_kind(&app, LabelKind::Department).len(),
            0,
            "explicit kind projection must not depend on the visible kind"
        );
    }

    /// Rendered-buffer test: a line-vector assertion passes even when the
    /// text is clipped off screen, which is exactly what an empty state
    /// exists to prevent.
    #[test]
    fn the_empty_state_names_the_cli_and_says_the_vocabulary_is_optional() {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;

        let mut term = Terminal::new(TestBackend::new(70, 10)).unwrap();
        term.draw(|f| render_empty_for_kind(f, f.area(), LabelKind::Owner, true))
            .unwrap();
        let dump = term.backend().to_string();
        assert!(
            dump.contains("warden label add"),
            "must name the verb that makes the first one; got:\n{dump}"
        );
        assert!(
            dump.contains("optional"),
            "a config with no vocabulary is not broken, and must not read as broken; got:\n{dump}"
        );
    }

    #[test]
    fn every_kind_has_a_menu_label() {
        for k in LabelKind::ALL {
            assert!(!kind_menu_label(k).is_empty(), "{k:?} has no menu label");
        }
    }

    /// The hint is derived, so a kind added to the menu cannot leave the
    /// operator reading a command line that omits it.
    ///
    /// Reads from [`menu_kinds`], not `LabelKind::ALL`.
    /// On its own that would be tautological — one list feeding both
    /// sides can never disagree with itself — so the two tests below
    /// carry the halves that can actually fail.
    #[test]
    fn empty_hint_names_every_menu_kind() {
        let hint = empty_hint();
        for k in menu_kinds() {
            assert!(hint.contains(k.as_str()), "{k} missing from: {hint}");
        }
    }

    /// The hint must not name a kind the menu does not paint.
    ///
    /// **INVERTED, and the inversion is the record.** The
    /// second assertion used to read `LabelKind::valid_values().contains("tag")`
    /// — *"the CLI's own enumeration must be untouched; `warden label add
    /// --kind tag` stays legal, and this test fails loudly if a future
    /// session narrows the schema instead of the view"*. That earlier
    /// change had narrowed only the view, and this pinned the gap shut.
    ///
    /// The schema was later narrowed too: `LabelKind::Tag` is gone, so
    /// `--kind tag` is refused by `parse_kind` and no longer enumerated.
    /// Kept and inverted rather than deleted — a change that removes a
    /// capability but leaves its old pinning test standing is a known
    /// class of bug, and a test that quietly disappears takes the
    /// record of the old rule with it.
    #[test]
    fn neither_the_hint_nor_the_cli_enumeration_offers_the_retired_tag_kind() {
        let hint = empty_hint();
        assert!(
            !hint.contains("tag"),
            "the menu has no Tags row; the hint must not send them there: {hint}"
        );
        assert!(
            !LabelKind::valid_values().contains("tag"),
            "the schema is narrowed now, not just the view — `--kind tag` \
             must not be offered anywhere: {}",
            LabelKind::valid_values()
        );
    }

    #[test]
    fn menu_kinds_offers_the_three_declared_vocabularies() {
        let kinds = menu_kinds();
        assert_eq!(
            kinds,
            vec![
                LabelKind::Owner,
                LabelKind::DeviceType,
                LabelKind::Department
            ],
            "three closed vocabularies — every kind there is now that \
             `tag` is retired"
        );
    }

    /// The anti-split-brain pin the two lists exist for: what the category rail
    /// **paints** and what the hint **names** must be the same set. A
    /// containment check against a shared const cannot fail; this one
    /// compares the rendered buffer against the rendered string.
    #[test]
    fn menu_and_hint_enumerate_the_same_kinds() {
        let labels = vec![label("dweller", LabelKind::Owner, "Dweller")];
        let mut app = App::new();
        app.loaded_config = Some(loaded(labels.clone(), Vec::new()));
        let term = draw(&mut app, 100, 24);
        let dump = term.backend().to_string();

        let hint = empty_hint();
        for k in menu_kinds() {
            assert!(
                dump.contains(category_label(k)),
                "{k} is in the hint but the menu does not paint it:\n{dump}"
            );
            assert!(hint.contains(k.as_str()), "{k} missing from: {hint}");
        }
        assert!(
            !dump.contains("Tags"),
            "the kind menu must not carry a Tags row:\n{dump}"
        );
    }

    fn focus_app(focus: LabelsFocus) -> App {
        let mut app = App::new();
        app.loaded_config = Some(loaded(
            vec![
                label("dweller", LabelKind::Owner, "Dweller"),
                label("dweller2", LabelKind::Owner, "Dweller2"),
            ],
            Vec::new(),
        ));
        app.labels.focus = focus;
        app.labels.selected_id = Some("dweller".to_string());
        app
    }

    fn draw(app: &mut App, w: u16, h: u16) -> ratatui::Terminal<ratatui::backend::TestBackend> {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;
        let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
        term.draw(|f| render(f, f.area(), app)).unwrap();
        term
    }

    #[test]
    fn wide_labels_uses_blue_categories_green_list_and_yellow_details() {
        let term = draw(&mut focus_app(LabelsFocus::Entries), 164, 46);
        let dump = term.backend().to_string();
        assert!(dump.contains("Owner"));
        assert!(dump.contains("Device Types"));
        assert!(dump.contains("Department"));
        assert!(!dump.contains("Kind:"));
        assert!(dump.contains("LABEL DETAILS"));
        assert!(dump.contains("dweller"));
        let (categories, list, details) = columns(Rect::new(0, 0, 164, 46));
        let details = details.unwrap();
        assert_eq!(categories, Rect::new(0, 0, 16, 46));
        assert_eq!(list, Rect::new(15, 0, 68, 46));
        assert_eq!(details, Rect::new(82, 0, 82, 46));

        let buffer = term.backend().buffer();
        assert_eq!(buffer[(1, 1)].bg, T.card_summary_title_bg);
        assert_eq!(buffer[(1, 2)].bg, T.card_summary_subtitle_bg);
        assert_eq!(buffer[(2, 3)].bg, T.bg_elevated);
        assert_eq!(buffer[(16, 1)].bg, T.card_analytics_title_bg);
        assert_eq!(buffer[(83, 1)].bg, T.card_history_title_bg);
    }

    #[test]
    fn category_mouse_rows_follow_the_painted_card_body() {
        use crossterm::event::{KeyModifiers, MouseButton, MouseEvent, MouseEventKind};

        let mut app = focus_app(LabelsFocus::Entries);
        let term = draw(&mut app, 80, 24);
        let buffer = term.backend().buffer();

        for (row, kind) in menu_kinds().into_iter().enumerate() {
            let y = 3 + row as u16;
            assert_eq!(buffer[(2, y)].bg, T.bg_elevated);
            assert_eq!(
                mouse::action(
                    &app,
                    MouseEvent {
                        kind: MouseEventKind::Down(MouseButton::Left),
                        column: 2,
                        row: y,
                        modifiers: KeyModifiers::NONE,
                    },
                ),
                Some(MouseAction::LabelKind(row)),
                "{} must be clickable where it is painted",
                category_label(kind),
            );
        }
    }

    #[test]
    fn at_the_eighty_column_floor_categories_and_entries_remain_visible() {
        let term = draw(&mut focus_app(LabelsFocus::Entries), 80, 24);
        let dump = term.backend().to_string();
        assert!(
            dump.contains("Device Types"),
            "category rail missing:\n{dump}"
        );
        assert!(dump.contains("dweller"), "entry table missing:\n{dump}");
        assert!(
            !dump.contains("LABEL DETAILS"),
            "detail must collapse:\n{dump}"
        );

        let (categories, list, details) = columns(Rect::new(0, 0, 80, 24));
        assert_eq!(categories, Rect::new(0, 0, 16, 24));
        assert_eq!(list, Rect::new(15, 0, 65, 24));
        assert_eq!(details, None);
    }

    /// [`menu_is_painted`] is the predicate the clamp keys off, so its
    /// boundary is worth pinning directly: 80 is the minimum-terminal
    /// floor and must be false, and the first width that paints the
    /// menu must be true.
    #[test]
    fn the_menu_is_not_painted_at_the_floor_but_is_when_wide() {
        assert!(!menu_is_painted(80), "the floor collapses the split");
        assert!(
            !menu_is_painted(107),
            "one column short of the threshold still collapses"
        );
        assert!(
            menu_is_painted(108),
            "the first width whose inner rect reaches the threshold"
        );
        assert!(menu_is_painted(164), "a comfortable terminal");
    }

    #[test]
    fn selected_category_remains_visible_when_the_rail_is_one_row_tall() {
        let mut app = focus_app(LabelsFocus::Categories);
        app.labels.selected_kind = LabelKind::Department;
        let term = draw(&mut app, 80, 3);
        let dump = term.backend().to_string();

        assert!(
            dump.contains("Department"),
            "selected row must scroll into view:\n{dump}"
        );
        assert_eq!(app.labels.category_state.selected(), Some(2));
        assert_eq!(app.labels.category_state.offset(), 2);
        assert_eq!(term.backend().buffer()[(2, 1)].bg, T.bg_highlight);
    }

    // `a_tag_counts_carriers_not_device_metadata` no longer exists.
    //
    // It was a discriminator: a fixture whose device `owner`
    // reads `kids` while its `tags` do NOT, so a tag routed through
    // `matches_value` reports 1 and the correct carrier walk reports 0.
    // The carrier walk was `collect_tag_usage`, since deleted;
    // `usage_count` now returns 0 for every `LabelKind::Tag` and there is
    // no second count left to tell apart from the first.
    //
    // **Its twin below survives and is the half that still discriminates**
    // — `a_metadata_label_does_not_count_tag_carriers` asserts the reverse
    // leak, that a device carrying the tag `kids` does not inflate an
    // `owner` label named `kids`. That direction is unaffected by this
    // lane and is what keeps the metadata branch honest.

    /// The twin of `tui_never_reaches_the_printing_tag_helper`
    /// (`tabs/tags.rs`), for the verbs this leaf makes reachable.
    ///
    /// **Read that test's comments for the reasoning; it is not repeated
    /// here.** The one thing worth restating is the shape of the skip:
    /// a scanner that `break`s at the first `#[cfg(test)]` marker reads
    /// only the file's leading fraction, and every module past the first
    /// test block goes unscanned — that is how this class of scanner
    /// previously went blind to real call sites. The column-0
    /// `#[cfg(test)]` … `}` pair delimits a top-level test module; an
    /// indented one is an attribute on a single item and stays scanned.
    /// That holds because `cargo fmt --check` is a gate.
    ///
    /// The needle is the **call** — `labels::run_add(` — never the bare
    /// name: `label_modal.rs` and `mod.rs` deliberately name these verbs
    /// in prose to say they must not be used, and a needle that also
    /// matches prose is how a detector dies.
    ///
    /// One list, read by the scanner **and** by its negative control. Two
    /// lists that "must stay in sync" are one commit away from not being.
    const VERBS: [&str; 5] = ["run_add", "run_set", "run_remove", "run_list", "run_show"];

    /// The line with its `//` comment cut and every string literal blanked,
    /// so what is searched is code. A verb named in prose or quoted inside a
    /// message is documentation, not a call; a scan that cannot tell them
    /// apart makes correct prose unwritable and eventually gets deleted.
    fn code_of(line: &str) -> String {
        let code = without_line_comment(line);
        let mut out = String::with_capacity(code.len());
        let mut in_string = false;
        let mut escaped = false;
        for c in code.chars() {
            if escaped {
                out.push(' ');
                escaped = false;
                continue;
            }
            match c {
                '\\' if in_string => {
                    out.push(' ');
                    escaped = true;
                }
                '"' => {
                    out.push(' ');
                    in_string = !in_string;
                }
                _ if in_string => out.push(' '),
                _ => out.push(c),
            }
        }
        out
    }

    /// True when `line` reaches a printing helper — by calling it outright,
    /// or by importing it. An alias (`use ..labels::run_add as add_label;`)
    /// renames the verb, so the call site never spells `labels::run_add(`
    /// and a call-only scan is blind to it; the import is the one place the
    /// real name must still appear.
    fn forbidden_hit(line: &str) -> bool {
        let code = code_of(line);
        if code.trim_start().starts_with("use ") && code.contains("labels::") {
            return VERBS.iter().any(|v| code.contains(v));
        }
        VERBS
            .iter()
            .any(|v| code.contains(&format!("labels::{v}(")))
    }

    /// One file's worth of the scan: skip every test-cfg item (block or
    /// bare declaration, same 3-state walk as `tui/mod.rs`'s
    /// `strip_test_items`) and record a `path:line: text` hit for every
    /// forbidden needle found in what is left. Pulled out of `scan` so it
    /// is testable against fixture strings, not only real files on disk.
    fn scan_source(hits: &mut Vec<String>, path_label: &str, src: &str) {
        let mut state = StripState::Normal;
        for (i, line) in src.lines().enumerate() {
            state = match state {
                StripState::Normal => {
                    if let Some(tail) = is_test_cfg_marker(line) {
                        classify_tail(tail)
                    } else {
                        if forbidden_hit(line) {
                            hits.push(format!("{path_label}:{}: {}", i + 1, line.trim()));
                        }
                        StripState::Normal
                    }
                }
                StripState::Classifying => {
                    if line.starts_with("#[") {
                        match split_leading_attr(line) {
                            Some((_, tail)) => classify_tail(tail),
                            None => panic!(
                                "attribute at {path_label}:{}: {line:?} did not \
                                 close its brackets on one physical line",
                                i + 1
                            ),
                        }
                    } else {
                        classify_tail(line.trim_end())
                    }
                }
                StripState::SkippingBlock => {
                    if line == "}" {
                        StripState::Normal
                    } else {
                        StripState::SkippingBlock
                    }
                }
            };
        }
        assert_eq!(
            state,
            StripState::Normal,
            "scan of {path_label} ended in {state:?} at EOF — a test item's \
             closing brace or semicolon was never found"
        );
    }

    fn scan(dir: &std::path::Path, hits: &mut Vec<String>) {
        for entry in std::fs::read_dir(dir).expect("src/tui must be readable") {
            let path = entry.expect("readable dir entry").path();
            if path.is_dir() {
                // `src/tui/tests/` holds `#[path]`-relocated `#[cfg(test)]`
                // module bodies: the cfg marker lives on the `mod` item back
                // in the file that declares it, not in these files, so a
                // plain recursive scan would read every line here as
                // production code and misfire on any test fixture that
                // happens to contain a forbidden call.
                if path.file_name().and_then(|n| n.to_str()) == Some("tests") {
                    continue;
                }
                scan(&path, hits);
                continue;
            }
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let src = std::fs::read_to_string(&path).expect("readable .rs file");
            // The scanner protects against this tab reaching the label CLI
            // helpers. Files with no label namespace cannot contain that
            // edge, and may be independently edited while this test runs;
            // avoid parsing unrelated cfg/test blocks as if they were part
            // of this invariant.
            if !src.contains("labels::") && !src.contains("commands::labels") {
                continue;
            }
            scan_source(hits, &path.display().to_string(), &src);
        }
    }

    #[test]
    fn tui_never_reaches_a_printing_labels_helper() {
        let mut hits = Vec::new();
        scan(
            &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/tui"),
            &mut hits,
        );
        assert!(
            hits.is_empty(),
            "the Labels tab must drive `labels::{{add,set,remove}}_inner`, never a \
             helper that prints — a `println!` under raw mode + alternate screen \
             staircases across the frame and outlives every redraw:\n{}",
            hits.join("\n")
        );
    }

    /// Proves the `tests/` directory skip added for the `#[path]` test-file
    /// move: a forbidden call inside `<dir>/tests/*.rs` must not surface,
    /// while the same call one level up still does.
    #[test]
    fn scan_skips_the_tests_directory() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("tests")).unwrap();
        std::fs::write(
            dir.path().join("tests").join("moved.rs"),
            "labels::run_add(x)\n",
        )
        .unwrap();
        std::fs::write(dir.path().join("sibling.rs"), "labels::run_add(x)\n").unwrap();

        let mut hits = Vec::new();
        scan(dir.path(), &mut hits);

        assert_eq!(
            hits.len(),
            1,
            "expected exactly the sibling.rs hit, tests/ should be skipped: {hits:?}"
        );
        assert!(hits[0].contains("sibling.rs"), "hit was: {:?}", hits[0]);
    }

    // `scan_source` fixture table — mirrors `tui/mod.rs`'s
    // `strip_test_items` fixtures. Single-line escaped strings only: a raw
    // multi-line block would place fixture content at real column 0
    // inside whichever file hosts it, which this scanner (recursing over
    // all of `src/tui`) would then read as if it were real code.

    #[test]
    fn scan_source_finds_a_forbidden_call_in_production_code() {
        let mut hits = Vec::new();
        scan_source(
            &mut hits,
            "fixture",
            "PROD_BEFORE\nlabels::run_add(x)\nPROD_AFTER\n",
        );
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn scan_source_resumes_correctly_after_a_bare_mod_declaration() {
        // The fix for the bare-declaration gap: before this fix, a bare
        // `mod t;` (no closing brace of its own) would leave the scanner
        // skipping past PROD_AFTER looking for some unrelated `}`,
        // silently blinding the scan to everything past it.
        let mut hits = Vec::new();
        let src = "#[cfg(test)]\nmod t;\nlabels::run_add(x)\n";
        scan_source(&mut hits, "fixture", src);
        assert_eq!(
            hits.len(),
            1,
            "a call after a bare `mod t;` declaration must still be seen: {hits:?}"
        );
    }

    #[test]
    fn scan_source_does_not_scan_inside_an_ordinary_test_module() {
        let mut hits = Vec::new();
        let src = "#[cfg(test)]\nmod t {\nlabels::run_add(x)\n}\n";
        scan_source(&mut hits, "fixture", src);
        assert!(hits.is_empty());
    }

    #[test]
    fn scan_source_does_not_scan_inside_a_cfg_all_test_module() {
        // The fix for the exact-string-spelling gap: `editor_failure_tests`
        // in `tui/mod.rs` is spelled exactly this way. Before this fix, a
        // module gated like this was left unskipped, so a legitimate
        // reference to a forbidden name inside its own test code would have
        // been reported as a false positive.
        let mut hits = Vec::new();
        let src = "#[cfg(all(test, unix))]\nmod t {\nlabels::run_add(x)\n}\n";
        scan_source(&mut hits, "fixture", src);
        assert!(hits.is_empty());
    }

    #[test]
    #[should_panic(expected = "did not close its brackets")]
    fn scan_source_panics_on_a_multiline_attribute_it_cannot_classify() {
        let mut hits = Vec::new();
        scan_source(
            &mut hits,
            "fixture",
            "#[cfg(test)]\n#[cfg(\n    unix\n)]\nmod t {\n}\n",
        );
    }

    #[test]
    #[should_panic(expected = "ended in")]
    fn scan_source_panics_on_an_unclosed_marker_at_eof() {
        let mut hits = Vec::new();
        scan_source(&mut hits, "fixture", "#[cfg(test)]\nmod t {\nTEST_BODY\n");
    }

    /// The negative control. A guard that cannot fire is
    /// indistinguishable from a guard that passes — and this one is the
    /// more brittle of the pair, because the seam it protects is *new*:
    /// `labels::run_add` and `add_inner` differ by six characters.
    #[test]
    fn the_scan_reads_code_not_prose() {
        assert!(forbidden_hit(
            "        match crate::cli::commands::labels::run_add(config_path, ...) {"
        ));

        // The same spelling as a comment or inside a string literal is text,
        // not a call. An earlier control only used prose that avoided the
        // `(`, which proved the needle's shape rather than the scan's ability
        // to tell code from text.
        for text in [
            "        // never call labels::run_add( from here",
            "        const W: &str = \"labels::run_remove(\";",
            "        /// `labels::run_list(` prints; drive `list_inner` instead.",
            "//! `cli::commands::labels::{add_inner, set_inner, remove_inner}` — the",
        ] {
            assert!(!forbidden_hit(text), "text read as a call: {text}");
        }

        // The seam itself must not be caught by its own guard.
        assert!(!forbidden_hit(
            "        match add_inner(config_path, &resolved.id, form.kind, ...) {"
        ));
    }

    #[test]
    fn the_scan_sees_a_printing_verb_imported_under_an_alias() {
        for import in [
            "use crate::cli::commands::labels::run_add as add_label;",
            "    use crate::cli::commands::labels::{run_add, run_set};",
            "use crate::cli::commands::labels::run_show;",
        ] {
            assert!(forbidden_hit(import), "alias import not seen: {import}");
        }

        // The non-printing seam may be imported freely, aliased or not.
        for import in [
            "use crate::cli::commands::labels::{add_inner, set_inner, remove_inner};",
            "use crate::cli::commands::labels::set_fields_inner;",
        ] {
            assert!(!forbidden_hit(import), "seam import refused: {import}");
        }
    }
}
