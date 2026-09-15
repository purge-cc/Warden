//! Shared filter cards, chip focus, and anchored draft editors.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::layout::{Alignment, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, Clear, Paragraph};
use ratatui::Frame;

use super::app::{
    App, DeviceGroupBy, InputMode, Leaf, ListsKindFilter, LogsLevelFilter, SincePreset,
};
use super::mouse::{self, MouseAction};
use super::query_log_controls::FilterFocus;
use super::theme::{self, CardRole, T};

const QUERY_DESCRIPTION: &str = "Narrow Requests by Domain, Client & Time";
const DEVICE_DESCRIPTION: &str = "Find Devices by Subnet & Organize the List";
const LISTS_DESCRIPTION: &str = "Search, Direction & Reset";
const LOGS_DESCRIPTION: &str = "Search Service Messages by Text & Severity";

struct Chip {
    label: &'static str,
    value: String,
    active: bool,
}

impl Chip {
    fn new(label: &'static str, value: impl Into<String>, active: bool) -> Self {
        Self {
            label,
            value: value.into(),
            active,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ChoiceKind {
    DeviceSubnet,
    DeviceGroup,
    ListsDirection,
    LogsLevel,
}

#[derive(Debug, Clone)]
pub(crate) struct ChoiceEditor {
    kind: ChoiceKind,
    selected: usize,
    focus: FilterFocus,
    subnets: Vec<String>,
}

impl ChoiceEditor {
    fn open(kind: ChoiceKind, selected: usize) -> Self {
        Self {
            kind,
            selected,
            focus: FilterFocus::Value,
            subnets: Vec::new(),
        }
    }

    fn refreshed(&self, app: &App) -> Self {
        let mut editor = self.clone();
        if editor.kind == ChoiceKind::DeviceSubnet {
            let draft = self.subnets.get(self.selected).cloned();
            editor.subnets = subnet_choices(app);
            if let Some(draft) = draft {
                if !editor.subnets.contains(&draft) {
                    editor
                        .subnets
                        .insert(editor.subnets.len().saturating_sub(1), draft.clone());
                }
                editor.selected = editor
                    .subnets
                    .iter()
                    .position(|value| *value == draft)
                    .unwrap_or(0);
            }
        }
        editor
    }

    fn choices(&self) -> Vec<&str> {
        match self.kind {
            ChoiceKind::DeviceSubnet => self.subnets.iter().map(String::as_str).collect(),
            ChoiceKind::DeviceGroup => vec!["None", "Owner", "Department", "Profile"],
            ChoiceKind::ListsDirection => vec!["All", "Deny", "Allow", "Off"],
            ChoiceKind::LogsLevel => vec!["All", "ERROR", "WARN", "INFO"],
        }
    }

    fn title(&self) -> &'static str {
        match self.kind {
            ChoiceKind::DeviceSubnet => "Subnet",
            ChoiceKind::DeviceGroup => "Group",
            ChoiceKind::ListsDirection => "Direction",
            ChoiceKind::LogsLevel => "Level",
        }
    }

    fn leaf_and_index(&self) -> (Leaf, usize) {
        match self.kind {
            ChoiceKind::DeviceSubnet => (Leaf::Devices, 0),
            ChoiceKind::DeviceGroup => (Leaf::Devices, 1),
            ChoiceKind::ListsDirection => (Leaf::Lists, 1),
            ChoiceKind::LogsLevel => (Leaf::Logs, 1),
        }
    }
}

fn subnet_choices(app: &App) -> Vec<String> {
    let configured = app
        .loaded_config
        .as_ref()
        .map(|loaded| loaded.config.subnets.as_slice())
        .unwrap_or_default();
    let unmapped = app
        .device_view
        .as_ref()
        .map(|view| view.unmapped.as_slice())
        .unwrap_or_default();
    let mut cidrs = std::collections::BTreeSet::new();
    for subnet in configured {
        cidrs.extend(subnet.cidrs.iter().cloned());
    }
    cidrs.extend(
        super::tabs::subnets::discover_candidates(unmapped, configured)
            .into_iter()
            .map(|candidate| candidate.cidr),
    );
    if let Some(applied) = &app.devices.filter_subnet {
        cidrs.insert(applied.clone());
    }
    std::iter::once("All".to_string())
        .chain(cidrs)
        .chain(std::iter::once("Custom CIDR…".to_string()))
        .collect()
}

fn chips(app: &App) -> Vec<Chip> {
    match app.active_leaf {
        Leaf::QueryLog => {
            let q = &app.query_log;
            let advanced = super::tabs::query_log::advanced_predicate_count(app);
            let client = match q.client_ips.as_slice() {
                [] => q
                    .filter_client
                    .clone()
                    .unwrap_or_else(|| "All Clients".into()),
                [ip] => app
                    .device_view
                    .as_ref()
                    .and_then(|view| view.mapped.iter().find(|device| device.ip == *ip))
                    .map(|device| device.name.clone())
                    .unwrap_or_else(|| ip.clone()),
                ips => format!("{} Clients", ips.len()),
            };
            vec![
                Chip::new(
                    "Domain",
                    q.filter_domain.as_deref().unwrap_or("All Domains"),
                    q.filter_domain.is_some(),
                ),
                Chip::new(
                    "Client",
                    client,
                    !q.client_ips.is_empty() || q.filter_client.is_some(),
                ),
                Chip::new(
                    "Period",
                    q.since.compact_label(),
                    q.since != SincePreset::Off,
                ),
                Chip::new(
                    "Blocked",
                    if q.blocked_only {
                        "Blocked Only"
                    } else {
                        "All Results"
                    },
                    q.blocked_only,
                ),
                Chip::new("Advanced", format!("{advanced} Rules"), advanced > 0),
                Chip::new("Reset All", "", false),
            ]
        }
        Leaf::Devices => vec![
            Chip::new(
                "Subnet",
                app.devices.filter_subnet.as_deref().unwrap_or("All"),
                app.devices.filter_subnet.is_some(),
            ),
            Chip::new(
                "Group",
                app.devices.group_by.display_label(),
                app.devices.group_by != DeviceGroupBy::None,
            ),
            Chip::new("Clear Subnet", "", false),
            Chip::new("Details", "", false),
        ],
        Leaf::Lists => vec![
            Chip::new(
                "Search",
                app.lists.filter_text.as_deref().unwrap_or("Any Text"),
                app.lists.filter_text.is_some(),
            ),
            Chip::new(
                "Direction",
                app.lists.kind_filter.display_label(),
                app.lists.kind_filter != ListsKindFilter::All,
            ),
            Chip::new("Reset", "", false),
        ],
        Leaf::Logs => vec![
            Chip::new(
                "Search",
                app.logs.filter_text.as_deref().unwrap_or("Any Text"),
                app.logs.filter_text.is_some(),
            ),
            Chip::new(
                "Level",
                app.logs.level_filter.display_label(),
                app.logs.level_filter != LogsLevelFilter::All,
            ),
            Chip::new(
                "Clear",
                "",
                app.logs.level_filter != LogsLevelFilter::All || app.logs.filter_text.is_some(),
            ),
        ],
        _ => Vec::new(),
    }
}

fn card_copy(leaf: Leaf) -> Option<(&'static str, &'static str)> {
    match leaf {
        Leaf::QueryLog => Some(("Query Filters", QUERY_DESCRIPTION)),
        Leaf::Devices => Some(("Device Filters", DEVICE_DESCRIPTION)),
        Leaf::Lists => Some(("List Filters", LISTS_DESCRIPTION)),
        Leaf::Logs => Some(("Filters", LOGS_DESCRIPTION)),
        _ => None,
    }
}

fn columns(leaf: Leaf, body_width: u16) -> usize {
    match leaf {
        Leaf::QueryLog => {
            if body_width >= 150 {
                6
            } else {
                3
            }
        }
        Leaf::Devices => {
            if body_width >= 100 {
                4
            } else {
                2
            }
        }
        Leaf::Lists => {
            if body_width >= 100 {
                3
            } else {
                2
            }
        }
        Leaf::Logs => 3,
        _ => 1,
    }
}

fn card_area(area: Rect, app: &App) -> Rect {
    let count = chips(app).len();
    if count == 0 || area.is_empty() {
        return Rect::default();
    }
    let body_width = area.width.saturating_sub(4);
    let columns = columns(app.active_leaf, body_width).max(1);
    let rows = count.div_ceil(columns) as u16;
    Rect::new(area.x, area.y, area.width, (4 + rows).min(area.height))
}

fn card_body(area: Rect) -> Rect {
    Rect::new(
        area.x.saturating_add(2),
        area.y.saturating_add(3),
        area.width.saturating_sub(4),
        area.height.saturating_sub(4),
    )
}

pub(super) fn chip_area(area: Rect, app: &App, index: usize) -> Rect {
    let body = card_body(card_area(area, app));
    let columns = columns(app.active_leaf, body.width).max(1);
    let width = body.width / columns as u16;
    Rect::new(
        body.x.saturating_sub(1) + (index % columns) as u16 * width,
        body.y + (index / columns) as u16,
        width.saturating_sub(1),
        1,
    )
}

pub(super) fn chip_style(active: bool, focused: bool) -> Style {
    if focused {
        Style::default()
            .fg(T.text_inverse)
            .bg(T.warden_teal)
            .add_modifier(Modifier::BOLD)
    } else if active {
        Style::default()
            .fg(T.warden_teal)
            .bg(T.bg_highlight)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(T.text_secondary).bg(T.bg_surface)
    }
}

fn render_chips(f: &mut Frame, area: Rect, app: &App) {
    let chips = chips(app);
    for (index, chip) in chips.iter().enumerate() {
        let rect = chip_area(area, app, index);
        if rect.is_empty() {
            continue;
        }
        let suffix = if chip.active { " ×" } else { "" };
        let label = if chip.value.is_empty() {
            chip.label.to_owned()
        } else {
            format!("{}: {}", chip.label, chip.value)
        };
        let available = rect
            .width
            .saturating_sub(2 + super::text::width(suffix).min(u16::MAX as usize) as u16);
        let label = super::text::fit(&label, available as usize);
        f.render_widget(
            Paragraph::new(format!(" {label}{suffix} ")).style(chip_style(
                chip.active,
                app.filter_focus == Some((app.active_leaf, index)),
            )),
            rect,
        );
        mouse::register(app, rect, MouseAction::Filter(app.active_leaf, index));
    }
}

/// Draw the standalone blue filter card and return the remaining page area.
/// The next card overlaps its bottom page-background gutter by one row.
pub(super) fn render_card(f: &mut Frame, area: Rect, app: &App) -> Rect {
    let Some((title, subtitle)) = card_copy(app.active_leaf) else {
        return area;
    };
    let filter_area = card_area(area, app);
    if filter_area.is_empty() {
        return area;
    }
    theme::filled_card(
        f.buffer_mut(),
        filter_area,
        title,
        subtitle,
        CardRole::Summary,
    );
    render_chips(f, area, app);
    let y = filter_area.bottom().saturating_sub(1);
    Rect::new(area.x, y, area.width, area.bottom().saturating_sub(y))
}

pub(super) fn handle_key(app: &mut App, key: KeyEvent) -> bool {
    let count = chips(app).len();
    if count == 0 {
        app.filter_focus = None;
        return false;
    }
    if matches!(key.code, KeyCode::Char('f' | 'F'))
        && !key
            .modifiers
            .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
    {
        app.filter_focus = Some((app.active_leaf, 0));
        return true;
    }
    let Some((leaf, index)) = app.filter_focus else {
        return false;
    };
    if leaf != app.active_leaf {
        app.filter_focus = None;
        return false;
    }
    match key.code {
        KeyCode::Left | KeyCode::Up | KeyCode::BackTab => {
            app.filter_focus = Some((leaf, (index + count - 1) % count))
        }
        KeyCode::Right | KeyCode::Down | KeyCode::Tab => {
            app.filter_focus = Some((leaf, (index + 1) % count))
        }
        KeyCode::Home => app.filter_focus = Some((leaf, 0)),
        KeyCode::End => app.filter_focus = Some((leaf, count - 1)),
        KeyCode::PageUp | KeyCode::PageDown => {}
        KeyCode::Enter | KeyCode::Char(' ') => activate(app, index),
        KeyCode::Delete => clear(app, index),
        KeyCode::Esc => app.filter_focus = None,
        _ => return false,
    }
    true
}

pub(super) fn activate(app: &mut App, index: usize) {
    if index >= chips(app).len() {
        return;
    }
    app.filter_focus = Some((app.active_leaf, index));
    app.filter_editor_focus = FilterFocus::Value;
    app.filter_editor_error = None;
    match (app.active_leaf, index) {
        (Leaf::QueryLog, 0) => {
            app.query_log.domain_focus = FilterFocus::Value;
            app.input_mode =
                InputMode::FilterDomain(app.query_log.filter_domain.clone().unwrap_or_default());
        }
        (Leaf::QueryLog, 1) => {
            app.query_log.client_picker =
                Some(super::query_log_client_picker::QueryLogClientPicker::open(
                    &app.query_log.client_ips,
                ));
            super::reads::request_query_log_picker_metadata(app);
        }
        (Leaf::QueryLog, 2) => {
            app.query_log.period_menu = true;
            app.query_log.period_draft = app.query_log.since;
            app.query_log.period_focus = FilterFocus::Value;
        }
        (Leaf::QueryLog, 3) => {
            app.query_log.blocked_only = !app.query_log.blocked_only;
            super::request_query_log_filter_fetch(app);
        }
        (Leaf::QueryLog, 4) => {
            app.query_log.advanced_modal = Some(
                super::query_log_filter_modal::QueryLogFilterModal::open(&app.query_log.advanced),
            )
        }
        (Leaf::QueryLog, 5) => clear(app, 5),
        (Leaf::Devices, 0) => {
            let mut editor = ChoiceEditor::open(ChoiceKind::DeviceSubnet, 0);
            editor.subnets = subnet_choices(app);
            editor.selected = app
                .devices
                .filter_subnet
                .as_ref()
                .and_then(|cidr| editor.subnets.iter().position(|option| option == cidr))
                .unwrap_or(0);
            app.filter_choice_editor = Some(editor);
        }
        (Leaf::Devices, 1) => {
            app.filter_choice_editor = Some(ChoiceEditor::open(
                ChoiceKind::DeviceGroup,
                app.devices.group_by.index(),
            ));
        }
        (Leaf::Devices, 2) => clear(app, 0),
        (Leaf::Devices, 3) => {
            super::open_device_inspect(app);
        }
        (Leaf::Lists, 0) => {
            app.input_mode =
                InputMode::FilterLists(app.lists.filter_text.clone().unwrap_or_default())
        }
        (Leaf::Lists, 1) => {
            app.filter_choice_editor = Some(ChoiceEditor::open(
                ChoiceKind::ListsDirection,
                app.lists.kind_filter.index(),
            ));
        }
        (Leaf::Lists, 2) => clear(app, 2),
        (Leaf::Logs, 0) => {
            app.input_mode = InputMode::FilterLogs(app.logs.filter_text.clone().unwrap_or_default())
        }
        (Leaf::Logs, 1) => {
            app.filter_choice_editor = Some(ChoiceEditor::open(
                ChoiceKind::LogsLevel,
                app.logs.level_filter.index(),
            ));
        }
        (Leaf::Logs, 2) => clear(app, 2),
        _ => {}
    }
}

fn clear(app: &mut App, index: usize) {
    match (app.active_leaf, index) {
        (Leaf::QueryLog, 0) => app.query_log.filter_domain = None,
        (Leaf::QueryLog, 1) => {
            app.query_log.filter_client = None;
            app.query_log.client_ips.clear();
            app.query_log.client_mode = super::app::ClientFilterMode::Selected;
        }
        (Leaf::QueryLog, 2) => app.query_log.since = SincePreset::Off,
        (Leaf::QueryLog, 3) => app.query_log.blocked_only = false,
        (Leaf::QueryLog, 4) => app.query_log.advanced = Default::default(),
        (Leaf::QueryLog, 5) => {
            app.query_log.filter_domain = None;
            app.query_log.filter_client = None;
            app.query_log.client_ips.clear();
            app.query_log.client_mode = super::app::ClientFilterMode::Selected;
            app.query_log.since = SincePreset::Off;
            app.query_log.blocked_only = false;
            app.query_log.advanced = Default::default();
        }
        (Leaf::Devices, 0 | 2) => app.devices.filter_subnet = None,
        (Leaf::Devices, 1) => app.devices.group_by = DeviceGroupBy::None,
        (Leaf::Lists, 0) => app.lists.filter_text = None,
        (Leaf::Lists, 1) => app.lists.kind_filter = ListsKindFilter::All,
        (Leaf::Lists, 2) => {
            app.lists.filter_text = None;
            app.lists.kind_filter = ListsKindFilter::All;
        }
        (Leaf::Logs, 0) => app.logs.filter_text = None,
        (Leaf::Logs, 1) => app.logs.level_filter = LogsLevelFilter::All,
        (Leaf::Logs, 2) => {
            app.logs.filter_text = None;
            app.logs.level_filter = LogsLevelFilter::All;
        }
        _ => return,
    }
    match app.active_leaf {
        Leaf::QueryLog => super::request_query_log_filter_fetch(app),
        Leaf::Lists => super::reconcile_lists_selection(app),
        Leaf::Logs => super::request_logs_filter_fetch(app),
        _ => {}
    }
}

pub(super) fn text_editor_open(app: &App) -> bool {
    matches!(
        app.input_mode,
        InputMode::FilterLists(_) | InputMode::FilterLogs(_) | InputMode::FilterDevicesSubnet(_)
    )
}

pub(super) fn choice_editor_open(app: &App) -> bool {
    app.filter_choice_editor.is_some()
}

pub(super) fn click_choice(app: &mut App, index: usize) -> bool {
    app.filter_choice_editor = app
        .filter_choice_editor
        .as_ref()
        .map(|editor| editor.refreshed(app));
    let Some(editor) = app.filter_choice_editor.as_mut() else {
        return false;
    };
    if index >= editor.choices().len() {
        return false;
    }
    editor.selected = index;
    editor.focus = FilterFocus::Value;
    true
}

pub(super) fn handle_choice_key(app: &mut App, key: KeyEvent) -> bool {
    let Some(mut editor) = app.filter_choice_editor.take() else {
        return false;
    };
    editor = editor.refreshed(app);
    let key = if super::is_save_key(key) {
        editor.focus = FilterFocus::Apply;
        KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE)
    } else {
        key
    };
    match key.code {
        KeyCode::Esc => return true,
        KeyCode::Tab => editor.focus = editor.focus.next(),
        KeyCode::BackTab => editor.focus = editor.focus.prev(),
        KeyCode::Up | KeyCode::Down | KeyCode::Home | KeyCode::End => {
            editor.focus = FilterFocus::Value;
            let count = editor.choices().len();
            editor.selected = match key.code {
                KeyCode::Up => (editor.selected + count - 1) % count,
                KeyCode::Down => (editor.selected + 1) % count,
                KeyCode::Home => 0,
                _ => count - 1,
            };
        }
        KeyCode::Enter if editor.focus == FilterFocus::Discard => return true,
        KeyCode::Enter => {
            match editor.kind {
                ChoiceKind::DeviceSubnet => {
                    if editor.selected + 1 == editor.subnets.len() {
                        app.input_mode = InputMode::FilterDevicesSubnet(
                            app.devices.filter_subnet.clone().unwrap_or_default(),
                        );
                        app.filter_editor_focus = FilterFocus::Value;
                    } else {
                        app.devices.filter_subnet =
                            (editor.selected != 0).then(|| editor.subnets[editor.selected].clone());
                    }
                }
                ChoiceKind::DeviceGroup => {
                    app.devices.group_by = DeviceGroupBy::from_index(editor.selected)
                }
                ChoiceKind::ListsDirection => {
                    app.lists.kind_filter = ListsKindFilter::from_index(editor.selected);
                    super::reconcile_lists_selection(app);
                }
                ChoiceKind::LogsLevel => {
                    app.logs.level_filter = LogsLevelFilter::from_index(editor.selected);
                    super::request_logs_filter_fetch(app);
                }
            }
            return true;
        }
        _ => {}
    }
    app.filter_choice_editor = Some(editor);
    true
}

pub(super) fn handle_text_key(app: &mut App, key: KeyEvent) -> bool {
    if !text_editor_open(app) {
        return false;
    }
    let apply = super::is_save_key(key)
        || (key.code == KeyCode::Enter && app.filter_editor_focus != FilterFocus::Discard);
    if key.code == KeyCode::Esc
        || (key.code == KeyCode::Enter && app.filter_editor_focus == FilterFocus::Discard)
    {
        app.input_mode = InputMode::Normal;
        app.filter_editor_error = None;
    } else if apply {
        if let InputMode::FilterDevicesSubnet(value) = &app.input_mode {
            if !value.trim().is_empty() && crate::config::cidr::Cidr::parse(value.trim()).is_err() {
                app.filter_editor_error =
                    Some("Enter a valid IPv4 or IPv6 CIDR, or leave empty for all devices.".into());
                return true;
            }
        }
        let mode = std::mem::replace(&mut app.input_mode, InputMode::Normal);
        let value = |s: String| {
            let s = s.trim().to_owned();
            (!s.is_empty()).then_some(s)
        };
        match mode {
            InputMode::FilterLists(s) => {
                app.lists.filter_text = value(s);
                super::reconcile_lists_selection(app);
            }
            InputMode::FilterLogs(s) => {
                app.logs.filter_text = value(s);
                super::request_logs_filter_fetch(app);
            }
            InputMode::FilterDevicesSubnet(s) => app.devices.filter_subnet = value(s),
            _ => unreachable!("text_editor_open checked the active input mode"),
        }
        app.filter_editor_error = None;
    } else {
        match key.code {
            KeyCode::Tab | KeyCode::Down => {
                app.filter_editor_focus = app.filter_editor_focus.next()
            }
            KeyCode::BackTab | KeyCode::Up => {
                app.filter_editor_focus = app.filter_editor_focus.prev()
            }
            _ if app.filter_editor_focus == FilterFocus::Value => {
                let (InputMode::FilterLists(text)
                | InputMode::FilterLogs(text)
                | InputMode::FilterDevicesSubnet(text)) = &mut app.input_mode
                else {
                    return true;
                };
                super::drive_text_input(text, key);
                app.filter_editor_error = None;
            }
            _ => {}
        }
    }
    true
}

fn popup_rect(bounds: Rect, anchor: Rect, width: u16, height: u16) -> Rect {
    let bounds = Rect::new(
        bounds.x.saturating_add(1),
        bounds.y,
        bounds.width.saturating_sub(2),
        bounds.height,
    );
    let width = width.min(bounds.width);
    let height = height.min(bounds.height);
    Rect::new(
        anchor
            .x
            .clamp(bounds.x, bounds.right().saturating_sub(width)),
        anchor
            .bottom()
            .clamp(bounds.y, bounds.bottom().saturating_sub(height)),
        width,
        height,
    )
}

pub(super) fn popup(
    f: &mut Frame,
    bounds: Rect,
    anchor: Rect,
    size: (u16, u16),
    title: &str,
) -> Rect {
    mouse::begin_overlay();
    let rect = popup_rect(bounds, anchor, size.0, size.1);
    f.render_widget(Clear, rect);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Plain)
        .border_style(Style::default().fg(T.text_primary))
        .style(Style::default().bg(T.bg_elevated))
        .title(Line::styled(
            format!(" {} ", title.to_uppercase()),
            Style::default()
                .fg(T.text_primary)
                .add_modifier(Modifier::BOLD),
        ));
    let inner = block.inner(rect);
    f.render_widget(block, rect);
    Rect::new(
        inner.x.saturating_add(1),
        inner.y,
        inner.width.saturating_sub(2),
        inner.height,
    )
}

pub(super) fn render_actions(f: &mut Frame, area: Rect, focus: FilterFocus) {
    let secondary = |focused| {
        if focused {
            Style::default()
                .fg(T.text_primary)
                .bg(T.bg_highlight)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(T.text_secondary)
        }
    };
    let primary = |focused| {
        if focused {
            Style::default()
                .fg(T.text_inverse)
                .bg(T.warden_teal)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(T.warden_teal)
        }
    };
    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(" Discard ", secondary(focus == FilterFocus::Discard)),
            Span::raw("  "),
            Span::styled(" Apply ", primary(focus == FilterFocus::Apply)),
        ]))
        .alignment(Alignment::Right),
        area,
    );
    let apply = Rect::new(area.right().saturating_sub(7), area.y, 7.min(area.width), 1);
    let discard = Rect::new(
        area.right().saturating_sub(18),
        area.y,
        9.min(area.width),
        1,
    );
    mouse::register_overlay(discard, KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    mouse::register_overlay(
        apply,
        KeyEvent::new(KeyCode::Char('s'), KeyModifiers::CONTROL),
    );
}

pub(super) fn input_text(value: &str, width: u16) -> String {
    let mut shown = format!("{value}▏");
    while super::text::width(&shown) > width as usize && !shown.is_empty() {
        shown.remove(0);
    }
    shown
}

pub(super) fn render_text_editor(f: &mut Frame, area: Rect, app: &App) {
    let (title, help, value, index) = match &app.input_mode {
        InputMode::FilterLists(value) => ("Search", "Match list ID, name, or source", value, 0),
        InputMode::FilterLogs(value) => ("Search", "Match message or target", value, 0),
        InputMode::FilterDevicesSubnet(value) => {
            ("Subnet", "Empty shows all devices · enter CIDR", value, 0)
        }
        _ => return,
    };
    let filter_bounds = if app.active_leaf == Leaf::Devices {
        super::tabs::devices::panels(area).0
    } else {
        area
    };
    let anchor = chip_area(filter_bounds, app, index);
    let inner = popup(f, area, anchor, (60, 7), title);
    let focused = app.filter_editor_focus == FilterFocus::Value;
    let shown = if focused {
        input_text(value, inner.width)
    } else if value.is_empty() {
        "All".to_owned()
    } else {
        super::text::fit(value, inner.width as usize)
    };
    f.render_widget(
        Paragraph::new(shown.as_str()).style(chip_style(!value.is_empty(), focused)),
        Rect::new(inner.x, inner.y, inner.width, 1),
    );
    mouse::register_overlay_action(
        Rect::new(inner.x, inner.y, inner.width, 1),
        MouseAction::OverlayField(0),
    );
    f.render_widget(
        Paragraph::new(help).style(Style::default().fg(T.text_muted)),
        Rect::new(inner.x, inner.y + 1, inner.width, 1),
    );
    if let Some(error) = app.filter_editor_error.as_deref() {
        f.render_widget(
            Paragraph::new(super::text::fit(error, inner.width as usize))
                .style(Style::default().fg(T.error)),
            Rect::new(inner.x, inner.bottom().saturating_sub(2), inner.width, 1),
        );
    }
    render_actions(
        f,
        Rect::new(inner.x, inner.bottom().saturating_sub(1), inner.width, 1),
        app.filter_editor_focus,
    );
    if focused {
        f.set_cursor_position((
            inner.x + super::text::width(&shown).saturating_sub(1) as u16,
            inner.y,
        ));
    }
}

pub(super) fn render_choice_editor(f: &mut Frame, area: Rect, app: &App) {
    let Some(editor) = app.filter_choice_editor.as_ref() else {
        return;
    };
    let editor = editor.refreshed(app);
    let (leaf, index) = editor.leaf_and_index();
    if leaf != app.active_leaf {
        return;
    }
    let choices = editor.choices();
    let filter_bounds = if app.active_leaf == Leaf::Devices {
        super::tabs::devices::panels(area).0
    } else {
        area
    };
    let anchor = chip_area(filter_bounds, app, index);
    let inner = popup(
        f,
        area,
        anchor,
        (
            if editor.kind == ChoiceKind::DeviceSubnet {
                36
            } else {
                48
            },
            choices.len() as u16 + 4,
        ),
        editor.title(),
    );
    let visible = inner.height.saturating_sub(1) as usize;
    let offset = editor.selected.saturating_add(1).saturating_sub(visible);
    for (index, choice) in choices.iter().enumerate().skip(offset).take(visible) {
        let selected = editor.selected == index;
        let row = Rect::new(inner.x, inner.y + (index - offset) as u16, inner.width, 1);
        f.render_widget(
            Paragraph::new(format!("({}) {choice}", if selected { "x" } else { " " })).style(
                chip_style(selected, selected && editor.focus == FilterFocus::Value),
            ),
            row,
        );
        mouse::register_overlay_action(row, MouseAction::OverlayChoice(index));
    }
    render_actions(
        f,
        Rect::new(inner.x, inner.bottom().saturating_sub(1), inner.width, 1),
        editor.focus,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    #[test]
    fn query_filter_focus_cycles_all_six_and_delete_keeps_focus() {
        let mut app = App::new();
        app.active_leaf = Leaf::QueryLog;
        assert!(handle_key(&mut app, key(KeyCode::Char('F'))));
        for _ in 0..5 {
            handle_key(&mut app, key(KeyCode::Tab));
        }
        assert_eq!(app.filter_focus, Some((Leaf::QueryLog, 5)));
        app.query_log.blocked_only = true;
        handle_key(&mut app, key(KeyCode::Delete));
        assert!(!app.query_log.has_active_filters());
        assert_eq!(app.filter_focus, Some((Leaf::QueryLog, 5)));
    }

    #[test]
    fn editor_discard_preserves_applied_value_and_chip_focus() {
        let mut app = App::new();
        app.active_leaf = Leaf::Lists;
        app.lists.kind_filter = ListsKindFilter::Allow;
        activate(&mut app, 1);
        handle_choice_key(&mut app, key(KeyCode::Down));
        handle_choice_key(&mut app, key(KeyCode::Esc));
        assert_eq!(app.lists.kind_filter, ListsKindFilter::Allow);
        assert_eq!(app.filter_focus, Some((Leaf::Lists, 1)));
    }

    #[test]
    fn pointer_choice_updates_only_the_draft() {
        let mut app = App::new();
        app.active_leaf = Leaf::Logs;
        app.logs.level_filter = LogsLevelFilter::Warn;
        activate(&mut app, 1);
        assert!(click_choice(&mut app, 3));
        assert_eq!(app.logs.level_filter, LogsLevelFilter::Warn);
        handle_choice_key(&mut app, key(KeyCode::Enter));
        assert_eq!(app.logs.level_filter, LogsLevelFilter::Info);
    }

    #[test]
    fn direction_editor_applies_off_and_reset_clears_both_filters() {
        let mut app = App::new();
        app.active_leaf = Leaf::Lists;
        app.lists.filter_text = Some("privacy".into());
        activate(&mut app, 1);
        for _ in 0..3 {
            handle_choice_key(&mut app, key(KeyCode::Down));
        }
        handle_choice_key(&mut app, key(KeyCode::Enter));
        assert_eq!(app.lists.kind_filter, ListsKindFilter::Off);
        activate(&mut app, 2);
        assert_eq!(app.lists.kind_filter, ListsKindFilter::All);
        assert!(app.lists.filter_text.is_none());
    }

    #[test]
    fn query_card_geometry_is_one_row_wide_and_two_rows_narrow() {
        let mut app = App::new();
        app.active_leaf = Leaf::QueryLog;
        assert_eq!(card_area(Rect::new(0, 0, 180, 30), &app).height, 5);
        assert_eq!(card_area(Rect::new(0, 0, 80, 30), &app).height, 6);
    }
    fn unmapped(ip: &str) -> crate::ipc::protocol::UnmappedDeviceDto {
        serde_json::from_value(serde_json::json!({
            "ip": ip, "queries": 0, "blocked": 0, "last_seen": 0, "online": false
        }))
        .unwrap()
    }

    #[tokio::test]
    async fn subnet_dropdown_uses_discovery_and_keeps_custom_validation_in_dispatch() {
        let mut app = App::new();
        app.active_leaf = Leaf::Devices;
        app.device_view = Some(crate::ipc::protocol::DeviceViewDto {
            mapped: vec![],
            unmapped: vec![unmapped("192.0.2.1"), unmapped("192.0.2.2")],
        });
        let poller =
            super::super::IpcPoller::new(std::path::Path::new("/tmp/warden-filter-test.sock"));
        let path = std::path::Path::new("/dev/null");
        activate(&mut app, 0);
        assert_eq!(
            app.filter_choice_editor.as_ref().unwrap().choices(),
            ["All", "192.0.2.0/24", "Custom CIDR…"]
        );
        super::super::handle_key(&mut app, key(KeyCode::Down), &poller, path).await;
        assert!(app.devices.filter_subnet.is_none());
        super::super::handle_key(&mut app, key(KeyCode::Enter), &poller, path).await;
        assert_eq!(app.devices.filter_subnet.as_deref(), Some("192.0.2.0/24"));
        activate(&mut app, 0);
        super::super::handle_key(&mut app, key(KeyCode::End), &poller, path).await;
        super::super::handle_key(&mut app, key(KeyCode::Enter), &poller, path).await;
        app.input_mode = InputMode::FilterDevicesSubnet("invalid".into());
        super::super::handle_key(&mut app, key(KeyCode::Enter), &poller, path).await;
        assert!(app.filter_editor_error.is_some());
        assert_eq!(app.devices.filter_subnet.as_deref(), Some("192.0.2.0/24"));
        app.input_mode = InputMode::FilterDevicesSubnet("2001:db8::/32".into());
        super::super::handle_key(&mut app, key(KeyCode::Enter), &poller, path).await;
        assert_eq!(app.devices.filter_subnet.as_deref(), Some("2001:db8::/32"));
    }

    #[tokio::test]
    async fn choice_popup_mouse_edits_a_draft_and_discard_keeps_applied_state() {
        use crossterm::event::{MouseButton, MouseEvent, MouseEventKind};
        use ratatui::{backend::TestBackend, Terminal};
        let mut app = App::new();
        app.active_leaf = Leaf::Logs;
        app.logs.level_filter = LogsLevelFilter::Warn;
        activate(&mut app, 1);
        let area = Rect::new(0, 0, 80, 16);
        let anchor = chip_area(area, &app, 1);
        let rect = popup_rect(area, anchor, 48, 8);
        let mut terminal = Terminal::new(TestBackend::new(80, 16)).unwrap();
        terminal
            .draw(|f| render_choice_editor(f, area, &app))
            .unwrap();
        let poller =
            super::super::IpcPoller::new(std::path::Path::new("/tmp/warden-filter-test.sock"));
        let path = std::path::Path::new("/dev/null");
        super::super::handle_mouse(
            &mut app,
            MouseEvent {
                kind: MouseEventKind::Down(MouseButton::Left),
                column: rect.x + 2,
                row: rect.y + 4,
                modifiers: KeyModifiers::NONE,
            },
            &poller,
            path,
        )
        .await;
        assert_eq!(app.filter_choice_editor.as_ref().unwrap().selected, 3);
        assert_eq!(app.logs.level_filter, LogsLevelFilter::Warn);
        super::super::handle_key(&mut app, key(KeyCode::Tab), &poller, path).await;
        super::super::handle_key(&mut app, key(KeyCode::Enter), &poller, path).await;
        assert!(app.filter_choice_editor.is_none());
        assert_eq!(app.logs.level_filter, LogsLevelFilter::Warn);
    }

    #[tokio::test]
    async fn details_chip_and_keyboard_open_the_same_selected_device_inspection() {
        let mut app = App::new();
        app.active_leaf = Leaf::Devices;
        let poller =
            super::super::IpcPoller::new(std::path::Path::new("/tmp/warden-filter-test.sock"));
        let path = std::path::Path::new("/dev/null");
        activate(&mut app, 3);
        assert!(!app.devices.inspect_open);
        app.device_view = Some(crate::ipc::protocol::DeviceViewDto {
            mapped: vec![],
            unmapped: vec![unmapped("192.0.2.4")],
        });
        activate(&mut app, 3);
        assert!(app.devices.inspect_open);
        let identity = app.devices.selected_id.clone();
        super::super::handle_key(&mut app, key(KeyCode::Esc), &poller, path).await;
        assert!(!app.devices.inspect_open);
        app.filter_focus = None;
        super::super::handle_key(&mut app, key(KeyCode::Char('i')), &poller, path).await;
        assert!(app.devices.inspect_open);
        assert_eq!(app.devices.selected_id, identity);
    }
}
