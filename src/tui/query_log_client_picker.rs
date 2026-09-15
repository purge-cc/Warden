//! Searchable, draft-based exact client picker for Query Log.

use std::collections::{BTreeMap, BTreeSet};

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::layout::Rect;
use ratatui::Frame;

use super::filter_chips;
use super::mouse::{self, MouseAction};
use super::query_log_controls::FilterFocus;
use super::theme::T;
use crate::ipc::protocol::DeviceViewDto;
use ratatui::style::Style;
use ratatui::widgets::Paragraph;

const W: u16 = 48;
const TITLE: &str = "Client filter";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ClientOption {
    pub(crate) ip: String,
    pub(crate) name: Option<String>,
}

impl ClientOption {
    pub(crate) fn label(&self) -> String {
        match &self.name {
            Some(name) if !name.is_empty() => format!("{name}  {}", self.ip),
            _ => self.ip.clone(),
        }
    }
}

/// An open picker owns an unapplied IP set plus a local search string. It
/// never derives selection from the filtered rows, so typing, refreshes and
/// resizes cannot lose a checkbox that is currently out of view.
#[derive(Debug, Clone)]
pub(crate) struct QueryLogClientPicker {
    pub(crate) search: String,
    search_focused: bool,
    action_focus: Option<FilterFocus>,
    pub(crate) selected: BTreeSet<String>,
    pub(crate) cursor: usize,
    pub(crate) scroll: usize,
    /// Identity, not a transient row index. Device refreshes may reorder the
    /// source view, but the row under the cursor must remain the same IP.
    focused_ip: Option<String>,
    /// Effective list rows from the last render; PgUp/PgDn follows the
    /// actual popup after a resize rather than a fixed menu page.
    pub(crate) visible_rows: usize,
}

impl QueryLogClientPicker {
    pub(crate) fn open(applied: &[String]) -> Self {
        Self {
            search: String::new(),
            search_focused: false,
            action_focus: None,
            selected: applied.iter().cloned().collect(),
            cursor: 0,
            scroll: 0,
            focused_ip: None,
            visible_rows: 1,
        }
    }

    pub(crate) fn options(
        view: Option<&DeviceViewDto>,
        selected: &BTreeSet<String>,
    ) -> Vec<ClientOption> {
        // IP is the wire identity. A duplicated display name is fine; a
        // duplicated IP is one checkbox, never two indistinguishable ways
        // to select the same exact predicate.
        let mut out = BTreeMap::<String, Option<String>>::new();
        if let Some(view) = view {
            for device in &view.mapped {
                out.insert(device.ip.clone(), Some(device.name.clone()));
            }
            for device in &view.unmapped {
                out.entry(device.ip.clone()).or_insert(None);
            }
        }
        // A device can disappear from a refreshed DeviceView while its draft
        // selection is still meaningful. Keep that checkbox until the
        // operator explicitly deselects it; otherwise a refresh makes the
        // draft impossible to correct.
        for ip in selected {
            out.entry(ip.clone()).or_insert(None);
        }
        out.into_iter()
            .map(|(ip, name)| ClientOption { ip, name })
            .collect()
    }

    pub(crate) fn filtered<'a>(&self, options: &'a [ClientOption]) -> Vec<&'a ClientOption> {
        let needle = self.search.to_lowercase();
        options
            .iter()
            .filter(|option| {
                needle.is_empty()
                    || option.ip.to_lowercase().contains(&needle)
                    || option
                        .name
                        .as_deref()
                        .is_some_and(|name| name.to_lowercase().contains(&needle))
            })
            .collect()
    }

    pub(crate) fn handle_key(
        &mut self,
        key: KeyEvent,
        options: &[ClientOption],
        list_height: usize,
    ) -> PickerOutcome {
        let key = if super::is_save_key(key) {
            self.action_focus = Some(FilterFocus::Apply);
            KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE)
        } else {
            key
        };
        self.reconcile(options, list_height);
        let visible = self.filtered(options);
        let outcome = match key.code {
            KeyCode::Esc => PickerOutcome::Cancel,
            KeyCode::Enter if self.action_focus == Some(FilterFocus::Discard) => {
                PickerOutcome::Cancel
            }
            KeyCode::Enter => PickerOutcome::Apply(self.selected.iter().cloned().collect()),
            KeyCode::Tab | KeyCode::BackTab => {
                let current = match self.action_focus {
                    Some(FilterFocus::Discard) => 2,
                    Some(FilterFocus::Apply) => 3,
                    _ if self.search_focused => 0,
                    _ => 1,
                };
                let next = (current + if key.code == KeyCode::Tab { 1 } else { 3 }) % 4;
                self.search_focused = next == 0;
                self.action_focus = match next {
                    2 => Some(FilterFocus::Discard),
                    3 => Some(FilterFocus::Apply),
                    _ => None,
                };
                PickerOutcome::KeepOpen
            }
            KeyCode::Up => {
                self.search_focused = false;
                self.action_focus = None;
                self.cursor = self.cursor.saturating_sub(1);
                self.keep_cursor_visible(visible.len(), list_height);
                self.focused_ip = visible.get(self.cursor).map(|option| option.ip.clone());
                PickerOutcome::KeepOpen
            }
            KeyCode::Down => {
                self.search_focused = false;
                self.action_focus = None;
                self.cursor = (self.cursor + 1).min(visible.len().saturating_sub(1));
                self.keep_cursor_visible(visible.len(), list_height);
                self.focused_ip = visible.get(self.cursor).map(|option| option.ip.clone());
                PickerOutcome::KeepOpen
            }
            KeyCode::PageUp => {
                self.search_focused = false;
                self.action_focus = None;
                self.cursor = self.cursor.saturating_sub(list_height.max(1));
                self.keep_cursor_visible(visible.len(), list_height);
                self.focused_ip = visible.get(self.cursor).map(|option| option.ip.clone());
                PickerOutcome::KeepOpen
            }
            KeyCode::PageDown => {
                self.search_focused = false;
                self.action_focus = None;
                self.cursor =
                    (self.cursor + list_height.max(1)).min(visible.len().saturating_sub(1));
                self.keep_cursor_visible(visible.len(), list_height);
                self.focused_ip = visible.get(self.cursor).map(|option| option.ip.clone());
                PickerOutcome::KeepOpen
            }
            KeyCode::Backspace => {
                self.search_focused = true;
                self.action_focus = None;
                self.search.pop();
                self.cursor = 0;
                self.scroll = 0;
                self.focused_ip = None;
                PickerOutcome::KeepOpen
            }
            KeyCode::Char(' ') if self.action_focus == Some(FilterFocus::Discard) => {
                PickerOutcome::Cancel
            }
            KeyCode::Char(' ') if self.action_focus == Some(FilterFocus::Apply) => {
                PickerOutcome::Apply(self.selected.iter().cloned().collect())
            }
            KeyCode::Char(' ') if !self.search_focused => {
                if let Some(ip) = visible.get(self.cursor).map(|option| option.ip.clone()) {
                    if !self.selected.insert(ip.clone()) {
                        self.selected.remove(&ip);
                    }
                }
                PickerOutcome::KeepOpen
            }
            KeyCode::Char(c)
                if !key
                    .modifiers
                    .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
            {
                self.append_search(&c.to_string());
                PickerOutcome::KeepOpen
            }
            _ => PickerOutcome::KeepOpen,
        };
        if matches!(outcome, PickerOutcome::KeepOpen) {
            self.reconcile(options, list_height);
        }
        outcome
    }

    /// Typing or pasting opens search editing; Space then belongs to the
    /// text field until Tab/Shift+Tab or an arrow returns focus to the list.
    /// Field zero is search; subsequent fields are the filtered client rows.
    pub(crate) fn click_field(&mut self, index: usize, options: &[ClientOption]) {
        self.action_focus = None;
        if index == 0 {
            self.search_focused = true;
            return;
        }
        let visible = self.filtered(options);
        let Some(option) = visible.get(index - 1) else {
            return;
        };
        self.search_focused = false;
        self.cursor = index - 1;
        self.focused_ip = Some(option.ip.clone());
        if !self.selected.remove(&option.ip) {
            self.selected.insert(option.ip.clone());
        }
        self.keep_cursor_visible(visible.len(), self.visible_rows);
    }

    pub(crate) fn append_search(&mut self, value: &str) {
        self.action_focus = None;
        self.search_focused = true;
        self.search.push_str(value);
        self.cursor = 0;
        self.scroll = 0;
        self.focused_ip = None;
    }

    pub(crate) fn footer_hint(&self) -> &'static str {
        if self.action_focus == Some(FilterFocus::Discard) {
            "Discard · Enter discard · Tab Apply · Esc discard"
        } else if self.action_focus == Some(FilterFocus::Apply) {
            "Apply · Enter apply · Tab Search · Esc discard"
        } else if self.search_focused {
            "Search · Tab clients/actions · Enter apply · Esc discard"
        } else {
            "List · Tab actions/search · Space toggle · Enter apply · Esc discard"
        }
    }

    /// Re-find the focused IP after filtering or after a DeviceView refresh.
    /// If it no longer matches the search, ordinary index clamping is the
    /// truthful fallback; it can never silently point at a different IP.
    pub(crate) fn reconcile(&mut self, options: &[ClientOption], list_height: usize) {
        let visible = self.filtered(options);
        if let Some(focused) = self.focused_ip.as_deref() {
            if let Some(index) = visible.iter().position(|option| option.ip == focused) {
                self.cursor = index;
            }
        }
        self.keep_cursor_visible(visible.len(), list_height);
        self.focused_ip = visible.get(self.cursor).map(|option| option.ip.clone());
    }

    fn keep_cursor_visible(&mut self, len: usize, height: usize) {
        self.cursor = self.cursor.min(len.saturating_sub(1));
        let height = height.max(1);
        self.scroll = self.scroll.min(len.saturating_sub(height));
        if self.cursor < self.scroll {
            self.scroll = self.cursor;
        } else if self.cursor >= self.scroll + height {
            self.scroll = self.cursor + 1 - height;
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PickerOutcome {
    KeepOpen,
    Cancel,
    Apply(Vec<String>),
}

/// Read status rendered inside the picker, rather than as a shell toast. The
/// picker is a local overlay and deliberately suppresses that toast surface.
#[derive(Clone, Copy)]
pub(crate) struct PickerReadState<'a> {
    pub(crate) devices_loading: bool,
    pub(crate) devices_error: Option<&'a str>,
    pub(crate) status_loading: bool,
    pub(crate) status_error: Option<&'a str>,
    pub(crate) exact_client_ips_supported: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PickerMessage {
    Status(String),
    Error(String),
}

impl PickerMessage {
    fn status(&self) -> Option<&str> {
        match self {
            Self::Status(message) => Some(message),
            Self::Error(_) => None,
        }
    }

    fn error(&self) -> Option<&str> {
        match self {
            Self::Error(message) => Some(message),
            Self::Status(_) => None,
        }
    }
}

fn picker_message(
    picker: &QueryLogClientPicker,
    view: Option<&DeviceViewDto>,
    state: PickerReadState<'_>,
) -> PickerMessage {
    if let Some(error) = state.status_error {
        return PickerMessage::Error(format!("Daemon capability fetch failed: {error}"));
    }
    if state.status_loading {
        return PickerMessage::Status("Checking daemon support for exact client selection…".into());
    }
    if state.exact_client_ips_supported == Some(false) {
        return PickerMessage::Error(
            "Daemon upgrade required for exact client selection; use the Advanced chip for name/IP search."
                .into(),
        );
    }
    if let Some(error) = state.devices_error {
        return PickerMessage::Error(format!("Client-list fetch failed: {error}"));
    }
    if view.is_none() {
        if state.devices_loading {
            return PickerMessage::Status("Loading known and unmapped clients…".into());
        }
        return PickerMessage::Status("Waiting for a client-list snapshot…".into());
    }
    let options = QueryLogClientPicker::options(view, &picker.selected);
    let filtered = picker.filtered(&options);
    if filtered.is_empty() {
        PickerMessage::Status(
            "No listed client matches; use the Advanced chip for name/IP search.".into(),
        )
    } else {
        PickerMessage::Status(format!(
            "{} selected · exact IPs are ORed; all other filters remain ANDed",
            picker.selected.len()
        ))
    }
}

/// Available client rows after search, status and actions have been reserved.
pub(crate) fn list_height(area: Rect) -> usize {
    usize::from(area.height.saturating_sub(5)).max(1)
}

pub(crate) fn render(
    f: &mut Frame,
    bounds: Rect,
    anchor: Rect,
    picker: &mut QueryLogClientPicker,
    view: Option<&DeviceViewDto>,
    state: PickerReadState<'_>,
) {
    let options = QueryLogClientPicker::options(view, &picker.selected);
    let count = picker.filtered(&options).len();
    let height = (count.clamp(1, 10) as u16).saturating_add(5);
    let inner = filter_chips::popup(f, bounds, anchor, (W, height), TITLE);
    if inner.is_empty() {
        return;
    }
    let visible = inner.height.saturating_sub(3) as usize;
    picker.visible_rows = visible.max(1);
    picker.reconcile(&options, picker.visible_rows.min(list_height(bounds)));
    let filtered = picker.filtered(&options);
    if inner.height >= 2 {
        let search = Rect::new(inner.x, inner.y, inner.width, 1);
        let shown = if picker.search_focused {
            filter_chips::input_text(&picker.search, inner.width)
        } else if picker.search.is_empty() {
            "Search name or IP…".to_owned()
        } else {
            super::text::fit(&picker.search, inner.width as usize)
        };
        f.render_widget(
            Paragraph::new(shown.as_str()).style(filter_chips::chip_style(
                !picker.search.is_empty(),
                picker.search_focused,
            )),
            search,
        );
        mouse::register_overlay_action(search, MouseAction::OverlayField(0));
        if picker.search_focused && search.width > 0 {
            f.set_cursor_position((
                search.x
                    + super::text::width(&shown)
                        .saturating_sub(1)
                        .min(search.width.saturating_sub(1) as usize) as u16,
                search.y,
            ));
        }
    }
    for (index, option) in filtered
        .iter()
        .enumerate()
        .skip(picker.scroll)
        .take(visible)
    {
        let row = Rect::new(
            inner.x,
            inner.y + 1 + (index - picker.scroll) as u16,
            inner.width,
            1,
        );
        let selected = picker.selected.contains(&option.ip);
        let label = format!("[{}] {}", if selected { "x" } else { " " }, option.label());
        f.render_widget(
            Paragraph::new(super::text::fit(&label, row.width as usize)).style(
                filter_chips::chip_style(
                    selected,
                    !picker.search_focused
                        && picker.action_focus.is_none()
                        && picker.cursor == index,
                ),
            ),
            row,
        );
        mouse::register_overlay_action(row, MouseAction::OverlayField(index + 1));
    }
    if visible > 0 && filtered.is_empty() {
        f.render_widget(
            Paragraph::new("No matching clients").style(Style::default().fg(T.text_muted)),
            Rect::new(inner.x, inner.y + 1, inner.width, 1),
        );
    }
    if inner.height >= 3 {
        let message = picker_message(picker, view, state);
        let color = if message.error().is_some() {
            T.error
        } else {
            T.text_muted
        };
        let value = message
            .error()
            .or_else(|| message.status())
            .unwrap_or_default();
        f.render_widget(
            Paragraph::new(super::text::fit(value, inner.width as usize))
                .style(Style::default().fg(color)),
            Rect::new(inner.x, inner.bottom().saturating_sub(2), inner.width, 1),
        );
    }
    filter_chips::render_actions(
        f,
        Rect::new(inner.x, inner.bottom().saturating_sub(1), inner.width, 1),
        picker.action_focus.unwrap_or(FilterFocus::Value),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn search_never_discards_an_out_of_view_checked_ip() {
        let options = vec![
            ClientOption {
                ip: "192.0.2.1".into(),
                name: Some("café".into()),
            },
            ClientOption {
                ip: "192.0.2.10".into(),
                name: Some("printer".into()),
            },
        ];
        let mut picker = QueryLogClientPicker::open(&["192.0.2.1".into()]);
        picker.search = "printer".into();
        assert_eq!(picker.filtered(&options).len(), 1);
        assert!(picker.selected.contains("192.0.2.1"));
    }

    #[test]
    fn space_toggles_exact_ip_and_enter_returns_or_set() {
        let options = vec![
            ClientOption {
                ip: "192.0.2.1".into(),
                name: Some("one".into()),
            },
            ClientOption {
                ip: "192.0.2.10".into(),
                name: Some("ten".into()),
            },
        ];
        let mut picker = QueryLogClientPicker::open(&[]);
        let key = |code| KeyEvent::new(code, KeyModifiers::NONE);
        assert_eq!(
            picker.handle_key(key(KeyCode::Char(' ')), &options, 4),
            PickerOutcome::KeepOpen
        );
        picker.handle_key(key(KeyCode::Down), &options, 4);
        picker.handle_key(key(KeyCode::Char(' ')), &options, 4);
        assert_eq!(
            picker.handle_key(key(KeyCode::Enter), &options, 4),
            PickerOutcome::Apply(vec!["192.0.2.1".into(), "192.0.2.10".into()])
        );
    }

    #[test]
    fn refresh_keeps_focus_on_the_same_ip_and_keeps_missing_selection() {
        let original = vec![
            ClientOption {
                ip: "192.0.2.1".into(),
                name: None,
            },
            ClientOption {
                ip: "192.0.2.2".into(),
                name: None,
            },
        ];
        let mut picker = QueryLogClientPicker::open(&["192.0.2.9".into()]);
        picker.cursor = 1;
        picker.reconcile(&original, 2);

        let refreshed = vec![
            ClientOption {
                ip: "192.0.2.2".into(),
                name: None,
            },
            ClientOption {
                ip: "192.0.2.1".into(),
                name: None,
            },
        ];
        picker.reconcile(&refreshed, 2);
        assert_eq!(picker.cursor, 0, "focus follows 192.0.2.2, not index 1");

        let retained = QueryLogClientPicker::options(None, &picker.selected);
        assert!(retained.iter().any(|option| option.ip == "192.0.2.9"));
    }

    #[test]
    fn tab_focus_distinguishes_multiword_search_from_checkbox_space() {
        let options = vec![ClientOption {
            ip: "192.0.2.1".into(),
            name: Some("Apple TV".into()),
        }];
        let mut picker = QueryLogClientPicker::open(&[]);
        let key = |code| KeyEvent::new(code, KeyModifiers::NONE);
        picker.handle_key(key(KeyCode::BackTab), &options, 4);
        for c in "Apple TV".chars() {
            picker.handle_key(key(KeyCode::Char(c)), &options, 4);
        }
        assert_eq!(picker.search, "Apple TV");
        assert_eq!(picker.filtered(&options).len(), 1);
        assert!(picker.selected.is_empty(), "editing Space toggled a client");

        picker.handle_key(key(KeyCode::Tab), &options, 4);
        picker.handle_key(key(KeyCode::Char(' ')), &options, 4);
        assert!(picker.selected.contains("192.0.2.1"));
        assert_eq!(picker.search, "Apple TV");
        picker.handle_key(
            KeyEvent::new(KeyCode::BackTab, KeyModifiers::SHIFT),
            &options,
            4,
        );
        picker.handle_key(key(KeyCode::Char(' ')), &options, 4);
        assert_eq!(picker.search, "Apple TV ");
        assert!(picker.selected.contains("192.0.2.1"));
    }

    #[test]
    fn typing_and_pasting_focus_search_without_reusing_the_old_cursor() {
        let options = vec![
            ClientOption {
                ip: "192.0.2.1".into(),
                name: Some("Apple TV".into()),
            },
            ClientOption {
                ip: "192.0.2.2".into(),
                name: Some("Phone".into()),
            },
        ];
        let mut picker = QueryLogClientPicker::open(&[]);
        let key = |code| KeyEvent::new(code, KeyModifiers::NONE);
        picker.handle_key(key(KeyCode::Down), &options, 1);
        assert_eq!(picker.cursor, 1);
        picker.append_search("Apple");
        picker.handle_key(key(KeyCode::Char(' ')), &options, 1);
        picker.append_search("TV");
        picker.reconcile(&options, 1);
        assert_eq!(picker.search, "Apple TV");
        assert_eq!(picker.cursor, 0);
        assert_eq!(picker.focused_ip.as_deref(), Some("192.0.2.1"));
        assert!(picker.search_focused);
        assert!(picker.selected.is_empty());
        assert!(picker.footer_hint().starts_with("Search"));
        picker.handle_key(key(KeyCode::Down), &options, 1);
        assert!(!picker.search_focused);
        assert!(picker.footer_hint().starts_with("List"));
    }

    #[test]
    fn picker_status_distinguishes_legacy_and_read_failures() {
        let picker = QueryLogClientPicker::open(&[]);
        let legacy = picker_message(
            &picker,
            None,
            PickerReadState {
                devices_loading: false,
                devices_error: None,
                status_loading: false,
                status_error: None,
                exact_client_ips_supported: Some(false),
            },
        );
        let legacy = legacy.error().expect("legacy capability is a refusal");
        assert!(legacy.contains("upgrade required"));
        assert!(legacy.contains("Advanced chip"));

        let status_failure = picker_message(
            &picker,
            None,
            PickerReadState {
                devices_loading: false,
                devices_error: Some("device offline"),
                status_loading: false,
                status_error: Some("status offline"),
                exact_client_ips_supported: None,
            },
        );
        assert!(status_failure
            .error()
            .is_some_and(|message| message.starts_with("Daemon capability fetch failed")));

        let devices_failure = picker_message(
            &picker,
            None,
            PickerReadState {
                devices_loading: false,
                devices_error: Some("device offline"),
                status_loading: false,
                status_error: None,
                exact_client_ips_supported: Some(true),
            },
        );
        assert!(devices_failure
            .error()
            .is_some_and(|message| message.starts_with("Client-list fetch failed")));
    }

    #[test]
    fn picker_renders_compact_search_choices_and_actions() {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;

        let mut picker = QueryLogClientPicker::open(&["192.0.2.44".into()]);
        let state = PickerReadState {
            devices_loading: false,
            devices_error: None,
            status_loading: false,
            status_error: None,
            exact_client_ips_supported: Some(true),
        };
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
        terminal
            .draw(|frame| {
                render(
                    frame,
                    frame.area(),
                    Rect::new(2, 3, 20, 1),
                    &mut picker,
                    None,
                    state,
                )
            })
            .unwrap();
        let buffer = terminal.backend().buffer();
        let mut rendered = String::new();
        for y in 0..buffer.area.height {
            for x in 0..buffer.area.width {
                rendered.push_str(buffer[(x, y)].symbol());
            }
            rendered.push('\n');
        }
        for expected in [
            &TITLE.to_uppercase(),
            "Search name or IP",
            "[x] 192.0.2.44",
            "Discard",
            "Apply",
        ] {
            assert!(
                rendered.contains(expected),
                "missing common modal row: {expected}"
            );
        }
    }
    #[test]
    fn actions_participate_in_tab_cycle_and_discard_never_applies() {
        let mut picker = QueryLogClientPicker::open(&["192.0.2.1".into()]);
        let options = QueryLogClientPicker::options(None, &picker.selected);
        let key = |code| KeyEvent::new(code, KeyModifiers::NONE);
        picker.handle_key(key(KeyCode::Tab), &options, 3);
        assert_eq!(picker.action_focus, Some(FilterFocus::Discard));
        assert_eq!(
            picker.handle_key(key(KeyCode::Enter), &options, 3),
            PickerOutcome::Cancel
        );
        picker.handle_key(key(KeyCode::Tab), &options, 3);
        assert_eq!(picker.action_focus, Some(FilterFocus::Apply));
        assert_eq!(
            picker.handle_key(key(KeyCode::Enter), &options, 3),
            PickerOutcome::Apply(vec!["192.0.2.1".into()])
        );
        picker.handle_key(key(KeyCode::Tab), &options, 3);
        assert!(picker.search_focused);
        picker.handle_key(key(KeyCode::BackTab), &options, 3);
        assert_eq!(picker.action_focus, Some(FilterFocus::Apply));
    }

    #[test]
    fn compact_popup_scrolls_to_selection_and_keeps_actions_inside_small_bounds() {
        use ratatui::{backend::TestBackend, Terminal};
        let selected = (1..=20).map(|n| format!("192.0.2.{n}")).collect::<Vec<_>>();
        let mut picker = QueryLogClientPicker::open(&selected);
        let options = QueryLogClientPicker::options(None, &picker.selected);
        picker.cursor = options.len() - 1;
        picker.reconcile(&options, 1);
        for height in [8, 12, 24, 8] {
            let mut terminal = Terminal::new(TestBackend::new(80, height)).unwrap();
            terminal
                .draw(|f| {
                    render(
                        f,
                        f.area(),
                        Rect::new(2, 3, 20, 1),
                        &mut picker,
                        None,
                        PickerReadState {
                            devices_loading: false,
                            devices_error: None,
                            status_loading: false,
                            status_error: None,
                            exact_client_ips_supported: Some(true),
                        },
                    )
                })
                .unwrap();
            let buffer = terminal.backend().buffer();
            let dump = (0..height)
                .map(|y| (0..80).map(|x| buffer[(x, y)].symbol()).collect::<String>())
                .collect::<Vec<_>>()
                .join("\n");
            assert!(
                dump.contains("192.0.2.9"),
                "last focused IP must remain visible: {dump}"
            );
            assert!(dump.contains("Discard") && dump.contains("Apply"), "{dump}");
            assert!(picker.visible_rows >= 1);
            assert_eq!(picker.selected.len(), 20);
            let bottom = (0..height)
                .find(|y| buffer[(2, *y)].symbol() == "└")
                .unwrap();
            assert_eq!(buffer[(49, bottom)].symbol(), "┘");
        }
    }
}
