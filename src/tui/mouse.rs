use std::cell::{Cell, RefCell};

use crossterm::event::{KeyCode, KeyEvent, MouseButton, MouseEvent, MouseEventKind};
use ratatui::layout::{Position, Rect};

use super::app::{App, Leaf, Section};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MouseAction {
    Section(Section),
    Leaf(Leaf),
    Key(KeyCode),
    OverlayKey(KeyEvent),
    OverlayField(usize),
    OverlayChoice(usize),
    Row(Leaf, usize),
    Sort(Leaf, usize),
    Filter(Leaf, usize),
    SubnetClientSort(usize),
    LabelKind(usize),
    LabelsPanel(super::app::LabelsFocus),
    LabelsScroll(super::app::LabelsFocus, KeyCode),
    CustomRuleRow(usize),
    SubnetPanel(usize),
    SubnetScroll(usize, KeyCode),
    DetailPanel(Leaf),
    DetailScroll(Leaf, KeyCode),
}

#[derive(Clone, Copy, Debug)]
struct Target {
    area: Rect,
    action: MouseAction,
}

// Rendering and input run on the same event-loop thread. Shared modal builders
// do not borrow App; their hit regions live only until the next frame reset.
thread_local! {
    static OVERLAY_TARGETS: RefCell<Vec<Target>> = const { RefCell::new(Vec::new()) };
    // Outer rect of the overlay begun last this frame, and whether it closes
    // on an outside click.
    static OVERLAY_FRAME: Cell<Option<(Rect, bool)>> = const { Cell::new(None) };
}

/// Start the overlay drawn at `frame`. It owns the clicks from now on and is
/// hard (outside clicks do nothing) until it opts in.
pub fn begin_overlay(frame: Rect) {
    OVERLAY_TARGETS.with(|targets| targets.borrow_mut().clear());
    OVERLAY_FRAME.set(Some((frame, false)));
}

/// Mark the overlay begun last as soft: a menu or a modal whose close loses
/// nothing. A left click outside it then acts as Esc. Overlays holding
/// unsaved or staged work never call this.
pub fn close_on_outside_click() {
    OVERLAY_FRAME.set(OVERLAY_FRAME.get().map(|(frame, _)| (frame, true)));
}

pub fn register_overlay(area: Rect, key: KeyEvent) {
    register_overlay_action(area, MouseAction::OverlayKey(key));
}

pub fn register_overlay_action(area: Rect, action: MouseAction) {
    if !area.is_empty() {
        OVERLAY_TARGETS.with(|targets| targets.borrow_mut().push(Target { area, action }));
    }
}

#[derive(Default, Debug)]
pub struct MouseState {
    targets: RefCell<Vec<Target>>,
    sorts: Vec<(Leaf, SortOrder)>,
    pub subnet_client_sort: Option<SortOrder>,
    pub subnet_panel: usize,
    pub subnet_clients_scroll: usize,
    pub subnet_clients_max_scroll: Cell<usize>,
    details: RefCell<Vec<DetailPanelState>>,
    sort_focus: Option<(Leaf, MouseAction)>,
    last_row_click: Option<(Leaf, String, u16, std::time::Instant)>,
}

/// Per-leaf read-only detail viewport.  This intentionally sits beside the
/// frame-local hit registry: rendering is allowed to update its measured max
/// without needing a mutable `App` borrow.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DetailPanelState {
    pub leaf: Leaf,
    pub offset: usize,
    pub max: usize,
    pub focused: bool,
    pub selection_key: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SortOrder {
    pub column: usize,
    pub descending: bool,
}

/// Two presses on one row within this window act as Enter.
const DOUBLE_CLICK: std::time::Duration = std::time::Duration::from_millis(400);

impl MouseState {
    pub fn blur_sort(&mut self) {
        self.sort_focus = None;
    }

    pub fn row_click(
        &mut self,
        leaf: Leaf,
        identity: String,
        row: u16,
        now: std::time::Instant,
    ) -> bool {
        let previous = self.last_row_click.take();
        if previous.is_some_and(|(old_leaf, old_id, _, at)| {
            old_leaf == leaf
                && old_id == identity
                && now.saturating_duration_since(at) <= DOUBLE_CLICK
        }) {
            return true;
        }
        self.last_row_click = Some((leaf, identity, row, now));
        false
    }

    /// Whether a press on screen `row` repeats the pending first click there.
    pub fn repeats_row_click(&self, leaf: Leaf, row: u16, now: std::time::Instant) -> bool {
        self.last_row_click
            .as_ref()
            .is_some_and(|(old_leaf, _, old_row, at)| {
                *old_leaf == leaf
                    && *old_row == row
                    && now.saturating_duration_since(*at) <= DOUBLE_CLICK
            })
    }

    pub fn clear_row_click(&mut self) {
        self.last_row_click = None;
    }

    pub fn sort(&self, leaf: Leaf) -> Option<SortOrder> {
        self.sorts
            .iter()
            .find(|(key, _)| *key == leaf)
            .map(|(_, sort)| *sort)
    }

    pub fn toggle_sort(&mut self, leaf: Leaf, column: usize) {
        if let Some((_, sort)) = self.sorts.iter_mut().find(|(key, _)| *key == leaf) {
            *sort = SortOrder {
                column,
                descending: sort.column == column && !sort.descending,
            };
        } else {
            self.sorts.push((
                leaf,
                SortOrder {
                    column,
                    descending: false,
                },
            ));
        }
    }

    fn detail_mut(&self, leaf: Leaf) -> std::cell::RefMut<'_, DetailPanelState> {
        let exists = {
            let states = self.details.borrow();
            states.iter().any(|state| state.leaf == leaf)
        };
        if !exists {
            self.details.borrow_mut().push(DetailPanelState {
                leaf,
                offset: 0,
                max: 0,
                focused: false,
                selection_key: String::new(),
            });
        }
        std::cell::RefMut::map(self.details.borrow_mut(), |states| {
            states
                .iter_mut()
                .find(|state| state.leaf == leaf)
                .expect("detail state inserted above")
        })
    }

    pub fn prepare_detail(&self, leaf: Leaf, selection_key: &str) {
        let mut state = self.detail_mut(leaf);
        if state.selection_key != selection_key {
            state.selection_key.clear();
            state.selection_key.push_str(selection_key);
            state.offset = 0;
        }
    }

    pub fn sync_detail(&self, leaf: Leaf, selection_key: &str, max: usize) -> usize {
        self.prepare_detail(leaf, selection_key);
        let mut state = self.detail_mut(leaf);
        state.max = max;
        state.offset = state.offset.min(max);
        state.offset
    }

    pub fn detail_focused(&self, leaf: Leaf) -> bool {
        self.details
            .borrow()
            .iter()
            .find(|state| state.leaf == leaf)
            .is_some_and(|state| state.focused)
    }

    pub fn focus_detail(&self, leaf: Leaf) -> bool {
        let mut states = self.details.borrow_mut();
        let Some(state) = states.iter_mut().find(|state| state.leaf == leaf) else {
            return false;
        };
        state.focused = true;
        true
    }

    pub fn blur_detail(&self, leaf: Leaf) {
        if let Some(state) = self
            .details
            .borrow_mut()
            .iter_mut()
            .find(|state| state.leaf == leaf)
        {
            state.focused = false;
        }
    }

    pub fn detail_offset(&self, leaf: Leaf) -> usize {
        self.details
            .borrow()
            .iter()
            .find(|state| state.leaf == leaf)
            .map_or(0, |state| state.offset)
    }

    pub fn scroll_detail(&self, leaf: Leaf, key: KeyCode, focus: bool, page_rows: usize) -> bool {
        let mut states = self.details.borrow_mut();
        let Some(state) = states.iter_mut().find(|state| state.leaf == leaf) else {
            return false;
        };
        if focus {
            state.focused = true;
        }
        if !state.focused {
            return false;
        }
        let next = match key {
            KeyCode::Up => state.offset.saturating_sub(1),
            KeyCode::Down => state.offset.saturating_add(1).min(state.max),
            KeyCode::PageUp => state.offset.saturating_sub(page_rows),
            KeyCode::PageDown => state.offset.saturating_add(page_rows).min(state.max),
            KeyCode::Home => 0,
            KeyCode::End => state.max,
            _ => return false,
        };
        state.offset = next;
        true
    }
}

pub fn handle_sort_key(app: &mut App, key: KeyEvent) -> bool {
    if key
        .modifiers
        .intersects(crossterm::event::KeyModifiers::CONTROL | crossterm::event::KeyModifiers::ALT)
    {
        return false;
    }
    let leaf = app.active_leaf;
    let columns: Vec<MouseAction> = app
        .mouse
        .targets
        .borrow()
        .iter()
        .filter_map(|target| match target.action {
            MouseAction::Sort(page, _)
                if page == leaf && !(leaf == Leaf::Subnets && app.mouse.subnet_panel == 2) =>
            {
                Some(target.action)
            }
            MouseAction::SubnetClientSort(_)
                if leaf == Leaf::Subnets && app.mouse.subnet_panel == 2 =>
            {
                Some(target.action)
            }
            _ => None,
        })
        .collect();
    if app.mouse.sort_focus.is_some_and(|(page, _)| page != leaf) {
        app.mouse.sort_focus = None;
    }
    if columns.is_empty() {
        app.mouse.sort_focus = None;
        return false;
    }
    if app.mouse.sort_focus.is_none() {
        if key.code != KeyCode::Char('s') {
            return false;
        }
        app.mouse.sort_focus = Some((leaf, columns[0]));
        if leaf == Leaf::Labels {
            app.mouse.blur_detail(leaf);
            app.labels.focus = super::app::LabelsFocus::Entries;
        }
        return true;
    }
    let focused = app.mouse.sort_focus.unwrap().1;
    let index = columns.iter().position(|a| *a == focused).unwrap_or(0);
    let next = match key.code {
        KeyCode::Left | KeyCode::BackTab => (index + columns.len() - 1) % columns.len(),
        KeyCode::Right | KeyCode::Tab => (index + 1) % columns.len(),
        KeyCode::Home => 0,
        KeyCode::End => columns.len() - 1,
        KeyCode::Enter | KeyCode::Char(' ') => {
            match columns[index] {
                MouseAction::Sort(page, column) => {
                    #[cfg(feature = "cluster")]
                    if page == Leaf::Nodes {
                        if let Some(sort) = super::nodes::NodeSort::from_column(column) {
                            app.nodes.descending = app.nodes.sort == sort && !app.nodes.descending;
                            app.nodes.sort = sort;
                        }
                    } else {
                        app.mouse.toggle_sort(page, column);
                    }
                    #[cfg(not(feature = "cluster"))]
                    app.mouse.toggle_sort(page, column);
                }
                MouseAction::SubnetClientSort(column) => {
                    let old = app.mouse.subnet_client_sort;
                    app.mouse.subnet_client_sort = Some(SortOrder {
                        column,
                        descending: old.is_some_and(|o| o.column == column && !o.descending),
                    });
                }
                _ => {}
            }
            index
        }
        KeyCode::Char('s') => index,
        KeyCode::Esc | KeyCode::Up | KeyCode::Down => {
            app.mouse.sort_focus = None;
            return key.code == KeyCode::Esc;
        }
        _ => {
            app.mouse.sort_focus = None;
            return false;
        }
    };
    app.mouse.sort_focus = Some((leaf, columns[next]));
    true
}

pub fn render_sort_focus(frame: &mut ratatui::Frame, app: &App) {
    let Some((leaf, action)) = app.mouse.sort_focus else {
        return;
    };
    if leaf != app.active_leaf || overlay_open(app) {
        return;
    }
    let targets = app.mouse.targets.borrow();
    if let Some(target) = targets.iter().find(|target| target.action == action) {
        let area = target.area.intersection(frame.area());
        frame.buffer_mut().set_style(
            area,
            ratatui::style::Style::default()
                .fg(super::theme::T.text_inverse)
                .bg(super::theme::T.warden_teal),
        );
    }
}

pub fn reset(app: &App) {
    app.mouse.targets.borrow_mut().clear();
    OVERLAY_TARGETS.with(|targets| targets.borrow_mut().clear());
    OVERLAY_FRAME.set(None);
}

pub fn register(app: &App, area: Rect, action: MouseAction) {
    if !area.is_empty() {
        app.mouse.targets.borrow_mut().push(Target { area, action });
    }
}

pub fn overlay_open(app: &App) -> bool {
    app.show_help || modal_open(app)
}

/// Every overlay but help. Help gets keys only while none of these is open.
pub fn modal_open(app: &App) -> bool {
    app.query_log.held.review.is_some()
        || app.information.is_some()
        || super::filter_chips::text_editor_open(app)
        || super::filter_chips::choice_editor_open(app)
        || app.operator_policy.is_some()
        || app.welcome_banner.is_some()
        || app.resolver_modal.is_some()
        || app.query_log_rule_modal.is_some()
        || super::tabs::query_log::overlay_open(app)
        || app.query_log.advanced_modal.is_some()
        || app.devices.modal.is_some()
        || app.subnets.modal.is_some()
        || app.groups.modal.is_some()
        || app.local_dns.modal.is_some()
        || app.profiles.modal.is_some()
        || app.custom_lists.modal.is_some()
        || app.custom_lists.mount_picker.is_some()
        || app.labels.modal.is_some()
        || app.settings.tracking_panel.is_some()
        || app.devices.inspect_open
        || app.groups.inspect_open
        || app.local_dns.inspect_open
        || app.subnets.inspect.is_some()
        || app.settings.restore_modal.is_some()
        || app.settings.backup_modal.is_some()
        || app.lists.import_source.is_some()
        || app.lists.catalog_picker.is_some()
        || app.lists.kind_confirm.is_some()
        || app.lists.edit_modal.is_some()
        || app.rules.edit_modal.is_some()
        || app.rules.add_modal.is_some()
        || app.file.section_jump.is_some()
        // Leaf-gated exactly like their key routing in `handle_key`, and open
        // only while they draw: a missing row leaves no frame to click off.
        || (app.active_leaf == Leaf::Profiles && super::tabs::profiles::info_row(app).is_some())
        || (app.active_leaf == Leaf::Lists && super::tabs::lists::detail_row(app).is_some())
        || (app.active_leaf == Leaf::CustomLists && super::tabs::custom_lists::info_drawn(app))
        || {
            #[cfg(feature = "cluster")]
            {
                app.nodes.dialog.is_some()
            }
            #[cfg(not(feature = "cluster"))]
            {
                false
            }
        }
}

pub fn action(app: &App, event: MouseEvent) -> Option<MouseAction> {
    if !overlay_open(app) {
        let key = match event.kind {
            MouseEventKind::ScrollUp => Some(KeyCode::Up),
            MouseEventKind::ScrollDown => Some(KeyCode::Down),
            _ => None,
        };
        if let Some(key) = key {
            if let Some(leaf) =
                app.mouse
                    .targets
                    .borrow()
                    .iter()
                    .rev()
                    .find_map(|target| match target.action {
                        MouseAction::DetailPanel(leaf)
                            if target.area.contains(Position::new(event.column, event.row)) =>
                        {
                            Some(leaf)
                        }
                        _ => None,
                    })
            {
                return Some(MouseAction::DetailScroll(leaf, key));
            }
        }
    }
    if app.active_leaf == Leaf::Labels && !overlay_open(app) {
        let key = match event.kind {
            MouseEventKind::ScrollUp => Some(KeyCode::Up),
            MouseEventKind::ScrollDown => Some(KeyCode::Down),
            _ => None,
        };
        if let Some(key) = key {
            let focus =
                app.mouse
                    .targets
                    .borrow()
                    .iter()
                    .rev()
                    .find_map(|target| match target.action {
                        MouseAction::LabelsPanel(focus)
                            if target.area.contains(Position::new(event.column, event.row)) =>
                        {
                            Some(focus)
                        }
                        _ => None,
                    });
            if let Some(focus) = focus {
                return Some(MouseAction::LabelsScroll(focus, key));
            }
        }
    }
    if app.active_leaf == Leaf::Subnets && !overlay_open(app) {
        let key = match event.kind {
            MouseEventKind::ScrollUp => Some(KeyCode::Up),
            MouseEventKind::ScrollDown => Some(KeyCode::Down),
            _ => None,
        };
        if let Some(key) = key {
            if let Some(panel) =
                app.mouse
                    .targets
                    .borrow()
                    .iter()
                    .rev()
                    .find_map(|target| match target.action {
                        MouseAction::SubnetPanel(panel)
                            if target.area.contains(Position::new(event.column, event.row)) =>
                        {
                            Some(panel)
                        }
                        _ => None,
                    })
            {
                return Some(MouseAction::SubnetScroll(panel, key));
            }
        }
    }
    match event.kind {
        MouseEventKind::ScrollUp => Some(MouseAction::Key(KeyCode::Up)),
        MouseEventKind::ScrollDown => Some(MouseAction::Key(KeyCode::Down)),
        MouseEventKind::Down(MouseButton::Left) if overlay_open(app) => {
            let pos = Position::new(event.column, event.row);
            OVERLAY_TARGETS
                .with(|targets| {
                    targets
                        .borrow()
                        .iter()
                        .rev()
                        .find(|target| target.area.contains(pos))
                        .map(|target| target.action)
                })
                .or_else(|| match OVERLAY_FRAME.get() {
                    // A pending action sends Esc to `handle_busy_key`, which
                    // closes the in-flight card, not the overlay clicked off.
                    Some((frame, true)) if !frame.contains(pos) && app.pending_action.is_none() => {
                        Some(MouseAction::OverlayKey(KeyCode::Esc.into()))
                    }
                    _ => None,
                })
        }
        MouseEventKind::Down(MouseButton::Left) if !overlay_open(app) => app
            .mouse
            .targets
            .borrow()
            .iter()
            .rev()
            .find(|target| target.area.contains(Position::new(event.column, event.row)))
            .map(|target| target.action),
        _ => None,
    }
}

/// The same indicator vocabulary for every sortable table.
pub fn sort_label(label: &str, column: usize, sort: Option<SortOrder>) -> String {
    match sort.filter(|order| order.column == column) {
        Some(order) if order.descending => format!("{label} ▼"),
        Some(_) => format!("{label} ▲"),
        None => label.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::KeyModifiers;

    fn click(x: u16, y: u16) -> MouseEvent {
        MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: x,
            row: y,
            modifiers: KeyModifiers::NONE,
        }
    }

    fn wheel(kind: MouseEventKind, x: u16, y: u16) -> MouseEvent {
        MouseEvent {
            kind,
            column: x,
            row: y,
            modifiers: KeyModifiers::NONE,
        }
    }

    #[test]
    fn double_click_requires_same_leaf_and_stable_identity_within_threshold() {
        let mut state = MouseState::default();
        let start = std::time::Instant::now();
        assert!(!state.row_click(Leaf::Labels, "owner:a".into(), 5, start));
        assert!(state.row_click(
            Leaf::Labels,
            "owner:a".into(),
            5,
            start + std::time::Duration::from_millis(400)
        ));
        assert!(!state.row_click(
            Leaf::Labels,
            "owner:a".into(),
            5,
            start + std::time::Duration::from_millis(500)
        ));
        assert!(!state.row_click(
            Leaf::Labels,
            "owner:b".into(),
            5,
            start + std::time::Duration::from_millis(510)
        ));
        assert!(!state.row_click(
            Leaf::Groups,
            "owner:b".into(),
            5,
            start + std::time::Duration::from_millis(520)
        ));
        state.clear_row_click();
        assert!(!state.row_click(
            Leaf::Groups,
            "owner:b".into(),
            5,
            start + std::time::Duration::from_millis(530)
        ));
        assert!(!state.row_click(
            Leaf::Groups,
            "owner:b".into(),
            5,
            start + std::time::Duration::from_millis(931)
        ));
    }

    #[test]
    fn a_repeat_click_needs_the_same_leaf_and_screen_row_within_threshold() {
        let mut state = MouseState::default();
        let start = std::time::Instant::now();
        let at = |ms| start + std::time::Duration::from_millis(ms);
        assert!(!state.row_click(Leaf::Labels, "a".into(), 5, start));
        assert!(state.repeats_row_click(Leaf::Labels, 5, at(400)));
        assert!(!state.repeats_row_click(Leaf::Labels, 6, at(100)));
        assert!(!state.repeats_row_click(Leaf::Groups, 5, at(100)));
        assert!(!state.repeats_row_click(Leaf::Labels, 5, at(401)));
        state.clear_row_click();
        assert!(!state.repeats_row_click(Leaf::Labels, 5, at(100)));
    }

    #[test]
    fn sort_focus_activates_painted_columns_and_preserves_editor_chords() {
        let mut app = App::new();
        app.active_leaf = Leaf::Labels;
        register(
            &app,
            Rect::new(1, 3, 10, 1),
            MouseAction::Sort(Leaf::Labels, 0),
        );
        register(
            &app,
            Rect::new(12, 3, 10, 1),
            MouseAction::Sort(Leaf::Labels, 1),
        );
        let key = |code| KeyEvent::new(code, KeyModifiers::NONE);
        assert!(!handle_sort_key(
            &mut app,
            KeyEvent::new(KeyCode::Char('s'), KeyModifiers::CONTROL)
        ));
        assert!(handle_sort_key(&mut app, key(KeyCode::Char('s'))));
        assert!(handle_sort_key(&mut app, key(KeyCode::Tab)));
        assert_eq!(
            app.mouse.sort_focus,
            Some((Leaf::Labels, MouseAction::Sort(Leaf::Labels, 1)))
        );
        assert!(handle_sort_key(&mut app, key(KeyCode::Enter)));
        assert_eq!(app.mouse.sort(Leaf::Labels).unwrap().column, 1);
        assert!(handle_sort_key(&mut app, key(KeyCode::Esc)));
        assert_eq!(app.mouse.sort_focus, None);
    }

    #[test]
    fn last_drawn_target_wins_and_frame_reset_removes_stale_hits() {
        let app = App::new();
        let rect = Rect::new(2, 3, 10, 1);
        register(&app, rect, MouseAction::Leaf(Leaf::Devices));
        register(&app, rect, MouseAction::Leaf(Leaf::Groups));
        assert_eq!(
            action(&app, click(2, 3)),
            Some(MouseAction::Leaf(Leaf::Groups))
        );
        assert_eq!(action(&app, click(12, 3)), None);
        reset(&app);
        assert_eq!(action(&app, click(2, 3)), None);
    }

    #[test]
    fn modal_prevents_clicking_the_underlying_navigation() {
        let mut app = App::new();
        reset(&app);
        register(
            &app,
            Rect::new(0, 0, 10, 1),
            MouseAction::Leaf(Leaf::Devices),
        );
        app.show_help = true;
        assert_eq!(action(&app, click(0, 0)), None);
    }

    #[test]
    fn wheel_over_detail_card_routes_before_default_list_navigation() {
        let app = App::new();
        register(
            &app,
            Rect::new(10, 4, 24, 12),
            MouseAction::DetailPanel(Leaf::Profiles),
        );
        assert_eq!(
            action(&app, wheel(MouseEventKind::ScrollDown, 12, 5)),
            Some(MouseAction::DetailScroll(Leaf::Profiles, KeyCode::Down))
        );
        assert_eq!(
            action(&app, wheel(MouseEventKind::ScrollUp, 1, 1)),
            Some(MouseAction::Key(KeyCode::Up))
        );
    }

    #[test]
    fn outside_click_closes_only_overlays_that_opt_in() {
        let mut app = App::new();
        reset(&app);
        app.show_help = true;
        begin_overlay(Rect::new(10, 5, 20, 8));
        assert_eq!(action(&app, click(0, 0)), None);
        close_on_outside_click();
        let esc = Some(MouseAction::OverlayKey(KeyCode::Esc.into()));
        assert_eq!(action(&app, click(0, 0)), esc);
        assert_eq!(action(&app, click(12, 7)), None);
        assert_eq!(action(&app, click(10, 5)), None);
        register_overlay(Rect::new(12, 7, 4, 1), KeyCode::Enter.into());
        assert_eq!(
            action(&app, click(12, 7)),
            Some(MouseAction::OverlayKey(KeyCode::Enter.into()))
        );
    }

    #[test]
    fn outside_click_belongs_to_the_overlay_begun_last() {
        let mut app = App::new();
        reset(&app);
        app.show_help = true;
        let (big, small) = (Rect::new(0, 0, 40, 20), Rect::new(5, 5, 10, 4));
        begin_overlay(big);
        close_on_outside_click();
        begin_overlay(small);
        assert_eq!(action(&app, click(20, 15)), None);
        begin_overlay(big);
        begin_overlay(small);
        close_on_outside_click();
        assert_eq!(
            action(&app, click(20, 15)),
            Some(MouseAction::OverlayKey(KeyCode::Esc.into()))
        );
    }

    #[test]
    fn outside_click_needs_an_open_overlay_and_a_current_frame() {
        let mut app = App::new();
        reset(&app);
        register(
            &app,
            Rect::new(0, 0, 10, 1),
            MouseAction::Leaf(Leaf::Devices),
        );
        begin_overlay(Rect::new(10, 5, 20, 8));
        close_on_outside_click();
        assert_eq!(
            action(&app, click(0, 0)),
            Some(MouseAction::Leaf(Leaf::Devices))
        );
        app.show_help = true;
        reset(&app);
        assert_eq!(action(&app, click(0, 0)), None);
    }

    #[test]
    fn info_overlays_block_clicks_only_on_their_leaf() {
        let mut app = App::new();
        reset(&app);
        app.lists.entries = vec![crate::lists::status::BlocklistStatusDto {
            id: Some("x".into()),
            ..Default::default()
        }];
        app.lists.detail_id = Some("id:x".into());
        app.active_leaf = Leaf::Lists;
        assert!(overlay_open(&app));
        app.active_leaf = Leaf::Devices;
        assert!(!overlay_open(&app));
        app.lists.detail_id = None;
        app.profiles.info_open = true;
        app.active_leaf = Leaf::Profiles;
        assert!(!overlay_open(&app), "no profile to show, so nothing draws");
        let mut config = crate::config::schema::ConfigV1::default();
        config.profiles.insert("home".into(), Default::default());
        app.loaded_config = Some(crate::config::loader::LoadedConfig {
            config,
            master_path: Default::default(),
            files_loaded: Vec::new(),
            total_bytes: 0,
            provenance: Default::default(),
            custom_lists: Default::default(),
        });
        assert!(overlay_open(&app));
        app.active_leaf = Leaf::Devices;
        assert!(!overlay_open(&app));
        app.active_leaf = Leaf::CustomLists;
        app.custom_lists.info = Some(crate::tui::app::CustomListInfo {
            target: crate::tui::app::CustomListInfoTarget::List("gone".into()),
            advanced_expanded: false,
        });
        assert!(!overlay_open(&app), "no such list, so nothing draws");
    }
}
