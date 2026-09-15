//! Custom Lists tab — the `[[custom_lists]]` entities and the pack files
//! behind them.
//!
//! Left pane: one row per declared list, with its allow / deny / skipped
//! counts and how many profiles mount it.
//!
//! ```text
//! Custom Lists (2)
//!   ID          A   D   S   USED BY
//! ▸ videogames  32  2   0   1
//! · casa         0  4   1   —
//! ```
//!
//! `▸` marks the cursor of the focused pane, `·` the resting cursor of the
//! other one.
//!
//! Right pane: the selected list's file, **one row per rule**. Comments and
//! blank lines are not rows — they enforce nothing, and the question this
//! pane answers is what the list does. A line the grammar REFUSED is a row,
//! labelled `SKIPPED`: the left pane shows those as a bare `S` count, so
//! this is the only surface where a degraded file is legible.
//!
//! ## Why the counts come from daemon pages, not from a file read
//!
//! A background job exhausts the revision-bound rule pages and publishes
//! counts only after every page retains the inventory fences. Rendering reads
//! that cache and never performs filesystem or IPC I/O.
//!
//! ## What no surface here may ever do
//!
//! Never rebuild a pack file from rendered rows. The rows are a strict
//! SUBSET of the file — comments and blanks never become rows at all — so a
//! save that round-tripped them would delete the operator's own prose
//! outright. Runtime mutations therefore go through
//! [`crate::operator_rules::OperatorRulesService`], which addresses rows by
//! snapshot-bound references and preserves unaddressed content.
//!
//! ## Not here
//! - Keys:  `mod.rs::handle_custom_lists_key` (`m` opens the mount picker,
//!   `a`/`e`/`d` open the list modal)
//! - Form:  `tui::custom_list_modal` (`CustomListModal` + `MountPicker`)
//! - State: `app::CustomListsState` (cursor, focus, `pack`, two table viewports)
//! - Tests: render + pure fns here; key handling in `tui/tests/`, declared from `mod.rs`

use std::cmp::Ordering;

use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Cell, Paragraph, Row, Table};
use ratatui::Frame;

#[cfg(test)]
use crate::config::custom_list::CompiledCustomList;
#[cfg(test)]
use crate::config::loader::LoadedConfig;
#[cfg(test)]
use crate::config::schema::CustomList;
#[cfg(test)]
use crate::config::schema::Id;
#[cfg(test)]
use crate::config::write_lock::ConfigWriteLock;
use crate::operator_rules::RuleAction;
use crate::tui::app::{App, CustomListCounts, CustomListInfoTarget, CustomListsFocus, Leaf};
use crate::tui::custom_list_modal::{BackendRuleRef, CustomListModal};
use crate::tui::mouse::{self, MouseAction, SortOrder};
use crate::tui::theme::{self, CardRole, T};

/// Profiles and Custom Lists share the frozen 42% / 58% family geometry.
const SPLIT_THRESHOLD: u16 = 108;
const COLUMN_SPACING: u16 = 2;
const LIST_HEADERS: [&str; 6] = ["ID", "DISPLAY NAME", "A", "D", "S", "USED BY"];

/// Shown in the rule pane when no list is selected.
pub const NO_SELECTION: &str = " select a list";

/// Does a terminal this wide actually paint the rule pane?
///
/// Takes the **viewport** width because the render loop is the only caller
/// that knows it, and the tab body spans the full width.
pub fn rules_pane_is_painted(viewport_width: u16) -> bool {
    viewport_width >= SPLIT_THRESHOLD
}

/// Shown in `USED BY` for a list no profile mounts.
///
/// Not an error, and never coloured as one: a list can legitimately exist
/// before it is mounted. It does mean the list filters nothing, which is
/// why the row is dimmed rather than silent.
pub const USED_BY_NONE: &str = "\u{2014}";

/// One row of the left pane, resolved from the daemon-owned catalogue.
///
/// **One builder, two consumers, deliberately.** [`render`] draws these and
/// highlights one; the key handler resolves which row `e`, `d` and `m` act
/// on. Two independent derivations would let the operator delete a row
/// other than the highlighted one with nothing on screen saying so.
#[derive(Debug, Clone)]
pub struct CustomListRow {
    pub id: String,
    pub display_name: String,
    pub description: String,
    pub allow_count: Option<usize>,
    pub deny_count: Option<usize>,
    pub skipped_count: Option<usize>,
    pub count_error: Option<String>,
    pub rule_count: usize,
    pub invalid_rows: usize,
    pub mounted_profiles: Vec<String>,
    pub bytes: usize,
    pub config_revision: String,
    pub pack_revision: String,
}

/// A rule row from the daemon's snapshot. `row_ref`, not a file offset or
/// reconstructed text, is the identity mutation requests must carry back to
/// the operator-policy service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustomListRuleRow {
    pub line: usize,
    pub raw: String,
    pub row_ref: String,
    pub rule_key: Option<String>,
    pub action: Option<RuleAction>,
    pub valid: bool,
    pub duplicate: bool,
}

/// The selected list's rule snapshot, with every non-ready state named.
///
/// A catalogue item is not enough to infer its rules: a matching IPC page is
/// required, including both revisions. This prevents an old page from being
/// painted as the rules of a newer list revision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CustomListRules {
    Unavailable { message: Option<String> },
    DifferentList { loaded_id: String },
    StaleRevision,
    Ready(Vec<CustomListRuleRow>),
}

impl CustomListRow {
    /// A list nothing mounts filters nothing, whatever it contains.
    pub fn is_inert(&self) -> bool {
        self.mounted_profiles.is_empty()
    }
}

pub fn display_row_key(row: &CustomListRow) -> &str {
    &row.id
}

pub fn index_of_display_key(rows: &[CustomListRow], selected_id: Option<&str>) -> Option<usize> {
    let selected_id = selected_id?;
    rows.iter().position(|row| row.id == selected_id)
}

pub fn selected_display_row<'a>(app: &App, rows: &'a [CustomListRow]) -> Option<&'a CustomListRow> {
    index_of_display_key(rows, app.custom_lists.selected_id.as_deref())
        .and_then(|index| rows.get(index))
        .or_else(|| rows.first())
}

pub fn rule_row_key(row: &CustomListRuleRow) -> &str {
    &row.row_ref
}

/// Open the least-lossy editor for a displayed backend row.
///
/// The compact domain editor is reserved for the legacy bare-domain syntax.
/// Any other valid operator-rule AST — and every refused row — opens the
/// verbatim replacement form. A parser miss therefore never means the row is
/// invalid, and never drops a modifier while preparing an edit.
pub fn rule_editor_modal(list_id: String, row: &CustomListRuleRow) -> CustomListModal {
    use crate::config::custom_list::{parse_pack_line, PackLine};

    let target = BackendRuleRef {
        row_ref: row.row_ref.clone(),
        line: row.line,
        raw: row.raw.clone(),
    };
    match parse_pack_line(&row.raw) {
        Ok(PackLine::Allow(domain)) => {
            CustomListModal::open_edit_rule_ref(list_id, target, domain.to_string(), true)
        }
        Ok(PackLine::Deny(domain)) => {
            CustomListModal::open_edit_rule_ref(list_id, target, domain.to_string(), false)
        }
        _ => CustomListModal::open_edit_raw_rule(list_id, target),
    }
}

fn is_display_rule(row: &crate::operator_rules::RuleRow) -> bool {
    // Comments and blank lines stay in the backend page, where their stable
    // references preserve unaddressed source content. They are not semantic
    // rules, so the operator-facing rule table hides them.
    !row.valid || row.action.is_some()
}

/// Project the one rules snapshot held by the app for `selected`.
///
/// This reads only the IPC-owned snapshot. In particular, it never falls
/// back to `CustomListsState::pack`: a local file view cannot prove it agrees
/// with the catalogue revision the operator is looking at.
pub fn display_rule_rows(app: &App, selected: &CustomListRow) -> CustomListRules {
    let Some(rules) = app.operator_rules.as_ref() else {
        return CustomListRules::Unavailable {
            message: app.operator_rules_error.clone(),
        };
    };
    if rules.id != selected.id {
        return CustomListRules::DifferentList {
            loaded_id: rules.id.clone(),
        };
    }
    if rules.config_revision != selected.config_revision
        || rules.pack_revision != selected.pack_revision
    {
        return CustomListRules::StaleRevision;
    }
    CustomListRules::Ready(
        rules
            .rows
            .iter()
            .filter(|row| is_display_rule(row))
            .map(|row| CustomListRuleRow {
                line: row.line,
                raw: row.raw.clone(),
                row_ref: row.row_ref.clone(),
                rule_key: row.rule_key.clone(),
                action: row.action,
                valid: row.valid,
                duplicate: row.duplicate,
            })
            .collect(),
    )
}

/// The only Custom Lists catalogue projection. The operator-policy inventory
/// is the authority because it carries revisions, parser degradation and
/// mounted profiles; loaded TOML and pack files are never used as a fallback.
pub fn build_display_rows(app: &App) -> Vec<CustomListRow> {
    let Some(catalog) = app.operator_catalog.as_ref() else {
        return Vec::new();
    };
    let mut rows: Vec<CustomListRow> = catalog
        .lists
        .iter()
        .map(|list| {
            let counts = app
                .custom_lists
                .counts
                .get(&list.id)
                .filter(|counts| match counts {
                    CustomListCounts::Ready {
                        config_revision,
                        pack_revision,
                        ..
                    }
                    | CustomListCounts::Unavailable {
                        config_revision,
                        pack_revision,
                        ..
                    } => {
                        config_revision == &list.config_revision
                            && pack_revision == &list.pack_revision
                    }
                });
            let (allow_count, deny_count, skipped_count, count_error) = match counts {
                Some(CustomListCounts::Ready {
                    allow,
                    deny,
                    skipped,
                    ..
                }) => (Some(*allow), Some(*deny), Some(*skipped), None),
                Some(CustomListCounts::Unavailable { error, .. }) => {
                    (None, None, None, Some(error.clone()))
                }
                None => (None, None, None, None),
            };
            CustomListRow {
                id: list.id.clone(),
                display_name: list.display_name.clone(),
                description: list.description.clone(),
                allow_count,
                deny_count,
                skipped_count,
                count_error,
                rule_count: list.rule_count,
                invalid_rows: list.invalid_rows,
                mounted_profiles: list.profiles.clone(),
                bytes: list.bytes,
                config_revision: list.config_revision.clone(),
                pack_revision: list.pack_revision.clone(),
            }
        })
        .collect();
    sort_display_rows(&mut rows, app.mouse.sort(Leaf::CustomLists));
    rows
}

fn sort_display_rows(rows: &mut [CustomListRow], sort: Option<SortOrder>) {
    let Some(sort) = sort else {
        return;
    };
    rows.sort_by(|left, right| {
        let order = match sort.column {
            0 => left.id.cmp(&right.id),
            1 => left
                .display_name
                .to_lowercase()
                .cmp(&right.display_name.to_lowercase()),
            2 => optional_order(left.allow_count, right.allow_count, sort.descending),
            3 => optional_order(left.deny_count, right.deny_count, sort.descending),
            4 => optional_order(left.skipped_count, right.skipped_count, sort.descending),
            5 => left
                .mounted_profiles
                .len()
                .cmp(&right.mounted_profiles.len()),
            _ => Ordering::Equal,
        };
        let order = if matches!(sort.column, 2..=4) {
            order
        } else if sort.descending {
            order.reverse()
        } else {
            order
        };
        order.then_with(|| left.id.cmp(&right.id))
    });
}

fn optional_order<T: Ord>(left: Option<T>, right: Option<T>, descending: bool) -> Ordering {
    match (left, right) {
        (Some(left), Some(right)) => {
            let order = left.cmp(&right);
            if descending {
                order.reverse()
            } else {
                order
            }
        }
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (None, None) => Ordering::Equal,
    }
}

pub fn render(f: &mut Frame, area: Rect, app: &mut App) {
    if app.operator_catalog.is_none() {
        render_catalog_unavailable(f, area, app.operator_catalog_error.as_deref());
        return;
    }
    let rows = build_display_rows(app);

    if rows.is_empty() {
        render_empty_master_detail(f, area, app);
        return;
    }

    let focus = app.custom_lists.focus;
    let wide = rules_pane_is_painted(area.width);
    app.custom_lists.rules_pane_painted = wide || focus == CustomListsFocus::Rules;

    if !wide {
        // At 80×24 the focused pane takes the full body, so Rules is not
        // merely visible somewhere off-screen: focus makes it reachable.
        if focus == CustomListsFocus::Rules {
            render_rules_pane(f, area, app, selected_display_row(app, &rows));
        } else {
            render_lists_pane(f, area, app, &rows);
        }
        return;
    }

    let cols = proportional_columns(area);

    render_lists_pane(f, cols[0], app, &rows);
    render_rules_pane(f, cols[1], app, selected_display_row(app, &rows));
}

fn proportional_columns(area: Rect) -> [Rect; 2] {
    let left = (u32::from(area.width) * 42 / 100) as u16;
    [
        Rect::new(area.x, area.y, left, area.height),
        Rect::new(
            area.x + left.saturating_sub(1),
            area.y,
            area.width.saturating_sub(left).saturating_add(1),
            area.height,
        ),
    ]
}

// ── Right pane: the selected list's file ─────────────────────────────

/// The rule pane, on the shape of `devices::render_card_panel`.
///
/// **The title is what answers "is this list selected?".** With a single
/// row a highlight has no unhighlighted neighbour to contrast against, so
/// the cursor reads as ambiguous. Devices does not solve that with a
/// stronger marker — it names the selection in the panel title, in
/// `T.brand_red`, and shows its content. Naming it here does the same job;
/// a louder cursor would be treating the symptom.
fn render_rules_pane(f: &mut Frame, area: Rect, app: &mut App, selected: Option<&CustomListRow>) {
    let subtitle = selected
        .map(|row| format!("{} \u{00b7} Rules & Validation", row.id))
        .unwrap_or_else(|| "Select a Custom List".to_string());
    let content = theme::filled_card(
        f.buffer_mut(),
        area,
        "CUSTOM LIST RULES",
        &subtitle,
        CardRole::History,
    );
    let Some(selected) = selected else {
        render_muted(f, content, NO_SELECTION);
        return;
    };
    match display_rule_rows(app, selected) {
        CustomListRules::Ready(rows) if rows.is_empty() => render_no_rules(
            f,
            content,
            app.custom_lists.focus == CustomListsFocus::Rules,
        ),
        CustomListRules::Ready(rows) => render_rules_table(f, content, app, selected, &rows),
        problem => render_rules_unavailable(f, content, selected, app.custom_lists.focus, problem),
    }
}

const RULE_HEADERS: [&str; 4] = ["#", "RULE", "DOMAIN", "ACTION"];

fn rule_constraints() -> [Constraint; RULE_HEADERS.len()] {
    [
        Constraint::Length(5),
        Constraint::Percentage(48),
        Constraint::Min(12),
        Constraint::Length(8),
    ]
}

/// **Comments and refused lines are rows, not omissions.** The daemon gives
/// every physical row a stable reference, so this table intentionally keeps
/// comments, blanks and malformed rows in source order rather than making a
/// lossy client-side rules-only projection.
fn backend_rule_row(r: &CustomListRuleRow) -> Row<'static> {
    let (domain, action) = rule_domain_action(r);
    Row::new(vec![
        Cell::from(r.line.to_string()).style(Style::default().fg(T.text_muted)),
        Cell::from(r.raw.clone()).style(backend_raw_style(r)),
        Cell::from(domain).style(Style::default().fg(T.text_secondary)),
        Cell::from(action).style(Style::default().fg(backend_state_color(r))),
    ])
}

fn rule_domain_action(row: &CustomListRuleRow) -> (String, &'static str) {
    use crate::config::custom_list::{parse_pack_line, PackLine};
    let domain = match parse_pack_line(&row.raw) {
        Ok(PackLine::Allow(domain) | PackLine::Deny(domain)) => domain.to_string(),
        _ => row.rule_key.clone().unwrap_or_else(|| "—".to_string()),
    };
    let action = if !row.valid || row.duplicate {
        "SKIPPED"
    } else {
        match row.action {
            Some(RuleAction::Allow) => "ALLOW",
            Some(RuleAction::Deny) => "DENY",
            None => "—",
        }
    };
    (domain, action)
}

fn backend_state_color(row: &CustomListRuleRow) -> Color {
    if !row.valid || row.duplicate {
        T.warning
    } else {
        match row.action {
            Some(RuleAction::Allow) => T.success,
            Some(RuleAction::Deny) => T.error,
            None => T.text_muted,
        }
    }
}

fn backend_raw_style(row: &CustomListRuleRow) -> Style {
    if !row.valid {
        Style::default().fg(T.warning)
    } else if row.action.is_none() {
        Style::default().fg(T.text_muted)
    } else {
        Style::default().fg(T.text_primary)
    }
}

fn render_rules_table(
    f: &mut Frame,
    area: Rect,
    app: &mut App,
    selected_list: &CustomListRow,
    rows: &[CustomListRuleRow],
) {
    let constraints = rule_constraints();
    let header = Row::new(RULE_HEADERS.iter().map(|label| Cell::from(*label)))
        .style(theme::table_heading_style(false));
    let selected = app
        .custom_lists
        .selected_row_ref
        .as_ref()
        .filter(|(list_id, _)| *list_id == selected_list.id)
        .and_then(|(_, row_ref)| rows.iter().position(|row| rule_row_key(row) == row_ref))
        .or_else(|| {
            app.custom_lists
                .selected_line
                .and_then(|line| rows.iter().position(|row| row.line == line))
        })
        .or_else(|| (!rows.is_empty()).then_some(0));
    let table = Table::new(
        rows.iter().map(backend_rule_row).collect::<Vec<_>>(),
        constraints,
    )
    .header(header)
    .column_spacing(COLUMN_SPACING)
    .row_highlight_style(theme::highlight_style());
    super::render_table(
        f,
        area,
        table,
        &mut app.custom_lists.rules_table_state,
        selected,
    );
    let offset = app.custom_lists.rules_table_state.offset();
    for (visible, index) in (0..rows.len())
        .skip(offset)
        .take(area.height.saturating_sub(1) as usize)
        .enumerate()
    {
        mouse::register(
            app,
            Rect::new(area.x, area.y + 1 + visible as u16, area.width, 1),
            MouseAction::CustomRuleRow(index),
        );
    }
}

// ── Left pane: the declared lists ────────────────────────────────────

fn render_lists_pane(f: &mut Frame, area: Rect, app: &mut App, rows: &[CustomListRow]) {
    let subtitle = format!("{} Operator-Managed Lists \u{00b7} Stable IDs", rows.len());
    let content = theme::filled_card(
        f.buffer_mut(),
        area,
        "CUSTOM LISTS",
        &subtitle,
        CardRole::Analytics,
    );
    let named = content.width >= 70;
    let visible_columns: Vec<usize> = if named {
        vec![0, 1, 2, 3, 4, 5]
    } else {
        vec![0, 2, 3, 4, 5]
    };
    let constraints = list_constraints(named);
    let columns = crate::tui::ui::table_column_rects(content, &constraints, COLUMN_SPACING, 0);
    let sort = app.mouse.sort(Leaf::CustomLists);
    let header = Row::new(visible_columns.iter().map(|&index| {
        Cell::from(sort_header(LIST_HEADERS[index], index, sort)).style(theme::table_heading_style(
            sort.is_some_and(|order| order.column == index),
        ))
    }))
    .style(theme::table_heading_style(false));

    let body: Vec<Row> = rows
        .iter()
        .map(|r| {
            // The gutter says "this list enforces nothing", which the counts
            // cannot: a list with 32 rules that no profile mounts looks
            // busiest of all.
            let id_style = if r.is_inert() {
                Style::default().fg(T.text_muted)
            } else {
                Style::default().fg(T.text_primary)
            };
            let mut cells = vec![Cell::from(r.id.clone()).style(id_style)];
            if named {
                cells.push(Cell::from(r.display_name.clone()));
            }
            cells.extend([
                Cell::from(count_text(r.allow_count)).style(Style::default().fg(T.success)),
                Cell::from(count_text(r.deny_count)).style(Style::default().fg(T.error)),
                Cell::from(count_text(r.skipped_count))
                    .style(skipped_style(r.skipped_count.unwrap_or_default())),
                Cell::from(used_by_text(r.mounted_profiles.len()))
                    .style(Style::default().fg(T.text_secondary)),
            ]);
            Row::new(cells)
        })
        .collect();

    // Re-resolve the anchor every frame rather than carrying an index: a
    // config reload can add, remove or reorder entries, and an index minted
    // last frame then points at a different list.
    let selected = index_of_display_key(rows, app.custom_lists.selected_id.as_deref())
        .or_else(|| (!rows.is_empty()).then_some(0));

    let table = Table::new(body, constraints.clone())
        .header(header)
        .column_spacing(COLUMN_SPACING)
        .row_highlight_style(theme::highlight_style());

    super::render_table(
        f,
        content,
        table,
        &mut app.custom_lists.table_state,
        selected,
    );
    for (&index, rect) in visible_columns.iter().zip(columns.iter()) {
        mouse::register(app, *rect, MouseAction::Sort(Leaf::CustomLists, index));
    }
    let offset = app.custom_lists.table_state.offset();
    for (visible, index) in (0..rows.len())
        .skip(offset)
        .take(content.height.saturating_sub(1) as usize)
        .enumerate()
    {
        mouse::register(
            app,
            Rect::new(content.x, content.y + 1 + visible as u16, content.width, 1),
            MouseAction::Row(Leaf::CustomLists, index),
        );
    }
}

fn list_constraints(named: bool) -> Vec<Constraint> {
    let mut constraints = vec![Constraint::Min(12)];
    if named {
        constraints.push(Constraint::Length(25));
    }
    constraints.extend([
        Constraint::Length(3),
        Constraint::Length(3),
        Constraint::Length(3),
        Constraint::Length(7),
    ]);
    constraints
}

fn count_text(value: Option<usize>) -> String {
    value
        .map(|count| count.to_string())
        .unwrap_or_else(|| "—".to_string())
}

fn sort_header(label: &str, index: usize, sort: Option<SortOrder>) -> String {
    match sort.filter(|sort| sort.column == index) {
        Some(sort) if sort.descending => format!("{label} ▼"),
        Some(_) => format!("{label} ▲"),
        None => label.to_string(),
    }
}

/// Nonzero skipped is a defect the operator should see; zero is the
/// ordinary case and must not shout.
fn skipped_style(skipped: usize) -> Style {
    if skipped > 0 {
        Style::default().fg(T.warning)
    } else {
        Style::default().fg(T.text_muted)
    }
}

pub fn used_by_text(used_by: usize) -> String {
    if used_by == 0 {
        USED_BY_NONE.to_string()
    } else {
        used_by.to_string()
    }
}

// ── Writing a pack ───────────────────────────────────────────────────

/// Why a pack could not be reached or written.
#[cfg(test)]
#[derive(Debug, thiserror::Error)]
pub enum PackAccessError {
    #[error(transparent)]
    Write(#[from] crate::config::custom_list::PackWriteError),
    /// Another writer holds the tree, or the config directory is not
    /// writable. Carries the message flattened rather than the error:
    /// it names the lock path and what to check, which an operator
    /// hitting it needs, and `anyhow::Error` is not a `std` error so it
    /// cannot be a `#[source]`.
    #[error("{0}")]
    Lock(String),
}

/// The operator's own ceiling on a pack file.
///
/// Read from the config, never assumed: a write above the configured cap
/// produces a file `read_pack` then refuses, and `build_store` is
/// all-or-nothing — so the next reload fails the whole config, not just
/// this list.
#[cfg(test)]
pub fn max_pack_bytes(loaded: &LoadedConfig) -> u64 {
    loaded.config.custom_list_limits.max_file_bytes
}

/// Claim the config tree for one pack write. **The only seat that takes
/// this lock for a pack.**
///
/// The lock covers the config **directory**, so a pack write and a
/// `[[custom_lists]]` promotion serialise against each other rather than
/// only against their own kind.
///
/// A caller may retain the guard through a matching config promotion, but
/// must end its synchronous guarded scope before any await or reload.
#[cfg(test)]
pub fn claim_tree(master: &std::path::Path) -> Result<ConfigWriteLock, PackAccessError> {
    crate::config::write_lock::acquire_for_write(master)
        .map_err(|e| PackAccessError::Lock(format!("{e:#}")))
}

/// Derive a managed pack path from the pinned canonical config root.
///
/// `loaded` is a freshly guarded UI snapshot. It contributes the declared
/// id/cap at the call site, but never its master-parent path: an alias used
/// to launch the TUI must not redirect pack writes beside the alias.
#[cfg(test)]
pub(crate) fn pack_file_locked(
    guard: &ConfigWriteLock,
    loaded: &LoadedConfig,
    id: &Id,
) -> Result<std::path::PathBuf, PackAccessError> {
    guard
        .verify_master(&loaded.master_path)
        .map_err(|e| PackAccessError::Lock(format!("{e:#}")))?;
    Ok(crate::config::custom_list::pack_path(
        &guard.identity().root,
        id,
    ))
}

/// Append one rule while the caller retains the tree guard. **The only way
/// this leaf grows a pack.**
///
/// The choke point is the point. `write_pack` validates every line and
/// rejects the whole file on the first bad one, so a surface that rebuilt a
/// pack from what it had drawn would either refuse a file that loaded
/// cleanly or silently drop the operator's comments and every line the
/// reader had skipped. `add_rule` appends and touches nothing else.
///
/// Serialised on the tree write lock, because the append is a
/// read-modify-write: two of them reading the same pre-state each rewrite
/// from it, and the second drops the first operator's rule silently.
#[cfg(test)]
pub(crate) fn append_rule_locked(
    guard: &ConfigWriteLock,
    loaded: &LoadedConfig,
    id: &Id,
    domain: &str,
    allow: bool,
) -> Result<crate::config::custom_list::AddOutcome, PackAccessError> {
    let path = pack_file_locked(guard, loaded, id)?;
    Ok(crate::config::custom_list::add_rule(
        guard,
        &path,
        domain,
        allow,
        max_pack_bytes(loaded),
    )?)
}

/// Drop `domain` from a pack — **in both directions**.
///
/// `remove_rule` matches on the domain alone, so a domain present as both
/// an allow and a deny loses both lines in one call. Every confirm that
/// reaches here has to say so: the row under the cursor shows one direction
/// and nothing on it hints at the other.
#[cfg(test)]
pub(crate) fn delete_rule_locked(
    guard: &ConfigWriteLock,
    loaded: &LoadedConfig,
    id: &Id,
    domain: &str,
) -> Result<bool, PackAccessError> {
    let path = pack_file_locked(guard, loaded, id)?;
    Ok(crate::config::custom_list::remove_rule(
        guard,
        &path,
        domain,
        max_pack_bytes(loaded),
    )?)
}

// ── Empty / error states ─────────────────────────────────────────────

fn render_empty(f: &mut Frame, area: Rect) {
    let lines = vec![
        Line::from(Span::styled(
            "  no custom lists declared.",
            Style::default().fg(T.text_muted),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "  a custom list is a file you write yourself — allow and deny",
            Style::default().fg(T.text_muted),
        )),
        Line::from(Span::styled(
            "  rules together, mounted on the profiles you choose.",
            Style::default().fg(T.text_muted),
        )),
        Line::from(""),
        // **Offered only because `a` is bound.** This read `[a] create one`
        // for a whole release while no handler existed: the operator
        // pressed it, nothing happened, and the reasonable conclusion was
        // that the tab was broken. The row and its handler travel together.
        Line::from(Span::styled(
            "  [a] create one",
            Style::default().fg(T.text_secondary),
        )),
    ];
    f.render_widget(Paragraph::new(lines), area);
}

fn render_empty_master_detail(f: &mut Frame, area: Rect, app: &App) {
    if !rules_pane_is_painted(area.width) {
        let content = theme::filled_card(
            f.buffer_mut(),
            area,
            "CUSTOM LISTS",
            "Operator-Managed Lists",
            CardRole::Analytics,
        );
        render_empty(f, content);
        return;
    }
    let cols = proportional_columns(area);
    let content = theme::filled_card(
        f.buffer_mut(),
        cols[0],
        "CUSTOM LISTS",
        "Operator-Managed Lists",
        CardRole::Analytics,
    );
    render_empty(f, content);
    let detail = theme::filled_card(
        f.buffer_mut(),
        cols[1],
        "CUSTOM LIST RULES",
        "No List Selected",
        CardRole::History,
    );
    render_muted(
        f,
        detail,
        if app.custom_lists.focus == CustomListsFocus::Rules {
            "  no rules are available until a list exists"
        } else {
            "  add a list to inspect its backend rule rows"
        },
    );
}

/// The rule pane's empty state.
///
/// Not "the file is empty": a pack holding only comments and blanks has
/// bytes in it and still enforces nothing, and this pane lists only the
/// lines that carry a rule.
///
/// The offered key depends on `focused` because `a` is bound per pane —
/// on the list pane it adds a LIST. A hint that named `a` unconditionally
/// would send the operator to the wrong modal from the state they are
/// actually in.
fn render_no_rules(f: &mut Frame, area: Rect, focused: bool) {
    let hint = if focused {
        "  [a] add a rule"
    } else {
        "  [\u{2192}] then [a] to add a rule"
    };
    let lines = vec![
        Line::from(Span::styled(
            "  no rules in this list.",
            Style::default().fg(T.text_muted),
        )),
        Line::from(""),
        Line::from(Span::styled(hint, Style::default().fg(T.text_secondary))),
    ];
    f.render_widget(Paragraph::new(lines), area);
}

fn render_muted(f: &mut Frame, area: Rect, text: &str) {
    f.render_widget(
        Paragraph::new(Line::from(Span::styled(
            text.to_string(),
            Style::default().fg(T.text_muted),
        ))),
        area,
    );
}

fn render_rules_unavailable(
    f: &mut Frame,
    area: Rect,
    selected: &CustomListRow,
    focus: CustomListsFocus,
    problem: CustomListRules,
) {
    let reason = match problem {
        CustomListRules::Unavailable { message } => {
            return render_rule_snapshot_problem(
                f,
                area,
                selected,
                focus,
                "  backend rule rows are unavailable.",
                message.map(|message| format!("  {message}")),
            );
        }
        CustomListRules::DifferentList { loaded_id } => {
            return render_rule_snapshot_problem(
                f,
                area,
                selected,
                focus,
                "  backend rows belong to a different list.",
                Some(format!("  loaded snapshot: {loaded_id}")),
            );
        }
        CustomListRules::StaleRevision => "  backend rule rows are stale for this list.",
        CustomListRules::Ready(_) => unreachable!("ready rows render as a table"),
    };
    render_rule_snapshot_problem(f, area, selected, focus, reason, None);
}

fn render_rule_snapshot_problem(
    f: &mut Frame,
    area: Rect,
    selected: &CustomListRow,
    focus: CustomListsFocus,
    reason: &str,
    detail: Option<String>,
) {
    let lines = vec![
        Line::from(Span::styled(reason, Style::default().fg(T.warning))),
        Line::from(Span::styled(
            format!(
                "  {} has {} declared rule row(s), {} malformed/skipped.",
                selected.id, selected.rule_count, selected.invalid_rows
            ),
            Style::default().fg(T.text_secondary),
        )),
        Line::from(Span::styled(
            detail.unwrap_or_default(),
            Style::default().fg(T.text_secondary),
        )),
        Line::from(""),
        Line::from(Span::styled(
            if focus == CustomListsFocus::Rules {
                "  stay on Rules; the IPC snapshot will populate this pane."
            } else {
                "  move focus to Rules after the IPC snapshot arrives."
            },
            Style::default().fg(T.text_muted),
        )),
    ];
    f.render_widget(Paragraph::new(lines), area);
}

fn render_catalog_unavailable(f: &mut Frame, area: Rect, error: Option<&str>) {
    let content = theme::filled_card(
        f.buffer_mut(),
        area,
        "CUSTOM LISTS",
        "Operator-Policy Catalogue Unavailable",
        CardRole::Analytics,
    );
    let text = error
        .map(|error| format!("  inventory unavailable: {error}"))
        .unwrap_or_else(|| {
            "  waiting for the operator-policy inventory; config files are not used as a fallback."
                .to_string()
        });
    render_muted(f, content, &text);
}

pub fn render_info_overlay(f: &mut Frame, area: Rect, app: &App) {
    use crate::tui::modal_form::{self, Action, ActionKind, NoticeSpec, ProseRow, ValueKind};

    let Some(info) = app.custom_lists.info.as_ref() else {
        return;
    };
    let mut prose = Vec::new();
    let (title, desc, attention) = match &info.target {
        CustomListInfoTarget::List(id) => {
            let Some(row) = build_display_rows(app)
                .into_iter()
                .find(|row| &row.id == id)
            else {
                return;
            };
            prose.extend([
                ProseRow::emphasis(format!("ID              {}", row.id), ValueKind::Identity),
                ProseRow::plain(format!("Display         {}", row.display_name)),
                ProseRow::plain(format!("Description     {}", row.description)),
                ProseRow::plain(format!(
                    "Rules           {} allow · {} deny · {} skipped",
                    count_text(row.allow_count),
                    count_text(row.deny_count),
                    count_text(row.skipped_count)
                )),
                ProseRow::plain(format!(
                    "Used by         {}",
                    if row.mounted_profiles.is_empty() {
                        "None · This List Filters Nothing".to_string()
                    } else {
                        row.mounted_profiles.join(", ")
                    }
                )),
            ]);
            let attention = row.count_error.is_some() || row.invalid_rows > 0;
            if info.advanced_expanded {
                prose.push(ProseRow::emphasis("ADVANCED", ValueKind::Caution));
                prose.push(ProseRow::plain(format!("Bytes           {}", row.bytes)));
                prose.push(ProseRow::verbatim(
                    format!("Config revision {}", row.config_revision),
                    ValueKind::Identity,
                ));
                prose.push(ProseRow::verbatim(
                    format!("Pack revision   {}", row.pack_revision),
                    ValueKind::Identity,
                ));
                if let Some(error) = row.count_error {
                    prose.push(ProseRow::verbatim(error, ValueKind::Blocking));
                }
            }
            (
                "Custom List Details".to_string(),
                "Identity, mounts and semantic counts".to_string(),
                attention,
            )
        }
        CustomListInfoTarget::Rule { list_id, row_ref } => {
            let Some(rule) = app.operator_rules.as_ref().and_then(|rules| {
                (rules.id == *list_id)
                    .then(|| rules.rows.iter().find(|row| row.row_ref == *row_ref))
                    .flatten()
            }) else {
                return;
            };
            let projected = CustomListRuleRow {
                line: rule.line,
                raw: rule.raw.clone(),
                row_ref: rule.row_ref.clone(),
                rule_key: rule.rule_key.clone(),
                action: rule.action,
                valid: rule.valid,
                duplicate: rule.duplicate,
            };
            let (domain, action) = rule_domain_action(&projected);
            prose.extend([
                ProseRow::emphasis(format!("List            {list_id}"), ValueKind::Identity),
                ProseRow::plain(format!("Line            {}", rule.line)),
                ProseRow::plain(format!("Domain          {domain}")),
                ProseRow::plain(format!("Action          {action}")),
            ]);
            let attention = !rule.valid || rule.duplicate;
            if info.advanced_expanded {
                prose.push(ProseRow::emphasis("ADVANCED", ValueKind::Caution));
                prose.push(ProseRow::verbatim(
                    format!("Raw             {}", rule.raw),
                    if attention {
                        ValueKind::Blocking
                    } else {
                        ValueKind::Identity
                    },
                ));
                prose.push(ProseRow::verbatim(
                    format!("Row reference   {}", rule.row_ref),
                    ValueKind::Identity,
                ));
                prose.push(ProseRow::plain(format!(
                    "Validation      {}{}",
                    if rule.valid { "valid" } else { "invalid" },
                    if rule.duplicate { " · duplicate" } else { "" }
                )));
            }
            (
                "Rule Details".to_string(),
                "Parsed meaning and lossless backend source".to_string(),
                attention,
            )
        }
    };
    let advanced = if info.advanced_expanded {
        "hide"
    } else {
        "show"
    };
    let spec = NoticeSpec {
        title,
        desc,
        prose,
        hint: if attention && !info.advanced_expanded {
            "validation needs attention · Advanced opened automatically on next view".into()
        } else {
            format!("Enter {advanced}s Advanced diagnostics")
        },
        keys: "[Enter] Advanced   [i / Esc] close".into(),
        actions: vec![
            Action::new("  [Enter] Advanced  ", false, ActionKind::Primary, "")
                .on_key(crossterm::event::KeyCode::Enter),
            Action::new("  [Esc] Close  ", false, ActionKind::Neutral, "")
                .on_key(crossterm::event::KeyCode::Esc),
        ],
        ..Default::default()
    };
    modal_form::render_modal(f, area, 76, |width| {
        (modal_form::notice_body(&spec, width), ())
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::custom_list::CustomListStore;
    use crate::config::schema::{ConfigV1, Id, Profile};
    use crate::operator_rules::{Capabilities, ListDetail, Metadata, RuleRow, TransportLimits};
    use crate::tui::operator_policy::{PolicyCatalog, PolicyRules};
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    fn entity(id: &str) -> CustomList {
        CustomList {
            id: Id::new(id).unwrap(),
            display_name: String::new(),
            description: String::new(),
        }
    }

    fn loaded(
        entities: Vec<CustomList>,
        store: Vec<(&str, CompiledCustomList)>,
        profiles: Vec<(&str, Profile)>,
    ) -> LoadedConfig {
        let mut compiled_store = CustomListStore::new();
        for (id, c) in store {
            compiled_store.insert(Id::new(id).unwrap(), c);
        }
        LoadedConfig {
            config: ConfigV1 {
                custom_lists: entities,
                profiles: profiles
                    .into_iter()
                    .map(|(k, v)| (k.to_string(), v))
                    .collect(),
                ..Default::default()
            },
            master_path: std::path::PathBuf::from("/tmp/dummy.toml"),
            files_loaded: Vec::new(),
            total_bytes: 0,
            provenance: Default::default(),
            custom_lists: compiled_store,
        }
    }

    fn dump(term: &Terminal<TestBackend>) -> String {
        let buf = term.backend().buffer().clone();
        let mut out = String::new();
        for y in 0..buf.area.height {
            for x in 0..buf.area.width {
                out.push_str(buf[(x, y)].symbol());
            }
            out.push('\n');
        }
        out
    }

    fn screen_lists(app: &mut App, rows: &[CustomListRow], w: u16, h: u16) -> String {
        let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
        term.draw(|f| render_lists_pane(f, f.area(), app, rows))
            .unwrap();
        dump(&term)
    }

    fn screen_rules(
        app: &mut App,
        selected: &CustomListRow,
        rows: &[CustomListRuleRow],
        w: u16,
        h: u16,
    ) -> String {
        let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
        term.draw(|f| {
            let area = f.area();
            let content = theme::filled_card(
                f.buffer_mut(),
                area,
                "CUSTOM LIST RULES",
                &format!("{} · Rules & Validation", selected.id),
                CardRole::History,
            );
            render_rules_table(f, content, app, selected, rows);
        })
        .unwrap();
        dump(&term)
    }

    fn screen_empty(app: &App, w: u16, h: u16) -> String {
        let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
        term.draw(|f| render_empty_master_detail(f, f.area(), app))
            .unwrap();
        dump(&term)
    }

    fn catalog_row(id: &str, rules: usize, invalid: usize, mounts: &[&str]) -> CustomListRow {
        CustomListRow {
            id: id.to_string(),
            display_name: id.to_string(),
            description: String::new(),
            allow_count: Some(rules.saturating_sub(invalid)),
            deny_count: Some(0),
            skipped_count: Some(invalid),
            count_error: None,
            rule_count: rules,
            invalid_rows: invalid,
            mounted_profiles: mounts.iter().map(|mount| (*mount).to_string()).collect(),
            bytes: rules * 20,
            config_revision: "config-r1".to_string(),
            pack_revision: format!("{id}-r1"),
        }
    }

    fn backend_row(
        line: usize,
        raw: &str,
        action: Option<RuleAction>,
        valid: bool,
        duplicate: bool,
    ) -> CustomListRuleRow {
        CustomListRuleRow {
            line,
            raw: raw.to_string(),
            row_ref: format!("videogames:r1:{line}"),
            rule_key: action.map(|_| format!("key-{line}")),
            action,
            valid,
            duplicate,
        }
    }

    fn policy_catalog(lists: Vec<CustomListRow>) -> PolicyCatalog {
        PolicyCatalog {
            capabilities: Capabilities {
                contract_version: 1,
                schema_version: 5,
                operator_rule_grammar: 1,
                operations: Vec::new(),
                semantic_hash: true,
                activation_ack: true,
                cluster_artifact: false,
                limits: TransportLimits::IPC,
            },
            metadata: Metadata {
                contract_version: 1,
                schema_version: 5,
                config_revision: "config-r1".to_string(),
                desired_operator_policy_hash: String::new(),
                active_policy: None,
                activation_in_sync: true,
                lists: lists.len(),
                mounted_lists: lists.iter().filter(|row| !row.is_inert()).count(),
                orphan_packs: 0,
            },
            lists: lists
                .into_iter()
                .map(|row| ListDetail {
                    id: row.id,
                    display_name: row.display_name,
                    description: row.description,
                    config_revision: row.config_revision,
                    pack_revision: row.pack_revision,
                    bytes: row.bytes,
                    rule_count: row.rule_count,
                    invalid_rows: row.invalid_rows,
                    profiles: row.mounted_profiles,
                })
                .collect(),
            orphan_packs: Vec::new(),
        }
    }

    fn policy_rules(id: &str, rows: Vec<CustomListRuleRow>) -> PolicyRules {
        PolicyRules {
            id: id.to_string(),
            config_revision: "config-r1".to_string(),
            pack_revision: format!("{id}-r1"),
            rows: rows
                .into_iter()
                .map(|row| RuleRow {
                    line: row.line,
                    raw: row.raw,
                    row_ref: row.row_ref,
                    rule_key: row.rule_key,
                    action: row.action,
                    valid: row.valid,
                    duplicate: row.duplicate,
                })
                .collect(),
        }
    }

    fn app_with(loaded: LoadedConfig) -> App {
        let mut app = App::new();
        app.active_leaf = crate::tui::app::Leaf::CustomLists;
        app.loaded_config = Some(loaded);
        app
    }

    // ── Render ───────────────────────────────────────────────────────

    #[test]
    fn the_catalogue_table_paints_backend_counts_and_the_unmounted_dash() {
        let source = vec![
            catalog_row("videogames", 3, 1, &["kids"]),
            catalog_row("orphan", 0, 0, &[]),
        ];
        let mut app = app_with(loaded(vec![], vec![], vec![]));
        app.operator_catalog = Some(policy_catalog(source));
        let rows = build_display_rows(&app);
        let out = screen_lists(&mut app, &rows, 80, 24);
        assert!(out.contains("CUSTOM LISTS"), "title; got:\n{out}");
        assert!(out.contains("videogames"), "id; got:\n{out}");
        for header in ["A", "D", "S", "USED BY"] {
            assert!(out.contains(header), "{header} header; got:\n{out}");
        }
        assert!(
            out.contains(USED_BY_NONE),
            "a list nobody mounts shows the dash, not a bare 0; got:\n{out}"
        );
    }

    #[test]
    fn list_selection_resolves_by_stable_id_after_a_sorted_projection() {
        let rows = [
            catalog_row("alpha", 1, 0, &[]),
            catalog_row("zulu", 2, 0, &[]),
        ];
        assert_eq!(index_of_display_key(&rows, Some("zulu")), Some(1));
        assert_eq!(index_of_display_key(&rows, Some("gone")), None);
    }

    #[test]
    fn typed_sort_uses_numeric_counts_and_a_stable_id_tie_breaker() {
        let mut rows = vec![
            catalog_row("zulu", 2, 0, &[]),
            catalog_row("alpha", 12, 0, &[]),
            catalog_row("beta", 2, 0, &[]),
        ];
        sort_display_rows(
            &mut rows,
            Some(SortOrder {
                column: 2,
                descending: false,
            }),
        );
        assert_eq!(
            rows.iter().map(|row| row.id.as_str()).collect::<Vec<_>>(),
            ["beta", "zulu", "alpha"],
            "rule counts are numeric and equal values sort by stable id"
        );
    }

    #[test]
    fn unavailable_counters_stay_last_in_both_directions() {
        for column in 2..=4 {
            let mut low = catalog_row("low", 2, 0, &[]);
            let mut high = catalog_row("high", 12, 0, &[]);
            let mut unavailable = catalog_row("unavailable", 0, 0, &[]);
            match column {
                2 => {
                    low.allow_count = Some(2);
                    high.allow_count = Some(12);
                    unavailable.allow_count = None;
                }
                3 => {
                    low.deny_count = Some(2);
                    high.deny_count = Some(12);
                    unavailable.deny_count = None;
                }
                4 => {
                    low.skipped_count = Some(2);
                    high.skipped_count = Some(12);
                    unavailable.skipped_count = None;
                }
                _ => unreachable!(),
            }

            for (descending, expected) in [
                (false, ["low", "high", "unavailable"]),
                (true, ["high", "low", "unavailable"]),
            ] {
                let mut rows = vec![unavailable.clone(), high.clone(), low.clone()];
                sort_display_rows(&mut rows, Some(SortOrder { column, descending }));
                assert_eq!(
                    rows.iter().map(|row| row.id.as_str()).collect::<Vec<_>>(),
                    expected,
                    "column {column}, descending={descending}"
                );
            }
        }
    }

    #[test]
    fn display_name_sort_uses_unicode_case_and_keeps_id_ties_ascending() {
        let mut upper = catalog_row("zeta", 1, 0, &[]);
        upper.display_name = "Äther".into();
        let mut lower = catalog_row("alpha", 1, 0, &[]);
        lower.display_name = "äther".into();

        for descending in [false, true] {
            let mut rows = vec![upper.clone(), lower.clone()];
            sort_display_rows(
                &mut rows,
                Some(SortOrder {
                    column: 1,
                    descending,
                }),
            );
            assert_eq!(
                rows.iter().map(|row| row.id.as_str()).collect::<Vec<_>>(),
                ["alpha", "zeta"],
                "Unicode-equivalent names retain an ascending immutable-id tie"
            );
        }
    }

    /// An empty config is the state every box is in before the first list,
    /// so it has to say what a custom list *is* — and must not offer a key
    /// that does nothing.
    ///
    /// **`[a] create one` is back, and the history is the point.** It
    /// shipped once while no `a` handler existed, so the only witness to
    /// this assertion was the phantom affordance it was meant to guard.
    /// The key is bound now, which is what makes the row honest — and
    /// `every_key_the_custom_lists_leaf_advertises_is_bound` is what keeps
    /// the two travelling together rather than this string.
    #[test]
    fn the_empty_state_explains_the_concept_and_offers_the_bound_key() {
        let out = screen_empty(&app_with(loaded(vec![], vec![], vec![])), 80, 12);
        assert!(out.contains("no custom lists declared"), "got:\n{out}");
        assert!(
            out.contains("a file you write yourself"),
            "the empty state must say what a custom list IS; got:\n{out}"
        );
        assert!(
            out.contains("[a] create one"),
            "`a` is bound now, so the empty state must offer it; got:\n{out}"
        );
    }

    // ── Rule pane ────────────────────────────────────────────────────

    /// Comments are hidden from the semantic table while an invalid backend
    /// row stays visible and classified. No display projection can write a pack.
    #[test]
    fn typed_rows_hide_comments_and_name_skipped_lines() {
        let selected = catalog_row("videogames", 2, 1, &["kids"]);
        let rows = [
            backend_row(1, "# ---- Mojang ----", None, true, false),
            backend_row(
                2,
                "@@||minecraft.net^",
                Some(RuleAction::Allow),
                true,
                false,
            ),
            backend_row(3, "", None, true, false),
            backend_row(4, "this line is not a rule", None, false, false),
        ];
        let mut app = app_with(loaded(vec![], vec![], vec![]));
        app.operator_rules = Some(policy_rules("videogames", rows.to_vec()));
        let CustomListRules::Ready(displayed) = display_rule_rows(&app, &selected) else {
            panic!("matching backend page must project")
        };
        let out = screen_rules(&mut app, &selected, &displayed, 120, 18);
        assert!(
            !out.contains("Mojang"),
            "a comment is not a semantic display row; got:\n{out}"
        );
        assert!(
            out.contains("this line is not a rule"),
            "an invalid row must be visible, not filtered away; got:\n{out}"
        );
        assert!(
            out.contains("SKIPPED"),
            "an invalid row must retain the frozen SKIPPED classification; got:\n{out}"
        );
        assert!(out.contains("ALLOW"), "got:\n{out}");
        assert!(
            !out.contains("COMMENT"),
            "comments must not occupy semantic rule rows; got:\n{out}"
        );
    }

    /// Hiding a comment does not discard its durable backend identity.
    #[test]
    fn hidden_comments_retain_their_row_refs() {
        let comment = backend_row(7, "# hand-written", None, true, false);
        assert_eq!(rule_row_key(&comment), "videogames:r1:7");
        assert!(comment.valid && comment.action.is_none());
    }

    /// Semantic rows retain backend order and row references. A display
    /// filter must never turn the visible index into a mutable file offset.
    #[test]
    fn backend_rule_identity_is_row_ref_not_visible_line() {
        let rows = [
            backend_row(2, "||a.example^", Some(RuleAction::Deny), true, false),
            backend_row(4, "@@||b.example^", Some(RuleAction::Allow), true, false),
        ];
        assert_eq!(rule_row_key(&rows[0]), "videogames:r1:2");
        assert_eq!(rule_row_key(&rows[1]), "videogames:r1:4");
        assert!(
            rows.iter().map(|row| row.line).eq([2, 4]),
            "backend source order remains visible"
        );
    }

    #[test]
    fn non_simple_backend_syntax_opens_the_verbatim_editor() {
        let row = backend_row(
            9,
            "@@||tracking.example.com^$important",
            Some(RuleAction::Allow),
            true,
            false,
        );
        let modal = rule_editor_modal("videogames".to_string(), &row);
        let crate::tui::custom_list_modal::Stage::AddingRule(form) = modal.stage else {
            panic!("rule editor must open a rule form")
        };
        assert!(form.is_raw_edit());
        assert_eq!(form.row_ref(), Some("videogames:r1:9"));
        assert_eq!(form.raw_rule, "@@||tracking.example.com^$important");
    }

    /// **The title is what answers "is this list selected?".** With one row
    /// the highlight has no unhighlighted neighbour to contrast against, so
    /// naming the selection is the fix — the same thing Devices does.
    #[test]
    fn the_rule_pane_names_the_selected_list_in_its_title() {
        let selected = catalog_row("videogames", 1, 0, &[]);
        let rows = [backend_row(
            1,
            "||a.example^",
            Some(RuleAction::Deny),
            true,
            false,
        )];
        let out = screen_rules(
            &mut app_with(loaded(vec![], vec![], vec![])),
            &selected,
            &rows,
            120,
            12,
        );
        assert!(
            out.contains("CUSTOM LIST RULES") && out.contains("videogames"),
            "the title must name the selection; got:\n{out}"
        );
    }

    /// No selection is not an error state; it reads like Devices' own.
    #[test]
    fn with_no_selection_the_rule_pane_invites_one() {
        let mut app = app_with(loaded(vec![], vec![], vec![]));
        let mut term = Terminal::new(TestBackend::new(120, 12)).unwrap();
        term.draw(|f| render_rules_pane(f, f.area(), &mut app, None))
            .unwrap();
        let out = dump(&term);
        assert!(out.contains(NO_SELECTION.trim()), "got:\n{out}");
    }

    /// An unavailable backend page is not an empty rule page.
    #[test]
    fn unavailable_backend_rows_are_not_rendered_as_empty() {
        let selected = catalog_row("videogames", 2, 0, &[]);
        let mut term = Terminal::new(TestBackend::new(120, 12)).unwrap();
        term.draw(|f| {
            render_rules_unavailable(
                f,
                f.area(),
                &selected,
                CustomListsFocus::Rules,
                CustomListRules::Unavailable {
                    message: Some("permission denied".to_string()),
                },
            )
        })
        .unwrap();
        let out = dump(&term);
        assert!(
            out.contains("backend rule rows are unavailable"),
            "got:\n{out}"
        );
        assert!(out.contains("permission denied"), "got:\n{out}");
    }

    /// Below the split threshold the rule pane is not painted at all, so
    /// the focus must never rest there. At the 80-column floor that is the
    /// normal state.
    #[test]
    fn the_split_collapses_at_the_eighty_column_floor() {
        assert!(
            !rules_pane_is_painted(80),
            "at the declared floor the rule pane must not be promised"
        );
        assert!(rules_pane_is_painted(120), "a wide terminal splits");
        let rows = [catalog_row("videogames", 1, 0, &[])];
        let out = screen_lists(&mut app_with(loaded(vec![], vec![], vec![])), &rows, 80, 12);
        assert!(
            !out.contains("CUSTOM LIST RULES"),
            "the collapsed layout must not paint a rule pane; got:\n{out}"
        );
        assert!(
            out.contains("USED BY"),
            "the list pane survives; got:\n{out}"
        );
    }

    /// At the declared floor the table still shows the columns `d` depends
    /// on. A cell that truncates does so in silence, so this reads the
    /// buffer rather than the row vector.
    #[test]
    fn used_by_survives_the_eighty_column_floor() {
        let rows = [catalog_row("videogames", 1, 0, &["kids"])];
        let out = screen_lists(&mut app_with(loaded(vec![], vec![], vec![])), &rows, 80, 24);
        assert!(
            out.contains("USED BY"),
            "USED BY must be readable at the declared floor; got:\n{out}"
        );
    }

    /// A `LoadedConfig` rooted in a real directory, so `packs/` and the
    /// tree write lock both resolve under `dir`.
    ///
    /// Built as a struct literal rather than through `load_config`: the
    /// writers below read only `master_path` and the byte cap, and a TOML
    /// fixture would tie these tests to schema fields they never touch.
    fn loaded_at(dir: &std::path::Path) -> LoadedConfig {
        let mut l = loaded(vec![entity("videogames")], vec![], vec![]);
        l.master_path = dir.join("config.toml");
        l
    }

    /// An empty pack for `videogames`, plus the comment line a real one
    /// carries — appends must not eat it.
    fn seed_pack(dir: &std::path::Path) -> std::path::PathBuf {
        std::fs::create_dir_all(dir.join("packs")).unwrap();
        let pack = dir.join("packs").join("videogames.txt");
        std::fs::write(&pack, "# hand-written\n").unwrap();
        pack
    }

    /// A separate TUI session's complete append gesture. Production callers
    /// that also mutate declarations retain the guard themselves; these race
    /// tests deliberately model independent sessions.
    fn append_for_test(
        loaded: &LoadedConfig,
        id: &Id,
        domain: &str,
        allow: bool,
    ) -> Result<crate::config::custom_list::AddOutcome, PackAccessError> {
        let guard = claim_tree(&loaded.master_path)?;
        append_rule_locked(&guard, loaded, id, domain, allow)
    }

    fn delete_for_test(
        loaded: &LoadedConfig,
        id: &Id,
        domain: &str,
    ) -> Result<bool, PackAccessError> {
        let guard = claim_tree(&loaded.master_path)?;
        delete_rule_locked(&guard, loaded, id, domain)
    }

    /// **Concurrent appends to one pack must not lose each other.**
    ///
    /// `add_rule` is a read-modify-write: it reads the whole file, appends
    /// one line and rewrites it. The write is atomic, so no reader ever
    /// sees a torn file — but atomicity says nothing about staleness. Two
    /// writers that both read the pre-state each rewrite from it, and the
    /// second erases the first operator's rule with no error on either
    /// side. Serialising on the tree write lock is what closes it.
    #[test]
    fn concurrent_appends_to_one_pack_all_land() {
        const THREADS: usize = 8;
        const PER_THREAD: usize = 4;

        let dir = tempfile::tempdir().unwrap();
        let pack = seed_pack(dir.path());
        let l = loaded_at(dir.path());
        let id = Id::new("videogames").unwrap();

        std::thread::scope(|s| {
            for t in 0..THREADS {
                let (l, id) = (&l, &id);
                s.spawn(move || {
                    for n in 0..PER_THREAD {
                        append_for_test(l, id, &format!("d{t}x{n}.example.com"), false)
                            .expect("every append must land");
                    }
                });
            }
        });

        let text = std::fs::read_to_string(&pack).unwrap();
        let rules = text.lines().filter(|l| l.starts_with("||")).count();
        assert_eq!(
            rules,
            THREADS * PER_THREAD,
            "a lost update dropped {} rule(s); file:\n{text}",
            THREADS * PER_THREAD - rules
        );
        assert!(
            text.contains("# hand-written"),
            "the operator's comment must survive every append; got:\n{text}"
        );
    }

    /// The removal half of the same race: interleaved appends and removals
    /// must leave the file agreeing with the calls that were made.
    #[test]
    fn a_removal_concurrent_with_appends_does_not_resurrect_rules() {
        const THREADS: usize = 6;

        let dir = tempfile::tempdir().unwrap();
        let pack = seed_pack(dir.path());
        let l = loaded_at(dir.path());
        let id = Id::new("videogames").unwrap();

        // Present before the race, and removed during it by one thread.
        append_for_test(&l, &id, "doomed.example.com", false).unwrap();

        std::thread::scope(|s| {
            s.spawn(|| {
                delete_for_test(&l, &id, "doomed.example.com").expect("the removal must land");
            });
            for t in 0..THREADS {
                let (l, id) = (&l, &id);
                s.spawn(move || {
                    append_for_test(l, id, &format!("k{t}.example.com"), false)
                        .expect("every append must land");
                });
            }
        });

        let text = std::fs::read_to_string(&pack).unwrap();
        for t in 0..THREADS {
            assert!(
                text.contains(&format!("||k{t}.example.com^")),
                "append k{t} was lost; file:\n{text}"
            );
        }
        assert!(
            !text.contains("doomed.example.com"),
            "a concurrent append rewrote the removal away; file:\n{text}"
        );
    }

    /// The locked primitive is deliberately no-acquire: a custom-list
    /// declaration operation owns this same guard and would self-contend if
    /// the pack layer tried to claim it again.
    #[test]
    fn locked_append_does_not_reacquire_the_tree() {
        let dir = tempfile::tempdir().unwrap();
        seed_pack(dir.path());
        let loaded = loaded_at(dir.path());
        let id = Id::new("videogames").unwrap();
        let guard = claim_tree(&loaded.master_path).unwrap();

        crate::config::write_lock::with_test_hook(
            |event| {
                if event == crate::config::write_lock::TestEvent::Contended
                    || event == crate::config::write_lock::TestEvent::RootLocked
                    || event == crate::config::write_lock::TestEvent::WriteRootLocked
                {
                    panic!("the locked helper must not acquire a second guard");
                }
            },
            || {
                append_rule_locked(&guard, &loaded, &id, "new.example.com", false)
                    .expect("the caller-owned guard is sufficient");
            },
        );
    }

    /// A loaded snapshot from another tree is rendering data, never an
    /// authority for a caller-owned guard.  Reject it before deriving or
    /// creating a managed `packs/` path.
    #[test]
    fn locked_pack_path_rejects_a_loaded_config_from_another_tree() {
        let first = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();
        let guard = claim_tree(&first.path().join("config.toml")).unwrap();
        let foreign = loaded_at(second.path());
        let id = Id::new("videogames").unwrap();

        let error = pack_file_locked(&guard, &foreign, &id)
            .expect_err("a guard must reject a foreign loaded-config snapshot");
        assert!(error.to_string().contains("guard belongs to"));
        assert!(
            !second.path().join("packs").exists(),
            "wrong-tree rejection must not create a pack directory"
        );
    }
}
