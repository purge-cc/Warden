//! Session-only Query Log rules held for one explicit batch Apply.
//!
//! Every Query Log Enter holds a (domain, action, list) target here instead of
//! applying it. `v` reviews the held targets; "Review all" sends them as one
//! operation vector through the existing operator-policy workflow, so several
//! domains on several lists cost one plan, one Apply and one reload.

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::{
    layout::Rect,
    style::Style,
    text::{Line, Span},
    widgets::Paragraph,
    Frame,
};
use serde::{Deserialize, Serialize};

use super::{
    filter_chips,
    modal_form::{self, Action, ActionKind, NoticeSpec, ProseRow},
    mouse::{register_overlay_action, MouseAction},
    query_log_controls::FilterFocus,
    theme::T,
    App, IpcPoller,
};
use crate::operator_rules::{
    BatchRequest, ListDetail, Operation, RuleAction, TransportLimits, CONTRACT_VERSION,
};

const READ_ONLY: &str = "Read-only node: apply these rules on the primary";
const APPLYING: &str = "Applying can take time; rebuilding lists can take longer.";
/// Table cells per rule: ACTION, DOMAIN, LIST. Each row registers one click
/// target per cell, `OverlayChoice(row * COLUMNS + column)`.
const COLUMNS: usize = 3;
/// Fixed cell widths, one space apart: the rows and click cells are the same
/// on both modal build passes, whatever the terminal width.
const CELLS: [usize; COLUMNS] = [6, 39, 20];
const TABLE_WIDTH: usize = CELLS[0] + CELLS[1] + CELLS[2] + COLUMNS - 1;
const ACTIONS: [(RuleAction, &str); 2] = [(RuleAction::Allow, "ALLOW"), (RuleAction::Deny, "DENY")];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HeldTarget {
    pub(crate) domain: String,
    pub(crate) action: RuleAction,
    pub(crate) list_id: String,
}

impl HeldTarget {
    pub(crate) fn operation(&self) -> Operation {
        Operation::AddDomainRule {
            id: self.list_id.clone(),
            domain: self.domain.clone(),
            action: self.action,
        }
    }
    pub(crate) fn verb(&self) -> &'static str {
        match self.action {
            RuleAction::Allow => "ALLOW",
            RuleAction::Deny => "DENY",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Review {
    Rules,
    Discard,
    Quit,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct QueryRuleBatch {
    pub(crate) targets: Vec<HeldTarget>,
    pub(crate) review: Option<Review>,
    pub(crate) selected_target: usize,
    pub(crate) row_offset: usize,
    /// Selected cell of the selected rule: 0 action, 1 domain, 2 list.
    pub(crate) column: usize,
    pub(crate) focus: usize,
    pub(crate) error: Option<String>,
    pub(crate) receipt: Option<String>,
    pub(crate) editor: Option<Editor>,
}

/// Draft of one cell of the selected rule; applying it runs the hold checks.
#[derive(Debug, Clone)]
pub(crate) struct Editor {
    pub(crate) column: usize,
    pub(crate) action: RuleAction,
    pub(crate) domain: String,
    pub(crate) lists: Vec<String>,
    pub(crate) cursor: usize,
    pub(crate) focus: FilterFocus,
    pub(crate) error: Option<String>,
}

/// "1 rule" / "N rules".
pub(crate) fn rule_count(count: usize) -> String {
    if count == 1 {
        "1 rule".into()
    } else {
        format!("{count} rules")
    }
}

pub(crate) fn editable(app: &App) -> bool {
    #[cfg(feature = "cluster")]
    {
        super::nodes::policy_access(app).editable
    }
    #[cfg(not(feature = "cluster"))]
    {
        let _ = app;
        true
    }
}

pub(crate) fn hold(
    app: &mut App,
    domain: &str,
    action: RuleAction,
    ids: Vec<String>,
) -> Result<usize, String> {
    let held = &app.query_log.held.targets;
    let (targets, added) = stage(app, held.clone(), held.len(), domain, action, ids)?;
    app.query_log.held.targets = targets;
    app.query_log.held.error = None;
    Ok(added)
}

/// Every hold check, shared by a new hold and by an edit: stages one rule per
/// list into `base` from position `at`, and returns the set only if all pass.
fn stage(
    app: &App,
    mut base: Vec<HeldTarget>,
    at: usize,
    domain: &str,
    action: RuleAction,
    ids: Vec<String>,
) -> Result<(Vec<HeldTarget>, usize), String> {
    if !editable(app) {
        return Err("Read-only node: policy changes are made on the primary".into());
    }
    if app.operator_policy.is_some() || app.pending_action.is_some() {
        return Err("Finish the open policy change before holding more rules".into());
    }
    if ids.is_empty() {
        return Err("Select at least one list".into());
    }
    let catalog = app
        .operator_catalog
        .as_ref()
        .ok_or("Custom Lists are not loaded yet; close and reopen to retry")?;
    if !catalog
        .capabilities
        .operations
        .iter()
        .any(|op| op == "add_domain_rule")
    {
        return Err("This daemon cannot add domain rules".into());
    }
    let domain = crate::config::custom_list::normalise_domain(domain)
        .map_err(|e| e.to_string())?
        .to_string();
    // The IPC ceiling (32 operations) keeps this linear scan small.
    let mut added = 0;
    for id in ids {
        if !catalog.lists.iter().any(|list| list.id == id) {
            return Err(format!("List {id} no longer exists; reopen to refresh"));
        }
        if let Some(target) = base
            .iter()
            .find(|target| target.domain == domain && target.list_id == id)
        {
            if target.action != action {
                return Err(format!(
                    "Already held as {} on {}; remove it first (v, Delete)",
                    target.verb(),
                    super::text::fit(&id, 20)
                ));
            }
        } else {
            base.insert(
                at + added,
                HeldTarget {
                    domain: domain.clone(),
                    action,
                    list_id: id,
                },
            );
            added += 1;
        }
    }
    let limit = catalog
        .capabilities
        .limits
        .max_operations
        .min(TransportLimits::IPC.max_operations);
    if base.len() > limit {
        return Err(format!(
            "At most {limit} held rules per Apply; nothing changed. Apply or remove some first"
        ));
    }
    check_wire_size(&base, &catalog.metadata.config_revision)?;
    Ok((base, added))
}

fn check_wire_size(targets: &[HeldTarget], revision: &str) -> Result<(), String> {
    // Size the whole plan command, token included, without reading the token.
    let command = crate::ipc::protocol::IpcCommand::OperatorRulesPlan {
        request: Some(BatchRequest {
            contract_version: CONTRACT_VERSION,
            request_id: "x".repeat(32),
            expected_config_revision: revision.into(),
            operations: targets.iter().map(HeldTarget::operation).collect(),
            expected_plan_hash: None,
        }),
        plan_ref: None,
        page: Default::default(),
        token: Some("x".repeat(128)),
    };
    let bytes = serde_json::to_vec(&command).map_err(|e| e.to_string())?;
    if bytes.len() > crate::ipc::protocol::OPERATOR_RULES_MAX_BYTES {
        return Err("Held rules exceed the 60 KiB request limit; nothing changed".into());
    }
    Ok(())
}

pub(crate) fn open_review(app: &mut App) {
    if app.operator_policy.is_some() || app.pending_action.is_some() {
        app.status_info("Finish the open policy change first".into());
        return;
    }
    let held = &mut app.query_log.held;
    held.review = Some(Review::Rules);
    held.selected_target = 0;
    held.row_offset = 0;
    held.column = 0;
    held.focus = 0;
    held.editor = None;
    app.filter_focus = None;
    // Without the catalog every target would read as a missing list.
    if let (None, Some(jobs)) = (&app.operator_catalog, &mut app.read_jobs) {
        jobs.request(
            super::jobs::ReadRequest::OperatorCatalog,
            super::jobs::ReadReason::Explicit,
        );
    }
}

/// True when the app may quit now; otherwise opens the discard confirmation.
pub(crate) fn request_quit(app: &mut App) -> bool {
    if app.query_log.held.targets.is_empty() {
        return true;
    }
    app.query_log.held.review = Some(Review::Quit);
    app.query_log.held.focus = 0;
    app.query_log.held.editor = None;
    false
}

pub(crate) async fn review_all(app: &mut App, poller: &IpcPoller) {
    if !editable(app) {
        app.query_log.held.error = Some(READ_ONLY.into());
        return;
    }
    let held = &mut app.query_log.held;
    if held.targets.is_empty() {
        held.error = Some("No held rules to apply".into());
        return;
    }
    let targets = held.targets.clone();
    let operations = targets.iter().map(HeldTarget::operation).collect();
    held.review = None;
    held.error = None;
    super::operator_policy::open(
        app,
        poller,
        super::operator_policy::PolicyOrigin::QueryBatch { targets },
        super::operator_policy::PolicyChange::Operations(operations),
    )
    .await;
}

/// Committed batch: drop exactly the submitted targets and keep the receipt.
pub(crate) fn finish_committed(app: &mut App, submitted: &[HeldTarget], message: String) {
    let held = &mut app.query_log.held;
    held.targets.retain(|target| !submitted.contains(target));
    held.selected_target = 0;
    held.row_offset = 0;
    held.error = None;
    held.editor = None;
    held.receipt = Some(message);
    if held.targets.is_empty() && held.review == Some(Review::Quit) {
        held.review = None;
    }
}

/// Failed or aborted batch: every held target stays for correction.
pub(crate) fn finish_failed(app: &mut App, message: &str) {
    app.query_log.held.error = Some(message.into());
}

/// One table row per rule.
pub(crate) fn target_rows(targets: &[HeldTarget]) -> Vec<(usize, String)> {
    targets
        .iter()
        .enumerate()
        .map(|(index, target)| {
            let [action, domain, list] = cells(target.verb(), &target.domain, &target.list_id);
            (index, format!("{action} {domain} {list}"))
        })
        .collect()
}

/// ACTION right-aligned, DOMAIN and LIST trimmed and padded to their cells.
fn cells(action: &str, domain: &str, list: &str) -> [String; COLUMNS] {
    [
        format!("{action:>width$}", width = CELLS[0]),
        super::text::pad(domain, CELLS[1]),
        super::text::pad(list, CELLS[2]),
    ]
}

fn catalog_lists(app: &App) -> &[ListDetail] {
    app.operator_catalog
        .as_ref()
        .map_or(&[][..], |catalog| catalog.lists.as_slice())
}

/// The selected rule's list name and the profiles that use the list.
fn list_context(app: &App, target: &HeldTarget) -> String {
    let loaded = app.operator_catalog.is_some();
    match catalog_lists(app)
        .iter()
        .find(|list| list.id == target.list_id)
    {
        Some(list) if list.profiles.is_empty() => {
            format!(
                "{} · no profile uses it: filters nothing",
                list.display_name
            )
        }
        Some(list) => format!(
            "{} · profiles: {}",
            list.display_name,
            list.profiles.join(", ")
        ),
        None if !loaded && app.operator_catalog_error.is_some() => {
            "Custom List inventory unavailable: reopen to retry".into()
        }
        None if !loaded => "Custom List inventory not loaded yet".into(),
        None => "list not found: remove this rule or reopen to refresh".into(),
    }
}

fn review_rows(app: &App) -> Vec<(usize, String)> {
    let mut rows = target_rows(&app.query_log.held.targets);
    for extra in [
        app.query_log.held.error.clone(),
        app.query_log
            .held
            .receipt
            .as_ref()
            .map(|receipt| format!("Last Apply: {receipt}")),
    ]
    .into_iter()
    .flatten()
    {
        rows.extend(
            super::text::wrap(&extra, 58)
                .into_iter()
                .map(|line| (usize::MAX, line)),
        );
    }
    rows
}

fn selected_row(held: &QueryRuleBatch, rows: &[(usize, String)]) -> usize {
    let start = rows
        .iter()
        .position(|(index, _)| *index == held.selected_target)
        .unwrap_or(0);
    let count = rows
        .iter()
        .skip(start)
        .take_while(|(index, _)| *index == held.selected_target)
        .count();
    start + held.row_offset.min(count.saturating_sub(1))
}

fn select_row(held: &mut QueryRuleBatch, rows: &[(usize, String)], row: usize) {
    if let Some((index, _)) = rows.get(row) {
        let first = rows
            .iter()
            .position(|(owner, _)| owner == index)
            .unwrap_or(row);
        held.selected_target = *index;
        held.row_offset = row - first;
    }
}

fn remove_selected(held: &mut QueryRuleBatch) {
    if held.selected_target < held.targets.len() {
        held.targets.remove(held.selected_target);
        held.selected_target = held
            .selected_target
            .min(held.targets.len().saturating_sub(1));
        held.row_offset = 0;
        held.error = None;
    }
}

fn scroll(app: &mut App, code: KeyCode) {
    let rows = review_rows(app);
    let last = rows.len().saturating_sub(1);
    let current = selected_row(&app.query_log.held, &rows);
    let row = match code {
        KeyCode::Up => current.saturating_sub(1),
        KeyCode::Down => (current + 1).min(last),
        KeyCode::PageUp => current.saturating_sub(6),
        KeyCode::PageDown => (current + 6).min(last),
        KeyCode::Home => 0,
        _ => last,
    };
    select_row(&mut app.query_log.held, &rows, row);
}

/// Returns true when the app should quit (confirmed discard on quit).
pub(crate) async fn handle_key(app: &mut App, key: KeyEvent, poller: &IpcPoller) -> bool {
    let Some(review) = app.query_log.held.review else {
        return false;
    };
    let is_scroll = matches!(
        key.code,
        KeyCode::Up
            | KeyCode::Down
            | KeyCode::PageUp
            | KeyCode::PageDown
            | KeyCode::Home
            | KeyCode::End
    );
    if review != Review::Rules {
        // Discard / Quit confirmation: focus 0 = Keep, 1 = Discard.
        let back = (review == Review::Discard).then_some(Review::Rules);
        match key.code {
            _ if is_scroll => scroll(app, key.code),
            KeyCode::Esc | KeyCode::Char('n' | 'N') => app.query_log.held.review = back,
            KeyCode::Tab | KeyCode::BackTab | KeyCode::Left | KeyCode::Right => {
                let held = &mut app.query_log.held;
                held.focus = 1 - held.focus.min(1);
            }
            KeyCode::Char('y' | 'Y') => return discard_all(app, review),
            KeyCode::Enter if app.query_log.held.focus == 1 => return discard_all(app, review),
            KeyCode::Enter => app.query_log.held.review = back,
            _ => {}
        }
        return false;
    }
    if app.query_log.held.editor.is_some() {
        editor_key(app, key);
        return false;
    }
    let can_apply = editable(app) && !app.query_log.held.targets.is_empty();
    let focus_count = if can_apply { 6 } else { 5 };
    match key.code {
        _ if is_scroll => {
            scroll(app, key.code);
            app.query_log.held.focus = 0;
        }
        KeyCode::Left | KeyCode::Right => {
            let held = &mut app.query_log.held;
            held.column = if key.code == KeyCode::Left {
                held.column.saturating_sub(1)
            } else {
                (held.column + 1).min(COLUMNS - 1)
            };
            held.focus = 0;
        }
        KeyCode::Char('e') => open_editor(app),
        KeyCode::Esc => app.query_log.held.review = None,
        KeyCode::Tab => {
            let held = &mut app.query_log.held;
            held.focus = (held.focus + 1) % focus_count;
        }
        KeyCode::BackTab => {
            let held = &mut app.query_log.held;
            held.focus = (held.focus + focus_count - 1) % focus_count;
        }
        KeyCode::Char('D') => {
            app.query_log.held.review = Some(Review::Discard);
            app.query_log.held.focus = 0;
        }
        KeyCode::Delete => remove_selected(&mut app.query_log.held),
        KeyCode::Enter => match app.query_log.held.focus {
            1 => app.query_log.held.review = None,
            2 => open_editor(app),
            3 => remove_selected(&mut app.query_log.held),
            4 => {
                app.query_log.held.review = Some(Review::Discard);
                app.query_log.held.focus = 0;
            }
            _ if !editable(app) => app.query_log.held.error = Some(READ_ONLY.into()),
            _ => review_all(app, poller).await,
        },
        _ => {}
    }
    false
}

/// `e`, Edit, or a click on the selected cell: draft that cell of the rule.
fn open_editor(app: &mut App) {
    if !editable(app) {
        app.query_log.held.error = Some(READ_ONLY.into());
        return;
    }
    let held = &app.query_log.held;
    let Some(target) = held.targets.get(held.selected_target) else {
        return;
    };
    let lists = catalog_lists(app);
    let editor = Editor {
        column: held.column,
        action: target.action,
        domain: target.domain.clone(),
        // Only the Lists picker drops a list the catalog no longer has; the
        // other cells keep it, so the hold check names the deleted list.
        lists: if held.column == 2 {
            lists
                .iter()
                .filter(|list| list.id == target.list_id)
                .map(|list| list.id.clone())
                .collect()
        } else {
            vec![target.list_id.clone()]
        },
        cursor: if held.column == 0 {
            ACTIONS
                .iter()
                .position(|(action, _)| *action == target.action)
                .unwrap_or(0)
        } else {
            lists
                .iter()
                .position(|list| list.id == target.list_id)
                .unwrap_or(0)
        },
        focus: FilterFocus::Value,
        error: None,
    };
    app.query_log.held.editor = Some(editor);
}

fn toggle(lists: &mut Vec<String>, id: &str) {
    if let Some(at) = lists.iter().position(|list| list == id) {
        lists.remove(at);
    } else {
        lists.push(id.to_owned());
    }
}

fn editor_key(app: &mut App, key: KeyEvent) {
    let ids: Vec<String> = catalog_lists(app)
        .iter()
        .map(|list| list.id.clone())
        .collect();
    let held = &mut app.query_log.held;
    let Some(editor) = held.editor.as_mut() else {
        return;
    };
    // Before the text input, which would take Enter as its own submit.
    if key.code == KeyCode::Esc
        || (key.code == KeyCode::Enter && editor.focus == FilterFocus::Discard)
    {
        held.editor = None;
        return;
    }
    if key.code == KeyCode::Enter || super::is_save_key(key) {
        return apply_edit(app);
    }
    let last = if editor.column == 0 {
        ACTIONS.len() - 1
    } else {
        ids.len().saturating_sub(1)
    };
    match key.code {
        KeyCode::Tab => editor.focus = editor.focus.next(),
        KeyCode::BackTab => editor.focus = editor.focus.prev(),
        // One value row: ↑↓ move focus, as in the Query Filters text editors.
        KeyCode::Down if editor.column == 1 => editor.focus = editor.focus.next(),
        KeyCode::Up if editor.column == 1 => editor.focus = editor.focus.prev(),
        KeyCode::Up | KeyCode::Down | KeyCode::Home | KeyCode::End if editor.column != 1 => {
            editor.focus = FilterFocus::Value;
            editor.cursor = match key.code {
                KeyCode::Up => editor.cursor.min(last).saturating_sub(1),
                KeyCode::Down => (editor.cursor + 1).min(last),
                KeyCode::Home => 0,
                _ => last,
            };
            if editor.column == 0 {
                editor.action = ACTIONS[editor.cursor].0;
                editor.error = None;
            }
        }
        KeyCode::Char(' ') if editor.column == 2 && editor.focus == FilterFocus::Value => {
            if let Some(id) = ids.get(editor.cursor) {
                toggle(&mut editor.lists, id);
                editor.error = None;
            }
        }
        _ if editor.column == 1 && editor.focus == FilterFocus::Value => {
            super::drive_text_input(&mut editor.domain, key);
            editor.error = None;
        }
        _ => {}
    }
}

/// Replace the selected rule with the draft, one rule per checked list, at
/// the same position. A refusal keeps the draft open with the reason.
fn apply_edit(app: &mut App) {
    let held = &app.query_log.held;
    let row = held.selected_target;
    let Some(editor) = held.editor.as_ref().filter(|_| row < held.targets.len()) else {
        app.query_log.held.editor = None;
        return;
    };
    let mut base = held.targets.clone();
    base.remove(row);
    // New rows follow the catalog order, whatever order lists were checked in.
    let lists = catalog_lists(app);
    let mut ids = editor.lists.clone();
    ids.sort_by_key(|id| lists.iter().position(|list| list.id == *id));
    let staged = stage(app, base, row, &editor.domain, editor.action, ids);
    let held = &mut app.query_log.held;
    match staged {
        Ok((targets, _)) => {
            held.selected_target = row.min(targets.len().saturating_sub(1));
            held.targets = targets;
            held.row_offset = 0;
            held.error = None;
            held.editor = None;
        }
        Err(error) => {
            if let Some(editor) = held.editor.as_mut() {
                editor.error = Some(error);
            }
        }
    }
}

fn discard_all(app: &mut App, review: Review) -> bool {
    let held = &mut app.query_log.held;
    held.targets.clear();
    held.review = None;
    held.error = None;
    review == Review::Quit
}

pub(crate) fn pointer_key(app: &mut App, code: KeyCode) {
    let held = &mut app.query_log.held;
    if held.review == Some(Review::Rules) && held.editor.is_none() && code == KeyCode::Enter {
        held.focus = 5;
    }
}

/// A click on a table cell selects it; a click on the cell that was already
/// selected opens its editor. With the editor open, `index` is its choice.
pub(crate) fn pointer_row(app: &mut App, index: usize) {
    if app.query_log.held.review != Some(Review::Rules) {
        return;
    }
    if app.query_log.held.editor.is_some() {
        return editor_click(app, index);
    }
    let rows = review_rows(app);
    let held = &mut app.query_log.held;
    let before = (held.selected_target, held.column);
    select_row(held, &rows, index / COLUMNS);
    held.focus = 0;
    if held.selected_target < held.targets.len() {
        held.column = index % COLUMNS;
        if (held.selected_target, held.column) == before {
            open_editor(app);
        }
    }
}

fn editor_click(app: &mut App, index: usize) {
    let id = catalog_lists(app).get(index).map(|list| list.id.clone());
    let Some(editor) = app.query_log.held.editor.as_mut() else {
        return;
    };
    editor.focus = FilterFocus::Value;
    if editor.column == 0 {
        editor.cursor = index.min(ACTIONS.len() - 1);
        editor.action = ACTIONS[editor.cursor].0;
        editor.error = None;
    } else if let Some(id) = id.filter(|_| editor.column == 2) {
        editor.cursor = index;
        toggle(&mut editor.lists, &id);
        editor.error = None;
    }
}

/// Footer legend for the review, its confirmations and its cell editors.
pub(crate) fn footer_hint(app: &App) -> &'static str {
    let held = &app.query_log.held;
    match (held.review, held.editor.as_ref().map(|editor| editor.column)) {
        (Some(Review::Rules), Some(0)) => "↑↓ choose · Tab focus · Enter apply · Esc discard",
        (Some(Review::Rules), Some(1)) => "Tab focus · Enter apply · Esc discard",
        (Some(Review::Rules), Some(_)) => {
            "↑↓ move · Space toggle · Tab focus · Enter apply · Esc discard"
        }
        (Some(Review::Rules), None)
            if editable(app) && !held.targets.is_empty() && matches!(held.focus, 0 | 5) =>
        {
            "Enter review all · e edit · ←→ cell · Tab buttons · Delete remove · D discard · Esc keep"
        }
        (Some(Review::Rules), None) => {
            "Tab buttons · Enter choose · e edit · Delete remove · D discard · Esc keep"
        }
        _ => "Tab choose · y discard · n/Esc keep",
    }
}

pub(crate) fn render(frame: &mut Frame, anchor: Rect, app: &App) {
    let Some(review) = app.query_log.held.review else {
        return;
    };
    let held = &app.query_log.held;
    let rows = review_rows(app);
    let listed = !held.targets.is_empty();
    let table = review == Review::Rules;
    // Confirmations print one explanatory line above the rule rows; when
    // rules follow it is pinned above their header, otherwise the focus row
    // and the highlight must both account for it.
    let pinned = listed && !table;
    let lead = usize::from(!table && !pinned);
    let selected = selected_row(held, &rows) + lead;
    let error = held
        .error
        .as_ref()
        .map(|_| "See the message below the rules.".to_string());
    let spec = if review == Review::Rules {
        let can_apply = editable(app) && !held.targets.is_empty();
        NoticeSpec {
            title: if held.targets.is_empty() && held.receipt.is_some() {
                "LAST QUERY LOG APPLY"
            } else {
                "HELD RULES — NOT ACTIVE YET"
            }
            .into(),
            desc: format!(
                "{} held · kept until you quit",
                rule_count(held.targets.len())
            ),
            prose: rows
                .into_iter()
                .map(|(_, line)| ProseRow::plain(line))
                .collect(),
            error,
            hint: {
                let note = if editable(app) { APPLYING } else { READ_ONLY };
                match held.targets.get(held.selected_target) {
                    Some(target) => format!(
                        "{}\n{note}",
                        super::text::fit(&list_context(app, target), TABLE_WIDTH)
                    ),
                    None => note.into(),
                }
            },
            keys: if can_apply && (held.focus == 0 || held.focus == 5) {
                "↑↓←→ cell · e edit · Delete remove · Enter review all · Esc keep"
            } else if can_apply {
                "Enter choose · Tab buttons · ↑↓←→ cell · e edit · Esc keep"
            } else if !editable(app) {
                "Read-only node · Tab buttons · ↑↓ scroll · Delete remove · Esc keep"
            } else {
                "Tab buttons · ↑↓ scroll · Esc close"
            }
            .into(),
            actions: vec![
                Action::new("Close", held.focus == 1, ActionKind::Neutral, "").on_key(KeyCode::Esc),
                Action::new("Edit", held.focus == 2, ActionKind::Neutral, "")
                    .on_key(KeyCode::Char('e')),
                Action::new("Remove", held.focus == 3, ActionKind::Neutral, "")
                    .on_key(KeyCode::Delete),
                Action::new("Discard all", held.focus == 4, ActionKind::Destructive, "")
                    .on_key(KeyCode::Char('D')),
                if can_apply {
                    Action::new("Review all", held.focus == 5, ActionKind::Primary, "")
                        .on_key(KeyCode::Enter)
                } else {
                    Action::new("Review unavailable", false, ActionKind::Neutral, "")
                },
            ],
            ..Default::default()
        }
    } else {
        // A submitted batch may still commit after quit; the journal resumes it.
        let pending = review == Review::Quit
            && app.operator_policy.as_ref().is_some_and(|dialog| {
                matches!(
                    dialog.origin,
                    super::operator_policy::PolicyOrigin::QueryBatch { .. }
                ) && dialog.apply_unresolved()
            });
        let count = rule_count(held.targets.len());
        NoticeSpec {
            title: if review == Review::Quit {
                "QUIT AND DISCARD HELD RULES?"
            } else {
                "DISCARD ALL HELD RULES?"
            }
            .into(),
            desc: if pending {
                format!("{count} held · Apply submitted, outcome unresolved")
            } else {
                format!("{count} held · not applied")
            },
            prose: std::iter::once(ProseRow::plain(if pending {
                "Quitting may not stop it; the next start resolves the outcome."
            } else {
                "Discarding drops held rules only; applied policy is unchanged."
            }))
            .chain(rows.into_iter().map(|(_, line)| ProseRow::plain(line)))
            .collect(),
            error,
            keys: "↑↓ scroll · Tab choose · y discard · n/Esc keep".into(),
            actions: vec![
                Action::new("Keep", held.focus == 0, ActionKind::Neutral, "")
                    .on_key(KeyCode::Char('n')),
                Action::new("Discard", held.focus == 1, ActionKind::Destructive, "")
                    .on_key(KeyCode::Char('y')),
            ],
            ..Default::default()
        }
    };
    let target = held.targets.get(held.selected_target).filter(|_| table);
    let rendered = modal_form::render_modal(frame, anchor, 72, |width| {
        let mut body = modal_form::notice_body(&spec, width);
        body.scrollable = true;
        if pinned {
            body.head.push(body.fields.remove(0));
        }
        if listed {
            body.head.push(Line::styled(
                super::text::pad(&cells("ACTION", "DOMAIN", "LIST").join(" "), width.into()),
                super::theme::table_heading_style(false),
            ));
        }
        if !body.fields.is_empty() {
            let row = selected.min(body.fields.len() - 1);
            body.focus_row = Some(row);
            body.fields[row] = match target {
                Some(target) => {
                    let mut spans = Vec::new();
                    for (column, cell) in cells(target.verb(), &target.domain, &target.list_id)
                        .into_iter()
                        .enumerate()
                    {
                        if column > 0 {
                            spans.push(Span::raw(" "));
                        }
                        spans.push(if column == held.column {
                            Span::styled(cell, filter_chips::chip_style(false, true))
                        } else {
                            Span::raw(cell)
                        });
                    }
                    Line::from(spans)
                }
                None => body.fields[row].clone(),
            }
            .style(super::theme::highlight_style());
        }
        (body, ())
    });
    crate::tui::mouse::close_on_outside_click();
    if !table {
        return;
    }
    let inner = rendered.inner;
    let view = rendered.view;
    let mut editing = None;
    for row in view.offset..view.offset + view.view_h {
        let mut x = inner.x;
        for (column, cell) in CELLS.into_iter().enumerate() {
            // Each cell owns its trailing gap, so every x in the row is a column.
            let rect = Rect::new(
                x,
                inner.y + (view.head_h + row - view.offset) as u16,
                cell as u16 + 1,
                1,
            )
            .intersection(inner);
            register_overlay_action(rect, MouseAction::OverlayChoice(row * COLUMNS + column));
            if row == selected && column == held.column {
                editing = Some(rect);
            }
            x += cell as u16 + 1;
        }
    }
    if let Some(editor) = held.editor.as_ref() {
        render_editor(frame, anchor, editing.unwrap_or(inner), editor, app);
    }
}

/// The cell editors reuse the Query Filters popup, rows and buttons.
fn render_editor(frame: &mut Frame, bounds: Rect, cell: Rect, editor: &Editor, app: &App) {
    let lists = catalog_lists(app);
    let (title, help, rows) = match editor.column {
        0 => (
            "Action",
            "Allow or deny the domain on this list",
            ACTIONS.len(),
        ),
        1 => ("Domain", "Rule domain; checked like a new hold", 1),
        _ => (
            "Lists",
            "Each checked list holds one rule",
            lists.len().clamp(1, 8),
        ),
    };
    let inner = filter_chips::popup(frame, bounds, cell, (64, rows as u16 + 5), title);
    let width = inner.width as usize;
    let visible = inner.height.saturating_sub(3) as usize;
    let focused = editor.focus == FilterFocus::Value;
    let row = |index: usize| Rect::new(inner.x, inner.y + index as u16, inner.width, 1);
    match editor.column {
        0 => {
            for (index, (action, label)) in ACTIONS.iter().enumerate().take(visible) {
                let checked = editor.action == *action;
                frame.render_widget(
                    Paragraph::new(format!("({}) {label}", if checked { "x" } else { " " }))
                        .style(filter_chips::chip_style(checked, checked && focused)),
                    row(index),
                );
                register_overlay_action(row(index), MouseAction::OverlayChoice(index));
            }
        }
        1 => {
            let shown = if focused {
                filter_chips::input_text(&editor.domain, inner.width)
            } else {
                super::text::fit(&editor.domain, width)
            };
            frame.render_widget(
                Paragraph::new(shown.as_str())
                    .style(filter_chips::chip_style(!editor.domain.is_empty(), focused)),
                row(0),
            );
            register_overlay_action(row(0), MouseAction::OverlayChoice(0));
            if focused {
                frame.set_cursor_position((
                    inner.x + super::text::width(&shown).saturating_sub(1) as u16,
                    inner.y,
                ));
            }
        }
        _ => {
            let cursor = editor.cursor.min(lists.len().saturating_sub(1));
            let offset = (cursor + 1).saturating_sub(visible);
            for (index, list) in lists.iter().enumerate().skip(offset).take(visible) {
                let checked = editor.lists.contains(&list.id);
                let text = format!(
                    "[{}] {} · {}",
                    if checked { "x" } else { " " },
                    list.display_name,
                    list.id
                );
                frame.render_widget(
                    Paragraph::new(super::text::fit(&text, width)).style(filter_chips::chip_style(
                        checked,
                        focused && index == cursor,
                    )),
                    row(index - offset),
                );
                register_overlay_action(row(index - offset), MouseAction::OverlayChoice(index));
            }
        }
    }
    // Two note rows: the help, or the refusal wrapped and trimmed to fit.
    let notes = match editor.error.as_deref() {
        Some(error) => {
            let mut lines = super::text::wrap(error, width).into_iter();
            let first = lines.next().unwrap_or_default();
            let rest = super::text::fit(&lines.collect::<Vec<_>>().join(" "), width);
            [first, rest].map(|line| (line, Style::default().fg(T.error)))
        }
        None => {
            [help.to_owned(), String::new()].map(|line| (line, Style::default().fg(T.text_muted)))
        }
    };
    for (index, (line, style)) in notes.into_iter().enumerate() {
        frame.render_widget(
            Paragraph::new(line).style(style),
            Rect::new(
                inner.x,
                (inner.bottom() + index as u16).saturating_sub(3),
                inner.width,
                1,
            ),
        );
    }
    filter_chips::render_actions(
        frame,
        Rect::new(inner.x, inner.bottom().saturating_sub(1), inner.width, 1),
        editor.focus,
    );
}

#[cfg(test)]
#[path = "tests/query_rule_batch_tests.rs"]
mod tests;
