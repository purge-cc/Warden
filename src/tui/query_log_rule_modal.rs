//! TUI rule picker opened from the Query Log tab. The entry surface is
//! a single `Enter` press (auto-flips Allow vs Deny based on the focused
//! row's `result` status).
//!
//! Renders a multi-select list of the operator's custom lists and sends the
//! marked rules as one atomic policy operation. The profiles that mount a
//! list decide who it filters.
//!
//! ## State machine
//!
//! ```text
//! Picking ──[space]──▶ Picking (toggle)
//!     │   ──[n]──▶ NewList ──create──▶ Picking (new list selected)
//!     │                    ──[Esc]──▶ Picking
//!     ├──[Enter], ≥1 marked──▶ Done(per-list report)
//!     └──[Esc]──▶ closed
//! ```
//!
//! ## Capture-at-render-time invariant
//!
//! When `Enter` is pressed, the keyhandler reads the highlighted row's
//! `domain` + `client` directly off the in-memory `query_log.entries`
//! slice — **NOT** by re-tailing the file. The row may scroll out
//! before the operator finishes choosing; the captured snapshot is the
//! source of truth from that moment forward.

use std::cell::Cell;

use crossterm::event::KeyCode;
use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::Frame;

use crate::cli::commands::rules::Action;
use crate::tui::custom_list_modal::CustomListModal;
use crate::tui::modal_form::{self, ActionKind, ScrollBody, TextTone};
use crate::tui::mouse::MouseAction;
use crate::tui::theme::T;

/// Map a Query Log row's `result` string to the inverse
/// rule action the operator most likely wants from a single keypress.
///
/// `BLOCKED` → `Some(Action::Allow)` (operator is whitelisting).
/// `ALLOWED` / `CACHED` / `STALE` → `Some(Action::Deny)` (blocklist).
/// `LOCAL` / `REFUSED` / `HINFO` / unknown → `None` (status is not
/// actionable from the Query Log; the Enter handler surfaces a
/// `last_error` rather than opening a modal).
///
/// `CACHED` / `STALE` are treated as `ALLOWED` for blocklist purposes:
/// both are cache-path outcomes for queries the resolver already let
/// through, so the operator's intent is identical to plain `ALLOWED`.
///
/// The `_` arm intentionally swallows any future daemon-emitted result
/// string (e.g. a hypothetical `DROPPED` for tunneling) — the new
/// status falls through to `None` and the caller surfaces the
/// "not actionable" footer message instead of opening a wrong modal.
pub fn inferred_action(result: &str) -> Option<Action> {
    match result {
        "BLOCKED" => Some(Action::Allow),
        "ALLOWED" | "CACHED" | "STALE" => Some(Action::Deny),
        _ => None,
    }
}

/// What a row says when no profile mounts its list.
pub const NOT_MOUNTED: &str = "no profile — filters nothing";

/// Refusal when Enter arrives with nothing marked. The picker opens at
/// zero selections deliberately, so this is a routine state and not an
/// operator error.
pub const NO_SELECTION: &str = "select at least one list";

/// One custom list the rule can be written into.
///
/// `mounted_on` is a snapshot of the profiles that mount the list, taken
/// when the modal opens. Its emptiness is the whole reason the field is
/// carried rather than derived at render time — a list nobody mounts
/// accepts the rule and filters nothing, and the row has to say so.
#[derive(Debug, Clone)]
pub struct ListRow {
    pub id: String,
    pub display: String,
    pub description: String,
    pub mounted_on: Vec<String>,
    pub selected: bool,
}

impl ListRow {
    pub fn new(id: String, display: String, mounted_on: Vec<String>) -> Self {
        Self {
            id,
            display,
            description: String::new(),
            mounted_on,
            selected: false,
        }
    }

    /// Attach the operator-authored description shown in the picker footer.
    pub fn with_description(mut self, description: String) -> Self {
        self.description = description;
        self
    }

    /// What the row's note states about where this list filters.
    pub fn mount_note(&self) -> String {
        if self.mounted_on.is_empty() {
            NOT_MOUNTED.to_string()
        } else {
            format!("\u{2192} profiles: {}", self.mounted_on.join(", "))
        }
    }
}

/// What the atomic rule batch did for one selected list.
///
/// `AlreadyPresent` is an **outcome**, not a failure: policy operations are
/// idempotent, and reporting a no-op as an error would send the operator
/// looking for a second line that is not there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleOutcome {
    Added,
    AlreadyPresent,
    Failed(String),
}

/// One line of the confirm's report.
#[derive(Debug, Clone)]
pub struct RuleReport {
    pub id: String,
    pub outcome: RuleOutcome,
}

/// Where the modal's state machine currently sits.
// `NewList` carries a whole form; the other two are small. Boxing the
// large variant to equalise them would add a heap alloc per keystroke for
// no measurable benefit — built once per operator action, never on a hot
// path. Mirrors `custom_list_modal::Stage`.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone)]
pub enum Stage {
    /// Mark zero or more lists. `space` toggles, Enter writes.
    Picking,
    /// The Custom Lists leaf's own add-list form, reached with `n`.
    ///
    /// The same modal the leaf opens, so an operator who has created a
    /// list once recognises it here. Its submit returns here with the new
    /// list marked.
    NewList(CustomListModal),
    /// The per-list report. Stays on screen until Enter or Escape closes it
    /// so the operator can inspect and scroll every outcome.
    Done(Vec<RuleReport>),
}

/// State bag for the modal lifecycle. Cleared (`= None`) when the
/// modal closes.
#[derive(Debug, Clone)]
pub struct QueryLogRuleModal {
    pub action: Action,
    /// Domain captured at row-render time — already non-empty (we open
    /// the modal only when the focused row carries one).
    pub domain: String,
    /// Display string of the matched device (or the source IP fallback).
    /// Surfaced in the modal for operator orientation.
    pub captured_client: String,
    pub rows: Vec<ListRow>,
    pub cursor: usize,
    /// Focus ring: list, Cancel, New List, Confirm.
    pub focus: usize,
    pub stage: Stage,
    /// First rendered result row shown by the fixed-height report viewport.
    pub report_scroll: usize,
    report_max_scroll: Cell<usize>,
    /// Why the last Enter did not write, or `None` when there is nothing
    /// to say. It replaces the two footer note rows without moving the list.
    ///
    /// Cleared by every keystroke that changes the selection: a rejection
    /// describes one selection, and a stale one contradicting what is now
    /// on screen is worse than silence.
    pub error: Option<String>,
}

impl QueryLogRuleModal {
    /// Open a fresh picker with `action` (Allow or Deny) for the given
    /// row data captured from the Query Log.
    ///
    /// **Nothing is pre-selected.** A default that writes into the wrong
    /// list is worse than one more keystroke, and the picker cannot know
    /// which list this domain belongs in.
    pub fn open(
        action: Action,
        domain: String,
        captured_client: String,
        rows: Vec<ListRow>,
    ) -> Self {
        Self {
            action,
            domain,
            captured_client,
            rows,
            cursor: 0,
            focus: 0,
            stage: Stage::Picking,
            report_scroll: 0,
            report_max_scroll: Cell::new(0),
            error: None,
        }
    }

    /// Fallible smart constructor that builds a picker pre-configured for
    /// a Query Log row. Returns `None` when the row's status is not
    /// actionable (LOCAL DNS records, REFUSED / HINFO upstream
    /// rejections, unknown future statuses); the Enter handler surfaces a
    /// `last_error` message in that case.
    ///
    /// The action is auto-flipped via [`inferred_action`] so the operator
    /// never has to pick allow vs deny manually — the row's current state
    /// determines the only sensible action.
    pub fn open_for_query_row(
        entry: &crate::ipc::protocol::QueryLogDto,
        captured_client: String,
        rows: Vec<ListRow>,
    ) -> Option<Self> {
        let action = inferred_action(&entry.result)?;
        Some(Self::open(
            action,
            entry.domain.clone(),
            captured_client,
            rows,
        ))
    }

    /// Move the cursor, wrapping. No-op outside [`Stage::Picking`] and on
    /// an empty list.
    pub fn move_cursor(&mut self, delta: i32) {
        if !matches!(self.stage, Stage::Picking) || self.rows.is_empty() {
            return;
        }
        let len = self.rows.len() as i32;
        self.cursor = (self.cursor as i32 + delta).rem_euclid(len) as usize;
        self.focus = 0;
    }

    /// Flip the focused row's mark.
    pub fn toggle(&mut self) {
        if !matches!(self.stage, Stage::Picking) {
            return;
        }
        if let Some(row) = self.rows.get_mut(self.cursor) {
            row.selected = !row.selected;
            self.error = None;
        }
        self.focus = 0;
    }

    /// Ids of every marked list, in the order they are drawn.
    pub fn selected_ids(&self) -> Vec<String> {
        self.rows
            .iter()
            .filter(|r| r.selected)
            .map(|r| r.id.clone())
            .collect()
    }

    /// Enter the add-list form.
    pub fn begin_new_list(&mut self, packs_dir: String) {
        if matches!(self.stage, Stage::Picking) {
            self.stage = Stage::NewList(CustomListModal::open_add(packs_dir));
            self.error = None;
        }
    }

    pub fn focus_next(&mut self) {
        let count = if self.rows.is_empty() { 2 } else { 4 };
        self.focus = (self.focus + 1) % count;
    }

    pub fn focus_prev(&mut self) {
        let count = if self.rows.is_empty() { 2 } else { 4 };
        self.focus = (self.focus + count - 1) % count;
    }

    /// Align an action-button click with the focus value consumed by the
    /// keyboard handler before it dispatches the button's key event.
    pub fn focus_pointer_action(&mut self, code: KeyCode) {
        if !matches!(self.stage, Stage::Picking) {
            return;
        }
        self.focus = match code {
            KeyCode::Esc => 1,
            KeyCode::Char('n' | 'N') if self.rows.is_empty() => 0,
            KeyCode::Char('n' | 'N') => 2,
            KeyCode::Enter if !self.rows.is_empty() => 3,
            _ => return,
        };
    }

    /// Leave the add-list form without creating anything.
    pub fn cancel_new_list(&mut self) {
        if matches!(self.stage, Stage::NewList(_)) {
            self.stage = Stage::Picking;
            self.error = None;
        }
    }

    /// Rebuild the row set after a create, keeping every existing mark and
    /// marking `select`.
    ///
    /// Marking the list the operator has just created **for this rule** is
    /// not a preselected default: it is the direct consequence of a
    /// gesture made inside this flow, and dropping back to zero selections
    /// after it would be the footgun, not the guard.
    pub fn adopt_lists(&mut self, rows: Vec<ListRow>, select: Option<&str>) {
        let marked: Vec<String> = self.selected_ids();
        self.rows = rows;
        for row in &mut self.rows {
            if marked.iter().any(|m| m == &row.id) || select == Some(row.id.as_str()) {
                row.selected = true;
            }
        }
        if let Some(id) = select {
            if let Some(idx) = self.rows.iter().position(|r| r.id == id) {
                self.cursor = idx;
            }
        }
        self.cursor = self.cursor.min(self.rows.len().saturating_sub(1));
        self.focus = 0;
        self.stage = Stage::Picking;
        self.error = None;
    }

    /// Record why an Enter did not write.
    pub fn note_no_selection(&mut self) {
        self.error = Some(NO_SELECTION.to_string());
    }

    /// Move to the report screen at the first result row.
    pub fn finish(&mut self, reports: Vec<RuleReport>) {
        self.report_max_scroll
            .set(report_line_count(&reports, REPORT_WRAP_WIDTH).saturating_sub(REPORT_VIEW_ROWS));
        self.stage = Stage::Done(reports);
        self.report_scroll = 0;
    }

    /// Move the result viewport by rendered rows, clamped to its last page.
    pub fn scroll_report(&mut self, delta: i32) {
        if !matches!(self.stage, Stage::Done(_)) {
            return;
        }
        let last = self.report_max_scroll.get();
        let current = self.report_scroll.min(last);
        self.report_scroll = if delta.is_negative() {
            current.saturating_sub(delta.unsigned_abs() as usize)
        } else {
            current.saturating_add(delta as usize).min(last)
        };
    }

    pub fn report_home(&mut self) {
        if matches!(self.stage, Stage::Done(_)) {
            self.report_scroll = 0;
        }
    }

    pub fn report_end(&mut self) {
        if matches!(self.stage, Stage::Done(_)) {
            self.report_scroll = self.report_max_scroll.get();
        }
    }
}

/// Title-band copy shared by the picker and its result report.
pub fn header(modal: &QueryLogRuleModal) -> String {
    let verb = match modal.action {
        Action::Allow => "ALLOW",
        Action::Deny => "DENY",
    };
    format!("Add {verb} Rule")
}

/// Fit complete graphemes into the modal's display-cell budget.
fn fit(s: &str, max: usize) -> String {
    modal_form::fit(s, max)
}

const MODAL_WIDTH: u16 = 68;
const MODAL_HEIGHT: u16 = 26;
const HEADER_HEIGHT: u16 = 3;
const PICKER_HEAD_ROWS: usize = 4;
const PICKER_TAIL_ROWS: usize = 4;
const REPORT_VIEW_ROWS: usize = 12;
const REPORT_WRAP_WIDTH: usize = 62;
const MOUNT_FALLBACK: &str = "Lists Apply Only to Their Assigned Profiles";

/// Draw the fixed-size rule picker inside the Query Log content area.
pub fn render_overlay(f: &mut Frame, anchor: Rect, modal: &QueryLogRuleModal) {
    if let Stage::NewList(inner) = &modal.stage {
        crate::tui::custom_list_modal::render_overlay(f, anchor, inner);
        return;
    }

    let width = MODAL_WIDTH.min(anchor.width.saturating_sub(4));
    let height = MODAL_HEIGHT.min(anchor.height.saturating_sub(2));
    let surface = modal_form::render_chrome_in(f, anchor, width, height, "", T.text_primary, true);
    if surface.is_empty() {
        return;
    }

    let description = if matches!(modal.stage, Stage::Done(_)) {
        "Custom List Results"
    } else {
        "Choose Custom Lists for This Rule"
    };
    let header_area = Rect::new(
        surface.x,
        surface.y,
        surface.width,
        HEADER_HEIGHT.min(surface.height),
    );
    modal_form::render_body_fixed(
        f,
        header_area,
        vec![
            modal_form::heading_band(&header(modal).to_uppercase(), surface.width, false),
            modal_form::heading_band(description, surface.width, true),
            Line::default(),
        ],
    );

    let content = Rect::new(
        surface.x.saturating_add(1),
        surface.y.saturating_add(HEADER_HEIGHT),
        surface.width.saturating_sub(2),
        surface.height.saturating_sub(HEADER_HEIGHT),
    );
    let visible = visible_rows(height);
    let (body, choice_hits) = match &modal.stage {
        Stage::Picking => picker_body(modal, content.width, content.height, visible),
        Stage::Done(reports) => (
            report_body(modal, reports, content.width, content.height),
            Vec::new(),
        ),
        Stage::NewList(_) => unreachable!("new-list stage returns before picker rendering"),
    };
    let view = modal_form::render_scroll_body(f, content, &body);
    register_choice_hits(content, &view, &choice_hits);
}

fn visible_rows(modal_height: u16) -> usize {
    (modal_height.saturating_sub(13) / 2).max(1) as usize
}

fn context_row(label: &str, value: &str, width: u16) -> Line<'static> {
    let label_width = 14usize.min(width as usize);
    let value_width = (width as usize).saturating_sub(label_width + 1);
    Line::from(vec![
        Span::styled(
            format!("{:<label_width$}", fit(label, label_width)),
            modal_form::text_style(TextTone::Secondary),
        ),
        Span::styled(
            format!(" {}", fit(value, value_width)),
            modal_form::text_style(TextTone::Primary),
        ),
    ])
}

fn section_band(label: &str, width: u16) -> Line<'static> {
    modal_form::filled_section_band(label, width, crate::tui::theme::CardRole::Summary)
}

fn picker_actions(modal: &QueryLogRuleModal) -> Vec<modal_form::Action> {
    let mut actions = vec![
        modal_form::Action::new("Cancel", modal.focus == 1, ActionKind::Neutral, "")
            .on_key(KeyCode::Esc),
        modal_form::Action::new(
            "New List",
            modal.focus == if modal.rows.is_empty() { 0 } else { 2 },
            ActionKind::Neutral,
            "",
        )
        .on_key(KeyCode::Char('n')),
    ];
    if !modal.rows.is_empty() {
        actions.push(
            modal_form::Action::new("Confirm", modal.focus == 3, ActionKind::Primary, "")
                .on_key(KeyCode::Enter),
        );
    }
    actions
}

fn action_body(actions: Vec<modal_form::Action>, width: u16) -> ScrollBody {
    ScrollBody {
        action_hits: modal_form::action_hits(&actions, width),
        field_hits: Vec::new(),
        head: Vec::new(),
        fields: Vec::new(),
        tail: Vec::new(),
        focus_row: None,
        scrollable: false,
    }
}

fn picker_body(
    modal: &QueryLogRuleModal,
    width: u16,
    height: u16,
    visible: usize,
) -> (ScrollBody, Vec<(usize, usize)>) {
    let actions = picker_actions(modal);
    let mut body = action_body(actions.clone(), width);
    let offset = modal
        .cursor
        .saturating_sub(visible.saturating_sub(1))
        .min(modal.rows.len().saturating_sub(visible));
    let compact = height < 10;

    let context = vec![
        context_row("Domain", &modal.domain, width),
        context_row("Client", &modal.captured_client, width),
        Line::default(),
        section_band("CUSTOM LISTS", width),
    ];
    if compact && modal.rows.is_empty() {
        body.fields.push(section_band("CUSTOM LISTS", width));
    } else if compact {
        body.fields.extend(context);
    } else {
        body.head.extend(context);
    }

    let mut choice_hits = Vec::new();
    if modal.rows.is_empty() {
        body.fields.push(Line::styled(
            "No Custom Lists · Press n to Create One",
            modal_form::text_style(TextTone::Secondary),
        ));
    } else {
        for (index, row) in modal.rows.iter().enumerate().skip(offset).take(visible) {
            let focused = modal.focus == 0 && modal.cursor == index;
            let field_row = body.fields.len();
            body.fields.push(modal_form::list_choice_row(
                &format!("[{}] {}", if row.selected { 'x' } else { ' ' }, row.display),
                width,
                focused,
                row.selected,
            ));
            body.fields.push(Line::styled(
                fit(
                    &if row.mounted_on.is_empty() {
                        "    No Profiles · Filters Nothing".to_string()
                    } else {
                        format!("    Profiles: {}", row.mounted_on.join(", "))
                    },
                    width as usize,
                ),
                modal_form::text_style(if row.mounted_on.is_empty() {
                    TextTone::Warning
                } else {
                    TextTone::Secondary
                }),
            ));
            choice_hits.push((index, field_row));
            if focused {
                body.focus_row = Some(field_row + 1);
            }
        }
    }

    if !compact {
        let field_budget = (height as usize).saturating_sub(PICKER_HEAD_ROWS + PICKER_TAIL_ROWS);
        body.fields
            .resize_with(field_budget.max(body.fields.len()), Line::default);
    }

    if let Some(error) = modal.error.as_deref() {
        body.tail
            .extend(modal_form::hint_or_error_rows(Some(error), "", width, 2));
    } else {
        let description = modal
            .rows
            .get(modal.cursor)
            .map(|row| row.description.as_str())
            .filter(|description| !description.is_empty())
            .unwrap_or(MOUNT_FALLBACK);
        body.tail.push(Line::styled(
            fit(description, width as usize),
            modal_form::text_style(TextTone::Muted),
        ));
        body.tail.push(Line::styled(
            format!(
                "{} Selected",
                modal.rows.iter().filter(|row| row.selected).count()
            ),
            modal_form::text_style(TextTone::Secondary),
        ));
    }
    if !compact {
        body.tail.push(Line::styled(
            if modal.rows.is_empty() {
                String::new()
            } else {
                format!(
                    "{}–{} of {} Lists",
                    offset + 1,
                    (offset + visible).min(modal.rows.len()),
                    modal.rows.len()
                )
            },
            modal_form::text_style(TextTone::Muted),
        ));
    }
    body.tail.push(modal_form::action_row(&actions, width));
    (body, choice_hits)
}

fn report_body(
    modal: &QueryLogRuleModal,
    reports: &[RuleReport],
    width: u16,
    height: u16,
) -> ScrollBody {
    let actions =
        vec![modal_form::Action::new("Close", true, ActionKind::Neutral, "").on_key(KeyCode::Esc)];
    let mut body = action_body(actions.clone(), width);
    let compact = height < 10;
    let context = [
        context_row("Domain", &modal.domain, width),
        context_row("Client", &modal.captured_client, width),
        Line::default(),
        section_band("RESULTS", width),
    ];
    body.head.extend(context);

    let lines = report_lines(reports, width);
    let field_budget = if compact {
        (height as usize).saturating_sub(body.head.len() + 1).max(1)
    } else {
        REPORT_VIEW_ROWS
    };
    modal
        .report_max_scroll
        .set(lines.len().saturating_sub(field_budget));
    let offset = modal
        .report_scroll
        .min(lines.len().saturating_sub(field_budget));
    body.fields.extend(
        lines
            .iter()
            .skip(offset)
            .take(field_budget)
            .map(|(_, line)| line.clone()),
    );
    body.fields.resize_with(field_budget, Line::default);

    let failed = reports
        .iter()
        .filter(|report| matches!(report.outcome, RuleOutcome::Failed(_)))
        .count();
    if !compact {
        let first = lines.get(offset).map(|(index, _)| index + 1);
        let last = lines
            .get((offset + field_budget).min(lines.len()).saturating_sub(1))
            .map(|(index, _)| index + 1);
        body.tail.extend([
            Line::default(),
            Line::default(),
            Line::styled(
                match (first, last) {
                    (Some(first), Some(last)) => {
                        format!(
                            "{} Lists · {failed} Failed · {first}–{last} of {}",
                            reports.len(),
                            reports.len()
                        )
                    }
                    _ => String::new(),
                },
                modal_form::text_style(TextTone::Secondary),
            ),
            Line::default(),
        ]);
    }
    body.tail.push(modal_form::action_row(&actions, width));
    body
}

fn report_line_count(reports: &[RuleReport], message_width: usize) -> usize {
    reports
        .iter()
        .map(|report| {
            1 + crate::tui::text::wrap(report_message(&report.outcome), message_width).len()
        })
        .sum()
}

fn report_message(outcome: &RuleOutcome) -> &str {
    match outcome {
        RuleOutcome::Added => "Rule Added",
        RuleOutcome::AlreadyPresent => "Already Present",
        RuleOutcome::Failed(message) => message,
    }
}

fn report_lines(reports: &[RuleReport], width: u16) -> Vec<(usize, Line<'static>)> {
    let mut lines = Vec::new();
    for (index, report) in reports.iter().enumerate() {
        lines.push((
            index,
            Line::styled(
                fit(&report.id, width as usize),
                modal_form::text_style(TextTone::Primary),
            ),
        ));
        let tone = match &report.outcome {
            RuleOutcome::Added => TextTone::Success,
            RuleOutcome::AlreadyPresent => TextTone::Secondary,
            RuleOutcome::Failed(_) => TextTone::Error,
        };
        let message_width = (width as usize).saturating_sub(2).max(1);
        let wrapped = crate::tui::text::wrap(report_message(&report.outcome), message_width);
        if wrapped.is_empty() {
            lines.push((index, Line::default()));
        } else {
            lines.extend(wrapped.into_iter().map(|row| {
                (
                    index,
                    Line::styled(format!("  {row}"), modal_form::text_style(tone)),
                )
            }));
        }
    }
    lines
}

fn register_choice_hits(content: Rect, view: &modal_form::ScrollView, hits: &[(usize, usize)]) {
    let viewport = Rect::new(
        content.x,
        content.y.saturating_add(view.head_h as u16),
        content.width,
        view.view_h as u16,
    );
    for &(index, row) in hits {
        let first_visible = row.max(view.offset);
        let after_visible = (row + 2).min(view.offset + view.view_h);
        if first_visible >= after_visible {
            continue;
        }
        let y = content
            .y
            .saturating_add(view.head_h as u16)
            .saturating_add((first_visible - view.offset) as u16);
        crate::tui::mouse::register_overlay_action(
            Rect::new(
                content.x,
                y,
                content.width,
                (after_visible - first_visible) as u16,
            )
            .intersection(viewport),
            MouseAction::OverlayChoice(index),
        );
    }
}

#[cfg(test)]
#[path = "tests/query_log_rule_modal_tests.rs"]
mod tests;
