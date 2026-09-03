//! TUI rule picker opened from the Query Log tab. The entry surface is
//! a single `Enter` press (auto-flips Allow vs Deny based on the focused
//! row's `result` status).
//!
//! Renders a multi-select list of the operator's custom lists and writes
//! the rule into every list they mark, through `config::custom_list`'s
//! `add_rule` — the same pack writers the Custom Lists leaf uses. No new
//! IPC verbs, and no `[[admin_rules]]`: the rule lands in a file the
//! operator owns, and the profiles that mount it decide who it filters.
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

use ratatui::layout::Rect;
use ratatui::Frame;

use crate::cli::commands::rules::Action;
use crate::tui::custom_list_modal::CustomListModal;
use crate::tui::modal_form::{
    self, ActionKind, ChoiceNote, ChoiceRow, NoticeSpec, ProseRow, ValueKind,
};

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

/// The explanatory note under the picker, **pre-split at word
/// boundaries**, one row per entry.
///
/// A custom list only filters the profiles it is mounted on, and the
/// picker is the moment the operator commits to one — so the modal says
/// where the mount happens rather than leaving them to find out that the
/// rule they just wrote changes nothing.
///
/// The split is the author's, not the renderer's. The Archetype-C body
/// has exactly one wrapping path — a `ProseRow::verbatim` — and that wrap
/// is a hard **character** chunk by design, because its job is to
/// reproduce a transcription target keystroke for keystroke. Prose is not
/// a transcription target: run through it, this note breaks mid-word
/// (`on. M` / `ount it from`). An ordinary `ProseRow` does not wrap at
/// all and is ellipsised instead. So a note that must read as prose has
/// to arrive already broken where a reader would break it — the same
/// shape the empty state uses below.
///
/// Every entry stays inside the interior a `ProseRow` is fitted to, which
/// is the modal's own width minus the chrome, the scrollbar column and
/// the 2-cell indent. `every_frozen_row_reaches_the_screen_whole` is what
/// keeps that true when the copy changes.
pub const MOUNT_NOTE_ROWS: [&str; 3] = [
    "A custom list only filters the profiles it is mounted on.",
    "Mount it from Filters → Profiles, or with [m] on",
    "Filters → Custom Lists.",
];

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
    pub mounted_on: Vec<String>,
    pub selected: bool,
}

impl ListRow {
    pub fn new(id: String, display: String, mounted_on: Vec<String>) -> Self {
        Self {
            id,
            display,
            mounted_on,
            selected: false,
        }
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

/// What one `add_rule` did, per list.
///
/// `AlreadyPresent` is an **outcome**, not a failure: the pack writers are
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
    /// list once recognises it here. Its submit runs the leaf's create
    /// path — the pack file first, then the declaration — and returns
    /// here with the new list marked.
    NewList(CustomListModal),
    /// The per-list report. Stays on screen until a key closes it: a
    /// partial write is exactly the case a single toast cannot state.
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
    pub stage: Stage,
    /// Why the last Enter did not write, or `None` when there is nothing
    /// to say. Rides the [`NoticeSpec::error`] slot, which displaces the
    /// hint — so it costs no row and cannot push the list off screen.
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
            stage: Stage::Picking,
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
        self.stage = Stage::Picking;
        self.error = None;
    }

    /// Record why an Enter did not write.
    pub fn note_no_selection(&mut self) {
        self.error = Some(NO_SELECTION.to_string());
    }

    /// Move to the report screen — the caller closes it on the next
    /// keypress.
    pub fn finish(&mut self, reports: Vec<RuleReport>) {
        self.stage = Stage::Done(reports);
    }
}

/// Title-band copy. Names the action and the domain, and is deliberately
/// the **same on every stage**: the create form and the report are steps
/// inside one flow about one domain, so a title that changed under the
/// operator would cost them their orientation rather than give them
/// information.
pub fn header(modal: &QueryLogRuleModal) -> String {
    let verb = match modal.action {
        Action::Allow => "ALLOW",
        Action::Deny => "DENY",
    };
    format!("Add {verb} for  {domain}", domain = modal.domain)
}

/// Truncate `s` to at most `max` columns, appending `…` when clipped.
/// Char-aware (counts scalar values, not bytes) so multi-byte ids do
/// not panic on a byte boundary. Keeps every row within the modal width.
fn fit(s: &str, max: usize) -> String {
    let n = s.chars().count();
    if n <= max {
        return s.to_string();
    }
    if max == 0 {
        return String::new();
    }
    let mut out: String = s.chars().take(max - 1).collect();
    out.push('…');
    out
}

// ── render (Archetype C via `modal_form`) ──────────────────────────────
//
// Every span in this module comes out of `modal_form`; not one colour is
// chosen here. That is deliberate rather than an aesthetic preference —
// the ecosystem colour rule has exactly one implementation, so every
// modal surface cannot drift apart. Pinned by
// `no_hand_rolled_colour_in_this_module` below.

/// Modal width, shared with the ecosystem's other Archetype-C overlays.
/// The *height* is derived by [`modal_form::render_modal`] from the body
/// it is handed and clamped to the anchor.
const MODAL_W: u16 = 64;

/// Two spaces between clusters, not the ecosystem's three: at three the
/// line runs 62 cells against an interior that is 59 once the chrome, the
/// scrollbar column and the lead indent are taken, and `nav_keys_line`
/// does not truncate — the row is simply clipped by the frame, so the
/// last key loses its name and nothing says it was cut.
const KEYS_PICK: &str = "[space] select  [n] new list  [Enter] confirm  [Esc] cancel";
const KEYS_EMPTY: &str = "[n] new list   [Esc] cancel";
const KEYS_DONE: &str = "[any key] close";

/// Draw the picker as an Archetype-C overlay anchored on the tab content
/// rect.
///
/// `anchor` is the tab content area, never `f.area()`: the header, the
/// menu card and the footer legend stay visible behind the modal.
///
/// The create form is drawn by the Custom Lists modal itself, so the two
/// routes to it cannot drift into looking different.
pub fn render_overlay(f: &mut Frame, anchor: Rect, modal: &QueryLogRuleModal) {
    if let Stage::NewList(inner) = &modal.stage {
        crate::tui::custom_list_modal::render_overlay(f, anchor, inner);
        return;
    }
    modal_form::render_modal(f, anchor, MODAL_W, |w| (body(modal, w), ()));
}

/// The picker body: the Archetype-C notice, plus the mount note appended
/// **below** the options.
///
/// Appending rather than passing the note as `NoticeSpec::prose`, which
/// [`modal_form::notice_body`] places *above* the options: at the minimum
/// terminal the note would then take the top of the scrolling region and
/// the operator would have to scroll to reach the lists they came to
/// pick.
fn body(modal: &QueryLogRuleModal, width: u16) -> modal_form::ScrollBody {
    let mut b = modal_form::notice_body(&notice(modal, width), width);
    if matches!(modal.stage, Stage::Picking) {
        b.fields.push(ratatui::text::Line::from(""));
        // One row per pre-split line. `prose_rows` is still the call —
        // it is the row vocabulary of this body — but the break points
        // are [`MOUNT_NOTE_ROWS`]', because the only wrapping it offers
        // breaks mid-word.
        for row in MOUNT_NOTE_ROWS {
            b.fields
                .extend(modal_form::prose_rows(&ProseRow::plain(row), width));
        }
    }
    b
}

/// The current stage as an Archetype-C [`NoticeSpec`].
///
/// `width` is the resolved inner width, which
/// [`modal_form::render_modal`] may lower by one column once it knows the
/// body scrolls. It only ever changes how far a string is truncated,
/// never how many rows the body has — a width-dependent row count would
/// silently mis-size the modal between the two build passes.
fn notice(modal: &QueryLogRuleModal, width: u16) -> NoticeSpec {
    match &modal.stage {
        Stage::Done(reports) => report_notice(modal, reports),
        // The create form draws itself; this arm is unreachable from
        // `render_overlay` and exists so the match is total.
        Stage::NewList(_) | Stage::Picking => pick_notice(modal, width),
    }
}

/// The list picker.
///
/// Every row states where its list is mounted on an indented row of its
/// own ([`ChoiceNote`]), never inline: a picker exists so its options can
/// be compared *before* the cursor reaches them, and the inline slot is
/// ellipsised at the interior width while the note row is not.
///
/// A list nobody mounts is [`ChoiceNote::Detail`], **not** `Blocked`:
/// writing into it is legal and sometimes exactly right — it is the
/// staging list — so the row says what will happen and stays choosable.
fn pick_notice(modal: &QueryLogRuleModal, width: u16) -> NoticeSpec {
    if modal.rows.is_empty() {
        return NoticeSpec {
            hint_rows: None,
            title: header(modal),
            desc: "no custom lists declared".to_string(),
            prose: vec![
                ProseRow::plain("an exception rule lives in a custom list:"),
                ProseRow::plain("a file you write yourself, mounted on the profiles you choose."),
            ],
            choices: Vec::new(),
            error: modal.error.clone(),
            hint: "create one and the rule goes into it".to_string(),
            keys: KEYS_EMPTY.to_string(),
            actions: vec![
                modal_form::Action::new("  Cancel  ", false, ActionKind::Neutral, ""),
                modal_form::Action::new("  [n] New list  ", false, ActionKind::Primary, ""),
            ],
        };
    }

    // Keep `choice_rows`' 2-cell lead and its trailing focus marker out
    // of the label's budget: a label built to the full width would push
    // the marker off the row.
    let label_avail = (width as usize).saturating_sub(4);
    let choices = modal
        .rows
        .iter()
        .enumerate()
        .map(|(idx, row)| ChoiceRow {
            label: fit(
                &format!("[{}] {}", if row.selected { 'x' } else { ' ' }, row.display),
                label_avail,
            ),
            // The mount state is the note row. Setting it inline as well
            // would print it twice, once truncated.
            detail: None,
            note: Some(ChoiceNote::Detail(row.mount_note())),
            // What writing here would mean: a mounted list filters
            // somebody, an unmounted one accepts the rule and changes
            // nothing until it is mounted.
            kind: if row.mounted_on.is_empty() {
                ValueKind::Caution
            } else {
                ValueKind::Healthy
            },
            focused: idx == modal.cursor,
        })
        .collect();

    NoticeSpec {
        // Left at the default so a refusal has rows to land in. Pinning
        // it low buys content rows and silently swallows the error —
        // `hint_or_error_rows` emits nothing at all for a zero budget.
        hint_rows: None,
        title: header(modal),
        desc: format!("which lists? \u{b7} {}", modal.captured_client),
        prose: Vec::new(),
        choices,
        error: modal.error.clone(),
        // Always present, so the tail keeps a fixed height and an error
        // replaces the hint instead of reflowing the body under the
        // operator's cursor.
        //
        // It names the movement keys because the key legend does not:
        // bound-and-unadvertised is the same wound as advertised-and-
        // unbound, facing the other way.
        hint: "\u{2191}/\u{2193} or j/k move \u{b7} the rule is written to every list you mark"
            .to_string(),
        keys: KEYS_PICK.to_string(),
        actions: vec![
            modal_form::Action::new("  Cancel  ", false, ActionKind::Neutral, ""),
            modal_form::Action::new("  Confirm  ", false, ActionKind::Primary, ""),
        ],
    }
}

/// The per-list report.
///
/// One row per list, and the list id **first** on every one: the rows are
/// ellipsised, so leading with the id means a long refusal loses its tail
/// rather than its identity, and the operator can still tell which list
/// refused.
fn report_notice(modal: &QueryLogRuleModal, reports: &[RuleReport]) -> NoticeSpec {
    let failed = reports
        .iter()
        .filter(|r| matches!(r.outcome, RuleOutcome::Failed(_)))
        .count();
    let prose = reports
        .iter()
        .map(|r| match &r.outcome {
            RuleOutcome::Added => {
                ProseRow::emphasis(format!("{}: rule added", r.id), ValueKind::Healthy)
            }
            RuleOutcome::AlreadyPresent => ProseRow::plain(format!("{}: already present", r.id)),
            RuleOutcome::Failed(msg) => {
                ProseRow::emphasis(format!("{}: {msg}", r.id), ValueKind::Blocking)
            }
        })
        .collect();
    NoticeSpec {
        hint_rows: None,
        title: header(modal),
        desc: if failed == 0 {
            "written to every list you marked".to_string()
        } else {
            format!("{failed} of {} lists did not accept it", reports.len())
        },
        prose,
        choices: Vec::new(),
        error: None,
        hint: String::new(),
        keys: KEYS_DONE.to_string(),
        actions: vec![modal_form::Action::new(
            "  Close  ",
            false,
            ActionKind::Primary,
            "",
        )],
    }
}

#[cfg(test)]
#[path = "tests/query_log_rule_modal_tests.rs"]
mod tests;
