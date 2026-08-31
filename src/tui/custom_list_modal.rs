//! Custom Lists tab modals.
//!
//! Opens over [`crate::tui::app::Leaf::CustomLists`].
//!
//! ## The mount picker
//!
//! `m` answers the half of the operator's complaint the list pane cannot:
//! *"in the profile I see no way to attach the custom list"*. Mounting is
//! the gesture that makes a list filter anything at all — an unmounted
//! list is inert however many rules it holds — and until now the only way
//! to perform it was editing the TOML over ssh.
//!
//! ### Why it stages, instead of writing on each keypress
//!
//! Every toggle is held in memory until `Enter`. Writing per keypress
//! would mean one validated write and one daemon reload per profile, so
//! mounting a list on three profiles would reload three times and could
//! stop half-way with the operator's intent partly applied. `Esc` also
//! has to mean something: with per-keypress writes there is nothing left
//! to discard.
//!
//! ### Why the rows carry two booleans
//!
//! `mounted` is what the file said when the picker opened; `staged` is
//! what the operator has asked for. Only the profiles where they differ
//! are written, so a save touches no profile the operator did not point
//! at — which matters because the write is a read-modify-write of a live
//! `[profiles.<id>]` table.

use crate::config::schema::CustomList;

/// Multi-select over the profiles a custom list can be mounted on.
#[derive(Debug, Clone)]
pub struct MountPicker {
    /// The list being mounted. Captured at open: later reloads cannot
    /// retarget a picker the operator is already looking at.
    pub list_id: String,
    pub list_display: String,
    /// One row per declared profile, in config order.
    pub rows: Vec<MountRow>,
    pub cursor: usize,
    pub error: Option<String>,
    /// Set once the save has run; the picker renders the outcome and
    /// closes on the next keypress.
    pub outcome: Option<String>,
    /// Whether [`Self::outcome`] is a failure.
    pub failed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountRow {
    pub profile: String,
    /// What the config said at open time.
    pub mounted: bool,
    /// What the operator has staged.
    pub staged: bool,
}

impl MountRow {
    pub fn changed(&self) -> bool {
        self.mounted != self.staged
    }
}

impl MountPicker {
    pub fn open(entity: &CustomList, profiles: Vec<(String, bool)>) -> Self {
        let rows: Vec<MountRow> = profiles
            .into_iter()
            .map(|(profile, mounted)| MountRow {
                profile,
                mounted,
                staged: mounted,
            })
            .collect();
        // Land on the first profile that already mounts the list when
        // there is one: the operator opening `m` on a mounted list is
        // usually there to unmount it.
        let cursor = rows.iter().position(|r| r.mounted).unwrap_or(0);
        Self {
            list_id: entity.id.as_str().to_string(),
            list_display: if entity.display_name.is_empty() {
                entity.id.as_str().to_string()
            } else {
                entity.display_name.clone()
            },
            rows,
            cursor,
            error: None,
            outcome: None,
            failed: false,
        }
    }

    pub fn toggle(&mut self) {
        if let Some(row) = self.rows.get_mut(self.cursor) {
            row.staged = !row.staged;
            self.error = None;
        }
    }

    pub fn step(&mut self, forward: bool) {
        if self.rows.is_empty() {
            return;
        }
        let last = self.rows.len() - 1;
        self.cursor = if forward {
            (self.cursor + 1).min(last)
        } else {
            self.cursor.saturating_sub(1)
        };
    }

    /// Profiles whose mount state the operator changed, and what to.
    pub fn changes(&self) -> Vec<(&str, bool)> {
        self.rows
            .iter()
            .filter(|r| r.changed())
            .map(|r| (r.profile.as_str(), r.staged))
            .collect()
    }

    pub fn is_done(&self) -> bool {
        self.outcome.is_some()
    }
}

// ── Add / Edit / Remove ──────────────────────────────────────────────

/// Top-level modal lifecycle for the three list verbs.
#[derive(Debug, Clone)]
pub struct CustomListModal {
    pub stage: Stage,
}

// `EditingForm` carries the whole form; the other two are small. Boxing the
// large variant to equalise them would add a heap alloc and a deref per
// keystroke for no measurable benefit — built once per operator action,
// never on a hot path. Mirrors `LabelModal`.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone)]
pub enum Stage {
    EditingForm(Form),
    /// Typed-id removal gate.
    ConfirmingRemove(RemoveConfirm),
    /// Add one rule to the selected list's pack.
    AddingRule(RuleForm),
    /// Confirm dropping a rule. Single-key, and the body states that the
    /// removal is bidirectional.
    ConfirmingRuleRemove(RuleRemoveConfirm),
    /// Renders the outcome and closes on the next keypress.
    Submitted(SubmitOutcome),
}

#[derive(Debug, Clone)]
pub enum SubmitOutcome {
    Ok(String),
    Failed(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormMode {
    Add,
    Edit,
}

/// Editable fields, in tab order.
///
/// **The file path is deliberately absent.** A variant here is something the
/// operator can tab to and change; the path is derived from the id and
/// neither.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormField {
    Id,
    DisplayName,
    Description,
    Submit,
    Cancel,
}

impl FormField {
    pub const ALL: [FormField; 5] = [
        FormField::Id,
        FormField::DisplayName,
        FormField::Description,
        FormField::Submit,
        FormField::Cancel,
    ];

    pub fn next(self) -> Self {
        let i = Self::ALL.iter().position(|&f| f == self).unwrap_or(0);
        Self::ALL[(i + 1) % Self::ALL.len()]
    }

    pub fn prev(self) -> Self {
        let i = Self::ALL.iter().position(|&f| f == self).unwrap_or(0);
        Self::ALL[(i + Self::ALL.len() - 1) % Self::ALL.len()]
    }
}

#[derive(Debug, Clone)]
pub struct Form {
    pub mode: FormMode,
    pub original: Option<OriginalSnapshot>,
    pub focused: FormField,
    pub id: String,
    pub display_name: String,
    pub description: String,
    /// Directory the pack lands in, captured at open so the form can show
    /// the derived path while the id is still being typed.
    pub packs_dir: String,
    pub error_message: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OriginalSnapshot {
    pub id: String,
    pub display_name: String,
    pub description: String,
}

#[derive(Debug, Clone)]
pub struct RemoveConfirm {
    pub id: String,
    pub display_name: String,
    /// Profiles that mount it, captured at open.
    ///
    /// Load-bearing rather than decorative: non-empty REFUSES the removal,
    /// and naming them is what makes the refusal actionable — the operator
    /// unmounts with `m` and comes back.
    pub mounted_on: Vec<String>,
    pub rules: usize,
    /// What the operator has typed. Only an exact match on `id` commits.
    pub typed: String,
}

impl RemoveConfirm {
    pub fn confirmed(&self) -> bool {
        self.typed == self.id
    }

    pub fn is_refused(&self) -> bool {
        !self.mounted_on.is_empty()
    }
}

/// Fields of the add-rule form, in tab order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleField {
    Domain,
    Direction,
    Submit,
    Cancel,
}

impl RuleField {
    pub const ALL: [RuleField; 4] = [
        RuleField::Domain,
        RuleField::Direction,
        RuleField::Submit,
        RuleField::Cancel,
    ];

    pub fn next(self) -> Self {
        let i = Self::ALL.iter().position(|&f| f == self).unwrap_or(0);
        Self::ALL[(i + 1) % Self::ALL.len()]
    }

    pub fn prev(self) -> Self {
        let i = Self::ALL.iter().position(|&f| f == self).unwrap_or(0);
        Self::ALL[(i + Self::ALL.len() - 1) % Self::ALL.len()]
    }
}

/// Add one rule to a pack.
///
/// **There is no edit-in-place counterpart, and the reason is the writer.**
/// `add_rule` appends, so changing a rule's domain would have to be a
/// remove followed by an add — which tears the rule out of the section its
/// comment heading describes and drops it at the end of the file under an
/// unrelated one. That is the same argument that keeps a direction-invert
/// key out, and it holds until a writer exists that substitutes in place.
#[derive(Debug, Clone)]
pub struct RuleForm {
    pub list_id: String,
    pub domain: String,
    /// `true` writes `@@||domain^`, `false` writes `||domain^`.
    pub allow: bool,
    pub focused: RuleField,
    pub error_message: Option<String>,
}

impl RuleForm {
    /// Opens on **deny**, which is what a filter is for. An operator adding
    /// an exception has one more keystroke; an operator who wanted a block
    /// and did not look does not get an exemption by accident.
    pub fn new(list_id: String) -> Self {
        Self {
            list_id,
            domain: String::new(),
            allow: false,
            focused: RuleField::Domain,
            error_message: None,
        }
    }

    pub fn direction_label(&self) -> &'static str {
        if self.allow {
            "allow"
        } else {
            "deny"
        }
    }

    /// The line this form would append, for the preview row.
    ///
    /// Rendered from the same two components `compose_line` uses, so the
    /// operator sees the exact syntax before committing to it.
    pub fn line_preview(&self) -> String {
        let d = self.domain.trim();
        let d = if d.is_empty() { "<domain>" } else { d };
        if self.allow {
            format!("@@||{d}^")
        } else {
            format!("||{d}^")
        }
    }
}

/// Confirm dropping a rule.
#[derive(Debug, Clone)]
pub struct RuleRemoveConfirm {
    pub list_id: String,
    pub domain: String,
    /// Every file line that names this domain, in file order.
    ///
    /// **`remove_rule` matches on the domain alone and takes BOTH
    /// directions**, so a domain present as an allow and as a deny loses
    /// two lines to one keystroke. The row under the cursor shows one of
    /// them and nothing on it hints at the other, so the confirm counts
    /// them and says so.
    pub affected: Vec<(usize, String)>,
}

impl RuleRemoveConfirm {
    pub fn takes_more_than_one_line(&self) -> bool {
        self.affected.len() > 1
    }
}

impl Form {
    pub fn new_add(packs_dir: String) -> Self {
        Self {
            mode: FormMode::Add,
            original: None,
            focused: FormField::Id,
            id: String::new(),
            display_name: String::new(),
            description: String::new(),
            packs_dir,
            error_message: None,
        }
    }

    pub fn new_edit(entity: &CustomList, packs_dir: String) -> Self {
        Self {
            mode: FormMode::Edit,
            original: Some(OriginalSnapshot {
                id: entity.id.as_str().to_string(),
                display_name: entity.display_name.clone(),
                description: entity.description.clone(),
            }),
            // The id is immutable once created: it names the file.
            focused: FormField::DisplayName,
            id: entity.id.as_str().to_string(),
            display_name: entity.display_name.clone(),
            description: entity.description.clone(),
            packs_dir,
            error_message: None,
        }
    }

    /// The file this list is backed by.
    ///
    /// Recomputed from the buffer rather than stored, so on Add it follows
    /// the id as it is typed — which is the point: the operator sees that
    /// the id *is* the path before committing to one.
    pub fn pack_path_preview(&self) -> String {
        let id = self.id.trim();
        if id.is_empty() {
            format!("{}/<id>.txt", self.packs_dir)
        } else {
            format!("{}/{id}.txt", self.packs_dir)
        }
    }

    /// Pre-flights only what needs no filesystem access.
    ///
    /// The charset gate (`Id::new`) is **not** duplicated here — the submit
    /// path runs it and names the field, and a second copy is a second place
    /// for the two to disagree. What this owes the operator instead is that
    /// the constraint be visible before Save, which is [`field_hint`]'s job.
    pub fn try_resolve(&self) -> Result<ResolvedForm, String> {
        let id = self.id.trim();
        if id.is_empty() {
            return Err("id is required".into());
        }
        let display = self.display_name.trim();
        Ok(ResolvedForm {
            id: id.to_string(),
            // A blank display name stores the id, so two surfaces cannot
            // produce different rows from the same input.
            display_name: if display.is_empty() {
                id.to_string()
            } else {
                display.to_string()
            },
            description: self.description.trim().to_string(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedForm {
    pub id: String,
    pub display_name: String,
    pub description: String,
}

impl CustomListModal {
    pub fn open_add(packs_dir: String) -> Self {
        Self {
            stage: Stage::EditingForm(Form::new_add(packs_dir)),
        }
    }

    pub fn open_edit(entity: &CustomList, packs_dir: String) -> Self {
        Self {
            stage: Stage::EditingForm(Form::new_edit(entity, packs_dir)),
        }
    }

    pub fn open_remove(entity: &CustomList, mounted_on: Vec<String>, rules: usize) -> Self {
        Self {
            stage: Stage::ConfirmingRemove(RemoveConfirm {
                id: entity.id.as_str().to_string(),
                display_name: entity.display_name.clone(),
                mounted_on,
                rules,
                typed: String::new(),
            }),
        }
    }

    pub fn open_add_rule(list_id: String) -> Self {
        Self {
            stage: Stage::AddingRule(RuleForm::new(list_id)),
        }
    }

    pub fn open_remove_rule(
        list_id: String,
        domain: String,
        affected: Vec<(usize, String)>,
    ) -> Self {
        Self {
            stage: Stage::ConfirmingRuleRemove(RuleRemoveConfirm {
                list_id,
                domain,
                affected,
            }),
        }
    }

    pub fn finish(&mut self, outcome: SubmitOutcome) {
        self.stage = Stage::Submitted(outcome);
    }

    pub fn is_submitted(&self) -> bool {
        matches!(self.stage, Stage::Submitted(_))
    }
}

// ── Render (Archetype C via `modal_form`) ────────────────────────────

use ratatui::layout::Rect;
use ratatui::Frame;

use crate::tui::modal_form::{
    self, Action, ActionKind, ChoiceRow, NoticeSpec, ProseRow, ValueKind,
};

/// Drawn when no profile is declared at all.
///
/// Not an error: a config can legitimately have none, and the remedy is on
/// another leaf.
pub const NO_PROFILES: &str = "no profiles are declared — create one on the Profiles tab.";

/// Anchored on the tab content rect, never `f.area()`, so the header, the
/// sub-tab strip and the footer stay visible behind it.
pub fn render_mount_picker(f: &mut Frame, anchor: Rect, picker: &MountPicker) {
    const W: u16 = 64;
    let spec = mount_spec(picker);
    modal_form::render_modal(f, anchor, W, |w| (modal_form::notice_body(&spec, w), ()));
}

fn mount_spec(picker: &MountPicker) -> NoticeSpec {
    if let Some(outcome) = picker.outcome.as_deref() {
        return NoticeSpec {
            hint_rows: None,
            title: if picker.failed {
                "Mount failed".to_string()
            } else {
                "Mounted".to_string()
            },
            desc: picker.list_id.clone(),
            prose: if picker.failed {
                Vec::new()
            } else {
                vec![ProseRow::plain(outcome.to_string())]
            },
            choices: Vec::new(),
            // A failure hard-wraps in the error slot; prose truncates.
            error: picker.failed.then(|| outcome.to_string()),
            hint: String::new(),
            keys: "any key closes".to_string(),
            actions: Vec::new(),
        };
    }

    if picker.rows.is_empty() {
        return NoticeSpec {
            hint_rows: None,
            title: format!("Mount {}", picker.list_id),
            desc: "nothing to mount it on".to_string(),
            prose: vec![ProseRow::plain(NO_PROFILES.to_string())],
            choices: Vec::new(),
            error: None,
            hint: String::new(),
            keys: "[Esc] close".to_string(),
            actions: vec![Action::new(
                "  [Esc] Close  ",
                false,
                ActionKind::Neutral,
                "",
            )],
        };
    }

    let choices: Vec<ChoiceRow> = picker
        .rows
        .iter()
        .enumerate()
        .map(|(i, r)| {
            // The tick is a GLYPH and not a colour: a `TestBackend` buffer
            // read back through `to_string()` discards every style, so a
            // colour-coded selection is invisible to the test meant to
            // prove it is drawn.
            let mark = if r.staged { "[x]" } else { "[ ]" };
            ChoiceRow {
                label: format!("{mark} {}", r.profile),
                // Says what changing this row will DO, which the tick
                // alone cannot: a ticked row that was already ticked
                // writes nothing.
                detail: r.changed().then(|| {
                    if r.staged {
                        "will mount".to_string()
                    } else {
                        "will unmount".to_string()
                    }
                }),
                kind: if r.staged {
                    ValueKind::Editable
                } else {
                    ValueKind::Identity
                },
                focused: i == picker.cursor,
                note: None,
            }
        })
        .collect();

    let staged = picker.changes().len();
    NoticeSpec {
        hint_rows: None,
        title: format!("Mount {}", picker.list_display),
        desc: "which profiles filter with this list".to_string(),
        prose: vec![ProseRow::emphasis(
            picker.list_id.clone(),
            ValueKind::Identity,
        )],
        choices,
        error: picker.error.clone(),
        hint: if staged == 0 {
            "nothing staged — Enter writes nothing".to_string()
        } else {
            format!("{staged} profile(s) will be rewritten on Enter")
        },
        keys: "[Space] toggle   [Enter] save   [Esc] discard".to_string(),
        actions: vec![
            Action::new("  [Esc] Discard  ", false, ActionKind::Neutral, ""),
            Action::new("  [Enter] Save  ", false, ActionKind::Primary, ""),
        ],
    }
}

/// Nav-key legend copy — byte-identical to the Labels and Groups modals'.
const KEYS: &str = "\u{21b9}/\u{2191}\u{2193} move";

/// Index of the typed-input row within [`remove_notice`]'s prose.
const TYPED_PROSE_IDX: usize = 3;

/// Draw the Add / Edit / Remove modal over the tab content rect.
pub fn render_overlay(f: &mut Frame, anchor: Rect, modal: &CustomListModal) {
    const W: u16 = 64;
    match &modal.stage {
        Stage::EditingForm(form) => {
            let render = modal_form::render_modal(f, anchor, W, |w| form_body(form, w));
            if let Some((row, caret)) = render.cursor {
                render.place_cursor(f, row, modal_form::VALUE_COL as u16 + caret);
            }
        }
        Stage::ConfirmingRemove(rc) => {
            let spec = remove_notice(rc);
            // The typed row hosts the real cursor. Its field-region index is
            // DERIVED, never counted by hand: an earlier verbatim row wraps
            // and the ordinal stops matching the rendered row.
            let idx = modal_form::prose_field_row(&spec.prose, TYPED_PROSE_IDX);
            let render =
                modal_form::render_modal(f, anchor, W, |w| (modal_form::notice_body(&spec, w), ()));
            if !rc.is_refused() {
                render.place_cursor(f, idx, 2 + rc.typed.chars().count() as u16);
            }
        }
        Stage::AddingRule(form) => {
            let render = modal_form::render_modal(f, anchor, W, |w| rule_body(form, w));
            if let Some((row, caret)) = render.cursor {
                render.place_cursor(f, row, modal_form::VALUE_COL as u16 + caret);
            }
        }
        Stage::ConfirmingRuleRemove(rc) => {
            let spec = rule_remove_notice(rc);
            modal_form::render_modal(f, anchor, W, |w| (modal_form::notice_body(&spec, w), ()));
        }
        Stage::Submitted(outcome) => {
            let spec = outcome_notice(outcome);
            modal_form::render_modal(f, anchor, W, |w| (modal_form::notice_body(&spec, w), ()));
        }
    }
}

fn rule_body(form: &RuleForm, width: u16) -> (modal_form::ScrollBody, Option<(usize, u16)>) {
    let focus = form.focused;
    let title = format!("Add rule \u{00b7} {}", form.list_id);
    let mut rows = modal_form::FormRows::new(&title, "one domain, one direction", width);

    rows.section("Rule");
    let d = focus == RuleField::Domain;
    rows.text_field(
        modal_form::value_row(
            "domain",
            &form.domain,
            d,
            ValueKind::Identity,
            Some("e.g. tracking.example.com"),
            width,
        ),
        d,
        rule_hint(RuleField::Domain),
        form.domain.chars().count() as u16,
    );
    rows.line(modal_form::value_row(
        "direction",
        form.direction_label(),
        focus == RuleField::Direction,
        // Not `Editable`: this is a two-value toggle, not a text field, and
        // the hint names the keys that change it.
        ValueKind::Identity,
        Some("Left/Right toggles"),
        width,
    ));
    rows.spacer();

    // **The exact line, before it is written.** The grammar admits two
    // forms and the operator hand-edits these files, so showing the syntax
    // is what stops `@@` and `||` being guessed at from the direction word.
    rows.section("Appends");
    rows.line(modal_form::state_row(
        "line",
        &form.line_preview(),
        ValueKind::Identity,
        "",
        width,
    ));

    let actions = [
        Action::new(
            "  [Esc] Discard  ",
            focus == RuleField::Cancel,
            ActionKind::Neutral,
            rule_hint(RuleField::Cancel),
        ),
        Action::new(
            "  [Enter] Add  ",
            focus == RuleField::Submit,
            ActionKind::Primary,
            rule_hint(RuleField::Submit),
        ),
    ];
    let tail = modal_form::form_tail(
        &rows,
        form.error_message.as_deref(),
        rule_hint(focus),
        KEYS,
        &actions,
    );
    rows.finish(tail)
}

fn rule_hint(f: RuleField) -> &'static str {
    match f {
        RuleField::Domain => "a bare domain — no wildcard, no regex, no path",
        RuleField::Direction => "deny blocks it; allow exempts it from every list",
        RuleField::Submit => "Enter appends the line to the end of the file",
        RuleField::Cancel => "discard and close (also Esc)",
    }
}

/// The rule-removal confirm.
///
/// Single-key rather than a typed gate: one rule is recoverable by typing
/// it again, where a whole list is not. What it MUST carry instead is the
/// bidirectionality — `remove_rule` matches the domain alone, so the
/// operator who meant to drop one direction has no way to learn from the
/// row that the other one goes too.
pub fn rule_remove_notice(rc: &RuleRemoveConfirm) -> NoticeSpec {
    let mut prose = vec![ProseRow::emphasis(rc.domain.clone(), ValueKind::Blocking)];
    if rc.takes_more_than_one_line() {
        prose.push(ProseRow::plain(format!(
            "{} lines name this domain, in BOTH directions:",
            rc.affected.len()
        )));
        for (n, raw) in &rc.affected {
            prose.push(ProseRow::plain(format!("  line {n}: {}", raw.trim())));
        }
        prose.push(ProseRow::plain(
            "all of them go — removal matches the domain, not the direction.".to_string(),
        ));
    } else {
        prose.push(ProseRow::plain(
            "removal matches the domain, not the direction: an allow AND a".to_string(),
        ));
        prose.push(ProseRow::plain(
            "deny for the same domain would both go.".to_string(),
        ));
    }
    NoticeSpec {
        hint_rows: None,
        title: format!("Remove rule \u{00b7} {}", rc.list_id),
        desc: "comments and unparsed lines are left untouched".to_string(),
        prose,
        choices: Vec::new(),
        error: None,
        hint: "the rest of the file keeps its order and its comments".to_string(),
        keys: "[y] confirm   [n / Esc] cancel".to_string(),
        actions: vec![
            Action::new("  [n] Cancel  ", false, ActionKind::Neutral, ""),
            Action::new("  [y] Remove  ", false, ActionKind::Destructive, ""),
        ],
    }
}

fn band_text(form: &Form) -> (String, String) {
    let desc = "a rule file you write yourself — allow and deny together".to_string();
    match form.mode {
        FormMode::Add => ("Add custom list".to_string(), desc),
        FormMode::Edit => (format!("Edit custom list \u{b7} {}", form.id), desc),
    }
}

fn form_body(form: &Form, width: u16) -> (modal_form::ScrollBody, Option<(usize, u16)>) {
    let focus = form.focused;
    let chars = |s: &String| s.chars().count() as u16;
    let (title, desc) = band_text(form);
    let mut rows = modal_form::FormRows::new(&title, &desc, width);

    rows.section("Identity");
    if form.mode == FormMode::Add {
        let f = focus == FormField::Id;
        rows.text_field(
            modal_form::value_row(
                "id",
                &form.id,
                f,
                ValueKind::Identity,
                Some("e.g. videogames"),
                width,
            ),
            f,
            field_hint(FormField::Id),
            chars(&form.id),
        );
    } else {
        // Immutable once created — it names the file. A plain row rather
        // than an unfocused value row: a greyed value row reads as
        // "editable, just not focused right now".
        rows.line(modal_form::value_row(
            "id",
            &form.id,
            false,
            ValueKind::Identity,
            None,
            width,
        ));
    }
    let dn = focus == FormField::DisplayName;
    rows.text_field(
        modal_form::value_row(
            "display name",
            &form.display_name,
            dn,
            ValueKind::Editable,
            Some("blank = the id"),
            width,
        ),
        dn,
        field_hint(FormField::DisplayName),
        chars(&form.display_name),
    );
    rows.spacer();

    rows.section("File");
    // Stated and unreachable. Derived from the id and never configured,
    // which is what makes a traversal, a symlink and two lists sharing one
    // file unrepresentable instead of merely refused.
    rows.line(modal_form::state_row(
        "path",
        &form.pack_path_preview(),
        ValueKind::Identity,
        "",
        width,
    ));
    rows.spacer();

    rows.section("Note");
    let de = focus == FormField::Description;
    rows.text_field(
        modal_form::value_row(
            "description",
            &form.description,
            de,
            ValueKind::Editable,
            Some("optional"),
            width,
        ),
        de,
        field_hint(FormField::Description),
        chars(&form.description),
    );

    let actions = [
        Action::new(
            "  [Esc] Discard  ",
            focus == FormField::Cancel,
            ActionKind::Neutral,
            field_hint(FormField::Cancel),
        ),
        Action::new(
            "  [Enter] Save  ",
            focus == FormField::Submit,
            ActionKind::Primary,
            field_hint(FormField::Submit),
        ),
    ];

    let tail = modal_form::form_tail(
        &rows,
        form.error_message.as_deref(),
        field_hint(focus),
        KEYS,
        &actions,
    );
    rows.finish(tail)
}

fn field_hint(f: FormField) -> &'static str {
    match f {
        FormField::Id => "lowercase, digits and dashes — it names the file",
        FormField::DisplayName => "what the tables show (blank = the id)",
        FormField::Description => "free note — nothing reads it, it filters nothing",
        FormField::Submit => "Enter creates the list and its file",
        FormField::Cancel => "discard changes and close (also Esc)",
    }
}

/// The Remove confirm, as a typed-id gate.
///
/// Two states, and the refused one is not a variant of the other: a mounted
/// list cannot be removed at any amount of typing, so it gets no input row
/// at all. Offering one that can never authorise anything is how a gate
/// teaches the operator to ignore it.
pub fn remove_notice(rc: &RemoveConfirm) -> NoticeSpec {
    if rc.is_refused() {
        return NoticeSpec {
            hint_rows: None,
            title: "Cannot remove custom list".to_string(),
            desc: "the list is still mounted".to_string(),
            prose: vec![
                ProseRow::emphasis(
                    format!("{} ({})", rc.id, rc.display_name),
                    ValueKind::Blocking,
                ),
                ProseRow::plain(format!("mounted on: {}", rc.mounted_on.join(", "))),
                ProseRow::plain("unmount it with [m], then remove it.".to_string()),
            ],
            choices: Vec::new(),
            error: None,
            hint: "removing a mounted list would change what those profiles filter".to_string(),
            keys: "[Esc] close".to_string(),
            actions: vec![Action::new(
                "  [Esc] Close  ",
                false,
                ActionKind::Neutral,
                "",
            )],
        };
    }
    NoticeSpec {
        hint_rows: None,
        title: "Remove custom list".to_string(),
        desc: "this drops rules nothing else holds".to_string(),
        prose: vec![
            ProseRow::emphasis(
                format!("{} ({})", rc.id, rc.display_name),
                ValueKind::Blocking,
            ),
            ProseRow::plain(format!("{} rule(s) in the file.", rc.rules)),
            ProseRow::plain("type the id to confirm:".to_string()),
            // Verbatim: a transcription target is reproduced keystroke for
            // keystroke, so it wraps rather than being ellipsised.
            ProseRow::verbatim(rc.typed.clone(), ValueKind::Identity),
        ],
        choices: Vec::new(),
        error: None,
        hint: "the pack file stays on disk; only the declaration goes".to_string(),
        keys: "[Enter] confirm   [Esc] cancel".to_string(),
        actions: vec![
            Action::new("  [Esc] Cancel  ", false, ActionKind::Neutral, ""),
            Action::new("  [Enter] Remove  ", false, ActionKind::Destructive, ""),
        ],
    }
}

fn outcome_notice(outcome: &SubmitOutcome) -> NoticeSpec {
    let (title, prose, error) = match outcome {
        SubmitOutcome::Ok(msg) => (
            "Saved".to_string(),
            vec![ProseRow::plain(msg.clone())],
            None,
        ),
        // A failure goes in the `error` slot rather than the prose: that
        // region hard-wraps, where `prose_row` truncates.
        SubmitOutcome::Failed(msg) => ("Failed".to_string(), Vec::new(), Some(msg.clone())),
    };
    NoticeSpec {
        hint_rows: None,
        title,
        desc: "custom list".to_string(),
        prose,
        choices: Vec::new(),
        error,
        hint: String::new(),
        keys: "any key closes".to_string(),
        actions: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::schema::Id;

    fn entity(id: &str) -> CustomList {
        CustomList {
            id: Id::new(id).unwrap(),
            display_name: String::new(),
            description: String::new(),
        }
    }

    fn picker(profiles: &[(&str, bool)]) -> MountPicker {
        MountPicker::open(
            &entity("videogames"),
            profiles
                .iter()
                .map(|(p, m)| ((*p).to_string(), *m))
                .collect(),
        )
    }

    #[test]
    fn staged_starts_equal_to_mounted_so_nothing_is_written_by_opening() {
        let p = picker(&[("kids", true), ("default", false)]);
        assert!(p.changes().is_empty(), "opening must stage nothing");
    }

    #[test]
    fn a_toggle_back_to_the_original_state_stages_nothing() {
        // Two toggles are not one write of the same value: the row is
        // clean again, so the profile must not be rewritten at all.
        let mut p = picker(&[("kids", true)]);
        p.toggle();
        assert_eq!(p.changes(), vec![("kids", false)]);
        p.toggle();
        assert!(p.changes().is_empty());
    }

    #[test]
    fn only_changed_rows_are_written() {
        let mut p = picker(&[("kids", true), ("default", false), ("guest", false)]);
        p.cursor = 1;
        p.toggle();
        assert_eq!(p.changes(), vec![("default", true)]);
    }

    /// The operator reaching for `m` on a mounted list is usually there to
    /// unmount it, so the cursor starts on the mounted row rather than on
    /// whichever profile happens to sort first.
    #[test]
    fn the_cursor_opens_on_the_first_mounted_profile() {
        let p = picker(&[("default", false), ("kids", true)]);
        assert_eq!(p.cursor, 1);
    }

    #[test]
    fn the_cursor_clamps_at_both_ends() {
        let mut p = picker(&[("a", false), ("b", false)]);
        p.step(false);
        assert_eq!(p.cursor, 0);
        p.step(true);
        p.step(true);
        assert_eq!(p.cursor, 1);
    }

    #[test]
    fn a_config_with_no_profiles_says_so_instead_of_offering_an_empty_list() {
        let p = picker(&[]);
        let spec = mount_spec(&p);
        assert!(spec.choices.is_empty());
        assert!(spec.prose.iter().any(|r| r.text == NO_PROFILES));
    }

    /// The tick has to survive a style-blind read, so it is a glyph.
    #[test]
    fn the_tick_is_a_glyph_not_a_colour() {
        let mut p = picker(&[("kids", true), ("default", false)]);
        p.cursor = 1;
        p.toggle();
        let spec = mount_spec(&p);
        assert!(spec.choices[0].label.starts_with("[x] "));
        assert!(spec.choices[1].label.starts_with("[x] "));
        p.toggle();
        let spec = mount_spec(&p);
        assert!(spec.choices[1].label.starts_with("[ ] "));
    }

    /// A mounted list cannot be removed at any amount of typing, so the
    /// refused gate offers no input row at all. A gate that accepts input
    /// it can never honour is one the operator learns to ignore.
    #[test]
    fn a_mounted_list_is_refused_and_the_confirm_names_the_profiles() {
        let rc = RemoveConfirm {
            id: "videogames".to_string(),
            display_name: "Video games".to_string(),
            mounted_on: vec!["kids".to_string(), "guest".to_string()],
            rules: 34,
            typed: "videogames".to_string(),
        };
        assert!(rc.is_refused(), "a mounted list must be refused");
        let spec = remove_notice(&rc);
        let blob: String = spec
            .prose
            .iter()
            .map(|r| r.text.clone())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(blob.contains("kids"), "the profiles must be named: {blob}");
        assert!(blob.contains("guest"), "the profiles must be named: {blob}");
        assert!(
            blob.contains("[m]"),
            "the remedy must be the key that performs it: {blob}"
        );
        assert!(
            !blob.contains("type the id"),
            "a refused gate must not ask for input it cannot honour: {blob}"
        );
    }

    /// Only the exact id commits. A prefix must not.
    #[test]
    fn only_the_exact_id_confirms_a_removal() {
        let mut rc = RemoveConfirm {
            id: "videogames".to_string(),
            display_name: String::new(),
            mounted_on: Vec::new(),
            rules: 3,
            typed: String::new(),
        };
        assert!(!rc.confirmed(), "empty must not confirm");
        rc.typed = "video".to_string();
        assert!(!rc.confirmed(), "a prefix must not confirm");
        rc.typed = "videogames ".to_string();
        assert!(!rc.confirmed(), "trailing space must not confirm");
        rc.typed = "videogames".to_string();
        assert!(rc.confirmed());
    }

    /// The unmounted gate says the file survives, because it does — and an
    /// operator who expects the rules gone would otherwise be surprised
    /// the next time they create a list with the same id.
    #[test]
    fn the_removal_gate_says_the_pack_file_stays() {
        let rc = RemoveConfirm {
            id: "tv".to_string(),
            display_name: String::new(),
            mounted_on: Vec::new(),
            rules: 2,
            typed: String::new(),
        };
        let spec = remove_notice(&rc);
        assert!(
            spec.hint.contains("stays on disk"),
            "got hint: {}",
            spec.hint
        );
    }

    /// The id being transcribed must reach the operator WHOLE — it is the
    /// string the gate compares against, so an ellipsis would make the
    /// confirm unsatisfiable by any keystroke sequence.
    #[test]
    fn the_typed_row_is_verbatim_so_it_is_never_ellipsised() {
        let rc = RemoveConfirm {
            id: "a".repeat(64),
            display_name: String::new(),
            mounted_on: Vec::new(),
            rules: 0,
            typed: "a".repeat(64),
        };
        let spec = remove_notice(&rc);
        assert!(
            spec.prose[TYPED_PROSE_IDX].verbatim,
            "the transcription row must be verbatim"
        );
    }

    /// A ticked row that was already ticked writes nothing, and the tick
    /// alone cannot say that.
    #[test]
    fn the_detail_names_the_change_only_on_rows_that_change() {
        let mut p = picker(&[("kids", true), ("default", false)]);
        p.cursor = 1;
        p.toggle();
        let spec = mount_spec(&p);
        assert_eq!(spec.choices[0].detail, None, "unchanged row says nothing");
        assert_eq!(spec.choices[1].detail.as_deref(), Some("will mount"));
    }
}
