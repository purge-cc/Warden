//! §4.66 L7 — Labels tab modals (Add / Edit / Delete).
//!
//! Opens over [`crate::tui::app::Leaf::Labels`] via `a` (Add), `e` (Edit)
//! or `d` / Delete (Remove). Submits through
//! `cli::commands::labels::{add_inner, set_inner, remove_inner}` — the
//! **sync** inner writers, never the `run_*` verbs: those `println!` their
//! outcome, and a `println!` on a raw-mode alternate screen bypasses
//! ratatui's diff buffer and staircases one column per line (the v0.29.1
//! defect). That seam exists because `s466-l7a` was split off to build it
//! ahead of this sprint.
//!
//! This module is a transposition of [`crate::tui::group_modal`], not a
//! new design — same three stages, same Archetype-F body, same y/n delete
//! tier. Three things differ, and each is a property of the entity rather
//! than a shortcut:
//!
//! ## The kind is context, not a field
//!
//! The operator asked for a menu *"contestuale alla selezione — se è
//! presente su Owners, il menu parlerà di Owners"*. So the modal carries
//! [`AddForm::kind`] read-only, seeded from the focused pane, and it is
//! **not** in [`FormField::ALL`]: there is no way to tab to it and no way
//! to change it. The rejected alternative — a kind selector inside the
//! form — fails as *context desync*: the operator browses Owners, presses
//! `a`, and the row appears in a pane they are not looking at.
//!
//! `warden label set <id> kind <k>` still moves a row between
//! vocabularies. Moving it from here would be the same desync from the
//! other side.
//!
//! ## Identity is the pair `(kind, id)`
//!
//! Every write threads `kind` alongside `id`, because the validator's R1
//! deliberately legalises the same id under two kinds. The inner writers
//! key on the pair (`labels`' own `row_matches`); `target::upsert_id_keyed`
//! compares `item["id"]` alone and would overwrite an `owner` row when a
//! `device-type` of the same id is added. That is a silent loss already
//! found and closed once on this entity — see the note on
//! `EntityClass::Labels` in `cli/commands/target.rs`.
//!
//! ## A save is scalar, and there is no second writer
//!
//! `submit_group_modal` writes twice — scalars, then a tag delta — because
//! `apply_group_field` refuses the `tags` field. [`Label`] has four fields
//! and none of them is `tags`. Anyone porting the Groups path literally
//! will go looking for a second writer that does not belong here.
//!
//! ## State machines
//!
//! Add (also reused by Edit, with `mode = Edit`):
//! ```text
//! EditingForm(AddForm) ──Enter on Submit──▶ Submitted(Ok | Failed)
//!                      ──Esc──▶ closed
//! ```
//!
//! Remove:
//! ```text
//! ConfirmingRemove(SingleKeypress) ──[y]──▶ Submitted(Ok | Failed)
//!                                  ──[n / Esc]──▶ closed
//! ```
//!
//! ## Capture-at-open invariant
//!
//! When `a` / `e` / `d` is pressed, the openers in `tui/mod.rs` snapshot
//! everything the modal needs — the focused kind, the focused row's
//! record, its usage count — into the [`LabelModal`]. Subsequent renders,
//! refreshes and `r` reloads cannot invalidate that snapshot: submitting
//! uses the captured values, never re-reads `loaded_config`. Mirrors
//! `group_modal` and `subnet_modal`.

use crate::config::schema::{Label, LabelKind};

/// Top-level modal lifecycle. `None` on `app.labels.modal` means no modal
/// is open; a `Some` variant grabs every keystroke until either submit
/// lands a [`Stage::Submitted`] outcome or the operator presses Esc.
#[derive(Debug, Clone)]
pub struct LabelModal {
    pub stage: Stage,
}

// `EditingForm` carries the full `AddForm`; the other two are small.
// Boxing the large variant to equalize sizes would add a heap alloc plus a
// deref per keystroke for no measurable benefit — the modal is built once
// per operator action and never on a hot path. Mirrors `GroupModal`.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone)]
pub enum Stage {
    /// Add or Edit form. The discriminant inside `AddForm` selects the
    /// title bar and the submit dispatch path.
    EditingForm(AddForm),
    /// Remove confirmation. Single-key y/n — the same tier Groups and
    /// Subnets use, and here the argument for it is stronger than
    /// anywhere else in the TUI. LB3 states it: *"cancellare un gruppo
    /// cambia il DNS di casa; cancellare un owner non cambia niente."*
    /// Removing a label is **inert** — the device's `owner = "Alex"`
    /// string survives, it only loses the row that declared it — and
    /// `remove_if_present` refuses outright while any device still
    /// carries the value. A typed-id gate here would price an inert
    /// action at the same bar as a destructive one.
    ConfirmingRemove(RemoveConfirm),
    /// Final state — the modal renders the success or error message and
    /// closes on the next keypress.
    Submitted(SubmitOutcome),
}

#[derive(Debug, Clone)]
pub enum SubmitOutcome {
    Ok(String),
    Failed(String),
}

/// Form mode discriminator — drives the title bar and the submit path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormMode {
    Add,
    /// Edit carries the original snapshot so the submit path knows which
    /// fields actually diverged.
    Edit,
}

/// Editable fields exposed by the form, in tab order. Keep in sync with
/// [`FormField::ALL`].
///
/// **`kind` is deliberately absent** — see the module doc. A variant here
/// is a thing the operator can tab to and change, and the kind is neither.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormField {
    Id,
    DisplayName,
    /// Free-form note. Inert — nothing in warden reads it, which the
    /// focus hint says out loud so the operator does not expect it to
    /// filter anything.
    Description,
    Submit,
    Cancel,
}

#[derive(Debug, Clone)]
pub struct AddForm {
    pub mode: FormMode,
    /// Which vocabulary this row belongs to. Captured from the focused
    /// pane at open time and immutable for the modal's lifetime.
    pub kind: LabelKind,
    /// Snapshot of the original entity at modal-open time. Set on Edit so
    /// the submit path can diff. `None` on Add.
    pub original: Option<OriginalSnapshot>,
    pub focused: FormField,
    pub id: String,
    pub display_name: String,
    pub description: String,
    /// Inline validation / submit error rendered at the bottom of the
    /// form. Cleared on the next field edit.
    pub error_message: Option<String>,
}

/// Original entity snapshot captured when an Edit modal opens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OriginalSnapshot {
    pub id: String,
    pub display_name: String,
    /// Flattened to the empty string, which is exactly what
    /// `apply_label_field` treats as "clear it" — so a diff against the
    /// form buffer needs no `Option` dance.
    pub description: String,
}

#[derive(Debug, Clone)]
pub struct RemoveConfirm {
    pub kind: LabelKind,
    pub id: String,
    pub display_name: String,
    /// How many devices carry this value, counted at open time by the
    /// same `tabs::labels::usage_count` the table's USED column shows.
    ///
    /// Load-bearing rather than decorative: at zero the removal is a pure
    /// vocabulary edit, and above zero `remove_if_present` will **refuse**
    /// it. Showing the number means the refusal is predictable from the
    /// confirm screen instead of arriving as an error afterwards.
    pub usage: usize,
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
        let idx = Self::ALL.iter().position(|&f| f == self).unwrap_or(0);
        Self::ALL[(idx + 1) % Self::ALL.len()]
    }

    pub fn prev(self) -> Self {
        let idx = Self::ALL.iter().position(|&f| f == self).unwrap_or(0);
        Self::ALL[(idx + Self::ALL.len() - 1) % Self::ALL.len()]
    }
}

impl AddForm {
    /// Empty form for `Add`, bound to the vocabulary the operator is
    /// looking at.
    pub fn new_add(kind: LabelKind) -> Self {
        Self {
            mode: FormMode::Add,
            kind,
            original: None,
            focused: FormField::Id,
            id: String::new(),
            display_name: String::new(),
            description: String::new(),
            error_message: None,
        }
    }

    /// Pre-filled form for `Edit`. The kind comes from the label itself,
    /// not from the pane — on Edit the two are the same by construction,
    /// and reading it off the record keeps the modal honest if they ever
    /// diverge.
    pub fn new_edit(label: &Label) -> Self {
        let description = label.description.clone().unwrap_or_default();
        Self {
            mode: FormMode::Edit,
            kind: label.kind,
            original: Some(OriginalSnapshot {
                id: label.id.as_str().to_string(),
                display_name: label.display_name.clone(),
                description: description.clone(),
            }),
            focused: FormField::DisplayName, // id is not editable
            id: label.id.as_str().to_string(),
            display_name: label.display_name.clone(),
            description,
            error_message: None,
        }
    }

    /// Resolve the form into the values ready to feed the inner writers.
    ///
    /// Pre-flights only what needs no filesystem access: a non-empty id.
    /// The charset gate (`Id::new`, `[a-z0-9-]`, 1..=64) is deliberately
    /// **not** duplicated here — `add_inner` runs it and names the field,
    /// and a second copy is a second place for the two to disagree. What
    /// this module owes the operator instead is that the constraint be
    /// *visible before Save*, which is [`field_hint`]'s job.
    pub fn try_resolve(&self) -> Result<ResolvedForm, String> {
        let id_trim = self.id.trim();
        if id_trim.is_empty() {
            return Err("id is required".into());
        }
        let display_trim = self.display_name.trim();
        Ok(ResolvedForm {
            id: id_trim.to_string(),
            // Same fallback the CLI applies: `warden label add alex
            // --kind owner` with no `--display-name` stores the id. The
            // two surfaces must not produce different rows from the same
            // input.
            display_name: if display_trim.is_empty() {
                id_trim.to_string()
            } else {
                display_trim.to_string()
            },
            description: self.description.trim().to_string(),
        })
    }
}

/// Output of [`AddForm::try_resolve`] — the modal-side view of a
/// submission. The submit path threads it into `add_inner` (Add) or diffs
/// it against `original` (Edit).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedForm {
    pub id: String,
    pub display_name: String,
    /// Empty means "no description" on Add and "clear it" on Edit — the
    /// same value `apply_label_field` reads as a clear.
    pub description: String,
}

impl LabelModal {
    /// Open an Add modal bound to the focused vocabulary.
    pub fn open_add(kind: LabelKind) -> Self {
        Self {
            stage: Stage::EditingForm(AddForm::new_add(kind)),
        }
    }

    /// Open an Edit modal pre-filled from the focused label.
    pub fn open_edit(label: &Label) -> Self {
        Self {
            stage: Stage::EditingForm(AddForm::new_edit(label)),
        }
    }

    /// Open a Remove modal at single-keypress confirm tier.
    pub fn open_remove(label: &Label, usage: usize) -> Self {
        Self {
            stage: Stage::ConfirmingRemove(RemoveConfirm {
                kind: label.kind,
                id: label.id.as_str().to_string(),
                display_name: label.display_name.clone(),
                usage,
            }),
        }
    }

    /// Mark the modal as submitted — the caller closes it on the next
    /// keypress.
    pub fn finish(&mut self, outcome: SubmitOutcome) {
        self.stage = Stage::Submitted(outcome);
    }

    /// Whether the modal is in a submitted state — used by the key
    /// handler to close on the next keypress.
    pub fn is_submitted(&self) -> bool {
        matches!(self.stage, Stage::Submitted(_))
    }

    /// Convenience: borrow the form when the stage is editing. Test-only.
    #[cfg(test)]
    pub fn form(&self) -> Option<&AddForm> {
        match &self.stage {
            Stage::EditingForm(f) => Some(f),
            _ => None,
        }
    }

    /// Mutable counterpart of [`Self::form`]. Test-only.
    #[cfg(test)]
    pub fn form_mut(&mut self) -> Option<&mut AddForm> {
        match &mut self.stage {
            Stage::EditingForm(f) => Some(f),
            _ => None,
        }
    }

    /// Convenience: borrow the remove-confirm state. Test-only.
    #[cfg(test)]
    pub fn remove(&self) -> Option<&RemoveConfirm> {
        match &self.stage {
            Stage::ConfirmingRemove(r) => Some(r),
            _ => None,
        }
    }
}

// ── Render (Archetype F / C via `modal_form`) ────────────────────────
//
// Every span in this module comes out of `modal_form`; not one colour is
// chosen here. That is the ecosystem rule's acceptance criterion, not an
// aesthetic preference — teal is static, emerald is focus, and there is
// exactly one implementation of that so the surfaces cannot drift apart.
// Pinned by `no_hand_rolled_colour_in_this_module` below.

use ratatui::layout::Rect;
use ratatui::Frame;

use crate::tui::modal_form::{self, Action, ActionKind, NoticeSpec, ProseRow, ValueKind};

/// Nav-key legend copy — byte-identical to the Groups and Subnets modals'.
// N14 stripped the save/cancel clause: the action row now bakes its
// own key into each button's label (`[Esc] Discard` / `[Enter] Save`),
// so a blanket "Enter save · Esc cancel" here would be a second,
// redundant source of the same fact.
const KEYS: &str = "\u{21b9}/\u{2191}\u{2193} move";

/// Draw the modal as an overlay anchored on the tab content rect.
///
/// `anchor` is the tab content area, never `f.area()`: the header, the
/// sub-tab strip and the footer legend stay visible behind the modal.
pub fn render_overlay(f: &mut Frame, anchor: Rect, modal: &LabelModal) {
    const W: u16 = 64;
    match &modal.stage {
        Stage::EditingForm(form) => {
            let render = modal_form::render_modal(f, anchor, W, |w| form_body(form, w));
            // The focused text field hosts the real terminal cursor.
            // `place_cursor` no-ops when that row is scrolled out of view.
            if let Some((row, caret)) = render.cursor {
                render.place_cursor(f, row, modal_form::VALUE_COL as u16 + caret);
            }
        }
        Stage::ConfirmingRemove(rc) => {
            let spec = remove_notice(rc);
            modal_form::render_modal(f, anchor, W, |w| (modal_form::notice_body(&spec, w), ()));
        }
        Stage::Submitted(outcome) => {
            let spec = outcome_notice(outcome);
            modal_form::render_modal(f, anchor, W, |w| (modal_form::notice_body(&spec, w), ()));
        }
    }
}

/// Title + description band copy for the add/edit form.
///
/// **The title names the kind, and that is load-bearing rather than
/// decorative.** Below 90 columns `tabs::labels::menu_is_painted` returns
/// false, the kind menu is not drawn at all and the focus is clamped onto
/// the table — so at the declared 80-column floor this title is the
/// *only* place the operator can see which vocabulary they are writing
/// into. Pinned by `the_title_names_the_kind_on_add_and_edit`.
///
/// The kind is spelled with [`LabelKind::as_str`], the wire form, rather
/// than the menu's prettified plural: it is the exact token the operator
/// would pass to `--kind`, so the two surfaces teach one vocabulary.
fn band_text(form: &AddForm) -> (String, String) {
    let desc = format!(
        "declared values for a device's {} field",
        form.kind.device_field()
    );
    match form.mode {
        FormMode::Add => (format!("Add {}", form.kind.as_str()), desc),
        FormMode::Edit => (
            format!("Edit {} \u{b7} {}", form.kind.as_str(), form.id),
            desc,
        ),
    }
}

/// Build the add/edit form as an Archetype-F [`modal_form::ScrollBody`] —
/// pinned head, scrolling field region, pinned tail — plus the real-cursor
/// target (index **within the field region** + caret offset) for the
/// focused text field, if any.
///
/// Nothing here branches on `width`: [`modal_form::render_modal`] sizes
/// the chrome from the first build and may call this a second time one
/// column narrower, so a width-dependent row count would silently
/// mis-size the modal.
fn form_body(form: &AddForm, width: u16) -> (modal_form::ScrollBody, Option<(usize, u16)>) {
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
                Some("e.g. alex or apple-tv"),
                width,
            ),
            f,
            field_hint(FormField::Id),
            chars(&form.id),
        );
    } else {
        // Immutable once created, and `mod.rs::next_editable_label_field`
        // skips it on Edit — so it is a plain row that can never take
        // focus. `false` is hardcoded for that reason: a row that renders
        // as focusable but cannot be reached is the same silent class of
        // defect as one that can be reached but not seen.
        rows.line(modal_form::value_row(
            "id",
            &form.id,
            false,
            ValueKind::Identity,
            None,
            width,
        ));
    }
    // The kind, stated and unreachable. It is a `state_row` rather than a
    // `value_row(.., false, ..)` because the two say different things: a
    // greyed value row reads as "editable, just not focused right now",
    // and `state_row` is the archetype's read-only shape.
    rows.line(modal_form::state_row(
        "kind",
        form.kind.as_str(),
        ValueKind::Identity,
        // The note carries its own separator — `state_row` concatenates
        // value and note with no space between them.
        //
        // **Branched, because one sentence was false in one of the two
        // modes.** On Add the kind really does come from the focused
        // pane, and saying so is what makes the context rule legible. On
        // Edit it is read off the row itself, so the same words would name
        // the wrong source — noticed on a real terminal, where the Edit
        // modal read "from the selected pane" over a row the operator had
        // reached by walking the table.
        // **Both notes are inside a budget that `state_row` enforces by
        // DROPPING, not clipping** — so an over-long note does not look
        // wrong, it looks absent, and nothing on screen says a sentence
        // went missing. The first draft of the Edit note was 35 columns
        // and vanished; only a test caught it. The budget is
        // `body_width - VALUE_COL - len("◆ " + kind)`, and the worst kind
        // is `device-type`. `the_kind_note_survives_the_narrow_rebuild`
        // pins it there rather than here, where a comment would rot.
        match form.mode {
            FormMode::Add => " \u{2014} from the selected pane",
            FormMode::Edit => " \u{2014} not editable here",
        },
        width,
    ));
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

    // N14: Discard left, Save right — the one `Primary` fill sits
    // right-most on every Archetype-F form (CONTRACT §3.1). The focus
    // ring still reaches `Submit` before `Cancel`, unchanged — same
    // precedent as `profile_modal.rs`'s tail.
    //
    // Discard is `Neutral`, not `Destructive`: it closes the form
    // without writing anything, which is what Esc does too.
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

/// One-line description of the focused field, shown on the validation
/// line whenever there is no pending error.
///
/// **The `id` hint spells the charset, and that is the one hint here that
/// earns its place by measurement.** The live values on the operator's
/// boxes are `Alex` and `Apple TV`, and those are exactly what a person
/// types into a field labelled *id* — neither passes `Id::validate`.
/// `add_inner` refuses and names the field, so this is not a correctness
/// gap; it is the difference between a feature that works on first use and
/// one that reads as broken.
///
/// The `display name` hint carries the other half: it is the field that
/// **adopts** a legacy value, because `check_device_metadata_vocabulary`
/// matches a device through `Label::matches_value`, which compares the id
/// **or** the display name.
fn field_hint(f: FormField) -> &'static str {
    match f {
        FormField::Id => "lowercase, digits and dashes only (immutable on edit)",
        FormField::DisplayName => "the value your devices carry, e.g. Alex (blank = the id)",
        FormField::Description => "free note — nothing reads it, it filters nothing",
        FormField::Submit => "Enter saves the label",
        FormField::Cancel => "discard changes and close (also Esc)",
    }
}

/// The Remove confirm as an Archetype-C notice.
///
/// The keying is a single `y` / `n` keypress, no focus ring. The actions
/// carry their key in the label because of that — they orient, they are
/// not Tab targets — and neither is `Primary`, so the modal has no filled
/// button: the one teal fill means "this is the action", and a
/// destructive confirm should not be advertising one.
///
/// The body states the consequence in the direction that surprises: a
/// label is a *declaration*, so removing it leaves every device's value
/// exactly where it was. The row is what goes.
fn remove_notice(rc: &RemoveConfirm) -> NoticeSpec {
    let (usage_line, hint) = if rc.usage == 0 {
        (
            "no device carries this value.".to_string(),
            "the vocabulary loses a row; nothing else changes".to_string(),
        )
    } else {
        (
            format!("{} device(s) still carry this value.", rc.usage),
            "warden will refuse this — clear the value on those devices first".to_string(),
        )
    };
    NoticeSpec {
        hint_rows: None,
        title: format!("Remove {}", rc.kind.as_str()),
        desc: "confirm removal of a vocabulary entry".to_string(),
        prose: vec![
            ProseRow::emphasis(
                format!("{} ({})", rc.id, rc.display_name),
                ValueKind::Blocking,
            ),
            // Kept inside the 62-column body: `prose_row` truncates
            // rather than wrapping, so copy that does not fit loses its
            // last words to an ellipsis.
            ProseRow::plain(usage_line),
            ProseRow::plain("device values are left untouched.".to_string()),
        ],
        choices: Vec::new(),
        error: None,
        hint,
        keys: "[y] confirm   [n / Esc] cancel".to_string(),
        actions: vec![
            Action::new("  [n] Cancel  ", false, ActionKind::Neutral, ""),
            Action::new("  [y] Remove  ", false, ActionKind::Destructive, ""),
        ],
    }
}

/// The submit outcome as an Archetype-C notice.
///
/// A failure goes in the `error` slot rather than the prose: that region
/// hard-wraps, where `prose_row` truncates.
///
/// **The failure branch pins `hint_rows: Some(4)`, for the same measured
/// reason Groups does.** `labels::remove_if_present`'s refusal names every
/// referring device *and* the remedy, and at the default
/// [`modal_form::HINT_ROWS`] of 2 the remedy is the half that gets
/// ellipsed — the half that tells the operator what to do.
///
/// **This branch is reached ONLY by a Remove, and the copy says so.** An
/// earlier version of this comment claimed a partially applied Edit landed
/// here too; it does not — `submit_label_modal` routes every form failure
/// back to the form's inline validation line and returns before
/// `finish()`, so `Stage::Submitted` is unreachable from a form. The
/// description followed that wrong claim and hedged with *"some of it may
/// already be applied"*, which of a refused remove is simply false:
/// `remove_if_present` bails before touching the file.
///
/// The `Ok` branch keeps `None`, which resolves to zero rows because its
/// message lives in the prose and its hint is empty — pinning 4 there
/// would open a blank band under a success.
fn outcome_notice(outcome: &SubmitOutcome) -> NoticeSpec {
    let (title, desc, prose, error, hint_rows) = match outcome {
        SubmitOutcome::Ok(msg) => (
            "Label \u{b7} done",
            "the change is saved to the configuration file",
            vec![ProseRow::emphasis(msg.clone(), ValueKind::Healthy)],
            None,
            None,
        ),
        SubmitOutcome::Failed(msg) => (
            "Label \u{b7} failed",
            "nothing was written — the vocabulary is unchanged",
            Vec::new(),
            Some(msg.clone()),
            Some(4),
        ),
    };
    NoticeSpec {
        hint_rows,
        title: title.to_string(),
        desc: desc.to_string(),
        prose,
        choices: Vec::new(),
        error,
        hint: String::new(),
        keys: "[any key] close".to_string(),
        actions: vec![Action::new("  Close  ", false, ActionKind::Primary, "")],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::schema::Id;

    fn label(id: &str, kind: LabelKind, display: &str, desc: Option<&str>) -> Label {
        Label {
            id: Id::new(id).unwrap(),
            kind,
            display_name: display.to_string(),
            description: desc.map(|s| s.to_string()),
        }
    }

    fn dump_buffer(buf: &ratatui::buffer::Buffer) -> String {
        let mut out = String::new();
        for y in 0..buf.area.height {
            for x in 0..buf.area.width {
                out.push_str(buf[(x, y)].symbol());
            }
            out.push('\n');
        }
        out
    }

    fn render_overlay_in(modal: &LabelModal, w: u16, h: u16) -> String {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;
        let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
        term.draw(|f| render_overlay(f, f.area(), modal)).unwrap();
        dump_buffer(term.backend().buffer())
    }

    /// **The title is the only kind indicator at the 80-column floor**, so
    /// it is pinned at that width rather than at a roomy one.
    /// `tabs::labels::menu_is_painted` returns false below 90 columns: the
    /// kind menu is not drawn and `clamp_labels_focus_to_layout` moves the
    /// focus off it, which leaves nothing else on screen naming the
    /// vocabulary the operator is writing into.
    #[test]
    fn the_title_names_the_kind_at_the_floor_width() {
        for kind in [
            LabelKind::Owner,
            LabelKind::DeviceType,
            LabelKind::Department,
        ] {
            let dump = render_overlay_in(&LabelModal::open_add(kind), 80, 14);
            assert!(
                dump.contains(&format!("Add {}", kind.as_str())),
                "the Add title must name {kind}; got:\n{dump}"
            );
        }
    }

    /// Edit names the kind **and** the row, for the same reason.
    #[test]
    fn the_edit_title_names_the_kind_and_the_row() {
        let l = label("apple-tv", LabelKind::DeviceType, "Apple TV", None);
        let dump = render_overlay_in(&LabelModal::open_edit(&l), 80, 14);
        assert!(
            dump.contains("Edit device-type") && dump.contains("apple-tv"),
            "got:\n{dump}"
        );
    }

    /// The kind is visible in the body and cannot be reached: it is not in
    /// [`FormField::ALL`], so no amount of Tab lands on it.
    #[test]
    fn the_kind_is_shown_and_is_not_a_tab_stop() {
        let dump = render_overlay_in(&LabelModal::open_add(LabelKind::Department), 100, 30);
        assert!(dump.contains("kind"), "the kind row is drawn; got:\n{dump}");
        assert!(
            dump.contains("department"),
            "and it names the vocabulary; got:\n{dump}"
        );

        // **Exhaustive on purpose, and it is the compiler that enforces
        // this — not the assertion below it.** Adding a `FormField::Kind`
        // variant is exactly the context-desync design this sprint
        // rejected, and it would make this `match` non-exhaustive: the
        // build stops instead of the field quietly becoming a tab stop.
        for f in FormField::ALL {
            match f {
                FormField::Id
                | FormField::DisplayName
                | FormField::Description
                | FormField::Submit
                | FormField::Cancel => {}
            }
        }
        // The other half: a variant could exist and be left out of `ALL`,
        // which the match cannot see. `next`/`prev` index `ALL`, so an
        // omitted variant is unreachable rather than misplaced — still
        // wrong, and this is what notices.
        assert_eq!(
            FormField::ALL.len(),
            5,
            "ALL is the tab order and must list every variant exactly once"
        );
    }

    /// **The kind row's note must not name the wrong source.** Caught on a
    /// real terminal, not in review: the Edit modal read "from the
    /// selected pane" over a row reached by walking the table, where the
    /// kind is read off the record. One sentence cannot be true in both
    /// modes, so there are two.
    #[test]
    fn the_kind_note_names_the_source_that_actually_applies() {
        let add = render_overlay_in(&LabelModal::open_add(LabelKind::Owner), 100, 30);
        assert!(add.contains("from the selected pane"), "got:\n{add}");

        let l = label("alex", LabelKind::Owner, "Alex", None);
        let edit = render_overlay_in(&LabelModal::open_edit(&l), 100, 30);
        assert!(
            !edit.contains("from the selected pane"),
            "Edit reads the kind off the row, not off the pane; got:\n{edit}"
        );
        assert!(
            edit.contains("not editable here"),
            "and it must still say the field is read-only; got:\n{edit}"
        );
    }

    /// **The note budget is nearly spent, and `state_row` fails by
    /// silence.** It drops a note that does not fit rather than clipping
    /// it, so an over-long string does not look wrong — it looks absent.
    /// The worst case is the longest kind at the narrowest width
    /// `render_modal` can rebuild to, and this asserts it there so
    /// lengthening either string reddens a test instead of quietly
    /// deleting a sentence.
    #[test]
    fn the_kind_note_survives_the_narrow_rebuild() {
        // 80x24 is the declared floor; `render_modal` may re-run one
        // column narrower than its nominal 64 when the body scrolls.
        let dump = render_overlay_in(&LabelModal::open_add(LabelKind::DeviceType), 80, 14);
        assert!(
            dump.contains("from the selected pane"),
            "the longest kind must still leave room for the note at the \
             floor — it is dropped, not clipped, so its absence is silent; \
             got:\n{dump}"
        );

        let l = label("apple-tv", LabelKind::DeviceType, "Apple TV", None);
        let edit = render_overlay_in(&LabelModal::open_edit(&l), 80, 14);
        assert!(edit.contains("not editable here"), "got:\n{edit}");
    }

    /// Add starts on `id`; Edit starts on `display name` because `id` is
    /// immutable once written and the renderer draws it as a plain row.
    #[test]
    fn edit_never_opens_focused_on_the_immutable_id() {
        let l = label("alex", LabelKind::Owner, "Alex", None);
        assert_eq!(AddForm::new_add(LabelKind::Owner).focused, FormField::Id);
        assert_eq!(AddForm::new_edit(&l).focused, FormField::DisplayName);
    }

    /// A blank display name resolves to the id — byte-identical to what
    /// `warden label add <id> --kind owner` writes with no
    /// `--display-name`. Two surfaces, one row.
    #[test]
    fn a_blank_display_name_resolves_to_the_id() {
        let mut form = AddForm::new_add(LabelKind::Owner);
        form.id = "  alex  ".to_string();
        let r = form.try_resolve().unwrap();
        assert_eq!(r.id, "alex", "the id is trimmed");
        assert_eq!(r.display_name, "alex");
    }

    /// An empty id is the one pre-flight this form owns. The charset gate
    /// is deliberately NOT duplicated here — `add_inner` runs it — so this
    /// test also documents the boundary: `Alex` resolves fine and is
    /// refused one layer down, by the writer that names the field.
    #[test]
    fn an_empty_id_is_refused_but_the_charset_is_left_to_the_writer() {
        let form = AddForm::new_add(LabelKind::Owner);
        assert_eq!(form.try_resolve().unwrap_err(), "id is required");

        let mut capitalised = AddForm::new_add(LabelKind::Owner);
        capitalised.id = "Alex".to_string();
        assert!(
            capitalised.try_resolve().is_ok(),
            "the form does not second-guess `Id::new`; a second copy of \
             that rule is a second place for the two to disagree"
        );
    }

    /// The `id` hint must spell the constraint, because the values this
    /// vocabulary exists to adopt (`Alex`, `Apple TV`) are exactly what
    /// an operator types into a field labelled *id*, and neither passes
    /// `Id::validate`. Without this the feature reads as broken on first
    /// use even though it refuses correctly.
    #[test]
    fn the_id_hint_states_the_charset_before_save() {
        let hint = field_hint(FormField::Id);
        assert!(
            hint.contains("lowercase") && hint.contains("dashes"),
            "the id hint must state the charset; got: {hint}"
        );
        let dn = field_hint(FormField::DisplayName);
        assert!(
            dn.contains("devices carry"),
            "the display-name hint must say it is the field that adopts a \
             live value; got: {dn}"
        );
    }

    /// The remove confirm states the consequence in the direction that
    /// surprises: removing a declaration leaves every device's value where
    /// it was. And it prints the usage count, so a refusal is predictable
    /// from the screen instead of arriving afterwards.
    #[test]
    fn the_remove_confirm_says_device_values_survive() {
        let l = label("alex", LabelKind::Owner, "Alex", None);
        let dump = render_overlay_in(&LabelModal::open_remove(&l, 0), 80, 14);
        assert!(dump.contains("Remove owner"), "got:\n{dump}");
        assert!(dump.contains("untouched"), "got:\n{dump}");
        assert!(dump.contains("no device carries"), "got:\n{dump}");

        let in_use = render_overlay_in(&LabelModal::open_remove(&l, 3), 80, 14);
        assert!(
            in_use.contains("3 device(s)") && in_use.contains("refuse"),
            "an in-use label must warn that the write will be refused; \
             got:\n{in_use}"
        );
    }

    /// The delete gate is a single keypress, not a typed id. LB3 is the
    /// reason and it is worth pinning as behaviour rather than prose:
    /// *"cancellare un gruppo cambia il DNS di casa; cancellare un owner
    /// non cambia niente"*. If a future sprint promotes this to a typed
    /// gate, this test is where the argument is recorded.
    #[test]
    fn the_remove_gate_is_single_keypress() {
        let l = label("alex", LabelKind::Owner, "Alex", None);
        let dump = render_overlay_in(&LabelModal::open_remove(&l, 0), 80, 14);
        assert!(
            dump.contains("[y] confirm") && dump.contains("[n / Esc] cancel"),
            "got:\n{dump}"
        );
        assert!(
            !dump.contains("type the id"),
            "an inert action must not be priced at the typed-id bar; got:\n{dump}"
        );
    }

    #[test]
    fn no_hand_rolled_colour_in_this_module() {
        // The ecosystem colour rule as a test rather than a claim in a
        // commit message. A surface that reaches for the theme directly is
        // a surface that will drift from the other thirteen. Needles are
        // split so this assertion cannot match itself.
        let src = include_str!("label_modal.rs");
        for needle in [
            concat!("Style::default()", ".fg("),
            concat!("Color", "::Rgb("),
            concat!("T", ".brand_red"),
        ] {
            assert!(
                !src.contains(needle),
                "{needle} in label_modal.rs — the colour belongs in modal_form"
            );
        }
    }
}
