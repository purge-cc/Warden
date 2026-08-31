//! §4.64 G2 — Groups tab modals (Add / Edit / Delete).
//!
//! Opens over [`crate::tui::app::Leaf::Groups`] via `a` (Add), `e`
//! (Edit) or `d` / Delete (Remove). Submits through
//! `cli::commands::groups::{add_inner, set_fields_inner, remove_inner}` —
//! the **sync** inner writers, never the `run_*` verbs: those `println!`
//! their outcome, and a `println!` on a raw-mode alternate screen
//! bypasses ratatui's diff buffer and staircases one column per line
//! (DG2, the v0.29.1 defect).
//!
//! This module is a transposition of [`crate::tui::subnet_modal`], not a
//! new design. A subnet and a group carry the same shape — an id, a
//! display name, a membership expression, a profile, a priority and a
//! tag set — so the two forms differ in exactly one field: a subnet's
//! membership is a CIDR list, a group's is a device-id list. Everything
//! else (the three stages, the y/n delete tier,
//! the Archetype-F body) is the template's, deliberately.
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
//! every value the modal needs (the focused row's record, the profile
//! ids known at this moment, the fleet-wide tag slugs) into the
//! [`GroupModal`] state. Subsequent renders / refreshes / `r` reloads
//! cannot invalidate the snapshot — submitting always uses the captured
//! values, never re-reads `loaded_config`. Mirrors the `subnet_modal`
//! precedent.
//!
//! ## Membership is free text, on purpose
//!
//! `devices` is a comma-separated id list, exactly as
//! `warden group set <id> devices a,b,c` takes it. It is **not**
//! pre-flighted here: `write_value_validated` validates the combined
//! final state of master + every include before promoting, and
//! `check_groups` (`config/schema/validator.rs`) refuses a group whose
//! `devices` names an undefined device or whose `profile` is not
//! defined. A TUI-side duplicate of that check would be a second place
//! for the two to disagree. A multi-select membership picker is **G4**,
//! not this sprint.

use crate::config::schema::Group;

/// Top-level modal lifecycle. `None` on `app.groups.modal` means no
/// modal is open; a `Some` variant grabs every keystroke until either
/// submit lands a [`Stage::Submitted`] outcome or the operator presses
/// Esc.
#[derive(Debug, Clone)]
pub struct GroupModal {
    pub stage: Stage,
}

// `EditingForm` carries the full `AddForm` (the retired tags picker added three
// fields on top of the string buffers); `ConfirmingRemove` / `Submitted`
// are small. Boxing the large variant to equalize sizes would add a heap
// alloc + deref per keystroke for no measurable benefit — the modal is
// constructed once per operator action, never on a hot path. Mirrors the
// `SubnetModal` / `ProfileModal` precedent.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone)]
pub enum Stage {
    /// Add or Edit form. The discriminant inside `AddForm` selects the
    /// title bar + the submit dispatch path.
    EditingForm(AddForm),
    /// Remove confirmation. Single-key y/n — the **same tier the Subnets
    /// modal uses**, deliberately not a typed-id gate. The typed gates in
    /// this codebase (list delete, unsigned-allow consent) buy
    /// deliberation for an action whose blast radius is invisible from
    /// the confirm screen; a group's is not — the members are on the
    /// screen, and `remove_inner` refuses outright while any device or
    /// schedule still points back at it.
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

/// Form mode discriminator — drives title bar, submit behaviour, and
/// (for Edit) which entity gets updated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormMode {
    Add,
    /// Edit carries the original snapshot so the submit path knows which
    /// entity to update and which fields actually diverged.
    Edit,
}

/// Editable fields exposed by the form, in tab order. Keep in sync with
/// [`FormField::ALL`] and the renderer's per-field highlight logic.
/// `Submit` then `Cancel` are the two action buttons (Save / Discard) at
/// the bottom of the grid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormField {
    Id,
    DisplayName,
    /// Comma-separated device ids — the group's entire substance. The
    /// positional analogue of the Subnets modal's `Cidrs`.
    Devices,
    Profile,
    Priority,
    Submit,
    Cancel,
}

#[derive(Debug, Clone)]
pub struct AddForm {
    pub mode: FormMode,
    /// Snapshot of the original entity at modal-open time. Set on Edit so
    /// the submit path knows which id to update + which fields actually
    /// changed. `None` on Add.
    pub original: Option<OriginalSnapshot>,
    pub focused: FormField,
    pub id: String,
    pub display_name: String,
    /// Raw operator input — single line, comma-separated device ids
    /// (mirrors `warden group set <id> devices a,b,c`). Empty is legal:
    /// a group with no members is a valid, inert policy binding.
    pub devices: String,
    /// Snapshot of profile ids captured at modal-open time. The dropdown
    /// walks this slice; the running config can gain or lose profiles
    /// during the form's lifetime, but the captured snapshot stays
    /// authoritative.
    pub profiles_snapshot: Vec<String>,
    /// Index into `profiles_snapshot`. Always points at a valid slot when
    /// the snapshot is non-empty; 0 when it is empty (the submit then
    /// errors with "no profiles defined").
    pub profile_idx: usize,
    /// Raw operator input — parsed to `i32` at submit. Empty means 0.
    pub priority_input: String,
    /// Inline validation / submit error rendered at the bottom of the
    /// form. Cleared on the next field edit.
    pub error_message: Option<String>,
}

/// Original entity snapshot captured when an Edit modal opens.
#[derive(Debug, Clone)]
pub struct OriginalSnapshot {
    pub id: String,
    pub display_name: String,
    pub devices: Vec<String>,
    pub profile: String,
    pub priority: i32,
}

#[derive(Debug, Clone)]
pub struct RemoveConfirm {
    pub id: String,
    pub display_name: String,
    pub profile: String,
    /// The forward membership list. Shown because it is **load-bearing**:
    /// `profiles::profile::groups_for_device` matches on
    /// `g.devices.contains(&device.id) || device.groups.contains(&g.id)`,
    /// so a device listed only here still resolves this group's profile,
    /// and `remove_inner` — which refuses only on the device-side
    /// back-reference — will happily remove it.
    pub devices: Vec<String>,
}

impl FormField {
    pub const ALL: [FormField; 7] = [
        FormField::Id,
        FormField::DisplayName,
        FormField::Devices,
        FormField::Profile,
        FormField::Priority,
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
    /// Empty form for `Add`. `default_profile_idx` is the slot the
    /// dropdown lands on when the form opens.
    pub fn new_add(profiles_snapshot: Vec<String>, default_profile_idx: usize) -> Self {
        let profile_idx = if profiles_snapshot.is_empty() {
            0
        } else {
            default_profile_idx.min(profiles_snapshot.len().saturating_sub(1))
        };
        Self {
            mode: FormMode::Add,
            original: None,
            focused: FormField::Id,
            id: String::new(),
            display_name: String::new(),
            devices: String::new(),
            profiles_snapshot,
            profile_idx,
            priority_input: String::new(),
            error_message: None,
        }
    }

    /// Pre-filled form for `Edit`. The entity's existing fields populate
    /// each input; the original snapshot is stashed so the submit path
    /// can diff against it.
    pub fn new_edit(group: &Group, profiles_snapshot: Vec<String>) -> Self {
        let profile_idx = profiles_snapshot
            .iter()
            .position(|p| p == group.profile.as_str())
            .unwrap_or(0);
        let devices: Vec<String> = group
            .devices
            .iter()
            .map(|d| d.as_str().to_string())
            .collect();
        Self {
            mode: FormMode::Edit,
            original: Some(OriginalSnapshot {
                id: group.id.as_str().to_string(),
                display_name: group.display_name.clone(),
                devices: devices.clone(),
                profile: group.profile.as_str().to_string(),
                priority: group.priority,
            }),
            focused: FormField::DisplayName, // id is not editable
            id: group.id.as_str().to_string(),
            display_name: group.display_name.clone(),
            devices: devices.join(", "),
            profiles_snapshot,
            profile_idx,
            priority_input: group.priority.to_string(),
            error_message: None,
        }
    }

    /// Operator-facing label for the focused dropdown slot.
    pub fn profile_option_label(&self) -> &str {
        self.profiles_snapshot
            .get(self.profile_idx)
            .map(|s| s.as_str())
            .unwrap_or("(no profiles)")
    }

    /// Resolve the form into the tuple ready to feed into `add_inner`.
    /// Performs the pre-flight validation that does NOT need filesystem
    /// access: empty id, absent profile vocabulary, malformed priority.
    ///
    /// It deliberately does **not** check that each device id exists —
    /// `write_value_validated` validates the combined final state before
    /// promoting and `check_groups` refuses undefined references, so a
    /// duplicate here would be a second place for the two to disagree.
    /// Nor does it require a non-empty membership: unlike a subnet, whose
    /// CIDR list is the only thing that makes it match anything, a group
    /// with no members is a legal (inert) policy binding, and
    /// `groups::add_inner` accepts one.
    pub fn try_resolve(&self) -> Result<ResolvedForm, String> {
        let id_trim = self.id.trim();
        if id_trim.is_empty() {
            return Err("id is required".into());
        }
        let display_trim = self.display_name.trim();
        let devices: Vec<String> = self
            .devices
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        if self.profiles_snapshot.is_empty() {
            return Err("no profiles defined — create one first".into());
        }
        let profile = self
            .profiles_snapshot
            .get(self.profile_idx)
            .cloned()
            .ok_or_else(|| "profile selection is out of range".to_string())?;
        let priority = parse_priority(&self.priority_input)?;
        Ok(ResolvedForm {
            id: id_trim.to_string(),
            display_name: if display_trim.is_empty() {
                id_trim.to_string()
            } else {
                display_trim.to_string()
            },
            devices,
            profile,
            priority,
        })
    }
}

/// Output of [`AddForm::try_resolve`] — the modal-side view of an
/// add/edit submission. The submit path threads it into `add_inner`
/// (Add) or diffs it against `original` (Edit).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedForm {
    pub id: String,
    pub display_name: String,
    pub devices: Vec<String>,
    pub profile: String,
    pub priority: i32,
}

/// Parse the operator's priority input. Empty → 0 (the schema default).
fn parse_priority(input: &str) -> Result<i32, String> {
    let t = input.trim();
    if t.is_empty() {
        return Ok(0);
    }
    t.parse::<i32>()
        .map_err(|_| format!("priority must be an integer, got '{t}'"))
}

impl GroupModal {
    /// Open an Add modal.
    pub fn open_add(profiles_snapshot: Vec<String>, default_profile_idx: usize) -> Self {
        Self {
            stage: Stage::EditingForm(AddForm::new_add(profiles_snapshot, default_profile_idx)),
        }
    }

    /// Open an Edit modal pre-filled from the focused group.
    pub fn open_edit(group: &Group, profiles_snapshot: Vec<String>) -> Self {
        Self {
            stage: Stage::EditingForm(AddForm::new_edit(group, profiles_snapshot)),
        }
    }

    /// Open a Remove modal at single-keypress confirm tier.
    pub fn open_remove(group: &Group) -> Self {
        Self {
            stage: Stage::ConfirmingRemove(RemoveConfirm {
                id: group.id.as_str().to_string(),
                display_name: group.display_name.clone(),
                profile: group.profile.as_str().to_string(),
                devices: group
                    .devices
                    .iter()
                    .map(|d| d.as_str().to_string())
                    .collect(),
            }),
        }
    }

    /// Mark the modal as submitted with the given outcome — caller closes
    /// it on the next keypress.
    pub fn finish(&mut self, outcome: SubmitOutcome) {
        self.stage = Stage::Submitted(outcome);
    }

    /// Whether the modal is currently in a submitted state — used by the
    /// keyhandler to close on the next keypress.
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

/// Nav-key legend copy — byte-identical to the Subnets modal's.
///
/// N14 stripped the save/cancel clause: the action row now bakes its
/// own key into each button's label (`[Esc] Discard` / `[Enter] Save`),
/// so a blanket "Enter save · Esc cancel" here would be a second,
/// redundant source of the same fact.
const KEYS: &str = "\u{21b9}/\u{2191}\u{2193} move \u{b7} \u{2190}/\u{2192} change";

/// Draw the modal as an overlay anchored on the tab content rect.
///
/// `anchor` is the tab content area (D18), never `f.area()`: the header,
/// the menu card and the footer legend stay visible behind the modal.
/// That costs the interior 10 rows — 12 at the declared 80×24 floor —
/// which is why every stage is built on a [`modal_form::ScrollBody`] and
/// rendered through [`modal_form::render_modal`]. It owns the chrome, the
/// height request, the anchor clamp, the two-pass width resolution and
/// the focus-following viewport; `overlay::centered_rect` clamps rather
/// than scrolls, so without that viewport the tail would simply be cut
/// while `Tab` went on reaching the rows that were cut.
pub fn render_overlay(f: &mut Frame, anchor: Rect, modal: &GroupModal) {
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
fn band_text(form: &AddForm) -> (String, &'static str) {
    const DESC: &str = "bind a set of devices to one profile";
    match form.mode {
        FormMode::Add => ("Add group".to_string(), DESC),
        FormMode::Edit => (format!("Edit group \u{b7} {}", form.id), DESC),
    }
}

/// Build the add/edit form as an Archetype-F [`modal_form::ScrollBody`] —
/// pinned head, scrolling field region, pinned tail — plus the real-cursor
/// target (index **within the field region** + caret offset) for the
/// focused text field, if any.
///
/// Every index handed back is relative to the field region, not to the
/// rendered frame. Nothing here branches on `width`:
/// [`modal_form::render_modal`] sizes the chrome from the first build and
/// may call this a second time one column narrower, so a width-dependent
/// row count would silently mis-size the modal
/// (`choice_rows_row_count_never_varies_with_width`).
fn form_body(form: &AddForm, width: u16) -> (modal_form::ScrollBody, Option<(usize, u16)>) {
    let focus = form.focused;
    let chars = |s: &String| s.chars().count() as u16;
    let (title, desc) = band_text(form);
    let mut rows = modal_form::FormRows::new(&title, desc, width);

    // IDENTITY
    rows.section("Identity");
    if form.mode == FormMode::Add {
        let f = focus == FormField::Id;
        rows.text_field(
            modal_form::value_row(
                "id",
                &form.id,
                f,
                ValueKind::Identity,
                Some("e.g. phones or kids-devices"),
                width,
            ),
            f,
            field_hint(FormField::Id),
            chars(&form.id),
        );
    } else {
        // Immutable once created, and `mod.rs::next_editable_group_field`
        // skips it on Edit — so it is a plain row that can never take
        // focus. `false` is hardcoded for that reason: a row that renders
        // as focusable but cannot be reached is the same silent class of
        // defect as a row that can be reached but not seen.
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

    // MEMBERSHIP
    rows.section("Membership");
    let devices = focus == FormField::Devices;
    rows.text_field(
        modal_form::value_row(
            "devices",
            &form.devices,
            devices,
            ValueKind::Identity,
            Some("blank = no members"),
            width,
        ),
        devices,
        field_hint(FormField::Devices),
        chars(&form.devices),
    );
    rows.spacer();

    // POLICY — profile and priority sit together because they are one
    // fact: which single profile a member resolves, and what breaks the
    // tie. The Groups detail card (`tabs/groups.rs`) states the same
    // pairing; the two surfaces must not teach different models.
    rows.section("Policy");
    let profile = focus == FormField::Profile;
    rows.field(
        modal_form::selector_row("profile", form.profile_option_label(), profile, width),
        profile,
        field_hint(FormField::Profile),
    );
    let priority = focus == FormField::Priority;
    rows.text_field(
        modal_form::value_row(
            "priority",
            &form.priority_input,
            priority,
            ValueKind::Editable,
            Some("0"),
            width,
        ),
        priority,
        field_hint(FormField::Priority),
        chars(&form.priority_input),
    );
    // N14: Discard left, Save right — the one `Primary` fill sits
    // right-most on every Archetype-F form (CONTRACT §3.1). The focus
    // ring still reaches `Submit` before `Cancel`, unchanged — same
    // precedent as `profile_modal.rs`'s tail.
    //
    // Discard is `Neutral`, not `Destructive`: it closes the form
    // without writing anything, which is what Esc does too. A filled or
    // red Discard next to a filled Save is how an operator loses work
    // they meant to keep — the ecosystem rule reserves red for an
    // action that actually destroys something (D15).
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
        // Belt and braces: a focus state that renders no row at all —
        // Id on Edit — still gets its guidance, from the
        // same table the rows drew theirs from.
        field_hint(focus),
        KEYS,
        &actions,
    );
    rows.finish(tail)
}

/// One-line description of the focused field, shown on the validation
/// line whenever there is no pending error.
fn field_hint(f: FormField) -> &'static str {
    match f {
        FormField::Id => "short stable key, e.g. phones (immutable on edit)",
        FormField::DisplayName => "human label shown in the table (blank = id)",
        FormField::Devices => "device ids, comma-separated — blank leaves the group empty",
        FormField::Profile => "profile every member resolves — ←/→ to change",
        FormField::Priority => "higher wins when a device is in several groups (blank = 0)",
        FormField::Submit => "Enter saves the group",
        FormField::Cancel => "discard changes and close (also Esc)",
    }
}

/// The Remove confirm as an Archetype-C notice.
///
/// The keying is a single `y` / `n` keypress, no focus ring. The actions
/// are painted with their key in the label because of that — they orient,
/// they are not Tab targets — and **neither is `Primary`, so the modal
/// has no filled button at all**. The one teal fill means "this is the
/// action"; a destructive confirm should not be advertising one.
///
/// The membership count is in the body rather than a footnote because it
/// is the consequence: `groups_for_device` matches on the **forward**
/// list as well as the device-side one, while `remove_inner` refuses only
/// on the device side. A group whose members are listed only here is
/// removable, and those members silently stop resolving its profile.
fn remove_notice(rc: &RemoveConfirm) -> NoticeSpec {
    let members = if rc.devices.is_empty() {
        "no members — nothing changes profile".to_string()
    } else {
        format!("{} member(s): {}", rc.devices.len(), rc.devices.join(", "))
    };
    NoticeSpec {
        hint_rows: None,
        title: "Remove group".to_string(),
        desc: "confirm removal of a policy binding".to_string(),
        prose: vec![
            ProseRow::emphasis(
                format!("{} ({})", rc.id, rc.display_name),
                ValueKind::Blocking,
            ),
            // Kept inside the 62-column body: `prose_row` truncates
            // rather than wrapping, so copy that does not fit loses its
            // last words to an ellipsis.
            ProseRow::plain(members),
            ProseRow::plain(format!(
                "members stop resolving profile \"{}\".",
                rc.profile
            )),
        ],
        choices: Vec::new(),
        error: None,
        hint: "the devices themselves are untouched — only this binding goes".to_string(),
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
/// **The failure branch pins `hint_rows: Some(4)`, and the default of 2
/// was measured to be wrong here, not guessed at.** This screen's Failed
/// state is only ever reached by a **Remove** — a form failure is routed
/// back to the form's inline line by `submit_group_modal`, so it never
/// gets here — and `groups::remove_inner`'s refusal is materially longer
/// than anything the Subnets modal can emit: it names every referring
/// device *and* the remedy command. At [`modal_form::HINT_ROWS`] the
/// remedy was the half that got ellipsed, which is the half that tells
/// the operator what to do.
///
/// Four is a fixed number on purpose — `hint_rows`' own doc-comment
/// explains why a region that resizes to the current text is the defect,
/// not the fix. It costs nothing the Failed branch was using: its `prose`
/// is empty by construction. The `Ok` branch keeps `None`, which resolves
/// to **zero** rows because its message lives in the prose and its hint
/// is empty — pinning 4 there would open a blank band under a success.
///
/// **Residual, stated rather than hidden:** the refusal grows with the
/// member list, so a group with many referring devices can still reach
/// the ellipsis. Four rows covers the refusals in their ordinary shape;
/// no fixed number can cover an unbounded list, and a scrolling tail is
/// not something this archetype has.
fn outcome_notice(outcome: &SubmitOutcome) -> NoticeSpec {
    let (title, desc, prose, error, hint_rows) = match outcome {
        SubmitOutcome::Ok(msg) => (
            "Group \u{b7} done",
            "the change is saved to the configuration file",
            vec![ProseRow::emphasis(msg.clone(), ValueKind::Healthy)],
            None,
            None,
        ),
        SubmitOutcome::Failed(msg) => (
            "Group \u{b7} failed",
            "nothing further was written — reopen the modal to retry",
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

    fn mk_group(id: &str) -> Group {
        Group {
            id: Id::new(id).unwrap(),
            display_name: "Display".into(),
            profile: Id::new("default").unwrap(),
            priority: 0,
            devices: vec![Id::new("phone-1").unwrap()],
        }
    }

    // ── Form-field navigation ─────────────────────────────────────────

    #[test]
    fn form_field_next_cycles_through_seven_in_order() {
        let mut f = FormField::Id;
        let order = [
            FormField::DisplayName,
            FormField::Devices,
            FormField::Profile,
            FormField::Priority,
            FormField::Submit,
            FormField::Cancel,
            FormField::Id,
        ];
        for expected in order {
            f = f.next();
            assert_eq!(f, expected);
        }
    }

    #[test]
    fn form_field_prev_walks_backwards_and_wraps() {
        assert_eq!(FormField::Id.prev(), FormField::Cancel);
        assert_eq!(FormField::DisplayName.prev(), FormField::Id);
    }

    // ── try_resolve validation ────────────────────────────────────────

    #[test]
    fn form_resolve_rejects_empty_id() {
        let modal = GroupModal::open_add(vec!["default".into()], 0);
        let err = modal.form().unwrap().try_resolve().unwrap_err();
        assert!(err.contains("id"), "empty id must error: {err}");
    }

    #[test]
    fn form_resolve_rejects_invalid_priority() {
        let mut modal = GroupModal::open_add(vec!["default".into()], 0);
        modal.form_mut().unwrap().id = "phones".into();
        modal.form_mut().unwrap().priority_input = "not-a-number".into();
        let err = modal.form().unwrap().try_resolve().unwrap_err();
        assert!(err.contains("priority"), "bad priority must error: {err}");
    }

    #[test]
    fn form_resolve_refuses_when_no_profile_vocabulary_exists() {
        // `Group.profile` is MANDATORY (`group.rs`), unlike a device's, so
        // an empty snapshot cannot produce a group and `try_resolve` must
        // say which thing is missing instead of letting `add_inner` fail
        // on an empty string.
        //
        // **Defensive, not operator-facing.** `server.default_profile` is
        // mandatory and validated, so a config that LOADS always carries
        // at least one profile — and `handle_groups_key` refuses to open
        // this modal at all when the config did not load
        // (`no_key_opens_a_modal_when_the_config_did_not_load`). No
        // operator path reaches this branch today. It is pinned because
        // `open_add` takes the snapshot as a parameter: a future caller
        // that passes an empty one gets a named error rather than a
        // confusing failure from two layers down.
        let mut modal = GroupModal::open_add(Vec::new(), 0);
        modal.form_mut().unwrap().id = "phones".into();
        let err = modal.form().unwrap().try_resolve().unwrap_err();
        assert!(err.contains("no profiles"), "got: {err}");
    }

    #[test]
    fn form_resolve_accepts_an_empty_membership() {
        // The deliberate divergence from the Subnets template: a subnet
        // with no CIDRs matches nothing and is refused, but a group with
        // no members is a legal, inert policy binding and
        // `groups::add_inner` accepts one. Refusing it here would make
        // the TUI stricter than the CLI for no reason.
        let mut modal = GroupModal::open_add(vec!["default".into()], 0);
        modal.form_mut().unwrap().id = "phones".into();
        let resolved = modal.form().unwrap().try_resolve().unwrap();
        assert!(resolved.devices.is_empty());
    }

    #[test]
    fn form_resolve_splits_and_trims_comma_separated_devices() {
        let mut modal = GroupModal::open_add(vec!["default".into()], 0);
        let form = modal.form_mut().unwrap();
        form.id = "phones".into();
        form.devices = " phone-1 , phone-2 ,, phone-3 ".into();
        let resolved = modal.form().unwrap().try_resolve().unwrap();
        assert_eq!(resolved.devices, vec!["phone-1", "phone-2", "phone-3"]);
    }

    #[test]
    fn form_resolve_defaults_display_name_to_id() {
        let mut modal = GroupModal::open_add(vec!["default".into()], 0);
        modal.form_mut().unwrap().id = "phones".into();
        let resolved = modal.form().unwrap().try_resolve().unwrap();
        assert_eq!(resolved.display_name, "phones");
    }

    // ── Edit modal ────────────────────────────────────────────────────

    #[test]
    fn edit_modal_captures_snapshot_at_open() {
        let g = mk_group("phones");
        let modal = GroupModal::open_edit(&g, vec!["default".into(), "kids".into()]);
        let form = modal.form().unwrap();
        assert_eq!(form.mode, FormMode::Edit);
        assert_eq!(form.id, "phones");
        assert_eq!(form.devices, "phone-1");
        let orig = form.original.as_ref().expect("Edit captures the original");
        assert_eq!(orig.id, "phones");
        assert_eq!(orig.profile, "default");
        assert_eq!(orig.devices, vec!["phone-1".to_string()]);
    }

    #[test]
    fn edit_modal_falls_back_to_first_profile_when_unknown() {
        let mut g = mk_group("phones");
        g.profile = Id::new("ghost").unwrap();
        let modal = GroupModal::open_edit(&g, vec!["default".into()]);
        assert_eq!(modal.form().unwrap().profile_idx, 0);
    }

    // ── Remove modal ──────────────────────────────────────────────────

    #[test]
    fn remove_modal_carries_the_forward_membership_list() {
        // Not decoration. `groups_for_device` matches on `g.devices` as
        // well as `d.groups`, but `remove_inner` refuses only on the
        // device-side back-reference — so this list is exactly the set of
        // devices that will silently change profile, and the operator has
        // to be able to see it before pressing `y`.
        let g = mk_group("phones");
        let modal = GroupModal::open_remove(&g);
        let rc = modal.remove().unwrap();
        assert_eq!(rc.id, "phones");
        assert_eq!(rc.devices, vec!["phone-1".to_string()]);
        assert_eq!(rc.profile, "default");
    }

    // ── Lifecycle ─────────────────────────────────────────────────────

    #[test]
    fn modal_finish_transitions_to_submitted() {
        let mut modal = GroupModal::open_add(vec!["default".into()], 0);
        assert!(!modal.is_submitted());
        modal.finish(SubmitOutcome::Ok("done".into()));
        assert!(modal.is_submitted());
    }

    // ── Render ────────────────────────────────────────────────────────

    /// Flatten the whole body — head, field region, tail — into one
    /// string for content assertions.
    ///
    /// The *line vector*, deliberately: it is enough for "is this row
    /// composed correctly", and useless for "is this row on screen". The
    /// floor tests below assert on the rendered buffer instead.
    fn render_text(form: &AddForm, width: u16) -> String {
        let (body, _) = form_body(form, width);
        body.head
            .iter()
            .chain(body.fields.iter())
            .chain(body.tail.iter())
            .map(|l| {
                l.spans
                    .iter()
                    .map(|s| s.content.as_ref())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
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

    fn render_overlay_in(modal: &GroupModal, w: u16, h: u16) -> String {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;
        let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
        term.draw(|f| render_overlay(f, f.area(), modal)).unwrap();
        dump_buffer(term.backend().buffer())
    }

    // `plp-s5d` removed `ux2_the_armed_valve_is_visible_in_the_groups_modal`
    // with the tags picker it tested — see the identical note in
    // `subnet_modal.rs`. No substitute assertion: the guarantee left with
    // the surface. The shared valve is still tested in
    // `tabs::lists::commit_tag_picker`.

    #[test]
    fn form_renders_banded_sections_and_the_active_marker() {
        let mut modal = GroupModal::open_add(vec!["default".into()], 0);
        let form = modal.form_mut().unwrap();
        form.id = "phones".into(); // focus defaults to Id on Add
        let text = render_text(form, 60);

        assert!(
            text.contains("IDENTITY") && text.contains("MEMBERSHIP") && text.contains("POLICY"),
            "labelled section bands:\n{text}"
        );
        assert!(
            !text.contains("phones_"),
            "the `_` caret is the cursor's job"
        );
        assert!(text.contains("phones"), "the focused value still renders");
        assert!(text.contains('◀'), "active row carries the focus marker");
        assert!(text.contains("Save") && text.contains("Discard"));
    }

    #[test]
    fn focused_text_field_hosts_the_real_cursor() {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;
        let mut modal = GroupModal::open_add(vec!["default".into()], 0);
        modal.form_mut().unwrap().id = "phones".into();

        let mut term = Terminal::new(TestBackend::new(100, 44)).unwrap();
        term.draw(|f| render_overlay(f, f.area(), &modal)).unwrap();
        let pos = term.get_cursor_position().unwrap();

        let dump = dump_buffer(term.backend().buffer());
        // Located by the focus marker, not by the value: exactly one row
        // carries `◀`.
        let row = dump
            .lines()
            .position(|l| l.contains('\u{25c0}'))
            .expect("the focused row must be on screen") as u16;
        assert!(
            dump.lines().nth(row as usize).unwrap().contains("phones"),
            "the focused row is the id row:\n{dump}"
        );
        assert_eq!(pos.y, row, "cursor must sit on the focused row:\n{dump}");
        // Modal is 64 wide and centred in 100 columns → inner left edge is
        // 18 + 1 border; the caret lands VALUE_COL + len("phones") in.
        let inner_x = (100 - 64) / 2 + 1;
        assert_eq!(
            pos.x,
            inner_x + modal_form::VALUE_COL as u16 + 6,
            "cursor must sit at the end of the typed value:\n{dump}"
        );
    }

    #[test]
    fn focused_selector_is_wrapped_in_angle_brackets() {
        let mut modal = GroupModal::open_add(vec!["default".into()], 0);
        modal.form_mut().unwrap().focused = FormField::Profile;
        let text = render_text(modal.form().unwrap(), 60);
        assert!(
            text.contains("‹ default ›"),
            "a focused selector value is wrapped to signal ←/→ cycles it"
        );
    }

    #[test]
    fn inline_error_replaces_the_hint_line() {
        let mut modal = GroupModal::open_add(vec!["default".into()], 0);
        modal.form_mut().unwrap().error_message = Some("id is required".into());
        let text = render_text(modal.form().unwrap(), 60);
        assert!(text.contains("⚠ id is required"), "error shows inline");
        // The hint for the (default-focused) Id field is suppressed while
        // an error is pending.
        assert!(!text.contains("short stable key"));
    }

    #[test]
    fn edit_id_is_read_only_without_caret() {
        let g = mk_group("phones");
        let modal = GroupModal::open_edit(&g, vec!["default".into()]);
        let form = modal.form().unwrap();
        assert_eq!(form.focused, FormField::DisplayName);
        let text = render_text(form, 60);
        assert!(text.contains("phones"), "id value still shown");
        assert!(!text.contains("phones_"), "read-only id carries no caret");
        assert!(
            !text.contains("(read-only)"),
            "dim styling signals read-only, not literal suffix text"
        );
    }

    // ── The 80×24 floor ──────────────────────────────────────────────
    //
    // `ui.rs` declares MIN_WIDTH 80 × MIN_HEIGHT 24. At that size the tab
    // content rect this overlay anchors on (D18) is
    // `24 − 4 header − 5 menu card − 1 footer = 14` rows.
    // `overlay::centered_rect` CLAMPS rather than scrolls, so a body
    // taller than that is silently cut at the bottom while `Tab` still
    // moves focus onto the rows that were cut — the operator then commits
    // or discards blind.

    fn edit_modal_for_floor() -> GroupModal {
        let g = mk_group("phones");
        let mut modal = GroupModal::open_edit(&g, vec!["default".into()]);
        let form = modal.form_mut().unwrap();
        form.display_name = "Family phones".into();
        form.devices = "phone-1, phone-2".into();
        form.priority_input = "77".into();
        modal
    }

    #[test]
    fn floor_keeps_the_action_row_and_the_focused_field_on_screen_together() {
        let mut modal = edit_modal_for_floor();
        modal.form_mut().unwrap().focused = FormField::Priority;
        let dump = render_overlay_in(&modal, 80, 14);

        assert!(
            dump.contains("Save"),
            "action row cut at the 80x24 floor — Tab still reaches it:\n{dump}"
        );
        assert!(
            dump.contains("Discard"),
            "Discard cut at the floor:\n{dump}"
        );
        assert!(
            dump.contains("77"),
            "the focused field's value is off-screen:\n{dump}"
        );
        assert!(
            dump.contains('\u{25c0}'),
            "the focus marker must be on screen with the action row:\n{dump}"
        );
    }

    #[test]
    fn floor_viewport_follows_focus_onto_the_last_field() {
        // `plp-s5d`: Tags WAS the last editable field on Edit; with the
        // picker gone, Priority is. The property is unchanged — the
        // viewport must scroll to the last field and therefore scroll the
        // *first* one out. Without that second half the assertion passes
        // on a body that only ever renders page one.
        let mut modal = edit_modal_for_floor();
        modal.form_mut().unwrap().focused = FormField::Priority;
        let dump = render_overlay_in(&modal, 80, 14);

        assert!(
            dump.contains("77"),
            "focused last field is off-screen:\n{dump}"
        );
        assert!(
            dump.contains("Save"),
            "action row cut while focus sits on the last field:\n{dump}"
        );
        assert!(
            !dump.contains("Family phones"),
            "a short viewport cannot be showing both ends of the form:\n{dump}"
        );
    }

    #[test]
    fn floor_add_mode_keeps_the_action_row_and_the_focused_field_together() {
        // Add is a different body from Edit — `id` is a focusable text
        // field — so the viewport arithmetic differs and it gets its own
        // floor assertion rather than riding on Edit's. (Before `plp-s5d`
        // the Edit body also carried two tags rows Add never had; that
        // difference is gone, the `id` one is not.)
        let mut modal = GroupModal::open_add(vec!["default".into()], 0);
        modal.form_mut().unwrap().focused = FormField::Priority; // last Add field
        let dump = render_overlay_in(&modal, 80, 14);

        assert!(
            dump.contains("priority"),
            "focused priority row is off-screen:\n{dump}"
        );
        assert!(dump.contains("Save"), "action row cut in Add mode:\n{dump}");
        assert!(
            !dump.contains("display name"),
            "the viewport must have scrolled past the first field:\n{dump}"
        );
    }

    #[test]
    fn floor_remove_confirm_shows_the_members_and_the_key_legend() {
        // The destructive stage. The member list is the whole reason this
        // screen exists — `remove_inner` does NOT refuse on the forward
        // list, so these are the devices that silently change profile.
        let modal = GroupModal {
            stage: Stage::ConfirmingRemove(RemoveConfirm {
                id: "phones".into(),
                display_name: "Family phones".into(),
                profile: "kids".into(),
                devices: vec!["phone-1".into(), "phone-2".into()],
            }),
        };
        let dump = render_overlay_in(&modal, 80, 14);

        assert!(
            dump.contains("phones (Family phones)"),
            "the operator must see which group they are removing:\n{dump}"
        );
        assert!(
            dump.contains("phone-1") && dump.contains("phone-2"),
            "the members that lose this binding must be named:\n{dump}"
        );
        assert!(
            dump.contains("[y] confirm") && dump.contains("[y] Remove"),
            "the y/n keying must stay legible:\n{dump}"
        );
    }

    #[test]
    fn submit_failure_wraps_instead_of_clipping_at_one_line() {
        // The REAL refusal string `groups::remove_inner` emits — not the
        // Subnets modal's, which is materially shorter. It names every
        // referring device AND the remedy command, so if this copy did
        // not hard-wrap through `NoticeSpec::error` the operator would
        // lose exactly the half that tells them what to do.
        let long = "group \"phones\" still appears in the groups field of device(s): \
                    phone-1, phone-2. Remove the reference first with \
                    `warden device set <device> groups <remaining-list>`.";
        let modal = GroupModal {
            stage: Stage::Submitted(SubmitOutcome::Failed(long.into())),
        };
        let dump = render_overlay_in(&modal, 80, 14);

        assert!(
            dump.contains('\u{26a0}'),
            "a failure carries the ⚠ affordance:\n{dump}"
        );
        assert!(
            dump.contains("remaining-list"),
            "the tail of the message — the remedy — must survive the wrap:\n{dump}"
        );
    }

    #[test]
    fn overlay_is_confined_to_the_anchor_rect() {
        // D18: the anchor is the tab content rect, so the header, the
        // menu card and the footer legend stay visible behind the modal.
        // Anchoring on `f.area()` instead paints over all three.
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;
        let anchor = Rect {
            x: 0,
            y: 9,
            width: 80,
            height: 14,
        };
        let modal = edit_modal_for_floor();
        let mut term = Terminal::new(TestBackend::new(80, 24)).unwrap();
        term.draw(|f| render_overlay(f, anchor, &modal)).unwrap();
        let dump = dump_buffer(term.backend().buffer());

        for (y, row) in dump.lines().enumerate() {
            let outside = y < anchor.y as usize || y >= (anchor.y + anchor.height) as usize;
            if outside {
                assert!(
                    row.trim().is_empty(),
                    "row {y} is outside the anchor but was painted: {row:?}\n{dump}"
                );
            }
        }
    }

    /// The clip-guard: the tallest this modal's content can get must not
    /// push Save/Discard off the bottom.
    ///
    /// **`plp-s5d` retargeted this from the tags picker to `devices`**, for
    /// the reason spelled out on the `subnet_modal.rs` twin: the picker was
    /// the tallest field, so deleting it would have left this guard with
    /// nothing tall to guard against — green forever, measuring nothing.
    /// `devices` is the surviving unbounded field (free text, one
    /// comma-separated line).
    #[test]
    fn render_overlay_keeps_save_discard_visible_with_an_overlong_devices_field() {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;

        let g = mk_group("phones");
        let mut modal = GroupModal::open_edit(&g, vec!["default".into()]);
        let form = modal.form_mut().unwrap();
        form.focused = FormField::Devices;
        // No spaces — `Wrap` can't break at a word boundary, so this
        // hard-wraps character-by-character.
        form.devices = "x".repeat(300);

        let mut term = Terminal::new(TestBackend::new(100, 24)).unwrap();
        term.draw(|f| render_overlay(f, f.area(), &modal)).unwrap();

        let dump = dump_buffer(term.backend().buffer());
        assert!(
            dump.contains("xxxx"),
            "the overlong field must actually be rendering — without this the \
             Save/Discard assertion below passes on a short body:\n{dump}"
        );
        assert!(
            dump.contains("Save") && dump.contains("Discard"),
            "the button row must survive an overlong field:\n{dump}"
        );
    }

    #[test]
    fn no_hand_rolled_colour_in_this_module() {
        // The ecosystem colour rule as a test rather than a claim in a
        // commit message. A surface that reaches for the theme directly is
        // a surface that will drift from the other twelve. Needles are
        // split so this assertion cannot match itself.
        let src = include_str!("group_modal.rs");
        for needle in [
            concat!("Style::default()", ".fg("),
            concat!("Color", "::Rgb("),
            concat!("T", ".brand_red"),
        ] {
            assert!(
                !src.contains(needle),
                "{needle} in group_modal.rs — the colour belongs in modal_form"
            );
        }
    }

    #[test]
    #[ignore = "visual aid: cargo test group_visual_dump -- --ignored --nocapture"]
    fn group_visual_dump() {
        let mut modal = edit_modal_for_floor();
        modal.form_mut().unwrap().focused = FormField::Devices;
        println!(
            "--- roomy anchor ---\n{}",
            render_overlay_in(&modal, 100, 40)
        );
        println!(
            "--- the 80x24 floor (14-row content rect) ---\n{}",
            render_overlay_in(&modal, 80, 14)
        );
        modal.form_mut().unwrap().focused = FormField::Priority;
        println!(
            "--- same, focus on the last field ---\n{}",
            render_overlay_in(&modal, 80, 14)
        );
        let rc = RemoveConfirm {
            id: "phones".into(),
            display_name: "Family phones".into(),
            profile: "kids".into(),
            devices: vec!["phone-1".into(), "phone-2".into()],
        };
        println!(
            "--- remove confirm (Archetype C) ---\n{}",
            render_overlay_in(
                &GroupModal {
                    stage: Stage::ConfirmingRemove(rc)
                },
                80,
                14
            )
        );
    }
}
