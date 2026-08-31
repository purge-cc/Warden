//! Sprint 51 T3 — Subnets tab modals (Add / Edit / Delete).
//!
//! Opens over [`crate::tui::app::Leaf::Subnets`] via `a` (Add), `e`
//! (Edit), `d` / Delete (Remove), or `Enter` on a discovered candidate
//! row (promote-from-suggestion → Add modal pre-filled with the
//! candidate's CIDR + a synthesised display name). Submits through
//! `cli::commands::subnets::{add_inner, set_inner, remove_inner}` —
//! same R7 single-seat path the CLI verbs use, so audit emissions are
//! byte-identical between the two surfaces.
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
//! When `a` / `e` / `d` is pressed, the openers in `tui/mod.rs`
//! snapshot every value the modal needs (the focused row's record,
//! the list of profile ids known at this moment) into the
//! [`SubnetModal`] state. Subsequent renders / refreshes / tab
//! scrolls cannot invalidate the snapshot — submitting always uses
//! the captured values, never re-reads `loaded_config`. Mirrors the
//! `local_dns_modal` precedent (S44).
//!
//! ## CIDR input
//!
//! The CIDR field accepts the friendly forms wired up by S50 T2 —
//! `10.14.0.*`, `10.14.0.0-10.14.0.255`, bare addresses, plain CIDR.
//! Translation happens at submit time inside `add_inner` /
//! `set_inner` (which call `Cidr::parse_friendly` internally), so the
//! operator sees a friendly error before the file is touched if their
//! input is ambiguous.

use crate::config::cidr::Cidr;
use crate::config::schema::Subnet;

/// Top-level modal lifecycle. `None` on `app.subnets.modal` means no
/// modal is open; a `Some` variant grabs every keystroke until either
/// submit lands a [`Stage::Submitted`] outcome or the operator
/// presses Esc.
#[derive(Debug, Clone)]
pub struct SubnetModal {
    pub stage: Stage,
}

// `EditingForm` carries the full `AddForm` (the retired tags picker added three
// more fields on top of the existing string buffers); `ConfirmingRemove`
// / `Submitted` are small. Boxing the large variant to equalize sizes
// would add a heap alloc + deref per keystroke for no measurable benefit
// — the modal is constructed once per operator action, never on a hot
// path. Mirrors the `ProfileModal` / `DeviceModal` precedent.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone)]
pub enum Stage {
    /// Add or Edit form. The discriminant inside `AddForm` selects
    /// the title bar + the submit dispatch path.
    EditingForm(AddForm),
    /// Remove confirmation. Single-key y/n — subnets are scope-narrow
    /// (SN2 tier 1 per the design doc), no typed-phrase tier needed.
    ConfirmingRemove(RemoveConfirm),
    /// Final state — the modal renders the success or error message
    /// and closes on the next keypress.
    Submitted(SubmitOutcome),
}

#[derive(Debug, Clone)]
pub enum SubmitOutcome {
    Ok(String),
    Failed(String),
}

/// Form mode discriminator — drives title bar, submit behaviour, and
/// (for Edit) which entity gets updated via `set_inner`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormMode {
    Add,
    /// Edit carries the original id snapshot so the submit path knows
    /// which entity to update. `set_inner` only touches one field at
    /// a time, so the submit walks every field that diverges from the
    /// captured snapshot.
    Edit,
}

/// Editable fields exposed by the form, in tab order. Mirror of
/// `local_dns_modal::FormField` — keep in sync with [`FormField::ALL`]
/// and the renderer's per-field highlight logic. `Submit` then `Cancel`
/// are the two action buttons (Save / Discard) at the bottom of the grid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormField {
    Id,
    DisplayName,
    Cidrs,
    Profile,
    Priority,
    Submit,
    Cancel,
}

#[derive(Debug, Clone)]
pub struct AddForm {
    pub mode: FormMode,
    /// Snapshot of the original entity at modal-open time. Set on
    /// Edit so the submit path knows which id to update + which
    /// fields actually changed. `None` on Add.
    pub original: Option<OriginalSnapshot>,
    pub focused: FormField,
    pub id: String,
    pub display_name: String,
    /// Raw operator input — single line. Multiple CIDRs separated by
    /// commas (mirrors `warden subnet add --cidrs ...`). Translated
    /// via `Cidr::parse_friendly` inside `add_inner` / `set_inner`,
    /// so wildcards (`10.99.0.*`) and ranges
    /// (`10.99.0.0-10.99.0.255`) round-trip transparently.
    pub cidrs: String,
    /// Snapshot of profile ids captured at modal-open time. The
    /// dropdown rendering walks this slice; the running config can
    /// change profiles in/out from under us during the form's
    /// lifetime, but the captured snapshot stays authoritative.
    pub profiles_snapshot: Vec<String>,
    /// Index into `profiles_snapshot`. Always points at a valid slot
    /// when `profiles_snapshot.len() > 0`; 0 when the snapshot is
    /// empty (the submit then errors with "no profiles defined").
    pub profile_idx: usize,
    /// Raw operator input — parsed to `i32` at submit. Empty string
    /// means 0 (the default per `Subnet::default_priority`).
    pub priority_input: String,
    /// Inline validation / submit error rendered at the bottom of
    /// the form. Cleared on the next field edit.
    pub error_message: Option<String>,
}

/// Original entity snapshot captured when an Edit modal opens.
#[derive(Debug, Clone)]
pub struct OriginalSnapshot {
    pub id: String,
    pub display_name: String,
    pub cidrs: Vec<String>,
    pub profile: String,
    pub priority: i32,
}

#[derive(Debug, Clone)]
pub struct RemoveConfirm {
    pub id: String,
    pub display_name: String,
    pub cidrs: Vec<String>,
}

impl FormField {
    pub const ALL: [FormField; 7] = [
        FormField::Id,
        FormField::DisplayName,
        FormField::Cidrs,
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
    /// dropdown lands on when the form opens — typically 0, but the
    /// caller may pass a different index (e.g. to land on the
    /// default profile instead of the first alphabetical entry).
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
            cidrs: String::new(),
            profiles_snapshot,
            profile_idx,
            priority_input: String::new(),
            error_message: None,
        }
    }

    /// Pre-filled form for `Add` from a discovered candidate
    /// (promote-from-suggestion). Pre-fills `cidrs` with the canonical
    /// bucket CIDR; synthesises a display name like `lan-10-14-0`
    /// from the bucket. The `id` stays empty so the operator must
    /// make a conscious choice — the synthesised display name is a
    /// hint, not a commitment.
    pub fn new_promote(
        cidr: &str,
        profiles_snapshot: Vec<String>,
        default_profile_idx: usize,
    ) -> Self {
        let mut form = Self::new_add(profiles_snapshot, default_profile_idx);
        form.cidrs = cidr.to_string();
        form.display_name = synthesise_display_name(cidr);
        form
    }

    /// Pre-filled form for `Edit`. The entity's existing fields
    /// populate each input; the original snapshot is stashed so the
    /// submit path can drive `set_inner` for each diverging field.
    pub fn new_edit(subnet: &Subnet, profiles_snapshot: Vec<String>) -> Self {
        let profile_idx = profiles_snapshot
            .iter()
            .position(|p| p == subnet.profile.as_str())
            .unwrap_or(0);
        Self {
            mode: FormMode::Edit,
            original: Some(OriginalSnapshot {
                id: subnet.id.as_str().to_string(),
                display_name: subnet.display_name.clone(),
                cidrs: subnet.cidrs.clone(),
                profile: subnet.profile.as_str().to_string(),
                priority: subnet.priority,
            }),
            focused: FormField::DisplayName, // id is not editable
            id: subnet.id.as_str().to_string(),
            display_name: subnet.display_name.clone(),
            cidrs: subnet.cidrs.join(", "),
            profiles_snapshot,
            profile_idx,
            priority_input: subnet.priority.to_string(),
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

    /// Resolve the form into the (id, display_name, cidrs, profile,
    /// priority) tuple ready to feed into `add_inner`. Performs the
    /// pre-flight validation that does NOT need filesystem access:
    /// empty fields, malformed priority, empty CIDR list. Does NOT
    /// validate individual CIDRs — that happens inside `add_inner`
    /// via `Cidr::parse_friendly` so the operator sees the same
    /// friendly error there as the CLI does.
    pub fn try_resolve(&self) -> Result<ResolvedForm, String> {
        let id_trim = self.id.trim();
        if id_trim.is_empty() {
            return Err("id is required".into());
        }
        let display_trim = self.display_name.trim();
        let cidrs_parts: Vec<String> = self
            .cidrs
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        if cidrs_parts.is_empty() {
            return Err("at least one CIDR is required".into());
        }
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
            cidrs: cidrs_parts,
            profile,
            priority,
        })
    }
}

/// Output of [`AddForm::try_resolve`] — the modal-side view of an
/// add/edit submission. The submit path threads it into `add_inner`
/// (Add) or walks the diff against `original` to fire `set_inner`
/// once per changed field (Edit).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedForm {
    pub id: String,
    pub display_name: String,
    pub cidrs: Vec<String>,
    pub profile: String,
    pub priority: i32,
}

/// Parse the operator's priority input. Empty → 0 (default).
/// Otherwise parse i32 and surface a friendly error.
fn parse_priority(input: &str) -> Result<i32, String> {
    let t = input.trim();
    if t.is_empty() {
        return Ok(0);
    }
    t.parse::<i32>()
        .map_err(|_| format!("priority must be an integer, got '{t}'"))
}

/// Synthesise a display name from a candidate bucket CIDR. `10.14.0.0/24`
/// → `lan-10-14-0`. IPv6 buckets use a `lan6-` prefix and the first
/// four hex segments. Best-effort: malformed input falls back to
/// `lan-discovered`.
pub fn synthesise_display_name(cidr: &str) -> String {
    if let Ok(c) = Cidr::parse(cidr) {
        match c {
            Cidr::V4 { network, .. } => {
                let bytes = network.to_be_bytes();
                format!("lan-{}-{}-{}", bytes[0], bytes[1], bytes[2])
            }
            Cidr::V6 { network, .. } => {
                let segs = std::net::Ipv6Addr::from(network).segments();
                format!(
                    "lan6-{:x}-{:x}-{:x}-{:x}",
                    segs[0], segs[1], segs[2], segs[3]
                )
            }
        }
    } else {
        "lan-discovered".to_string()
    }
}

impl SubnetModal {
    /// Open an Add modal.
    pub fn open_add(profiles_snapshot: Vec<String>, default_profile_idx: usize) -> Self {
        Self {
            stage: Stage::EditingForm(AddForm::new_add(profiles_snapshot, default_profile_idx)),
        }
    }

    /// Open a promote-from-suggestion modal — Add modal pre-filled
    /// with the candidate's CIDR + a synthesised display name.
    pub fn open_promote(
        cidr: &str,
        profiles_snapshot: Vec<String>,
        default_profile_idx: usize,
    ) -> Self {
        Self {
            stage: Stage::EditingForm(AddForm::new_promote(
                cidr,
                profiles_snapshot,
                default_profile_idx,
            )),
        }
    }

    /// Open an Edit modal pre-filled from the focused subnet.
    pub fn open_edit(subnet: &Subnet, profiles_snapshot: Vec<String>) -> Self {
        Self {
            stage: Stage::EditingForm(AddForm::new_edit(subnet, profiles_snapshot)),
        }
    }

    /// Open a Remove modal at single-keypress confirm tier.
    pub fn open_remove(subnet: &Subnet) -> Self {
        Self {
            stage: Stage::ConfirmingRemove(RemoveConfirm {
                id: subnet.id.as_str().to_string(),
                display_name: subnet.display_name.clone(),
                cidrs: subnet.cidrs.clone(),
            }),
        }
    }

    /// Mark the modal as submitted with the given outcome — caller
    /// closes it on the next keypress.
    pub fn finish(&mut self, outcome: SubmitOutcome) {
        self.stage = Stage::Submitted(outcome);
    }

    /// Whether the modal is currently in a submitted state — used
    /// by the keyhandler to close on the next keypress.
    pub fn is_submitted(&self) -> bool {
        matches!(self.stage, Stage::Submitted(_))
    }

    /// Convenience: borrow the form when the stage is editing.
    /// Test-only.
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

// ── Render (§4.61 Wave 2a — Archetype F / C via `modal_form`) ─────────
//
// Every span in this module comes out of `modal_form`; not one colour is
// chosen here. That is the wave's acceptance criterion, not an aesthetic
// preference: the ecosystem colour rule has exactly one implementation,
// so twelve surfaces cannot drift apart. Pinned by
// `no_hand_rolled_colour_in_this_module` below.

use ratatui::layout::Rect;
use ratatui::Frame;

use crate::tui::modal_form::{self, Action, ActionKind, NoticeSpec, ProseRow, ValueKind};

/// Nav-key legend copy. Byte-identical to the legacy
/// `modal_form::keys_line()` string this modal used before the
/// migration — §4.61 D7′ changes chrome, layout and colour and leaves
/// the keying alone, so the legend it advertises must not move either.
///
/// N14 stripped the save/cancel clause: the action row now bakes its
/// own key into each button's label (`[Esc] Discard` / `[Enter] Save`),
/// so a blanket "Enter save · Esc cancel" here would be a second,
/// redundant source of the same fact.
const KEYS: &str = "\u{21b9}/\u{2191}\u{2193} move \u{b7} \u{2190}/\u{2192} change";

/// Draw the modal as an overlay anchored on the tab content rect.
/// Branches on the stage so the operator sees the form, the confirm
/// prompt, or the outcome at the right moment.
///
/// `anchor` is the tab content area (§4.61 D18), never `f.area()`: the
/// header, the menu card and the footer legend stay visible behind the
/// modal. That costs the interior 10 rows — 12 at the declared 80×24
/// floor, against a body of ~23 — which is why every stage here is built
/// on a [`modal_form::ScrollBody`] and rendered through
/// [`modal_form::render_modal`]. It owns the chrome, the height request,
/// the anchor clamp, the two-pass width resolution and the
/// focus-following viewport; `overlay::centered_rect` clamps rather than
/// scrolls, so without that viewport the tail would simply be cut while
/// `Tab` went on reaching the rows that were cut.
///
/// The border accent is deliberately not a parameter any more: chrome
/// stays neutral grey and `brand_red` is never a border (D15). The
/// Remove confirm and the outcome screens carry their meaning in the
/// body — a `Blocking`/`Healthy` value colour — instead of in the frame.
pub fn render_overlay(f: &mut Frame, anchor: Rect, modal: &SubnetModal) {
    const W: u16 = 64;
    match &modal.stage {
        Stage::EditingForm(form) => {
            let render = modal_form::render_modal(f, anchor, W, |w| form_body(form, w));
            // The `_` caret of the old grid is gone; the focused text
            // field hosts the real terminal cursor, as the Lists
            // reference does. `place_cursor` no-ops when that row is
            // scrolled out of view.
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
    const DESC: &str = "map a range of client addresses to the profile they get";
    match form.mode {
        FormMode::Add => ("Add subnet".to_string(), DESC),
        FormMode::Edit => (format!("Edit subnet \u{b7} {}", form.id), DESC),
    }
}

/// Build the add/edit form as an Archetype-F [`modal_form::ScrollBody`] —
/// pinned head, scrolling field region, pinned tail — plus the
/// real-cursor target (index **within the field region** + caret offset)
/// for the focused text field, if any.
///
/// Every index handed back is relative to the field region, not to the
/// rendered frame: how many of those rows are on screen is the
/// renderer's decision, not this builder's. Nothing here branches on
/// `width` — [`modal_form::render_modal`] sizes the chrome from the
/// first build and may call this a second time one column narrower, so a
/// width-dependent row count would silently mis-size the modal.
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
                Some("e.g. lan or guest-wifi"),
                width,
            ),
            f,
            field_hint(FormField::Id),
            chars(&form.id),
        );
    } else {
        // Immutable once created, and `mod.rs::next_editable_field` skips
        // it on Edit — so it is a plain row that can never take focus.
        // `false` is hardcoded for that reason: a row that renders as
        // focusable but cannot be reached is the same silent class of
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

    // RANGE
    rows.section("Range");
    let cidrs = focus == FormField::Cidrs;
    rows.text_field(
        modal_form::value_row(
            "cidrs",
            &form.cidrs,
            cidrs,
            ValueKind::Identity,
            Some("10.99.0.* or 10.99.0.0/24"),
            width,
        ),
        cidrs,
        field_hint(FormField::Cidrs),
        chars(&form.cidrs),
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
    rows.spacer();

    // POLICY
    rows.section("Policy");
    let profile = focus == FormField::Profile;
    rows.field(
        modal_form::selector_row("profile", form.profile_option_label(), profile, width),
        profile,
        field_hint(FormField::Profile),
    );
    // N14: Discard left, Save right — the one `Primary` fill sits
    // right-most on every Archetype-F form (CONTRACT §3.1). The focus
    // ring still reaches `Submit` before `Cancel`, unchanged — same
    // precedent as `profile_modal.rs`'s tail.
    //
    // Discard is `Neutral`, not `Destructive`, despite throwing the
    // operator's typed input away: Esc does the identical thing, and a
    // filled or red Discard next to a filled Save is how an operator
    // loses work they meant to keep. Red stays reserved for an action
    // that destroys something already saved (D15).
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
        // Id on Edit — still gets its guidance, from the same table the
        // rows drew theirs from.
        field_hint(focus),
        KEYS,
        &actions,
    );
    rows.finish(tail)
}

/// One-line description of the focused field, shown on the validation
/// line whenever there is no pending error. The CIDR line preserves the
/// friendly-form guidance that used to sit on a permanent footer hint.
fn field_hint(f: FormField) -> &'static str {
    match f {
        FormField::Id => "short stable key, e.g. lan or guest-wifi (immutable on edit)",
        FormField::DisplayName => "human label shown in the table (blank = id)",
        FormField::Cidrs => "10.99.0.*, 10.99.0.0-10.99.0.255 or /24 — comma-separated",
        FormField::Profile => "profile applied to clients in range — ←/→ to change",
        FormField::Priority => "higher wins when ranges overlap (blank = 0)",
        FormField::Submit => "Enter saves the subnet",
        FormField::Cancel => "discard changes and close (also Esc)",
    }
}

/// The Remove confirm as an Archetype-C notice.
///
/// The keying is unchanged (D7′): a single `y` / `n` keypress, no focus
/// ring. The actions are painted with their key in the label because of
/// that — they orient, they are not Tab targets — and **neither is
/// `Primary`, so the modal has no filled button at all**. The one teal
/// fill means "this is the action"; a destructive confirm should not be
/// advertising one.
fn remove_notice(rc: &RemoveConfirm) -> NoticeSpec {
    NoticeSpec {
        hint_rows: None,
        title: "Remove subnet".to_string(),
        desc: "confirm removal of a configured range".to_string(),
        prose: vec![
            ProseRow::emphasis(
                format!("{} ({})", rc.id, rc.display_name),
                ValueKind::Blocking,
            ),
            ProseRow::plain(format!("cidrs: {}", rc.cidrs.join(", "))),
            // Kept inside the 62-column body: `prose_row` truncates
            // rather than wrapping, so copy that does not fit loses its
            // last words to an ellipsis.
            ProseRow::plain("devices in range fall back to the global default profile."),
        ],
        choices: Vec::new(),
        error: None,
        hint: "device mappings are untouched — only resolution by range changes".to_string(),
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
/// hard-wraps to [`modal_form::HINT_ROWS`] rows, and a validator refusal
/// carried up from `set_fields_inner` is long enough to run off the end
/// of the single non-wrapping line this used to be.
fn outcome_notice(outcome: &SubmitOutcome) -> NoticeSpec {
    let (title, desc, prose, error) = match outcome {
        SubmitOutcome::Ok(msg) => (
            "Subnet \u{b7} done",
            "the change is saved to the configuration file",
            vec![ProseRow::emphasis(msg.clone(), ValueKind::Healthy)],
            None,
        ),
        SubmitOutcome::Failed(msg) => (
            "Subnet \u{b7} failed",
            "nothing further was written — reopen the modal to retry",
            Vec::new(),
            Some(msg.clone()),
        ),
    };
    NoticeSpec {
        hint_rows: None,
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

    fn mk_subnet(id: &str) -> Subnet {
        Subnet {
            id: Id::new(id).unwrap(),
            display_name: "Display".into(),
            cidrs: vec!["10.0.0.0/24".into()],
            profile: Id::new("default").unwrap(),
            priority: 0,
        }
    }

    // ── Form-field navigation ─────────────────────────────────────────

    #[test]
    fn s51_form_field_next_cycles_through_seven_in_order() {
        let mut f = FormField::Id;
        let order = [
            FormField::DisplayName,
            FormField::Cidrs,
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
    fn s51_form_field_prev_walks_backwards_and_wraps() {
        let f = FormField::Id;
        // Cancel (the Discard button) is now the last field, so Id wraps
        // back to it.
        assert_eq!(f.prev(), FormField::Cancel);
        assert_eq!(FormField::DisplayName.prev(), FormField::Id);
    }

    // ── try_resolve validation ────────────────────────────────────────

    #[test]
    fn s51_form_resolve_rejects_empty_id() {
        let modal = SubnetModal::open_add(vec!["default".into()], 0);
        let err = modal.form().unwrap().try_resolve().unwrap_err();
        assert!(err.contains("id"), "empty id must error: {err}");
    }

    #[test]
    fn s51_form_resolve_rejects_empty_cidrs() {
        let mut modal = SubnetModal::open_add(vec!["default".into()], 0);
        let form = modal.form_mut().unwrap();
        form.id = "lan".into();
        // cidrs left empty
        let err = modal.form().unwrap().try_resolve().unwrap_err();
        assert!(err.contains("CIDR"), "empty CIDRs must error: {err}");
    }

    #[test]
    fn s51_form_resolve_rejects_invalid_priority() {
        let mut modal = SubnetModal::open_add(vec!["default".into()], 0);
        let form = modal.form_mut().unwrap();
        form.id = "lan".into();
        form.cidrs = "10.0.0.0/24".into();
        form.priority_input = "not-a-number".into();
        let err = modal.form().unwrap().try_resolve().unwrap_err();
        assert!(err.contains("priority"), "bad priority must error: {err}");
    }

    #[test]
    fn s51_form_resolve_defaults_display_name_to_id() {
        let mut modal = SubnetModal::open_add(vec!["default".into()], 0);
        let form = modal.form_mut().unwrap();
        form.id = "lan".into();
        form.cidrs = "10.0.0.0/24".into();
        // display_name left empty
        let resolved = modal.form().unwrap().try_resolve().unwrap();
        assert_eq!(resolved.display_name, "lan");
    }

    #[test]
    fn s51_form_resolve_splits_comma_separated_cidrs() {
        let mut modal = SubnetModal::open_add(vec!["default".into()], 0);
        let form = modal.form_mut().unwrap();
        form.id = "lan".into();
        form.cidrs = "10.0.0.0/24, 10.1.0.0/24, 10.2.0.0/24".into();
        let resolved = modal.form().unwrap().try_resolve().unwrap();
        assert_eq!(resolved.cidrs.len(), 3);
        assert_eq!(resolved.cidrs[0], "10.0.0.0/24");
        assert_eq!(resolved.cidrs[2], "10.2.0.0/24");
    }

    #[test]
    fn s51_form_resolve_passes_wildcard_through_to_add_inner() {
        // The form does NOT pre-validate CIDRs — that happens inside
        // `add_inner` via `Cidr::parse_friendly` so wildcards survive
        // the modal layer and the operator sees the same friendly
        // error/success path the CLI does.
        let mut modal = SubnetModal::open_add(vec!["default".into()], 0);
        let form = modal.form_mut().unwrap();
        form.id = "lan-99".into();
        form.cidrs = "10.99.0.*".into();
        let resolved = modal.form().unwrap().try_resolve().unwrap();
        assert_eq!(resolved.cidrs, vec!["10.99.0.*".to_string()]);
    }

    // ── Promote-from-suggestion ───────────────────────────────────────

    #[test]
    fn s51_promote_prefills_cidr_and_synthesises_display_name() {
        let modal = SubnetModal::open_promote("10.14.0.0/24", vec!["default".into()], 0);
        let form = modal.form().unwrap();
        assert_eq!(form.cidrs, "10.14.0.0/24");
        assert_eq!(form.display_name, "lan-10-14-0");
        assert!(
            form.id.is_empty(),
            "id must remain empty so the operator picks it consciously"
        );
    }

    #[test]
    fn s51_synthesise_display_name_v6() {
        let name = synthesise_display_name("2001:db8::/64");
        assert_eq!(name, "lan6-2001-db8-0-0");
    }

    #[test]
    fn s51_synthesise_display_name_falls_back_on_garbage() {
        assert_eq!(synthesise_display_name("not-a-cidr"), "lan-discovered");
    }

    // ── Edit modal ────────────────────────────────────────────────────

    #[test]
    fn s51_edit_modal_captures_snapshot_at_open() {
        let s = mk_subnet("lan");
        let modal = SubnetModal::open_edit(&s, vec!["default".into(), "kids".into()]);
        let form = modal.form().unwrap();
        assert_eq!(form.mode, FormMode::Edit);
        assert_eq!(form.id, "lan");
        assert_eq!(form.cidrs, "10.0.0.0/24");
        assert!(
            form.original.is_some(),
            "Edit captures the original snapshot"
        );
        let orig = form.original.as_ref().unwrap();
        assert_eq!(orig.id, "lan");
        assert_eq!(orig.profile, "default");
    }

    #[test]
    fn s51_edit_modal_falls_back_to_first_profile_when_unknown() {
        let mut s = mk_subnet("lan");
        s.profile = Id::new("ghost").unwrap();
        let modal = SubnetModal::open_edit(&s, vec!["default".into()]);
        // ghost not in snapshot → drop to slot 0 (default)
        assert_eq!(modal.form().unwrap().profile_idx, 0);
    }

    // ── Remove modal ──────────────────────────────────────────────────

    #[test]
    fn s51_remove_modal_carries_subnet_metadata() {
        let s = mk_subnet("lan");
        let modal = SubnetModal::open_remove(&s);
        let rc = modal.remove().unwrap();
        assert_eq!(rc.id, "lan");
        assert_eq!(rc.cidrs, vec!["10.0.0.0/24".to_string()]);
    }

    // ── Lifecycle ─────────────────────────────────────────────────────

    #[test]
    fn s51_modal_finish_transitions_to_submitted() {
        let mut modal = SubnetModal::open_add(vec!["default".into()], 0);
        assert!(!modal.is_submitted());
        modal.finish(SubmitOutcome::Ok("done".into()));
        assert!(modal.is_submitted());
    }

    // ── Grid render (shared modal_form) ───────────────────────────────

    /// Flatten the whole body — head, field region, tail — into one
    /// string for content assertions.
    ///
    /// The *line vector*, deliberately: it is enough for "is this row
    /// composed correctly", and useless for "is this row on screen".
    /// Every past instance of `lists-modal-min-height-clip` had a correct
    /// vector and a wrong render, which is why the floor tests below
    /// assert on the rendered buffer instead.
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

    #[test]
    fn s51_form_renders_banded_sections_and_the_active_marker() {
        // §4.61 Wave 2a replaced the grey `Field │ Value` grid with the
        // banded, labelled-section Archetype-F body. Two assertions from
        // the grid era had to change with it, and both are behaviour:
        //
        //  - the "Field"/"Value" header is gone — sections label
        //    themselves now (IDENTITY / RANGE / POLICY);
        //  - the `_` caret is gone — a focused text field hosts the real
        //    terminal cursor, as the operator-validated Lists modal
        //    does. `focused_text_field_hosts_the_real_cursor` below is
        //    the replacement assertion, and it has to be made against a
        //    rendered frame, not a line vector.
        let mut modal = SubnetModal::open_add(vec!["default".into()], 0);
        let form = modal.form_mut().unwrap();
        form.id = "lan".into(); // focus defaults to Id on Add
        let text = render_text(form, 60);

        assert!(
            text.contains("IDENTITY") && text.contains("RANGE") && text.contains("POLICY"),
            "labelled section bands:\n{text}"
        );
        assert!(!text.contains("lan_"), "the `_` caret is the cursor's job");
        assert!(text.contains("lan"), "the focused value still renders");
        assert!(text.contains('◀'), "active row carries the focus marker");
        assert!(text.contains("Save"), "Save action present");
        assert!(text.contains("Discard"), "Discard action present");
    }

    #[test]
    fn focused_text_field_hosts_the_real_cursor() {
        // The `_` caret's replacement. Placed at VALUE_COL + the value's
        // char length, in the viewport's coordinate space — so it tracks
        // the scrolled field region rather than a fixed body offset.
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;
        let mut modal = SubnetModal::open_add(vec!["default".into()], 0);
        modal.form_mut().unwrap().id = "lan".into();

        let mut term = Terminal::new(TestBackend::new(100, 44)).unwrap();
        term.draw(|f| render_overlay(f, f.area(), &modal)).unwrap();
        let pos = term.get_cursor_position().unwrap();

        let dump = dump_buffer(term.backend().buffer());
        // Located by the focus marker, not by the value: exactly one row
        // carries `◀`, whereas "lan" also hides inside the display-name
        // placeholder ("blank = the id") two rows below.
        let row = dump
            .lines()
            .position(|l| l.contains('\u{25c0}'))
            .expect("the focused row must be on screen") as u16;
        assert!(
            dump.lines().nth(row as usize).unwrap().contains("lan"),
            "the focused row is the id row:\n{dump}"
        );
        assert_eq!(pos.y, row, "cursor must sit on the focused row:\n{dump}");
        // Modal is 64 wide and centred in 100 columns → inner left edge
        // is 18 + 1 border; the caret lands VALUE_COL + len("lan") in.
        let inner_x = (100 - 64) / 2 + 1;
        assert_eq!(
            pos.x,
            inner_x + modal_form::VALUE_COL as u16 + 3,
            "cursor must sit at the end of the typed value:\n{dump}"
        );
    }

    #[test]
    fn s51_grid_form_focused_selector_is_wrapped_in_angle_brackets() {
        let mut modal = SubnetModal::open_add(vec!["default".into()], 0);
        let form = modal.form_mut().unwrap();
        form.focused = FormField::Profile;
        let text = render_text(form, 60);
        assert!(
            text.contains("‹ default ›"),
            "a focused selector value is wrapped to signal ←/→ cycles it"
        );
    }

    #[test]
    fn s51_grid_form_inline_error_replaces_the_hint_line() {
        let mut modal = SubnetModal::open_add(vec!["default".into()], 0);
        let form = modal.form_mut().unwrap();
        form.error_message = Some("at least one CIDR is required".into());
        let text = render_text(form, 60);
        assert!(
            text.contains("⚠ at least one CIDR is required"),
            "error shows inline"
        );
        // The hint for the (default-focused) Id field is suppressed while
        // an error is pending.
        assert!(!text.contains("short stable key"));
    }

    #[test]
    fn s51_grid_form_edit_id_is_read_only_without_caret() {
        let s = mk_subnet("lan");
        let modal = SubnetModal::open_edit(&s, vec!["default".into()]);
        let form = modal.form().unwrap();
        // Edit focus starts on Display name; the Id row shows the id
        // verbatim with no `_` caret and no literal "(read-only)" text —
        // the dim ReadOnly styling is the affordance.
        assert_eq!(form.focused, FormField::DisplayName);
        let text = render_text(form, 60);
        assert!(text.contains("lan"), "id value still shown");
        assert!(!text.contains("lan_"), "read-only id carries no caret");
        assert!(
            !text.contains("(read-only)"),
            "dim styling signals read-only, not literal suffix text"
        );
    }

    #[test]
    fn s51_subnet_suggested_tag_byte_frozen() {
        // The integration assertion lives in
        // `tests/frozen_strings_s51.rs`; this in-file echo lets a
        // same-file regression surface during `cargo test --lib`
        // without requiring the integration cohort.
        use crate::tui::tabs::subnets::SUBNET_SUGGESTED_TAG;
        assert_eq!(SUBNET_SUGGESTED_TAG, " [suggested]");
        assert_eq!(SUBNET_SUGGESTED_TAG.len(), 12);
    }

    // ── §3.5 tag-model-consolidation: populated tags field ────────────

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

    // ── §4.61 Wave 2a: the 80×24 floor ───────────────────────────────
    //
    // `ui.rs` declares MIN_WIDTH 80 × MIN_HEIGHT 24. At that size the tab
    // content rect this overlay anchors on (D18) is
    // `24 − 4 header − 5 menu card − 1 footer = 14` rows, leaving a
    // 12-row interior. `overlay::centered_rect` CLAMPS rather than
    // scrolls, so a body taller than that is silently cut at the bottom
    // while `Tab` still moves focus onto the rows that were cut — the
    // operator then commits or discards blind. These render the real
    // `render_overlay` into a backend the size of that content rect.

    fn render_overlay_in(modal: &SubnetModal, w: u16, h: u16) -> String {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;
        let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
        term.draw(|f| render_overlay(f, f.area(), modal)).unwrap();
        dump_buffer(term.backend().buffer())
    }

    // `plp-s5d` removed `ux2_the_armed_valve_is_visible_in_the_subnets_modal`
    // with the tags picker it tested. The §4.65 UX2 valve — a typed slug
    // waiting on a second `Enter` — was a property of the chip picker, and
    // this modal no longer has one. There is NO substitute assertion here
    // on purpose: the guarantee left with the surface rather than moving
    // to another one, and saying so beats a renamed test that pins
    // nothing. The shared valve itself still lives in
    // `tabs::lists::commit_tag_picker` and is tested there.

    fn edit_modal_for_floor() -> SubnetModal {
        let s = mk_subnet("lan");
        let mut modal = SubnetModal::open_edit(&s, vec!["default".into()]);
        let form = modal.form_mut().unwrap();
        form.display_name = "Guest WiFi".into();
        form.cidrs = "10.0.0.0/24".into();
        form.priority_input = "77".into();
        modal
    }

    #[test]
    fn floor_keeps_the_action_row_and_the_focused_field_on_screen_together() {
        // The two things a clip silently takes away. Asserted on the
        // rendered buffer, never on the line vector: the vector was
        // correct in every past instance of this defect
        // (`lists-modal-min-height-clip`) — only the render was wrong.
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
        // picker gone, Priority is. The property under test is unchanged —
        // the viewport must scroll to the last field and therefore scroll
        // the *first* one out. Without that second half the assertion
        // passes on a body that only ever renders page one.
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
            !dump.contains("Guest WiFi"),
            "a 4-row viewport cannot be showing both ends of the form:\n{dump}"
        );
    }

    #[test]
    fn floor_add_mode_keeps_the_action_row_and_the_focused_field_together() {
        // Add is a different body from Edit — `id` is a focusable text
        // field — so the row count and the viewport arithmetic differ.
        // (Before `plp-s5d` the Edit body also carried two tags rows Add
        // never had; that difference is gone, the `id` one is not.) Add is
        // also the
        // most-travelled path here (promote-from-suggestion opens it),
        // so it gets its own floor assertion rather than riding on
        // Edit's.
        //
        // No fail-before: the pre-migration Add body was exactly 12
        // lines and fitted the 12-row interior by luck. This pins
        // behaviour that already works.
        let mut modal = SubnetModal::open_add(vec!["default".into()], 0);
        modal.form_mut().unwrap().focused = FormField::Profile; // last Add field
        let dump = render_overlay_in(&modal, 80, 14);

        assert!(
            dump.contains("\u{2039} default \u{203a}"),
            "focused profile row is off-screen:\n{dump}"
        );
        assert!(dump.contains("Save"), "action row cut in Add mode:\n{dump}");
        assert!(
            !dump.contains("display name"),
            "the viewport must have scrolled past the first field:\n{dump}"
        );
    }

    #[test]
    fn floor_remove_confirm_shows_the_entity_and_the_key_legend() {
        // The destructive stage. It fits the floor with one row of
        // slack (13 requested against 14), which is exactly the margin
        // worth pinning rather than leaving to the visual dump.
        let modal = SubnetModal {
            stage: Stage::ConfirmingRemove(RemoveConfirm {
                id: "lan".into(),
                display_name: "Guest WiFi".into(),
                cidrs: vec!["10.0.0.0/24".into()],
            }),
        };
        let dump = render_overlay_in(&modal, 80, 14);

        assert!(
            dump.contains("lan (Guest WiFi)"),
            "the operator must see which subnet they are removing:\n{dump}"
        );
        assert!(
            dump.contains("[y] confirm") && dump.contains("[y] Remove"),
            "the y/n keying is unchanged and must stay legible:\n{dump}"
        );
    }

    #[test]
    fn submit_failure_wraps_instead_of_clipping_at_one_line() {
        // A real long failure from `mod.rs::submit_subnet_modal`. It used
        // to render as a single non-wrapping line and lost its tail;
        // routing it through `NoticeSpec::error` hard-wraps it to
        // HINT_ROWS. Pins the fix so it cannot silently regress by moving
        // the message back into the prose region.
        //
        // `plp-s5d` swapped the specimen. It was the partial-failure copy
        // ("subnet fields saved (…) but the tag change failed: …"), which
        // this lane deleted along with the two-write tag path that emitted
        // it. A wrap test pinned to a string the product can no longer
        // produce is a test that measures nothing, so the specimen is now
        // a validator refusal carried up from `set_fields_inner` — a
        // message this path still emits, and still long enough to wrap.
        // Length matters, not just content: the notice hard-wraps to
        // HINT_ROWS and then truncates with "+N more". The retired
        // specimen was 103 chars and fitted; a first attempt at this one
        // ran to 118 and lost its tail, failing this very assertion. Kept
        // at ~102 so it still spans more than one row without overflowing
        // the budget the neighbouring clip test pins.
        let long = "edit failed: subnet \"lan\" overlaps subnet \"guest\" and \
                    neither declares a priority — reopen to retry it";
        let modal = SubnetModal {
            stage: Stage::Submitted(SubmitOutcome::Failed(long.into())),
        };
        let dump = render_overlay_in(&modal, 80, 14);

        assert!(
            dump.contains('\u{26a0}'),
            "a failure carries the ⚠ affordance:\n{dump}"
        );
        assert!(
            dump.contains("reopen to retry it"),
            "the tail of the message must survive the wrap:\n{dump}"
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

    #[test]
    fn no_hand_rolled_colour_in_this_module() {
        // §4.61 Wave 2a's acceptance criterion, as a test rather than a
        // claim in a commit message. A surface that reaches for the
        // theme directly is a surface that will drift from the other
        // eleven — and R1 is that every wave re-derives the colour rule
        // locally. Needles are split so this assertion cannot match
        // itself.
        let src = include_str!("subnet_modal.rs");
        for needle in [
            concat!("Style::default()", ".fg("),
            concat!("Color", "::Rgb("),
            concat!("T", ".brand_red"),
        ] {
            assert!(
                !src.contains(needle),
                "{needle} in subnet_modal.rs — the colour belongs in modal_form"
            );
        }
    }

    #[test]
    #[ignore = "visual aid: cargo test subnet_visual_dump -- --ignored --nocapture"]
    fn subnet_visual_dump() {
        let mut modal = edit_modal_for_floor();
        modal.form_mut().unwrap().focused = FormField::Cidrs;
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
        modal.form_mut().unwrap().focused = FormField::Submit;
        println!(
            "--- same, focus on Save (no field row focused) ---\n{}",
            render_overlay_in(&modal, 80, 14)
        );
        let rc = RemoveConfirm {
            id: "lan".into(),
            display_name: "Guest WiFi".into(),
            cidrs: vec!["10.0.0.0/24".into()],
        };
        println!(
            "--- remove confirm (Archetype C) ---\n{}",
            render_overlay_in(
                &SubnetModal {
                    stage: Stage::ConfirmingRemove(rc)
                },
                80,
                14
            )
        );
        println!(
            "--- submit failure (Archetype C) ---\n{}",
            render_overlay_in(
                &SubnetModal {
                    stage: Stage::Submitted(SubmitOutcome::Failed(
                        "edit failed: subnet \"lan\" overlaps subnet \"guest\" and neither declares a priority — reopen to retry it".into()
                    ))
                },
                80,
                14
            )
        );
    }

    /// The clip-guard: the tallest this modal's content can get must not
    /// push Save/Discard off the bottom.
    ///
    /// **`plp-s5d` retargeted this from the tags picker to `cidrs`, and
    /// the retarget is the point.** The picker was the tallest field
    /// (chips + a type-ahead buffer + a suggestions row), so deleting it
    /// would have deleted the only test driving this modal's body past
    /// its slack — the clip-guard would have gone green forever by having
    /// nothing tall left to guard against, which is the deletion-lane
    /// trap. `cidrs` is the surviving unbounded field (free text, one
    /// comma-separated line), so the guarantee keeps a subject.
    ///
    /// No spaces in the filler — `Wrap` cannot break at a word boundary,
    /// so it hard-wraps character-by-character. A short value does not
    /// reliably overflow the slack.
    #[test]
    fn render_overlay_keeps_save_discard_visible_with_an_overlong_cidrs_field() {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;

        let s = mk_subnet("lan");
        let mut modal = SubnetModal::open_edit(&s, vec!["default".into()]);
        let form = modal.form_mut().unwrap();
        form.focused = FormField::Cidrs;
        form.cidrs = "x".repeat(300);

        let backend = TestBackend::new(100, 24);
        let mut term = Terminal::new(backend).unwrap();
        term.draw(|f| {
            render_overlay(f, f.area(), &modal);
        })
        .unwrap();

        let dump = dump_buffer(term.backend().buffer());
        assert!(
            dump.contains("xxxx"),
            "the overlong field must actually be rendering — without this \
             the Save/Discard assertion below passes on a short body:\n{dump}"
        );
        assert!(
            dump.contains("Save") && dump.contains("Discard"),
            "the button row must survive an overlong field, not be clipped off the bottom:\n{dump}"
        );
    }
}
