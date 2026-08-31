//! Sprint 44 — Local DNS tab modals (Add / Remove / Edit). Opens
//! over [`crate::tui::app::Leaf::LocalDns`] via `a` / `d|Delete` / `e`
//! keypresses. Submits through the R7 single-seat helpers
//! `cli::commands::local_dns::add_inner` / `remove_inner` — same code
//! path the CLI verbs use, so audit emissions are byte-identical
//! between the two surfaces.
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
//! ConfirmingRemove(TypedPhrase)    ──Enter (buffer == domain)──▶ Submitted(...)
//!                                  ──Esc──▶ closed
//! ```
//!
//! ## Capture-at-open invariant
//!
//! When `a` / `e` / `d` is pressed, the helpers in `tui/mod.rs`
//! snapshot every value the modal needs (the focused row's record, the
//! list of profile ids known at this moment, the resolved scope) into
//! the [`LocalDnsModal`] state. Subsequent renders / `r`-refreshes /
//! tab scrolls cannot invalidate the snapshot — submitting always uses
//! the captured values, never re-reads `loaded_config`.

use crate::cli::commands::local_dns::{LocalRecordScope, LocalRecordSpec};
use crate::config::settings::{LocalDnsRecord, LocalDnsRecordType};

/// Top-level modal lifecycle. `None` on `app.local_dns.modal` means no
/// modal is open; a `Some` variant grabs every keystroke until either
/// submit lands a [`Stage::Submitted`] outcome or the operator presses
/// Esc.
#[derive(Debug, Clone)]
pub struct LocalDnsModal {
    pub stage: Stage,
}

#[derive(Debug, Clone)]
pub enum Stage {
    /// Add or Edit form. The discriminant inside `AddForm` selects the
    /// title bar + the submit dispatch path.
    EditingForm(AddForm),
    /// Remove confirmation. The tier selects single-keypress vs
    /// typed-phrase per SN2 (S43).
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
/// (for Edit) which record gets dropped before the new one is appended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormMode {
    Add,
    /// Edit carries the original (scope, record) snapshot so the submit
    /// path can `remove_inner` the old row before `add_inner` of the new
    /// one. Non-atomic: documented in the module docs.
    Edit,
}

/// Editable fields exposed by the form, in tab order. Matches the
/// `DeviceFormField` precedent — keep in sync with [`FormField::ALL`]
/// and the renderer's per-field highlight logic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormField {
    Domain,
    RecordType,
    Value,
    MatchSubdomains,
    Ttl,
    Profile,
    Submit,
    Cancel,
}

#[derive(Debug, Clone)]
pub struct AddForm {
    pub mode: FormMode,
    /// Snapshot of (scope, record) at modal-open time. Set on Edit so
    /// the submit path knows which row to drop. `None` on Add.
    pub original: Option<OriginalSnapshot>,
    pub focused: FormField,
    pub domain: String,
    pub record_type: LocalDnsRecordType,
    pub value: String,
    pub match_subdomains: bool,
    /// Raw operator input — parsed to `Option<u32>` at submit. Empty
    /// string means "use the default TTL fallback".
    pub ttl_input: String,
    /// Snapshot of profile ids captured at modal-open time. The
    /// dropdown rendering walks this slice; the running config can
    /// change profiles in/out from under us during the form's lifetime,
    /// but the captured snapshot stays authoritative.
    pub profiles_snapshot: Vec<String>,
    /// Index into `profiles_snapshot` plus a leading `Global` slot.
    /// `0` is always `Global`; `1..=profiles_snapshot.len()` selects
    /// `profiles_snapshot[profile_idx - 1]`.
    pub profile_idx: usize,
    /// Inline validation / submit error rendered at the bottom of the
    /// form. Cleared on the next field edit.
    pub error_message: Option<String>,
}

/// Original (scope, record) snapshot captured when an Edit modal opens.
/// The submit path reads it to decide which row gets dropped before the
/// new one is appended.
#[derive(Debug, Clone)]
pub struct OriginalSnapshot {
    pub scope: LocalRecordScope,
    pub spec: LocalRecordSpec,
}

#[derive(Debug, Clone)]
pub struct RemoveConfirm {
    pub scope: LocalRecordScope,
    pub spec: LocalRecordSpec,
    pub tier: ConfirmTier,
    /// Typed-phrase buffer. Unused for [`ConfirmTier::SingleKeypress`].
    pub buffer: String,
    /// Why the last Enter did not submit, or `None` when there is
    /// nothing to say. Rides the [`modal_form::NoticeSpec::error`] slot,
    /// which sits in the pinned tail and *displaces* the hint — so it
    /// costs no prose row and cannot push the typed-phrase input off
    /// screen at the D18 floor.
    ///
    /// Set only through [`Self::confirm_or_refuse`] and cleared by every
    /// edit to `buffer`: a rejection describes one buffer, and a stale
    /// one contradicting what is now on screen is worse than silence.
    pub error: Option<String>,
}

/// Tiered confirm shape (SN2 from S43). The lower the blast radius, the
/// cheaper the confirm gesture — operators removing a single
/// profile-scoped record get a single keystroke; operators removing a
/// *.global wildcard must type the domain to confirm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfirmTier {
    /// Single keypress `[y]` / `[n]`. Used for:
    /// - profile-scope removals (lower blast radius — only one
    ///   profile's clients affected).
    /// - global-scope removals where `match_subdomains == false` (only
    ///   the apex domain is affected).
    SingleKeypress,
    /// Typed-phrase confirm — operator types the domain to proceed.
    /// Used for global-scope `match_subdomains == true` removals
    /// because dropping a wildcard rewrites every name under the
    /// domain back to the upstream answer, which is a high-blast-radius
    /// silent change.
    TypedPhrase,
}

impl ConfirmTier {
    /// Pick the tier from the (scope, match_subdomains) pair the
    /// operator is removing.
    pub fn for_remove(scope: &LocalRecordScope, match_subdomains: bool) -> Self {
        match (scope, match_subdomains) {
            (LocalRecordScope::Profile(_), _) => Self::SingleKeypress,
            (LocalRecordScope::Global, false) => Self::SingleKeypress,
            (LocalRecordScope::Global, true) => Self::TypedPhrase,
        }
    }
}

impl FormField {
    pub const ALL: [FormField; 8] = [
        FormField::Domain,
        FormField::RecordType,
        FormField::Value,
        FormField::MatchSubdomains,
        FormField::Ttl,
        FormField::Profile,
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
    /// dropdown lands on when the form opens (typically `0` = Global).
    pub fn new_add(profiles_snapshot: Vec<String>, default_profile_idx: usize) -> Self {
        let n_options = profiles_snapshot.len() + 1; // +1 for Global slot
        let profile_idx = default_profile_idx.min(n_options.saturating_sub(1));
        Self {
            mode: FormMode::Add,
            original: None,
            focused: FormField::Domain,
            domain: String::new(),
            record_type: LocalDnsRecordType::A,
            value: String::new(),
            match_subdomains: false,
            ttl_input: String::new(),
            profiles_snapshot,
            profile_idx,
            error_message: None,
        }
    }

    /// Pre-filled form for `Edit`. The record's existing fields populate
    /// each input; the original (scope, spec) is stashed so the submit
    /// path can drop the old row before appending the new one.
    pub fn new_edit(
        scope: LocalRecordScope,
        record: &LocalDnsRecord,
        profiles_snapshot: Vec<String>,
    ) -> Self {
        let profile_idx = match &scope {
            LocalRecordScope::Global => 0,
            LocalRecordScope::Profile(id) => profiles_snapshot
                .iter()
                .position(|p| p == id)
                .map(|i| i + 1)
                .unwrap_or(0),
        };
        let spec = LocalRecordSpec {
            domain: record.domain.clone(),
            record_type: record.record_type,
            value: record.value.clone(),
            match_subdomains: record.match_subdomains,
            ttl_secs: record.ttl_secs,
        };
        Self {
            mode: FormMode::Edit,
            original: Some(OriginalSnapshot {
                scope,
                spec: spec.clone(),
            }),
            focused: FormField::Domain,
            domain: record.domain.clone(),
            record_type: record.record_type,
            value: record.value.clone(),
            match_subdomains: record.match_subdomains,
            ttl_input: record.ttl_secs.map(|n| n.to_string()).unwrap_or_default(),
            profiles_snapshot,
            profile_idx,
            error_message: None,
        }
    }

    /// Total number of profile-dropdown options (`Global` + each
    /// configured profile).
    pub fn profile_options_len(&self) -> usize {
        self.profiles_snapshot.len() + 1
    }

    /// Operator-facing label for the focused dropdown slot.
    pub fn profile_option_label(&self) -> String {
        if self.profile_idx == 0 {
            "Global".into()
        } else {
            self.profiles_snapshot
                .get(self.profile_idx - 1)
                .cloned()
                .unwrap_or_else(|| "?".into())
        }
    }

    /// Resolve the form into the (scope, spec) tuple ready to feed into
    /// [`crate::cli::commands::local_dns::add_inner`]. Performs the
    /// pre-flight validation that does NOT need filesystem access (empty
    /// fields, malformed TTL, profile-idx out of range). The validator
    /// pre-flight inside `add_inner` catches the rest (PSL, reserved
    /// IPs, CNAME loops, etc.).
    pub fn try_resolve(&self) -> Result<(LocalRecordScope, LocalRecordSpec), String> {
        let domain_trim = self.domain.trim();
        if domain_trim.is_empty() {
            return Err("domain is required".into());
        }
        let value_trim = self.value.trim();
        if value_trim.is_empty() {
            return Err("value is required".into());
        }
        let ttl_secs = parse_ttl(&self.ttl_input)?;
        let scope = if self.profile_idx == 0 {
            LocalRecordScope::Global
        } else {
            let pid = self
                .profiles_snapshot
                .get(self.profile_idx - 1)
                .ok_or_else(|| "profile selection is out of range".to_string())?
                .clone();
            LocalRecordScope::Profile(pid)
        };
        let spec = LocalRecordSpec {
            domain: domain_trim.to_ascii_lowercase(),
            record_type: self.record_type,
            value: value_trim.to_string(),
            match_subdomains: self.match_subdomains,
            ttl_secs,
        };
        Ok((scope, spec))
    }
}

/// Parse the operator's TTL input. Empty → `None` (use config default).
/// Otherwise parse a u32 and range-check it against the validator's
/// `1..=86_400` window, so `0` and out-of-range values are rejected
/// inline — before Apply hands the record to the config validator's DR5
/// gate (`config::validator::LOCAL_RECORDS_TTL_OUT_OF_RANGE`). Wording
/// mirrors that gate so the pre- and post-Apply messages read the same.
fn parse_ttl(input: &str) -> Result<Option<u32>, String> {
    let t = input.trim();
    if t.is_empty() {
        return Ok(None);
    }
    let n = t
        .parse::<u32>()
        .map_err(|_| format!("ttl_secs '{t}' is not a valid non-negative integer"))?;
    if !(1..=86_400).contains(&n) {
        return Err(format!(
            "ttl_secs {n} is out of range (allowed: 1..=86400 seconds)"
        ));
    }
    Ok(Some(n))
}

impl LocalDnsModal {
    /// Open an Add modal. `default_profile_idx` selects the dropdown
    /// slot to land on (typically `0` for Global, or `1..` to preselect
    /// a specific profile when the operator opened the modal from the
    /// Profile panel).
    pub fn open_add(profiles_snapshot: Vec<String>, default_profile_idx: usize) -> Self {
        Self {
            stage: Stage::EditingForm(AddForm::new_add(profiles_snapshot, default_profile_idx)),
        }
    }

    /// Open an Edit modal pre-filled from the focused row.
    pub fn open_edit(
        scope: LocalRecordScope,
        record: &LocalDnsRecord,
        profiles_snapshot: Vec<String>,
    ) -> Self {
        Self {
            stage: Stage::EditingForm(AddForm::new_edit(scope, record, profiles_snapshot)),
        }
    }

    /// Open a Remove modal at the appropriate confirm tier.
    pub fn open_remove(scope: LocalRecordScope, record: &LocalDnsRecord) -> Self {
        let tier = ConfirmTier::for_remove(&scope, record.match_subdomains);
        let spec = LocalRecordSpec {
            domain: record.domain.clone(),
            record_type: record.record_type,
            value: record.value.clone(),
            match_subdomains: record.match_subdomains,
            ttl_secs: record.ttl_secs,
        };
        Self {
            stage: Stage::ConfirmingRemove(RemoveConfirm {
                scope,
                spec,
                tier,
                buffer: String::new(),
                error: None,
            }),
        }
    }

    /// Mark the modal as submitted with the given outcome — caller
    /// closes it on the next keypress.
    pub fn finish(&mut self, outcome: SubmitOutcome) {
        self.stage = Stage::Submitted(outcome);
    }

    /// Whether the modal is currently in a submitted state — used by
    /// the keyhandler to close on the next keypress.
    pub fn is_submitted(&self) -> bool {
        matches!(self.stage, Stage::Submitted(_))
    }

    /// Convenience: borrow the form when the stage is editing. Used
    /// only by the test cohort — the production handler pattern-matches
    /// on `self.stage` directly.
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

    /// Mutable counterpart of [`Self::remove`]. Test-only.
    #[cfg(test)]
    pub fn remove_mut(&mut self) -> Option<&mut RemoveConfirm> {
        match &mut self.stage {
            Stage::ConfirmingRemove(r) => Some(r),
            _ => None,
        }
    }
}

impl RemoveConfirm {
    /// Whether the typed-phrase buffer matches the target domain
    /// exactly (case-insensitive). Always `true` for
    /// [`ConfirmTier::SingleKeypress`] — the gesture there is the
    /// keypress itself, not the buffer.
    pub fn typed_phrase_matches(&self) -> bool {
        match self.tier {
            ConfirmTier::SingleKeypress => true,
            ConfirmTier::TypedPhrase => self
                .buffer
                .trim()
                .eq_ignore_ascii_case(self.spec.domain.trim()),
        }
    }

    /// Answer [`Self::typed_phrase_matches`] **and** record the refusal
    /// when it is `false`. This is what an Enter must call.
    ///
    /// The two are fused on purpose. The key handler previously consulted
    /// the bare predicate and, on `false`, re-stashed the modal untouched
    /// — so Enter was a dead key on the highest-blast-radius gesture in
    /// this module, and the operator had no way to tell "I typed it
    /// wrong" from "the app is frozen". Splitting the gate from the
    /// record puts that silence one forgotten line away from returning;
    /// fusing them makes it unreachable, because there is no way to ask
    /// whether the phrase matched without the refusal being written.
    ///
    /// An **empty** buffer is not an error — the operator has not typed
    /// anything yet, and the prompt row already says what to do — so that
    /// case stays quiet. Enter is still inert there, deliberately.
    pub fn confirm_or_refuse(&mut self) -> bool {
        if self.typed_phrase_matches() {
            self.error = None;
            return true;
        }
        let typed = self.buffer.trim();
        // Name both halves. The operator is looking at what they typed and
        // must reproduce a value they can also see, so a refusal that
        // repeats both turns a dead end into a one-keystroke correction —
        // "does not match" alone would not.
        //
        // Order is load-bearing, not style. `hint_or_error_rows` fills at
        // most `HINT_ROWS` rows and ellipsises the last one, and nothing
        // caps the buffer — so a long enough echo destroys whatever comes
        // after it. The domain is the invariant the operator needs and the
        // echo is disposable, so the domain goes first and the truncation
        // eats the right half. See
        // `a_long_wrong_phrase_still_names_the_expected_domain`.
        self.error = (!typed.is_empty()).then(|| {
            format!(
                "the domain is '{}' \u{2014} you typed '{}'",
                self.spec.domain, typed
            )
        });
        false
    }

    /// Append to the typed-phrase buffer, clearing any refusal.
    pub fn push_char(&mut self, c: char) {
        self.buffer.push(c);
        self.error = None;
    }

    /// Erase the last character of the typed-phrase buffer, clearing any
    /// refusal.
    pub fn backspace(&mut self) {
        self.buffer.pop();
        self.error = None;
    }
}

// ── Render helpers (called from tabs/local_dns.rs) ────────────────────

use ratatui::layout::Rect;
use ratatui::Frame;

use crate::tui::modal_form::{self, Action, ActionKind, ProseRow, ValueKind};

/// Outer width of every stage of this modal — the same 64 the Lists
/// reference uses, so the two read as one system side by side.
const MODAL_W: u16 = 64;

/// Nav-key legend. The migration changed chrome, layout and colour and
/// **not** the keying (§4.61 D7′): `mod.rs` still maps Tab/↑↓ to move,
/// ←/→ and Space to change, Enter to save and Esc to cancel.
///
/// N14 stripped the save/cancel clause: the action row now bakes its
/// own key into each button's label (`[Esc] Discard` / `[Enter] Save`),
/// so a blanket "Enter save · Esc cancel" here would be a second,
/// redundant source of the same fact.
const FORM_KEYS: &str = "\u{21b9}/\u{2191}\u{2193} move \u{b7} \u{2190}/\u{2192} change";

/// Draw the modal over the tab content rect. Branches on the stage so the
/// operator sees the form, the confirm prompt, or the outcome at the right
/// moment.
///
/// `anchor` is the tab content rect (§4.61 D18), never `f.area()` — a
/// modal is transient and must not occlude the header, the menu card or
/// the footer legend. That leaves **12 interior rows** at the declared
/// 80×24 floor, which no stage of this modal fits, so every stage is built
/// on [`modal_form::ScrollBody`] via [`modal_form::render_modal`]: the
/// tail is allocated first, so the action row survives a squeeze that the
/// field rows do not.
///
/// Nothing geometric is decided here. `render_modal` owns the chrome, the
/// height request, the anchor clamp, the two-pass width resolution that
/// keeps rows clear of the scrollbar column, and the focus-following
/// viewport. What is left is this modal's width and where its real
/// terminal cursor goes.
pub fn render_overlay(f: &mut Frame, anchor: Rect, modal: &LocalDnsModal) {
    match &modal.stage {
        Stage::EditingForm(form) => {
            let render = modal_form::render_modal(f, anchor, MODAL_W, |w| form_body(form, w));
            if let Some((row, value_len)) = render.cursor {
                render.place_cursor(f, row, modal_form::VALUE_COL as u16 + value_len);
            }
        }
        Stage::ConfirmingRemove(rc) => {
            let spec = remove_notice(rc);
            modal_form::render_modal(f, anchor, MODAL_W, |w| {
                (modal_form::notice_body(&spec, w), ())
            });
        }
        Stage::Submitted(outcome) => {
            let spec = submitted_notice(outcome);
            modal_form::render_modal(f, anchor, MODAL_W, |w| {
                (modal_form::notice_body(&spec, w), ())
            });
        }
    }
}

/// Build the Archetype-F body — pinned head, scrolling field region,
/// pinned tail — plus the real-cursor target (index **within the field
/// region** + value char length) for the focused text field, if any.
///
/// Every index handed back is relative to the field region, not to the
/// rendered frame: how many of those rows reach the screen is
/// [`modal_form::render_modal`]'s decision, not this function's.
fn form_body(form: &AddForm, width: u16) -> (modal_form::ScrollBody, Option<(usize, u16)>) {
    let focus = form.focused;
    let (title, desc) = match form.mode {
        FormMode::Add => (
            "Add local DNS record",
            "answered by the daemon instead of forwarded upstream",
        ),
        FormMode::Edit => (
            "Edit local DNS record",
            "the old record is dropped and the edited one re-added",
        ),
    };
    let mut rows = modal_form::FormRows::new(title, desc, width);

    // RECORD — what is being answered, and with what.
    rows.section("Record");
    let domain_focus = focus == FormField::Domain;
    rows.text_field(
        modal_form::value_row(
            "domain",
            &form.domain,
            domain_focus,
            ValueKind::Identity,
            Some("e.g. nas.home"),
            width,
        ),
        domain_focus,
        field_hint(FormField::Domain),
        form.domain.chars().count() as u16,
    );
    let type_focus = focus == FormField::RecordType;
    rows.field(
        modal_form::selector_row(
            "type",
            record_type_display(form.record_type),
            type_focus,
            width,
        ),
        type_focus,
        field_hint(FormField::RecordType),
    );
    let value_focus = focus == FormField::Value;
    rows.text_field(
        modal_form::value_row(
            "value",
            &form.value,
            value_focus,
            ValueKind::Identity,
            Some(value_placeholder(form.record_type)),
            width,
        ),
        value_focus,
        field_hint(FormField::Value),
        form.value.chars().count() as u16,
    );
    rows.spacer();

    // MATCHING — how widely the answer applies.
    rows.section("Matching");
    let subs_focus = focus == FormField::MatchSubdomains;
    // A radio, not a `yes`/`no` selector: the two sides mean different
    // things, and the colour rule can say so. Wildcarding is `Caution`
    // (every name under the apex stops going upstream), the apex-only
    // answer is `Healthy`. The keying is untouched — ←/→ and Space still
    // toggle it, exactly as they did against the old selector.
    rows.field(
        modal_form::radio_row(
            "match subdomains",
            ("Yes", ValueKind::Caution),
            ("No", ValueKind::Healthy),
            form.match_subdomains,
            subs_focus,
            width,
        ),
        subs_focus,
        field_hint(FormField::MatchSubdomains),
    );
    let ttl_focus = focus == FormField::Ttl;
    rows.text_field(
        modal_form::value_row(
            "ttl (secs)",
            &form.ttl_input,
            ttl_focus,
            ValueKind::Editable,
            Some("default"),
            width,
        ),
        ttl_focus,
        field_hint(FormField::Ttl),
        form.ttl_input.chars().count() as u16,
    );
    rows.spacer();

    // SCOPE — who gets the answer.
    rows.section("Scope");
    let profile_focus = focus == FormField::Profile;
    rows.field(
        modal_form::selector_row(
            "profile",
            &form.profile_option_label(),
            profile_focus,
            width,
        ),
        profile_focus,
        field_hint(FormField::Profile),
    );

    // N14: Discard left, Save right — the one `Primary` fill sits
    // right-most on every Archetype-F form (CONTRACT §3.1), superseding
    // this file's earlier left-to-right-Tab-order argument. The focus
    // ring still reaches `Submit` before `Cancel`, unchanged — same
    // precedent as `profile_modal.rs`'s tail: D7′ protects the keying,
    // not the pixel order, so Tab visiting Save before Discard while Save
    // renders on the right is accepted, not a regression.
    //
    // Discard is `Neutral`, not `Destructive`: it closes the form without
    // writing anything, which is what Esc does. It used to fill red on
    // focus — the one paint the ecosystem rule reserves for an action that
    // actually destroys something (D15).
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
        // Belt and braces: `field_hint` covers every focus state, so a
        // state that somehow renders no row still gets its guidance from
        // the same table the rows drew theirs from.
        field_hint(focus),
        FORM_KEYS,
        &actions,
    );
    rows.finish(tail)
}

/// Placeholder for the value field, keyed off the record type — an
/// operator who has just switched to CNAME should not be shown an IP.
fn value_placeholder(rt: LocalDnsRecordType) -> &'static str {
    match rt {
        LocalDnsRecordType::A => "e.g. 10.0.0.5",
        LocalDnsRecordType::AAAA => "e.g. fd00::1",
        LocalDnsRecordType::CNAME => "e.g. nas.home",
    }
}

/// One-line description of the focused field, shown on the validation
/// line whenever there is no pending error.
fn field_hint(f: FormField) -> &'static str {
    match f {
        FormField::Domain => "name to answer locally (e.g. nas.home)",
        FormField::RecordType => "A / AAAA / CNAME — ←/→ or Space to change",
        FormField::Value => "IP for A/AAAA, target host for CNAME",
        FormField::MatchSubdomains => "also match every *.domain — Space to toggle",
        FormField::Ttl => "cache seconds (blank = config default)",
        FormField::Profile => "Global, or one profile — ←/→ to change",
        FormField::Submit => "Enter saves the record",
        FormField::Cancel => "discard changes and close (also Esc)",
    }
}

/// The Remove confirm as an Archetype-C notice.
///
/// **The prose budget here is bounded and it is not negotiable.** An
/// Archetype-C body at the D18 floor has 12 interior rows, of which
/// `notice_body`'s head takes 2 and this spec's tail takes 4 (the default
/// `hint_rows` region plus the key legend and the action row), leaving
/// **6** — and with no `choices` there is no focus target at all, so the
/// viewport is pinned at offset 0, `ScrollBody::scrollable` is false and a
/// seventh row is unreachable by any keystroke *and* advertises nothing.
/// The row that would vanish is the typed-phrase input, on the highest
/// blast-radius gesture in this module. Scope and wildcard status
/// therefore ride in the description band, which is pinned, rather than
/// as prose. See `floor_typed_phrase_confirm_keeps_the_input_row_on_screen`.
///
/// §4.63 S1 raised that ceiling from 4 to 6 by giving Archetype C its own
/// head and tail budget. S3 spends part of that headroom, deliberately:
///
/// | tier | prose rows |
/// |---|---|
/// | single-keypress | 2 — domain, `(TYPE) → value` |
/// | typed-phrase | 4 — + prompt, input |
///
/// plus one more line for every 59 characters of domain past the first.
///
/// **The domain gets a row of its own** because that is what the gate
/// compares against — `rc.spec.domain` alone, not the record. It used to
/// share a row with the record type and the value, so even rendered whole
/// the operator could not see where the string they had to type ended.
/// And it is [`modal_form::ProseRow::verbatim`], so a domain past the wrap
/// column is wrapped rather than ellipsised — cut, the confirm was
/// unpassable by any keystroke sequence. See
/// `typed_phrase_confirm_renders_a_long_domain_in_full_at_the_floor` and
/// `typed_phrase_confirm_gives_the_domain_a_row_of_its_own`.
///
/// **A domain past 177 characters overflows the budget** — 3 prose rows
/// plus 4 wrapped lines of domain against 6. What is cut is the
/// **typed-phrase input**, not the domain: `scroll_layout` fills the field
/// region from the front, so the operator sees the whole string to type
/// and not what they are typing. Silent — with no `choices` there is no
/// focus target, the viewport is pinned and `ScrollBody::scrollable` is
/// false, so no scrollbar appears either. A legal DNS name runs to 253.
/// Measured by `past_177_chars_the_wrap_costs_the_typed_phrase_input_its_row`
/// and recorded rather than papered over: the remedy is a scroll
/// affordance for a focus-less notice, a mechanism this module does not
/// have.
fn remove_notice(rc: &RemoveConfirm) -> modal_form::NoticeSpec {
    let scope = match &rc.scope {
        LocalRecordScope::Global => "global".to_string(),
        LocalRecordScope::Profile(id) => format!("profile '{id}'"),
    };
    let desc = if rc.spec.match_subdomains {
        format!("{scope} \u{b7} wildcard \u{2014} every name under the apex")
    } else {
        format!("{scope} \u{b7} apex only")
    };

    // The domain alone, on its own row, verbatim — the three things the
    // gate needs and the composite row gave none of. What kind of record
    // it is rides the row below, where it cannot be mistaken for part of
    // the string to type.
    let mut prose = vec![
        ProseRow::verbatim(rc.spec.domain.clone(), ValueKind::Identity),
        ProseRow::plain(format!(
            "{} \u{2192} {}",
            record_type_display(rc.spec.record_type),
            rc.spec.value
        )),
    ];

    // The button copy carries the key, because this stage has no focus
    // ring: Tab does nothing here, and a row of buttons that looks
    // Tab-able would say otherwise.
    let (keys, cancel, confirm) = match rc.tier {
        ConfirmTier::SingleKeypress => (
            "[y] remove \u{b7} [n]/Esc cancel",
            "  [n] Cancel  ",
            "  [y] Remove  ",
        ),
        ConfirmTier::TypedPhrase => {
            prose.push(ProseRow::plain("type the domain to confirm:"));
            prose.push(ProseRow::emphasis(
                format!("{}_", rc.buffer),
                ValueKind::Blocking,
            ));
            (
                "Enter submit \u{b7} Backspace erase \u{b7} Esc cancel",
                "  [Esc] Cancel  ",
                "  [Enter] Remove  ",
            )
        }
    };

    modal_form::NoticeSpec {
        hint_rows: None,
        title: "Remove local DNS record".into(),
        desc,
        prose,
        choices: Vec::new(),
        // Budget-neutral by construction: `hint` below is never empty and
        // `hint_rows` is `None`, so `notice_body` already reserves
        // `HINT_ROWS` whether or not this is `Some`. The refusal displaces
        // the hint inside that region — it does not add a row, so the
        // three prose rows above (and the typed-phrase input among them)
        // are untouched. See `floor_typed_phrase_refusal_keeps_the_input_row`.
        error: rc.error.clone(),
        hint: "the name goes back to the upstream resolver's answer".into(),
        keys: keys.into(),
        // Cancel is the Primary — the one filled action — because on a
        // destructive confirm the safe path is the recommended one. Remove
        // is `Destructive`: coloured, never filled (D15).
        actions: vec![
            Action::new(cancel, false, ActionKind::Primary, ""),
            Action::new(confirm, false, ActionKind::Destructive, ""),
        ],
    }
}

/// The post-submit outcome screen as an Archetype-C notice.
///
/// A failure message goes to `error`, not to prose: `hint_or_error_rows`
/// wraps it across [`modal_form::HINT_ROWS`] and ellipsises what still
/// does not fit, whereas `prose_row` would cut a long `add_inner`
/// diagnostic at the modal's width. The "[any key] close" instruction
/// lives in `keys`, which is a separate row — the hint row is exactly what
/// an error takes over.
fn submitted_notice(outcome: &SubmitOutcome) -> modal_form::NoticeSpec {
    let (title, desc, prose, error) = match outcome {
        SubmitOutcome::Ok(msg) => (
            "Local DNS record \u{2014} done",
            "the change is on disk",
            vec![ProseRow::emphasis(msg.clone(), ValueKind::Healthy)],
            None,
        ),
        SubmitOutcome::Failed(msg) => (
            "Local DNS record \u{2014} failed",
            "nothing was written",
            Vec::new(),
            Some(msg.clone()),
        ),
    };
    modal_form::NoticeSpec {
        hint_rows: None,
        title: title.into(),
        desc: desc.into(),
        prose,
        choices: Vec::new(),
        error,
        hint: String::new(),
        keys: "[any key] close".into(),
        actions: vec![Action::new("  Close  ", true, ActionKind::Primary, "")],
    }
}

fn record_type_display(rt: LocalDnsRecordType) -> &'static str {
    match rt {
        LocalDnsRecordType::A => "A",
        LocalDnsRecordType::AAAA => "AAAA",
        LocalDnsRecordType::CNAME => "CNAME",
    }
}

/// Cycle the record-type radio forward (`→` / `Space`). Used by the
/// keyhandler when the focus is on the RecordType field.
pub fn cycle_record_type_next(rt: LocalDnsRecordType) -> LocalDnsRecordType {
    match rt {
        LocalDnsRecordType::A => LocalDnsRecordType::AAAA,
        LocalDnsRecordType::AAAA => LocalDnsRecordType::CNAME,
        LocalDnsRecordType::CNAME => LocalDnsRecordType::A,
    }
}

/// Cycle the record-type radio backward (`←`).
pub fn cycle_record_type_prev(rt: LocalDnsRecordType) -> LocalDnsRecordType {
    match rt {
        LocalDnsRecordType::A => LocalDnsRecordType::CNAME,
        LocalDnsRecordType::AAAA => LocalDnsRecordType::A,
        LocalDnsRecordType::CNAME => LocalDnsRecordType::AAAA,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(domain: &str, value: &str, ms: bool, ttl: Option<u32>) -> LocalDnsRecord {
        LocalDnsRecord {
            domain: domain.into(),
            record_type: LocalDnsRecordType::A,
            value: value.into(),
            match_subdomains: ms,
            ttl_secs: ttl,
        }
    }

    #[test]
    fn s44_form_field_next_cycles_through_all_eight_in_order() {
        let mut f = FormField::Domain;
        let order = [
            FormField::RecordType,
            FormField::Value,
            FormField::MatchSubdomains,
            FormField::Ttl,
            FormField::Profile,
            FormField::Submit,
            FormField::Cancel,
            FormField::Domain,
        ];
        for expected in order {
            f = f.next();
            assert_eq!(f, expected);
        }
    }

    #[test]
    fn s44_form_field_prev_walks_backwards_and_wraps() {
        let f = FormField::Domain;
        assert_eq!(f.prev(), FormField::Cancel);
        assert_eq!(FormField::RecordType.prev(), FormField::Domain);
    }

    #[test]
    fn s44_add_modal_form_validation_rejects_empty_domain() {
        let modal = LocalDnsModal::open_add(vec!["default".into(), "kids".into()], 0);
        let form = modal.form().unwrap();
        let err = form.try_resolve().unwrap_err();
        assert!(err.contains("domain"), "empty domain must error: {err}");
    }

    #[test]
    fn s44_add_modal_form_validation_rejects_empty_value() {
        let mut modal = LocalDnsModal::open_add(vec!["default".into()], 0);
        let form = modal.form_mut().unwrap();
        form.domain = "nas.home".into();
        // value left empty
        let err = modal.form().unwrap().try_resolve().unwrap_err();
        assert!(err.contains("value"), "empty value must error: {err}");
    }

    #[test]
    fn s44_add_modal_form_validation_rejects_invalid_ttl() {
        let mut modal = LocalDnsModal::open_add(vec!["default".into()], 0);
        let form = modal.form_mut().unwrap();
        form.domain = "nas.home".into();
        form.value = "192.168.1.50".into();
        form.ttl_input = "not-a-number".into();
        let err = modal.form().unwrap().try_resolve().unwrap_err();
        assert!(err.contains("ttl_secs"), "bad TTL must error: {err}");
    }

    #[test]
    fn s44_add_modal_form_validation_rejects_zero_ttl_inline() {
        // Regression: `0` parses as a u32 (it IS a non-negative integer),
        // so the old parse-only check let it through and the operator only
        // learned it was invalid after Apply hit the DR5 config validator.
        // The inline range check must now reject it up front.
        let mut modal = LocalDnsModal::open_add(vec!["default".into()], 0);
        let form = modal.form_mut().unwrap();
        form.domain = "nas.home".into();
        form.value = "192.168.1.50".into();
        form.ttl_input = "0".into();
        let err = modal.form().unwrap().try_resolve().unwrap_err();
        assert!(
            err.contains("out of range"),
            "TTL 0 must be rejected inline: {err}"
        );
    }

    #[test]
    fn s44_parse_ttl_empty_is_none_and_range_is_enforced() {
        // Empty → None (use the [local_dns].ttl_secs default) must stay
        // valid — the optional case the modal relies on.
        assert_eq!(parse_ttl(""), Ok(None));
        assert_eq!(parse_ttl("   "), Ok(None), "whitespace-only is still empty");
        // In-range boundaries accepted.
        assert_eq!(parse_ttl("1"), Ok(Some(1)));
        assert_eq!(parse_ttl("86400"), Ok(Some(86_400)));
        assert_eq!(parse_ttl("3600"), Ok(Some(3600)));
        // Out-of-range rejected inline (mirrors DR5's 1..=86_400 window).
        assert!(parse_ttl("0").unwrap_err().contains("out of range"));
        assert!(parse_ttl("86401").unwrap_err().contains("out of range"));
        // Non-integer still hits the parse-error branch, unchanged.
        assert!(parse_ttl("abc").unwrap_err().contains("ttl_secs"));
    }

    #[test]
    fn s44_add_modal_form_resolves_global_scope_when_profile_idx_zero() {
        let mut modal = LocalDnsModal::open_add(vec!["default".into(), "kids".into()], 0);
        let form = modal.form_mut().unwrap();
        form.domain = "nas.home".into();
        form.value = "192.168.1.50".into();
        let (scope, spec) = modal.form().unwrap().try_resolve().unwrap();
        assert_eq!(scope, LocalRecordScope::Global);
        assert_eq!(spec.domain, "nas.home");
        assert_eq!(spec.value, "192.168.1.50");
        assert_eq!(spec.record_type, LocalDnsRecordType::A);
        assert!(!spec.match_subdomains);
        assert_eq!(spec.ttl_secs, None);
    }

    #[test]
    fn s44_add_modal_form_resolves_profile_scope_when_profile_idx_nonzero() {
        let mut modal = LocalDnsModal::open_add(vec!["default".into(), "kids".into()], 0);
        let form = modal.form_mut().unwrap();
        form.domain = "example.test".into();
        form.value = "192.0.2.50".into();
        form.profile_idx = 2; // 0=Global, 1=default, 2=kids
        form.match_subdomains = true;
        form.ttl_input = "7200".into();
        let (scope, spec) = modal.form().unwrap().try_resolve().unwrap();
        assert_eq!(scope, LocalRecordScope::Profile("kids".into()));
        assert_eq!(spec.domain, "example.test");
        assert!(spec.match_subdomains);
        assert_eq!(spec.ttl_secs, Some(7200));
    }

    #[test]
    fn s44_add_modal_form_canonicalises_domain_to_lowercase() {
        let mut modal = LocalDnsModal::open_add(vec![], 0);
        let form = modal.form_mut().unwrap();
        form.domain = "  NAS.Home  ".into();
        form.value = "192.168.1.50".into();
        let (_, spec) = modal.form().unwrap().try_resolve().unwrap();
        assert_eq!(spec.domain, "nas.home", "domain trimmed + lowercased");
    }

    #[test]
    fn s44_add_modal_dropdown_lists_global_plus_each_profile() {
        let modal =
            LocalDnsModal::open_add(vec!["default".into(), "kids".into(), "guest".into()], 0);
        let form = modal.form().unwrap();
        assert_eq!(form.profile_options_len(), 4); // 1 Global + 3 profiles
        assert_eq!(form.profile_option_label(), "Global");
    }

    #[test]
    fn s44_add_modal_default_profile_idx_clamps_to_options_len() {
        // open_add called with default_idx=99 against 2 profiles → 3
        // options total → idx must clamp to options_len-1, not panic.
        let modal = LocalDnsModal::open_add(vec!["default".into(), "kids".into()], 99);
        let form = modal.form().unwrap();
        assert!(
            form.profile_idx < form.profile_options_len(),
            "idx must clamp to options_len"
        );
    }

    // ── Edit modal ────────────────────────────────────────────────────

    #[test]
    fn s44_edit_modal_prefills_from_row() {
        let r = rec("example.test", "192.0.2.50", true, Some(3600));
        let modal = LocalDnsModal::open_edit(
            LocalRecordScope::Profile("kids".into()),
            &r,
            vec!["default".into(), "kids".into()],
        );
        let form = modal.form().unwrap();
        assert_eq!(form.mode, FormMode::Edit);
        assert_eq!(form.domain, "example.test");
        assert_eq!(form.value, "192.0.2.50");
        assert!(form.match_subdomains);
        assert_eq!(form.ttl_input, "3600");
        assert_eq!(
            form.profile_idx, 2,
            "kids is option 2 (after Global, default)"
        );
        assert!(
            form.original.is_some(),
            "Edit captures the original snapshot"
        );
    }

    #[test]
    fn s44_edit_modal_falls_back_to_global_when_profile_id_unknown() {
        let r = rec("nas.home", "192.168.1.50", false, None);
        // Original scope is profile 'ghost' but the snapshot only knows
        // about 'default' — the dropdown lands on Global instead of
        // panicking on a missing profile id.
        let modal = LocalDnsModal::open_edit(
            LocalRecordScope::Profile("ghost".into()),
            &r,
            vec!["default".into()],
        );
        assert_eq!(modal.form().unwrap().profile_idx, 0);
    }

    // ── Remove modal — tiered confirm ─────────────────────────────────

    #[test]
    fn s44_remove_modal_global_exact_match_uses_single_keypress_tier() {
        let r = rec("nas.home", "192.168.1.50", false, None);
        let modal = LocalDnsModal::open_remove(LocalRecordScope::Global, &r);
        let rc = modal.remove().unwrap();
        assert_eq!(rc.tier, ConfirmTier::SingleKeypress);
        assert!(rc.typed_phrase_matches(), "single-keypress is always ready");
    }

    #[test]
    fn s44_remove_modal_global_match_subdomains_uses_typed_phrase_tier() {
        let r = rec("example.test", "192.0.2.50", true, None);
        let modal = LocalDnsModal::open_remove(LocalRecordScope::Global, &r);
        let rc = modal.remove().unwrap();
        assert_eq!(rc.tier, ConfirmTier::TypedPhrase);
        assert!(
            !rc.typed_phrase_matches(),
            "empty buffer must NOT satisfy typed-phrase confirm"
        );
    }

    #[test]
    fn s44_remove_modal_profile_scope_always_uses_single_keypress_tier() {
        // Even with match_subdomains=true, profile-scope removals stay
        // at the cheap tier — the blast radius is bounded by the profile.
        let r = rec("example.test", "192.0.2.50", true, None);
        let modal = LocalDnsModal::open_remove(LocalRecordScope::Profile("kids".into()), &r);
        assert_eq!(modal.remove().unwrap().tier, ConfirmTier::SingleKeypress);
    }

    #[test]
    fn s44_remove_modal_typed_phrase_accepts_exact_domain_case_insensitive() {
        let r = rec("example.test", "192.0.2.50", true, None);
        let mut modal = LocalDnsModal::open_remove(LocalRecordScope::Global, &r);
        let rc = modal.remove_mut().unwrap();
        rc.buffer = "EXAMPLE.test".into();
        assert!(
            rc.typed_phrase_matches(),
            "case-insensitive match accepts mixed case input"
        );
    }

    #[test]
    fn s44_remove_modal_typed_phrase_rejects_wrong_domain() {
        let r = rec("example.test", "192.0.2.50", true, None);
        let mut modal = LocalDnsModal::open_remove(LocalRecordScope::Global, &r);
        let rc = modal.remove_mut().unwrap();
        rc.buffer = "evil.com".into();
        assert!(!rc.typed_phrase_matches());
    }

    // ── Cycling helpers ───────────────────────────────────────────────

    #[test]
    fn s44_cycle_record_type_walks_a_aaaa_cname_and_wraps() {
        assert_eq!(
            cycle_record_type_next(LocalDnsRecordType::A),
            LocalDnsRecordType::AAAA
        );
        assert_eq!(
            cycle_record_type_next(LocalDnsRecordType::AAAA),
            LocalDnsRecordType::CNAME
        );
        assert_eq!(
            cycle_record_type_next(LocalDnsRecordType::CNAME),
            LocalDnsRecordType::A
        );
        assert_eq!(
            cycle_record_type_prev(LocalDnsRecordType::A),
            LocalDnsRecordType::CNAME
        );
    }

    // ── Lifecycle ─────────────────────────────────────────────────────

    #[test]
    fn s44_modal_finish_transitions_to_submitted() {
        let mut modal = LocalDnsModal::open_add(vec![], 0);
        assert!(!modal.is_submitted());
        modal.finish(SubmitOutcome::Ok("done".into()));
        assert!(modal.is_submitted());
    }

    #[test]
    fn s44_modal_form_accessors_only_yield_some_in_editing_stage() {
        let mut modal = LocalDnsModal::open_add(vec![], 0);
        assert!(modal.form().is_some());
        assert!(modal.remove().is_none());
        modal.finish(SubmitOutcome::Failed("x".into()));
        assert!(modal.form().is_none());
        assert!(modal.remove().is_none());
    }

    // ── Form render ───────────────────────────────────────────────────

    /// Flatten the whole body — head, field region, tail — into one
    /// string for content assertions.
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
    fn form_renders_banded_title_labelled_sections_and_actions() {
        // Replaces `grid_form_renders_header_caret_and_active_marker`.
        // Two of its assertions were pinning the surface this wave
        // removes, and are gone deliberately:
        //   * `Field` / `Value` — the legacy `│`-ruled grid header, which
        //     Archetype F replaces with labelled section bands;
        //   * `nas_` — the fake `_` caret. The ecosystem rows carry none;
        //     the real terminal cursor marks the insertion point, and it
        //     is asserted in `floor_hardware_cursor_sits_in_the_focused_
        //     text_field`, where a buffer dump cannot reach.
        let mut modal = LocalDnsModal::open_add(vec!["kids".into()], 0);
        let form = modal.form_mut().unwrap();
        form.domain = "nas".into(); // focus defaults to Domain
        let text = render_text(form, 60);

        assert!(text.contains("Add local DNS record"), "banded title");
        for section in ["RECORD", "MATCHING", "SCOPE"] {
            assert!(text.contains(section), "missing {section} section band");
        }
        assert!(text.contains("nas"), "the typed value is on its row");
        assert!(text.contains('◀'), "active row carries the focus marker");
        assert!(
            text.contains("name to answer locally"),
            "validation line shows the focused field's hint"
        );
        assert!(text.contains("Save"), "Save action present");
        assert!(text.contains("Discard"), "Discard action present");
    }

    #[test]
    fn grid_form_focused_selector_is_wrapped_in_angle_brackets() {
        let mut modal = LocalDnsModal::open_add(vec![], 0);
        let form = modal.form_mut().unwrap();
        form.focused = FormField::RecordType;
        let text = render_text(form, 60);
        assert!(
            text.contains("‹ A ›"),
            "a focused selector value is wrapped to signal ←/→ cycles it"
        );
    }

    #[test]
    fn grid_form_inline_error_replaces_the_hint_line() {
        let mut modal = LocalDnsModal::open_add(vec![], 0);
        let form = modal.form_mut().unwrap();
        form.error_message = Some("value is required".into());
        let text = render_text(form, 60);
        assert!(text.contains("⚠ value is required"), "error shows inline");
        // The hint for the (default-focused) Domain field is suppressed
        // while an error is pending.
        assert!(!text.contains("name to answer locally"));
    }

    // ── §4.61 Wave 2b — Archetype F at the 80×24 floor ────────────────
    //
    // Everything below asserts on the RENDERED BUFFER, never on the line
    // vector. Every past instance of `lists-modal-min-height-clip` had a
    // correct line vector; the defect lived only in what reached the
    // screen.

    /// The D18 anchor at the declared floor. `ui.rs::layout_chunks` gives
    /// a 4-row header, a 5-row menu card (Network is a multi-leaf
    /// section) and a 1-row footer, so a leaf tab's content rect on an
    /// 80×24 terminal is exactly `(0, 9, 80, 14)` — 12 interior rows once
    /// the modal frame takes its two.
    fn floor_anchor() -> Rect {
        Rect::new(0, 9, 80, 14)
    }

    fn draw_at_floor(modal: &LocalDnsModal) -> ratatui::buffer::Buffer {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;
        let mut term = Terminal::new(TestBackend::new(80, 24)).unwrap();
        term.draw(|f| render_overlay(f, floor_anchor(), modal))
            .unwrap();
        term.backend().buffer().clone()
    }

    /// Row-by-row cell-symbol dump. No ANSI ever enters a `TestBackend`
    /// buffer — styling is a per-cell `Style`, not interleaved escapes —
    /// so this is a faithful plain-text reconstruction of the screen.
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

    fn dump_at_floor(modal: &LocalDnsModal) -> String {
        dump_buffer(&draw_at_floor(modal))
    }

    /// A form with a distinct, greppable value in every field, so a
    /// `label + value` row assertion cannot be satisfied by accident from
    /// the hint line or the title band.
    fn floor_form(focus: FormField) -> LocalDnsModal {
        let mut modal = LocalDnsModal::open_add(vec!["kids".into()], 0);
        let form = modal.form_mut().unwrap();
        form.domain = "nas.home".into();
        form.value = "10.9.9.9".into();
        form.ttl_input = "300".into();
        form.focused = focus;
        modal
    }

    /// `(label, on-row evidence)` for each editable field — the two
    /// strings that must land on the SAME screen row for that field to be
    /// genuinely visible.
    const FLOOR_ROWS: [(FormField, &str, &str); 6] = [
        (FormField::Domain, "domain", "nas.home"),
        (FormField::RecordType, "type", "\u{2039} A \u{203a}"),
        (FormField::Value, "value", "10.9.9.9"),
        (FormField::MatchSubdomains, "match subdomains", "No"),
        (FormField::Ttl, "ttl", "300"),
        (FormField::Profile, "profile", "\u{2039} Global \u{203a}"),
    ];

    #[test]
    fn floor_action_row_and_focused_field_are_on_screen_together() {
        // DoD 3. A clipped modal still lets Tab reach the Save it has cut,
        // so the operator commits blind — the two things a clip silently
        // takes away are the action row and the field under focus, and the
        // only assertion that catches it demands BOTH in one render.
        for (focus, label, evidence) in FLOOR_ROWS {
            let s = dump_at_floor(&floor_form(focus));
            assert!(
                s.contains("Save"),
                "{focus:?}: action row off-screen at 80\u{d7}24:\n{s}"
            );
            assert!(
                s.lines().any(|l| l.contains(label) && l.contains(evidence)),
                "{focus:?}: focused row ('{label}' + '{evidence}') off-screen \
                 at 80\u{d7}24:\n{s}"
            );
        }
    }

    #[test]
    fn floor_viewport_follows_focus_to_the_last_field() {
        // DoD 4. A viewport pinned to page one would satisfy the test
        // above for the first fields and still hide the last.
        let last = dump_at_floor(&floor_form(FormField::Profile));
        assert!(
            last.lines()
                .any(|l| l.contains("profile") && l.contains("\u{2039} Global \u{203a}")),
            "focused last field is off-screen:\n{last}"
        );
        let first = dump_at_floor(&floor_form(FormField::Domain));
        assert!(
            first
                .lines()
                .any(|l| l.contains("domain") && l.contains("nas.home")),
            "focused first field is off-screen:\n{first}"
        );
        assert!(
            !first.contains("\u{2039} Global \u{203a}"),
            "a 4-row viewport cannot be showing both ends at once — the \
             viewport is not moving:\n{first}"
        );
    }

    #[test]
    fn floor_modal_never_paints_outside_the_content_anchor() {
        // DoD 2 / §4.62 N1: the header, the menu card and the footer
        // legend are off limits to anything transient.
        let anchor = floor_anchor();
        for modal in [
            floor_form(FormField::Domain),
            LocalDnsModal::open_remove(
                LocalRecordScope::Global,
                &rec("wild.home", "10.9.9.9", true, None),
            ),
            {
                let mut m = LocalDnsModal::open_add(vec![], 0);
                m.finish(SubmitOutcome::Ok("added nas.home".into()));
                m
            },
        ] {
            let buf = draw_at_floor(&modal);
            for y in 0..buf.area.height {
                for x in 0..buf.area.width {
                    if anchor.contains(ratatui::layout::Position { x, y }) {
                        continue;
                    }
                    assert_eq!(
                        buf[(x, y)].symbol(),
                        " ",
                        "the modal painted ({x},{y}), outside the content rect \
                         {anchor:?}:\n{}",
                        dump_buffer(&buf)
                    );
                }
            }
        }
    }

    #[test]
    fn floor_typed_phrase_confirm_keeps_the_input_row_on_screen() {
        // An Archetype-C body gets exactly 4 scrolling rows at the floor
        // and has no `focus_row` to scroll to, so a fifth prose row is
        // unreachable — silently. The row that would vanish here is the
        // one the operator types into, on the highest-blast-radius gesture
        // in the module.
        let mut modal = LocalDnsModal::open_remove(
            LocalRecordScope::Global,
            &rec("wild.home", "10.9.9.9", true, None),
        );
        modal.remove_mut().unwrap().buffer = "wild.ho".into();
        let s = dump_at_floor(&modal);
        assert!(
            s.contains("wild.ho_"),
            "typed-phrase buffer off-screen at 80\u{d7}24 — the operator \
             confirms a wildcard removal blind:\n{s}"
        );
        assert!(
            s.contains("wild.home"),
            "the record being removed is off-screen:\n{s}"
        );
    }

    /// Chrome and indents stripped, so a domain that had to wrap across
    /// two rows reads back contiguous. `…` is deliberately kept — it is
    /// exactly what the transcription target must never produce.
    fn dechrome(dump: &str) -> String {
        dump.chars()
            .filter(|c| {
                !matches!(
                    c,
                    ' ' | '\n'
                        | '\u{2502}'
                        | '\u{2500}'
                        | '\u{256d}'
                        | '\u{256e}'
                        | '\u{2570}'
                        | '\u{256f}'
                        | '\u{258c}'
                        | '\u{2588}'
                        | '\u{25c0}'
                )
            })
            .collect()
    }

    /// The gate compares the buffer against `rc.spec.domain` **alone**, so
    /// the domain has to be on screen whole — and it has to be legible as
    /// its own token.
    ///
    /// Two distinct failures live here. The row was
    /// `"{domain} ({type}) → {value}"`, so (a) past the interior width the
    /// domain was ellipsised and no keystroke sequence could satisfy the
    /// gate, and (b) even rendered whole, three fields on one row do not
    /// say where the string the operator must type ends.
    #[test]
    fn typed_phrase_confirm_renders_a_long_domain_in_full_at_the_floor() {
        // 62 chars: past the 60 usable cells a `prose_row` leaves at the
        // 62-column interior, and well inside a legal DNS name.
        for n in 55..=64usize {
            let domain = format!("remove-me-{}.endsentinel", "x".repeat(n - 22));
            assert_eq!(domain.len(), n, "fixture must be exactly {n} chars");
            let modal = LocalDnsModal::open_remove(
                LocalRecordScope::Global,
                &rec(&domain, "10.9.9.9", true, None),
            );
            let s = dump_at_floor(&modal);
            // The domain wraps, so its tail is NOT contiguous on one row —
            // that is the fix working. What must never appear is a `…`,
            // and nothing else in this stage is long enough to produce
            // one.
            assert!(
                !s.contains('\u{2026}'),
                "a {n}-char domain was ellipsised — the gate compares \
                 against all {n} bytes and the cut ones are \
                 unrecoverable:\n{s}"
            );
            assert!(
                dechrome(&s).contains(&domain),
                "a {n}-char domain is not recoverable from the screen — \
                 the operator cannot type what the gate demands:\n{s}"
            );
        }
    }

    /// Where the wrap runs out of budget, measured rather than reasoned
    /// about.
    ///
    /// The typed-phrase body is 3 prose rows plus the domain's own, so the
    /// domain may spend 3 lines — 177 characters at the 59-cell wrap —
    /// against Archetype C's 6-row content budget. At 178 it needs a
    /// fourth and the body wants 7.
    ///
    /// **What gets cut is the input row, not the domain.** `scroll_layout`
    /// serves the tail, then the head, and the field region takes what is
    /// left from the *front* — so the domain renders whole and the row the
    /// operator types into falls off the bottom. They can see the string
    /// to transcribe and not what they are transcribing. Silent by
    /// construction: with no `choices` there is no focus target, the
    /// viewport is pinned at offset 0, `ScrollBody::scrollable` is false
    /// and not even a scrollbar appears.
    ///
    /// A legal DNS name runs to 253, so this is reachable. Pinned rather
    /// than fixed because the remedy is a scroll affordance for a
    /// focus-less notice, which this module does not have. If that lands,
    /// this test is the one to update.
    #[test]
    fn past_177_chars_the_wrap_costs_the_typed_phrase_input_its_row() {
        let probe = |len: usize| {
            let domain = format!("{}.endsentinel", "x".repeat(len - 12));
            assert_eq!(domain.len(), len);
            let mut modal = LocalDnsModal::open_remove(
                LocalRecordScope::Global,
                &rec(&domain, "10.9.9.9", true, None),
            );
            modal.remove_mut().unwrap().buffer = "ZZQQ".into();
            let s = dump_at_floor(&modal);
            // The domain, and the row the operator types into.
            (dechrome(&s).contains(&domain), s.contains("ZZQQ_"), s)
        };

        let (domain_whole, input_visible, dump) = probe(177);
        assert!(
            domain_whole && input_visible,
            "177 chars is inside the budget — both the domain and the \
             input row must be on screen:\n{dump}"
        );

        let (domain_whole, input_visible, dump) = probe(178);
        assert!(
            domain_whole,
            "the domain is cut at 178 — the overflow moved, so re-derive \
             both this test and `remove_notice`'s doc:\n{dump}"
        );
        assert!(
            !input_visible,
            "the input row survives at 178 — the budget changed, so update \
             this test and `remove_notice`'s doc together:\n{dump}"
        );
    }

    /// The answer to "does `hint_or_error_rows` need the verbatim
    /// contract too?" — no, and this is why.
    ///
    /// The refusal names the domain (`the domain is '…' — you typed '…'`)
    /// and rides a 2-row region that ellipsises, so for a long domain that
    /// message IS cut. That is acceptable precisely because the refusal is
    /// no longer the operator's only sight of the string: the verbatim
    /// prose row above it carries the domain whole, with a refusal pending
    /// or without one. A hint is guidance about a transcription target,
    /// never the target itself.
    #[test]
    fn a_refusal_never_becomes_the_only_sight_of_the_domain() {
        let domain = format!("refuse-me-{}.endsentinel", "x".repeat(42));
        assert_eq!(domain.len(), 64);
        let mut modal = LocalDnsModal::open_remove(
            LocalRecordScope::Global,
            &rec(&domain, "10.9.9.9", true, None),
        );
        let rc = modal.remove_mut().unwrap();
        rc.buffer = "wrong".into();
        assert!(!rc.confirm_or_refuse(), "fixture must be a mismatch");

        let s = dump_at_floor(&modal);
        assert!(
            s.contains('\u{26a0}'),
            "the refusal never reached the screen:\n{s}"
        );
        assert!(
            dechrome(&s).contains(&domain),
            "with a refusal pending the domain is no longer recoverable \
             whole — the operator has nothing left to transcribe:\n{s}"
        );
    }

    /// Contract item 5: the transcription target gets a row of its own.
    ///
    /// The gate wants the domain and nothing else. A composite row showing
    /// `domain (TYPE) → value` leaves the operator guessing where the
    /// string they must type ends — a defect the length fix alone does not
    /// touch.
    #[test]
    fn typed_phrase_confirm_gives_the_domain_a_row_of_its_own() {
        let modal = LocalDnsModal::open_remove(
            LocalRecordScope::Global,
            &rec("nas.home", "10.9.9.9", true, None),
        );
        let s = dump_at_floor(&modal);
        let row = s
            .lines()
            .find(|l| l.contains("nas.home"))
            .expect("the domain must be on screen");
        assert!(
            !row.contains("10.9.9.9"),
            "the gate compares against the domain alone, but its row also \
             carries the record value — nothing says where to stop \
             typing:\n{row}"
        );
    }

    /// The budget claim, measured rather than reasoned about: a refusal
    /// must not cost the typed-phrase input its row at the D18 floor.
    ///
    /// `remove_notice` leaves `hint_rows` at `None` and always ships a
    /// non-empty `hint`, so `notice_body` reserves `HINT_ROWS` either way
    /// and the error *displaces* the hint inside that region. That is the
    /// argument; this is the measurement. The failure mode it guards is
    /// silent — with no `choices` there is no focus target, so a row
    /// pushed past the viewport is unreachable by any keystroke and
    /// nothing announces it.
    #[test]
    fn floor_typed_phrase_refusal_keeps_the_input_row() {
        let mut modal = LocalDnsModal::open_remove(
            LocalRecordScope::Global,
            &rec("wild.home", "10.9.9.9", true, None),
        );
        let rc = modal.remove_mut().unwrap();
        rc.buffer = "wild.ho".into();
        assert!(!rc.confirm_or_refuse(), "fixture must be a mismatch");

        let s = dump_at_floor(&modal);
        assert!(
            s.contains('\u{26a0}'),
            "the refusal never reached the screen at 80\u{d7}24:\n{s}"
        );
        assert!(
            s.contains("wild.ho_"),
            "the refusal pushed the typed-phrase buffer off-screen \u{2014} \
             the operator now confirms a wildcard removal blind:\n{s}"
        );
        assert!(
            s.contains("wild.home"),
            "the refusal pushed the record being removed off-screen:\n{s}"
        );
    }

    /// The other half of the budget claim: the prose region is the same
    /// three rows with a refusal pending as without one.
    ///
    /// Weaker than the floor render above — it cannot see a row that
    /// falls off the viewport — but it pins *where* the refusal lives, so
    /// a later change that moves it into prose fails here with a reason
    /// rather than at the floor with a geometry puzzle.
    #[test]
    fn refusal_costs_no_prose_row() {
        let mut modal = LocalDnsModal::open_remove(
            LocalRecordScope::Global,
            &rec("wild.home", "10.9.9.9", true, None),
        );
        let quiet = remove_notice(modal.remove().unwrap()).prose.len();

        let rc = modal.remove_mut().unwrap();
        rc.buffer = "nope".into();
        rc.confirm_or_refuse();
        let spec = remove_notice(modal.remove().unwrap());

        // Four since S3 split the composite row: the gate compares
        // against `rc.spec.domain` alone, so the domain gets a verbatim
        // row of its own and `(TYPE) → value` rides the row below it.
        assert_eq!(quiet, 4, "the typed-phrase prose budget is four rows");
        assert_eq!(
            spec.prose.len(),
            quiet,
            "a refusal must ride the error slot, not a prose row"
        );
        assert!(
            spec.error.is_some(),
            "the refusal never reached the notice at all"
        );
    }

    /// Enter with nothing typed is not a mistake to report — the operator
    /// has not attempted the phrase yet, and the prompt row already says
    /// what to do. Enter stays inert there, deliberately.
    #[test]
    fn confirm_or_refuse_is_quiet_on_an_empty_buffer() {
        let mut modal = LocalDnsModal::open_remove(
            LocalRecordScope::Global,
            &rec("wild.home", "10.9.9.9", true, None),
        );
        let rc = modal.remove_mut().unwrap();
        assert!(!rc.confirm_or_refuse(), "an empty buffer cannot submit");
        assert!(
            rc.error.is_none(),
            "nothing was typed, so there is nothing to reject: {:?}",
            rc.error
        );
    }

    /// A match submits and leaves nothing behind. Also covers the
    /// single-keypress tier, where `typed_phrase_matches` is always true
    /// and no refusal is reachable.
    #[test]
    fn confirm_or_refuse_is_silent_when_it_says_yes() {
        for (domain, ms) in [("wild.home", true), ("nas.home", false)] {
            let mut modal = LocalDnsModal::open_remove(
                LocalRecordScope::Global,
                &rec(domain, "10.9.9.9", ms, None),
            );
            let rc = modal.remove_mut().unwrap();
            if ms {
                rc.buffer = domain.into();
            }
            assert!(rc.confirm_or_refuse(), "{domain} should be ready to submit");
            assert!(rc.error.is_none(), "a yes must carry no complaint");
        }
    }

    /// A refusal describes one buffer. Editing that buffer must retract
    /// it, or the screen contradicts itself: a message naming a phrase
    /// the operator has already moved past.
    #[test]
    fn editing_the_buffer_retracts_the_refusal() {
        for edit in ["push", "backspace"] {
            let mut modal = LocalDnsModal::open_remove(
                LocalRecordScope::Global,
                &rec("wild.home", "10.9.9.9", true, None),
            );
            let rc = modal.remove_mut().unwrap();
            rc.buffer = "nope".into();
            rc.confirm_or_refuse();
            assert!(rc.error.is_some(), "fixture must start refused");

            match edit {
                "push" => rc.push_char('x'),
                _ => rc.backspace(),
            }
            assert!(
                rc.error.is_none(),
                "{edit} left a stale refusal: {:?}",
                rc.error
            );
        }
    }

    #[test]
    fn floor_hardware_cursor_sits_in_the_focused_text_field() {
        // The ecosystem rows carry no `_` caret — the real terminal cursor
        // marks the insertion point (D7', same as the Lists reference), so
        // the only way to assert it is through the backend's cursor.
        use ratatui::backend::{Backend, TestBackend};
        use ratatui::Terminal;
        let modal = floor_form(FormField::Domain);
        let mut term = Terminal::new(TestBackend::new(80, 24)).unwrap();
        term.draw(|f| render_overlay(f, floor_anchor(), &modal))
            .unwrap();
        let pos = term.backend_mut().get_cursor_position().unwrap();
        let dump = dump_buffer(term.backend().buffer());
        let row = dump.lines().nth(pos.y as usize).unwrap_or("");
        assert!(
            row.contains("domain") && row.contains("nas.home"),
            "cursor row {} is not the focused domain field:\n{dump}",
            pos.y
        );
        // Column: modal inner-left + VALUE_COL + what has been typed.
        let inner_x = (80 - MODAL_W) / 2 + 1;
        assert_eq!(
            pos.x,
            inner_x + modal_form::VALUE_COL as u16 + "nas.home".chars().count() as u16,
            "cursor is not at the end of the typed value:\n{dump}"
        );
    }
}
