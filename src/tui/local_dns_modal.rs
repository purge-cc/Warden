//! Local DNS tab modals (Add / Remove / Edit). Opens
//! over [`crate::tui::app::Leaf::LocalDns`] via `a` / `d|Delete` / `e`
//! keypresses. Submits through the single-seat helpers
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
    /// typed-phrase.
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
    /// screen at the minimum-terminal-size floor.
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

/// Nav-key legend. The migration to `modal_form` changed chrome, layout
/// and colour and **not** the keying: `mod.rs` still maps Tab/↑↓ to
/// move, ←/→ and Space to change, Enter to save and Esc to cancel.
///
/// The action row bakes its own key into each button's label
/// (`[Esc] Discard` / `[Enter] Save`), so a blanket "Enter save · Esc
/// cancel" here would be a second, redundant source of the same fact.
const FORM_KEYS: &str = "\u{21b9}/\u{2191}\u{2193} move \u{b7} \u{2190}/\u{2192} change";

/// Draw the modal over the tab content rect. Branches on the stage so the
/// operator sees the form, the confirm prompt, or the outcome at the right
/// moment.
///
/// `anchor` is the tab content rect, never `f.area()` — a
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
            modal_form::render_modal(f, anchor, MODAL_W, |w| {
                (modal_form::notice_body(&remove_notice(rc, w), w), ())
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

    // Discard left, Save right — the one `Primary` fill sits right-most
    // on every Archetype-F form. The focus ring still reaches `Submit`
    // before `Cancel`, unchanged — same precedent as `profile_modal.rs`'s
    // tail: the keying is protected, not the pixel order, so Tab
    // visiting Save before Discard while Save renders on the right is
    // accepted, not a regression.
    //
    // Discard is `Neutral`, not `Destructive`: it closes the form without
    // writing anything, which is what Esc does. It used to fill red on
    // focus — the one paint the ecosystem rule reserves for an action that
    // actually destroys something.
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

/// [`modal_form::fit`]'s mirror for the typed-phrase buffer row: keep the
/// **tail**, mark the cut on the left. The row this feeds is a plain
/// [`ProseRow`], which truncates on the right by default — backwards for
/// text the operator is typing INTO, since the caret and whatever was just
/// typed sit at the end. Mirrors `scope_modal::tail_fit`; not shared
/// because `modal_form`'s own `fit_tail` is private to that module.
fn tail_fit(s: &str, max: usize) -> String {
    let n = s.chars().count();
    if n <= max {
        return s.to_string();
    }
    if max == 0 {
        return String::new();
    }
    let mut out = String::from('\u{2026}');
    out.extend(s.chars().skip(n - (max - 1)));
    out
}

/// The Remove confirm as an Archetype-C notice.
///
/// **The prose budget here is bounded and it is not negotiable.** An
/// Archetype-C body at the minimum-terminal-size floor has 12 interior
/// rows, of which
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
/// Archetype C has its own head and tail budget, and the tier table
/// below spends part of that headroom, deliberately:
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
fn remove_notice(rc: &RemoveConfirm, width: u16) -> modal_form::NoticeSpec {
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
            let avail = (width as usize).saturating_sub(2);
            prose.push(ProseRow::emphasis(
                tail_fit(&format!("{}_", rc.buffer), avail),
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
        // is `Destructive`: coloured, never filled.
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
#[path = "tests/local_dns_modal_tests.rs"]
mod tests;
